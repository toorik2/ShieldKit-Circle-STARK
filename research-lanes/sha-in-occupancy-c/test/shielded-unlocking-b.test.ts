import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { decodeTransaction, hash256 } from "@bitauth/libauth";
import {
  BLOWUP,
  FRI_QUERIES,
  FRI_VERSION,
  GRIND_BITS,
  TRACE_LEN,
  VK_ID,
} from "../src/backends/circle/params.ts";
import { soundnessWorksheet } from "../src/backends/circle/soundness.ts";
import { algebraicCQuotientLde, quotientAtDomain, shaMixForOccupancyC } from "../src/backends/circle/air.ts";
import { evalCirclePoly, interpolateCircle } from "../src/backends/circle/interpolate.ts";
import { HASH_BIT_ROWS_BYTES, shaPubsAcc, shaStatementResiduals, statementShaOpens } from "../src/chain/note-auth-air.ts";
import { add, encodeLe, mul, sub } from "../src/backends/circle/m31.ts";
import { openingMaskAt } from "../src/backends/circle/witness-mask.ts";
import { circleDomain, decodeFriProof, encodeFriProof, proveFri, proveFromTLde, verifyFri, wWithdraw } from "../src/backends/circle/fri.ts";
import { FRI_N } from "../src/backends/circle/params.ts";
import { compileCovenantSuccessor } from "../src/chain/covenant-spend.ts";
import { compilePoolCovenant, compilePoolP2sTrampoline } from "../src/chain/covenant-p2s.ts";
import {
  AIR_OFF_HASHBIT,
  AIR_OFF_IDX,
  AIR_OFF_NTABLE,
  AIR_OFF_OPEN_MASK,
  AIR_OFF_QTABLE,
  AIR_OFF_CELLS,
  AIR_OFF_SHA_ACC,
  AIR_OFF_SHA_C,
  AIR_OFF_SHA_OPEN,
  AIR_SHA_C_BYTES,
  AIR_SHA_OPEN_BYTES,
  AIR_SHA_OUT_BYTES,
  HASH_CELL_COMMIT,
  encodeAirPacked,
  SLOT_KERNEL_COUNT_CONSENSUS,
} from "../src/chain/air-cqz.ts";
import { createLabWallet } from "../src/chain/wallet.ts";
import { evaluateNoteAuthKernel, evaluatePoolSuccessorVm, evaluateSuccessorInputMeters } from "../src/chain/vm-verifier.ts";
import { noteAuthBindHash, noteAuthKernelUnlocking, noteAuthPublicOpens } from "../src/chain/note-auth-kernel.ts";
import { concatBytes, sha256 } from "../src/pool/bytes.ts";
import { encodePublicPaa1, emptyState, utxoValueFor } from "../src/pool/state.ts";
import { applyDeposit, applyWithdraw } from "../src/pool/transition.ts";
import { IncrementalMerkle, NullifierSet, type Note } from "../src/pool/notes.ts";
import { writeI64LE } from "../src/pool/bytes.ts";
import { LAB_PAYOUT_DIGEST } from "../src/chain/payout.ts";
import { FRI_LEFTOVER_BYTES, FRI_PAIR_BYTES_L0, FRI_PAIR_BYTES_QM } from "../src/chain/fri-kernel.ts";
import { defaultInternalHash } from "../src/backends/circle/internal-hash.ts";
import {
  SHA_LDE_N_LEAVES,
  SHA_LDE_SHARD_BYTES,
  SHA_LDE_VALUE_BYTES,
  encodeShaLdeShards,
  openShaLde,
} from "../src/chain/sha-lde.ts";

import type { FriProof } from "../src/backends/circle/fri.ts";
import type { FriAuth } from "../src/backends/circle/air.ts";
import type { PoolStatement } from "../src/pool/statement.ts";
import type { NoteAuthOpens } from "../src/chain/note-auth-bind.ts";
import type { InternalHash } from "../src/backends/circle/internal-hash.ts";
import { MerkleTree } from "../src/backends/circle/merkle.ts";

function firstPushLen(u: Uint8Array): number {
  const op = u[0]!;
  if (op === 0x4d) return u[1]! | (u[2]! << 8);
  if (op === 0x4c) return u[1]!;
  return op;
}

function lastPush(u: Uint8Array): Uint8Array {
  let i = 0;
  let last = new Uint8Array();
  while (i < u.length) {
    const op = u[i]!;
    if (op > 0 && op <= 75) {
      last = u.subarray(i + 1, i + 1 + op);
      i += 1 + op;
    } else if (op === 0x4c) {
      const n = u[i + 1]!;
      last = u.subarray(i + 2, i + 2 + n);
      i += 2 + n;
    } else if (op === 0x4d) {
      const n = u[i + 1]! | (u[i + 2]! << 8);
      last = u.subarray(i + 3, i + 3 + n);
      i += 3 + n;
    } else i += 1;
  }
  return last;
}

/** Occupancy-only qTable/nTable on packed AIR (SHA mix stripped). Attack packed. */
function recookOccupancyPacked(statement: PoolStatement, packed: Uint8Array): Uint8Array {
  const out = new Uint8Array(packed);
  const hash = defaultInternalHash();
  const small = circleDomain(TRACE_LEN);
  const big = circleDomain(FRI_N);
  const occ = algebraicCQuotientLde(statement, small, big, hash, undefined, undefined, undefined, undefined, true);
  const commit = out.subarray(AIR_OFF_OPEN_MASK, AIR_OFF_OPEN_MASK + 32);
  for (let s = 0; s < FRI_QUERIES; s += 1) {
    const i = (out[AIR_OFF_IDX + s * 2]! << 8) | out[AIR_OFF_IDX + s * 2 + 1]!;
    const r = openingMaskAt(commit, i, hash, occ.zLde[i]!);
    out.set(encodeLe(add(occ.qLde[i]!, r)), AIR_OFF_QTABLE + s * 4);
    out.set(encodeLe(add(occ.nLde[i]!, mul(r, occ.zLde[i]!))), AIR_OFF_NTABLE + s * 4);
  }
  return out;
}

/** Recooked junk merkle of mixed-prefix leaves. Retry uniqueness until encodeFriProof cargo fits; never a 1-leaf degenerate tree. */
function mixedJunkBits(args: {
  statement: PoolStatement;
  qLde: import("../src/backends/circle/m31.ts").M31El[];
  auth: FriAuth;
  pin: Uint8Array;
  mixedLeaves: Uint8Array;
  mixedOpens: NoteAuthOpens;
  hash: InternalHash;
}): FriProof {
  const prefix = new Uint8Array(12);
  prefix.set(args.mixedOpens.amountCommit.subarray(0, 4), 0);
  prefix.set(args.mixedOpens.leaf.subarray(0, 4), 4);
  prefix.set(args.mixedOpens.nf.subarray(0, 4), 8);
  let lastErr: Error | undefined;
  for (let unique = 40; unique >= 8; unique -= 4) {
    const bodies = Array.from({ length: unique }, () => {
      const v = new Uint8Array(SHA_LDE_VALUE_BYTES);
      v.set(prefix);
      crypto.getRandomValues(v.subarray(12));
      return v;
    });
    const leaves = Array.from({ length: SHA_LDE_N_LEAVES }, (_, i) => new Uint8Array(bodies[i % unique]!));
    const root = new MerkleTree(leaves, args.hash).root;
    const recooked = proveFromTLde(args.statement, args.qLde, args.auth, {
      hashRoot: args.pin,
      hashLeaves: args.mixedLeaves,
      hashBitRoot: root,
    });
    const lde = openShaLde(leaves, recooked.queries.map((q) => q.index), args.hash);
    try {
      encodeShaLdeShards(lde);
    } catch (e) {
      lastErr = e instanceof Error ? e : new Error(String(e));
      if (!lastErr.message.includes("sha-lde cargo")) throw lastErr;
      continue;
    }
    const bits = proveFromTLde(args.statement, args.qLde, args.auth, {
      hashRoot: args.pin,
      hashLeaves: args.mixedLeaves,
      hashBitRoot: root,
      hashBitLde: lde,
    });
    encodeFriProof(bits);
    return bits;
  }
  throw lastErr ?? new Error("mixed junk sha-lde cargo did not fit after uniqueness retry");
}

const rnd32 = () => crypto.getRandomValues(new Uint8Array(32));
const hex = (u: Uint8Array) => Buffer.from(u).toString("hex");
const hasPreimage = (u: Uint8Array, n: Note) => {
  const h = hex(u);
  return h.includes(hex(n.rho)) || h.includes(hex(n.ownerSecret)) || h.includes(hex(writeI64LE(n.amountSats)));
};

describe("shielded unlocking envelope-B successor", () => {
  it("occupancy pins hold", () => {
    assert.equal(FRI_VERSION, 10);
    assert.equal(TRACE_LEN, 64);
    assert.equal(BLOWUP, 16);
    assert.equal(FRI_QUERIES, 36);
    assert.equal(GRIND_BITS, 20);
    assert.equal(FRI_PAIR_BYTES_L0, 8);
    assert.equal(FRI_PAIR_BYTES_QM, 32);
    assert.equal(VK_ID.includes("qm31"), true);
    const w = soundnessWorksheet();
    assert.equal(w.fieldBits, 124);
    assert.equal(w.minBits >= 100, true);
    assert.equal(w.queryConjectureBits, 128);
  });

  it(
    "honest successor: verifyFri + standard VM, 10k/100k, no preimages; mutated path/nf VM-reject",
    { timeout: 180_000 },
    () => {
      const note: Note = { amountSats: 20_000n, rho: rnd32(), ownerSecret: rnd32() };
      const d = applyDeposit(
        { state: emptyState(rnd32()), notes: new IncrementalMerkle(), nullifiers: new NullifierSet() },
        note,
      );
      const w = applyWithdraw(d.machine, note, d.index, LAB_PAYOUT_DIGEST, 7_777n);
      const wit = wWithdraw(note, d.index, w.path, w.created);
      const proved = proveFri(w.statement, wit);
      const fri = verifyFri(w.statement, proved, wit);
      assert.equal(fri.ok, true, fri.ok ? "ok" : fri.reason);
      let raw = encodeFriProof(proved);
      let measured = compileCovenantSuccessor({
        wallet: createLabWallet(),
        pool: {
          tx_hash: "11".repeat(32),
          tx_pos: 0,
          value: utxoValueFor(w.statement.oldState),
          category: new Uint8Array(32).fill(0x11),
          commitment: encodePublicPaa1(w.statement.oldState),
        },
        newState: w.statement.newState,
        proof: raw,
        statement: w.statement,
        lockKind: "p2s",
        envelope: "consensus",
        slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
        note,
        change: w.created?.note,
      });
      let vm = evaluatePoolSuccessorVm({
        oldState: w.statement.oldState,
        newState: w.statement.newState,
        proof: raw,
        statement: w.statement,
        slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
        standard: true,
        note,
        change: w.created?.note,
      });
      for (let t = 0; t < 48 && (measured.txBytes > 100000 || !vm.accepted); t += 1) {
        const again = proveFri(w.statement, wit);
        raw = encodeFriProof(again);
        measured = compileCovenantSuccessor({
          wallet: createLabWallet(),
          pool: {
            tx_hash: "11".repeat(32),
            tx_pos: 0,
            value: utxoValueFor(w.statement.oldState),
            category: new Uint8Array(32).fill(0x11),
            commitment: encodePublicPaa1(w.statement.oldState),
          },
          newState: w.statement.newState,
          proof: raw,
          statement: w.statement,
          lockKind: "p2s",
          envelope: "consensus",
          slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
          note,
          change: w.created?.note,
        });
        if (measured.txBytes > 100000) continue;
        vm = evaluatePoolSuccessorVm({
          oldState: w.statement.oldState,
          newState: w.statement.newState,
          proof: raw,
          statement: w.statement,
          slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
          standard: true,
          note,
          change: w.created?.note,
        });
      }
      assert.ok(measured.txBytes <= 100000, String(measured.txBytes));
      const tx = decodeTransaction(measured.raw);
      if (typeof tx === "string") throw new Error(tx);
      assert.equal(tx.inputs.length, 18, "18-input successor");
      const body = compilePoolCovenant({ slotKernels: SLOT_KERNEL_COUNT_CONSENSUS });
      const trampoline = compilePoolP2sTrampoline({ slotKernels: SLOT_KERNEL_COUNT_CONSENSUS });
      const bodyHash = hash256(body);
      assert.ok(trampoline.length <= 201, `P2S lock ${trampoline.length} ≤ 201`);
      assert.ok(vm.lockingBytes <= 201, `input 0 scriptPubKey ${vm.lockingBytes} ≤ 201`);
      assert.ok(
        Buffer.from(trampoline).includes(Buffer.from(bodyHash)),
        "P2S lock commits hash256(pool body)",
      );
      assert.equal(measured.lockKind, "p2s");
      const in0 = tx.inputs[0]!.unlockingBytecode;
      assert.ok(in0.length <= 10000, `input 0 unlocking ${in0.length}`);
      assert.equal(firstPushLen(in0), FRI_LEFTOVER_BYTES, "leftover-only first push");
      const in0Body = lastPush(in0);
      assert.deepEqual(Buffer.from(hash256(in0Body)), Buffer.from(bodyHash), "unlocking body matches the committed pool");
      const meters = evaluateSuccessorInputMeters({
        oldState: w.statement.oldState,
        newState: w.statement.newState,
        proof: raw,
        statement: w.statement,
        slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
        standard: true,
        note,
        change: w.created?.note,
      });
      assert.equal(meters.standardTxAccepted, true, meters.standardTxError ?? "meters");
      assert.ok(
        (meters.inputs[0]?.hashDigestIterations ?? 0) < 252,
        `input 0 is not HASH_BIT walks, hash ${meters.inputs[0]?.hashDigestIterations}`,
      );
      const maxUnlock = Math.max(...tx.inputs.map((i) => i.unlockingBytecode.length));
      assert.ok(maxUnlock <= 10000, String(maxUnlock));
      for (const input of tx.inputs) {
        assert.equal(hasPreimage(input.unlockingBytecode, note), false);
        if (w.created) assert.equal(hasPreimage(input.unlockingBytecode, w.created.note), false);
      }
      assert.equal(vm.accepted, true, vm.error ?? "vm");
      const cookedPath = w.path.map((p, i) => {
        if (i !== 0) return p;
        const c = new Uint8Array(p);
        c[0] ^= 1;
        return c;
      });
      const badPath = evaluateNoteAuthKernel({
        oldState: w.statement.oldState,
        newState: w.statement.newState,
        action: 2n,
        note,
        change: w.created?.note,
        spentIndex: d.index,
        spentPath: cookedPath,
        createdIndex: w.created!.index,
        createdPath: w.created!.path,
      });
      assert.equal(badPath.accepted, false, "mutated membership path must VM-reject");
      const cookedNf = { ...w.statement.newState, nullifierRoot: rnd32() };
      const badNf = evaluateNoteAuthKernel({
        oldState: w.statement.oldState,
        newState: cookedNf,
        action: 2n,
        note,
        change: w.created?.note,
        spentIndex: d.index,
        spentPath: w.path,
        createdIndex: w.created!.index,
        createdPath: w.created!.path,
      });
      assert.equal(badNf.accepted, false, "mutated nullifier root must VM-reject");

      const attacker: Note = { amountSats: 1n, rho: rnd32(), ownerSecret: rnd32() };
      const victimOpens = noteAuthPublicOpens({
        note,
        change: w.created?.note,
        action: "WITHDRAW",
        poolInstanceId: w.statement.oldState.poolInstanceId,
      });
      const mixedOpens = {
        leaf: victimOpens.leaf,
        nf: noteAuthPublicOpens({
          note: attacker,
          action: "WITHDRAW",
          poolInstanceId: w.statement.oldState.poolInstanceId,
        }).nf,
        amountCommit: rnd32(),
        createdLeaf: victimOpens.createdLeaf,
      };
      const stolenRoot = sha256(concatBytes(w.statement.oldState.nullifierRoot, mixedOpens.nf));
      const mixedUnlocking = evaluateNoteAuthKernel({
        oldState: w.statement.oldState,
        newState: { ...w.statement.newState, nullifierRoot: stolenRoot },
        action: 2n,
        note,
        change: w.created?.note,
        spentIndex: d.index,
        spentPath: w.path,
        createdIndex: w.created ? w.created.index : 0,
        createdPath: w.created ? w.created.path : [],
        packedOpens: victimOpens,
        unlockOpens: mixedOpens,
        packedNet: new Uint8Array(32),
      });
      assert.equal(mixedUnlocking.accepted, false, "missing hash residual root must VM-reject");
    },
  );

  it(
    "proveFromTLde mixed publics is JS-fail and VM-reject (same-secret, not pin recook)",
    { timeout: 400_000 },
    () => {
      const note: Note = { amountSats: 20_000n, rho: rnd32(), ownerSecret: rnd32() };
      const d = applyDeposit(
        { state: emptyState(rnd32()), notes: new IncrementalMerkle(), nullifiers: new NullifierSet() },
        note,
      );
      const w = applyWithdraw(d.machine, note, d.index, LAB_PAYOUT_DIGEST, 7_777n);
      const wit = wWithdraw(note, d.index, w.path, w.created);
      const proved = proveFri(w.statement, wit);
      const authVictim: FriAuth = {
        ...proved.auth,
        leaf: new Uint8Array(proved.auth.leaf),
        nullifier: new Uint8Array(proved.auth.nullifier),
        amountCommit: new Uint8Array(proved.auth.amountCommit),
        rho: new Uint8Array(proved.auth.rho),
        owner: new Uint8Array(proved.auth.owner),
        createdLeaf: new Uint8Array(proved.auth.createdLeaf),
      };
      const attacker: Note = { amountSats: 1n, rho: rnd32(), ownerSecret: rnd32() };
      const victimOpens = noteAuthPublicOpens({
        note,
        change: w.created?.note,
        action: "WITHDRAW",
        poolInstanceId: w.statement.oldState.poolInstanceId,
      });
      const mixedOpens = {
        leaf: victimOpens.leaf,
        nf: noteAuthPublicOpens({
          note: attacker,
          action: "WITHDRAW",
          poolInstanceId: w.statement.oldState.poolInstanceId,
        }).nf,
        amountCommit: rnd32(),
        createdLeaf: victimOpens.createdLeaf,
      };
      const stolenRoot = sha256(concatBytes(w.statement.oldState.nullifierRoot, mixedOpens.nf));
      const statement2 = {
        ...w.statement,
        nullifier: mixedOpens.nf,
        amountCommitIn: mixedOpens.amountCommit,
        newState: { ...w.statement.newState, nullifierRoot: stolenRoot },
      };
      const auth2 = {
        ...proved.auth,
        nullifier: mixedOpens.nf,
        amountCommit: mixedOpens.amountCommit,
      };
      const { qLde } = algebraicCQuotientLde(statement2, circleDomain(TRACE_LEN), circleDomain(FRI_N));
      const cheat = proveFromTLde(statement2, qLde, auth2);
      const jsCheat = verifyFri(statement2, cheat, wit);
      assert.equal(jsCheat.ok, false, jsCheat.ok ? "js mixed must fail" : jsCheat.reason);
      const mixedUnlock = noteAuthKernelUnlocking({
        note,
        spentIndex: d.index,
        spentPath: w.path,
        createdIndex: w.created ? w.created.index : 0,
        createdPath: w.created ? w.created.path : [],
        poolInstanceId: statement2.oldState.poolInstanceId,
        action: "WITHDRAW",
        opens: mixedOpens,
      });
      const stolen = evaluatePoolSuccessorVm({
        oldState: statement2.oldState,
        newState: statement2.newState,
        outputCommitment: encodePublicPaa1(statement2.newState),
        proof: encodeFriProof(cheat),
        statement: statement2,
        slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
        standard: true,
        note,
        change: w.created?.note,
        noteAuthUnlocking: mixedUnlock,
      });
      assert.equal(
        stolen.accepted,
        false,
        `masked proveFromTLde mixed (encodeFriProof path) must not VM-accept: ${stolen.error}`,
      );

      const pin = noteAuthBindHash(mixedOpens);
      const pinned = proveFromTLde(statement2, qLde, auth2, { hashRoot: pin });
      const jsPinned = verifyFri(statement2, pinned, wit);
      assert.equal(jsPinned.ok, false, jsPinned.ok ? "js pin-mixed must fail" : jsPinned.reason);
      const pinnedVm = evaluatePoolSuccessorVm({
        oldState: statement2.oldState,
        newState: statement2.newState,
        outputCommitment: encodePublicPaa1(statement2.newState),
        proof: encodeFriProof(pinned),
        statement: statement2,
        slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
        standard: true,
        note,
        change: w.created?.note,
        noteAuthUnlocking: mixedUnlock,
      });
      assert.equal(
        pinnedVm.accepted,
        false,
        `masked mixed + matching AIR_OFF_NET pin must not VM-accept: ${pinnedVm.error}`,
      );

      const mixedLeaves = concatBytes(mixedOpens.amountCommit, mixedOpens.leaf, mixedOpens.nf);
      const { qLde: qOccOnly } = algebraicCQuotientLde(
        statement2,
        circleDomain(TRACE_LEN),
        circleDomain(FRI_N),
        undefined,
        auth2,
        undefined,
        undefined,
        undefined,
        true,
      );
      const leafPinned = proveFromTLde(statement2, qOccOnly, auth2, {
        hashRoot: pin,
        hashLeaves: mixedLeaves,
      });
      const jsLeaves = verifyFri(statement2, decodeFriProof(encodeFriProof(leafPinned)));
      assert.equal(jsLeaves.ok, false, jsLeaves.ok ? "js mixed-leaves must fail" : jsLeaves.reason);
      assert.equal(jsLeaves.reason, "sha-in-c residuals", `mixed-leaves JS reason: ${jsLeaves.reason}`);
      const leavesVm = evaluatePoolSuccessorVm({
        oldState: statement2.oldState,
        newState: statement2.newState,
        outputCommitment: encodePublicPaa1(statement2.newState),
        proof: encodeFriProof(leafPinned),
        statement: statement2,
        slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
        standard: true,
        note,
        change: w.created?.note,
        noteAuthUnlocking: mixedUnlock,
      });
      assert.equal(
        leavesVm.accepted,
        false,
        `masked mixed + matching pin + matching hashLeaves must not VM-accept: ${leavesVm.error}`,
      );
      assert.equal(
        /input index 11\b/.test(String(leavesVm.error)),
        false,
        `matching mixedLeaves must not be note-auth: ${leavesVm.error}`,
      );

      const zeros = Array.from({ length: TRACE_LEN }, () => 0n);
      const honestLeaves = concatBytes(authVictim.amountCommit, authVictim.leaf, authVictim.nullifier);
      assert.ok(
        shaStatementResiduals(statement2, proved.shaTrace, undefined, authVictim.leaf).some((x) => x !== 0n),
        "mixed statement vs victim TRACE must not vanish",
      );
      const matchLeavesOcc = proveFromTLde(statement2, qOccOnly, auth2, {
        hashRoot: pin,
        hashLeaves: mixedLeaves,
        shaResiduals: zeros,
      });
      const matchRaw = encodeFriProof(matchLeavesOcc);
      const matchJs = verifyFri(statement2, decodeFriProof(matchRaw));
      assert.equal(matchJs.ok, false, matchJs.ok ? "js matching mixedLeaves occupancy must fail" : matchJs.reason);
      assert.equal(matchJs.reason, "sha-in-c residuals", `matching mixedLeaves JS: ${matchJs.reason}`);
      const matchVm = evaluatePoolSuccessorVm({
        oldState: statement2.oldState,
        newState: statement2.newState,
        outputCommitment: encodePublicPaa1(statement2.newState),
        proof: matchRaw,
        statement: statement2,
        slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
        standard: true,
        note,
        change: w.created?.note,
        noteAuthUnlocking: mixedUnlock,
      });
      assert.equal(matchVm.accepted, false, `matching mixedLeaves occupancy must VM-reject: ${matchVm.error}`);
      assert.equal(
        /input index 11\b/.test(String(matchVm.error)),
        false,
        `matching mixedLeaves occupancy must not be note-auth: ${matchVm.error}`,
      );

      const recookZeros = proveFromTLde(statement2, qOccOnly, auth2, {
        hashRoot: pin,
        hashLeaves: honestLeaves,
        shaResiduals: zeros,
      });
      assert.ok(
        !(recookZeros.shaResiduals ?? []).some((x) => x !== 0n),
        "proveFromTLde must not overwrite caller zeros cargo",
      );
      const jsRecook = verifyFri(statement2, decodeFriProof(encodeFriProof(recookZeros)));
      assert.equal(jsRecook.ok, false, jsRecook.ok ? "js skeptic recook must fail" : jsRecook.reason);
      assert.equal(jsRecook.reason, "sha-in-c residuals", `skeptic JS reason: ${jsRecook.reason}`);
      const recookVm = evaluatePoolSuccessorVm({
        oldState: statement2.oldState,
        newState: statement2.newState,
        outputCommitment: encodePublicPaa1(statement2.newState),
        proof: encodeFriProof(recookZeros),
        statement: statement2,
        slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
        standard: true,
        note,
        change: w.created?.note,
        noteAuthUnlocking: mixedUnlock,
      });
      assert.equal(
        recookVm.accepted,
        false,
        `skeptic occupancy qLde + honest tags + zeros cargo must VM-reject on SHA-in-C: ${recookVm.error}`,
      );

      const occMasked = proveFromTLde(statement2, qOccOnly, auth2, {
        hashRoot: pin,
        hashLeaves: honestLeaves,
        shaResiduals: zeros,
      });
      const decodedMasked = decodeFriProof(encodeFriProof(occMasked));
      assert.equal(decodedMasked.authMasked, true, "encodeFriProof masks rho/owner/amount");
      decodedMasked.shaResiduals = zeros;
      decodedMasked.hashLeaves = honestLeaves;
      const maskedRaw = encodeFriProof({ ...decodedMasked, authMasked: true });
      const maskedProof = decodeFriProof(maskedRaw);
      const maskedMix = shaMixForOccupancyC(
        statement2,
        defaultInternalHash(),
        maskedProof.auth,
        maskedProof.shaResiduals,
        maskedProof.hashLeaves,
        maskedProof.shaTrace,
      );
      assert.ok(
        maskedMix.some((x) => x !== 0n),
        "masked occupancy recook: TRACE vs mixed statement must stay in C",
      );
      const jsMasked = verifyFri(statement2, maskedProof);
      assert.equal(jsMasked.ok, false, jsMasked.ok ? "js masked skeptic recook must fail" : jsMasked.reason);
      assert.equal(jsMasked.reason, "sha-in-c residuals", `masked skeptic JS reason: ${jsMasked.reason}`);
      const maskedVm = evaluatePoolSuccessorVm({
        oldState: statement2.oldState,
        newState: statement2.newState,
        outputCommitment: encodePublicPaa1(statement2.newState),
        proof: maskedRaw,
        statement: statement2,
        slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
        standard: true,
        note,
        change: w.created?.note,
        noteAuthUnlocking: mixedUnlock,
      });
      assert.equal(
        maskedVm.accepted,
        false,
        `masked auth + shaResiduals=zeros + honest hashLeaves + occupancy qLde must not skip SHA-in-C: ${maskedVm.error}`,
      );

      const occDecoded = decodeFriProof(encodeFriProof(matchLeavesOcc));
      occDecoded.shaTrace = undefined;
      const occPacked = encodeAirPacked(statement2, occDecoded);
      const jsOccPacked = verifyFri(statement2, occDecoded);
      assert.equal(jsOccPacked.ok, false, jsOccPacked.ok ? "js occupancy-only packed must fail" : jsOccPacked.reason);
      assert.equal(jsOccPacked.reason, "sha-in-c residuals", `occupancy-only packed JS: ${jsOccPacked.reason}`);
      const occPackedVm = evaluatePoolSuccessorVm({
        oldState: statement2.oldState,
        newState: statement2.newState,
        outputCommitment: encodePublicPaa1(statement2.newState),
        proof: encodeFriProof(matchLeavesOcc),
        airPacked: occPacked,
        statement: statement2,
        slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
        standard: true,
        note,
        change: w.created?.note,
        noteAuthUnlocking: mixedUnlock,
      });
      assert.equal(
        occPackedVm.accepted,
        false,
        `occupancy-only packed AIR must VM-reject on SHA N: ${occPackedVm.error}`,
      );
      assert.equal(
        /input index 11\b/.test(String(occPackedVm.error)),
        false,
        `occupancy-only packed reject must not be note-auth: ${occPackedVm.error}`,
      );

      const slicedRaw = encodeFriProof(matchLeavesOcc).subarray(
        0,
        encodeFriProof(matchLeavesOcc).length - HASH_BIT_ROWS_BYTES,
      );
      const slicedDec = decodeFriProof(slicedRaw);
      const slicedPacked = encodeAirPacked(statement2, slicedDec);
      const slicedJs = verifyFri(statement2, slicedDec);
      assert.equal(slicedJs.ok, false, slicedJs.ok ? "js TRACE-sliced must fail" : slicedJs.reason);
      const slicedVm = evaluatePoolSuccessorVm({
        oldState: statement2.oldState,
        newState: statement2.newState,
        outputCommitment: encodePublicPaa1(statement2.newState),
        proof: slicedRaw,
        airPacked: slicedPacked,
        statement: statement2,
        slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
        standard: true,
        note,
        change: w.created?.note,
        noteAuthUnlocking: mixedUnlock,
      });
      assert.equal(slicedVm.accepted, false, `TRACE-sliced packed AIR must VM-reject: ${slicedVm.error}`);

      const acc = shaPubsAcc(statementShaOpens(statement2, mixedOpens.leaf));
      const openBlob = new Uint8Array(FRI_QUERIES * 4);
      for (let s = 0; s < FRI_QUERIES; s += 1) openBlob.set(encodeLe(acc), s * 4);
      const fakeRoot = sha256(openBlob);
      const accRecook = proveFromTLde(statement2, qOccOnly, auth2, {
        hashRoot: pin,
        hashLeaves: mixedLeaves,
        hashBitRoot: fakeRoot,
      });
      const accPacked = encodeAirPacked(statement2, accRecook);
      accPacked.set(openBlob, AIR_OFF_SHA_C);
      accPacked.set(fakeRoot, AIR_OFF_HASHBIT);
      const accVm = evaluatePoolSuccessorVm({
        oldState: statement2.oldState,
        newState: statement2.newState,
        outputCommitment: encodePublicPaa1(statement2.newState),
        proof: encodeFriProof(accRecook),
        airPacked: accPacked,
        statement: statement2,
        slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
        standard: true,
        note,
        change: w.created?.note,
        noteAuthUnlocking: mixedUnlock,
      });
      assert.equal(
        accVm.accepted,
        false,
        `openings=statementAcc occupancy recook must VM-reject: ${accVm.error}`,
      );
      assert.equal(
        /input index 11\b/.test(String(accVm.error)),
        false,
        `openings=statementAcc reject must not be note-auth: ${accVm.error}`,
      );

      const small = circleDomain(TRACE_LEN);
      const big = circleDomain(FRI_N);
      const hash = defaultInternalHash();
      const occQ = algebraicCQuotientLde(statement2, small, big, hash, auth2, undefined, undefined, undefined, true);
      const shaR = shaMixForOccupancyC(statement2, hash, auth2, undefined, undefined, undefined, false);
      const shaQ = quotientAtDomain(shaR, small, big).qLde;
      const cancelled = occQ.qLde.map((q, i) => sub(q, shaQ[i]!));
      const occLeftover = proveFromTLde(statement2, occQ.qLde, auth2, {
        hashRoot: pin,
        hashLeaves: mixedLeaves,
        occupancyOnly: true,
      });
      const callerOcc = proveFromTLde(statement2, occQ.qLde, auth2, {
        hashRoot: pin,
        hashLeaves: mixedLeaves,
        occupancyOnly: true,
        useCallerTLde: true,
      });
      const callerPacked = recookOccupancyPacked(statement2, encodeAirPacked(statement2, callerOcc));
      const callerJs = verifyFri(statement2, callerOcc);
      assert.equal(callerJs.ok, false, callerJs.ok ? "js caller occupancy leftover mixed must fail" : callerJs.reason);
      const callerVm = evaluatePoolSuccessorVm({
        oldState: statement2.oldState,
        newState: statement2.newState,
        outputCommitment: encodePublicPaa1(statement2.newState),
        proof: encodeFriProof(callerOcc),
        airPacked: callerPacked,
        statement: statement2,
        slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
        standard: false,
        note,
        change: w.created?.note,
        noteAuthUnlocking: mixedUnlock,
      });
      assert.equal(
        callerVm.accepted,
        false,
        `useCallerTLde occupancy leftover + occupancy packed must VM-reject on miner C_SHA: ${callerVm.error}`,
      );
      assert.equal(
        /input index 11\b/.test(String(callerVm.error)),
        false,
        `useCallerTLde occupancy leftover reject must not be note-auth: ${callerVm.error}`,
      );
      assert.equal(
        /input index 1\b/.test(String(callerVm.error)),
        false,
        `occupancy leftover merkle must pass; reject is miner N not leftover-bind: ${callerVm.error}`,
      );
      assert.equal(
        /input index 12\b/.test(String(callerVm.error)),
        true,
        `occupancy leftover reject is fused SHA-in-C input 12: ${callerVm.error}`,
      );
      assert.equal(/input index 10\b/.test(String(callerVm.error)), false, `not algebraicC 10: ${callerVm.error}`);
      const occPackedQ = recookOccupancyPacked(statement2, encodeAirPacked(statement2, occLeftover));
      const occN0Js = verifyFri(statement2, occLeftover);
      assert.equal(occN0Js.ok, false, occN0Js.ok ? "js occupancy leftover mixed must fail" : occN0Js.reason);
      const occN0Vm = evaluatePoolSuccessorVm({
        oldState: statement2.oldState,
        newState: statement2.newState,
        outputCommitment: encodePublicPaa1(statement2.newState),
        proof: encodeFriProof(occLeftover),
        airPacked: occPackedQ,
        statement: statement2,
        slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
        standard: false,
        note,
        change: w.created?.note,
        noteAuthUnlocking: mixedUnlock,
      });
      assert.equal(
        occN0Vm.accepted,
        false,
        `occupancy leftover + occupancy packed must VM-reject on miner C_SHA: ${occN0Vm.error}`,
      );
      assert.equal(
        /input index 11\b/.test(String(occN0Vm.error)),
        false,
        `occupancy leftover N reject must not be note-auth: ${occN0Vm.error}`,
      );
      assert.equal(
        /input index 1\b/.test(String(occN0Vm.error)),
        false,
        `occupancy leftover merkle must pass; reject is miner N: ${occN0Vm.error}`,
      );
      assert.equal(
        /input index 12\b/.test(String(occN0Vm.error)),
        true,
        `occupancy leftover reject is fused SHA-in-C input 12: ${occN0Vm.error}`,
      );
      assert.match(String(occN0Vm.error), /OP_VERIFY/, `occupancy leftover must NUMEQUALVERIFY, not density: ${occN0Vm.error}`);
      assert.equal(/input index 10\b/.test(String(occN0Vm.error)), false, `not algebraicC 10: ${occN0Vm.error}`);
      assert.equal(/density|operation cost/i.test(String(occN0Vm.error)), false, `not density: ${occN0Vm.error}`);

      const zeroInterp = new Uint8Array(occPackedQ);
      zeroInterp.fill(0, AIR_OFF_SHA_C, AIR_OFF_SHA_C + AIR_SHA_C_BYTES);
      const zeroVm = evaluatePoolSuccessorVm({
        oldState: statement2.oldState,
        newState: statement2.newState,
        outputCommitment: encodePublicPaa1(statement2.newState),
        proof: encodeFriProof(occLeftover),
        airPacked: zeroInterp,
        statement: statement2,
        slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
        standard: false,
        note,
        change: w.created?.note,
        noteAuthUnlocking: mixedUnlock,
      });
      assert.equal(zeroVm.accepted, false, `zeros interpolant must VM-reject: ${zeroVm.error}`);
      assert.equal(/input index 11\b/.test(String(zeroVm.error)), false, `zeros interpolant not note-auth: ${zeroVm.error}`);
      assert.equal(
        /input index 12\b/.test(String(zeroVm.error)),
        true,
        `zeros interpolant reject is fused SHA-in-C input 12: ${zeroVm.error}`,
      );
      assert.equal(/input index 10\b/.test(String(zeroVm.error)), false, `not algebraicC 10: ${zeroVm.error}`);

      const recookOpen = new Uint8Array(occPackedQ);
      recookOpen.fill(0, AIR_OFF_SHA_OPEN, AIR_OFF_SHA_OPEN + AIR_SHA_OPEN_BYTES);
      const recookOpenVm = evaluatePoolSuccessorVm({
        oldState: statement2.oldState,
        newState: statement2.newState,
        outputCommitment: encodePublicPaa1(statement2.newState),
        proof: encodeFriProof(occLeftover),
        airPacked: recookOpen,
        statement: statement2,
        slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
        standard: false,
        note,
        change: w.created?.note,
        noteAuthUnlocking: mixedUnlock,
      });
      assert.equal(recookOpenVm.accepted, false, `openings recook to 0 must VM-reject: ${recookOpenVm.error}`);
      assert.equal(/input index 11\b/.test(String(recookOpenVm.error)), false, `openings recook not note-auth: ${recookOpenVm.error}`);
      assert.equal(
        /input index 10\b/.test(String(recookOpenVm.error)),
        true,
        `zeros 144 B without zeros-column hashBitRoot is algebraicC grind-bind: ${recookOpenVm.error}`,
      );

      const jointRecook = new Uint8Array(occPackedQ);
      jointRecook.fill(0, AIR_OFF_SHA_C, AIR_OFF_SHA_C + AIR_SHA_C_BYTES);
      jointRecook.fill(0, AIR_OFF_SHA_OPEN, AIR_OFF_SHA_OPEN + AIR_SHA_OPEN_BYTES);
      const jointVm = evaluatePoolSuccessorVm({
        oldState: statement2.oldState,
        newState: statement2.newState,
        outputCommitment: encodePublicPaa1(statement2.newState),
        proof: encodeFriProof(occLeftover),
        airPacked: jointRecook,
        statement: statement2,
        slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
        standard: false,
        note,
        change: w.created?.note,
        noteAuthUnlocking: mixedUnlock,
      });
      assert.equal(jointVm.accepted, false, `joint interpolant+openings recook must VM-reject: ${jointVm.error}`);
      assert.equal(/input index 11\b/.test(String(jointVm.error)), false, `joint recook not note-auth: ${jointVm.error}`);
      assert.equal(
        /input index 10\b/.test(String(jointVm.error)),
        true,
        `joint zeros openings without zeros-column hashBitRoot is algebraicC grind-bind: ${jointVm.error}`,
      );

      const recookOut = new Uint8Array(zeroInterp);
      recookOut.set(
        recookOut.subarray(AIR_OFF_CELLS + HASH_CELL_COMMIT * 4, AIR_OFF_CELLS + HASH_CELL_COMMIT * 4 + AIR_SHA_OUT_BYTES),
        AIR_OFF_SHA_ACC,
      );
      const recookOutVm = evaluatePoolSuccessorVm({
        oldState: statement2.oldState,
        newState: statement2.newState,
        outputCommitment: encodePublicPaa1(statement2.newState),
        proof: encodeFriProof(occLeftover),
        airPacked: recookOut,
        statement: statement2,
        slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
        standard: false,
        note,
        change: w.created?.note,
        noteAuthUnlocking: mixedUnlock,
      });
      assert.equal(recookOutVm.accepted, false, `zeros interpolant + TRACE_OUT=pubs must VM-reject: ${recookOutVm.error}`);
      assert.equal(/input index 11\b/.test(String(recookOutVm.error)), false, `TRACE_OUT recook not note-auth: ${recookOutVm.error}`);
      assert.equal(
        /input index 12\b/.test(String(recookOutVm.error)),
        true,
        `TRACE_OUT recook reject is fused SHA-in-C input 12: ${recookOutVm.error}`,
      );
      assert.equal(/input index 10\b/.test(String(recookOutVm.error)), false, `not algebraicC 10: ${recookOutVm.error}`);

      const jsStrip = verifyFri(w.statement, { ...proved, shaTrace: undefined });
      assert.equal(jsStrip.ok, false, jsStrip.ok ? "js missing TRACE must fail" : jsStrip.reason);
      const strippedPacked = new Uint8Array(encodeAirPacked(w.statement, proved));
      const missingTraceR = shaStatementResiduals(w.statement, undefined, undefined, proved.auth.leaf, false);
      const missingInterp = interpolateCircle(circleDomain(TRACE_LEN), missingTraceR);
      const missingBig = circleDomain(FRI_N);
      for (let s = 0; s < FRI_QUERIES; s += 1) {
        const i = (strippedPacked[AIR_OFF_IDX + s * 2]! << 8) | strippedPacked[AIR_OFF_IDX + s * 2 + 1]!;
        strippedPacked.set(encodeLe(evalCirclePoly(missingInterp, missingBig[i]!)), AIR_OFF_SHA_OPEN + s * 4);
      }
      const stripVm = evaluatePoolSuccessorVm({
        oldState: w.statement.oldState,
        newState: w.statement.newState,
        outputCommitment: encodePublicPaa1(w.statement.newState),
        proof: encodeFriProof(proved),
        airPacked: strippedPacked,
        statement: w.statement,
        slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
        standard: false,
        note,
        change: w.created?.note,
      });
      assert.equal(stripVm.accepted, false, `missing TRACE must VM-reject: ${stripVm.error}`);
      assert.equal(/input index 11\b/.test(String(stripVm.error)), false, `missing TRACE not note-auth: ${stripVm.error}`);
      assert.equal(/input index 1\b/.test(String(stripVm.error)), false, `missing TRACE leftover merkle must pass: ${stripVm.error}`);
      assert.equal(
        /input index 12\b/.test(String(stripVm.error)),
        true,
        `missing TRACE reject is fused SHA-in-C input 12: ${stripVm.error}`,
      );

      const copiedBits = proveFromTLde(statement2, qOccOnly, auth2, {
        hashRoot: pin,
        hashLeaves: mixedLeaves,
        hashBitRoot: proved.hashBitRoot,
        hashBitLde: proved.hashBitLde,
      });
      const copiedVm = evaluatePoolSuccessorVm({
        oldState: statement2.oldState,
        newState: statement2.newState,
        outputCommitment: encodePublicPaa1(statement2.newState),
        proof: encodeFriProof(copiedBits),
        statement: statement2,
        slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
        standard: true,
        note,
        change: w.created?.note,
        noteAuthUnlocking: mixedUnlock,
      });
      assert.equal(
        copiedVm.accepted,
        false,
        `copied honest SHA-bit rows + mixed hashLeaves must not VM-accept: ${copiedVm.error}`,
      );

      const h = defaultInternalHash();
      const junkBits = mixedJunkBits({
        statement: statement2,
        qLde: qOccOnly,
        auth: auth2,
        pin,
        mixedLeaves,
        mixedOpens,
        hash: h,
      });
      const jsJunk = verifyFri(statement2, junkBits, wit);
      assert.equal(jsJunk.ok, false, jsJunk.ok ? "js junk-bits must fail" : jsJunk.reason);
      const junkVm = evaluatePoolSuccessorVm({
        oldState: statement2.oldState,
        newState: statement2.newState,
        outputCommitment: encodePublicPaa1(statement2.newState),
        proof: encodeFriProof(junkBits),
        statement: statement2,
        slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
        standard: true,
        note,
        change: w.created?.note,
        noteAuthUnlocking: mixedUnlock,
      });
      assert.equal(
        junkVm.accepted,
        false,
        `junk SHA-LDE vector + mixed hashLeaves must not VM-accept: ${junkVm.error}`,
      );

      const occJunk = mixedJunkBits({
        statement: statement2,
        qLde: qOccOnly,
        auth: auth2,
        pin,
        mixedLeaves,
        mixedOpens,
        hash: h,
      });
      const jsOccJunk = verifyFri(statement2, occJunk, wit);
      assert.equal(jsOccJunk.ok, false, jsOccJunk.ok ? "js occupancyQ-junk must fail" : jsOccJunk.reason);
      const occJunkVm = evaluatePoolSuccessorVm({
        oldState: statement2.oldState,
        newState: statement2.newState,
        outputCommitment: encodePublicPaa1(statement2.newState),
        proof: encodeFriProof(occJunk),
        statement: statement2,
        slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
        standard: true,
        note,
        change: w.created?.note,
        noteAuthUnlocking: mixedUnlock,
      });
      assert.equal(
        occJunkVm.accepted,
        false,
        `occupancy-only Q + matching pin/hashLeaves/junk merkle must not VM-accept: ${occJunkVm.error}`,
      );
    },
  );
});

import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  decodeFriProof,
  encodeFriProof,
  mutateTraceAndProve,
  proveFri,
  verifyFri,
  wDeposit,
  wWithdraw,
} from "../src/backends/circle/fri.ts";
import { CONJECTURAL_BITS, FRI_QUERIES, FRI_VERSION, GRIND_BITS } from "../src/backends/circle/params.ts";
import { encodeLe, mul } from "../src/backends/circle/m31.ts";
import { openingMaskAt } from "../src/backends/circle/witness-mask.ts";
import { DEFAULT_INTERNAL_HASH_ID, defaultInternalHash } from "../src/backends/circle/internal-hash.ts";
import { encodeStatement } from "../src/pool/statement.ts";
import { sha256 } from "../src/pool/bytes.ts";
import {
  AIR_NEWTON_BYTES,
  AIR_OFF_EVEN,
  AIR_OFF_NONCE,
  AIR_OFF_NTABLE,
  AIR_OFF_ODD,
  AIR_OFF_OPEN_MASK,
  AIR_OFF_QTABLE,
  SLOT_KERNEL_COUNT,
  SLOT_KERNEL_COUNT_CONSENSUS,
  compileSlotsKernel,
  encodeAirPacked,
  fiatShamirQueryIndices,
  nqzAt,
} from "../src/chain/air-cqz.ts";
import { collectFriOpenings, friShardUnlockings, openingPairsBlob } from "../src/chain/fri-openings.ts";
import { applyDeposit, applyWithdraw } from "../src/pool/transition.ts";
import { IncrementalMerkle, NullifierSet, type Note } from "../src/pool/notes.ts";
import { emptyState } from "../src/pool/state.ts";
import { LAB_PAYOUT_DIGEST } from "../src/chain/payout.ts";
import { compileGrindKernel, grindKernelUnlocking } from "../src/chain/grind-kernel.ts";
import { compileAlgebraicCKernel, algebraicCKernelUnlocking } from "../src/chain/algebraic-c-kernel.ts";
import { compileNoteAuthKernel } from "../src/chain/note-auth-kernel.ts";
import { compilePoolCovenant } from "../src/chain/covenant-p2s.ts";
import { compileCovenantSuccessor } from "../src/chain/covenant-spend.ts";
import { createLabWallet } from "../src/chain/wallet.ts";
import { encodePublicPaa1, utxoValueFor } from "../src/pool/state.ts";
import { CONSENSUS_TX_BYTES, RELAY_STANDARD_TX_BYTES, UNLOCKING_MAX_BYTES } from "../src/chain/envelope.ts";
import { evaluateFriQueryOpening, evaluatePoolSuccessorVm } from "../src/chain/vm-verifier.ts";
import { compactLayerKernelAsm, compileFriQueryKernel, FRI_KERNEL_INPUTS } from "../src/chain/fri-kernel.ts";
import { COMMITTED_LAYERS } from "../src/backends/circle/params.ts";
import { FOLD_PAIR_ASM, foldQueriesAsm } from "../src/chain/fold-asm.ts";
import { FOLD_QUERIES_PER_KERNEL, FOLD_KERNEL_COUNT_CONSENSUS, foldKernelAsm } from "../src/chain/fold-kernel.ts";
import { buildLayerProofs, encodeLayerUnlocking } from "../src/chain/merkle-multiproof.ts";
import { decodeTransaction } from "@bitauth/libauth";

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
    } else {
      i += 1;
    }
  }
  return last;
}

function dummy22Prefix(u: Uint8Array): number {
  if (u.length < 2) return 0;
  const op = u[0]!;
  let n = 0;
  let off = 1;
  if (op > 0 && op <= 75) n = op;
  else if (op === 0x4c && u.length >= 2) {
    n = u[1]!;
    off = 2;
  } else if (op === 0x4d && u.length >= 3) {
    n = u[1]! | (u[2]! << 8);
    off = 3;
  } else return 0;
  if (n < 1 || off + n > u.length) return 0;
  const body = u.subarray(off, off + n);
  return body.every((b) => b === 0x22) ? n : 0;
}

function mix() {
  const note: Note = {
    amountSats: 20_000n,
    rho: crypto.getRandomValues(new Uint8Array(32)),
    ownerSecret: crypto.getRandomValues(new Uint8Array(32)),
  };
  const d = applyDeposit(
    { state: emptyState(crypto.getRandomValues(new Uint8Array(32))), notes: new IncrementalMerkle(), nullifiers: new NullifierSet() },
    note,
  );
  const w = applyWithdraw(d.machine, note, d.index, LAB_PAYOUT_DIGEST, 7_777n);
  const proof = encodeFriProof(proveFri(w.statement, wWithdraw(note, d.index, w.path, w.created)));
  return { w, proof, note, d, change: w.created?.note };
}

describe("hole-free statistical-soundness kernels (B)", () => {
  it("B is 36 unique-orbit Circle FRI M31, FRI_VERSION 9, not a second family", () => {
    assert.equal(FRI_VERSION, 9);
    assert.equal(FRI_QUERIES, 36);
    assert.equal(SLOT_KERNEL_COUNT_CONSENSUS * 6, FRI_QUERIES);
    assert.equal(FOLD_KERNEL_COUNT_CONSENSUS * FOLD_QUERIES_PER_KERNEL, FRI_QUERIES);
    assert.ok(SLOT_KERNEL_COUNT < FRI_QUERIES, "A may chunk fewer slots; B keeps 36");
  });

  it("grind and algebraicC redeems stay under 10 KB", () => {
    const g = compileGrindKernel();
    const a = compileAlgebraicCKernel();
    assert.ok(g.length > 40);
    assert.ok(a.length > 40);
    assert.ok(g.length <= UNLOCKING_MAX_BYTES, `grind redeem ${g.length}`);
    assert.ok(a.length <= UNLOCKING_MAX_BYTES, `algebraicC redeem ${a.length}`);
    assert.ok(grindKernelUnlocking().length <= UNLOCKING_MAX_BYTES);
    assert.ok(algebraicCKernelUnlocking().length <= UNLOCKING_MAX_BYTES);
    const noteAuth = compileNoteAuthKernel();
    assert.ok(noteAuth.length <= UNLOCKING_MAX_BYTES, `note-auth redeem ${noteAuth.length}`);
    const r6 = compilePoolCovenant({ slotKernels: SLOT_KERNEL_COUNT });
    const r36 = compilePoolCovenant({ slotKernels: SLOT_KERNEL_COUNT_CONSENSUS });
    assert.ok(r6.length <= UNLOCKING_MAX_BYTES, `standard-slot redeem ${r6.length}`);
    assert.ok(r36.length <= UNLOCKING_MAX_BYTES, `36-slot redeem ${r36.length}`);
    const fri = compileFriQueryKernel();
    assert.ok(fri.length <= UNLOCKING_MAX_BYTES, `FRI kernel ${fri.length}`);
    assert.ok(foldQueriesAsm(1).includes(String(COMMITTED_LAYERS)), "fold kernel walks every FRI layer");
  });

  it("honest 36-query B successor VM-accepts with grind + algebraicC", () => {
    const { w, proof, note, change } = mix();
    const ev = evaluatePoolSuccessorVm({
      oldState: w.statement.oldState,
      newState: w.statement.newState,
      proof,
      statement: w.statement,
      slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
      standard: false,
      note,
      change,
    });
    assert.equal(ev.accepted, true, ev.error ?? "honest B");
  });

  it("36-query B rejects cooked viewing-commit, recooked Q/N, and cooked pair blob", () => {
    const { w, proof, note, change } = mix();
    const base = {
      oldState: w.statement.oldState,
      newState: w.statement.newState,
      proof,
      statement: w.statement,
      slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
      standard: false as const,
      note,
      change,
    };
    const packed = encodeAirPacked(w.statement, proof);
    const cookCommit = new Uint8Array(packed);
    cookCommit[AIR_OFF_OPEN_MASK] ^= 0xff;
    const commitEv = evaluatePoolSuccessorVm({ ...base, airPacked: cookCommit });
    assert.equal(commitEv.accepted, false, "cooked viewing-commit must fail on-chain R");

    const decoded = decodeFriProof(proof);
    const i0 = fiatShamirQueryIndices(
      sha256(encodeStatement(w.statement)),
      decoded,
      defaultInternalHash(),
      packed.subarray(AIR_OFF_EVEN, AIR_OFF_EVEN + AIR_NEWTON_BYTES),
      packed.subarray(AIR_OFF_ODD, AIR_OFF_ODD + AIR_NEWTON_BYTES),
    )[0]!;
    const nqz = nqzAt(w.statement, i0);
    if (nqz.z !== 0n) {
      const r = openingMaskAt(decoded.viewingCommit ?? new Uint8Array(32), i0, undefined, nqz.z);
      const qPrime = (nqz.q + r + 1n) % 2147483647n;
      const nPrime = mul(qPrime, nqz.z);
      const cookQn = new Uint8Array(packed);
      cookQn.set(encodeLe(qPrime), AIR_OFF_QTABLE);
      cookQn.set(encodeLe(nPrime), AIR_OFF_NTABLE);
      const qnEv = evaluatePoolSuccessorVm({ ...base, airPacked: cookQn });
      assert.equal(qnEv.accepted, false, "masked-consistent recook of Q/N must fail independent N");
    }

    const pairs = openingPairsBlob(collectFriOpenings(proof));
    pairs[0] ^= 0xff;
    const cookedPacked = new Uint8Array(packed.length + pairs.length);
    cookedPacked.set(packed);
    cookedPacked.set(pairs, packed.length);
    const blobEv = evaluatePoolSuccessorVm({
      ...base,
      airPacked: cookedPacked,
    });
    assert.equal(blobEv.accepted, false, "cooked pair blob with honest Merkle left||right must fail");
  });

  it("A still fits 100 KB after grind + algebraicC; B holds FRI9 completeness in one standard tx", () => {
    const { w, proof, note, change } = mix();
    const pool = {
      tx_hash: "11".repeat(32),
      tx_pos: 0,
      value: utxoValueFor(w.statement.oldState),
      category: new Uint8Array(32).fill(0x11),
      commitment: encodePublicPaa1(w.statement.oldState),
    };
    const A = compileCovenantSuccessor({
      wallet: createLabWallet(),
      pool,
      newState: w.statement.newState,
      proof,
      statement: w.statement,
      lockKind: "p2sh32",
      envelope: "standard",
    });
    const B = compileCovenantSuccessor({
      wallet: createLabWallet(),
      pool,
      newState: w.statement.newState,
      proof,
      statement: w.statement,
      lockKind: "p2sh32",
      envelope: "consensus",
      slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
      note,
      change,
    });
    assert.ok(A.txBytes <= RELAY_STANDARD_TX_BYTES, `A ${A.txBytes}`);
    assert.ok(A.unlockingBytes <= UNLOCKING_MAX_BYTES);
    assert.ok(B.txBytes <= RELAY_STANDARD_TX_BYTES, `B ${B.txBytes}`);
    assert.ok(B.unlockingBytes <= UNLOCKING_MAX_BYTES);
    assert.equal(FRI_VERSION, 9);
    assert.equal(FRI_QUERIES, 36);
    assert.equal(DEFAULT_INTERNAL_HASH_ID, "sha256");
    const headroom = CONSENSUS_TX_BYTES - B.txBytes;
    assert.ok(headroom > 0, "B leftover is unused envelope, not OP_DROP cargo");
    console.log(`size-proof A=${A.txBytes} B=${B.txBytes} headroom=${headroom} Aunlock=${A.unlockingBytes} Bunlock=${B.unlockingBytes}`);
  });

  it("full-completeness B successor is one standard 100 KB tx", () => {
    const { w, proof, note, change } = mix();
    const B = compileCovenantSuccessor({
      wallet: createLabWallet(),
      pool: {
        tx_hash: "11".repeat(32),
        tx_pos: 0,
        value: utxoValueFor(w.statement.oldState),
        category: new Uint8Array(32).fill(0x11),
        commitment: encodePublicPaa1(w.statement.oldState),
      },
      newState: w.statement.newState,
      proof,
      statement: w.statement,
      lockKind: "p2sh32",
      envelope: "consensus",
      slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
      note,
      change,
    });
    assert.ok(B.txBytes <= RELAY_STANDARD_TX_BYTES, `B ${B.txBytes}`);
    const tx = decodeTransaction(B.raw);
    if (typeof tx === "string") throw new Error(tx);
    const unlockingLens = tx.inputs.map((i) => i.unlockingBytecode.length);
    const maxUnlocking = Math.max(...unlockingLens);
    assert.ok(maxUnlocking <= UNLOCKING_MAX_BYTES, `max unlocking ${maxUnlocking}`);
    const redeemLens = tx.inputs.map((i) => lastPush(i.unlockingBytecode).length);
    const maxRedeem = Math.max(...redeemLens);
    assert.ok(maxRedeem <= UNLOCKING_MAX_BYTES, `max redeem ${maxRedeem}`);
    const padSum = tx.inputs.reduce((n, i) => n + dummy22Prefix(i.unlockingBytecode), 0);
    assert.equal(padSum, 0, "no 0x22 leftover-fill prefix on any unlocking");
    const layerProofs = buildLayerProofs(collectFriOpenings(proof));
    assert.equal(FRI_KERNEL_INPUTS, COMMITTED_LAYERS);
    for (let layer = 0; layer < COMMITTED_LAYERS; layer += 1) {
      const want = encodeLayerUnlocking(layerProofs[layer]!, compileFriQueryKernel(layer));
      const got = tx.inputs[1 + layer]!.unlockingBytecode;
      assert.equal(got.length, want.length, `merkle layer ${layer} unlocking length`);
      assert.deepEqual(Buffer.from(got), Buffer.from(want), `merkle layer ${layer} is table+openings+redeem only`);
    }
    for (const layer of [4, 5, 6]) {
      const fetch = compactLayerKernelAsm(layer).split("OP_BEGIN")[0]!;
      assert.ok(fetch.includes("OP_INPUTBYTECODE"), `layer ${layer} fetches input 0`);
      assert.ok(!fetch.includes("OP_PICK"), `layer ${layer} fetch has no extraBottom PICK`);
      assert.ok(!fetch.includes("OP_DUP"), `layer ${layer} does not DUP packed onto alt`);
    }
    assert.ok(FOLD_PAIR_ASM.includes("OP_NUMEQUALVERIFY"), "foldPair runs in-script");
    assert.ok(foldKernelAsm(6).includes("OP_INVOKE"), "fold kernels INVOKE foldPair");
    const slots = compileSlotsKernel(0, 6);
    assert.ok(slots.length > 200, "on-chain R slot redeem is not a digest");
    const noteAuth = compileNoteAuthKernel();
    assert.ok(noteAuth.length > 40, "note-auth redeem is on-chain");
    assert.ok(compileFriQueryKernel(0).length > 40, "Merkle walker is on-chain");
    assert.equal(FRI_VERSION, 9);
    assert.equal(FRI_QUERIES, 36);
    assert.equal(GRIND_BITS, 20);
    assert.ok(CONJECTURAL_BITS >= 100, `worksheet bits ${CONJECTURAL_BITS}`);
    assert.equal(DEFAULT_INTERNAL_HASH_ID, "sha256");
    assert.equal(FOLD_KERNEL_COUNT_CONSENSUS * FOLD_QUERIES_PER_KERNEL, FRI_QUERIES);
    const v = verifyFri(w.statement, decodeFriProof(proof));
    assert.equal(v.ok, true, v.ok ? "ok" : v.reason);
    const std = evaluatePoolSuccessorVm({
      oldState: w.statement.oldState,
      newState: w.statement.newState,
      proof,
      statement: w.statement,
      slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
      standard: true,
      note,
      change,
    });
    assert.equal(std.accepted, true, std.error ?? "standard B");
    console.log(
      `gating B.txBytes=${B.txBytes} maxUnlocking=${maxUnlocking} maxRedeem=${maxRedeem} padSum=${padSum} FRI_VERSION=${FRI_VERSION} FRI_QUERIES=${FRI_QUERIES} grind=${GRIND_BITS} worksheetBits=${CONJECTURAL_BITS} hash=${DEFAULT_INTERNAL_HASH_ID} merklePayloadOnly verifyFri=${v.ok} standard=true accepted=${std.accepted}`,
    );
  });

  it("each layer-0 opening binds qTable[slot], not any slot", () => {
    const { w, proof } = mix();
    const packed = encodeAirPacked(w.statement, proof);
    const firstL0 = collectFriOpenings(proof).find((o) => o.layerIndex === 0);
    assert.ok(firstL0);
    const ok = evaluateFriQueryOpening({
      left: firstL0!.left,
      right: firstL0!.right,
      root: firstL0!.root,
      parentPath: firstL0!.parentPath,
      parentIndex: firstL0!.parentIndex,
      layerIndex: 0,
      slot: firstL0!.slot,
      packed,
    });
    assert.equal(ok.accepted, true, ok.error ?? "honest slot");
    const wrong = evaluateFriQueryOpening({
      left: firstL0!.left,
      right: firstL0!.right,
      root: firstL0!.root,
      parentPath: firstL0!.parentPath,
      parentIndex: firstL0!.parentIndex,
      layerIndex: 0,
      slot: (firstL0!.slot + 1) % FRI_QUERIES,
      packed,
    });
    assert.equal(wrong.accepted, false, "L0 felt must match qTable[slot], not another slot");
  });

  it("false AIR (trace bump) is rejected on-chain, not only by verifyFri", () => {
    const { w, d, note } = mix();
    const wit = wWithdraw(note, d.index, w.path, w.created);
    const bad = mutateTraceAndProve(w.statement, 0, wit);
    assert.equal(verifyFri(w.statement, bad, wit).ok, false, "verifyFri must reject false AIR");
    const ev = evaluatePoolSuccessorVm({
      oldState: w.statement.oldState,
      newState: w.statement.newState,
      proof: encodeFriProof(bad),
      statement: w.statement,
      slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
      standard: false,
      note,
      change: w.created?.note,
    });
    assert.equal(ev.accepted, false, "36-query lock must reject a false statement, not only a tampered honest proof");
  });

  it("36-query B rejects a fake note preimage on the note-auth kernel", () => {
    const { w, proof, note, change, d } = mix();
    const fake: Note = { ...note, rho: crypto.getRandomValues(new Uint8Array(32)) };
    const ev = evaluatePoolSuccessorVm({
      oldState: w.statement.oldState,
      newState: w.statement.newState,
      proof,
      statement: w.statement,
      slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
      standard: false,
      note: fake,
      change,
    });
    assert.equal(ev.accepted, false, "fake rho must fail on-chain note Merkle");
    void d;
  });

  it("Merkle walker rejects omitting openings (N=1 LIFO-last or drop slot 0)", () => {
    const { w, proof, note, change } = mix();
    const base = {
      oldState: w.statement.oldState,
      newState: w.statement.newState,
      proof,
      statement: w.statement,
      slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
      standard: true as const,
      note,
      change,
    };
    const proofs = buildLayerProofs(collectFriOpenings(proof));
    const n1 = proofs.map((p) =>
      encodeLayerUnlocking(
        { ...p, openings: [p.openings[p.openings.length - 1]!] },
        compileFriQueryKernel(p.layer),
      ),
    );
    const omit0 = proofs.map((p) =>
      encodeLayerUnlocking(
        { ...p, openings: p.openings.filter((o) => o.slot !== 0) },
        compileFriQueryKernel(p.layer),
      ),
    );
    const ev1 = evaluatePoolSuccessorVm({ ...base, kernelUnlockings: n1 });
    const ev0 = evaluatePoolSuccessorVm({ ...base, kernelUnlockings: omit0 });
    assert.equal(ev1.accepted, false, "N=1 LIFO-last must fail leftover pair-group empty check");
    assert.equal(ev0.accepted, false, "dropping slot-0 opening must fail leftover pair-group empty check");
  });

  it("grind nonce, dup×36 openings, and table-index confusion are rejected", () => {
    const { w, proof, note, change } = mix();
    const base = {
      oldState: w.statement.oldState,
      newState: w.statement.newState,
      proof,
      statement: w.statement,
      slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
      standard: true as const,
      note,
      change,
    };
    const proofs = buildLayerProofs(collectFriOpenings(proof));
    const last = proofs.map((p) => {
      const o = p.openings[p.openings.length - 1]!;
      return encodeLayerUnlocking(
        { ...p, openings: Array.from({ length: FRI_QUERIES }, () => o) },
        compileFriQueryKernel(p.layer),
      );
    });
    const dup = evaluatePoolSuccessorVm({ ...base, kernelUnlockings: last });
    assert.equal(dup.accepted, false, "one leaf ×36 must not bind 36 pair groups");

    const p0 = proofs[0]!;
    assert.ok(p0.table.length >= 64, "need two unique siblings to swap");
    const table = new Uint8Array(p0.table);
    const a = table.slice(0, 32);
    table.set(table.subarray(32, 64), 0);
    table.set(a, 32);
    const swapped = proofs.map((p, i) =>
      encodeLayerUnlocking(i === 0 ? { ...p, table } : p, compileFriQueryKernel(p.layer)),
    );
    const swapEv = evaluatePoolSuccessorVm({ ...base, kernelUnlockings: swapped });
    assert.equal(swapEv.accepted, false, "swapped unique-table slots must fail the walk");

    const oF = { ...p0.openings[0]!, compactPath: new Uint8Array(p0.openings[0]!.compactPath) };
    oF.compactPath[1] = 0xff;
    oF.compactPath[2] = 0xff;
    const ffff = proofs.map((p, i) =>
      encodeLayerUnlocking(
        i === 0 ? { ...p, openings: [oF, ...p.openings.slice(1)] } : p,
        compileFriQueryKernel(p.layer),
      ),
    );
    const idxEv = evaluatePoolSuccessorVm({ ...base, kernelUnlockings: ffff });
    assert.equal(idxEv.accepted, false, "compact-path index 0xFFFF must not PICK a forged sibling");

    const packed = encodeAirPacked(w.statement, proof);
    packed[AIR_OFF_NONCE + 3] ^= 0x01;
    const grindEv = evaluatePoolSuccessorVm({ ...base, airPacked: packed });
    assert.equal(grindEv.accepted, false, "flipped grind nonce must fail grind or unique-FS bind");

    const empty = proofs.map((p) =>
      encodeLayerUnlocking({ ...p, openings: [] }, compileFriQueryKernel(p.layer)),
    );
    const n0 = evaluatePoolSuccessorVm({ ...base, kernelUnlockings: empty });
    assert.equal(n0.accepted, false, "N=0 must not vacuously accept a full pair blob");
  });
});

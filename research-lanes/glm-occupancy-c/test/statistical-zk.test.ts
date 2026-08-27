import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { decodeTransaction } from "@bitauth/libauth";
import {
  circleDomain,
  decodeFriProof,
  encodeFriProof,
  mutateTraceAndProve,
  proveFri,
  unmaskFriProof,
  verifyFri,
  wDeposit,
  wWithdraw,
} from "../src/backends/circle/fri.ts";
import {
  freshViewingKey,
  openingMaskAt,
  openingMaskFelt,
  unmaskAuth,
  viewingCommit,
} from "../src/backends/circle/witness-mask.ts";
import {
  AIR_NEWTON_BYTES,
  AIR_OFF_CELLS,
  AIR_OFF_EVEN,
  AIR_OFF_NTABLE,
  AIR_OFF_ODD,
  AIR_OFF_OPEN_MASK,
  AIR_OFF_QTABLE,
  encodeAirPacked,
  newtonEvalJs,
  nqzAt,
  TRACE_XS,
} from "../src/chain/air-cqz.ts";
import { FRI_QUERIES, TRACE_LEN } from "../src/backends/circle/params.ts";
import { add, encodeLe, inv, mul, sub } from "../src/backends/circle/m31.ts";
import { decodeFeltBlob } from "../src/chain/m31-asm.ts";
import { circleFriPlugin } from "../src/backends/circle/plugin.ts";
import { applyDeposit, applyWithdraw } from "../src/pool/transition.ts";
import { IncrementalMerkle, NullifierSet, type Note } from "../src/pool/notes.ts";
import { emptyState, encodePublicPaa1, utxoValueFor } from "../src/pool/state.ts";
import { LAB_PAYOUT_DIGEST } from "../src/chain/payout.ts";
import { compileCovenantSuccessor } from "../src/chain/covenant-spend.ts";
import { createLabWallet } from "../src/chain/wallet.ts";


function rnd32(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}

function containsBytes(hay: Uint8Array, needle: Uint8Array): boolean {
  if (needle.length === 0) return false;
  outer: for (let i = 0; i + needle.length <= hay.length; i += 1) {
    for (let j = 0; j < needle.length; j += 1) {
      if (hay[i + j] !== needle[j]) continue outer;
    }
    return true;
  }
  return false;
}

function machine() {
  return {
    state: emptyState(rnd32()),
    notes: new IncrementalMerkle(),
    nullifiers: new NullifierSet(),
  };
}

describe("statistical ZK of the published witness", () => {
  it("honest in-memory verifyFri and plugin.verify accept", async () => {
    const note: Note = { amountSats: 12_000n, rho: rnd32(), ownerSecret: rnd32() };
    const d = applyDeposit(machine(), note);
    const proof = proveFri(d.statement, wDeposit(note, d.index, d.path));
    assert.equal(verifyFri(d.statement, proof).ok, true);
    const encoded = encodeFriProof(proof);
    assert.equal(circleFriPlugin.verify(d.statement, encoded).ok, true);
    const decoded = decodeFriProof(encoded);
    assert.equal(decoded.authMasked, true);
    assert.equal(verifyFri(d.statement, decoded).ok, true, "public verify (no viewing key) accepts honest");
    assert.equal(verifyFri(d.statement, decoded, {}, { viewingKey: proof.viewingKey }).ok, true);
  });

  it("encodeFriProof and every successor unlocking omit rho/owner", () => {
    const note: Note = { amountSats: 0x0a1b2c3d4e5f6071n, rho: rnd32(), ownerSecret: rnd32() };
    const d = applyDeposit(machine(), note);
    const w = applyWithdraw(d.machine, note, d.index, LAB_PAYOUT_DIGEST, note.amountSats / 4n);
    const inner = proveFri(w.statement, wWithdraw(note, d.index, w.path, w.created));
    const raw = encodeFriProof(inner);
    assert.equal(containsBytes(raw, note.rho), false, "encoded proof must not carry rho");
    assert.equal(containsBytes(raw, note.ownerSecret), false, "encoded proof must not carry owner");
    assert.equal(containsBytes(raw, inner.viewingKey!), false, "viewing key stays off the encoding");
    const decoded = decodeFriProof(raw);
    assert.notDeepEqual(decoded.auth.rho, note.rho);
    assert.deepEqual(unmaskAuth(decoded.auth, inner.viewingKey!).rho, note.rho);
    assert.throws(() => unmaskFriProof(decoded, freshViewingKey()));

    const measured = compileCovenantSuccessor({
      wallet: createLabWallet(),
      feeUtxo: { tx_hash: "33".repeat(32), tx_pos: 0, value: 250_000 },
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
      lockKind: "p2sh32",
    });
    const tx = decodeTransaction(measured.raw);
    if (typeof tx === "string") throw new Error(tx);
    for (const input of tx.inputs) {
      assert.equal(containsBytes(input.unlockingBytecode, note.rho), false);
      assert.equal(containsBytes(input.unlockingBytecode, note.ownerSecret), false);
      assert.equal(containsBytes(input.unlockingBytecode, inner.viewingKey!), false);
    }
    const commit = decoded.viewingCommit!;
    for (const q of decoded.queries) {
      const rawQ = nqzAt(w.statement, q.index).q;
      const zQ = nqzAt(w.statement, q.index).z;
      const r = openingMaskAt(commit, q.index, undefined, zQ);
      assert.notEqual(q.layers[0]!.value, rawQ, "opening is not plaintext Q");
      assert.equal(q.layers[0]!.value, add(rawQ, r));
      const rOn = openingMaskAt(commit, q.index, undefined, 0n);
      if (zQ !== 0n) assert.notEqual(r, rOn, "off-domain Z·R must move openings off the trace");
    }
    const q0 = decoded.queries[0]!;
    const rawQ0 = nqzAt(w.statement, q0.index).q;
    const r0 = openingMaskAt(commit, q0.index, undefined, nqzAt(w.statement, q0.index).z);
    const poolUnlock = tx.inputs[0]!.unlockingBytecode;
    assert.equal(containsBytes(poolUnlock, encodeLe(add(rawQ0, r0))), true, "packed Q is masked");
    const packed = encodeAirPacked(w.statement, raw);
    assert.notDeepEqual(
      packed.slice(AIR_OFF_OPEN_MASK, AIR_OFF_OPEN_MASK + 4),
      encodeLe(r0),
      "mask felt is not packed as a degree-0 field",
    );
    const even = decodeFeltBlob(packed.slice(AIR_OFF_EVEN, AIR_OFF_EVEN + AIR_NEWTON_BYTES));
    const odd = decodeFeltBlob(packed.slice(AIR_OFF_ODD, AIR_OFF_ODD + AIR_NEWTON_BYTES));
    const cells = decodeFeltBlob(packed.slice(AIR_OFF_CELLS, AIR_OFF_CELLS + TRACE_LEN * 4));
    const domain = circleDomain(TRACE_LEN);
    const tAt = (i: number) => {
      const p = domain[i]!;
      return add(newtonEvalJs(even, p.x, TRACE_XS), mul(p.y, newtonEvalJs(odd, p.x, TRACE_XS)));
    };
    for (let i = 0; i < TRACE_LEN; i += 1) {
      const fromCells = sub(tAt(i), cells[i]!);
      const rI = openingMaskAt(commit, i, undefined, 0n);
      assert.notEqual(fromCells, rI, `T(domain[${i}])-cell must not be the opening mask`);
      assert.notEqual(sub(tAt(i), 1n), rI, `T(domain[${i}])-1 must not be the opening mask`);
      assert.notEqual(sub(tAt(i), 2n), rI, `T(domain[${i}])-2 must not be the opening mask`);
    }
    for (let s = 0; s < decoded.queries.length; s += 1) {
      const qP = decodeFeltBlob(packed.slice(AIR_OFF_QTABLE + s * 4, AIR_OFF_QTABLE + s * 4 + 4))[0]!;
      const nP = decodeFeltBlob(packed.slice(AIR_OFF_NTABLE + s * 4, AIR_OFF_NTABLE + s * 4 + 4))[0]!;
      const idx = decoded.queries[s]!.index;
      const zVal = nqzAt(w.statement, idx).z;
      if (zVal === 0n) continue;
      const fromQn = sub(qP, mul(nP, inv(zVal)));
      const zFull = nqzAt(w.statement, idx).z;
      assert.notEqual(
        fromQn,
        openingMaskAt(commit, idx, undefined, zFull),
        `qTable[${s}]-nTable/Z must not be the opening mask`,
      );
    }
  });

  it("two honest proofs differ; opening diffs are not degree-0 Q diffs", () => {
    const note: Note = { amountSats: 12_000n, rho: rnd32(), ownerSecret: rnd32() };
    const d = applyDeposit(machine(), note);
    const wit = wDeposit(note, d.index, d.path);
    const a = proveFri(d.statement, wit);
    const b = proveFri(d.statement, wit);
    assert.equal(verifyFri(d.statement, a, wit).ok, true);
    assert.equal(verifyFri(d.statement, b, wit).ok, true);
    const packedA = encodeAirPacked(d.statement, encodeFriProof(a));
    const packedB = encodeAirPacked(d.statement, encodeFriProof(b));
    assert.notDeepEqual(
      packedA.slice(AIR_OFF_QTABLE, AIR_OFF_QTABLE + FRI_QUERIES * 4),
      packedB.slice(AIR_OFF_QTABLE, AIR_OFF_QTABLE + FRI_QUERIES * 4),
      "second honest proof must publish a different packed Q view",
    );
    const i0 = a.queries[0]!.index;
    const i1 = a.queries.find((q) => q.index !== i0)?.index;
    assert.ok(i1 !== undefined, "need two distinct query indices");
    const q0 = nqzAt(d.statement, i0).q;
    const q1 = nqzAt(d.statement, i1).q;
    const plainDiff = sub(a.queries[0]!.layers[0]!.value, a.queries.find((q) => q.index === i1)!.layers[0]!.value);
    const qDiff = sub(q0, q1);
    assert.notEqual(plainDiff, qDiff, "degree-0 mask would cancel; poly mask must not");
    const c = openingMaskFelt(a.viewingCommit!);
    const d0Opened0 = add(q0, c);
    const d0Opened1 = add(q1, c);
    assert.equal(sub(d0Opened0, d0Opened1), qDiff, "degree-0-only contrast: constants cancel");
    assert.notEqual(a.queries[0]!.layers[0]!.value, d0Opened0, "shipped opening is not degree-0 Q+c");
    const falseProof = mutateTraceAndProve(d.statement, 0, wit);
    assert.equal(verifyFri(d.statement, falseProof, wit).ok, false, "false statement still rejects");
  });

  it("wrong viewing key does not open the preimage", () => {
    const note: Note = { amountSats: 9_000n, rho: rnd32(), ownerSecret: rnd32() };
    const d = applyDeposit(machine(), note);
    const inner = proveFri(d.statement, wDeposit(note, d.index, d.path));
    const decoded = decodeFriProof(encodeFriProof(inner));
    const bad = verifyFri(d.statement, decoded, {}, { viewingKey: freshViewingKey() });
    assert.equal(bad.ok, false);
    assert.match(bad.ok ? "" : bad.reason, /viewing key/);
    assert.deepEqual(decoded.viewingCommit, viewingCommit(inner.viewingKey!));
  });
});

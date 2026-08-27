import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { encodeFriProof, proveFri, wDeposit, wWithdraw } from "../src/backends/circle/fri.ts";
import { applyDeposit, applyWithdraw } from "../src/pool/transition.ts";
import { IncrementalMerkle, NullifierSet, type Note } from "../src/pool/notes.ts";
import { emptyState, encodePublicPaa1, encodeState, STATE_BASE_SATS, utxoValueFor } from "../src/pool/state.ts";
import { LAB_PAYOUT_DIGEST } from "../src/chain/payout.ts";
import { compileCovenantSuccessor } from "../src/chain/covenant-spend.ts";
import { createLabWallet } from "../src/chain/wallet.ts";
import { evaluatePoolSuccessorVm } from "../src/chain/vm-verifier.ts";

function mix() {
  const note: Note = {
    amountSats: 10_000n,
    rho: crypto.getRandomValues(new Uint8Array(32)),
    ownerSecret: crypto.getRandomValues(new Uint8Array(32)),
  };
  const d = applyDeposit(
    { state: emptyState(crypto.getRandomValues(new Uint8Array(32))), notes: new IncrementalMerkle(), nullifiers: new NullifierSet() },
    note,
  );
  const w = applyWithdraw(d.machine, note, d.index, LAB_PAYOUT_DIGEST, 3_000n);
  const raw = encodeFriProof(proveFri(w.statement, wWithdraw(note, d.index, w.path, w.created)));
  return { note, d, w, raw };
}

describe("on-chain seq / reserve-zero without publishing the spent note", () => {
  it("honest successor accepts; seq-not-plus-one and nonzero public reserve reject", () => {
    const { w, raw } = mix();
    const honest = evaluatePoolSuccessorVm({
      oldState: w.statement.oldState,
      newState: w.statement.newState,
      proof: raw,
      statement: w.statement,
    });
    assert.equal(honest.accepted, true, honest.error ?? "honest");
    const badSeq = {
      ...w.statement.newState,
      sequence: w.statement.oldState.sequence,
    };
    const seqFail = evaluatePoolSuccessorVm({
      oldState: w.statement.oldState,
      newState: badSeq,
      proof: raw,
      statement: w.statement,
    });
    assert.equal(seqFail.accepted, false, "seq must increase by 1");
    const reserved = encodeState({ ...w.statement.newState, reserveSats: 99n });
    const resFail = evaluatePoolSuccessorVm({
      oldState: w.statement.oldState,
      newState: w.statement.newState,
      proof: raw,
      statement: w.statement,
      outputCommitment: reserved,
    });
    assert.equal(resFail.accepted, false, "nonzero PAA1 reserve must fail");
  });

  it("successor hex does not contain spent rho or owner", () => {
    const { note, w, raw } = mix();
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
    const hex = Buffer.from(measured.raw).toString("hex");
    assert.equal(hex.includes(Buffer.from(note.rho).toString("hex")), false);
    assert.equal(hex.includes(Buffer.from(note.ownerSecret).toString("hex")), false);
    const pub = encodePublicPaa1(w.statement.newState);
    assert.deepEqual(pub.subarray(16, 24), new Uint8Array(8), "public PAA1 reserve bytes stay zero");
  });
});

import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { decodeTransaction } from "@bitauth/libauth";
import { encodeFriProof, proveFri, verifyFri, wDeposit, wWithdraw } from "../src/backends/circle/fri.ts";
import { applyDeposit, applyWithdraw } from "../src/pool/transition.ts";
import { IncrementalMerkle, NullifierSet, type Note } from "../src/pool/notes.ts";
import { emptyState, encodePublicPaa1, STATE_BASE_SATS, utxoValueFor } from "../src/pool/state.ts";
import { LAB_PAYOUT_DIGEST, LAB_PAYOUT_LOCKING } from "../src/chain/payout.ts";
import { compileCovenantSuccessor } from "../src/chain/covenant-spend.ts";

/** Distinct from STATE_BASE (2000) and from the standard 100_000 successor fee budget. */
const WITHDRAW_SATS = 7777n;

function rnd32(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}

describe("successor fee unlinked from withdraw", () => {
  it("withdraw successor has no user P2PKH fee input; miner fee is kernel sats", () => {
    const note: Note = {
      amountSats: 20_000n,
      rho: rnd32(),
      ownerSecret: rnd32(),
    };
    const d = applyDeposit(
      {
        state: emptyState(rnd32()),
        notes: new IncrementalMerkle(),
        nullifiers: new NullifierSet(),
      },
      note,
    );
    const w = applyWithdraw(d.machine, note, d.index, LAB_PAYOUT_DIGEST, WITHDRAW_SATS);
    assert.ok(w.change, "partial withdraw must mint change");
    const witness = wWithdraw(note, d.index, w.path, w.created);
    const fri = proveFri(w.statement, witness);
    const checked = verifyFri(w.statement, fri, witness);
    const proof = encodeFriProof(fri);
    assert.equal(checked.ok, true, checked.ok ? "" : checked.reason);
    assert.equal(w.statement.publicAmountSats, -WITHDRAW_SATS);
    assert.notEqual(WITHDRAW_SATS, STATE_BASE_SATS);

    const measured = compileCovenantSuccessor({
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
    });
    const decoded = decodeTransaction(measured.raw);
    if (typeof decoded === "string") throw new Error(decoded);
    const values = decoded.outputs.map((o) => o.valueSatoshis);
    assert.equal(values.length, 2, "pool + payout; no user fee change");
    assert.equal(values[0], utxoValueFor(w.statement.newState));
    assert.equal(values[0], STATE_BASE_SATS + (20_000n - WITHDRAW_SATS));
    assert.equal(values[1], WITHDRAW_SATS);
    assert.deepEqual(decoded.outputs[1]!.lockingBytecode, LAB_PAYOUT_LOCKING);
    assert.notEqual(values[1], STATE_BASE_SATS);
  });
});

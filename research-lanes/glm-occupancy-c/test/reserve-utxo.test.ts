import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { decodeTransaction } from "@bitauth/libauth";
import { encodeFriProof, proveFri, wDeposit, wWithdraw } from "../src/backends/circle/fri.ts";
import { applyDeposit, applyWithdraw } from "../src/pool/transition.ts";
import { IncrementalMerkle, NullifierSet, type Note } from "../src/pool/notes.ts";
import { emptyState, encodePublicPaa1, STATE_BASE_SATS, utxoValueFor } from "../src/pool/state.ts";
import { compileCovenantSuccessor } from "../src/chain/covenant-spend.ts";
import { createLabWallet } from "../src/chain/wallet.ts";
import { evaluatePoolSuccessorVm } from "../src/chain/vm-verifier.ts";
import { hashPayoutLocking, LAB_PAYOUT_DIGEST, LAB_PAYOUT_LOCKING } from "../src/chain/payout.ts";
import { encodeAirPacked, AIR_OFF_CELLS, recookNewtonFromPacked } from "../src/chain/air-cqz.ts";
import { encodeLe } from "../src/backends/circle/m31.ts";


const DEPOSIT_SATS = 10_000n;
const WITHDRAW_SATS = 3_000n;
const FEE_UTXO_SATS = 250_000;
const STANDARD_FEE = 100_000n;

function rnd32(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}

function machine() {
  return {
    state: emptyState(rnd32()),
    notes: new IncrementalMerkle(),
    nullifiers: new NullifierSet(),
  };
}

describe("pool UTXO reserve + withdraw payout", () => {
  it("deposit/withdraw compile: pool sats = dust+reserve; payout; fee ≠ withdraw; lock rejects bad value/payout", () => {
    const note: Note = { amountSats: DEPOSIT_SATS, rho: rnd32(), ownerSecret: rnd32() };
    const d = applyDeposit(machine(), note);
    const depProof = encodeFriProof(proveFri(d.statement, wDeposit(note, d.index, d.path)));
    const depTx = compileCovenantSuccessor({
      wallet: createLabWallet(),
      feeUtxo: { tx_hash: "33".repeat(32), tx_pos: 0, value: FEE_UTXO_SATS },
      pool: {
        tx_hash: "11".repeat(32),
        tx_pos: 0,
        value: utxoValueFor(d.statement.oldState),
        category: new Uint8Array(32).fill(0x11),
        commitment: encodePublicPaa1(d.statement.oldState),
      },
      newState: d.statement.newState,
      proof: depProof,
      statement: d.statement,
      lockKind: "p2sh32",
    });
    const depDec = decodeTransaction(depTx.raw);
    if (typeof depDec === "string") throw new Error(depDec);
    const depValues = depDec.outputs.map((o) => o.valueSatoshis);
    assert.equal(depValues[0], utxoValueFor(d.statement.newState));
    assert.equal(depValues[0], STATE_BASE_SATS + DEPOSIT_SATS);
    assert.equal(depValues[0]! - STATE_BASE_SATS, DEPOSIT_SATS);
    assert.equal(encodePublicPaa1(d.statement.newState).subarray(16, 24).every((b) => b === 0), true);

    const depVm = evaluatePoolSuccessorVm({
      oldState: d.statement.oldState,
      newState: d.statement.newState,
      proof: depProof,
      statement: d.statement,
    });
    assert.equal(depVm.accepted, true, depVm.error ?? "honest deposit successor");
    const depBadVal = evaluatePoolSuccessorVm({
      oldState: d.statement.oldState,
      newState: d.statement.newState,
      proof: depProof,
      statement: d.statement,
      outputValueSats: utxoValueFor(d.statement.newState) + 1n,
    });
    assert.equal(depBadVal.accepted, false, "mutated deposit pool value must fail");

    const w = applyWithdraw(d.machine, note, d.index, LAB_PAYOUT_DIGEST, WITHDRAW_SATS);
    const wdProof = encodeFriProof(proveFri(w.statement, wWithdraw(note, d.index, w.path, w.created)));
    const wdTx = compileCovenantSuccessor({
      wallet: createLabWallet(),
      feeUtxo: { tx_hash: "33".repeat(32), tx_pos: 0, value: FEE_UTXO_SATS },
      pool: {
        tx_hash: "11".repeat(32),
        tx_pos: 0,
        value: utxoValueFor(w.statement.oldState),
        category: new Uint8Array(32).fill(0x11),
        commitment: encodePublicPaa1(w.statement.oldState),
      },
      newState: w.statement.newState,
      proof: wdProof,
      statement: w.statement,
      lockKind: "p2sh32",
    });
    const wdDec = decodeTransaction(wdTx.raw);
    if (typeof wdDec === "string") throw new Error(wdDec);
    const poolOut = wdDec.outputs[0]!.valueSatoshis;
    const payoutOut = wdDec.outputs[1]!.valueSatoshis;
    const changeOut = wdDec.outputs[2]!.valueSatoshis;
    assert.equal(poolOut, utxoValueFor(w.statement.newState));
    assert.equal(poolOut, STATE_BASE_SATS + (DEPOSIT_SATS - WITHDRAW_SATS));
    assert.equal(utxoValueFor(w.statement.oldState) - poolOut, WITHDRAW_SATS);
    assert.equal(payoutOut, WITHDRAW_SATS);
    assert.deepEqual(wdDec.outputs[1]!.lockingBytecode, LAB_PAYOUT_LOCKING);
    assert.deepEqual(hashPayoutLocking(wdDec.outputs[1]!.lockingBytecode), LAB_PAYOUT_DIGEST);
    const funderFee = BigInt(FEE_UTXO_SATS) - changeOut;
    assert.notEqual(funderFee, WITHDRAW_SATS);
    assert.equal(funderFee, STANDARD_FEE);
    assert.deepEqual(encodePublicPaa1(w.statement.newState).subarray(16, 24), new Uint8Array(8));

    const wdVm = evaluatePoolSuccessorVm({
      oldState: w.statement.oldState,
      newState: w.statement.newState,
      proof: wdProof,
      statement: w.statement,
    });
    assert.equal(wdVm.accepted, true, wdVm.error ?? "honest withdraw successor");
    const wdBadVal = evaluatePoolSuccessorVm({
      oldState: w.statement.oldState,
      newState: w.statement.newState,
      proof: wdProof,
      statement: w.statement,
      outputValueSats: utxoValueFor(w.statement.newState) + 1n,
    });
    assert.equal(wdBadVal.accepted, false, "mutated withdraw pool value must fail");
    const badLock = new Uint8Array(LAB_PAYOUT_LOCKING);
    badLock[3] ^= 1;
    const wdBadPay = evaluatePoolSuccessorVm({
      oldState: w.statement.oldState,
      newState: w.statement.newState,
      proof: wdProof,
      statement: w.statement,
      payoutLockingBytecode: badLock,
    });
    assert.equal(wdBadPay.accepted, false, "mutated payout locking must fail");
    const wdBadPayVal = evaluatePoolSuccessorVm({
      oldState: w.statement.oldState,
      newState: w.statement.newState,
      proof: wdProof,
      statement: w.statement,
      payoutValueSats: WITHDRAW_SATS + 1n,
    });
    assert.equal(wdBadPayVal.accepted, false, "mutated payout value must fail");

    const honestPacked = encodeAirPacked(w.statement, wdProof);
    const steal = WITHDRAW_SATS + 1_000n;
    const cooked = new Uint8Array(honestPacked);
    cooked.set(encodeLe(steal), AIR_OFF_CELLS + 5 * 4);
    const recooked = recookNewtonFromPacked(cooked);
    const drain = evaluatePoolSuccessorVm({
      oldState: w.statement.oldState,
      newState: w.statement.newState,
      proof: wdProof,
      statement: w.statement,
      airPacked: recooked,
      outputValueSats: utxoValueFor(w.statement.oldState) - steal,
      payoutValueSats: steal,
      payoutLockingBytecode: LAB_PAYOUT_LOCKING,
    });
    assert.equal(drain.accepted, false, drain.error ?? "recooked cell5 Newton T with honest Q/N must fail");
  });
});

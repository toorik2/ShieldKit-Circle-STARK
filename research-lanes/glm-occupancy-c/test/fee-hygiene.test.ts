import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { decodeTransaction } from "@bitauth/libauth";
import { encodeFriProof, proveFri, wWithdraw } from "../src/backends/circle/fri.ts";
import { applyDeposit, applyWithdraw } from "../src/pool/transition.ts";
import { IncrementalMerkle, NullifierSet, type Note } from "../src/pool/notes.ts";
import { emptyState, encodePublicPaa1, utxoValueFor } from "../src/pool/state.ts";
import { LAB_PAYOUT_DIGEST } from "../src/chain/payout.ts";
import { compileCovenantSuccessor, compileFundVerifierKernels } from "../src/chain/covenant-spend.ts";
import { createLabWallet, p2pkhLockingOf } from "../src/chain/wallet.ts";
import { successorFeeCoinSats } from "../src/chain/envelope.ts";

function rnd32(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}

describe("fee coin sized to the fee; fresh change address", () => {
  it("withdraw successor has no funder change output", () => {
    const note: Note = { amountSats: 20_000n, rho: rnd32(), ownerSecret: rnd32() };
    const d = applyDeposit(
      { state: emptyState(rnd32()), notes: new IncrementalMerkle(), nullifiers: new NullifierSet() },
      note,
    );
    const w = applyWithdraw(d.machine, note, d.index, LAB_PAYOUT_DIGEST, 7_777n);
    const proof = encodeFriProof(proveFri(w.statement, wWithdraw(note, d.index, w.path, w.created)));
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
    assert.equal(decoded.outputs.length, 2, "pool + payout");
    assert.equal(decoded.outputs[1]!.valueSatoshis, 7_777n);
  });

  it("kernel fund embeds miner fee in the first FRI carrier; leftover is a fresh treasury", () => {
    const wallet = createLabWallet();
    const funded = compileFundVerifierKernels(
      wallet,
      { tx_hash: "44".repeat(32), tx_pos: 0, value: 5_000_000 },
      1_000,
    );
    assert.equal(funded.fri[0]!.value, 1_000 + Number(successorFeeCoinSats("standard")));
    assert.equal(funded.fri[1]!.value, 1_000);
    assert.ok(funded.treasuryValue !== undefined && funded.treasuryValue > 1_000_000);
    assert.ok(funded.treasuryAddress && funded.treasuryAddress.startsWith("bchtest:"));
    const decoded = decodeTransaction(funded.raw);
    if (typeof decoded === "string") throw new Error(decoded);
    const treOut = decoded.outputs[funded.treasuryPos!]!;
    assert.equal(treOut.valueSatoshis, BigInt(funded.treasuryValue!));
    assert.notDeepEqual(treOut.lockingBytecode, p2pkhLockingOf(wallet));
  });
});

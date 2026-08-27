import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { hashPayoutSet, LAB_PAYOUT_LOCKING } from "../src/chain/payout.ts";
import { PAYOUT_BUCKETS_SATS, splitIntoBuckets } from "../src/pool/payout-buckets.ts";
import { applyDeposit, applyWithdrawBucketed } from "../src/pool/transition.ts";
import { IncrementalMerkle, NullifierSet, type Note } from "../src/pool/notes.ts";
import { emptyState } from "../src/pool/state.ts";
import { proveFri, verifyFri, wWithdraw } from "../src/backends/circle/fri.ts";

function rnd32(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}

function lock(fill: number): Uint8Array {
  const out = new Uint8Array(LAB_PAYOUT_LOCKING);
  out[3] = fill;
  return out;
}

describe("payout buckets", () => {
  it("greedy-fills 1 BCH .. 1000 sat slices; leftover is unbucketed", () => {
    assert.deepEqual(PAYOUT_BUCKETS_SATS[0], 100_000_000n);
    const a = splitIntoBuckets(37_500n);
    assert.equal(a.publicSats, 37_000n);
    assert.deepEqual(a.slices, [10_000n, 10_000n, 10_000n, 1_000n, 1_000n, 1_000n, 1_000n, 1_000n, 1_000n, 1_000n]);
    assert.equal(a.unbucketed, 500n);
    const b = splitIntoBuckets(20_000n);
    assert.equal(b.publicSats, 20_000n);
    assert.deepEqual(b.slices, [10_000n, 10_000n]);
    const c = splitIntoBuckets(500n);
    assert.equal(c.publicSats, 0n);
    assert.equal(c.unbucketed, 500n);
  });

  it("applyWithdrawBucketed pays snapped public sats; rest is a change note in the same tree", () => {
    const note: Note = { amountSats: 50_000n, rho: rnd32(), ownerSecret: rnd32() };
    const d = applyDeposit(
      { state: emptyState(rnd32()), notes: new IncrementalMerkle(), nullifiers: new NullifierSet() },
      note,
    );
    const split = splitIntoBuckets(37_500n);
    const payouts = split.slices.map((sats, i) => ({ lockingBytecode: lock(0x10 + i), sats }));
    const w = applyWithdrawBucketed(d.machine, note, d.index, payouts, 37_500n);
    assert.equal(w.publicSats, 37_000n);
    assert.equal(w.statement.publicAmountSats, -37_000n);
    assert.equal(w.machine.state.reserveSats, 13_000n);
    assert.ok(w.change);
    assert.equal(w.change!.amountSats, 13_000n);
    assert.deepEqual(w.statement.payoutLockingDigest, hashPayoutSet(payouts));
    const wit = wWithdraw(note, d.index, w.path, w.created);
    assert.equal(verifyFri(w.statement, proveFri(w.statement, wit), wit).ok, true);
  });

  it("rejects a second payout to the same locking when two slices need two locks", () => {
    const note: Note = { amountSats: 20_000n, rho: rnd32(), ownerSecret: rnd32() };
    const d = applyDeposit(
      { state: emptyState(rnd32()), notes: new IncrementalMerkle(), nullifiers: new NullifierSet() },
      note,
    );
    const one = { lockingBytecode: lock(1), sats: 10_000n };
    assert.throws(
      () => applyWithdrawBucketed(d.machine, note, d.index, [one, one], 20_000n),
      /address reuse/,
    );
  });
});

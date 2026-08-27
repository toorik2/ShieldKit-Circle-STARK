/**
 * FRI10's published proof, verified the way a third party actually gets it.
 *
 * Three real defects lived here and none had a test:
 *
 *  1. `checkAuthsAgainstStatement` was gated behind `if (!proof.authMasked ...)`,
 *     which is never true for a PUBLISHED proof — so the batch checks were
 *     unreachable exactly where they mattered, with or without a viewing key.
 *  2. Nothing verified that `newState.nullifierRoot` is the fold of the spent
 *     nullifiers. A prover could set it to anything and never record the spends,
 *     which is a double-spend across transactions. Both families accepted it.
 *  3. An honest 3-note batch was REJECTED with "withdraw exceeds note", because
 *     FRI9's single-note fallthrough ran on `auths[0]` instead of the batch.
 *
 * Every case below runs on the ENCODED-then-DECODED proof, never the in-memory
 * object, because the in-memory one has unmasked auths and hides all three bugs.
 *
 * Batched and non-batched are both covered: N=1 is not a special case, it is the
 * same path with one auth.
 */
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { runBatchSuccessor } from "../src/pool/mix-successor.ts";
import {
  proveFriBatch,
  verifyFriBatch,
  encodeFriBatchProof,
  decodeFriBatchProof,
  checkAuthsPublicly,
} from "../src/backends/circle-batch/fri-batch.ts";
import { wBatchExit } from "../src/backends/circle/air.ts";
import { defaultInternalHash } from "../src/backends/circle/internal-hash.ts";

const rnd32 = () => crypto.getRandomValues(new Uint8Array(32));

/** Prove, then round-trip through the published encoding. */
function published(statement: unknown, spends: unknown) {
  const p = proveFriBatch(statement as never, wBatchExit(spends as never) as never) as never as {
    viewingKey: Uint8Array;
  };
  const dec = decodeFriBatchProof(encodeFriBatchProof(p as never));
  return { p, dec };
}

const forgeRoot = (b: ReturnType<typeof runBatchSuccessor>) =>
  ({ ...b.statement, newState: { ...b.statement.newState, nullifierRoot: rnd32() } }) as never;

describe("FRI10 published-proof verification", () => {
  for (const n of [1, 3]) {
    const label = n === 1 ? "NON-BATCHED (N=1)" : `BATCHED (N=${n})`;

    it(`${label}: an honest proof verifies with NO viewing key`, () => {
      const b = runBatchSuccessor({ depositCount: 6, noteCount: n });
      const { dec } = published(b.statement, b.spends);
      const r = verifyFriBatch(b.statement, dec, {}, {});
      assert.equal(r.ok, true, r.ok ? "" : r.reason);
    });

    it(`${label}: an honest proof verifies WITH the viewing key`, () => {
      const b = runBatchSuccessor({ depositCount: 6, noteCount: n });
      const { p, dec } = published(b.statement, b.spends);
      const r = verifyFriBatch(b.statement, dec, {}, { viewingKey: p.viewingKey });
      assert.equal(r.ok, true, r.ok ? "" : r.reason);
    });

    it(`${label}: a forged nullifier root is rejected WITHOUT a key`, () => {
      const b = runBatchSuccessor({ depositCount: 6, noteCount: n });
      const forged = forgeRoot(b);
      const { dec } = published(forged, b.spends);
      const r = verifyFriBatch(forged, dec, {}, {});
      assert.equal(r.ok, false, "a forged accumulator must not verify");
      assert.match(
        r.ok ? "" : r.reason,
        /nullifier root is not the fold/,
        "and must be rejected for the right reason",
      );
    });

    it(`${label}: a forged nullifier root is rejected WITH a key`, () => {
      const b = runBatchSuccessor({ depositCount: 6, noteCount: n });
      const forged = forgeRoot(b);
      const { p, dec } = published(forged, b.spends);
      const r = verifyFriBatch(forged, dec, {}, { viewingKey: p.viewingKey });
      assert.equal(r.ok, false, "a forged accumulator must not verify");
    });
  }

  it("the public checks need no key: nullifier, leaf, index and path are unmasked", () => {
    // This is why public verification is possible at all — and, separately, why
    // the proof leaks which deposit was spent. See test/onchain-privacy.test.ts.
    const b = runBatchSuccessor({ depositCount: 6, noteCount: 3 });
    const { dec } = published(b.statement, b.spends);
    const auths = (dec as unknown as { auths: Array<{ leaf: Uint8Array; index: number }> }).auths;
    assert.equal(auths.length, 3);
    const r = checkAuthsPublicly(b.statement as never, auths as never, defaultInternalHash());
    assert.equal(r.ok, true, r.ok ? "" : r.reason);
  });

  it("a duplicate note index is rejected without a key", () => {
    const b = runBatchSuccessor({ depositCount: 6, noteCount: 3 });
    const { dec } = published(b.statement, b.spends);
    const auths = (dec as unknown as { auths: Array<{ index: number }> }).auths;
    const dup = [auths[0]!, { ...auths[1]!, index: auths[0]!.index }, auths[2]!];
    const r = checkAuthsPublicly(b.statement as never, dup as never, defaultInternalHash());
    assert.equal(r.ok, false);
    assert.match(r.ok ? "" : r.reason, /duplicate note index/);
  });

  it("dropping an auth is caught by the declared count, before anything else", () => {
    const b = runBatchSuccessor({ depositCount: 6, noteCount: 3 });
    const { dec } = published(b.statement, b.spends);
    const short = {
      ...(dec as object),
      auths: (dec as unknown as { auths: unknown[] }).auths.slice(0, 2),
    };
    const r = verifyFriBatch(b.statement, short as never, {}, {});
    assert.equal(r.ok, false);
    assert.match(r.ok ? "" : r.reason, /auth count 2 != declared 3/);
  });
});

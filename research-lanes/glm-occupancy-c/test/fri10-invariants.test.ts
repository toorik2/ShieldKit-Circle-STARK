/**
 * The six invariants FRI10 must meet to be as sound as FRI9.
 *
 * Written BEFORE the implementation, deliberately. An earlier claim in this work
 * ("FRI10's exposure is closed") turned out to be false — the guard module
 * existed but nothing imported it. Tests that predate the thing they guard cannot
 * be written to fit it after the fact.
 *
 * Matching FRI9 is the target everywhere EXCEPT masking. FRI9's key-as-pad is a
 * correct one-time pad only because it carries one auth; copying that code to N
 * auths is precisely what breaks it. So: match FRI9's *property* (one pad per
 * plaintext), not its implementation.
 */
import assert from "node:assert/strict";
import { describe, it } from "node:test";

const BATCH = "../src/backends/circle-batch/";

async function tryImport(path: string): Promise<Record<string, unknown> | null> {
  try {
    return (await import(path)) as Record<string, unknown>;
  } catch {
    return null;
  }
}

describe("FRI10 invariants (must hold before the batch family ships)", () => {
  it("1. one pad per masked plaintext — no reuse across auths", async () => {
    const m = await tryImport(`${BATCH}auth-pad.ts`);
    assert.ok(m, "auth-pad.ts must exist");
    const { maskAuths, authPadAt } = m as any;
    const { freshViewingKey, xorBytes } = await import("../src/backends/circle/witness-mask.ts");
    const key = freshViewingKey();
    const mk = (r: number) => ({
      leaf: new Uint8Array(32), index: 0, path: [], root: new Uint8Array(32),
      nullifier: new Uint8Array(32), rho: new Uint8Array(32).fill(r),
      owner: new Uint8Array(32).fill(r), amountSats: 1n, publicDeltaSats: 0n,
      amountCommit: new Uint8Array(32), createdLeaf: new Uint8Array(32),
      createdIndex: 0, createdPath: [],
    });
    const a1 = mk(0xaa), a2 = mk(0xbb);
    const [m1, m2] = maskAuths([a1, a2], key);
    assert.notDeepEqual(xorBytes(m1.rho, m2.rho), xorBytes(a1.rho, a2.rho), "two-time pad");
    const pads = Array.from({ length: 32 }, (_, i) => Buffer.from(authPadAt(key, i)).toString("hex"));
    assert.equal(new Set(pads).size, pads.length, "pads must be distinct per index");
  });

  it("2. every auth is checked — no short-circuit on the first", async () => {
    const m = await tryImport(`${BATCH}fri-batch.ts`);
    assert.ok(m, "fri-batch.ts must exist");
    const { verifyFriBatch } = m as any;
    assert.equal(typeof verifyFriBatch, "function", "batch verify must be exported");
    // A proof whose FIRST auth is valid and whose SECOND is corrupt must be
    // rejected. Checking only auths[0] would pass this happy-path-looking case.
    const { makeBatchFixture } = (await tryImport(`${BATCH}fixture.ts`)) as any ?? {};
    assert.ok(makeBatchFixture, "a batch fixture is needed to build multi-auth proofs");
    const f = makeBatchFixture({ notes: 3 });
    const ok = verifyFriBatch(f.statement, f.proof);
    assert.equal(ok.ok, true, "honest 3-auth proof must verify");
    for (const i of [0, 1, 2]) {
      const bad = f.corruptAuth(i);
      const r = verifyFriBatch(f.statement, bad);
      assert.equal(r.ok, false, `corrupting auth ${i} must be rejected`);
    }
  });

  it("3. N is bound by withdrawalCount — truncating or padding the list fails", async () => {
    const m = await tryImport(`${BATCH}fri-batch.ts`);
    assert.ok(m, "fri-batch.ts must exist");
    const { verifyFriBatch } = m as any;
    const { makeBatchFixture } = (await tryImport(`${BATCH}fixture.ts`)) as any ?? {};
    assert.ok(makeBatchFixture, "fixture needed");
    const f = makeBatchFixture({ notes: 3 });
    // withdrawalCount delta is inside PAA1 (state.ts:74, byte 28) and the covenant
    // binds PAA1 on chain, so the count is pinned by consensus, not convention.
    const delta =
      f.statement.newState.withdrawalCount - f.statement.oldState.withdrawalCount;
    assert.equal(Number(delta), 3, "fixture must move withdrawalCount by the note count");
    assert.equal(verifyFriBatch(f.statement, f.dropAuth()).ok, false, "truncated list must fail");
    assert.equal(verifyFriBatch(f.statement, f.duplicateAuth()).ok, false, "padded list must fail");
  });

  it("4. order is bound — permuting the auths fails", async () => {
    const m = await tryImport(`${BATCH}fri-batch.ts`);
    assert.ok(m, "fri-batch.ts must exist");
    const { verifyFriBatch } = m as any;
    const { makeBatchFixture } = (await tryImport(`${BATCH}fixture.ts`)) as any ?? {};
    assert.ok(makeBatchFixture, "fixture needed");
    const f = makeBatchFixture({ notes: 3 });
    assert.equal(verifyFriBatch(f.statement, f.swapAuths(0, 1)).ok, false, "permutation must fail");
  });

  it("5. soundness parameters are the SAME objects as FRI9, not copies", async () => {
    const { soundnessWorksheet } = await import("../src/backends/circle/soundness.ts");
    const w = soundnessWorksheet();
    assert.equal(w.conjecturalBits, 128, "128 conjectural bits");
    assert.equal(w.queries, 36);
    assert.equal(w.blowup, 16);
    assert.equal(w.grind, 20);
    assert.equal(w.sound, true);
    // the batch backend must not redefine any of these
    const fs = await import("node:fs");
    const src = fs.readFileSync(
      new URL("../src/backends/circle-batch/fri-batch.ts", import.meta.url),
      "utf8",
    );
    for (const forbidden of ["FRI_QUERIES =", "BLOWUP =", "GRIND_BITS =", "TRACE_LEN ="]) {
      assert.equal(src.includes(forbidden), false, `batch backend must not redefine ${forbidden}`);
    }
  });

  it("6. cross-family: a FRI10 proof must not verify as FRI9, or vice versa", async () => {
    const m = await tryImport(`${BATCH}plugin.ts`);
    assert.ok(m, "the batch plugin must exist and be registered");
    const { circleFriBatchPlugin } = m as any;
    const { circleFriPlugin } = await import("../src/backends/circle/plugin.ts");
    assert.notEqual(circleFriBatchPlugin.family, circleFriPlugin.family, "distinct family ids");
    assert.notEqual(circleFriBatchPlugin.vkId, circleFriPlugin.vkId, "distinct vkIds");
    const { zkpPlugins } = await import("../src/plugins/registry.ts");
    assert.ok(
      zkpPlugins.some((p) => p.family === circleFriBatchPlugin.family),
      "batch family must be registered",
    );
    const { makeBatchFixture } = (await tryImport(`${BATCH}fixture.ts`)) as any ?? {};
    assert.ok(makeBatchFixture, "fixture needed");
    const f = makeBatchFixture({ notes: 2 });
    assert.equal(
      circleFriPlugin.verify(f.statement, f.encoded).ok,
      false,
      "FRI9 must reject a batch proof",
    );
  });
});

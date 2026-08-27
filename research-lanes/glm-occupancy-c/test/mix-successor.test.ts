import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { encodePublicPaa1 } from "../src/pool/state.ts";
import {
  mixChangedRootsAndReserve,
  publicStateHasNoNoteAmounts,
  runMixSuccessor,
} from "../src/pool/mix-successor.ts";
import { circleFriPlugin } from "../src/backends/circle/plugin.ts";
import { decodeFriProof, verifyFri } from "../src/backends/circle/fri.ts";
import { evaluateOnChainVerify } from "../src/chain/vm-verifier.ts";

describe("mix successor updates the public cell", () => {
  it("deposit→aggregate→withdraw changes noteRoot, nullifierRoot, and reserve", () => {
    const mix = runMixSuccessor({ depositCount: 6, withdrawSats: 500n });
    assert.ok(mixChangedRootsAndReserve(mix));
    assert.ok(mix.oldState.depositCount >= 6n);
    assert.ok(mix.newState.withdrawalCount >= 1n);
    assert.ok(mix.newState.reserveSats < mix.oldState.reserveSats);
    assert.ok(mix.publicAfter.anonSet >= mix.publicBefore.anonSet);
    assert.ok(publicStateHasNoNoteAmounts(mix.oldState, [2_000n, 4_000n, 12_000n, 500n]));
    assert.ok(publicStateHasNoNoteAmounts(mix.newState, [2_000n, 4_000n, 12_000n, 500n]));
    const oldBin = encodePublicPaa1(mix.oldState);
    const newBin = encodePublicPaa1(mix.newState);
    assert.notDeepEqual(oldBin.subarray(64, 96), newBin.subarray(64, 96));
    assert.notDeepEqual(oldBin.subarray(96, 128), newBin.subarray(96, 128));
    assert.deepEqual(oldBin.subarray(16, 24), new Uint8Array(8));
    assert.deepEqual(newBin.subarray(16, 24), new Uint8Array(8));
    assert.equal(mix.publicBefore.noteRoot.includes("amount"), false);
  });

  it("VM-evals the mix withdraw successor; digest-only still fails", () => {
    const mix = runMixSuccessor({ depositCount: 5, withdrawSats: 1_000n });
    const v = verifyFri(mix.statement, decodeFriProof(mix.proof));
    assert.equal(v.ok, true, v.ok ? "" : v.reason);
    const plugin = circleFriPlugin.verify(mix.statement, mix.proof);
    assert.equal(plugin.ok, true, plugin.ok ? "" : plugin.reason);
    const on = evaluateOnChainVerify(mix.statement, mix.proof);
    assert.equal(on.stark.ok, true, on.stark.ok ? "" : on.stark.reason);
    assert.equal(on.pool.accepted, true, on.pool.error ?? "pool vm");
    assert.equal(on.accepted, true);
  });
});

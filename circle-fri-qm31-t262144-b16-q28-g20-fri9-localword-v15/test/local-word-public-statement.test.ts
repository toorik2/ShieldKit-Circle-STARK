import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { encodeLocalWordPublicStatement, localWordProfile } from
  "../src/backends/circle/local-word-public-statement.ts";
import { emptyState } from "../src/pool/state.ts";
import type { PoolStatement } from "../src/pool/statement.ts";

function statement(): PoolStatement {
  const oldState = emptyState(new Uint8Array(32).fill(0x31));
  return {
    profile: "any-amount-v0",
    action: "DEPOSIT",
    publicAmountSats: 20_000n,
    netBlind: new Uint8Array(32).fill(0x11),
    oldState,
    newState: { ...oldState, sequence: 1n, reserveSats: 20_000n, depositCount: 1n },
    noteCommitment: new Uint8Array(32).fill(0x22),
    nullifier: new Uint8Array(32),
    payoutLockingDigest: new Uint8Array(32),
    amountCommitIn: new Uint8Array(32).fill(0x33),
    amountCommitOut: new Uint8Array(32).fill(0x44),
  };
}

describe("local-word public statement boundary", () => {
  it("cannot observe legacy note tags, note identity, or statement blinding", () => {
    const base = statement();
    const encoded = encodeLocalWordPublicStatement(base);
    const changed: PoolStatement = {
      ...base,
      netBlind: new Uint8Array(32).fill(0xaa),
      noteCommitment: new Uint8Array(32).fill(0xbb),
      amountCommitIn: new Uint8Array(32).fill(0xcc),
      amountCommitOut: new Uint8Array(32).fill(0xdd),
    };
    assert.deepEqual(encodeLocalWordPublicStatement(changed), encoded);
    assert.notDeepEqual(encodeLocalWordPublicStatement(base, 1_000n), encoded);
    assert.equal(localWordProfile(base), "deposit");
  });

  it("derives withdrawal profile only from the public root transition", () => {
    const base = statement();
    const full: PoolStatement = {
      ...base,
      action: "WITHDRAW",
      publicAmountSats: -7_000n,
      newState: { ...base.newState, noteRoot: base.oldState.noteRoot },
      amountCommitOut: new Uint8Array(32).fill(0xee),
    };
    assert.equal(localWordProfile(full), "withdraw-full");
    assert.equal(localWordProfile({
      ...full,
      newState: { ...full.newState, noteRoot: new Uint8Array(32).fill(1) },
      amountCommitOut: new Uint8Array(32),
    }), "withdraw-change");
  });
});

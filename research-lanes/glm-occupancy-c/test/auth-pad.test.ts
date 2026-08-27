/**
 * The two-time-pad guard for the FRI10 batch family.
 *
 * FRI9 masks its single auth with the viewing key used directly as an 80-byte
 * pad. That is a correct one-time pad for one auth. Masking N auths under the
 * same key would make it a two-time pad and leak the XOR of every pair of
 * waiters' rho, owner and amounts - while still round-tripping perfectly, so no
 * functional test would notice. These tests are the thing that notices.
 */
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { authPadAt, maskAuths, unmaskAuths, maskAuthAt, unmaskAuthAt } from "../src/backends/circle-batch/auth-pad.ts";
import { maskAuth, freshViewingKey, xorBytes, VIEWING_PAD_LEN } from "../src/backends/circle/witness-mask.ts";
import type { FriAuth } from "../src/backends/circle/air.ts";

function authWith(rho: number, owner: number, amount: bigint): FriAuth {
  return {
    leaf: new Uint8Array(32).fill(1),
    index: 0,
    path: [],
    root: new Uint8Array(32).fill(2),
    nullifier: new Uint8Array(32).fill(3),
    rho: new Uint8Array(32).fill(rho),
    owner: new Uint8Array(32).fill(owner),
    amountSats: amount,
    publicDeltaSats: 0n,
    amountCommit: new Uint8Array(32).fill(4),
    createdLeaf: new Uint8Array(32).fill(5),
    createdIndex: 0,
    createdPath: [],
  } as unknown as FriAuth;
}

describe("FRI10 per-auth pads", () => {
  it("the naive approach IS a two-time pad — this is what we are avoiding", () => {
    const key = freshViewingKey();
    const a1 = authWith(0xaa, 0x11, 1000n);
    const a2 = authWith(0xbb, 0x22, 2000n);
    // masking both with the same key, the FRI9 way
    const m1 = maskAuth(a1, key);
    const m2 = maskAuth(a2, key);
    // the pad cancels: the XOR of the masked values equals the XOR of the plaintexts
    assert.deepEqual(xorBytes(m1.rho, m2.rho), xorBytes(a1.rho, a2.rho));
    assert.deepEqual(xorBytes(m1.owner, m2.owner), xorBytes(a1.owner, a2.owner));
  });

  it("per-auth pads defeat it: masked XOR no longer equals plaintext XOR", () => {
    const key = freshViewingKey();
    const a1 = authWith(0xaa, 0x11, 1000n);
    const a2 = authWith(0xbb, 0x22, 2000n);
    const [m1, m2] = maskAuths([a1, a2], key);
    assert.notDeepEqual(xorBytes(m1!.rho, m2!.rho), xorBytes(a1.rho, a2.rho));
    assert.notDeepEqual(xorBytes(m1!.owner, m2!.owner), xorBytes(a1.owner, a2.owner));
  });

  it("pads are distinct per index and the right width", () => {
    const key = freshViewingKey();
    const pads = Array.from({ length: 16 }, (_, i) => authPadAt(key, i));
    for (const p of pads) assert.equal(p.length, VIEWING_PAD_LEN);
    const seen = new Set(pads.map((p) => Buffer.from(p).toString("hex")));
    assert.equal(seen.size, pads.length, "every index must get its own pad");
  });

  it("a different viewing key gives different pads", () => {
    assert.notDeepEqual(authPadAt(freshViewingKey(), 0), authPadAt(freshViewingKey(), 0));
  });

  it("mask then unmask round-trips at every index", () => {
    const key = freshViewingKey();
    const auths = Array.from({ length: 5 }, (_, i) => authWith(i + 1, i + 100, BigInt(1000 * (i + 1))));
    const back = unmaskAuths(maskAuths(auths, key), key);
    for (const [i, a] of auths.entries()) {
      assert.deepEqual(back[i]!.rho, a.rho, `rho ${i}`);
      assert.deepEqual(back[i]!.owner, a.owner, `owner ${i}`);
      assert.equal(back[i]!.amountSats, a.amountSats, `amount ${i}`);
    }
  });

  it("position is bound: unmasking at the wrong index does not recover the note", () => {
    const key = freshViewingKey();
    const a = authWith(0xaa, 0x11, 1000n);
    const masked = maskAuthAt(a, key, 3);
    assert.deepEqual(unmaskAuthAt(masked, key, 3).rho, a.rho, "right index recovers");
    assert.notDeepEqual(unmaskAuthAt(masked, key, 4).rho, a.rho, "wrong index must not");
  });

  it("rejects a wrong-width key and an out-of-range index", () => {
    assert.throws(() => authPadAt(new Uint8Array(31), 0), /viewing key width/);
    assert.throws(() => authPadAt(freshViewingKey(), -1), /out of range/);
    assert.throws(() => authPadAt(freshViewingKey(), 0x10000), /out of range/);
  });

  it("FRI9's single-auth masking is untouched", () => {
    const key = freshViewingKey();
    const a = authWith(0xaa, 0x11, 1000n);
    // index 0 must NOT silently equal the raw-key pad, or the new scheme would be
    // indistinguishable from the old one and the guard would be vacuous
    assert.notDeepEqual(maskAuthAt(a, key, 0).rho, maskAuth(a, key).rho);
    // and the FRI9 path still round-trips on its own terms
    assert.deepEqual(maskAuth(maskAuth(a, key), key).rho, a.rho);
  });
});

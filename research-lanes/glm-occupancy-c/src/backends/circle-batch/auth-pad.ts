/**
 * Per-auth one-time pads for the FRI10 batch family.
 *
 * WHY THIS EXISTS. `maskAuth(auth, key)` in ../circle/witness-mask.ts uses the
 * viewing key **directly** as an 80-byte pad:
 *
 *     rho             ^= key[0:32]
 *     owner           ^= key[32:64]
 *     amountSats      ^= key[64:72]
 *     publicDeltaSats ^= key[72:80]
 *
 * With one auth that is a one-time pad and it is fine. FRI9 carries exactly one,
 * so FRI9 is safe. The moment a batch masks N auths under the same key it becomes
 * a TWO-TIME PAD:
 *
 *     mask(a1).rho ^ mask(a2).rho  ==  a1.rho ^ a2.rho
 *
 * The pad cancels and the XOR of every pair of waiters' rho, owner and amounts
 * leaks. Amounts are 8 bytes of low entropy, so pairwise differences are often
 * enough to recover the values outright. Nothing about this breaks a functional
 * test - masked values still round-trip perfectly - which is exactly why it is
 * written down here rather than left to be rediscovered.
 *
 * So each auth gets its own pad, derived by domain-separated indexed hashing in
 * the same shape the opening-mask streams already use (witness-mask.ts:90):
 *
 *     pad(key, i) = H(VIEWING_TAG || AUTH_PAD_TAG || key || u32be(i) || ctr)
 *
 * Binding `i` into the pad also binds ORDER: reordering the auths makes them fail
 * to unmask, so the position of a waiter in the batch is not malleable.
 */
import { concatBytes } from "../../pool/bytes.ts";
import { defaultInternalHash, type InternalHash } from "../circle/internal-hash.ts";
import { maskAuth, VIEWING_PAD_LEN, VIEWING_TAG } from "../circle/witness-mask.ts";
import type { FriAuth } from "../circle/air.ts";

export const AUTH_PAD_TAG = new TextEncoder().encode("PAA1-AUTH-PAD-v1");

function u32be(n: number): Uint8Array {
  return Uint8Array.of((n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff);
}

/** 80 distinct bytes for auth `index`, deterministic in the viewing key. */
export function authPadAt(
  key: Uint8Array,
  index: number,
  hash: InternalHash = defaultInternalHash(),
): Uint8Array {
  if (key.length !== VIEWING_PAD_LEN) throw new Error("viewing key width");
  if (!Number.isInteger(index) || index < 0 || index > 0xffff) {
    throw new Error(`auth index out of range: ${index}`);
  }
  const blocks: Uint8Array[] = [];
  for (let ctr = 0; blocks.length * 32 < VIEWING_PAD_LEN; ctr += 1) {
    blocks.push(
      hash.digest(concatBytes(VIEWING_TAG, AUTH_PAD_TAG, key, u32be(index), Uint8Array.of(ctr))),
    );
  }
  return concatBytes(...blocks).subarray(0, VIEWING_PAD_LEN);
}

/**
 * Mask one auth at its position in the batch. Self-inverse like `maskAuth`, since
 * the pad is deterministic and the operation is XOR.
 */
export function maskAuthAt(
  auth: FriAuth,
  key: Uint8Array,
  index: number,
  hash: InternalHash = defaultInternalHash(),
): FriAuth {
  return maskAuth(auth, authPadAt(key, index, hash));
}

export function unmaskAuthAt(
  auth: FriAuth,
  key: Uint8Array,
  index: number,
  hash: InternalHash = defaultInternalHash(),
): FriAuth {
  return maskAuthAt(auth, key, index, hash);
}

export function maskAuths(
  auths: readonly FriAuth[],
  key: Uint8Array,
  hash: InternalHash = defaultInternalHash(),
): FriAuth[] {
  return auths.map((a, i) => maskAuthAt(a, key, i, hash));
}

export function unmaskAuths(
  auths: readonly FriAuth[],
  key: Uint8Array,
  hash: InternalHash = defaultInternalHash(),
): FriAuth[] {
  return auths.map((a, i) => unmaskAuthAt(a, key, i, hash));
}

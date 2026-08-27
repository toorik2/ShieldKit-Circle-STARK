/**
 * One-time pad for the published note preimage (rho, owner, amounts).
 * viewingKey is 80 uniform bytes, never written into encodeFriProof.
 * Masked fields are statistically independent of the witness (OTP).
 */
import { concatBytes, readU64BE, writeU64BE } from "../../pool/bytes.ts";
import type { FriAuth } from "./air.ts";
import { defaultInternalHash, type InternalHash } from "./internal-hash.ts";
import { add, mul } from "./m31.ts";

export const VIEWING_TAG = new TextEncoder().encode("PAA1-VIEW-v1");
export const FRI_OPEN_MASK_TAG = new TextEncoder().encode("fri-open-mask");
export const VIEWING_PAD_LEN = 80;

export function freshViewingKey(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(VIEWING_PAD_LEN));
}

export function viewingCommit(key: Uint8Array, hash: InternalHash = defaultInternalHash()): Uint8Array {
  if (key.length !== VIEWING_PAD_LEN) throw new Error("viewing key width");
  return hash.digest(concatBytes(VIEWING_TAG, key));
}

export function xorBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const n = Math.min(a.length, b.length);
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i += 1) out[i] = a[i]! ^ b[i]!;
  return out;
}

export function maskAuth(auth: FriAuth, key: Uint8Array): FriAuth {
  if (key.length !== VIEWING_PAD_LEN) throw new Error("viewing key width");
  return {
    ...auth,
    rho: xorBytes(auth.rho, key.subarray(0, 32)),
    owner: xorBytes(auth.owner, key.subarray(32, 64)),
    amountSats: readU64BE(xorBytes(writeU64BE(auth.amountSats), key.subarray(64, 72)), 0),
    publicDeltaSats: readU64BE(xorBytes(writeU64BE(auth.publicDeltaSats), key.subarray(72, 80)), 0),
  };
}

export function unmaskAuth(auth: FriAuth, key: Uint8Array): FriAuth {
  return maskAuth(auth, key);
}

/**
 * Degree-0 mask felt. Leftover for contrast tests: opened[i]−opened[j] = Q[i]−Q[j]
 * because the constant cancels. Production openings use `openingMaskAt` (on-domain
 * poly plus off-domain Z·R, ePrint 2024/1037-style). Coeffs are a PRF of the
 * **published** viewingCommit so a public verifier can check N=(opened−R)Z.
 * A key-only PRF would not be checkable after encodeFriProof drops the key.
 * Not a Lean HVZK theorem.
 */
export function openingMaskFelt(commit: Uint8Array, hash: InternalHash = defaultInternalHash()): bigint {
  if (commit.length !== 32) throw new Error("viewing commit width");
  const h = hash.digest(concatBytes(VIEWING_TAG, commit, FRI_OPEN_MASK_TAG));
  const n =
    BigInt(h[0]!) |
    (BigInt(h[1]!) << 8n) |
    (BigInt(h[2]!) << 16n) |
    (BigInt(h[3]! & 0x7f) << 24n);
  return n % 2147483647n;
}

/** On-domain index poly degree. Off-domain Z·R uses OPEN_MASK_OFF_DEGREE. */
export const OPEN_MASK_DEGREE = 7;
/** Off-trace randomizer degree (ePrint 2024/1037 ZH·R). Not a Lean HVZK theorem. */
export const OPEN_MASK_OFF_DEGREE = 35;

function feltFromHash(h: Uint8Array): bigint {
  const n =
    BigInt(h[0]!) |
    (BigInt(h[1]!) << 8n) |
    (BigInt(h[2]!) << 16n) |
    (BigInt(h[3]! & 0x7f) << 24n);
  return n % 2147483647n;
}

export function openingMaskCoeffs(
  commit: Uint8Array,
  hash: InternalHash = defaultInternalHash(),
  which: "on" | "off" = "on",
): bigint[] {
  if (commit.length !== 32) throw new Error("viewing commit width");
  const deg = which === "on" ? OPEN_MASK_DEGREE : OPEN_MASK_OFF_DEGREE;
  const stream = which === "on" ? 0 : 1;
  const out: bigint[] = [];
  for (let block = 0; out.length <= deg; block += 1) {
    const h = hash.digest(concatBytes(VIEWING_TAG, commit, FRI_OPEN_MASK_TAG, Uint8Array.of(stream, block)));
    for (let i = 0; i < 8 && out.length <= deg; i += 1) {
      out.push(feltFromHash(h.subarray(i * 4, i * 4 + 4)));
    }
  }
  return out;
}

/** R(index+1) = c0 + c1 x + c2 x^2 + c3 x^3 over M31. Unique per LDE index. */
export function evalMaskPoly(coeffs: readonly bigint[], index: number): bigint {
  const x = BigInt((index & 1023) + 1);
  let acc = 0n;
  let pow = 1n;
  for (const c of coeffs) {
    acc = (acc + ((c % 2147483647n) * pow)) % 2147483647n;
    pow = (pow * x) % 2147483647n;
  }
  return acc;
}

/** R_on(i) + Z(i)·R_off(i). Z=0 on the trace so AIR-on-H is only R_on. */
export function openingMaskAt(
  commit: Uint8Array,
  index: number,
  hash: InternalHash = defaultInternalHash(),
  zAt = 0n,
): bigint {
  const h = hash ?? defaultInternalHash();
  const on = evalMaskPoly(openingMaskCoeffs(commit, h, "on"), index);
  if (zAt === 0n) return on;
  return add(on, mul(zAt, evalMaskPoly(openingMaskCoeffs(commit, h, "off"), index)));
}

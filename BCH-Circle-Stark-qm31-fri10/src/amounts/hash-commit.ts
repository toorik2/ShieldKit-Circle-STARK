/**
 * Production note-amount commit: tagged internal hash (default SHA-256).
 * Hides v given a uniform 32-byte blind. No discrete-log / EC assumption.
 * Pedersen (C = vG + rH) stays in pedersen.ts as a comparison plugin only.
 */
import { concatBytes, writeI64LE, ZERO32 } from "../pool/bytes.ts";
import { defaultInternalHash, type InternalHash } from "../backends/circle/internal-hash.ts";

export const HASH_AMOUNT_TAG = new TextEncoder().encode("PAA1-HASH-AMT-v1");
export const HASH_NET_TAG = new TextEncoder().encode("PAA1-HASH-NET-v1");
export const HASH_RESERVE_TAG = new TextEncoder().encode("PAA1-HASH-RSV-v1");

/** H(tag || amount_i64le || blind32). Default H is SHA-256. */
export function commitAmount(
  value: bigint,
  blind: Uint8Array,
  hash: InternalHash = defaultInternalHash(),
): Uint8Array {
  if (value < 0n) throw new Error("negative amount");
  if (blind.length !== 32) throw new Error("amount blind width");
  return hash.digest(concatBytes(HASH_AMOUNT_TAG, writeI64LE(value), blind));
}

export const NET_BLIND_LEN = 32;

/** Uniform 32-byte blind for `commitPublicNet`. Not written into `encodeStatement`. */
export function freshNetBlind(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(NET_BLIND_LEN));
}

/**
 * Hiding commit of the public deposit/withdraw net.
 * H(tag || amount_i64le || payout32 || blind32). Blind stays off the encoding.
 * Still a tagged hash — not Bulletproofs or Orchard.
 */
export function commitPublicNet(
  publicAmountSats: bigint,
  payoutLockingDigest: Uint8Array,
  netBlind: Uint8Array,
  hash: InternalHash = defaultInternalHash(),
): Uint8Array {
  if (netBlind.length !== NET_BLIND_LEN) throw new Error("net blind width");
  const payout = payoutLockingDigest.length === 32 ? payoutLockingDigest : ZERO32;
  return hash.digest(concatBytes(HASH_NET_TAG, writeI64LE(publicAmountSats), payout, netBlind));
}

/** Hiding commit of a reserve so `encodeStatement` does not carry the raw i64. */
export function commitReserve(
  reserveSats: bigint,
  netBlind: Uint8Array,
  hash: InternalHash = defaultInternalHash(),
): Uint8Array {
  if (reserveSats < 0n) throw new Error("negative reserve");
  if (netBlind.length !== NET_BLIND_LEN) throw new Error("net blind width");
  return hash.digest(concatBytes(HASH_RESERVE_TAG, writeI64LE(reserveSats), netBlind));
}

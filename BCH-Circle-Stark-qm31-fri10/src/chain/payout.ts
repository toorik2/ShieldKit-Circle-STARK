/**
 * Withdraw payout lock. HASH256 of this bytecode is `payoutLockingDigest`
 * for a single payout. Multi-payout uses `hashPayoutSet` (each lock + value).
 * Distinct from the fee-funder P2PKH so feeUtxo−change is not the payout.
 */
import { hash256 } from "@bitauth/libauth";
import { concatBytes } from "../pool/bytes.ts";

const HASH160_FIXTURE = new Uint8Array(20).fill(0x11);

/** Standard P2PKH template used as the lab withdraw payout locking bytecode. */
export const LAB_PAYOUT_LOCKING = Uint8Array.of(
  0x76,
  0xa9,
  0x14,
  ...HASH160_FIXTURE,
  0x88,
  0xac,
);

export function hashPayoutLocking(locking: Uint8Array): Uint8Array {
  return hash256(locking);
}

export const LAB_PAYOUT_DIGEST = hashPayoutLocking(LAB_PAYOUT_LOCKING);

/**
 * 8-byte LE signed script number. Matches CashVM `<8> OP_NUM2BIN` of OUTPUTVALUE.
 */
export function scriptNum8(n: bigint): Uint8Array {
  if (n < 0n) throw new Error("payout sats");
  const out = new Uint8Array(8);
  if (n === 0n) return out;
  const bytes: number[] = [];
  let v = n;
  while (v > 0n) {
    bytes.push(Number(v & 0xffn));
    v >>= 8n;
  }
  if ((bytes[bytes.length - 1]! & 0x80) !== 0) bytes.push(0);
  if (bytes.length > 8) throw new Error("payout sats width");
  out.set(Uint8Array.from(bytes), 0);
  return out;
}

export type PayoutPair = { lockingBytecode: Uint8Array; sats: bigint };

/**
 * One payout: HASH256(lock). Two or more: HASH256 of the concatenation of
 * HASH256(lock_i) || NUM2BIN(value_i, 8) in output order. Binds every payout
 * lock and amount so a later output cannot be redirected or swapped.
 */
export function hashPayoutSet(payouts: PayoutPair[]): Uint8Array {
  if (payouts.length === 0) return new Uint8Array(32);
  if (payouts.length === 1) return hashPayoutLocking(payouts[0]!.lockingBytecode);
  const parts = payouts.map((p) => concatBytes(hashPayoutLocking(p.lockingBytecode), scriptNum8(p.sats)));
  return hash256(concatBytes(...parts));
}

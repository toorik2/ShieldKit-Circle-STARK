/**
 * Public withdraw outputs snap to these sizes. Leftover stays a change *note*
 * in the same Merkle set. Does not split the tree into Classic tiers.
 * Smallest slice is 1000 sats so Chipnet lab notes can fill exactly.
 */
export const PAYOUT_BUCKETS_SATS: readonly bigint[] = [
  100_000_000n, // 1 BCH
  10_000_000n, // 0.1 BCH
  1_000_000n, // 0.01 BCH
  100_000n, // 0.001 BCH
  10_000n, // 0.0001 BCH
  1_000n, // 0.00001 BCH
];

export type BucketSplit = {
  requested: bigint;
  publicSats: bigint;
  slices: bigint[];
  unbucketed: bigint;
};

/** Greedy fill of `requested` from PAYOUT_BUCKETS_SATS. Remainder is unbucketed. */
export function splitIntoBuckets(requested: bigint): BucketSplit {
  if (requested < 0n) throw new Error("bucket requested sats");
  const slices: bigint[] = [];
  let left = requested;
  for (const b of PAYOUT_BUCKETS_SATS) {
    while (left >= b) {
      slices.push(b);
      left -= b;
    }
  }
  const publicSats = requested - left;
  return { requested, publicSats, slices, unbucketed: left };
}

export function assertBucketFilling(sats: bigint): bigint[] {
  const split = splitIntoBuckets(sats);
  if (split.publicSats <= 0n) {
    throw new Error(`withdraw ${sats} is below the smallest payout bucket ${PAYOUT_BUCKETS_SATS.at(-1)}`);
  }
  return split.slices;
}

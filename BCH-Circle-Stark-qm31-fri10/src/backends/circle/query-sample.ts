/**
 * Fiat–Shamir query indices with unique first-fold orbits.
 * Mix-in is the current unique count (same "q"||count stream as before);
 * a colliding index or partner (i + N/2) is discarded and the stream retries.
 */
import { concatBytes } from "../../pool/bytes.ts";
import type { InternalHash } from "./internal-hash.ts";

export const QUERY_MIX_TAG = new TextEncoder().encode("q");

/** ABL pairs i with (i+n/2) mod n; the first-fold orbit is i mod (n/2). */
export function firstFoldOrbit(index: number, n: number): number {
  if (!Number.isInteger(n) || n < 2 || n % 2 !== 0) throw new Error("FRI domain");
  const i = ((index % n) + n) % n;
  return i % (n / 2);
}

export type UniqueQuerySample = {
  indices: number[];
  attempts: number;
};

export function sampleUniqueQueryIndices(
  hash: InternalHash,
  seed: Uint8Array,
  n: number,
  count: number,
): UniqueQuerySample {
  if (!Number.isInteger(count) || count < 1) throw new Error("query count");
  if (!Number.isInteger(n) || n < 2 || n % 2 !== 0) throw new Error("FRI domain");
  const orbits = n / 2;
  if (count > orbits) throw new Error("query count exceeds first-fold orbits");
  if (seed.length !== 32) throw new Error("FS seed width");
  const indices: number[] = [];
  const seen = new Set<number>();
  let h = seed;
  let attempts = 0;
  const cap = Math.max(4096, count * 64);
  while (indices.length < count) {
    if (attempts >= cap) throw new Error("unique-orbit sampling failed");
    h = hash.digest(concatBytes(h, QUERY_MIX_TAG, Uint8Array.of(indices.length)));
    attempts += 1;
    const v = ((h[0]! << 8) | h[1]!) % n;
    const orbit = firstFoldOrbit(v, n);
    if (seen.has(orbit)) continue;
    seen.add(orbit);
    indices.push(v);
  }
  return { indices, attempts };
}

export function uniqueQueryIndices(
  hash: InternalHash,
  seed: Uint8Array,
  n: number,
  count: number,
): number[] {
  return sampleUniqueQueryIndices(hash, seed, n, count).indices;
}

import { addPoints, CIRCLE_GEN, CIRCLE_ONE, scalarMul, type CirclePoint } from "./group.ts";

/** M31's circle group has two-adic order 2^31. */
export const CIRCLE_TWO_ADIC_LOG_ORDER = 31;

function checkedLog2(n: number): number {
  if (!Number.isInteger(n) || n < 2 || (n & (n - 1)) !== 0) {
    throw new Error(`circle domain size must be a power of two >= 2: ${n}`);
  }
  const log = Math.log2(n);
  if (log > CIRCLE_TWO_ADIC_LOG_ORDER - 1) {
    throw new Error(`circle domain too large: 2^${log}`);
  }
  return log;
}

function points(start: CirclePoint, step: CirclePoint, n: number): CirclePoint[] {
  const out: CirclePoint[] = [start];
  let acc = start;
  for (let i = 1; i < n; i += 1) {
    acc = addPoints(acc, step);
    out.push(acc);
  }
  return out;
}

const subgroupCache = new Map<number, CirclePoint[]>();
const halfCosetCache = new Map<number, CirclePoint[]>();

/** Legacy trace domain: the order-n subgroup containing the identity. */
export function circleSubgroupDomain(n: number): CirclePoint[] {
  const hit = subgroupCache.get(n);
  if (hit) return hit;
  const log = checkedLog2(n);
  const step = scalarMul(CIRCLE_GEN, 2n ** BigInt(CIRCLE_TWO_ADIC_LOG_ORDER - log));
  const domain = points(CIRCLE_ONE, step, n);
  subgroupCache.set(n, domain);
  return domain;
}

/**
 * Canonical disjoint LDE domain for a successor proof.
 *
 * If g generates the order-n subgroup, this is g/2 + <g>. It is disjoint from
 * every subgroup contained in <g>, remains closed under the first-fold
 * antipodal pairing, and projects under circle doubling to the corresponding
 * half-coset of size n/2.
 */
export function circleHalfCosetDomain(n: number): CirclePoint[] {
  const hit = halfCosetCache.get(n);
  if (hit) return hit;
  const log = checkedLog2(n);
  const stepScalar = 2n ** BigInt(CIRCLE_TWO_ADIC_LOG_ORDER - log);
  const step = scalarMul(CIRCLE_GEN, stepScalar);
  const halfStep = scalarMul(CIRCLE_GEN, stepScalar / 2n);
  const domain = points(halfStep, step, n);
  halfCosetCache.set(n, domain);
  return domain;
}

export function circleHalfCosetPoint(n: number, index: number): CirclePoint {
  const log = checkedLog2(n);
  if (!Number.isInteger(index) || index < 0 || index >= n) throw new Error("circle half-coset index");
  const stepScalar = 2n ** BigInt(CIRCLE_TWO_ADIC_LOG_ORDER - log);
  return scalarMul(CIRCLE_GEN, stepScalar / 2n + BigInt(index) * stepScalar);
}

export function circlePointKey(p: CirclePoint): string {
  return `${p.x}:${p.y}`;
}

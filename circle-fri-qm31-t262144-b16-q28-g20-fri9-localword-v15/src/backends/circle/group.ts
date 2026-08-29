import { add, el, mul, neg, square, sub, type M31El } from "./m31.ts";

/**
 * Circle group x² + y² = 1 over M31 (ePrint 2024/278).
 * Addition is complex multiplication: (x1+iy1)(x2+iy2).
 */
export type CirclePoint = { x: M31El; y: M31El };

export const CIRCLE_ONE: CirclePoint = { x: 1n, y: 0n };

/** Stwo / Plonky3 M31 generator (x=2). Verified on-circle in tests. */
export const CIRCLE_GEN: CirclePoint = { x: 2n, y: 1268011823n };

export function onCircle(p: CirclePoint): boolean {
  return add(square(p.x), square(p.y)) === 1n;
}

export function addPoints(a: CirclePoint, b: CirclePoint): CirclePoint {
  return {
    x: sub(mul(a.x, b.x), mul(a.y, b.y)),
    y: add(mul(a.x, b.y), mul(a.y, b.x)),
  };
}

export function doublePoint(p: CirclePoint): CirclePoint {
  return addPoints(p, p);
}

export function negatePoint(p: CirclePoint): CirclePoint {
  return { x: p.x, y: neg(p.y) };
}

export function scalarMul(p: CirclePoint, k: bigint): CirclePoint {
  if (k < 0n) throw new Error("scalar must be nonnegative");
  let acc = CIRCLE_ONE;
  let base = p;
  let n = k;
  while (n > 0n) {
    if (n & 1n) acc = addPoints(acc, base);
    base = doublePoint(base);
    n >>= 1n;
  }
  return acc;
}

/** Circle doubling map π(x,y) = (x² − y², 2xy). Equals 2P. */
export function projectPi(p: CirclePoint): CirclePoint {
  return {
    x: sub(square(p.x), square(p.y)),
    y: mul(2n, mul(p.x, p.y)),
  };
}

export function assertOnCircle(p: CirclePoint, name = "point"): CirclePoint {
  el(p.x, `${name}.x`);
  el(p.y, `${name}.y`);
  if (!onCircle(p)) throw new Error(`${name} is not on x^2+y^2=1`);
  return p;
}

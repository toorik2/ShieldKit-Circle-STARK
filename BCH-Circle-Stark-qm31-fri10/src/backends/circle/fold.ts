import { add, inv, mul, sub, type M31El } from "./m31.ts";
import { liftM31, qmAdd, qmMul, qmMulM31, qmSub, type QM31El } from "./qm31.ts";
import { negatePoint, projectPi, type CirclePoint } from "./group.ts";

/**
 * One Circle-FRI fold (2024/278 style).
 *
 * For evaluations f(P), f(P̄) where P̄ = (x, −y), and challenge λ:
 *   f'(π(P)) = (f(P)+f(P̄))/2 + λ · (f(P)−f(P̄)) / (2x)
 *
 * This is the first closed P2 piece (circle + one fold). It is not a verifier.
 */
export function foldPair(
  p: CirclePoint,
  fAtP: M31El,
  fAtConj: M31El,
  lambda: M31El,
): { domain: CirclePoint; value: M31El } {
  const twoInv = inv(2n);
  const even = mul(add(fAtP, fAtConj), twoInv);
  const odd = mul(sub(fAtP, fAtConj), twoInv);
  const denom = p.x !== 0n ? p.x : p.y;
  if (denom === 0n) throw new Error("cannot fold at origin");
  return {
    domain: projectPi(p),
    value: add(even, mul(lambda, mul(odd, inv(denom)))),
  };
}

export function conjugate(p: CirclePoint): CirclePoint {
  return negatePoint(p);
}

/**
 * First-fold occupancy: M31 openings, QM31 λ.
 * even/odd stay M31; result = lift(even) + λ · odd  in QM31.
 */
export function foldPairSecure(
  p: CirclePoint,
  fAtP: M31El,
  fAtConj: M31El,
  lambda: QM31El,
): { domain: CirclePoint; value: QM31El } {
  const twoInv = inv(2n);
  const even = mul(add(fAtP, fAtConj), twoInv);
  const odd = mul(sub(fAtP, fAtConj), twoInv);
  const denom = p.x !== 0n ? p.x : p.y;
  if (denom === 0n) throw new Error("cannot fold at origin");
  const oddOver = mul(odd, inv(denom));
  return {
    domain: projectPi(p),
    value: qmAdd(liftM31(even), qmMulM31(lambda, oddOver)),
  };
}

/** Later-layer fold: both openings already QM31. */
export function foldPairQm31(
  p: CirclePoint,
  fAtP: QM31El,
  fAtConj: QM31El,
  lambda: QM31El,
): { domain: CirclePoint; value: QM31El } {
  const twoInv = inv(2n);
  const even = qmMulM31(qmAdd(fAtP, fAtConj), twoInv);
  const odd = qmMulM31(qmSub(fAtP, fAtConj), twoInv);
  const denom = p.x !== 0n ? p.x : p.y;
  if (denom === 0n) throw new Error("cannot fold at origin");
  return {
    domain: projectPi(p),
    value: qmAdd(even, qmMul(lambda, qmMulM31(odd, inv(denom)))),
  };
}

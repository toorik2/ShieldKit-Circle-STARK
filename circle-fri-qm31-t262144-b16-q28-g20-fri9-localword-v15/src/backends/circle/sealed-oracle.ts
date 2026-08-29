import type { CirclePoint } from "./group.ts";
import { evalCirclePoly, interpolateCircle } from "./interpolate.ts";
import { add, inv, M31, mul, sub, type M31El } from "./m31.ts";

declare const privateTraceBrand: unique symbol;
declare const sealedOracleBrand: unique symbol;

export type PrivateTraceSet = {
  readonly [privateTraceBrand]: true;
  readonly traceDomain: readonly CirclePoint[];
  readonly columns: readonly (readonly M31El[])[];
};

export type SealedOracleSet = {
  readonly [sealedOracleBrand]: true;
  readonly traceLength: number;
  readonly maskDimension: number;
  readonly evaluationDomain: readonly CirclePoint[];
  readonly columns: readonly (readonly M31El[])[];
};

export type FeltSource = () => M31El;

export function freshM31(): M31El {
  const bytes = new Uint8Array(4);
  for (;;) {
    crypto.getRandomValues(bytes);
    const candidate =
      (bytes[0]! | (bytes[1]! << 8) | (bytes[2]! << 16) | (bytes[3]! << 24)) >>> 0;
    if (candidate < Number(M31)) return BigInt(candidate);
  }
}

export function createPrivateTraceSet(
  traceDomain: readonly CirclePoint[],
  columns: readonly (readonly M31El[])[],
): PrivateTraceSet {
  if (traceDomain.length < 2) throw new Error("private trace domain");
  if (columns.length < 1) throw new Error("private trace columns");
  for (const column of columns) {
    if (column.length !== traceDomain.length) throw new Error("private trace column length");
  }
  return { traceDomain, columns } as PrivateTraceSet;
}

/** Product over the distinct x-coordinates of a conjugation-closed trace domain. */
export function circleTraceVanishingAt(traceDomain: readonly CirclePoint[], p: CirclePoint): M31El {
  const xs = new Set<string>();
  let acc = 1n;
  for (const point of traceDomain) {
    const key = point.x.toString();
    if (xs.has(key)) continue;
    xs.add(key);
    acc = mul(acc, sub(p.x, point.x));
  }
  return acc;
}

/** Circle basis 1,y,x,xy,x^2,x^2y,... with exactly coeffs.length dimensions. */
export function evalCircleMaskBasis(coeffs: readonly M31El[], p: CirclePoint): M31El {
  let even = 0n;
  let odd = 0n;
  let xPower = 1n;
  for (let i = 0; i < coeffs.length; i += 2) {
    even = add(even, mul(coeffs[i]!, xPower));
    if (i + 1 < coeffs.length) odd = add(odd, mul(coeffs[i + 1]!, xPower));
    xPower = mul(xPower, p.x);
  }
  return add(even, mul(p.y, odd));
}

/**
 * Seal every private column as w_hat = w + Z_H r on a disjoint evaluation
 * domain. Randomizer coefficients never leave this function.
 *
 * This is the witness-oracle sealing primitive, not yet the complete STARK ZK
 * compiler: quotient decomposition and the independent FRI mask remain separate
 * transcript obligations.
 */
export function sealPrivateTrace(
  privateTrace: PrivateTraceSet,
  evaluationDomain: readonly CirclePoint[],
  maskDimension: number,
  randomFelt: FeltSource = freshM31,
): SealedOracleSet {
  if (!Number.isInteger(maskDimension) || maskDimension < 1) {
    throw new Error("mask dimension");
  }
  const z = evaluationDomain.map((p) => circleTraceVanishingAt(privateTrace.traceDomain, p));
  if (z.some((value) => value === 0n)) {
    throw new Error("sealed-oracle evaluation domain intersects trace domain");
  }
  const columns = privateTrace.columns.map((traceColumn) => {
    const witness = interpolateCircle([...privateTrace.traceDomain], [...traceColumn]);
    const randomizer = Array.from({ length: maskDimension }, () => randomFelt());
    return evaluationDomain.map((p, i) =>
      add(evalCirclePoly(witness, p), mul(z[i]!, evalCircleMaskBasis(randomizer, p))),
    );
  });
  return {
    traceLength: privateTrace.traceDomain.length,
    maskDimension,
    evaluationDomain,
    columns,
  } as unknown as SealedOracleSet;
}

/** Public matrix used to prove that the chosen mask space covers opened forms. */
export function randomizerEvaluationMatrix(
  traceDomain: readonly CirclePoint[],
  observationPoints: readonly CirclePoint[],
  maskDimension: number,
): M31El[][] {
  return observationPoints.map((p) => {
    const z = circleTraceVanishingAt(traceDomain, p);
    const row: M31El[] = [];
    let xPower = 1n;
    for (let column = 0; column < maskDimension; column += 2) {
      row.push(mul(z, xPower));
      if (column + 1 < maskDimension) row.push(mul(z, mul(p.y, xPower)));
      xPower = mul(xPower, p.x);
    }
    return row;
  });
}

export function m31MatrixRank(matrix: readonly (readonly M31El[])[]): number {
  if (matrix.length === 0) return 0;
  const width = matrix[0]!.length;
  const a = matrix.map((row) => {
    if (row.length !== width) throw new Error("matrix width");
    return [...row];
  });
  let rank = 0;
  for (let column = 0; column < width && rank < a.length; column += 1) {
    let pivot = rank;
    while (pivot < a.length && a[pivot]![column] === 0n) pivot += 1;
    if (pivot === a.length) continue;
    [a[rank], a[pivot]] = [a[pivot]!, a[rank]!];
    const scale = inv(a[rank]![column]!);
    for (let j = column; j < width; j += 1) a[rank]![j] = mul(a[rank]![j]!, scale);
    for (let row = 0; row < a.length; row += 1) {
      if (row === rank) continue;
      const factor = a[row]![column]!;
      if (factor === 0n) continue;
      for (let j = column; j < width; j += 1) {
        a[row]![j] = sub(a[row]![j]!, mul(factor, a[rank]![j]!));
      }
    }
    rank += 1;
  }
  return rank;
}

/** Rank of public evaluations as linear forms in the original trace values. */
export function traceEvaluationRank(
  traceDomain: readonly CirclePoint[],
  observationPoints: readonly CirclePoint[],
): number {
  const matrix: M31El[][] = observationPoints.map(() => []);
  for (let basis = 0; basis < traceDomain.length; basis += 1) {
    const values = Array.from({ length: traceDomain.length }, (_, i) => (i === basis ? 1n : 0n));
    const interp = interpolateCircle([...traceDomain], values);
    for (let row = 0; row < observationPoints.length; row += 1) {
      matrix[row]!.push(evalCirclePoly(interp, observationPoints[row]!));
    }
  }
  return m31MatrixRank(matrix);
}

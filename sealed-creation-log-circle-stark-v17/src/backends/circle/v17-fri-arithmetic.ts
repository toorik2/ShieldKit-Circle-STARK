/**
 * v17 FRI arithmetic kernel.
 *
 * The proof carries values and twiddles, never inverses. All inverses in this
 * module are derived by the verifier from the authenticated twiddles.
 */
import { M31, inv as mInv, type M31El } from "./m31.ts";
import {
  liftM31,
  qmAdd,
  qmInv,
  qmMul,
  qmMulM31,
  qmSub,
  type QM31El,
} from "./qm31.ts";

/** Eight radix-four layers plus one binary tail use 8 * 3 + 1 divisors. */
export const V17_FRI_CURRENT_DENOMINATOR_COUNT = 25;

export type V17FriRadixFourLayer = {
  readonly folds: 2;
  readonly values: readonly [QM31El, QM31El, QM31El, QM31El];
  readonly twiddles: readonly [M31El, M31El, M31El];
  /** One independently sampled challenge for each binary fold. */
  readonly alphas: readonly [QM31El, QM31El];
};

export type V17FriBinaryLayer = {
  readonly folds: 1;
  readonly values: readonly [QM31El, QM31El];
  readonly twiddles: readonly [M31El];
  readonly alphas: readonly [QM31El];
};

export type V17FriFoldLayer = V17FriRadixFourLayer | V17FriBinaryLayer;

export type V17BatchInversionCounts = {
  readonly denominators: number;
  readonly qm31Inversions: 1;
  readonly qm31Multiplications: number;
};

function isZero(value: QM31El): boolean {
  return value[0] === 0n && value[1] === 0n && value[2] === 0n && value[3] === 0n;
}

function assertCanonicalQm31(value: QM31El, index: number): void {
  for (const limb of value) {
    if (limb < 0n || limb >= M31) throw new Error(`noncanonical QM31 denominator at ${index}`);
  }
}

/** Exact field-operation count of the prefix/suffix construction below. */
export function v17Qm31BatchInversionCounts(denominators: number): V17BatchInversionCounts {
  if (!Number.isSafeInteger(denominators) || denominators < 1) {
    throw new Error("QM31 batch inversion requires at least one denominator");
  }
  return {
    denominators,
    qm31Inversions: 1,
    qm31Multiplications: 3 * (denominators - 1),
  };
}

/**
 * Invert a non-empty QM31 vector with one inversion and 3(n-1)
 * multiplications. The initial scan rejects each zero explicitly before any
 * prefix product is evaluated; a zero cannot be hidden inside the product.
 */
export function invertQm31Batch(denominators: readonly QM31El[]): readonly QM31El[] {
  v17Qm31BatchInversionCounts(denominators.length);
  denominators.forEach((denominator, index) => {
    assertCanonicalQm31(denominator, index);
    if (isZero(denominator)) throw new Error(`zero QM31 denominator at ${index}`);
  });

  const prefixes: QM31El[] = new Array(denominators.length);
  prefixes[0] = denominators[0]!;
  for (let index = 1; index < denominators.length; index += 1) {
    prefixes[index] = qmMul(prefixes[index - 1]!, denominators[index]!);
  }

  const inverses: QM31El[] = new Array(denominators.length);
  let suffixInverse = qmInv(prefixes[prefixes.length - 1]!);
  for (let index = denominators.length - 1; index > 0; index -= 1) {
    inverses[index] = qmMul(suffixInverse, prefixes[index - 1]!);
    suffixInverse = qmMul(suffixInverse, denominators[index]!);
  }
  inverses[0] = suffixInverse;
  return inverses;
}

function scalarFromLiftedQm31(value: QM31El, index: number): M31El {
  if (value[1] !== 0n || value[2] !== 0n || value[3] !== 0n) {
    throw new Error(`FRI scalar inverse escaped M31 at ${index}`);
  }
  return value[0];
}

function foldPairFromScalarInverse(
  left: QM31El,
  right: QM31El,
  inverseTwiddle: M31El,
  alpha: QM31El,
): QM31El {
  const sum = qmAdd(left, right);
  const odd = qmMulM31(qmSub(left, right), inverseTwiddle);
  return qmAdd(sum, qmMul(alpha, odd));
}

function fusedFourWayFromScalarInverses(
  values: readonly [QM31El, QM31El, QM31El, QM31El],
  inverseTwiddles: readonly [M31El, M31El, M31El],
  alphas: readonly [QM31El, QM31El],
): QM31El {
  const lower = foldPairFromScalarInverse(values[0], values[1], inverseTwiddles[0], alphas[0]);
  const upper = foldPairFromScalarInverse(values[2], values[3], inverseTwiddles[1], alphas[0]);
  return foldPairFromScalarInverse(lower, upper, inverseTwiddles[2], alphas[1]);
}

/**
 * The current radix-four semantics, fused into one expression. This small
 * entry point remains useful for differential tests; the full-query entry
 * point below amortizes one inversion across all 25 divisors.
 */
export function foldFriFourWayFused(
  values: readonly [QM31El, QM31El, QM31El, QM31El],
  twiddles: readonly [M31El, M31El, M31El],
  alphas: readonly [QM31El, QM31El],
): QM31El {
  const liftedInverses = invertQm31Batch(twiddles.map(liftM31));
  return fusedFourWayFromScalarInverses(values, [
    scalarFromLiftedQm31(liftedInverses[0]!, 0),
    scalarFromLiftedQm31(liftedInverses[1]!, 1),
    scalarFromLiftedQm31(liftedInverses[2]!, 2),
  ], alphas);
}

/**
 * Fold every opened layer for one query. The current schedule has 25
 * divisors; accepting a larger future schedule keeps the primitive general,
 * while rejecting smaller schedules prevents accidental non-production use.
 */
export function foldFriQueryBatched(layers: readonly V17FriFoldLayer[]): readonly QM31El[] {
  const twiddles = layers.flatMap((layer) => [...layer.twiddles]);
  if (twiddles.length < V17_FRI_CURRENT_DENOMINATOR_COUNT) {
    throw new Error(`v17 FRI batch requires at least ${V17_FRI_CURRENT_DENOMINATOR_COUNT} denominators`);
  }
  const liftedInverses = invertQm31Batch(twiddles.map(liftM31));
  const scalarInverses = liftedInverses.map(scalarFromLiftedQm31);
  let offset = 0;

  return layers.map((layer) => {
    if (layer.folds === 1) {
      const folded = foldPairFromScalarInverse(
        layer.values[0],
        layer.values[1],
        scalarInverses[offset]!,
        layer.alphas[0],
      );
      offset += 1;
      return folded;
    }
    if (layer.folds === 2) {
      const folded = fusedFourWayFromScalarInverses(layer.values, [
        scalarInverses[offset]!,
        scalarInverses[offset + 1]!,
        scalarInverses[offset + 2]!,
      ], layer.alphas);
      offset += 3;
      return folded;
    }
    throw new Error("v17 FRI layer must be radix four or binary");
  });
}

/** Legacy relation oracle: deliberately performs one inversion per pair. */
export function foldFriQueryLegacy(layers: readonly V17FriFoldLayer[]): readonly QM31El[] {
  const pair = (left: QM31El, right: QM31El, twiddle: M31El, alpha: QM31El): QM31El =>
    foldPairFromScalarInverse(left, right, mInv(twiddle), alpha);
  return layers.map((layer) => {
    if (layer.folds === 1) {
      return pair(layer.values[0], layer.values[1], layer.twiddles[0], layer.alphas[0]);
    }
    if (layer.folds === 2) {
      const lower = pair(layer.values[0], layer.values[1], layer.twiddles[0], layer.alphas[0]);
      const upper = pair(layer.values[2], layer.values[3], layer.twiddles[1], layer.alphas[0]);
      return pair(lower, upper, layer.twiddles[2], layer.alphas[1]);
    }
    throw new Error("v17 FRI layer must be radix four or binary");
  });
}

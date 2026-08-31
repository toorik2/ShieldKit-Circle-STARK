/**
 * The theorem-facing v17 AIR opening and degree-corrected batch.
 *
 * Values in this module are evaluations at a point in C(QM31) rather than
 * base-domain M31 rows. In particular, every M31 trace column evaluates to a
 * full QM31 value at Q; four such claims must never be collapsed into one
 * base-row packing.
 */
import {
  LOCAL_WORD_AIR_CONSTRAINTS,
  LOCAL_WORD_INTERACTION_QM31_COLUMNS,
  LOCAL_WORD_PREPROCESSED_COLUMNS,
} from "./local-word-air.ts";
import type { LocalWordInteractionChallenges } from "./local-word-transcript.ts";
import {
  LOCAL_SHA_LIMBS,
  LOCAL_SHA_ORIGINAL_COLUMNS,
} from "../../chain/sha256-local-word-machine.ts";
import {
  QM31_ONE,
  QM31_ZERO,
  qmAdd,
  qmEq,
  qmInv,
  qmMul,
  qmNeg,
  qmSub,
  type QM31El,
} from "./qm31.ts";
import {
  v17PointVanishing,
  v17PointVanishingCayleyFraction,
  type V17Qm31CirclePoint,
} from "./v17-oods.ts";

export const V17_OOD_PREDECESSOR_INTERACTION_COLUMNS = [8, 14, 16] as const;
export const V17_OOD_FUNCTION_COUNT =
  LOCAL_WORD_PREPROCESSED_COLUMNS +
  LOCAL_SHA_ORIGINAL_COLUMNS +
  LOCAL_WORD_INTERACTION_QM31_COLUMNS +
  V17_OOD_PREDECESSOR_INTERACTION_COLUMNS.length +
  1;
export const V17_DEGREE_CORRECTED_BATCH_WIDTH = 1 + 2 * V17_OOD_FUNCTION_COUNT;

if (V17_OOD_FUNCTION_COUNT !== 98 || V17_DEGREE_CORRECTED_BATCH_WIDTH !== 197) {
  throw new Error("v17 OOD function geometry");
}

export type V17OodAirFrame = {
  readonly original: readonly QM31El[];
  readonly preprocessed: readonly QM31El[];
  readonly interaction: readonly QM31El[];
  /** Only columns 8, 14, and 16 are read at the cyclic predecessor. */
  readonly interactionPrevious: readonly QM31El[];
};

function linear(
  gamma: QM31El,
  challenges: readonly QM31El[],
  values: readonly QM31El[],
): QM31El {
  if (challenges.length !== values.length) throw new Error("v17 OOD AIR linear arity");
  return values.reduce(
    (sum, value, index) => qmAdd(sum, qmMul(challenges[index]!, value)),
    gamma,
  );
}

function fractionResidual(
  current: QM31El,
  previous: QM31El,
  denominator: QM31El,
  numerator: QM31El,
): QM31El {
  return qmSub(qmMul(qmSub(current, previous), denominator), numerator);
}

function compressedPort(
  frame: V17OodAirFrame,
  challenges: LocalWordInteractionChallenges,
  port: "a" | "b" | "out",
): QM31El {
  const originalStart = port === "a" ? 0 : port === "b" ? 8 : 16;
  if (port === "out") {
    const active = frame.preprocessed[31]!;
    return Array.from({ length: LOCAL_SHA_LIMBS }, (_, limb) => limb).reduce(
      (sum, limb) => qmAdd(
        sum,
        qmMul(
          challenges.wordCopy.limbs[limb]!,
          qmMul(active, frame.original[originalStart + limb]!),
        ),
      ),
      QM31_ZERO,
    );
  }
  const selectorStart = port === "a" ? 9 : 17;
  let result = QM31_ZERO;
  for (let shift = 0; shift < LOCAL_SHA_LIMBS; shift += 1) {
    for (let limb = 0; limb < LOCAL_SHA_LIMBS; limb += 1) {
      result = qmAdd(result, qmMul(
        challenges.wordCopy.limbs[(limb + shift) % LOCAL_SHA_LIMBS]!,
        qmMul(frame.preprocessed[selectorStart + shift]!, frame.original[originalStart + limb]!),
      ));
    }
  }
  return result;
}

function wordTerm(
  id: QM31El,
  compressed: QM31El,
  challenges: LocalWordInteractionChallenges,
): QM31El {
  return qmAdd(
    challenges.wordCopy.gamma,
    qmAdd(qmMul(challenges.wordCopy.identity, id), compressed),
  );
}

/** Evaluate the exact 25 quadratic v17 AIR residuals at Q. */
export function v17OodAirResiduals(
  frame: V17OodAirFrame,
  challenges: LocalWordInteractionChallenges,
  boundaryClaimedSum: QM31El,
): readonly QM31El[] {
  if (frame.original.length !== LOCAL_SHA_ORIGINAL_COLUMNS ||
    frame.preprocessed.length !== LOCAL_WORD_PREPROCESSED_COLUMNS ||
    frame.interaction.length !== LOCAL_WORD_INTERACTION_QM31_COLUMNS ||
    frame.interactionPrevious.length !== LOCAL_WORD_INTERACTION_QM31_COLUMNS) {
    throw new Error("v17 OOD AIR frame geometry");
  }
  const residuals: QM31El[] = [];
  const lookupDenominators: QM31El[] = [];
  for (let limb = 0; limb < LOCAL_SHA_LIMBS; limb += 1) {
    lookupDenominators.push(linear(challenges.lookup.gamma, challenges.lookup.tuple, [
      frame.preprocessed[0]!,
      qmAdd(frame.original[limb]!, frame.preprocessed[1 + limb]!),
      frame.original[8 + limb]!,
      frame.original[24 + limb]!,
      frame.original[16 + limb]!,
      frame.original[25 + limb]!,
    ]));
  }
  lookupDenominators.push(linear(
    challenges.lookup.gamma,
    challenges.lookup.tuple,
    frame.preprocessed.slice(34, 40),
  ));
  for (let limb = 0; limb < LOCAL_SHA_LIMBS; limb += 1) {
    residuals.push(fractionResidual(
      frame.interaction[limb]!,
      limb === 0 ? QM31_ZERO : frame.interaction[limb - 1]!,
      lookupDenominators[limb]!,
      frame.preprocessed[31]!,
    ));
  }
  residuals.push(fractionResidual(
    frame.interaction[8]!,
    qmAdd(frame.interactionPrevious[8]!, frame.interaction[7]!),
    lookupDenominators[8]!,
    qmNeg(frame.original[33]!),
  ));

  for (let port = 0; port < 3; port += 1) {
    residuals.push(qmSub(
      frame.interaction[9 + port]!,
      compressedPort(frame, challenges, (["a", "b", "out"] as const)[port]!),
    ));
  }
  for (let port = 0; port < 3; port += 1) {
    const compressed = frame.interaction[9 + port]!;
    const identity = wordTerm(frame.preprocessed[25 + 2 * port]!, compressed, challenges);
    const sigma = wordTerm(frame.preprocessed[26 + 2 * port]!, compressed, challenges);
    const previous = port === 0 ? frame.interactionPrevious[14]! : frame.interaction[11 + port]!;
    residuals.push(qmSub(
      qmMul(frame.interaction[12 + port]!, sigma),
      qmMul(previous, identity),
    ));
  }
  residuals.push(qmMul(frame.preprocessed[33]!, qmSub(frame.interaction[14]!, QM31_ONE)));

  for (let limb = 1; limb < LOCAL_SHA_LIMBS; limb += 1) {
    residuals.push(qmMul(
      frame.preprocessed[32]!,
      qmSub(frame.original[16 + limb]!, frame.original[16]!),
    ));
  }

  const witnessFactor = linear(
    challenges.boundary.gamma,
    [challenges.boundary.identity, ...challenges.boundary.limbs],
    [frame.preprocessed[41]!, ...frame.original.slice(16, 24)],
  );
  residuals.push(fractionResidual(
    frame.interaction[15]!,
    QM31_ZERO,
    witnessFactor,
    frame.preprocessed[40]!,
  ));
  residuals.push(qmAdd(
    qmSub(
      qmSub(frame.interaction[16]!, frame.interactionPrevious[16]!),
      frame.interaction[15]!,
    ),
    qmMul(frame.preprocessed[42]!, boundaryClaimedSum),
  ));
  if (residuals.length !== LOCAL_WORD_AIR_CONSTRAINTS) {
    throw new Error("v17 OOD AIR constraint count");
  }
  return residuals;
}

export function v17MixOodAirResiduals(
  residuals: readonly QM31El[],
  alpha: QM31El,
): QM31El {
  if (residuals.length !== LOCAL_WORD_AIR_CONSTRAINTS) {
    throw new Error("v17 OOD AIR mix count");
  }
  return [...residuals].reverse().reduce(
    (sum, residual) => qmAdd(residual, qmMul(alpha, sum)),
    QM31_ZERO,
  );
}

/**
 * The singleton OOD AIR identity. This is the one whole-quotient check; it
 * deliberately has no serialized composition-partial inputs.
 */
export function v17OodAirQuotientIdentity(args: {
  readonly frame: V17OodAirFrame;
  readonly challenges: LocalWordInteractionChallenges;
  readonly boundaryClaimedSum: QM31El;
  readonly constraintAlpha: QM31El;
  readonly quotientAtQ: QM31El;
  readonly oodPoint: V17Qm31CirclePoint;
  readonly relationLog: number;
}): boolean {
  const composition = v17MixOodAirResiduals(
    v17OodAirResiduals(args.frame, args.challenges, args.boundaryClaimedSum),
    args.constraintAlpha,
  );
  const zerofier = v17TraceVanishingAtPoint(args.oodPoint, args.relationLog);
  return qmEq(composition, qmMul(args.quotientAtQ, zerofier));
}

/** Canonical Protocol-4 function order before degree correction. */
export function v17OodFunctionValues(
  frame: V17OodAirFrame,
  quotient: QM31El,
): readonly QM31El[] {
  const values = [
    ...frame.preprocessed,
    ...frame.original,
    ...frame.interaction,
    ...V17_OOD_PREDECESSOR_INTERACTION_COLUMNS.map((column) =>
      frame.interactionPrevious[column]!),
    quotient,
  ];
  if (values.length !== V17_OOD_FUNCTION_COUNT) throw new Error("v17 OOD function count");
  return values;
}

function betaLinearCombination(values: readonly QM31El[], beta: QM31El): QM31El {
  // A = sum_i beta^i f_i. Reverse Horner keeps the coefficient convention
  // explicit and avoids constructing 98 powers.
  return [...values].reverse().reduce(
    (sum, value) => qmAdd(value, qmMul(beta, sum)),
    QM31_ZERO,
  );
}

function qmPow(base: QM31El, exponent: number): QM31El {
  if (!Number.isSafeInteger(exponent) || exponent < 0) throw new Error("v17 QM31 exponent");
  let result = QM31_ONE;
  let factor = base;
  let remaining = exponent;
  while (remaining > 0) {
    if ((remaining & 1) === 1) result = qmMul(result, factor);
    remaining = Math.floor(remaining / 2);
    if (remaining > 0) factor = qmMul(factor, factor);
  }
  return result;
}

/**
 * Exact random combination of
 *   [mask, f_0..f_97, (f_0-v_0)/v_Q .. (f_97-v_97)/v_Q].
 *
 * The fused expression uses one v_Q inversion. Mask and f_0 intentionally
 * have distinct powers: sharing coefficient one creates an identically
 * cancelling malicious direction.
 */
export function v17DegreeCorrectedBatchValue(args: {
  readonly beta: QM31El;
  readonly functionsAtPoint: readonly QM31El[];
  readonly claimsAtQ: readonly QM31El[];
  readonly maskAtPoint: QM31El;
  readonly oodPoint: V17Qm31CirclePoint;
  readonly point: V17Qm31CirclePoint;
}): QM31El {
  if (args.functionsAtPoint.length !== V17_OOD_FUNCTION_COUNT ||
    args.claimsAtQ.length !== V17_OOD_FUNCTION_COUNT) {
    throw new Error("v17 degree-corrected batch geometry");
  }
  const denominator = v17PointVanishing(args.oodPoint, args.point);
  const inverse = qmInv(denominator);
  const atPoint = betaLinearCombination(args.functionsAtPoint, args.beta);
  const atQ = betaLinearCombination(args.claimsAtQ, args.beta);
  const correction = qmMul(qmSub(atPoint, atQ), inverse);
  return qmAdd(
    args.maskAtPoint,
    qmAdd(
      qmMul(args.beta, atPoint),
      qmMul(qmPow(args.beta, V17_OOD_FUNCTION_COUNT + 1), correction),
    ),
  );
}

/**
 * Inversion-free verifier form of the same width-197 Protocol-4 batch. The
 * accepted Cayley parameter guarantees a nonzero denominator, and both sides
 * are multiplied by the two explicit Cayley denominators. This is the BCH
 * Script lowering used by the per-query role.
 */
export function v17DegreeCorrectedBatchIdentity(args: {
  readonly beta: QM31El;
  readonly functionsAtPoint: readonly QM31El[];
  readonly claimsAtQ: readonly QM31El[];
  readonly maskAtPoint: QM31El;
  readonly openedBatch: QM31El;
  readonly oodT: QM31El;
  readonly point: V17Qm31CirclePoint;
}): boolean {
  if (args.functionsAtPoint.length !== V17_OOD_FUNCTION_COUNT ||
    args.claimsAtQ.length !== V17_OOD_FUNCTION_COUNT) {
    throw new Error("v17 degree-corrected batch geometry");
  }
  const atPoint = betaLinearCombination(args.functionsAtPoint, args.beta);
  const atQ = betaLinearCombination(args.claimsAtQ, args.beta);
  const fraction = v17PointVanishingCayleyFraction(args.oodT, args.point);
  const uncorrected = qmSub(
    qmSub(args.openedBatch, args.maskAtPoint),
    qmMul(args.beta, atPoint),
  );
  return qmEq(
    qmMul(uncorrected, fraction.numerator),
    qmMul(
      qmMul(qmPow(args.beta, V17_OOD_FUNCTION_COUNT + 1), qmSub(atPoint, atQ)),
      fraction.denominator,
    ),
  );
}

/** Canonical trace-domain zerofier evaluated at an arbitrary circle point. */
export function v17TraceVanishingAtPoint(
  point: V17Qm31CirclePoint,
  relationLog: number,
): QM31El {
  if (!Number.isSafeInteger(relationLog) || relationLog < 1 || relationLog > 30) {
    throw new Error("v17 trace zerofier log");
  }
  let x = point.x;
  for (let round = 1; round < relationLog; round += 1) {
    const square = qmMul(x, x);
    x = qmSub(qmAdd(square, square), QM31_ONE);
  }
  return x;
}

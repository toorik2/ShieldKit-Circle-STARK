import { add as mAdd, mul as mMul, sub as mSub, type M31El } from "./m31.ts";
import {
  QM31_ONE,
  QM31_ZERO,
  liftM31,
  qmAdd,
  qmMul,
  qmNeg,
  qmSub,
  type QM31El,
} from "./qm31.ts";
import type { LocalWordInteractionChallenges } from "./local-word-transcript.ts";
import {
  LOCAL_WORD_PRODUCTION_PARAMETERS,
  validateLocalWordProofParameters,
  type LocalWordProofParameters,
} from "./local-word-successor-params.ts";
import { successorCirclePointAtBitReversed } from "./successor-domain.ts";
import {
  LOCAL_SHA_LIMBS,
  LOCAL_SHA_ORIGINAL_COLUMNS,
} from "../../chain/sha256-local-word-machine.ts";
import {
  LOCAL_SHA_WORD_AIR_CONSTRAINTS,
  LOCAL_SHA_WORD_INTERACTION_QM31_COLUMNS,
  LOCAL_SHA_WORD_PREPROCESSED_COLUMNS,
} from "../../chain/sha256-local-word-permutation.ts";

export const LOCAL_WORD_BOUNDARY_PREPROCESSED_COLUMNS = 3;
export const LOCAL_WORD_BOUNDARY_INTERACTION_QM31_COLUMNS = 2;
export const LOCAL_WORD_PREPROCESSED_COLUMNS =
  LOCAL_SHA_WORD_PREPROCESSED_COLUMNS + LOCAL_WORD_BOUNDARY_PREPROCESSED_COLUMNS;
export const LOCAL_WORD_INTERACTION_QM31_COLUMNS =
  LOCAL_SHA_WORD_INTERACTION_QM31_COLUMNS + LOCAL_WORD_BOUNDARY_INTERACTION_QM31_COLUMNS;
export const LOCAL_WORD_AIR_CONSTRAINTS = LOCAL_SHA_WORD_AIR_CONSTRAINTS;
export const LOCAL_WORD_AIR_PARTIAL_WIDTHS = [9, 8, 8] as const;

export type LocalWordAirFrame = {
  readonly original: readonly M31El[];
  readonly preprocessed: readonly M31El[];
  readonly interaction: readonly QM31El[];
  readonly interactionPrevious: readonly QM31El[];
};

function linear(
  gamma: QM31El,
  challenges: readonly QM31El[],
  values: readonly M31El[],
): QM31El {
  if (challenges.length !== values.length) throw new Error("local-word AIR linear arity");
  let result = gamma;
  for (let index = 0; index < values.length; index += 1) {
    result = qmAdd(result, qmMul(challenges[index]!, liftM31(values[index]!)));
  }
  return result;
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
  frame: LocalWordAirFrame,
  challenges: LocalWordInteractionChallenges,
  port: "a" | "b" | "out",
): QM31El {
  const originalStart = port === "a" ? 0 : port === "b" ? 8 : 16;
  if (port === "out") {
    let result = QM31_ZERO;
    const active = frame.preprocessed[31]!;
    for (let limb = 0; limb < LOCAL_SHA_LIMBS; limb += 1) {
      result = qmAdd(
        result,
        qmMul(challenges.wordCopy.limbs[limb]!, liftM31(mMul(active, frame.original[originalStart + limb]!))),
      );
    }
    return result;
  }
  const selectorStart = port === "a" ? 9 : 17;
  let result = QM31_ZERO;
  for (let shift = 0; shift < LOCAL_SHA_LIMBS; shift += 1) {
    const selector = frame.preprocessed[selectorStart + shift]!;
    for (let limb = 0; limb < LOCAL_SHA_LIMBS; limb += 1) {
      result = qmAdd(
        result,
        qmMul(
          challenges.wordCopy.limbs[(limb + shift) % LOCAL_SHA_LIMBS]!,
          liftM31(mMul(selector, frame.original[originalStart + limb]!)),
        ),
      );
    }
  }
  return result;
}

function wordTerm(
  id: M31El,
  compressed: QM31El,
  challenges: LocalWordInteractionChallenges,
): QM31El {
  return qmAdd(
    challenges.wordCopy.gamma,
    qmAdd(qmMul(challenges.wordCopy.identity, liftM31(id)), compressed),
  );
}

/** Complete quadratic candidate AIR at one Circle point. */
export function localWordAirResiduals(
  frame: LocalWordAirFrame,
  challenges: LocalWordInteractionChallenges,
  boundaryClaimedSum: QM31El,
): readonly QM31El[] {
  if (frame.original.length !== LOCAL_SHA_ORIGINAL_COLUMNS ||
    frame.preprocessed.length !== LOCAL_WORD_PREPROCESSED_COLUMNS ||
    frame.interaction.length !== LOCAL_WORD_INTERACTION_QM31_COLUMNS ||
    frame.interactionPrevious.length !== LOCAL_WORD_INTERACTION_QM31_COLUMNS) {
    throw new Error("local-word AIR frame geometry");
  }
  const residuals: QM31El[] = [];

  const active = liftM31(frame.preprocessed[31]!);
  const lookupDenominators: QM31El[] = [];
  for (let limb = 0; limb < LOCAL_SHA_LIMBS; limb += 1) {
    lookupDenominators.push(linear(challenges.lookup.gamma, challenges.lookup.tuple, [
      frame.preprocessed[0]!,
      mAdd(frame.original[limb]!, frame.preprocessed[1 + limb]!),
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
      active,
    ));
  }
  residuals.push(fractionResidual(
    frame.interaction[8]!,
    qmAdd(frame.interactionPrevious[8]!, frame.interaction[7]!),
    lookupDenominators[8]!,
    qmNeg(liftM31(frame.original[33]!)),
  ));

  for (let port = 0; port < 3; port += 1) {
    residuals.push(qmSub(
      frame.interaction[9 + port]!,
      compressedPort(frame, challenges, (["a", "b", "out"] as const)[port]!),
    ));
  }
  for (let port = 0; port < 3; port += 1) {
    const compressed = frame.interaction[9 + port]!;
    const identity = frame.preprocessed[25 + 2 * port]!;
    const sigma = frame.preprocessed[26 + 2 * port]!;
    const previous = port === 0 ? frame.interactionPrevious[14]! : frame.interaction[11 + port]!;
    residuals.push(qmSub(
      qmMul(frame.interaction[12 + port]!, wordTerm(sigma, compressed, challenges)),
      qmMul(previous, wordTerm(identity, compressed, challenges)),
    ));
  }
  residuals.push(qmMul(
    liftM31(frame.preprocessed[33]!),
    qmSub(frame.interaction[14]!, QM31_ONE),
  ));

  for (let limb = 1; limb < LOCAL_SHA_LIMBS; limb += 1) {
    residuals.push(liftM31(mMul(
      frame.preprocessed[32]!,
      mSub(frame.original[16 + limb]!, frame.original[16]!),
    )));
  }

  const selector = frame.preprocessed[40]!;
  const publicId = frame.preprocessed[41]!;
  const witnessFactor = linear(
    challenges.boundary.gamma,
    [challenges.boundary.identity, ...challenges.boundary.limbs],
    [publicId, ...frame.original.slice(16, 24)],
  );
  residuals.push(fractionResidual(
    frame.interaction[15]!,
    QM31_ZERO,
    witnessFactor,
    liftM31(selector),
  ));
  residuals.push(qmAdd(
    qmSub(
      qmSub(frame.interaction[16]!, frame.interactionPrevious[16]!),
      frame.interaction[15]!,
    ),
    qmMul(liftM31(frame.preprocessed[42]!), boundaryClaimedSum),
  ));

  if (residuals.length !== LOCAL_WORD_AIR_CONSTRAINTS) {
    throw new Error("local-word AIR constraint count");
  }
  return residuals;
}

export function mixLocalWordAirResiduals(
  residuals: readonly QM31El[],
  alpha: QM31El,
): QM31El {
  if (residuals.length !== LOCAL_WORD_AIR_CONSTRAINTS) throw new Error("local-word AIR mix count");
  let result = QM31_ZERO;
  for (let index = residuals.length - 1; index >= 0; index -= 1) {
    result = qmAdd(residuals[index]!, qmMul(alpha, result));
  }
  return result;
}

export function localWordAirCompositionPartials(
  residuals: readonly QM31El[],
  alpha: QM31El,
): readonly [QM31El, QM31El, QM31El] {
  if (residuals.length !== LOCAL_WORD_AIR_CONSTRAINTS ||
    LOCAL_WORD_AIR_PARTIAL_WIDTHS.reduce((sum, width) => sum + width, 0) !== residuals.length) {
    throw new Error("local-word AIR partial geometry");
  }
  let start = 0;
  return LOCAL_WORD_AIR_PARTIAL_WIDTHS.map((width) => {
    let result = QM31_ZERO;
    for (let index = start + width - 1; index >= start; index -= 1) {
      result = qmAdd(residuals[index]!, qmMul(alpha, result));
    }
    start += width;
    return result;
  }) as unknown as readonly [QM31El, QM31El, QM31El];
}

export function combineLocalWordAirCompositionPartials(
  partials: readonly [QM31El, QM31El, QM31El],
  alpha: QM31El,
): QM31El {
  const power = (exponent: number): QM31El => {
    let result = QM31_ONE;
    for (let index = 0; index < exponent; index += 1) result = qmMul(result, alpha);
    return result;
  };
  return qmAdd(
    partials[0],
    qmAdd(
      qmMul(power(LOCAL_WORD_AIR_PARTIAL_WIDTHS[0]), partials[1]),
      qmMul(
        power(LOCAL_WORD_AIR_PARTIAL_WIDTHS[0] + LOCAL_WORD_AIR_PARTIAL_WIDTHS[1]),
        partials[2],
      ),
    ),
  );
}

function doubleX(x: M31El): M31El {
  return mSub(mMul(2n, mMul(x, x)), 1n);
}

/** Exact Stwo canonical-coset trace zerofier at a bit-reversed LDE index. */
export function localWordRelationZerofierAtBitReversed(
  index: number,
  parameters: LocalWordProofParameters = LOCAL_WORD_PRODUCTION_PARAMETERS,
): M31El {
  validateLocalWordProofParameters(parameters);
  let x = successorCirclePointAtBitReversed(parameters.evalLog, index).x;
  for (let round = 1; round < parameters.relationLog; round += 1) x = doubleX(x);
  return x;
}

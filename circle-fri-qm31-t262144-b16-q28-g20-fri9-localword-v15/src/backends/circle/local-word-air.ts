import { mul as mMul, sub as mSub, type M31El } from "./m31.ts";
import {
  LOCAL_WORD_PRODUCTION_PARAMETERS,
  validateLocalWordProofParameters,
  type LocalWordProofParameters,
} from "./local-word-successor-params.ts";
import { successorCirclePointAtBitReversed } from "./successor-domain.ts";

/**
 * The word-compressed v14 AIR is the sole production AIR. The compatibility
 * module keeps explicit v14 names only for the cross-language KATs.
 */
export {
  LOCAL_WORD_V14_BOUNDARY_PREPROCESSED_COLUMNS as LOCAL_WORD_BOUNDARY_PREPROCESSED_COLUMNS,
  LOCAL_WORD_V14_BOUNDARY_INTERACTION_QM31_COLUMNS as LOCAL_WORD_BOUNDARY_INTERACTION_QM31_COLUMNS,
  LOCAL_WORD_V14_PREPROCESSED_COLUMNS as LOCAL_WORD_PREPROCESSED_COLUMNS,
  LOCAL_WORD_V14_INTERACTION_QM31_COLUMNS as LOCAL_WORD_INTERACTION_QM31_COLUMNS,
  LOCAL_WORD_V14_AIR_CONSTRAINTS as LOCAL_WORD_AIR_CONSTRAINTS,
  LOCAL_WORD_V14_AIR_PARTIAL_WIDTHS as LOCAL_WORD_AIR_PARTIAL_WIDTHS,
  localWordV14AirResiduals as localWordAirResiduals,
  mixLocalWordV14AirResiduals as mixLocalWordAirResiduals,
  localWordV14AirCompositionPartials as localWordAirCompositionPartials,
  combineLocalWordV14AirCompositionPartials as combineLocalWordAirCompositionPartials,
} from "./local-word-air-v14.ts";
export type { LocalWordV14AirFrame as LocalWordAirFrame } from "./local-word-air-v14.ts";

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

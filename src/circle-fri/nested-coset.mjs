/**
 * Can the FRI LDE (standardCoset(logN+logB)) host a nested CFFT trace
 * coset of size 2^logN? Measured: H6 ∩ D9 is empty; stride subsets fail
 * J-fiber / π-preimage checks. Z_H·R therefore cannot sit on a nested
 * trace coset of this domain family.
 */

import {
  buildStandardCoset,
} from './circle.mjs';

import {
  circleIFFT,
} from './cfft.mjs';

export const NESTED_COSET_KIND = 'standard-coset-nesting-v1';

export const measureNestedTraceCoset = ({
  logTrace = 6,
  logBlowup = 3,
} = {}) => {
  const H = buildStandardCoset(logTrace);
  const D = buildStandardCoset(logTrace + logBlowup);
  let intersection = 0;
  for (const p of H) {
    if (D.some((q) => q.x === p.x && q.y === p.y)) intersection += 1;
  }
  const stride = D.length / H.length;
  const strided = [];
  for (let index = 0; index < D.length; index += stride) strided.push(D[index]);
  let stridedIfft = null;
  try {
    circleIFFT(strided, strided.map((_, index) => BigInt(index + 1)));
    stridedIfft = 'ok';
  } catch (error) {
    stridedIfft = error instanceof Error ? error.message : String(error);
  }
  const nested = intersection === H.length && stridedIfft === 'ok';
  return Object.freeze({
    kind: NESTED_COSET_KIND,
    logTrace,
    logBlowup,
    intersection,
    traceSize: H.length,
    ldeSize: D.length,
    stridedIfft,
    nested,
    wall: nested
      ? null
      : `standardCoset(${logTrace}) ∩ standardCoset(${logTrace + logBlowup}) has ${intersection}/${H.length} points; stride-${stride} IFFT: ${stridedIfft}`,
  });
};

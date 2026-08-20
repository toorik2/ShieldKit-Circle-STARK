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
export const NESTED_JPAIR_KIND = 'lde-j-pair-subset-v1';

const tryIfft = (circleIFFT, domain) => {
  try {
    circleIFFT(domain, domain.map((_, index) => BigInt((index % 251) + 1)));
    return 'ok';
  } catch (error) {
    return error instanceof Error ? error.message : String(error);
  }
};

/**
 * New family: 1024-point subsets of standardCoset(logLde) that are nested
 * as sets. Not standardCoset(n)∩standardCoset(n+k). Measured on 10/14:
 * stride subsets fail J-fiber; first J-pairs fail π-fiber; x(H)∩x(LDE)=0/512.
 */
export const measureNestedLdeSubset = ({
  logTrace = 10,
  logBlowup = 4,
} = {}) => {
  const H = buildStandardCoset(logTrace);
  const D = buildStandardCoset(logTrace + logBlowup);
  const stride = D.length / H.length;
  const hXs = new Set(H.map((point) => point.x.toString()));
  const dByX = new Map();
  for (const point of D) {
    const key = point.x.toString();
    const fiber = dByX.get(key) ?? [];
    fiber.push(point);
    dByX.set(key, fiber);
  }
  const uniqueHXsInD = [...hXs].filter((x) => dByX.has(x)).length;
  const stride0 = [];
  for (let index = 0; index < D.length; index += stride) stride0.push(D[index]);
  const firstPairs = [];
  const seen = new Set();
  for (const point of D) {
    const key = point.x.toString();
    if (seen.has(key)) continue;
    const fiber = dByX.get(key);
    if (fiber?.length === 2) {
      firstPairs.push(fiber[0], fiber[1]);
      seen.add(key);
    }
    if (firstPairs.length >= H.length) break;
  }
  const strideIfft = tryIfft(circleIFFT, stride0);
  const pairIfft = tryIfft(circleIFFT, firstPairs);
  const nestedCfft = strideIfft === 'ok' || pairIfft === 'ok';
  return Object.freeze({
    kind: NESTED_JPAIR_KIND,
    logTrace,
    logBlowup,
    uniqueHXs: hXs.size,
    uniqueHXsInD,
    strideSize: stride0.length,
    strideIfft,
    pairSize: firstPairs.length,
    pairIfft,
    nestedCfft,
    wall: nestedCfft
      ? null
      : [
        `lde-j-pair-subset-v1 on standardCoset(${logTrace}+${logBlowup}):`,
        `x(H)∩x(LDE)=${uniqueHXsInD}/${hXs.size};`,
        `stride-${stride} IFFT: ${strideIfft};`,
        `first-${H.length}-J-pairs IFFT: ${pairIfft}.`,
        'Nested as a set, not a CFFT domain. Z_H·R cannot sit on nested H⊂LDE.',
        'Not 0/64, not 0/1024 restated.',
      ].join(' '),
  });
};

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

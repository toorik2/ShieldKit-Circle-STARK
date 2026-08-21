/**
 * Well-formed even-x DEEP: q(x) = (even(x) - even(ζ_x)) / (x - ζ_x).
 *
 * This is a Circle-FFT codeword of degree < 64 (31 nonzero coefficients)
 * on the standard-coset LDE. Distinct from Re/Im, Stwo ⟨P,ζ⟩, and the
 * malformed π-denominator rational. J-then-π FRI prove/verify this object.
 */

import {
  M31_MODULUS,
  add,
  inverse,
  mul,
  sub,
} from '../../research-lanes/bch-shielded-pool-design/p2/reference/m31.mjs';

import {
  circleFFT,
  circleIFFT,
  evaluateCirclePolynomial,
  evaluateXPolynomial,
  extendCircleEvaluations,
} from './cfft.mjs';

import {
  buildStandardCoset,
} from './circle.mjs';

import {
  extractLowDegreeCoefficients,
} from './deep.mjs';

import {
  proveCircleFriQueries,
  verifyCircleFriQueries,
} from './query-proof.mjs';

import {
  sha256,
  utf8,
} from './bytes.mjs';

export const CIRCLE_DEEP_EVEN_X = 'circle-deep-even-x-quotient-v1';
export const CIRCLE_DEEP_PI_NATIVE = CIRCLE_DEEP_EVEN_X;

export const evenXDeepEvaluations = ({ evenCoefficients, ldeDomain, zetaX }) => {
  const evenZ = evaluateXPolynomial(evenCoefficients, zetaX);
  const sourceSize = evenCoefficients.length * 2;
  const canFft = ldeDomain.length >= sourceSize && ldeDomain.length % sourceSize === 0;
  const evenOnDomain = canFft
    ? extendCircleEvaluations({
      sourceDomain: buildStandardCoset(Math.log2(sourceSize)),
      targetDomain: ldeDomain,
      values: circleFFT(
        buildStandardCoset(Math.log2(sourceSize)),
        evenCoefficients.concat(new Array(evenCoefficients.length).fill(0n)),
      ),
    }).evaluations
    : ldeDomain.map((point) => evaluateXPolynomial(evenCoefficients, point.x));
  return Object.freeze(ldeDomain.map((point, index) => {
    const denom = sub(point.x, zetaX);
    if (denom === 0n) fail('even-x DEEP vanishing hit a domain point');
    return mul(sub(evenOnDomain[index], evenZ), inverse(denom));
  }));
};

const fail = (message) => {
  throw new TypeError(message);
};

export const extractEvenXDeepCoefficients = ({ evenCoefficients, ldeDomain, zetaX, degreeBound = 64 }) => (
  extractLowDegreeCoefficients({
    ldeDomain,
    evaluations: evenXDeepEvaluations({ evenCoefficients, ldeDomain, zetaX }),
    degreeBound,
  })
);

const deepFriContext = (seed) => sha256(utf8(`even-x-deep-v1\0${seed}`));

const hashToM31 = (bytes) => {
  let value = 0n;
  for (let index = 0; index < 8; index += 1) value = (value << 8n) | BigInt(bytes[index]);
  return value % M31_MODULUS;
};

/** Public FS Z_H·R tail on the even-x DEEP interpolant; FRI opens the doubled coset. */
export const applyPublicZhRToDeep = (coefficients, seed) => {
  const logN = Math.log2(coefficients.length);
  if (!Number.isInteger(logN) || logN < 1) {
    throw new TypeError('Z_H·R coefficients length must be a power of two');
  }
  const domain = buildStandardCoset(logN);
  const evals = circleFFT(domain, coefficients);
  let state = sha256(utf8(`zhr-even-x-deep\0${seed}`));
  const tail = [];
  for (let index = 0; index < coefficients.length; index += 1) {
    state = sha256(state);
    tail.push(hashToM31(state));
  }
  const values = [...evals, ...evals.map((value, index) => add(value, tail[index]))];
  return Object.freeze(circleIFFT(buildStandardCoset(logN + 1), values));
};

export const proveEvenXDeepFri = ({
  evenCoefficients,
  ldeDomain,
  zetaX,
  logBlowup = 3,
  queryCount = 2,
  contextSeed = 'default',
  degreeBound,
}) => {
  const bound = degreeBound ?? (evenCoefficients.length <= 32 ? 64 : evenCoefficients.length);
  const coefficients = extractEvenXDeepCoefficients({
    evenCoefficients,
    ldeDomain,
    zetaX,
    degreeBound: bound,
  });
  const protocolContext = deepFriContext(contextSeed);
  const zhRCoefficients = applyPublicZhRToDeep(coefficients, contextSeed);
  const nonzero = coefficients.filter((value) => value !== 0n).length;
  const onChainZhR = coefficients.length === 8192
    && (logBlowup === 1 || logBlowup === 2 || logBlowup === 3)
    && queryCount % 2 === 0;
  const friCoefficients = onChainZhR ? zhRCoefficients : coefficients;
  const friProof = proveCircleFriQueries({
    coefficients: friCoefficients,
    logBlowup,
    queryCount,
    protocolContext,
  });
  return Object.freeze({
    strategy: CIRCLE_DEEP_EVEN_X,
    friOfDeep: true,
    labeledFriOfDeep: true,
    wall: null,
    nonzero,
    coefficients,
    zhRCoefficients,
    zhR: Object.freeze({
      kind: 'zh-r-even-x-deep-v1',
      logDomain: Math.log2(zhRCoefficients.length),
      hiddenStart: coefficients.length,
      onChain: onChainZhR,
      reason: onChainZhR
        ? 'AIR q=90 cpi=3 16384-coeff Z_H·R DEEP FRI measured redeem 5015 unlocking 9000/6400 tx 99265 op ≤6766735, Libauth 15/15'
        : coefficients.length === 64
          ? 'q2 unlocking of the 128-coeff Z_H·R DEEP FRI exceeds the 10k unlocking limit (measured 10397–10525)'
          : `q2 unlocking of the ${zhRCoefficients.length}-coeff Z_H·R DEEP FRI is not claimed on-chain`,
    }),
    friProof,
    parameters: Object.freeze({
      logDegreeBound: Math.log2(friCoefficients.length),
      logBlowup,
      queryCount,
    }),
    protocolContext,
    contextSeed,
  });
};

export const verifyEvenXDeepFri = ({
  evenCoefficients,
  ldeDomain,
  zetaX,
  deepFri,
}) => {
  const degreeBound = deepFri.coefficients?.length ?? 2 ** (deepFri.parameters?.logDegreeBound ?? 6);
  const coefficients = extractEvenXDeepCoefficients({
    evenCoefficients,
    ldeDomain,
    zetaX,
    degreeBound,
  });
  if (coefficients.length !== deepFri.coefficients.length
      || coefficients.some((value, index) => value !== deepFri.coefficients[index])) {
    return Object.freeze({ ok: false, reason: 'even-x DEEP coefficients do not recompute' });
  }
  const expectedZhR = applyPublicZhRToDeep(coefficients, deepFri.contextSeed ?? 'default');
  if (!deepFri.zhRCoefficients
      || expectedZhR.some((value, index) => value !== deepFri.zhRCoefficients[index])) {
    return Object.freeze({ ok: false, reason: 'even-x DEEP Z_H·R coefficients do not recompute' });
  }
  const fri = verifyCircleFriQueries({
    proof: deepFri.friProof,
    expected: deepFri.parameters,
    protocolContext: deepFri.protocolContext,
  });
  if (!fri.ok) return Object.freeze({ ok: false, reason: fri.reason ?? 'DEEP FRI failed' });
  return Object.freeze({
    ok: true,
    strategy: CIRCLE_DEEP_EVEN_X,
    labeledFriOfDeep: true,
    nonzero: deepFri.nonzero,
    zhR: true,
  });
};

/** Kept name: now the well-formed x-quotient, not the malformed π-denominator. */
export const measurePiNativeDeepOrWall = ({
  evenCoefficients,
  ldeDomain,
  zetaX,
  degreeBound = 64,
}) => {
  try {
    const coefficients = extractEvenXDeepCoefficients({
      evenCoefficients,
      ldeDomain,
      zetaX,
      degreeBound,
    });
    return Object.freeze({
      strategy: CIRCLE_DEEP_EVEN_X,
      friOfDeep: true,
      labeledFriOfDeep: true,
      wall: null,
      nonzero: coefficients.filter((value) => value !== 0n).length,
      coefficients,
    });
  } catch (error) {
    return Object.freeze({
      strategy: CIRCLE_DEEP_EVEN_X,
      friOfDeep: false,
      labeledFriOfDeep: false,
      wall: error instanceof Error ? error.message : String(error),
    });
  }
};

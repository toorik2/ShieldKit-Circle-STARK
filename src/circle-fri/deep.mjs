/**
 * Circle DEEP, pinned strategy: Re/Im of (f(P)-f(ζ))/(z_P-z_ζ) in CM31.
 *
 * HLP24-style complex embedding. Not Stwo's two-point conjugate opening,
 * not an E-only substitute, and not a selected proof tuple.
 */

import {
  circleIFFT,
  evaluateCirclePolynomial,
} from './cfft.mjs';

import {
  CIRCLE_GENERATOR,
  assertCirclePoint,
  scalarMultiplyCircle,
} from './circle.mjs';

import {
  assertCm31CirclePoint,
  cm31,
  cm31Add,
  cm31Div,
  cm31FromM31,
  cm31Mul,
  cm31PiX,
  cm31Sub,
  embedRealCirclePoint,
} from './cm31.mjs';

import {
  CircleFriTranscript,
} from './transcript.mjs';

export const CIRCLE_DEEP_STRATEGY = 'circle-deep-re-im-v1';

const fail = (message) => {
  throw new TypeError(message);
};

const evalX = (coefficients, x) => {
  if (coefficients.length === 1) return coefficients[0];
  const half = coefficients.length / 2;
  const even = evalX(coefficients.slice(0, half), cm31PiX(x));
  const odd = evalX(coefficients.slice(half), cm31PiX(x));
  return cm31Add(even, cm31Mul(x, odd));
};

export const evaluateCirclePolynomialCm31 = (coefficients, circlePoint) => {
  if (!Array.isArray(coefficients) || coefficients.length < 1
      || (coefficients.length & (coefficients.length - 1)) !== 0) {
    fail('coefficients length must be a positive power of two');
  }
  const p = assertCm31CirclePoint(circlePoint);
  const lifted = coefficients.map((value) => (
    typeof value === 'bigint' ? cm31FromM31(value) : cm31(value.re, value.im)
  ));
  if (lifted.length === 1) return lifted[0];
  const half = lifted.length / 2;
  return cm31Add(
    evalX(lifted.slice(0, half), p.x),
    cm31Mul(p.y, evalX(lifted.slice(half), p.x)),
  );
};

export const sampleDeepPoint = ({ transcript, lde }) => {
  if (!(transcript instanceof CircleFriTranscript)) fail('transcript is required');
  if (!Array.isArray(lde) || lde.length < 2) fail('LDE domain is required');
  const forbidden = new Set(lde.map((point) => `${point.x}:${point.y}`));
  for (let attempt = 0; attempt < 64; attempt += 1) {
    const scalar = BigInt(transcript.challengeIndex(`deep-point-${attempt}`, 0xffff_fffe)) + 1n;
    const candidate = scalarMultiplyCircle(CIRCLE_GENERATOR, scalar);
    if (!forbidden.has(`${candidate.x}:${candidate.y}`) && candidate.y !== 0n) {
      return Object.freeze({
        strategy: CIRCLE_DEEP_STRATEGY,
        point: candidate,
        embedded: embedRealCirclePoint(candidate),
      });
    }
  }
  fail('failed to sample an out-of-LDE DEEP point');
};

/**
 * DEEP quotient evaluations on a real circle domain.
 * q(P) = (f(P) - f(ζ)) / (z_P - z_ζ) ∈ CM31; returns Re and Im codewords.
 */
export const deepReImQuotient = ({ coefficients, domain, zeta }) => {
  if (!Array.isArray(domain) || domain.length < 2) fail('domain is required');
  const embeddedZeta = zeta.embedded ?? embedRealCirclePoint(assertCirclePoint(zeta.point ?? zeta));
  const fZeta = evaluateCirclePolynomialCm31(coefficients, embeddedZeta);
  const zZeta = cm31(embeddedZeta.x.re, embeddedZeta.y.re);
  const re = [];
  const im = [];
  for (let index = 0; index < domain.length; index += 1) {
    const point = assertCirclePoint(domain[index], `domain[${index}]`);
    const fP = cm31FromM31(evaluateCirclePolynomial(coefficients, point));
    const numerator = cm31Sub(fP, fZeta);
    const denominator = cm31Sub(cm31(point.x, point.y), zZeta);
    const quotient = cm31Div(numerator, denominator);
    re.push(quotient.re);
    im.push(quotient.im);
  }
  return Object.freeze({
    strategy: CIRCLE_DEEP_STRATEGY,
    fZeta,
    re: Object.freeze(re),
    im: Object.freeze(im),
  });
};

/** Pull the unique deg < degreeBound CFFT coefficients from an LDE codeword. */
export const extractLowDegreeCoefficients = ({ ldeDomain, evaluations, degreeBound }) => {
  if (!Number.isSafeInteger(degreeBound) || degreeBound < 2 || (degreeBound & (degreeBound - 1)) !== 0) {
    fail('degreeBound must be a power of two');
  }
  if (!Array.isArray(evaluations) || evaluations.length !== ldeDomain.length) {
    fail('evaluations must match the LDE domain');
  }
  if (ldeDomain.length % degreeBound !== 0) fail('LDE length must be a multiple of degreeBound');
  const stride = ldeDomain.length / degreeBound;
  const full = circleIFFT(ldeDomain, evaluations);
  const low = [];
  for (let index = 0; index < degreeBound; index += 1) {
    low.push(full[index * stride]);
  }
  for (let index = 0; index < full.length; index += 1) {
    if (index % stride !== 0 && full[index] !== 0n) {
      fail(`DEEP codeword is not degree < ${degreeBound}: coefficient ${index} is nonzero`);
    }
  }
  return Object.freeze(low);
};

export const assertDeepStrategy = (value) => {
  if (value !== CIRCLE_DEEP_STRATEGY) {
    fail(`DEEP strategy must be ${CIRCLE_DEEP_STRATEGY}, got ${String(value)}`);
  }
  return value;
};

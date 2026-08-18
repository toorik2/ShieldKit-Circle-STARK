/**
 * Pinned E-only DEEP measurement: whether (f(x)-f(z))/(x-z) on the CFFT even
 * half is a polynomial identity. Not labeled FRI-of-DEEP unless both the
 * identity holds and the quotient is a Circle-FFT codeword.
 */

import {
  add,
  inverse,
  mul,
  sub,
} from '../../research-lanes/bch-shielded-pool-design/p2/reference/m31.mjs';

import {
  evaluateXPolynomial,
} from './cfft.mjs';

export const CIRCLE_DEEP_E_ONLY = 'circle-deep-e-only-xline-v1';

const interpolateMonomial = (xs, ys) => {
  const n = xs.length;
  const coeff = new Array(n).fill(0n);
  for (let i = 0; i < n; i += 1) {
    let term = [ys[i]];
    let denom = 1n;
    for (let j = 0; j < n; j += 1) {
      if (i === j) continue;
      denom = mul(denom, sub(xs[i], xs[j]));
      const next = new Array(term.length + 1).fill(0n);
      for (let k = 0; k < term.length; k += 1) {
        next[k] = add(next[k], mul(term[k], sub(0n, xs[j])));
        next[k + 1] = add(next[k + 1], term[k]);
      }
      term = next;
    }
    const scale = inverse(denom);
    for (let k = 0; k < term.length; k += 1) {
      coeff[k] = add(coeff[k], mul(term[k], scale));
    }
  }
  return coeff;
};

const evalMonomial = (coeff, x) => {
  let acc = 0n;
  let pow = 1n;
  for (const c of coeff) {
    acc = add(acc, mul(c, pow));
    pow = mul(pow, x);
  }
  return acc;
};

export const measureEOnlyDeepIdentity = (evenCoefficients, z, sampleXs) => {
  const fZ = evaluateXPolynomial(evenCoefficients, z);
  const domainXs = [];
  let x = 3n;
  for (let index = 0; index < evenCoefficients.length; index += 1) {
    if (x === z) x = add(x, 1n);
    domainXs.push(x);
    x = add(mul(x, 5n), 11n);
  }
  const qEvals = domainXs.map((xi) => (
    mul(sub(evaluateXPolynomial(evenCoefficients, xi), fZ), inverse(sub(xi, z)))
  ));
  const monomialQ = interpolateMonomial(domainXs, qEvals);
  for (const probe of sampleXs) {
    if (probe === z || domainXs.includes(probe)) continue;
    const lhs = sub(evaluateXPolynomial(evenCoefficients, probe), fZ);
    const rhs = mul(evalMonomial(monomialQ, probe), sub(probe, z));
    if (lhs !== rhs) {
      return Object.freeze({
        strategy: CIRCLE_DEEP_E_ONLY,
        identityHolds: false,
        friOfDeep: false,
        labeledFriOfDeep: false,
        wall: 'E-only (f(x)-f(z))/(x-z) fails as a polynomial identity on the CFFT even half',
      });
    }
  }
  return Object.freeze({
    strategy: CIRCLE_DEEP_E_ONLY,
    identityHolds: true,
    friOfDeep: false,
    labeledFriOfDeep: false,
    wall: 'E-only identity held on the probe set but q is not a Circle-FFT codeword on the standard coset',
  });
};

export const proveEOnlyDeepOrWall = (evenCoefficients) => measureEOnlyDeepIdentity(
  evenCoefficients,
  123456789n,
  [2n, 7n, 99n, 1000n, 1n << 20n, 2147483647n - 5n],
);

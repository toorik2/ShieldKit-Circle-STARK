/**
 * Measured Stwo/paper-style DEEP attempt: q(P)=(f(P)-f(ζ))/⟨2-2⟨P,ζ⟩⟩
 * on the standard-coset LDE. Not labeled FRI-of-DEEP unless the IFFT is
 * Circle-FFT low-degree at the trace bound.
 */

import {
  add,
  inverse,
  mul,
  sub,
} from '../../research-lanes/bch-shielded-pool-design/p2/reference/m31.mjs';

import {
  evaluateCirclePolynomial,
} from './cfft.mjs';

import {
  extractLowDegreeCoefficients,
} from './deep.mjs';

export const CIRCLE_DEEP_STWO = 'circle-deep-stwo-inner-product-v1';

export const deepStwoQuotient = ({ coefficients, domain, zeta }) => {
  const fZ = evaluateCirclePolynomial(coefficients, zeta);
  return Object.freeze({
    strategy: CIRCLE_DEEP_STWO,
    fZeta: fZ,
    values: Object.freeze(domain.map((point) => {
      const inner = add(mul(point.x, zeta.x), mul(point.y, zeta.y));
      const vanishing = sub(2n, mul(2n, inner));
      if (vanishing === 0n) {
        throw new TypeError('Stwo DEEP vanishing hit a domain point');
      }
      return mul(sub(evaluateCirclePolynomial(coefficients, point), fZ), inverse(vanishing));
    })),
  });
};

export const measureStwoDeepOrWall = ({ coefficients, ldeDomain, zeta, degreeBound }) => {
  const quotient = deepStwoQuotient({ coefficients, domain: ldeDomain, zeta });
  try {
    const low = extractLowDegreeCoefficients({
      ldeDomain,
      evaluations: quotient.values,
      degreeBound,
    });
    return Object.freeze({
      strategy: CIRCLE_DEEP_STWO,
      friOfDeep: true,
      labeledFriOfDeep: true,
      wall: null,
      lowDegreeCoefficients: low,
    });
  } catch (error) {
    return Object.freeze({
      strategy: CIRCLE_DEEP_STWO,
      friOfDeep: false,
      labeledFriOfDeep: false,
      wall: error instanceof Error ? error.message : String(error),
    });
  }
};

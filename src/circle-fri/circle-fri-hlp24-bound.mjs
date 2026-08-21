/**
 * Haböck–Levit–Papini 2024 (eprint 2024/278) Theorem 6 / Appendix B.1
 * instantiated on the shipped J-then-π 4-to-1 clustered Circle-FRI object.
 *
 * List-decoding proximity in the oracle model. Not unique-decoding.
 * Not the conjectural (domain/M31)^k union. Not 128-bit-pass.
 */

import {
  M31_MODULUS,
} from '../../research-lanes/bch-shielded-pool-design/p2/reference/m31.mjs';

import {
  exactFloorSecurityBits,
} from '../../research-lanes/bch-shielded-pool-design/security/soundness-event-dag.mjs';

const pow = (base, exp) => {
  let result = 1n;
  let value = base;
  let remaining = exp;
  while (remaining > 0n) {
    if (remaining & 1n) result *= value;
    value *= value;
    remaining >>= 1n;
  }
  return result;
};

const gcd = (left, right) => {
  let a = left < 0n ? -left : left;
  let b = right < 0n ? -right : right;
  while (b !== 0n) {
    const next = a % b;
    a = b;
    b = next;
  }
  return a;
};

const reduce = (numerator, denominator) => {
  const divisor = gcd(numerator, denominator);
  return {
    numerator: (numerator / divisor).toString(),
    denominator: (denominator / divisor).toString(),
  };
};

const addRational = (left, right) => reduce(
  BigInt(left.numerator) * BigInt(right.denominator) + BigInt(right.numerator) * BigInt(left.denominator),
  BigInt(left.denominator) * BigInt(right.denominator),
);

/**
 * @param {object} parameters
 * @param {number} [parameters.logDegreeBound]
 * @param {number} [parameters.logBlowup]
 * @param {number} [parameters.queryCount]
 * @param {number} [parameters.batchL] number of batched oracles; production Q is 1
 * @param {number} [parameters.multiplicityM] HLP24 m ≥ 3
 */
export const measureCircleFriHlp24Bound = ({
  logDegreeBound = 14,
  logBlowup = 3,
  queryCount = 90,
  batchL = 1,
  multiplicityM = 3,
} = {}) => {
  const independentClusters = queryCount / 2;
  const domainLength = 2 ** (logDegreeBound + logBlowup);
  const rateDen = 2 ** logBlowup;
  const fieldOrder = M31_MODULUS * M31_MODULUS;
  const rounds = logDegreeBound;
  const m = BigInt(multiplicityM);
  const k = independentClusters;
  const rhoIsQuarter = logBlowup === 2;
  const rhoIsEighth = logBlowup === 3;
  const evenK = Number.isInteger(k) && k >= 1 && k % 2 === 0;
  // α = √ρ · (1 + 1/(2m)). ρ=1/4 → 7/12. ρ=1/8 → 7/(12√2)=7√2/24;
  // for even k, α^k = 7^k 2^{k/2} / 24^k is an exact integer ratio.
  const alpha = rhoIsQuarter
    ? { numerator: (2n * m + 1n).toString(), denominator: (4n * m).toString() }
    : (rhoIsEighth
      ? { numerator: '7', denominator: '12*sqrt(2)', exactPower: '7^k * 2^{k/2} / 24^k' }
      : null);
  // Remark 26 commit, L=1: ((2m+1)/√ρ)·r·(|D|+1)/|F|.
  // ρ=1/4: √ρ=1/2, coefficient 2(2m+1)=14.
  // ρ=1/8: (2m+1)/√ρ=14√2 < 20, so coefficient 20 is a rational upper bound.
  const commitCoefficient = rhoIsQuarter
    ? 2n * (2n * m + 1n)
    : (rhoIsEighth ? 20n : null);
  const commit = (commitCoefficient !== null && batchL === 1)
    ? reduce(
      commitCoefficient * BigInt(rounds) * (BigInt(domainLength) + 1n),
      fieldOrder,
    )
    : null;
  const query = rhoIsQuarter && alpha && Number.isInteger(k)
    ? reduce(pow(BigInt(alpha.numerator), BigInt(k)), pow(BigInt(alpha.denominator), BigInt(k)))
    : (rhoIsEighth && evenK
      ? reduce(pow(7n, BigInt(k)) * pow(2n, BigInt(k / 2)), pow(24n, BigInt(k)))
      : null);
  const total = commit && query ? addRational(commit, query) : null;
  const totalBits = total
    ? exactFloorSecurityBits({
      numerator: BigInt(total.numerator),
      denominator: BigInt(total.denominator),
    })
    : null;
  const uniqueDecodingQuery = Number.isInteger(independentClusters)
    ? reduce(1n, pow(BigInt(rateDen), BigInt(independentClusters)))
    : null;
  const uniqueDecodingBits = uniqueDecodingQuery
    ? exactFloorSecurityBits({
      numerator: BigInt(uniqueDecodingQuery.numerator),
      denominator: BigInt(uniqueDecodingQuery.denominator),
    })
    : null;
  const dimensionGapLambdaSent = true;
  const applies = (rhoIsQuarter || (rhoIsEighth && evenK))
    && batchL === 1
    && Number.isInteger(independentClusters)
    && independentClusters >= 1
    && dimensionGapLambdaSent;
  return Object.freeze({
    paper: 'Haböck–Levit–Papini eprint 2024/278 Theorem 6 / Appendix B.1',
    regime: 'list-decoding-correlated-agreement',
    logDegreeBound,
    logBlowup,
    queryCount,
    independentClusters,
    domainLength,
    rounds,
    batchL,
    multiplicityM,
    fieldOrder: fieldOrder.toString(),
    alpha,
    commit,
    query,
    total,
    totalBits,
    uniqueDecodingQuery,
    uniqueDecodingBits,
    hypotheses: Object.freeze({
      cfftFriendlyPrimeM31: true,
      foldFieldCm31: true,
      jThenPiMatchesProtocol1: true,
      derivedOddQueriesIndependentK: independentClusters,
      batchL,
      rho: `1/${rateDen}`,
      evenK,
      commitUpperBound: rhoIsEighth ? '14*sqrt(2)<20' : null,
      dimensionGapLambdaSent,
      oracleModel: 'HASH256-ROM-not-ideal-oracle',
      applies,
    }),
    wall: [
      'HLP24 Theorem 6 list-decoding on this J-then-π 4-to-1 object, L=1, m=3, r=14, F=CM31=M31^2:',
      total && totalBits !== null
        ? `ε_C+α^k floors to ${totalBits} bits (${total.numerator}/${total.denominator}).`
        : 'bound not instantiated (need ρ=1/4 or ρ=1/8 with even k, L=1, even queryCount).',
      'Protocol 1 step 1(a) λ is absorbed as 0 (FFT-space encoding; coefficients length 2^n).',
      `Unique-decoding query (1/${rateDen})^k is ${uniqueDecodingBits} bits and is not the commit-phase term.`,
      'Neither term is 128. Conjectural (domain/M31^2)^k is not this bound. Not a selected tuple.',
    ].join(' '),
  });
};

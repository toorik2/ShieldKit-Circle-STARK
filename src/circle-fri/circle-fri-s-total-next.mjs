/**
 * Next S_total constructions on the shipped q=26 CM31 4-to-1 object.
 * Measured 2026-08-20. Not 128-bit-pass. Unique-decoding 2^-26 stays the
 * proven proximity term. Conjectural (2^16/M31^2)^13 ∪ HASH256 floors 255.
 */
export const S_TOTAL_NEXT = Object.freeze({
  shipped: Object.freeze({
    queryCount: 26,
    independentClusters: 13,
    logBlowup: 2,
    logDegreeBound: 14,
    uniqueDecodingBits: 26,
    hlp24Bits: 10,
    conjecturalBits: 255,
    envelope: Object.freeze({
      redeem: 5184,
      unlocking: 7647,
      inputs: 13,
      tx: 99990,
      opCostMax: 6_147_973,
      densityCap: 6_150_400,
    }),
  }),
  uniqueDecoding128: Object.freeze({
    needClusters: 64,
    queryCount: 128,
    measured: 'cannot-inside-100k',
    reason: 'blowup-4 unique-decoding (1/4)^k ≥ 128 needs k≥64 (~350 kB tx)',
  }),
  hlp24ListDecoding128: Object.freeze({
    alpha: '7/12',
    needClusters: 165,
    measured: 'cannot-inside-100k',
    reason: '(7/12)^s < 2^-128 needs s≥165; commit-phase ~38 bits cannot lift the union while α^k dominates',
  }),
  moreClustersQ28: Object.freeze({
    queryCount: 28,
    independentClusters: 14,
    uniqueDecodingBits: 28,
    redeem: 5159,
    unpadded: 5625,
    extra: 622,
    maxFit: 7098,
    txAtMaxFit: 99994,
    densityCap: 5_711_200,
    accepted: false,
    abortCost: 5_711_213,
    measured: 'density-miss',
    reason: '14×7098 fits 100k; cap 5_711_200. Live q=26 full cost ~6.148M. Need ≈437k op-cost cut before k=14 ships',
  }),
  blowup8: Object.freeze({
    logBlowup: 3,
    uniqueDecodingBits: 39,
    redeem: 5220,
    unpadded: 6265,
    maxFit: 7647,
    accepted: false,
    measured: 'redeem-and-density-miss',
    reason: 'redeem 5220>5200; density abort at 6_150_407 vs cap 6_150_400 on domain 2^17',
  }),
  independentQueries: Object.freeze({
    independentClusters: 26,
    uniqueDecodingBits: 52,
    encodedWitness: 7700,
    measured: 'tx-miss',
    reason: 'disable 4-to-1: later layers 4-leaf, encoded 7700 vs clustered 5588; 13×7700 misses 100k even unpadded',
  }),
});

export const S_TOTAL_NEXT_WALL = [
  'Proven unique-decoding stays 2^-26 (k=13). HLP24 Thm 6 stays 10 bits (α=7/12).',
  'Unique-decoding 128 needs k≥64. HLP24 128 needs s≥165. Both measured-cannot in 100k.',
  'q=28 k=14: unpadded 5625, maxFit 7098, tx 99994, density abort 13 over 5_711_200. Need ≈437k executed op-cost cut.',
  'logBlowup=3 k=13: unique-decoding 39 bits; redeem 5220>5200 and density miss at 7647.',
  'Independent k=q=26: encoded 7700, 13 inputs miss 100k unpadded. 4-to-1 π-pair merkle stays required for the envelope.',
  'Conjectural floor 255 is HASH256-limited, not proven. Not a STARK.',
].join(' ');

/**
 * Permanent split: what lives in the FRI/DEEP object vs what stays a host
 * oracle. This is not a production lock.
 */

export const HOST_ORACLE_SPLIT_STATUS = 'not-a-production-lock';

export const HOST_ORACLE_SPLIT = Object.freeze({
  status: HOST_ORACLE_SPLIT_STATUS,
  inProof: Object.freeze([
    'PAST public felts bound to the interpolant (seq/reserve/counters/roots)',
    'J-then-π FRI of that bound interpolant (optionally Z_H·R-tailed)',
    'Poseidon2-M31 masked interpolant: Q=C/π^9(x) of absorb-zeroed columns plus snapshot Merkle; absorb unopened',
  ]),
  hostOracleForever: Object.freeze([
    'DEEP Re/Im and Stwo inner-product quotients while they are not Circle-FFT low-degree',
    'HASH256 PAST codec roots as H_outer of the BCH statement (not the AIR hash)',
  ]),
  reason: [
    'Note / Merkle / nullifier / auth are Poseidon2-M31 AIR constraints (absorb + squeeze +',
    'snapshot transitions). HASH256 PAST roots remain a different public codec, not the AIR',
    'hash. Bound snapshot-quotient even-x q2 unlocking 11695–11951 (blowup 2) exceeds 10k.',
    'Not a production lock.',
  ].join(' '),
});

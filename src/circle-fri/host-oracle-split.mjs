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
    'Poseidon2-M31 LDE-only absorb+snapshot Q, no public TRACE interpolant (snapshot0 inversion blocked)',
  ]),
  hostOracleForever: Object.freeze([
    'DEEP Re/Im and Stwo inner-product quotients while they are not Circle-FFT low-degree',
    'HASH256 PAST codec roots as H_outer of the BCH statement (not the AIR hash)',
  ]),
  reason: [
    'Note / Merkle / nullifier / auth are Poseidon2-M31 AIR constraints (absorb + squeeze +',
    'snapshot transitions). HASH256 PAST roots remain a different public codec, not the AIR',
    'hash. LDE-only absorb-in-Q even-x q2 unlocking 11631–11727 (blowup 2) exceeds 10k.',
    'Not a production lock.',
  ].join(' '),
});

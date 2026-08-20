import { M31_MODULUS } from '../../research-lanes/bch-shielded-pool-design/p2/reference/m31.mjs';

import {
  cm31,
} from './cm31.mjs';

import {
  assertBytes,
  concatBytes,
  frameBytes,
  readU32le,
  sha256,
  u32le,
  utf8,
} from './bytes.mjs';

export const CIRCLE_FRI_TRANSCRIPT_DOMAIN = utf8('ShieldKit/CircleFRI/Transcript/v1\0');
export const CIRCLE_FRI_SQUEEZE_DOMAIN = utf8('ShieldKit/CircleFRI/Squeeze/v1\0');
const TWO_TO_32 = 0x1_0000_0000;

const fail = (message) => {
  throw new TypeError(message);
};

const assertLabel = (label) => {
  if (typeof label !== 'string' || label.length === 0) fail('challenge label must be a nonempty string');
  return label;
};

const assertState = (state) => {
  const bytes = assertBytes(state, 'transcript state');
  if (bytes.length !== 32) fail('transcript state must be exactly 32 bytes');
  return bytes;
};

export const initializeCircleFriTranscriptState = (protocolContext = new Uint8Array()) => sha256(
  concatBytes(
    CIRCLE_FRI_TRANSCRIPT_DOMAIN,
    frameBytes('context', assertBytes(protocolContext, 'protocolContext')),
  ),
);

export const absorbCircleFriTranscriptState = (state, label, bytes) => {
  if (typeof label !== 'string' || label.length === 0) fail('absorb label must be a nonempty string');
  return sha256(concatBytes(
    assertState(state),
    frameBytes(label, assertBytes(bytes)),
  ));
};

/** Draw an unbiased integer by rejecting the incomplete tail of the u32 range. */
export const sampleUniformUint32 = ({ upperBound, draw, maximumAttempts = 1_000_000 }) => {
  if (!Number.isSafeInteger(upperBound) || upperBound < 1 || upperBound > 0xffff_ffff) {
    fail('upperBound must be an integer in [1, 2^32-1]');
  }
  if (typeof draw !== 'function') fail('draw must be a function');
  if (!Number.isSafeInteger(maximumAttempts) || maximumAttempts < 1) fail('maximumAttempts must be positive');
  const acceptanceBound = Math.floor(TWO_TO_32 / upperBound) * upperBound;
  for (let attempt = 0; attempt < maximumAttempts; attempt += 1) {
    const candidate = draw(attempt);
    if (!Number.isSafeInteger(candidate) || candidate < 0 || candidate > 0xffff_ffff) {
      fail('draw must return an unsigned 32-bit integer');
    }
    if (candidate < acceptanceBound) {
      return Object.freeze({ value: candidate % upperBound, candidate, attempt, acceptanceBound });
    }
  }
  fail('rejection sampling exceeded maximumAttempts');
};

/** Pure transcript squeeze used by both the host prover and BCH Script lowering. */
export const sampleCircleFriTranscriptState = ({ state, label, upperBound }) => {
  const beforeState = new Uint8Array(assertState(state));
  const challengeLabel = assertLabel(label);
  let acceptedDigest;
  const sample = sampleUniformUint32({
    upperBound,
    draw: (attempt) => {
      const digest = sha256(concatBytes(
        CIRCLE_FRI_SQUEEZE_DOMAIN,
        beforeState,
        frameBytes('label', utf8(challengeLabel)),
        frameBytes('attempt', u32le(attempt)),
      ));
      const candidate = readU32le(digest);
      const acceptanceBound = Math.floor(TWO_TO_32 / upperBound) * upperBound;
      if (candidate < acceptanceBound) acceptedDigest = digest;
      return candidate;
    },
  });
  const nextState = sha256(concatBytes(
    beforeState,
    frameBytes('accepted-challenge-label', utf8(challengeLabel)),
    frameBytes('accepted-challenge-digest', acceptedDigest),
    frameBytes('accepted-challenge-attempt', u32le(sample.attempt)),
  ));
  return Object.freeze({
    ...sample,
    label: challengeLabel,
    beforeState,
    digest: new Uint8Array(acceptedDigest),
    state: nextState,
  });
};

export class CircleFriTranscript {
  #state;

  constructor(protocolContext = new Uint8Array()) {
    this.#state = initializeCircleFriTranscriptState(protocolContext);
  }

  get digest() {
    return new Uint8Array(this.#state);
  }

  absorb(label, bytes) {
    this.#state = absorbCircleFriTranscriptState(this.#state, label, bytes);
    return this;
  }

  #sample(label, upperBound) {
    const sample = sampleCircleFriTranscriptState({ state: this.#state, label, upperBound });
    this.#state = sample.state;
    return sample.value;
  }

  challengeField(label) {
    return BigInt(this.#sample(label, Number(M31_MODULUS)));
  }

  challengeCm31(label) {
    return cm31(
      this.challengeField(`${label}-re`),
      this.challengeField(`${label}-im`),
    );
  }

  challengeIndex(label, range) {
    if (!Number.isSafeInteger(range) || range < 1 || range > 0xffff_ffff) {
      fail('challenge index range must be an integer in [1, 2^32-1]');
    }
    return this.#sample(label, range);
  }
}

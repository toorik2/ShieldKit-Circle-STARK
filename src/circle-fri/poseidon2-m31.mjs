/**
 * Poseidon2 over M31 (Grassi–Khovratovich–et al., ePrint 2023/323).
 *
 * Instance: t=16, α=5, R_F=8, R_P=14. External layer is circ(2,1,…,1).
 * Internal layer is the paper’s sparse mix. Round constants are Grain-LFSR
 * generated for this (p,t,R_F,R_P) — not a Horizen/Stwo pin, not selected.
 *
 * This is the algebraic permutation used to measure whether a PoolAction AIR
 * can be stated in the TRACE-64 even-x CFFT lane. Not a production hash lock.
 */

import {
  M31_MODULUS,
  add,
  mul,
} from '../../research-lanes/bch-shielded-pool-design/p2/reference/m31.mjs';

export const POSEIDON2_M31_ID = 'poseidon2-m31-t16-rf8-rp14-grain-v1';
export const POSEIDON2_T = 16;
export const POSEIDON2_RATE = 8;
export const POSEIDON2_RF = 8;
export const POSEIDON2_RP = 14;
export const POSEIDON2_ALPHA = 5;
export const POSEIDON2_SBOX_PER_PERM = (POSEIDON2_RF * POSEIDON2_T) + POSEIDON2_RP;
export const POSEIDON2_ROUNDS = POSEIDON2_RF + POSEIDON2_RP;
export const POSEIDON2_STATE_CELLS = POSEIDON2_ROUNDS * POSEIDON2_T;

const fail = (message) => {
  throw new TypeError(message);
};

const pow5 = (value) => {
  const sq = mul(value, value);
  return mul(mul(sq, sq), value);
};

/** Grain LFSR (Poseidon parameter generator) over an 80-bit state. */
const grainNext = (state) => {
  const bit = state[0] ^ state[13] ^ state[23] ^ state[38] ^ state[51] ^ state[62];
  state.copyWithin(0, 1);
  state[79] = bit;
  return bit;
};

const toBits = (value, width) => {
  const bits = [];
  for (let index = width - 1; index >= 0; index -= 1) {
    bits.push((value >> index) & 1);
  }
  return bits;
};

const generateGrainConstants = () => {
  const init = [
    1,
    0, 0,
    0, 0, 0, 0,
    ...toBits(31, 12),
    ...toBits(POSEIDON2_T, 12),
    ...toBits(POSEIDON2_RF, 10),
    ...toBits(POSEIDON2_RP, 10),
  ];
  if (init.length > 80) fail('Grain init exceeds 80 bits');
  while (init.length < 80) init.push(1);
  const state = Uint8Array.from(init);
  for (let index = 0; index < 160; index += 1) grainNext(state);

  const needed = (POSEIDON2_RF * POSEIDON2_T) + POSEIDON2_RP;
  const constants = [];
  while (constants.length < needed) {
    let acc = 0n;
    for (let bit = 0; bit < 31; bit += 1) {
      acc = (acc << 1n) | BigInt(grainNext(state));
    }
    if (acc < M31_MODULUS) constants.push(acc);
  }
  return Object.freeze(constants);
};

export const POSEIDON2_ROUND_CONSTANTS = generateGrainConstants();

const applyExternal = (state) => {
  let sum = 0n;
  for (let index = 0; index < POSEIDON2_T; index += 1) sum = add(sum, state[index]);
  for (let index = 0; index < POSEIDON2_T; index += 1) {
    state[index] = add(state[index], sum);
  }
};

const applyInternal = (state) => {
  let sum = 0n;
  for (let index = 0; index < POSEIDON2_T; index += 1) sum = add(sum, state[index]);
  const first = add(state[0], sum);
  for (let index = 1; index < POSEIDON2_T; index += 1) {
    state[index] = add(state[index], state[0]);
  }
  state[0] = first;
};

const runPermutation = (input, recordRounds) => {
  if (!Array.isArray(input) || input.length !== POSEIDON2_T) {
    fail(`Poseidon2 state must have ${POSEIDON2_T} M31 elements`);
  }
  const state = input.slice();
  const rounds = recordRounds ? [] : null;
  applyExternal(state);
  let cursor = 0;
  const half = POSEIDON2_RF / 2;
  const snapshot = () => {
    if (rounds) rounds.push(state.slice());
  };
  snapshot();
  for (let round = 0; round < half; round += 1) {
    for (let index = 0; index < POSEIDON2_T; index += 1) {
      state[index] = pow5(add(state[index], POSEIDON2_ROUND_CONSTANTS[cursor]));
      cursor += 1;
    }
    applyExternal(state);
    snapshot();
  }
  for (let round = 0; round < POSEIDON2_RP; round += 1) {
    state[0] = pow5(add(state[0], POSEIDON2_ROUND_CONSTANTS[cursor]));
    cursor += 1;
    applyInternal(state);
    snapshot();
  }
  for (let round = 0; round < half; round += 1) {
    for (let index = 0; index < POSEIDON2_T; index += 1) {
      state[index] = pow5(add(state[index], POSEIDON2_ROUND_CONSTANTS[cursor]));
      cursor += 1;
    }
    applyExternal(state);
    snapshot();
  }
  if (cursor !== POSEIDON2_ROUND_CONSTANTS.length) fail('Poseidon2 constant cursor drifted');
  return { output: Object.freeze(state.slice()), rounds };
};

export const applyPoseidon2External = (input) => {
  const state = input.slice();
  applyExternal(state);
  return Object.freeze(state);
};

/** One snapshot step: 0..3 full, 4..17 partial, 18..21 full. */
export const nextPoseidon2Snapshot = (input, snapshotIndex) => {
  if (!Number.isSafeInteger(snapshotIndex) || snapshotIndex < 0 || snapshotIndex >= POSEIDON2_ROUNDS) {
    fail('snapshotIndex must be in [0, 22)');
  }
  const state = input.slice();
  const half = POSEIDON2_RF / 2;
  if (snapshotIndex < half) {
    let cursor = snapshotIndex * POSEIDON2_T;
    for (let index = 0; index < POSEIDON2_T; index += 1) {
      state[index] = pow5(add(state[index], POSEIDON2_ROUND_CONSTANTS[cursor]));
      cursor += 1;
    }
    applyExternal(state);
    return Object.freeze(state);
  }
  if (snapshotIndex < half + POSEIDON2_RP) {
    const cursor = (half * POSEIDON2_T) + (snapshotIndex - half);
    state[0] = pow5(add(state[0], POSEIDON2_ROUND_CONSTANTS[cursor]));
    applyInternal(state);
    return Object.freeze(state);
  }
  let cursor = (half * POSEIDON2_T) + POSEIDON2_RP
    + ((snapshotIndex - half - POSEIDON2_RP) * POSEIDON2_T);
  for (let index = 0; index < POSEIDON2_T; index += 1) {
    state[index] = pow5(add(state[index], POSEIDON2_ROUND_CONSTANTS[cursor]));
    cursor += 1;
  }
  applyExternal(state);
  return Object.freeze(state);
};

export const permutePoseidon2M31 = (input) => runPermutation(input, false).output;

export const permutePoseidon2M31Traced = (input) => {
  const { output, rounds } = runPermutation(input, true);
  return Object.freeze({
    output,
    rounds: Object.freeze(rounds.map((row) => Object.freeze(row))),
    cells: Object.freeze(rounds.flat()),
  });
};

/** 32-byte string → nine 31-bit M31 limbs (last limb holds the leftover bits). */
export const bytesToM31Limbs = (bytes) => {
  if (!(bytes instanceof Uint8Array) || bytes.length !== 32) {
    fail('bytesToM31Limbs expects 32 bytes');
  }
  let acc = 0n;
  for (let index = bytes.length - 1; index >= 0; index -= 1) {
    acc = (acc << 8n) | BigInt(bytes[index]);
  }
  const limbs = [];
  for (let index = 0; index < 9; index += 1) {
    limbs.push(acc % M31_MODULUS);
    acc /= M31_MODULUS;
  }
  if (acc !== 0n) fail('32-byte value exceeded nine M31 limbs');
  return Object.freeze(limbs);
};

export const hashPoseidon2Sponge = (felts) => {
  const traced = hashPoseidon2SpongeTraced(felts);
  return Object.freeze({
    digest: traced.digest,
    capacity: traced.capacity,
    permutations: traced.permutations,
  });
};

export const hashPoseidon2SpongeTraced = (felts) => {
  if (!Array.isArray(felts) || felts.length === 0) fail('sponge input is required');
  const state = new Array(POSEIDON2_T).fill(0n);
  let offset = 0;
  let permutations = 0;
  const cells = [];
  while (offset < felts.length) {
    for (let index = 0; index < POSEIDON2_RATE && offset < felts.length; index += 1) {
      state[index] = add(state[index], felts[offset]);
      offset += 1;
    }
    const step = permutePoseidon2M31Traced(state);
    cells.push(...step.cells);
    for (let index = 0; index < POSEIDON2_T; index += 1) state[index] = step.output[index];
    permutations += 1;
  }
  return Object.freeze({
    digest: Object.freeze(state.slice(0, POSEIDON2_RATE)),
    capacity: Object.freeze(state.slice(POSEIDON2_RATE)),
    permutations,
    cells: Object.freeze(cells),
  });
};

export const poseidon2DomainFelt = (label) => {
  const bytes = new TextEncoder().encode(label);
  let acc = 0n;
  for (const byte of bytes) acc = (acc * 257n + BigInt(byte)) % M31_MODULUS;
  return acc;
};

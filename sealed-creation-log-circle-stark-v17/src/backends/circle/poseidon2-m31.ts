/**
 * Poseidon2 over M31 (Grassi–Khovratovich–et al., ePrint 2023/323).
 *
 * Instance: t=16, α=5, R_F=8, R_P=14. External layer is circ(2,1,…,1).
 * Internal layer is the paper’s sparse mix. Round constants are Grain-LFSR
 * generated for this (p,t,R_F,R_P) — not a Horizen/Stwo pin.
 *
 * TypeScript port of the public permutation at
 * https://github.com/toorik2/ShieldKit-Circle-STARK/blob/%40toorik2/src/circle-fri/poseidon2-m31.mjs
 *
 * Prover-side InternalHash only. Not a production hash lock (CashVM stays
 * OP_SHA256). The Poseidon2 four-predicate AIR / LDE-only bind lives on
 * `@toorik2` (`poseidon2-air.mjs`, `algebraic-hash-air.mjs`) and is not
 * this file — TRACE-64 cannot hold that S-box budget.
 */
import { M31, add, encodeLe, mul, type M31El } from "./m31.ts";

export const POSEIDON2_M31_ID = "poseidon2-m31-t16-rf8-rp14-grain-v1";
export const POSEIDON2_T = 16;
export const POSEIDON2_RATE = 8;
export const POSEIDON2_RF = 8;
export const POSEIDON2_RP = 14;
export const POSEIDON2_ALPHA = 5;
export const POSEIDON2_SBOX_PER_PERM = POSEIDON2_RF * POSEIDON2_T + POSEIDON2_RP;
export const POSEIDON2_ROUNDS = POSEIDON2_RF + POSEIDON2_RP;
export const POSEIDON2_STATE_CELLS = POSEIDON2_ROUNDS * POSEIDON2_T;

/** Domain tag for the byte-oriented InternalHash adapter. */
export const POSEIDON2_IH_DOMAIN = "PAA1-IH-poseidon2-m31-v1";

function fail(message: string): never {
  throw new TypeError(message);
}

function pow5(value: M31El): M31El {
  const sq = mul(value, value);
  return mul(mul(sq, sq), value);
}

/** Grain LFSR (Poseidon parameter generator) over an 80-bit state. */
function grainNext(state: Uint8Array): number {
  const bit = state[0]! ^ state[13]! ^ state[23]! ^ state[38]! ^ state[51]! ^ state[62]!;
  state.copyWithin(0, 1);
  state[79] = bit;
  return bit;
}

function toBits(value: number, width: number): number[] {
  const bits: number[] = [];
  for (let index = width - 1; index >= 0; index -= 1) {
    bits.push((value >> index) & 1);
  }
  return bits;
}

function generateGrainConstants(): readonly M31El[] {
  const init = [
    1,
    0,
    0,
    0,
    0,
    0,
    0,
    ...toBits(31, 12),
    ...toBits(POSEIDON2_T, 12),
    ...toBits(POSEIDON2_RF, 10),
    ...toBits(POSEIDON2_RP, 10),
  ];
  if (init.length > 80) fail("Grain init exceeds 80 bits");
  while (init.length < 80) init.push(1);
  const state = Uint8Array.from(init);
  for (let index = 0; index < 160; index += 1) grainNext(state);

  const needed = POSEIDON2_RF * POSEIDON2_T + POSEIDON2_RP;
  const constants: M31El[] = [];
  while (constants.length < needed) {
    let acc = 0n;
    for (let bit = 0; bit < 31; bit += 1) {
      acc = (acc << 1n) | BigInt(grainNext(state));
    }
    if (acc < M31) constants.push(acc);
  }
  return Object.freeze(constants);
}

export const POSEIDON2_ROUND_CONSTANTS: readonly M31El[] = generateGrainConstants();

function applyExternal(state: M31El[]): void {
  let sum = 0n;
  for (let index = 0; index < POSEIDON2_T; index += 1) sum = add(sum, state[index]!);
  for (let index = 0; index < POSEIDON2_T; index += 1) {
    state[index] = add(state[index]!, sum);
  }
}

function applyInternal(state: M31El[]): void {
  let sum = 0n;
  for (let index = 0; index < POSEIDON2_T; index += 1) sum = add(sum, state[index]!);
  const first = add(state[0]!, sum);
  for (let index = 1; index < POSEIDON2_T; index += 1) {
    state[index] = add(state[index]!, state[0]!);
  }
  state[0] = first;
}

function runPermutation(
  input: readonly M31El[],
  recordRounds: boolean,
): { output: readonly M31El[]; rounds: M31El[][] | null } {
  if (input.length !== POSEIDON2_T) {
    fail(`Poseidon2 state must have ${POSEIDON2_T} M31 elements`);
  }
  const state = input.slice();
  const rounds: M31El[][] | null = recordRounds ? [] : null;
  applyExternal(state);
  let cursor = 0;
  const half = POSEIDON2_RF / 2;
  const snapshot = (): void => {
    if (rounds) rounds.push(state.slice());
  };
  snapshot();
  for (let round = 0; round < half; round += 1) {
    for (let index = 0; index < POSEIDON2_T; index += 1) {
      state[index] = pow5(add(state[index]!, POSEIDON2_ROUND_CONSTANTS[cursor]!));
      cursor += 1;
    }
    applyExternal(state);
    snapshot();
  }
  for (let round = 0; round < POSEIDON2_RP; round += 1) {
    state[0] = pow5(add(state[0]!, POSEIDON2_ROUND_CONSTANTS[cursor]!));
    cursor += 1;
    applyInternal(state);
    snapshot();
  }
  for (let round = 0; round < half; round += 1) {
    for (let index = 0; index < POSEIDON2_T; index += 1) {
      state[index] = pow5(add(state[index]!, POSEIDON2_ROUND_CONSTANTS[cursor]!));
      cursor += 1;
    }
    applyExternal(state);
    snapshot();
  }
  if (cursor !== POSEIDON2_ROUND_CONSTANTS.length) fail("Poseidon2 constant cursor drifted");
  return { output: Object.freeze(state.slice()), rounds };
}

export function applyPoseidon2External(input: readonly M31El[]): readonly M31El[] {
  const state = input.slice();
  applyExternal(state);
  return Object.freeze(state);
}

/** One snapshot step: 0..3 full, 4..17 partial, 18..21 full. */
export function nextPoseidon2Snapshot(input: readonly M31El[], snapshotIndex: number): readonly M31El[] {
  if (!Number.isSafeInteger(snapshotIndex) || snapshotIndex < 0 || snapshotIndex >= POSEIDON2_ROUNDS) {
    fail("snapshotIndex must be in [0, 22)");
  }
  const state = input.slice();
  const half = POSEIDON2_RF / 2;
  if (snapshotIndex < half) {
    let cursor = snapshotIndex * POSEIDON2_T;
    for (let index = 0; index < POSEIDON2_T; index += 1) {
      state[index] = pow5(add(state[index]!, POSEIDON2_ROUND_CONSTANTS[cursor]!));
      cursor += 1;
    }
    applyExternal(state);
    return Object.freeze(state);
  }
  if (snapshotIndex < half + POSEIDON2_RP) {
    const cursor = half * POSEIDON2_T + (snapshotIndex - half);
    state[0] = pow5(add(state[0]!, POSEIDON2_ROUND_CONSTANTS[cursor]!));
    applyInternal(state);
    return Object.freeze(state);
  }
  let cursor = half * POSEIDON2_T + POSEIDON2_RP + (snapshotIndex - half - POSEIDON2_RP) * POSEIDON2_T;
  for (let index = 0; index < POSEIDON2_T; index += 1) {
    state[index] = pow5(add(state[index]!, POSEIDON2_ROUND_CONSTANTS[cursor]!));
    cursor += 1;
  }
  applyExternal(state);
  return Object.freeze(state);
}

export function permutePoseidon2M31(input: readonly M31El[]): readonly M31El[] {
  return runPermutation(input, false).output;
}

export function permutePoseidon2M31Traced(input: readonly M31El[]): {
  output: readonly M31El[];
  rounds: readonly (readonly M31El[])[];
  cells: readonly M31El[];
} {
  const { output, rounds } = runPermutation(input, true);
  const frozenRounds = Object.freeze((rounds ?? []).map((row) => Object.freeze(row)));
  return Object.freeze({
    output,
    rounds: frozenRounds,
    cells: Object.freeze(frozenRounds.flat()),
  });
}

/** 32-byte string → nine 31-bit M31 limbs (last limb holds the leftover bits). */
export function bytesToM31Limbs(bytes: Uint8Array): readonly M31El[] {
  if (!(bytes instanceof Uint8Array) || bytes.length !== 32) {
    fail("bytesToM31Limbs expects 32 bytes");
  }
  let acc = 0n;
  for (let index = bytes.length - 1; index >= 0; index -= 1) {
    acc = (acc << 8n) | BigInt(bytes[index]!);
  }
  const limbs: M31El[] = [];
  for (let index = 0; index < 9; index += 1) {
    limbs.push(acc % M31);
    acc /= M31;
  }
  if (acc !== 0n) fail("32-byte value exceeded nine M31 limbs");
  return Object.freeze(limbs);
}

export function hashPoseidon2Sponge(felts: readonly M31El[]): {
  digest: readonly M31El[];
  capacity: readonly M31El[];
  permutations: number;
} {
  const traced = hashPoseidon2SpongeTraced(felts);
  return Object.freeze({
    digest: traced.digest,
    capacity: traced.capacity,
    permutations: traced.permutations,
  });
}

export function hashPoseidon2SpongeTraced(felts: readonly M31El[]): {
  digest: readonly M31El[];
  capacity: readonly M31El[];
  permutations: number;
  cells: readonly M31El[];
} {
  if (!Array.isArray(felts) || felts.length === 0) fail("sponge input is required");
  const state: M31El[] = new Array(POSEIDON2_T).fill(0n);
  let offset = 0;
  let permutations = 0;
  const cells: M31El[] = [];
  while (offset < felts.length) {
    for (let index = 0; index < POSEIDON2_RATE && offset < felts.length; index += 1) {
      state[index] = add(state[index]!, felts[offset]!);
      offset += 1;
    }
    const step = permutePoseidon2M31Traced(state);
    cells.push(...step.cells);
    for (let index = 0; index < POSEIDON2_T; index += 1) state[index] = step.output[index]!;
    permutations += 1;
  }
  return Object.freeze({
    digest: Object.freeze(state.slice(0, POSEIDON2_RATE)),
    capacity: Object.freeze(state.slice(POSEIDON2_RATE)),
    permutations,
    cells: Object.freeze(cells),
  });
}

export function poseidon2DomainFelt(label: string): M31El {
  const bytes = new TextEncoder().encode(label);
  let acc = 0n;
  for (const byte of bytes) acc = (acc * 257n + BigInt(byte)) % M31;
  return acc;
}

function bytesToRateFelts(data: Uint8Array): M31El[] {
  const felts: M31El[] = [poseidon2DomainFelt(POSEIDON2_IH_DOMAIN), BigInt(data.length)];
  for (let i = 0; i < data.length; i += 3) {
    let v = BigInt(data[i] ?? 0);
    if (i + 1 < data.length) v |= BigInt(data[i + 1]!) << 8n;
    if (i + 2 < data.length) v |= BigInt(data[i + 2]!) << 16n;
    felts.push(v);
  }
  return felts;
}

/** 32-byte InternalHash digest: sponge over domain‖len‖3-byte limbs, pack rate-8. */
export function digestPoseidon2M31Bytes(data: Uint8Array): Uint8Array {
  const { digest } = hashPoseidon2Sponge(bytesToRateFelts(data));
  const out = new Uint8Array(32);
  for (let i = 0; i < POSEIDON2_RATE; i += 1) out.set(encodeLe(digest[i]!), i * 4);
  return out;
}

import { bytesToHex, hexToBytes, readU64BE, writeU64BE } from "./bytes.ts";
import { EDGE_HISTORY_CAPACITY, emptyEdgeHistoryRoot } from "./edge-history.ts";
import { emptySparseNullifierRoot } from "./sparse-nullifiers.ts";

/** Canonical v16 state commitment carried by the immutable state NFT. */
export const ANY_STATE_MAGIC = "PAA2";
export const ANY_STATE_BYTES = 128;
export const ANY_STATE_VERSION = 2;
export const STATE_BASE_SATS = 2000n;

/**
 * Logical pool state. `reserveSats` is deliberately not serialized in PAA2:
 * consensus derives it from the state UTXO value. Pool category is likewise
 * absent here and is derived from the immutable state NFT by settlement.
 */
export type AnyAmountState = {
  magic: typeof ANY_STATE_MAGIC;
  version: typeof ANY_STATE_VERSION;
  sequence: bigint;
  reserveSats: bigint;
  creationCount: bigint;
  creationHead: Uint8Array;
  edgeHistoryRoot: Uint8Array;
  nullifierRoot: Uint8Array;
};

function assertLen(value: Uint8Array, length: number, name: string): Uint8Array {
  if (value.length !== length) throw new Error(`${name} must be ${length} bytes`);
  return value;
}

function assertReservedZero(bytes: Uint8Array, start: number, end: number): void {
  for (let i = start; i < end; i += 1) {
    if (bytes[i] !== 0) throw new Error(`nonzero reserved state byte ${i}`);
  }
}

function assertState(state: AnyAmountState): void {
  if (state.magic !== ANY_STATE_MAGIC) throw new Error("bad magic");
  if (state.version !== ANY_STATE_VERSION) throw new Error("bad version");
  if (state.reserveSats < 0n) throw new Error("negative reserve");
  if (state.creationCount < 0n || state.creationCount > EDGE_HISTORY_CAPACITY) {
    throw new Error("creation count exceeds depth-32 edge history");
  }
  assertLen(state.creationHead, 32, "creationHead");
  assertLen(state.edgeHistoryRoot, 32, "edgeHistoryRoot");
  assertLen(state.nullifierRoot, 32, "nullifierRoot");
}

export function emptyState(): AnyAmountState {
  return {
    magic: ANY_STATE_MAGIC,
    version: ANY_STATE_VERSION,
    sequence: 0n,
    reserveSats: 0n,
    creationCount: 0n,
    creationHead: new Uint8Array(32),
    edgeHistoryRoot: emptyEdgeHistoryRoot(),
    nullifierRoot: emptySparseNullifierRoot(),
  };
}

/**
 * Exact PAA2 bytes:
 * - 0..4 `PAA2`; 4 version 2; 5..8 reserved zero
 * - 8..16 transition sequence, u64 big-endian
 * - 16..24 creation count, u64 big-endian; 24..32 reserved zero
 * - 32..64 current creation head
 * - 64..96 edge-history root
 * - 96..128 sparse-nullifier root
 */
export function encodeState(state: AnyAmountState): Uint8Array {
  assertState(state);
  const out = new Uint8Array(ANY_STATE_BYTES);
  out.set(new TextEncoder().encode(ANY_STATE_MAGIC), 0);
  out[4] = ANY_STATE_VERSION;
  out.set(writeU64BE(state.sequence), 8);
  out.set(writeU64BE(state.creationCount), 16);
  out.set(state.creationHead, 32);
  out.set(state.edgeHistoryRoot, 64);
  out.set(state.nullifierRoot, 96);
  return out;
}

/** Explicit name for the bytes committed by the public state NFT. */
export function encodePublicPaa2(state: AnyAmountState): Uint8Array {
  return encodeState(state);
}

/**
 * Decode PAA2 while requiring the reserve derived from the state UTXO.
 * There is intentionally no default: omitted reserve must not become a second
 * non-consensus source of logical state.
 */
export function decodeState(bytes: Uint8Array, reserveSats: bigint): AnyAmountState {
  if (bytes.length !== ANY_STATE_BYTES) {
    throw new Error(`state must be ${ANY_STATE_BYTES} bytes`);
  }
  const magic = new TextDecoder().decode(bytes.subarray(0, 4));
  if (magic !== ANY_STATE_MAGIC) throw new Error(`bad magic ${magic}`);
  if (bytes[4] !== ANY_STATE_VERSION) throw new Error("bad version");
  assertReservedZero(bytes, 5, 8);
  assertReservedZero(bytes, 24, 32);

  const state: AnyAmountState = {
    magic: ANY_STATE_MAGIC,
    version: ANY_STATE_VERSION,
    sequence: readU64BE(bytes, 8),
    reserveSats,
    creationCount: readU64BE(bytes, 16),
    creationHead: bytes.slice(32, 64),
    edgeHistoryRoot: bytes.slice(64, 96),
    nullifierRoot: bytes.slice(96, 128),
  };
  assertState(state);
  return state;
}

export function stateHex(state: AnyAmountState): string {
  return bytesToHex(encodeState(state));
}

export function stateFromHex(hex: string, reserveSats: bigint): AnyAmountState {
  return decodeState(hexToBytes(hex, "state"), reserveSats);
}

/** Dust state-NFT carrier plus the public outstanding reserve. */
export function utxoValueFor(state: AnyAmountState): bigint {
  if (state.reserveSats < 0n) throw new Error("negative reserve");
  return STATE_BASE_SATS + state.reserveSats;
}

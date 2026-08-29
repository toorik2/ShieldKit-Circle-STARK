import { bytesToHex, hexToBytes, readU64BE, writeU64BE } from "./bytes.ts";
import { emptyMerkleRoot } from "./notes.ts";
import { defaultInternalHash, type InternalHash } from "../backends/circle/internal-hash.ts";

function writeU32BE(value: bigint): Uint8Array {
  if (value < 0n || value > 0xffffffffn) throw new Error("u32 out of range");
  const n = Number(value);
  return Uint8Array.of((n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff);
}

function readU32BE(bytes: Uint8Array, offset: number): bigint {
  return (
    (BigInt(bytes[offset]!) << 24n) |
    (BigInt(bytes[offset + 1]!) << 16n) |
    (BigInt(bytes[offset + 2]!) << 8n) |
    BigInt(bytes[offset + 3]!)
  );
}

/** Any-amount profile. Not PoolStateFv1 (that is PAF1 / 0.1 ticket). */
export const ANY_STATE_MAGIC = "PAA1";
export const ANY_STATE_BYTES = 128;
export const ANY_STATE_VERSION = 1;
export const STATE_BASE_SATS = 2000n;

export type AnyAmountState = {
  magic: typeof ANY_STATE_MAGIC;
  version: typeof ANY_STATE_VERSION;
  sequence: bigint;
  reserveSats: bigint;
  depositCount: bigint;
  withdrawalCount: bigint;
  poolInstanceId: Uint8Array;
  noteRoot: Uint8Array;
  nullifierRoot: Uint8Array;
};

function assertLen(value: Uint8Array, n: number, name: string): Uint8Array {
  if (value.length !== n) throw new Error(`${name} must be ${n} bytes`);
  return value;
}

export function emptyState(
  poolInstanceId: Uint8Array,
  hash: InternalHash = defaultInternalHash(),
): AnyAmountState {
  return {
    magic: ANY_STATE_MAGIC,
    version: ANY_STATE_VERSION,
    sequence: 0n,
    reserveSats: 0n,
    depositCount: 0n,
    withdrawalCount: 0n,
    poolInstanceId: assertLen(poolInstanceId, 32, "poolInstanceId"),
    noteRoot: emptyMerkleRoot(undefined, hash),
    nullifierRoot: new Uint8Array(32),
  };
}

export function encodeState(state: AnyAmountState): Uint8Array {
  if (state.magic !== ANY_STATE_MAGIC) throw new Error("bad magic");
  if (state.version !== ANY_STATE_VERSION) throw new Error("bad version");
  if (state.reserveSats < 0n) throw new Error("negative reserve");
  const out = new Uint8Array(ANY_STATE_BYTES);
  out.set(new TextEncoder().encode(ANY_STATE_MAGIC), 0);
  out[4] = ANY_STATE_VERSION;
  out[5] = 0;
  out[6] = 0;
  out[7] = 0;
  // 4 magic + 4 ver/res + 8 seq + 8 reserve + 4 dep + 4 wd + 32 id + 32 note + 32 null = 128
  out.set(writeU64BE(state.sequence), 8);
  out.set(writeU64BE(state.reserveSats), 16);
  out.set(writeU32BE(state.depositCount), 24);
  out.set(writeU32BE(state.withdrawalCount), 28);
  out.set(assertLen(state.poolInstanceId, 32, "poolInstanceId"), 32);
  out.set(assertLen(state.noteRoot, 32, "noteRoot"), 64);
  out.set(assertLen(state.nullifierRoot, 32, "nullifierRoot"), 96);
  return out;
}

/**
 * On-chain NFT cell: instance, roots, sequence. Reserve *bytes* stay zero —
 * outstanding reserve lives in the covenant UTXO satoshis (`utxoValueFor`).
 */
export function encodePublicPaa1(state: AnyAmountState): Uint8Array {
  const bin = encodeState(state);
  bin.fill(0, 16, 24);
  return bin;
}

export function decodeState(bytes: Uint8Array): AnyAmountState {
  if (bytes.length !== ANY_STATE_BYTES) {
    throw new Error(`state must be ${ANY_STATE_BYTES} bytes`);
  }
  const magic = new TextDecoder().decode(bytes.subarray(0, 4));
  if (magic !== ANY_STATE_MAGIC) throw new Error(`bad magic ${magic}`);
  if (bytes[4] !== ANY_STATE_VERSION) throw new Error("bad version");
  return {
    magic: ANY_STATE_MAGIC,
    version: ANY_STATE_VERSION,
    sequence: readU64BE(bytes, 8),
    reserveSats: readU64BE(bytes, 16),
    depositCount: readU32BE(bytes, 24),
    withdrawalCount: readU32BE(bytes, 28),
    poolInstanceId: bytes.slice(32, 64),
    noteRoot: bytes.slice(64, 96),
    nullifierRoot: bytes.slice(96, 128),
  };
}

export function stateHex(state: AnyAmountState): string {
  return bytesToHex(encodeState(state));
}

export function stateFromHex(hex: string): AnyAmountState {
  return decodeState(hexToBytes(hex, "state"));
}

/** Dust NFT carrier plus outstanding reserve. TVL is a public consensus field. */
export function utxoValueFor(state: AnyAmountState): bigint {
  if (state.reserveSats < 0n) throw new Error("negative reserve");
  return STATE_BASE_SATS + state.reserveSats;
}

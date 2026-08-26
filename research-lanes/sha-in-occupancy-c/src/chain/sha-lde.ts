/**
 * SHA witness as 36 occupancy-query LDE openings, not TRACE w-rows.
 * Circle even/odd have 64 coefficients; 36 samples do not interpolate TRACE.
 * Leaf = public A/L/N prefix (12 B) || masked w-mix (32 × 4 B M31).
 */
import { vanishingOnTrace } from "../backends/circle/air.ts";
import type { CirclePoint } from "../backends/circle/group.ts";
import { interpolateCircle, evalCirclePoly } from "../backends/circle/interpolate.ts";
import { MerkleTree } from "../backends/circle/merkle.ts";
import { add, encodeLe, mul, type M31El } from "../backends/circle/m31.ts";
import { FRI_LOG_N, FRI_N, FRI_QUERIES, TRACE_LEN } from "../backends/circle/params.ts";
import { evalMaskPoly, openingMaskCoeffs } from "../backends/circle/witness-mask.ts";
import { defaultInternalHash, type InternalHash } from "../backends/circle/internal-hash.ts";
import { concatBytes, eq32 } from "../pool/bytes.ts";
const COMPACT_PATH_STRIDE = 3;

function uniqueTableAndIndex(hashes: Uint8Array[]): { table: Uint8Array; indexOf: Map<string, number> } {
  const indexOf = new Map<string, number>();
  const parts: Uint8Array[] = [];
  for (const h of hashes) {
    const k = Buffer.from(h).toString("hex");
    if (!indexOf.has(k)) {
      indexOf.set(k, parts.length);
      parts.push(h);
    }
  }
  const table = new Uint8Array(parts.length * 32);
  for (let i = 0; i < parts.length; i += 1) table.set(parts[i]!, i * 32);
  return { table, indexOf };
}

function compactPath(parentIndex: number, parentPath: Uint8Array[], indexOf: Map<string, number>): Uint8Array {
  const n = parentPath.length;
  const out = new Uint8Array(n * COMPACT_PATH_STRIDE);
  let i = parentIndex;
  for (let s = 0; s < n; s += 1) {
    const sib = parentPath[s]!;
    const idx = indexOf.get(Buffer.from(sib).toString("hex"));
    if (idx === undefined) throw new Error("sibling missing from unique table");
    out[s * COMPACT_PATH_STRIDE] = i & 1;
    out[s * COMPACT_PATH_STRIDE + 1] = idx & 0xff;
    out[s * COMPACT_PATH_STRIDE + 2] = (idx >> 8) & 0xff;
    i >>= 1;
  }
  return out;
}

function lookupTable(table: Uint8Array, index: number): Uint8Array {
  const o = index * 32;
  if (o + 32 > table.length) throw new Error(`table index ${index}`);
  return table.subarray(o, o + 32);
}
import {
  buildHashBitTrace,
  noteAuthPublicsFromWitness,
  packHashBitRow,
  wWordFromRow,
  type NoteAuthWitness,
} from "./note-auth-air.ts";
import type { NoteAuthOpens } from "./note-auth-bind.ts";

export const SHA_LDE_PREFIX = 12;
/** 32 consecutive mix felts / leaf → 32-leaf tree, depth 5. Depth 6 still overflowed density by ~630 ops. */
export const SHA_LDE_BUNDLE = 32;
export const SHA_LDE_VALUE_BYTES = SHA_LDE_PREFIX + SHA_LDE_BUNDLE * 4;
/** 32-leaf tree: prefix‖32 consecutive masked w-mix LDE felts. Path depth 5. */
export const SHA_LDE_PATH_DEPTH = 5;
export const SHA_LDE_COMPACT = SHA_LDE_PATH_DEPTH * COMPACT_PATH_STRIDE;
/** deg(Z·R)≈32+1130 > 36×32 samples, so TRACE w does not interpolate. */
export const SHA_LDE_OFF_DEGREE = 1130;
export const SHA_LDE_SHARD_BYTES = 1200;
export const SHA_LDE_SHARD_COUNT = 6;
export const SHA_LDE_SLOT = SHA_LDE_SHARD_BYTES * SHA_LDE_SHARD_COUNT;

export type ShaLdeOpening = {
  index: number;
  value: Uint8Array;
  compact: Uint8Array;
};

export const SHA_LDE_N_LEAVES = FRI_N / SHA_LDE_BUNDLE;
export const SHA_LDE_VECTOR_BYTES = SHA_LDE_N_LEAVES * SHA_LDE_VALUE_BYTES;

export type ShaLdeProof = {
  root: Uint8Array;
  merkleRoot?: Uint8Array;
  table: Uint8Array;
  openings: ShaLdeOpening[];
  leaves: Uint8Array[];
};

/** Query-independent commitment: SHA256 of the 128-leaf SHA-LDE vector. */
export function shaLdeVectorRoot(leaves: Uint8Array[], hash: InternalHash): Uint8Array {
  if (leaves.length !== SHA_LDE_N_LEAVES) throw new Error("sha-lde leaves");
  return hash.digest(concatBytes(...leaves));
}

export function shaPublicPrefix(pubs: NoteAuthOpens): Uint8Array {
  const out = new Uint8Array(SHA_LDE_PREFIX);
  out.set(pubs.amountCommit.subarray(0, 4), 0);
  out.set(pubs.leaf.subarray(0, 4), 4);
  out.set(pubs.nf.subarray(0, 4), 8);
  return out;
}

export function shaWMixColumn(w: NoteAuthWitness): M31El[] {
  const trace = buildHashBitTrace(w);
  const col: M31El[] = [];
  for (let r = 0; r < TRACE_LEN; r += 1) {
    const word = wWordFromRow(packHashBitRow(trace.columns, r), 0);
    col.push(BigInt(word % 2147483647));
  }
  return col;
}

/** 32 C_SHA LDE bundles (zero prefix — not A/L/N sticker). Leaf = field-AIR residual at 32 consecutive LDE points. */
export function leavesFromLdeColumn(mixes: M31El[]): Uint8Array[] {
  if (mixes.length !== FRI_N) throw new Error("sha-c lde width");
  const prefix = new Uint8Array(SHA_LDE_PREFIX);
  return Array.from({ length: SHA_LDE_N_LEAVES }, (_, k) =>
    encodeShaLdeLeaf(prefix, mixes.slice(k * SHA_LDE_BUNDLE, (k + 1) * SHA_LDE_BUNDLE)),
  );
}

/** Merkle root of the all-zero C_SHA LDE column. Honest openings are zeros. */
export function zerosCShaMerkleRoot(hash: InternalHash = defaultInternalHash()): Uint8Array {
  const zeros = Array.from({ length: FRI_N }, () => 0n);
  return new MerkleTree(leavesFromLdeColumn(zeros), hash).root;
}

export function encodeShaLdeLeaf(prefix: Uint8Array, mixes: M31El[]): Uint8Array {
  if (prefix.length !== SHA_LDE_PREFIX) throw new Error("sha prefix");
  if (mixes.length !== SHA_LDE_BUNDLE) throw new Error("sha bundle");
  const out = new Uint8Array(SHA_LDE_VALUE_BYTES);
  out.set(prefix, 0);
  for (let i = 0; i < SHA_LDE_BUNDLE; i += 1) out.set(encodeLe(mixes[i]!), SHA_LDE_PREFIX + i * 4);
  return out;
}

export function buildShaLdeLeaves(args: {
  witness: NoteAuthWitness;
  small: CirclePoint[];
  big: CirclePoint[];
  commit: Uint8Array;
  hash: InternalHash;
}): { prefix: Uint8Array; leaves: Uint8Array[] } {
  const pubs = noteAuthPublicsFromWitness(args.witness);
  const prefix = shaPublicPrefix(pubs);
  const mix = shaWMixColumn(args.witness);
  const interp = interpolateCircle(args.small, mix);
  const zLde = vanishingOnTrace(args.big, args.small);
  const rOff = shaOffCoeffs(args.commit, args.hash);
  const mixes = args.big.map((p, i) => add(evalCirclePoly(interp, p), mul(zLde[i]!, evalMaskPoly(rOff, i))));
  const nLeaf = args.big.length / SHA_LDE_BUNDLE;
  const leaves = Array.from({ length: nLeaf }, (_, k) =>
    encodeShaLdeLeaf(prefix, mixes.slice(k * SHA_LDE_BUNDLE, (k + 1) * SHA_LDE_BUNDLE)),
  );
  return { prefix, leaves };
}

function shaOffCoeffs(commit: Uint8Array, hash: InternalHash): bigint[] {
  const base = openingMaskCoeffs(commit, hash, "off");
  const out = base.slice();
  while (out.length <= SHA_LDE_OFF_DEGREE) {
    const h = hash.digest(concatBytes(commit, Uint8Array.of(out.length)));
    out.push(
      (BigInt(h[0]!) | (BigInt(h[1]!) << 8n) | (BigInt(h[2]!) << 16n) | (BigInt(h[3]! & 0x7f) << 24n)) % 2147483647n,
    );
  }
  return out.slice(0, SHA_LDE_OFF_DEGREE + 1);
}

export function openShaLde(
  leaves: Uint8Array[],
  queryIndex: number[],
  hash: InternalHash,
): ShaLdeProof {
  const tree = new MerkleTree(leaves, hash);
  if (queryIndex.length !== FRI_QUERIES) throw new Error("sha queries");
  const sibs: Uint8Array[] = [];
  for (const i of queryIndex) sibs.push(...tree.path(Math.floor(i / SHA_LDE_BUNDLE)));
  const { table, indexOf } = uniqueTableAndIndex(sibs);
  const openings = queryIndex.map((index) => {
    const leafIndex = Math.floor(index / SHA_LDE_BUNDLE);
    return {
      index,
      value: leaves[leafIndex]!,
      compact: compactPath(leafIndex, tree.path(leafIndex), indexOf),
    };
  });
  return { root: tree.root, merkleRoot: tree.root, table, openings, leaves };
}

export function shaLdeCargoBytes(proof: ShaLdeProof): number {
  const nTable = proof.table.length / 32;
  const values = FRI_QUERIES * SHA_LDE_VALUE_BYTES;
  const compact = FRI_QUERIES * SHA_LDE_COMPACT;
  return 2 + values + compact + nTable * 32;
}

/**
 * Compact C_SHA LDE cargo with unique 140-byte leaves.
 * Layout: nValues u8 ‖ nTable u8 ‖ values ‖ idx[36] ‖ compact ‖ sibTable.
 * Honest TRACE+pubs: one zero leaf (~880 B). Mixed: ≤32 unique leaves.
 */
export function encodeShaCLdeCargo(proof: ShaLdeProof): Uint8Array {
  const nTable = proof.table.length / 32;
  const compact = concatBytes(...proof.openings.map((o) => o.compact));
  if (compact.length !== FRI_QUERIES * SHA_LDE_COMPACT) throw new Error("sha-c compact");
  const indexOf = new Map<string, number>();
  const parts: Uint8Array[] = [];
  const ids = new Uint8Array(FRI_QUERIES);
  for (let q = 0; q < FRI_QUERIES; q += 1) {
    const v = proof.openings[q]!.value;
    if (v.length !== SHA_LDE_VALUE_BYTES) throw new Error("sha-c value");
    const k = Buffer.from(v).toString("hex");
    let i = indexOf.get(k);
    if (i === undefined) {
      i = parts.length;
      indexOf.set(k, i);
      parts.push(v);
    }
    ids[q] = i;
  }
  const nValues = parts.length;
  if (nValues > 255) throw new Error("sha-c unique leaves");
  return concatBytes(Uint8Array.of(nValues, nTable), ...parts, ids, compact, proof.table);
}

export function decodeShaCLdeCargo(blob: Uint8Array): ShaLdeProof | undefined {
  if (blob.length < 2 + FRI_QUERIES + FRI_QUERIES * SHA_LDE_COMPACT) return undefined;
  const nValues = blob[0]!;
  const nTable = blob[1]!;
  let o = 2;
  const values = blob.subarray(o, o + nValues * SHA_LDE_VALUE_BYTES);
  o += nValues * SHA_LDE_VALUE_BYTES;
  const ids = blob.subarray(o, o + FRI_QUERIES);
  o += FRI_QUERIES;
  const compact = blob.subarray(o, o + FRI_QUERIES * SHA_LDE_COMPACT);
  o += FRI_QUERIES * SHA_LDE_COMPACT;
  const table = blob.subarray(o, o + nTable * 32);
  if (table.length !== nTable * 32) return undefined;
  const openings = Array.from({ length: FRI_QUERIES }, (_, q) => {
    const vi = ids[q]!;
    return {
      index: q,
      value: values.subarray(vi * SHA_LDE_VALUE_BYTES, (vi + 1) * SHA_LDE_VALUE_BYTES),
      compact: compact.subarray(q * SHA_LDE_COMPACT, (q + 1) * SHA_LDE_COMPACT),
    };
  });
  return { root: new Uint8Array(32), table, openings, leaves: [] };
}

export function encodeShaLdeShards(proof: ShaLdeProof): Uint8Array[] {
  const nTable = proof.table.length / 32;
  const values = concatBytes(...proof.openings.map((o) => o.value));
  const compact = concatBytes(...proof.openings.map((o) => o.compact));
  const head = concatBytes(Uint8Array.of((nTable >> 8) & 0xff, nTable & 0xff), values, compact, proof.table);
  if (head.length > SHA_LDE_SLOT) {
    throw new Error(`sha-lde cargo ${head.length} > ${SHA_LDE_SLOT} nTable=${nTable}`);
  }
  const blob = new Uint8Array(SHA_LDE_SLOT);
  blob.set(head, 0);
  for (let o = head.length; o + 32 <= SHA_LDE_SLOT; o += 32) blob.set(proof.root, o);
  const shards: Uint8Array[] = [];
  for (let s = 0; s < SHA_LDE_SHARD_COUNT; s += 1) {
    shards.push(blob.subarray(s * SHA_LDE_SHARD_BYTES, (s + 1) * SHA_LDE_SHARD_BYTES));
  }
  return shards;
}

export function walkShaOpening(
  value: Uint8Array,
  compact: Uint8Array,
  table: Uint8Array,
  root: Uint8Array,
  hash: InternalHash,
): boolean {
  if (compact.length !== SHA_LDE_COMPACT) return false;
  let acc = hash.digest(value);
  for (let s = 0; s < SHA_LDE_PATH_DEPTH; s += 1) {
    const o = s * COMPACT_PATH_STRIDE;
    const bit = compact[o]!;
    const idx = compact[o + 1]! | (compact[o + 2]! << 8);
    const sib = lookupTable(table, idx);
    acc = bit === 0 ? hash.digest(concatBytes(acc, sib)) : hash.digest(concatBytes(sib, acc));
  }
  return eq32(acc, root);
}

export function decodeShaLdeShards(shards: Uint8Array[]): {
  nTable: number;
  values: Uint8Array;
  compact: Uint8Array;
  table: Uint8Array;
  leaves: Uint8Array[];
} {
  const blob = concatBytes(...shards.map((s) => s.subarray(0, SHA_LDE_SHARD_BYTES)));
  const nTable = (blob[0]! << 8) | blob[1]!;
  const vLen = FRI_QUERIES * SHA_LDE_VALUE_BYTES;
  const cLen = FRI_QUERIES * SHA_LDE_COMPACT;
  let o = 2;
  const values = blob.subarray(o, o + vLen);
  o += vLen;
  const compact = blob.subarray(o, o + cLen);
  o += cLen;
  const table = blob.subarray(o, o + nTable * 32);
  const leaves = Array.from({ length: FRI_QUERIES }, (_, q) =>
    values.subarray(q * SHA_LDE_VALUE_BYTES, (q + 1) * SHA_LDE_VALUE_BYTES),
  );
  return { nTable, values, compact, table, leaves };
}

import { concatBytes, eq32, writeU32BE, writeU32LE } from "../../pool/bytes.ts";
import { defaultInternalHash, type InternalHash } from "./internal-hash.ts";

const TREE_DOMAIN = new TextEncoder().encode("ShieldKit/CanonicalMerkle/v1");
const LEAF_TAG = Uint8Array.of(0);
const NODE_TAG = Uint8Array.of(1);
const NODE4_TAG = Uint8Array.of(2);

function treeKey(label: string, hash: InternalHash): Uint8Array {
  if (!label || label.length > 96) throw new Error("Merkle label");
  return hash.digest(concatBytes(TREE_DOMAIN, new TextEncoder().encode(label)));
}

export function canonicalMerkleLeaf(
  label: string,
  index: number,
  raw: Uint8Array,
  hash: InternalHash = defaultInternalHash(),
): Uint8Array {
  return hash.digest(concatBytes(LEAF_TAG, treeKey(label, hash), writeU32BE(index), raw));
}

export function canonicalMerkleParent(
  label: string,
  level: number,
  left: Uint8Array,
  right: Uint8Array,
  hash: InternalHash = defaultInternalHash(),
): Uint8Array {
  if (!Number.isInteger(level) || level < 0 || level > 31) throw new Error("Merkle level");
  if (left.length !== 32 || right.length !== 32) throw new Error("Merkle node width");
  return hash.digest(concatBytes(NODE_TAG, treeKey(label, hash), Uint8Array.of(level), left, right));
}

export function canonicalMerkleParent4(
  label: string,
  level: number,
  children: readonly Uint8Array[],
  hash: InternalHash = defaultInternalHash(),
): Uint8Array {
  if (!Number.isInteger(level) || level < 0 || level > 15) throw new Error("Merkle-4 level");
  if (children.length !== 4 || children.some((child) => child.length !== 32)) {
    throw new Error("Merkle-4 node width");
  }
  return hash.digest(concatBytes(
    NODE4_TAG,
    treeKey(label, hash),
    Uint8Array.of(level),
    ...children,
  ));
}

export type CanonicalMerkleFrontierNode4 = {
  readonly index: number;
  readonly hash: Uint8Array;
};

export type CanonicalMerkleFrontier4 = {
  readonly level: number;
  readonly nodes: readonly CanonicalMerkleFrontierNode4[];
  readonly siblingCount: number;
};

/**
 * Advance the unique radix-4 multiproof schedule by an exact number of levels.
 * This is the canonical cross-gate state: sorted `(u32le index, hash)` nodes,
 * with no merge program or duplicated opening.
 */
export function canonicalMerkleFrontier4(
  label: string,
  rows: readonly { readonly index: number; readonly raw: Uint8Array }[],
  siblings: readonly Uint8Array[],
  rowCount: number,
  levels: number,
  hash: InternalHash = defaultInternalHash(),
): CanonicalMerkleFrontier4 {
  const logRows = Math.log2(rowCount);
  if (rowCount < 4 || !Number.isInteger(logRows) || logRows % 2 !== 0 ||
    !Number.isInteger(levels) || levels < 0 || levels > logRows / 2) {
    throw new Error("Merkle-4 frontier geometry");
  }
  const indices = normalizeIndices(rows.map(({ index }) => index), rowCount);
  if (indices.length !== rows.length || rows.some(({ index }, position) => index !== indices[position])) {
    throw new Error("Merkle-4 frontier rows");
  }
  let frontier = new Map<number, Uint8Array>(
    rows.map(({ index, raw }) => [index, canonicalMerkleLeaf(label, index, raw, hash)]),
  );
  let siblingCount = 0;
  for (let level = 0; level < levels; level += 1) {
    const next = new Map<number, Uint8Array>();
    const parents = [...new Set([...frontier.keys()].map((index) => index >>> 2))]
      .sort((left, right) => left - right);
    for (const parent of parents) {
      const children = Array.from({ length: 4 }, (_, child) => {
        const value = frontier.get(parent * 4 + child) ?? siblings[siblingCount++];
        if (!value || value.length !== 32) throw new Error("Merkle-4 frontier siblings");
        return value;
      });
      next.set(parent, canonicalMerkleParent4(label, level, children, hash));
    }
    frontier = next;
  }
  return {
    level: levels,
    nodes: [...frontier.entries()].map(([index, value]) => ({ index, hash: value })),
    siblingCount,
  };
}

export function encodeCanonicalMerkleFrontier4(frontier: CanonicalMerkleFrontier4): Uint8Array {
  return concatBytes(...frontier.nodes.map(({ index, hash }) => {
    if (!Number.isSafeInteger(index) || index < 0 || index > 0xffff_ffff || hash.length !== 32) {
      throw new Error("Merkle-4 frontier node");
    }
    return concatBytes(writeU32LE(index), hash);
  }));
}

export class CanonicalMerkleTree {
  readonly label: string;
  readonly hash: InternalHash;
  readonly layers: readonly (readonly Uint8Array[])[];

  constructor(label: string, rows: readonly Uint8Array[], hash: InternalHash = defaultInternalHash()) {
    if (rows.length < 2 || (rows.length & (rows.length - 1)) !== 0) throw new Error("Merkle row count");
    this.label = label;
    this.hash = hash;
    const layers: Uint8Array[][] = [rows.map((raw, index) => canonicalMerkleLeaf(label, index, raw, hash))];
    while (layers.at(-1)!.length > 1) {
      const current = layers.at(-1)!;
      const level = layers.length - 1;
      const next: Uint8Array[] = [];
      for (let i = 0; i < current.length; i += 2) {
        next.push(canonicalMerkleParent(label, level, current[i]!, current[i + 1]!, hash));
      }
      layers.push(next);
    }
    this.layers = layers;
  }

  get root(): Uint8Array {
    return this.layers.at(-1)![0]!;
  }

  path(index: number): Uint8Array[] {
    if (!Number.isInteger(index) || index < 0 || index >= this.layers[0]!.length) throw new Error("Merkle index");
    const out: Uint8Array[] = [];
    let cursor = index;
    for (let level = 0; level < this.layers.length - 1; level += 1) {
      out.push(this.layers[level]![cursor ^ 1]!);
      cursor >>= 1;
    }
    return out;
  }

  /** Minimal deterministic sibling frontier for a set of opened rows. */
  multiproof(indices: readonly number[]): Uint8Array[] {
    let frontier = normalizeIndices(indices, this.layers[0]!.length);
    const siblings: Uint8Array[] = [];
    for (let level = 0; level < this.layers.length - 1; level += 1) {
      const present = new Set(frontier);
      for (const index of frontier) {
        const sibling = index ^ 1;
        if (!present.has(sibling)) siblings.push(this.layers[level]![sibling]!);
      }
      frontier = [...new Set(frontier.map((index) => index >> 1))].sort((a, b) => a - b);
    }
    return siblings;
  }

  static verify(
    label: string,
    raw: Uint8Array,
    index: number,
    path: readonly Uint8Array[],
    root: Uint8Array,
    hash: InternalHash = defaultInternalHash(),
  ): boolean {
    let acc = canonicalMerkleLeaf(label, index, raw, hash);
    let cursor = index;
    for (let level = 0; level < path.length; level += 1) {
      const sibling = path[level]!;
      acc = (cursor & 1) === 0
        ? canonicalMerkleParent(label, level, acc, sibling, hash)
        : canonicalMerkleParent(label, level, sibling, acc, hash);
      cursor >>= 1;
    }
    return eq32(acc, root);
  }


  static verifyMany(
    label: string,
    rows: readonly { readonly index: number; readonly raw: Uint8Array }[],
    siblings: readonly Uint8Array[],
    rowCount: number,
    root: Uint8Array,
    hash: InternalHash = defaultInternalHash(),
  ): boolean {
    if (root.length !== 32 || !Number.isInteger(rowCount) || rowCount < 2 || (rowCount & (rowCount - 1)) !== 0) {
      return false;
    }
    let indices: number[];
    try {
      indices = normalizeIndices(rows.map(({ index }) => index), rowCount);
    } catch {
      return false;
    }
    if (indices.length !== rows.length || rows.some(({ index }, position) => index !== indices[position])) return false;
    let frontier = new Map<number, Uint8Array>(
      rows.map(({ index, raw }) => [index, canonicalMerkleLeaf(label, index, raw, hash)]),
    );
    let siblingCursor = 0;
    for (let level = 0; (1 << level) < rowCount; level += 1) {
      const next = new Map<number, Uint8Array>();
      const currentIndices = [...frontier.keys()].sort((a, b) => a - b);
      for (const index of currentIndices) {
        if ((index & 1) === 1 && frontier.has(index ^ 1)) continue;
        const siblingIndex = index ^ 1;
        const sibling = frontier.get(siblingIndex) ?? siblings[siblingCursor++];
        if (!sibling || sibling.length !== 32) return false;
        const value = frontier.get(index)!;
        const parent = (index & 1) === 0
          ? canonicalMerkleParent(label, level, value, sibling, hash)
          : canonicalMerkleParent(label, level, sibling, value, hash);
        next.set(index >> 1, parent);
      }
      frontier = next;
    }
    return siblingCursor === siblings.length && frontier.size === 1 && eq32(frontier.get(0)!, root);
  }
}

/** Canonical four-way tree used by the radix-4 local-word construction. */
export class CanonicalMerkleTree4 {
  readonly label: string;
  readonly hash: InternalHash;
  readonly layers: readonly (readonly Uint8Array[])[];

  constructor(label: string, rows: readonly Uint8Array[], hash: InternalHash = defaultInternalHash()) {
    const logRows = Math.log2(rows.length);
    if (rows.length < 4 || !Number.isInteger(logRows) || logRows % 2 !== 0) {
      throw new Error("Merkle-4 row count");
    }
    this.label = label;
    this.hash = hash;
    const layers: Uint8Array[][] = [rows.map((raw, index) => canonicalMerkleLeaf(label, index, raw, hash))];
    while (layers.at(-1)!.length > 1) {
      const current = layers.at(-1)!;
      const level = layers.length - 1;
      const next: Uint8Array[] = [];
      for (let index = 0; index < current.length; index += 4) {
        next.push(canonicalMerkleParent4(label, level, current.slice(index, index + 4), hash));
      }
      layers.push(next);
    }
    this.layers = layers;
  }

  get root(): Uint8Array {
    return this.layers.at(-1)![0]!;
  }

  multiproof(indices: readonly number[]): Uint8Array[] {
    let frontier = normalizeIndices(indices, this.layers[0]!.length);
    const siblings: Uint8Array[] = [];
    for (let level = 0; level < this.layers.length - 1; level += 1) {
      const present = new Set(frontier);
      const parents = [...new Set(frontier.map((index) => index >>> 2))].sort((a, b) => a - b);
      for (const parent of parents) {
        for (let child = 0; child < 4; child += 1) {
          const index = parent * 4 + child;
          if (!present.has(index)) siblings.push(this.layers[level]![index]!);
        }
      }
      frontier = parents;
    }
    return siblings;
  }

  static verifyMany(
    label: string,
    rows: readonly { readonly index: number; readonly raw: Uint8Array }[],
    siblings: readonly Uint8Array[],
    rowCount: number,
    root: Uint8Array,
    hash: InternalHash = defaultInternalHash(),
  ): boolean {
    const logRows = Math.log2(rowCount);
    if (root.length !== 32 || rowCount < 4 || !Number.isInteger(logRows) || logRows % 2 !== 0) {
      return false;
    }
    let indices: number[];
    try {
      indices = normalizeIndices(rows.map(({ index }) => index), rowCount);
    } catch {
      return false;
    }
    if (indices.length !== rows.length || rows.some(({ index }, position) => index !== indices[position])) {
      return false;
    }
    let frontier = new Map<number, Uint8Array>(
      rows.map(({ index, raw }) => [index, canonicalMerkleLeaf(label, index, raw, hash)]),
    );
    let siblingCursor = 0;
    for (let level = 0; 4 ** level < rowCount; level += 1) {
      const next = new Map<number, Uint8Array>();
      const parents = [...new Set([...frontier.keys()].map((index) => index >>> 2))].sort((a, b) => a - b);
      for (const parent of parents) {
        const children: Uint8Array[] = [];
        for (let child = 0; child < 4; child += 1) {
          const value = frontier.get(parent * 4 + child) ?? siblings[siblingCursor++];
          if (!value || value.length !== 32) return false;
          children.push(value);
        }
        next.set(parent, canonicalMerkleParent4(label, level, children, hash));
      }
      frontier = next;
    }
    return siblingCursor === siblings.length && frontier.size === 1 && eq32(frontier.get(0)!, root);
  }
}

function normalizeIndices(indices: readonly number[], rowCount: number): number[] {
  if (indices.length === 0) throw new Error("empty Merkle opening");
  const sorted = [...indices].sort((a, b) => a - b);
  for (let i = 0; i < sorted.length; i += 1) {
    if (!Number.isInteger(sorted[i]) || sorted[i]! < 0 || sorted[i]! >= rowCount) throw new Error("Merkle index");
    if (i > 0 && sorted[i] === sorted[i - 1]) throw new Error("duplicate Merkle index");
  }
  return sorted;
}

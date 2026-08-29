import { concatBytes, eq32, sha256, ZERO32 } from "./bytes.ts";

export const SPARSE_NULLIFIER_DEPTH = 256;
export const SPARSE_NULLIFIER_PATH_BYTES = SPARSE_NULLIFIER_DEPTH * 32;
export const SPARSE_NULLIFIER_MID_LEVEL = SPARSE_NULLIFIER_DEPTH / 2;
export const SPARSE_NULLIFIER_SEGMENT_BYTES = SPARSE_NULLIFIER_MID_LEVEL * 32;
export const NULLIFIER_USED_TAG = new TextEncoder().encode("PAA1-NULLIFIER-USED-v1");

function keyIndex(key: Uint8Array): bigint {
  if (key.length !== 32) throw new Error("nullifier key width");
  let out = 0n;
  for (let i = 0; i < 32; i += 1) out |= BigInt(key[i]!) << BigInt(i * 8);
  return out;
}

function nodeKey(level: number, index: bigint): string {
  return `${level}:${index}`;
}

export function usedNullifierLeaf(nullifier: Uint8Array): Uint8Array {
  if (nullifier.length !== 32 || nullifier.every((byte) => byte === 0)) {
    throw new Error("non-zero nullifier required");
  }
  return sha256(concatBytes(NULLIFIER_USED_TAG, nullifier));
}

let cachedZeros: Uint8Array[] | undefined;

/** zeros[level] is the root of an empty subtree containing 2^level leaves. */
export function sparseNullifierZeros(): readonly Uint8Array[] {
  if (cachedZeros) return cachedZeros;
  const zeros: Uint8Array[] = [new Uint8Array(ZERO32)];
  for (let level = 0; level < SPARSE_NULLIFIER_DEPTH; level += 1) {
    zeros.push(sha256(concatBytes(zeros[level]!, zeros[level]!)));
  }
  cachedZeros = zeros;
  return zeros;
}

export function emptySparseNullifierRoot(): Uint8Array {
  return new Uint8Array(sparseNullifierZeros()[SPARSE_NULLIFIER_DEPTH]!);
}

export function foldSparseNullifierPath(
  leaf: Uint8Array,
  nullifier: Uint8Array,
  path: readonly Uint8Array[],
): Uint8Array {
  if (leaf.length !== 32 || nullifier.length !== 32) throw new Error("sparse nullifier width");
  if (path.length !== SPARSE_NULLIFIER_DEPTH || path.some((node) => node.length !== 32)) {
    throw new Error("sparse nullifier path");
  }
  return foldSparseNullifierPathSegment(leaf, nullifier, path, 0);
}

/** Fold one consecutive path segment, starting at the given key bit. */
export function foldSparseNullifierPathSegment(
  leaf: Uint8Array,
  nullifier: Uint8Array,
  path: readonly Uint8Array[],
  startLevel: number,
): Uint8Array {
  if (leaf.length !== 32 || nullifier.length !== 32 ||
    !Number.isInteger(startLevel) || startLevel < 0 ||
    startLevel + path.length > SPARSE_NULLIFIER_DEPTH ||
    path.some((node) => node.length !== 32)) {
    throw new Error("sparse nullifier segment");
  }
  let acc = leaf;
  let index = keyIndex(nullifier) >> BigInt(startLevel);
  for (const sibling of path) {
    acc = (index & 1n) === 0n
      ? sha256(concatBytes(acc, sibling))
      : sha256(concatBytes(sibling, acc));
    index >>= 1n;
  }
  return acc;
}

export function verifySparseNullifierInsertion(args: {
  nullifier: Uint8Array;
  path: readonly Uint8Array[];
  oldRoot: Uint8Array;
  newRoot: Uint8Array;
}): boolean {
  const old = foldSparseNullifierPath(ZERO32, args.nullifier, args.path);
  if (!eq32(old, args.oldRoot)) return false;
  const next = foldSparseNullifierPath(usedNullifierLeaf(args.nullifier), args.nullifier, args.path);
  return eq32(next, args.newRoot);
}

/**
 * Small reference store for construction tests and wallet-side path creation.
 * Consensus only needs `verifySparseNullifierInsertion`; it never trusts this
 * mutable helper.
 */
export class SparseNullifierTree {
  readonly nodes = new Map<string, Uint8Array>();
  readonly zeros = sparseNullifierZeros();

  get root(): Uint8Array {
    return new Uint8Array(this.nodes.get(nodeKey(SPARSE_NULLIFIER_DEPTH, 0n)) ?? this.zeros[SPARSE_NULLIFIER_DEPTH]!);
  }

  path(nullifier: Uint8Array): Uint8Array[] {
    let index = keyIndex(nullifier);
    const path: Uint8Array[] = [];
    for (let level = 0; level < SPARSE_NULLIFIER_DEPTH; level += 1) {
      path.push(new Uint8Array(this.nodes.get(nodeKey(level, index ^ 1n)) ?? this.zeros[level]!));
      index >>= 1n;
    }
    return path;
  }

  insert(nullifier: Uint8Array): { oldRoot: Uint8Array; newRoot: Uint8Array; path: Uint8Array[] } {
    const oldRoot = this.root;
    const path = this.path(nullifier);
    if (!eq32(foldSparseNullifierPath(ZERO32, nullifier, path), oldRoot)) {
      throw new Error("nullifier already used");
    }
    let index = keyIndex(nullifier);
    let acc = usedNullifierLeaf(nullifier);
    this.nodes.set(nodeKey(0, index), acc);
    for (let level = 0; level < SPARSE_NULLIFIER_DEPTH; level += 1) {
      const sibling = this.nodes.get(nodeKey(level, index ^ 1n)) ?? this.zeros[level]!;
      acc = (index & 1n) === 0n
        ? sha256(concatBytes(acc, sibling))
        : sha256(concatBytes(sibling, acc));
      index >>= 1n;
      this.nodes.set(nodeKey(level + 1, index), acc);
    }
    const newRoot = this.root;
    if (!verifySparseNullifierInsertion({ nullifier, path, oldRoot, newRoot })) {
      throw new Error("sparse nullifier insertion");
    }
    return { oldRoot, newRoot, path };
  }
}

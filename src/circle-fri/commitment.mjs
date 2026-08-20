import {
  M31_MODULUS,
  encodeM31,
} from '../../research-lanes/bch-shielded-pool-design/p2/reference/m31.mjs';

import {
  cm31,
  isCm31,
} from './cm31.mjs';

import {
  assertBytes,
  concatBytes,
  equalBytes,
  hash256,
  utf8,
} from './bytes.mjs';

export const M31_MERKLE_LEAF_DOMAIN = utf8('ShieldKit/CircleFRI/M31Leaf/v1\0');
export const CM31_MERKLE_LEAF_DOMAIN = utf8('ShieldKit/CircleFRI/CM31Leaf/v1\0');
export const M31_MERKLE_NODE_DOMAIN = utf8('ShieldKit/CircleFRI/MerkleNode/v1\0');

const fail = (message) => {
  throw new TypeError(message);
};

const assertElement = (value, name) => {
  if (typeof value !== 'bigint' || value < 0n || value >= M31_MODULUS) {
    fail(`${name} must be a canonical M31 element`);
  }
  return value;
};

const isPowerOfTwo = (value) => (
  Number.isSafeInteger(value)
  && value > 0
  && (value & (value - 1)) === 0
);

const canonicalizeMerkleIndices = (indices, length, { requireSorted = false } = {}) => {
  if (!Array.isArray(indices) || indices.length === 0) {
    fail('Merkle multiproof indices must be a nonempty array');
  }
  const canonical = indices.map((index, ordinal) => {
    if (!Number.isSafeInteger(index) || index < 0 || index >= length) {
      fail(`Merkle multiproof indices[${ordinal}] is out of range`);
    }
    return index;
  });
  if (new Set(canonical).size !== canonical.length) fail('Merkle multiproof indices must be unique');
  if (requireSorted) {
    for (let index = 1; index < canonical.length; index += 1) {
      if (canonical[index - 1] >= canonical[index]) {
        fail('Merkle multiproof indices must be strictly increasing');
      }
    }
    return canonical;
  }
  return canonical.sort((a, b) => a - b);
};

export const hashM31Leaf = (value) => hash256(concatBytes(
  M31_MERKLE_LEAF_DOMAIN,
  encodeM31(assertElement(value, 'leaf value')),
));

export const hashCm31Leaf = (value) => {
  const felt = isCm31(value) ? cm31(value.re, value.im) : fail('CM31 leaf value is required');
  return hash256(concatBytes(
    CM31_MERKLE_LEAF_DOMAIN,
    encodeM31(felt.re),
    encodeM31(felt.im),
  ));
};

const hashCodewordLeaf = (value) => (
  isCm31(value) ? hashCm31Leaf(value) : hashM31Leaf(value)
);

export const hashMerkleNode = (left, right) => {
  const a = assertBytes(left, 'left hash');
  const b = assertBytes(right, 'right hash');
  if (a.length !== 32 || b.length !== 32) fail('Merkle child hashes must be exactly 32 bytes');
  return hash256(concatBytes(M31_MERKLE_NODE_DOMAIN, a, b));
};

export const buildM31MerkleTree = (values) => {
  if (!Array.isArray(values) || !isPowerOfTwo(values.length)) {
    fail('Merkle codeword length must be a positive power of two');
  }
  const codeword = values.map((value, index) => (
    isCm31(value) ? cm31(value.re, value.im) : assertElement(value, `values[${index}]`)
  ));
  const layers = [codeword.map(hashCodewordLeaf)];
  while (layers.at(-1).length > 1) {
    const current = layers.at(-1);
    const parent = new Array(current.length / 2);
    for (let index = 0; index < current.length; index += 2) {
      parent[index / 2] = hashMerkleNode(current[index], current[index + 1]);
    }
    layers.push(parent);
  }
  return Object.freeze({
    length: codeword.length,
    root: new Uint8Array(layers.at(-1)[0]),
    layers,
  });
};

export const openM31Merkle = (tree, index) => {
  if (tree === null || typeof tree !== 'object' || !isPowerOfTwo(tree.length) || !Array.isArray(tree.layers)) {
    fail('tree must be an M31 Merkle tree');
  }
  if (!Number.isSafeInteger(index) || index < 0 || index >= tree.length) fail('Merkle index is out of range');
  const siblings = [];
  let currentIndex = index;
  for (let level = 0; level < tree.layers.length - 1; level += 1) {
    const sibling = tree.layers[level][currentIndex ^ 1];
    siblings.push(new Uint8Array(sibling));
    currentIndex = Math.floor(currentIndex / 2);
  }
  return Object.freeze({ index, siblings });
};

/**
 * Build the unique canonical frontier for several leaves in one M31 Merkle tree.
 *
 * Indices are returned in strictly increasing order. Frontier hashes are emitted
 * bottom-up and, within each level, by increasing known-node index. A verifier
 * therefore needs no positions, flags, or caller-selected traversal metadata.
 */
export const openM31MerkleMulti = (tree, indices) => {
  if (tree === null || typeof tree !== 'object' || !isPowerOfTwo(tree.length) || !Array.isArray(tree.layers)) {
    fail('tree must be an M31 Merkle tree');
  }
  const canonicalIndices = canonicalizeMerkleIndices(indices, tree.length);
  const siblings = [];
  let current = canonicalIndices;
  for (let level = 0; level < tree.layers.length - 1; level += 1) {
    const known = new Set(current);
    for (const index of current) {
      const siblingIndex = index ^ 1;
      if (!known.has(siblingIndex)) siblings.push(new Uint8Array(tree.layers[level][siblingIndex]));
    }
    current = [...new Set(current.map((index) => Math.floor(index / 2)))].sort((a, b) => a - b);
  }
  return Object.freeze({
    indices: Object.freeze(canonicalIndices),
    siblings: Object.freeze(siblings),
  });
};

export const verifyM31Merkle = ({ root, length, index, value, siblings }) => {
  const expectedRoot = assertBytes(root, 'root');
  if (expectedRoot.length !== 32) fail('Merkle root must be exactly 32 bytes');
  if (!isPowerOfTwo(length)) fail('Merkle length must be a positive power of two');
  if (!Number.isSafeInteger(index) || index < 0 || index >= length) fail('Merkle index is out of range');
  if (!Array.isArray(siblings) || siblings.length !== Math.log2(length)) {
    fail('Merkle path length does not match the committed codeword length');
  }

  let current = hashCodewordLeaf(value);
  let currentIndex = index;
  for (let level = 0; level < siblings.length; level += 1) {
    const sibling = assertBytes(siblings[level], `siblings[${level}]`);
    if (sibling.length !== 32) fail(`siblings[${level}] must be exactly 32 bytes`);
    current = (currentIndex & 1) === 0
      ? hashMerkleNode(current, sibling)
      : hashMerkleNode(sibling, current);
    currentIndex = Math.floor(currentIndex / 2);
  }
  return equalBytes(current, expectedRoot);
};

/** Verify a canonical M31 Merkle multiproof without caller-supplied flags. */
export const verifyM31MerkleMulti = ({ root, length, indices, values, siblings }) => {
  const expectedRoot = assertBytes(root, 'root');
  if (expectedRoot.length !== 32) fail('Merkle root must be exactly 32 bytes');
  if (!isPowerOfTwo(length)) fail('Merkle length must be a positive power of two');
  const canonicalIndices = canonicalizeMerkleIndices(indices, length, { requireSorted: true });
  if (!Array.isArray(values) || values.length !== canonicalIndices.length) {
    fail('Merkle multiproof values must match the index count');
  }
  if (!Array.isArray(siblings)) fail('Merkle multiproof siblings must be an array');
  const frontier = siblings.map((hash, index) => {
    const bytes = assertBytes(hash, `siblings[${index}]`);
    if (bytes.length !== 32) fail(`siblings[${index}] must be exactly 32 bytes`);
    return bytes;
  });

  let current = new Map(canonicalIndices.map((index, ordinal) => [
    index,
    hashCodewordLeaf(values[ordinal]),
  ]));
  let siblingCursor = 0;
  let levelLength = length;
  while (levelLength > 1) {
    const parents = new Map();
    for (const index of [...current.keys()].sort((a, b) => a - b)) {
      const parentIndex = Math.floor(index / 2);
      if (parents.has(parentIndex)) continue;
      const leftIndex = parentIndex * 2;
      const rightIndex = leftIndex + 1;
      const left = current.get(leftIndex) ?? frontier[siblingCursor++];
      const right = current.get(rightIndex) ?? frontier[siblingCursor++];
      if (left === undefined || right === undefined) fail('Merkle multiproof frontier is truncated');
      parents.set(parentIndex, hashMerkleNode(left, right));
    }
    current = parents;
    levelLength /= 2;
  }
  if (siblingCursor !== frontier.length) fail('Merkle multiproof frontier has unused hashes');
  return equalBytes(current.get(0), expectedRoot);
};

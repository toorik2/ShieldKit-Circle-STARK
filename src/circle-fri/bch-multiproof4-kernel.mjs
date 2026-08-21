/**
 * BCH-2026 P2SH32 kernel for canonical exactly-four-leaf M31 multiproofs.
 *
 * The reusable verification fragment takes its tree width from the stack.
 * Four runtime index/value pairs are converted to sorted 36-byte records
 * (`u32le(index) || hash32`) and reduced through the canonical bottom-up union
 * frontier. A standalone redeem remains specialized only to the committed
 * power-of-two tree length by pushing that width before the fragment. No
 * proof-specific positions or merge flags enter either form.
 */

import {
  encodeLockingBytecodeP2sh32,
  hash256,
} from '@bitauth/libauth';

import {
  encodeM31,
  evaluateScriptFixture,
} from '../../research-lanes/bch-shielded-pool-design/p2/bch-kernels/m31-kernel.mjs';

import { M31_MODULUS } from '../../research-lanes/bch-shielded-pool-design/p2/reference/m31.mjs';

import {
  buildM31MerkleTree,
  openM31MerkleMulti,
  M31_MERKLE_LEAF_DOMAIN,
  M31_MERKLE_NODE_DOMAIN,
} from './commitment.mjs';

import { equalBytes } from './bytes.mjs';

const FIXTURE_KIND = 'bch-m31-canonical-four-leaf-multiproof-v1';
const RECORD_BYTES = 36;
const INDEX_BYTES = 4;
const HASH_BYTES = 32;
const MAXIMUM_TREE_LENGTH = 0x8000_0000;

const OP = Object.freeze({
  OP_0: 0x00,
  OP_1: 0x51,
  OP_2: 0x52,
  OP_4: 0x54,
  OP_IF: 0x63,
  OP_BEGIN: 0x65,
  OP_UNTIL: 0x66,
  OP_ELSE: 0x67,
  OP_ENDIF: 0x68,
  OP_VERIFY: 0x69,
  OP_TOALTSTACK: 0x6b,
  OP_FROMALTSTACK: 0x6c,
  OP_DROP: 0x75,
  OP_DUP: 0x76,
  OP_NIP: 0x77,
  OP_OVER: 0x78,
  OP_PICK: 0x79,
  OP_ROLL: 0x7a,
  OP_ROT: 0x7b,
  OP_SWAP: 0x7c,
  OP_CAT: 0x7e,
  OP_SPLIT: 0x7f,
  OP_NUM2BIN: 0x80,
  OP_BIN2NUM: 0x81,
  OP_SIZE: 0x82,
  OP_EQUAL: 0x87,
  OP_1ADD: 0x8b,
  OP_DIV: 0x96,
  OP_MOD: 0x97,
  OP_NUMEQUAL: 0x9c,
  OP_NUMEQUALVERIFY: 0x9d,
  OP_LESSTHAN: 0x9f,
  OP_GREATERTHANOREQUAL: 0xa2,
  OP_HASH256: 0xaa,
});

const require = (condition, message) => {
  if (!condition) throw new TypeError(message);
};

const concat = (...parts) => {
  const length = parts.reduce((sum, part) => {
    require(part instanceof Uint8Array, 'script parts must be Uint8Array values');
    return sum + part.length;
  }, 0);
  const result = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
};

const encodeMinimalDataPush = (value) => {
  require(value instanceof Uint8Array, 'push value must be a Uint8Array');
  if (value.length === 0) return Uint8Array.of(OP.OP_0);
  if (value.length <= 75) return concat(Uint8Array.of(value.length), value);
  if (value.length <= 0xff) return concat(Uint8Array.of(0x4c, value.length), value);
  if (value.length <= 0xffff) return concat(Uint8Array.of(0x4d, value.length & 0xff, value.length >>> 8), value);
  throw new TypeError('kernel push exceeds OP_PUSHDATA2 capacity');
};

const encodeScriptNumber = (value) => {
  require(typeof value === 'bigint' && value >= 0n, 'Script number must be a nonnegative BigInt');
  if (value === 0n) return new Uint8Array();
  const bytes = [];
  let remaining = value;
  while (remaining > 0n) {
    bytes.push(Number(remaining & 0xffn));
    remaining >>= 8n;
  }
  if ((bytes.at(-1) & 0x80) !== 0) bytes.push(0);
  return Uint8Array.from(bytes);
};

const pushNumber = (value) => {
  const number = typeof value === 'bigint' ? value : BigInt(value);
  if (number === 0n) return Uint8Array.of(OP.OP_0);
  if (number >= 1n && number <= 16n) return Uint8Array.of(0x50 + Number(number));
  return encodeMinimalDataPush(encodeScriptNumber(number));
};

const isPowerOfTwo = (value) => Number.isSafeInteger(value)
  && value > 0
  && value <= MAXIMUM_TREE_LENGTH
  && (BigInt(value) & (BigInt(value) - 1n)) === 0n;

const assertM31 = (value, name) => {
  require(typeof value === 'bigint' && value >= 0n && value < M31_MODULUS, `${name} must be a canonical M31 element`);
  return value;
};

const assertIndexQuad = (indices, length) => {
  require(Array.isArray(indices) && indices.length === 4, 'kernel requires exactly four Merkle indices');
  for (let ordinal = 0; ordinal < indices.length; ordinal += 1) {
    require(Number.isSafeInteger(indices[ordinal]) && indices[ordinal] >= 0 && indices[ordinal] < length, `indices[${ordinal}] is out of range`);
    if (ordinal > 0) require(indices[ordinal - 1] < indices[ordinal], 'Merkle indices must be strictly increasing and unique');
  }
  return indices;
};

const assertHash = (value, name) => {
  require(value instanceof Uint8Array && value.length === HASH_BYTES, `${name} must be exactly 32 bytes`);
  return value;
};

const compileScript = (script) => {
  require(Array.isArray(script), 'compiled Script must be an array');
  require(
    script.every((byte) => Number.isInteger(byte) && byte >= 0 && byte <= 0xff),
    'compiled Script contains an invalid or undefined byte',
  );
  return Uint8Array.from(script);
};

const hashLeaf = () => [
  ...encodeMinimalDataPush(M31_MERKLE_LEAF_DOMAIN),
  OP.OP_SWAP,
  OP.OP_CAT,
  OP.OP_HASH256,
];

/** Input: left hash, right hash. Output: parent hash. */
const hashNode = () => [
  OP.OP_CAT,
  ...encodeMinimalDataPush(M31_MERKLE_NODE_DOMAIN),
  OP.OP_SWAP,
  OP.OP_CAT,
  OP.OP_HASH256,
];

/**
 * Input suffix: frontier, remainingCurrent, currentHash, currentIndex.
 * Output suffix: frontier, remainingCurrent, currentHash, currentIndex, bool.
 */
const nextRecordIsRightSibling = () => [
  OP.OP_DUP,
  OP.OP_2,
  OP.OP_MOD,
  OP.OP_0,
  OP.OP_NUMEQUAL,
  OP.OP_IF,
    // An empty remaining blob cannot contain the right sibling.
    OP.OP_2,
    OP.OP_PICK,
    OP.OP_SIZE,
    OP.OP_NIP,
    OP.OP_0,
    OP.OP_NUMEQUAL,
    OP.OP_IF,
      OP.OP_0,
    OP.OP_ELSE,
      // Peek at the next record's fixed-width index without consuming it.
      OP.OP_2,
      OP.OP_PICK,
      ...pushNumber(INDEX_BYTES),
      OP.OP_SPLIT,
      OP.OP_DROP,
      OP.OP_BIN2NUM,
      OP.OP_OVER,
      OP.OP_1ADD,
      OP.OP_NUMEQUAL,
    OP.OP_ENDIF,
  OP.OP_ELSE,
    OP.OP_0,
  OP.OP_ENDIF,
];

/**
 * Known-sibling branch.
 *
 * Input: root, nextBlob, frontier, remainingCurrent, hash0, index0.
 * Output: root, nextBlob, remainingCurrent, frontier, parentHash, parentIndex.
 */
const mergeKnownSibling = () => [
  OP.OP_2,
  OP.OP_DIV,
  OP.OP_TOALTSTACK,

  // Consume the next complete record from remainingCurrent.
  OP.OP_SWAP,
  ...pushNumber(RECORD_BYTES),
  OP.OP_SPLIT,
  OP.OP_SWAP,
  ...pushNumber(INDEX_BYTES),
  OP.OP_SPLIT,
  OP.OP_SWAP,
  OP.OP_DROP,

  // Normalize to frontier, remainingCurrent, leftHash, rightHash.
  OP.OP_ROT,
  OP.OP_SWAP,
  ...hashNode(),

  // Swap frontier and remainingCurrent under the computed parent.
  OP.OP_TOALTSTACK,
  OP.OP_SWAP,
  OP.OP_FROMALTSTACK,
  OP.OP_FROMALTSTACK,
];

/**
 * Missing-sibling branch.
 *
 * Input: root, nextBlob, frontier, remainingCurrent, hash, index.
 * Output: root, nextBlob, remainingCurrent, frontier, parentHash, parentIndex.
 */
const mergeFrontierSibling = () => [
  OP.OP_DUP,
  OP.OP_2,
  OP.OP_MOD,
  OP.OP_SWAP,
  OP.OP_2,
  OP.OP_DIV,

  // Move the packed frontier to the top and consume exactly one hash.
  ...pushNumber(4),
  OP.OP_ROLL,
  ...pushNumber(HASH_BYTES),
  OP.OP_SPLIT,
  OP.OP_TOALTSTACK,

  // Move parentIndex aside, then order children from runtime parity.
  OP.OP_SWAP,
  OP.OP_TOALTSTACK,
  OP.OP_SWAP,
  OP.OP_IF,
    OP.OP_SWAP,
  OP.OP_ENDIF,
  ...hashNode(),

  // Restore parentIndex and remaining frontier, then normalize the state.
  OP.OP_FROMALTSTACK,
  OP.OP_FROMALTSTACK,
  OP.OP_ROT,
  OP.OP_ROT,
];

/** Input: root, nextBlob, remainingCurrent, frontier, parentHash, parentIndex. */
const appendParentRecord = () => [
  OP.OP_4,
  OP.OP_NUM2BIN,
  OP.OP_SWAP,
  OP.OP_CAT,

  // Append, never prepend: parent records remain strictly sorted.
  ...pushNumber(3),
  OP.OP_ROLL,
  OP.OP_SWAP,
  OP.OP_CAT,
  OP.OP_ROT,
  OP.OP_ROT,
];

/** Input and output state: root, nextBlob, currentBlob, frontier. */
const reduceOneCurrentRecord = () => [
  // Split and decode the first complete current record.
  OP.OP_SWAP,
  ...pushNumber(RECORD_BYTES),
  OP.OP_SPLIT,
  OP.OP_SWAP,
  ...pushNumber(INDEX_BYTES),
  OP.OP_SPLIT,
  OP.OP_SWAP,
  OP.OP_BIN2NUM,

  ...nextRecordIsRightSibling(),
  OP.OP_IF,
    ...mergeKnownSibling(),
  OP.OP_ELSE,
    ...mergeFrontierSibling(),
  OP.OP_ENDIF,
  ...appendParentRecord(),
];

const duplicateRuntimeWidth = () => [
  OP.OP_FROMALTSTACK,
  OP.OP_DUP,
  OP.OP_TOALTSTACK,
];

const validateRuntimeIndices = () => [
  // Initial witness stack: root, i0, i1, i2, i3, v0, v1, v2, v3, frontier.
  ...[8, 7, 6, 5].flatMap((depth) => [
    ...pushNumber(depth),
    OP.OP_PICK,
    OP.OP_0,
    OP.OP_GREATERTHANOREQUAL,
    OP.OP_VERIFY,
    ...pushNumber(depth),
    OP.OP_PICK,
    ...duplicateRuntimeWidth(),
    OP.OP_LESSTHAN,
    OP.OP_VERIFY,
  ]),
  ...[8, 7, 6].flatMap((depth) => [
    ...pushNumber(depth),
    OP.OP_PICK,
    ...pushNumber(depth),
    OP.OP_PICK,
    OP.OP_LESSTHAN,
    OP.OP_VERIFY,
  ]),
];

const buildInitialCurrentBlob = ({ hashedLeaves = false } = {}) => [
  // Keep the caller's packed frontier below four internally built records.
  OP.OP_TOALTSTACK,
  ...[4, 3, 2, 1].flatMap((indexDepth) => [
    ...(hashedLeaves ? [] : hashLeaf()),
    ...pushNumber(indexDepth),
    OP.OP_ROLL,
    OP.OP_4,
    OP.OP_NUM2BIN,
    OP.OP_SWAP,
    OP.OP_CAT,
    OP.OP_TOALTSTACK,
  ]),

  // Records return in ascending index order: rec0 || rec1 || rec2 || rec3.
  OP.OP_FROMALTSTACK,
  OP.OP_FROMALTSTACK,
  OP.OP_CAT,
  OP.OP_FROMALTSTACK,
  OP.OP_CAT,
  OP.OP_FROMALTSTACK,
  OP.OP_CAT,
  OP.OP_FROMALTSTACK,

  // Normalize to root, emptyNextBlob, currentBlob, frontier.
  OP.OP_0,
  OP.OP_ROT,
  OP.OP_ROT,
];

/**
 * Compile the reusable exactly-four-leaf verification function body.
 *
 * Input suffix, bottom-to-top (any lower caller prefix is preserved):
 * `root, i0, i1, i2, i3, rawM31v0, rawM31v1, rawM31v2, rawM31v3,
 * packedCanonicalFrontier, treeWidth`.
 * `hashedLeaves: true` takes 32-byte leaf hashes instead of raw M31 values.
 *
 * The four indices must be strictly increasing. `treeWidth` is consumed from
 * the top, must be a power of two by runtime reduction, and independently
 * determines both the exact number of tree levels and exact frontier
 * consumption. Output is one boolean replacing the complete suffix.
 */
export const buildBchM31Multiproof4VerificationBytecode = ({ hashedLeaves = false } = {}) => {
  const script = [
    // Keep the runtime width above any pre-existing alternate-stack caller
    // state. All temporary alternate-stack use in this body remains balanced.
    OP.OP_TOALTSTACK,
    ...validateRuntimeIndices(),
    ...buildInitialCurrentBlob({ hashedLeaves }),

    // Tree width is independent of caller-supplied frontier length.
    OP.OP_BEGIN,
      // Reduce all known nodes in this level, consuming the canonical frontier.
      OP.OP_BEGIN,
        ...reduceOneCurrentRecord(),
        OP.OP_OVER,
        OP.OP_SIZE,
        OP.OP_NIP,
        OP.OP_0,
        OP.OP_NUMEQUAL,
      OP.OP_UNTIL,

      // Drop the proven-empty current blob and promote nextBlob.
      OP.OP_SWAP,
      OP.OP_DROP,
      OP.OP_0,
      OP.OP_ROT,
      OP.OP_ROT,

      // Consume exactly one committed tree level.
      OP.OP_FROMALTSTACK,
      OP.OP_DUP,
      OP.OP_2,
      OP.OP_MOD,
      OP.OP_0,
      OP.OP_NUMEQUALVERIFY,
      OP.OP_2,
      OP.OP_DIV,
      OP.OP_DUP,
      OP.OP_TOALTSTACK,
      OP.OP_1,
      OP.OP_NUMEQUAL,
    OP.OP_UNTIL,
    OP.OP_FROMALTSTACK,
    OP.OP_1,
    OP.OP_NUMEQUALVERIFY,

    // Final state must be one index-0 record, no frontier, and no next blob.
    OP.OP_ROT,
    OP.OP_SIZE,
    OP.OP_0,
    OP.OP_NUMEQUALVERIFY,
    OP.OP_DROP,
    OP.OP_SIZE,
    OP.OP_0,
    OP.OP_NUMEQUALVERIFY,
    OP.OP_DROP,
    OP.OP_SIZE,
    ...pushNumber(RECORD_BYTES),
    OP.OP_NUMEQUALVERIFY,
    ...pushNumber(INDEX_BYTES),
    OP.OP_SPLIT,
    OP.OP_SWAP,
    OP.OP_BIN2NUM,
    OP.OP_0,
    OP.OP_NUMEQUALVERIFY,
    OP.OP_EQUAL,
  ];
  return compileScript(script);
};

/** Compile one fixed tree length; no proof-specific index enters the redeem. */
export const buildBchM31Multiproof4RedeemBytecode = (fixture) => {
  require(fixture?.kind === FIXTURE_KIND, 'four-leaf multiproof fixture is required');
  require(isPowerOfTwo(fixture.length), 'Merkle length must be a supported positive power of two');
  return compileScript([
    ...pushNumber(fixture.length),
    ...buildBchM31Multiproof4VerificationBytecode(),
  ]);
};

export const buildBchM31Multiproof4OperandUnlockingBytecode = (fixture) => {
  require(fixture?.kind === FIXTURE_KIND, 'four-leaf multiproof fixture is required');
  require(isPowerOfTwo(fixture.length), 'Merkle length must be a supported positive power of two');
  assertIndexQuad(fixture.indices, fixture.length);
  require(Array.isArray(fixture.frontier), 'Merkle multiproof frontier must be an array');
  const rawValues = fixture.rawValues ?? fixture.values.map(encodeM31);
  const rawIndices = fixture.rawIndices ?? fixture.indices.map((index) => encodeScriptNumber(BigInt(index)));
  require(Array.isArray(rawValues) && rawValues.length === 4, 'multiproof needs four raw M31 values');
  require(Array.isArray(rawIndices) && rawIndices.length === 4, 'multiproof needs four raw indices');
  return concat(
    encodeMinimalDataPush(assertHash(fixture.root, 'Merkle root')),
    ...(fixture.rawIndices === undefined
      ? fixture.indices.map(pushNumber)
      : rawIndices.map((index, ordinal) => encodeMinimalDataPush((require(index instanceof Uint8Array, `rawIndices[${ordinal}] must be bytes`), index)))),
    ...rawValues.map((value, ordinal) => encodeMinimalDataPush((require(value instanceof Uint8Array, `rawValues[${ordinal}] must be bytes`), value))),
    encodeMinimalDataPush(concat(...fixture.frontier.map((hash, ordinal) => {
      require(hash instanceof Uint8Array, `frontier[${ordinal}] must be bytes`);
      return hash;
    }))),
  );
};

export const createBchM31Multiproof4Fixture = ({ values, indices }) => {
  require(Array.isArray(values) && isPowerOfTwo(values.length), 'Merkle values must have supported positive power-of-two length');
  values.forEach((value, ordinal) => assertM31(value, `values[${ordinal}]`));
  assertIndexQuad(indices, values.length);
  const tree = buildM31MerkleTree(values);
  const opening = openM31MerkleMulti(tree, indices);
  return Object.freeze({
    kind: FIXTURE_KIND,
    canonicalBottomUpFrontier: true,
    length: tree.length,
    indices: Object.freeze(opening.indices.slice()),
    values: Object.freeze(opening.indices.map((index) => values[index])),
    root: new Uint8Array(tree.root),
    frontier: Object.freeze(opening.siblings.map((hash) => new Uint8Array(hash))),
  });
};

export const materializeBchM31Multiproof4P2sh32 = (fixture) => {
  const redeemBytecode = buildBchM31Multiproof4RedeemBytecode(fixture);
  const operandUnlockingBytecode = buildBchM31Multiproof4OperandUnlockingBytecode(fixture);
  const lockingBytecode = encodeLockingBytecodeP2sh32(hash256(redeemBytecode));
  return Object.freeze({
    ...fixture,
    redeemBytecode,
    operandUnlockingBytecode,
    lockingBytecode,
    unlockingBytecode: concat(operandUnlockingBytecode, encodeMinimalDataPush(redeemBytecode)),
  });
};

export const evaluateBchM31Multiproof4P2sh32 = (fixture) => evaluateScriptFixture(
  materializeBchM31Multiproof4P2sh32(fixture),
);

export const isBchM31Multiproof4Root = (fixture, root) => root instanceof Uint8Array
  && root.length === HASH_BYTES
  && equalBytes(fixture.root, root);

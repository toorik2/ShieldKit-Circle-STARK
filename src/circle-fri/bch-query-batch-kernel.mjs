/**
 * BCH-2026 P2SH32 lowering for one canonical Circle-FRI q2 witness.
 *
 * Each unlocking bytecode is exactly three pushes: the public transcript
 * digest, the unchanged q2 witness codec, and this fixed-parameter redeem.
 * Consecutive identical P2SH32 inputs cover the public schedule in aligned
 * q2 batches. The redeem derives every public query index, selects the active
 * pair from OP_INPUTINDEX, and binds the public transcript digest across
 * every input bytecode.
 */

import {
  binToHex,
  createVirtualMachineBch2026,
  encodeLockingBytecodeP2sh32,
  encodeTransaction,
  encodeTransactionOutputs,
  hash256,
} from '@bitauth/libauth';

import {
  encodeM31,
  rawMetricProjection,
} from '../../research-lanes/bch-shielded-pool-design/p2/bch-kernels/m31-kernel.mjs';

import {
  isCm31,
} from './cm31.mjs';

import {
  M31_MODULUS,
} from '../../research-lanes/bch-shielded-pool-design/p2/reference/m31.mjs';

import {
  CM31_MERKLE_LEAF_DOMAIN,
  M31_MERKLE_LEAF_DOMAIN,
  M31_MERKLE_NODE_DOMAIN,
} from './commitment.mjs';

import {
  buildBchM31Multiproof4VerificationBytecode,
} from './bch-multiproof4-kernel.mjs';

import {
  CIRCLE_FRI_DIMENSION_GAP_LAMBDA_LABEL,
  CIRCLE_FRI_MERKLE_STRIDE,
  CIRCLE_FRI_QUERY_CANDIDATE_LABEL,
  assertCircleFriParameters,
  circleFriUsesCm31Fold,
  circleFriUsesFourToOne,
  encodeCircleFriDimensionGapLambda,
  encodeCircleFriParameters,
} from './query-proof.mjs';

import {
  QUERY_BATCH_WITNESS_VERSION,
  encodeCircleFriQ2BatchWitness,
  verifyCircleFriQ2BatchWitness,
} from './query-batch-witness.mjs';

import {
  CIRCLE_FRI_SQUEEZE_DOMAIN,
  CIRCLE_FRI_TRANSCRIPT_DOMAIN,
  absorbCircleFriTranscriptState,
  initializeCircleFriTranscriptState,
  sampleCircleFriTranscriptCm31,
  sampleCircleFriTranscriptState,
} from './transcript.mjs';

import {
  CIRCLE_FRI_TOPOLOGY_LEAF_DOMAIN,
  buildCircleFriTopologyTable,
  clusteredTopologyRoot,
  circleFriCodecTopologyRecordBytes,
  circleFriTopologyRecordBytes,
} from './topology-table.mjs';

import {
  equalBytes,
  frameBytes,
  sha256,
  u16le,
  u32le,
  utf8,
} from './bytes.mjs';

const BATCH_SIZE = 2;
const ZERO_BYTE = Uint8Array.of(0);

const assertEvenPublicQueryCount = (parameters) => {
  require(
    Number.isSafeInteger(parameters.queryCount)
      && parameters.queryCount >= BATCH_SIZE
      && parameters.queryCount % BATCH_SIZE === 0,
    'q2 batch kernel requires an even public queryCount of at least 2',
  );
  return parameters.queryCount;
};

const publicBatchCount = (parameters) => assertEvenPublicQueryCount(parameters) / BATCH_SIZE;
const TWO_TO_32 = 0x1_0000_0000;
const HALF = (M31_MODULUS + 1n) / 2n;

const OP = Object.freeze({
  OP_0: 0x00,
  OP_1: 0x51,
  OP_2: 0x52,
  OP_4: 0x54,
  OP_8: 0x58,
  OP_INPUTINDEX: 0xc0,
  OP_TXINPUTCOUNT: 0xc3,
  OP_INPUTBYTECODE: 0xca,
  OP_IF: 0x63,
  OP_BEGIN: 0x65,
  OP_UNTIL: 0x66,
  OP_ELSE: 0x67,
  OP_ENDIF: 0x68,
  OP_VERIFY: 0x69,
  OP_TOALTSTACK: 0x6b,
  OP_FROMALTSTACK: 0x6c,
  OP_2DROP: 0x6d,
  OP_2DUP: 0x6e,
  OP_2OVER: 0x70,
  OP_2SWAP: 0x72,
  OP_DEPTH: 0x74,
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
  OP_EQUALVERIFY: 0x88,
  OP_DEFINE: 0x89,
  OP_INVOKE: 0x8a,
  OP_NOT: 0x91,
  OP_1ADD: 0x8b,
  OP_1SUB: 0x8c,
  OP_ADD: 0x93,
  OP_SUB: 0x94,
  OP_MUL: 0x95,
  OP_DIV: 0x96,
  OP_MOD: 0x97,
  OP_BOOLAND: 0x9a,
  OP_NUMEQUAL: 0x9c,
  OP_NUMEQUALVERIFY: 0x9d,
  OP_NUMNOTEQUAL: 0x9e,
  OP_LESSTHAN: 0x9f,
  OP_GREATERTHAN: 0xa0,
  OP_GREATERTHANOREQUAL: 0xa2,
  OP_MIN: 0xa3,
  OP_MAX: 0xa4,
  OP_WITHIN: 0xa5,
  OP_SHA256: 0xa8,
  OP_HASH256: 0xaa,
});

const FUNCTION = Object.freeze({
  HASH_NODE: 1,
  DECODE_M31: 2,
  FOLD_M31: 3,
  SAMPLE_TRANSCRIPT: 4,
  SAMPLE_M31_TRANSCRIPT: 5,
  HASH_M31_LEAF: 6,
  LOOKUP4: 7,
  MULTIPROOF4: 8,
  HASHED_MULTIPROOF2: 9,
  HASHED_MULTIPROOF4: 22,
  VERIFY_CLUSTER: 23,
  TRANSCRIPT_UNIQUE: 24,
  VERIFY_AIR_LDE: 25,
  SORT4: 10,
  VERIFY_LAYER: 11,
  VERIFY_LAYER2: 12,
  TRANSCRIPT_LAYER: 13,
  VERIFY_FULL_LAYER: 14,
  PACK_LATER_PLAN: 15,
  FOLD_AFTER_MERKLE: 16,
  HASH_CM31_LEAF: 17,
  FOLD_M31_TO_CM31: 18,
  FOLD_CM31: 19,
  M31_REDUCE: 20,
  M31_WRAP_SUB: 21,
});

const require = (condition, message) => {
  if (!condition) throw new TypeError(message);
};

const concat = (...parts) => {
  const length = parts.reduce((sum, part) => {
    require(part instanceof Uint8Array, 'bytecode parts must be Uint8Array values');
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
  if (value.length <= 0xffff) {
    return concat(Uint8Array.of(0x4d, value.length & 0xff, value.length >>> 8), value);
  }
  throw new TypeError('push exceeds OP_PUSHDATA2 capacity');
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

const pushFunctionId = (identifier) => {
  require(Number.isSafeInteger(identifier) && identifier >= 1, 'function identifier is out of range');
  if (identifier <= 16) return Uint8Array.of(0x50 + identifier);
  return pushNumber(identifier);
};

const defineFunction = (identifier, bytecode) => concat(
  encodeMinimalDataPush(bytecode),
  pushFunctionId(identifier),
  Uint8Array.of(OP.OP_DEFINE),
);

const invokeFunction = (identifier) => [
  ...pushFunctionId(identifier),
  OP.OP_INVOKE,
];

const compileScript = (script, name = 'compiled script') => {
  require(Array.isArray(script), `${name} must be an array`);
  require(
    script.every((byte) => Number.isInteger(byte) && byte >= 0 && byte <= 0xff),
    `${name} contains an invalid or undefined byte`,
  );
  return Uint8Array.from(script);
};

const extractTopBytes = (offset, length) => [
  ...(offset === 0 ? [] : [
    ...pushNumber(offset),
    OP.OP_SPLIT,
    OP.OP_SWAP,
    OP.OP_DROP,
  ]),
  ...pushNumber(length),
  OP.OP_SPLIT,
  OP.OP_DROP,
];

/** TOS re, im (im on top) → 8-byte re||im blob. */
const packCm31Top = () => [
  ...pushNumber(4),
  OP.OP_NUM2BIN,
  OP.OP_TOALTSTACK,
  ...pushNumber(4),
  OP.OP_NUM2BIN,
  OP.OP_FROMALTSTACK,
  OP.OP_CAT,
];

/** TOS 8-byte re||im blob → re, im scriptnums (im on top).
 * Limbs are Merkle-authenticated canonical 4-byte encodings, or NUM2BIN of
 * an already-reduced SAMPLE_M31, so BIN2NUM is enough. */
const unpackCm31Blob = () => [
  ...pushNumber(4),
  OP.OP_SPLIT,
  OP.OP_TOALTSTACK,
  OP.OP_BIN2NUM,
  OP.OP_FROMALTSTACK,
  OP.OP_BIN2NUM,
];

/** Indices and u16 counts fit in a positive ScriptNum; CAT-0 is not required. */
const decodeUnsignedTop = () => [
  OP.OP_BIN2NUM,
];

const framePrefix = (label, payloadLength) => {
  const labelBytes = utf8(label);
  return concat(u16le(labelBytes.length), labelBytes, u32le(payloadLength));
};

const AIR_ROW_LEAF_DOMAIN = utf8('poseidon2-air-row-v1\0');
const AIR_LDE_SIBLING_COUNT = 14;
const AIR_LDE_LEAF_BYTES = 16 * 4;
const AIR_LDE_OPENING_BYTES = 2 + AIR_LDE_LEAF_BYTES + AIR_LDE_SIBLING_COUNT * 32;

/** TOS blob: u16le index || 64-byte AIR LDE row || 14×32 siblings. Baked LDE root. */
const buildVerifyAirLdeFunction = (root) => compileScript([
  ...pushNumber(2),
  OP.OP_SPLIT,
  OP.OP_SWAP,
  OP.OP_BIN2NUM,
  OP.OP_SWAP,
  ...pushNumber(AIR_LDE_LEAF_BYTES),
  OP.OP_SPLIT,
  OP.OP_SWAP,
  ...encodeMinimalDataPush(AIR_ROW_LEAF_DOMAIN),
  OP.OP_SWAP,
  OP.OP_CAT,
  OP.OP_HASH256,
  ...pushNumber(AIR_LDE_SIBLING_COUNT),
  OP.OP_TOALTSTACK,
  OP.OP_BEGIN,
  OP.OP_FROMALTSTACK,
  OP.OP_DUP,
  OP.OP_NOT,
  OP.OP_IF,
  OP.OP_DROP,
  OP.OP_1,
  OP.OP_ELSE,
  OP.OP_1SUB,
  OP.OP_TOALTSTACK,
  ...pushNumber(2),
  OP.OP_PICK,
  OP.OP_2,
  OP.OP_MOD,
  OP.OP_TOALTSTACK,
  OP.OP_TOALTSTACK,
  ...pushNumber(32),
  OP.OP_SPLIT,
  OP.OP_SWAP,
  OP.OP_FROMALTSTACK,
  OP.OP_SWAP,
  OP.OP_FROMALTSTACK,
  OP.OP_IF,
  OP.OP_SWAP,
  OP.OP_ENDIF,
  OP.OP_CAT,
  ...encodeMinimalDataPush(M31_MERKLE_NODE_DOMAIN),
  OP.OP_SWAP,
  OP.OP_CAT,
  OP.OP_HASH256,
  OP.OP_ROT,
  OP.OP_2,
  OP.OP_DIV,
  OP.OP_ROT,
  OP.OP_ROT,
  OP.OP_0,
  OP.OP_ENDIF,
  OP.OP_UNTIL,
  ...encodeMinimalDataPush(root),
  OP.OP_EQUALVERIFY,
  OP.OP_DROP,
  OP.OP_DROP,
], 'verify AIR note-squeeze LDE opening');

const HASH_NODE_FUNCTION = compileScript([
  OP.OP_CAT,
  ...encodeMinimalDataPush(M31_MERKLE_NODE_DOMAIN),
  OP.OP_SWAP,
  OP.OP_CAT,
  OP.OP_HASH256,
], 'hash-node function');

const HASH_M31_LEAF_FUNCTION = compileScript([
  ...encodeMinimalDataPush(M31_MERKLE_LEAF_DOMAIN),
  OP.OP_SWAP,
  OP.OP_CAT,
  OP.OP_HASH256,
], 'hash-M31-leaf function');

const HASH_CM31_LEAF_FUNCTION = compileScript([
  ...encodeMinimalDataPush(CM31_MERKLE_LEAF_DOMAIN),
  OP.OP_SWAP,
  OP.OP_CAT,
  OP.OP_HASH256,
], 'hash-CM31-leaf function');

const m31Reduce = () => [
  ...pushNumber(M31_MODULUS),
  OP.OP_MOD,
];

const m31WrapSub = () => [
  ...pushNumber(M31_MODULUS),
  OP.OP_ADD,
  ...pushNumber(M31_MODULUS),
  OP.OP_MOD,
];

const M31_REDUCE_FUNCTION = compileScript(m31Reduce(), 'm31 reduce');
const M31_WRAP_SUB_FUNCTION = compileScript(m31WrapSub(), 'm31 wrap-sub');
const invokeM31Reduce = () => invokeFunction(FUNCTION.FOLD_M31);
const invokeM31WrapSub = () => invokeFunction(FUNCTION.M31_WRAP_SUB);

/**
 * Input bottom→top: left, right, inv(2x), beta_re, beta_im.
 * Output bottom→top: out_re, out_im.
 * even+βre·odd over M31, out_im = βim·odd. Matches foldPairCm31 on M31 leaves.
 */
const FOLD_M31_TO_CM31_FUNCTION = compileScript([
  OP.OP_TOALTSTACK,
  OP.OP_TOALTSTACK,
  OP.OP_TOALTSTACK,
  OP.OP_2DUP,
  OP.OP_ADD,
  ...pushNumber(HALF),
  OP.OP_MUL,
  ...invokeM31Reduce(),
  OP.OP_TOALTSTACK,
  OP.OP_SUB,
  ...m31WrapSub(),
  OP.OP_FROMALTSTACK,
  OP.OP_FROMALTSTACK,
  OP.OP_ROT,
  OP.OP_MUL,
  ...invokeM31Reduce(),
  OP.OP_FROMALTSTACK,
  OP.OP_OVER,
  OP.OP_MUL,
  ...invokeM31Reduce(),
  OP.OP_ROT,
  OP.OP_ADD,
  ...invokeM31Reduce(),
  OP.OP_SWAP,
  OP.OP_FROMALTSTACK,
  OP.OP_MUL,
  ...invokeM31Reduce(),
], 'fold-M31-to-CM31 function');

/**
 * Input bottom→top: lre, lim, rre, rim, inv(2x), beta_re, beta_im.
 * Output bottom→top: out_re, out_im.
 * Matches foldPairCm31 on CM31 leaves.
 */
const FOLD_CM31_FUNCTION = compileScript([
  OP.OP_TOALTSTACK,
  OP.OP_TOALTSTACK,
  ...pushNumber(4),
  OP.OP_PICK,
  ...pushNumber(3),
  OP.OP_PICK,
  OP.OP_ADD,
  ...pushNumber(HALF),
  OP.OP_MUL,
  ...m31Reduce(),
  OP.OP_TOALTSTACK,
  ...pushNumber(3),
  OP.OP_PICK,
  ...pushNumber(2),
  OP.OP_PICK,
  OP.OP_ADD,
  ...pushNumber(HALF),
  OP.OP_MUL,
  ...m31Reduce(),
  OP.OP_TOALTSTACK,
  ...pushNumber(4),
  OP.OP_PICK,
  ...pushNumber(3),
  OP.OP_PICK,
  OP.OP_SUB,
  ...m31WrapSub(),
  OP.OP_OVER,
  OP.OP_MUL,
  ...m31Reduce(),
  OP.OP_TOALTSTACK,
  ...pushNumber(3),
  OP.OP_PICK,
  ...pushNumber(2),
  OP.OP_PICK,
  OP.OP_SUB,
  ...m31WrapSub(),
  OP.OP_OVER,
  OP.OP_MUL,
  ...m31Reduce(),
  OP.OP_NIP,
  OP.OP_NIP,
  OP.OP_NIP,
  OP.OP_NIP,
  OP.OP_NIP,
  OP.OP_FROMALTSTACK,
  OP.OP_FROMALTSTACK,
  OP.OP_FROMALTSTACK,
  OP.OP_FROMALTSTACK,
  OP.OP_FROMALTSTACK,
  OP.OP_OVER,
  ...pushNumber(5),
  OP.OP_PICK,
  OP.OP_MUL,
  ...m31Reduce(),
  ...pushNumber(3),
  OP.OP_PICK,
  OP.OP_ADD,
  ...m31Reduce(),
  OP.OP_OVER,
  ...pushNumber(7),
  OP.OP_PICK,
  OP.OP_MUL,
  ...m31Reduce(),
  OP.OP_SUB,
  ...m31WrapSub(),
  OP.OP_TOALTSTACK,
  OP.OP_OVER,
  ...pushNumber(6),
  OP.OP_PICK,
  OP.OP_MUL,
  ...m31Reduce(),
  ...pushNumber(4),
  OP.OP_PICK,
  OP.OP_ADD,
  ...m31Reduce(),
  OP.OP_OVER,
  ...pushNumber(6),
  OP.OP_PICK,
  OP.OP_MUL,
  ...m31Reduce(),
  OP.OP_ADD,
  ...m31Reduce(),
  OP.OP_NIP,
  OP.OP_NIP,
  OP.OP_NIP,
  OP.OP_NIP,
  OP.OP_NIP,
  OP.OP_NIP,
  OP.OP_FROMALTSTACK,
  OP.OP_SWAP,
], 'fold-CM31 function');

const DECODE_M31_FUNCTION = compileScript([
  OP.OP_BIN2NUM,
  OP.OP_DUP,
  ...pushNumber(M31_MODULUS),
  OP.OP_LESSTHAN,
  OP.OP_VERIFY,
], 'decode-M31 function');

const FOLD_M31_FUNCTION = compileScript([
  // Input: left, right, inverse(2*x), beta.
  OP.OP_TOALTSTACK,
  OP.OP_TOALTSTACK,
  OP.OP_2DUP,
  OP.OP_ADD,
  ...pushNumber(HALF),
  OP.OP_MUL,
  ...pushNumber(M31_MODULUS),
  OP.OP_MOD,
  OP.OP_TOALTSTACK,
  OP.OP_SUB,
  ...pushNumber(M31_MODULUS),
  OP.OP_ADD,
  ...pushNumber(M31_MODULUS),
  OP.OP_MOD,
  OP.OP_FROMALTSTACK,
  OP.OP_FROMALTSTACK,
  OP.OP_ROT,
  OP.OP_MUL,
  OP.OP_FROMALTSTACK,
  OP.OP_MUL,
  ...pushNumber(M31_MODULUS),
  OP.OP_MOD,
  OP.OP_ADD,
  ...pushNumber(M31_MODULUS),
  OP.OP_MOD,
], 'fold-M31 function');

const buildTranscriptCandidate = () => [
  OP.OP_DUP,
  ...pushNumber(4),
  OP.OP_SPLIT,
  OP.OP_DROP,
  ...encodeMinimalDataPush(ZERO_BYTE),
  OP.OP_CAT,
  OP.OP_BIN2NUM,
];

const SAMPLE_TRANSCRIPT_FUNCTION = compileScript([
  // Input: state, drawPrefix, labelFrame, upperBound, acceptanceBound, attempt.
  OP.OP_BEGIN,
  ...pushNumber(5),
  OP.OP_PICK,
  ...encodeMinimalDataPush(CIRCLE_FRI_SQUEEZE_DOMAIN),
  OP.OP_SWAP,
  OP.OP_CAT,
  ...pushNumber(5),
  OP.OP_PICK,
  OP.OP_CAT,
  OP.OP_OVER,
  ...pushNumber(4),
  OP.OP_NUM2BIN,
  OP.OP_CAT,
  OP.OP_SHA256,
  ...buildTranscriptCandidate(),
  OP.OP_DUP,
  ...pushNumber(4),
  OP.OP_PICK,
  OP.OP_LESSTHAN,
  OP.OP_IF,
  OP.OP_DUP,
  ...pushNumber(5),
  OP.OP_PICK,
  OP.OP_MOD,
  OP.OP_TOALTSTACK,
  OP.OP_DROP,
  ...pushNumber(6),
  OP.OP_PICK,
  ...pushNumber(5),
  OP.OP_PICK,
  OP.OP_CAT,
  ...encodeMinimalDataPush(framePrefix('accepted-challenge-digest', 32)),
  OP.OP_CAT,
  OP.OP_OVER,
  OP.OP_CAT,
  ...encodeMinimalDataPush(framePrefix('accepted-challenge-attempt', 4)),
  OP.OP_CAT,
  ...pushNumber(2),
  OP.OP_PICK,
  ...pushNumber(4),
  OP.OP_NUM2BIN,
  OP.OP_CAT,
  OP.OP_SHA256,
  OP.OP_TOALTSTACK,
  OP.OP_2DROP,
  OP.OP_2DROP,
  OP.OP_2DROP,
  OP.OP_DROP,
  OP.OP_FROMALTSTACK,
  OP.OP_FROMALTSTACK,
  OP.OP_1,
  OP.OP_ELSE,
  OP.OP_2DROP,
  OP.OP_1ADD,
  OP.OP_0,
  OP.OP_ENDIF,
  OP.OP_UNTIL,
], 'sample-transcript function');

const SAMPLE_M31_TRANSCRIPT_FUNCTION = compileScript([
  ...pushNumber(M31_MODULUS),
  ...pushNumber(Number(M31_MODULUS) * 2),
  OP.OP_0,
  ...invokeFunction(FUNCTION.SAMPLE_TRANSCRIPT),
], 'sample-M31-transcript function');

const compareExchangeTop = () => [
  OP.OP_2DUP,
  OP.OP_MAX,
  OP.OP_TOALTSTACK,
  OP.OP_MIN,
  OP.OP_FROMALTSTACK,
];

const SORT4_FUNCTION = compileScript([
  // Sorting network: (0,1),(2,3),(0,2),(1,3),(1,2).
  ...compareExchangeTop(),
  OP.OP_2SWAP,
  ...compareExchangeTop(),
  OP.OP_2SWAP,
  OP.OP_TOALTSTACK,
  OP.OP_1,
  OP.OP_ROLL,
  OP.OP_TOALTSTACK,
  ...compareExchangeTop(),
  OP.OP_FROMALTSTACK,
  OP.OP_SWAP,
  OP.OP_FROMALTSTACK,
  OP.OP_1,
  OP.OP_ROLL,
  OP.OP_TOALTSTACK,
  ...compareExchangeTop(),
  OP.OP_FROMALTSTACK,
  OP.OP_SWAP,
  OP.OP_TOALTSTACK,
  ...compareExchangeTop(),
  OP.OP_FROMALTSTACK,
], 'sort4 function');

const buildLookup4Function = () => {
  const script = [];
  for (let slot = 0; slot < 4; slot += 1) {
    script.push(
      OP.OP_DUP,
      ...pushNumber(3),
      OP.OP_PICK,
      ...extractTopBytes(slot * 4, 4),
      ...decodeUnsignedTop(),
      OP.OP_NUMEQUAL,
      OP.OP_IF,
      OP.OP_DROP,
      OP.OP_DUP,
      ...extractTopBytes(slot * 4, 4),
      OP.OP_TOALTSTACK,
      OP.OP_2DROP,
      OP.OP_FROMALTSTACK,
      OP.OP_ELSE,
    );
  }
  script.push(OP.OP_0, OP.OP_VERIFY);
  for (let slot = 0; slot < 4; slot += 1) script.push(OP.OP_ENDIF);
  return compileScript(script, 'lookup4 function');
};

const LOOKUP4_FUNCTION = buildLookup4Function();

const buildTranscriptInitialization = ({ protocolContext, parameters }) => [
  ...encodeMinimalDataPush(concat(
    CIRCLE_FRI_TRANSCRIPT_DOMAIN,
    frameBytes('context', protocolContext),
  )),
  OP.OP_SHA256,
  ...encodeMinimalDataPush(frameBytes('fri-parameters', encodeCircleFriParameters(parameters))),
  OP.OP_CAT,
  OP.OP_SHA256,
  ...encodeMinimalDataPush(frameBytes(
    CIRCLE_FRI_DIMENSION_GAP_LAMBDA_LABEL,
    encodeCircleFriDimensionGapLambda(),
  )),
  OP.OP_CAT,
  OP.OP_SHA256,
];

const buildTranscriptAbsorbRuntime = (label, payloadLength) => [
  OP.OP_SIZE,
  ...pushNumber(payloadLength),
  OP.OP_NUMEQUALVERIFY,
  ...encodeMinimalDataPush(framePrefix(label, payloadLength)),
  OP.OP_SWAP,
  OP.OP_CAT,
  OP.OP_CAT,
  OP.OP_SHA256,
];

const buildTranscriptChallenge = ({ label, upperBound }) => {
  const acceptanceBound = Math.floor(TWO_TO_32 / upperBound) * upperBound;
  return [
    ...encodeMinimalDataPush(concat(
      frameBytes('label', utf8(label)),
      framePrefix('attempt', 4),
    )),
    ...encodeMinimalDataPush(frameBytes('accepted-challenge-label', utf8(label))),
    ...(upperBound === Number(M31_MODULUS)
      ? invokeFunction(FUNCTION.SAMPLE_M31_TRANSCRIPT)
      : [
          ...pushNumber(upperBound),
          ...pushNumber(acceptanceBound),
          OP.OP_0,
          ...invokeFunction(FUNCTION.SAMPLE_TRANSCRIPT),
        ]),
  ];
};

const hashFrontierStep2 = () => [
  OP.OP_DUP,
  OP.OP_2,
  OP.OP_MOD,
  OP.OP_IF,
  OP.OP_TOALTSTACK,
  OP.OP_SWAP,
  ...invokeFunction(FUNCTION.HASH_NODE),
  OP.OP_FROMALTSTACK,
  OP.OP_2,
  OP.OP_DIV,
  OP.OP_ELSE,
  OP.OP_TOALTSTACK,
  ...invokeFunction(FUNCTION.HASH_NODE),
  OP.OP_FROMALTSTACK,
  OP.OP_2,
  OP.OP_DIV,
  OP.OP_ENDIF,
];

const popFrontierAndHashStep2 = () => [
  OP.OP_ROT,
  ...pushNumber(32),
  OP.OP_SPLIT,
  OP.OP_TOALTSTACK,
  OP.OP_SWAP,
  ...hashFrontierStep2(),
  OP.OP_FROMALTSTACK,
];

const orderedSiblingPredicate2 = () => [
  OP.OP_OVER,
  OP.OP_2,
  OP.OP_MOD,
  OP.OP_0,
  OP.OP_NUMEQUAL,
  OP.OP_TOALTSTACK,
  OP.OP_SWAP,
  OP.OP_1ADD,
  OP.OP_NUMEQUAL,
  OP.OP_FROMALTSTACK,
  OP.OP_BOOLAND,
];

const currentIndicesAreSiblings2 = () => [
  ...pushNumber(3),
  OP.OP_PICK,
  ...pushNumber(2),
  OP.OP_PICK,
  ...orderedSiblingPredicate2(),
];

/** TOS: domain min, max (max on top) → 2*min, 2*min+1 Merkle pair. */
const domainPairToMerklePair = () => [
  OP.OP_DROP,
  OP.OP_DUP,
  OP.OP_ADD,
  OP.OP_DUP,
  OP.OP_1ADD,
];

const stepBothPaths2 = () => [
  ...pushNumber(4),
  OP.OP_ROLL,
  ...pushNumber(4),
  OP.OP_ROLL,
  ...popFrontierAndHashStep2(),
  ...pushNumber(4),
  OP.OP_ROLL,
  ...pushNumber(4),
  OP.OP_ROLL,
  ...popFrontierAndHashStep2(),
];

/** Runtime ABI: treeLength, root, i0, i1, hash0, hash1, packedFrontier. */
const HASHED_MULTIPROOF2_FUNCTION = compileScript([
  ...pushNumber(6),
  OP.OP_ROLL,
  OP.OP_TOALTSTACK,
  ...pushNumber(4),
  OP.OP_PICK,
  OP.OP_FROMALTSTACK,
  OP.OP_DUP,
  OP.OP_TOALTSTACK,
  OP.OP_LESSTHAN,
  OP.OP_VERIFY,
  ...pushNumber(3),
  OP.OP_PICK,
  OP.OP_FROMALTSTACK,
  OP.OP_DUP,
  OP.OP_TOALTSTACK,
  OP.OP_LESSTHAN,
  OP.OP_VERIFY,

  // Reorder root,i0,i1,h0,h1,frontier to root,h0,i0,h1,i1,frontier.
  OP.OP_TOALTSTACK,
  ...pushNumber(2),
  OP.OP_ROLL,
  OP.OP_TOALTSTACK,
  OP.OP_TOALTSTACK,
  OP.OP_SWAP,
  OP.OP_TOALTSTACK,
  OP.OP_TOALTSTACK,
  OP.OP_FROMALTSTACK,
  OP.OP_FROMALTSTACK,
  OP.OP_FROMALTSTACK,
  OP.OP_FROMALTSTACK,
  OP.OP_FROMALTSTACK,

  // π-pair leaves are (2p, 2p+1) siblings. A forged non-adjacent pair
  // hashes to the wrong parent and fails the root check below.
  ...pushNumber(4),
  OP.OP_ROLL,
  ...pushNumber(3),
  OP.OP_ROLL,
  ...invokeFunction(FUNCTION.HASH_NODE),
  ...pushNumber(3),
  OP.OP_ROLL,
  OP.OP_2,
  OP.OP_DIV,
  ...pushNumber(3),
  OP.OP_ROLL,
  OP.OP_DROP,
  ...pushNumber(2),
  OP.OP_ROLL,
  OP.OP_FROMALTSTACK,
  OP.OP_2,
  OP.OP_DIV,
  OP.OP_DUP,
  OP.OP_TOALTSTACK,
  OP.OP_1,
  OP.OP_NUMEQUAL,
  OP.OP_IF,
  OP.OP_ELSE,
  OP.OP_BEGIN,
  ...pushNumber(32),
  OP.OP_SPLIT,
  OP.OP_TOALTSTACK,
  OP.OP_SWAP,
  ...hashFrontierStep2(),
  OP.OP_FROMALTSTACK,
  OP.OP_FROMALTSTACK,
  OP.OP_2,
  OP.OP_DIV,
  OP.OP_DUP,
  OP.OP_TOALTSTACK,
  OP.OP_1,
  OP.OP_NUMEQUAL,
  OP.OP_UNTIL,
  OP.OP_ENDIF,
  OP.OP_FROMALTSTACK,
  OP.OP_1,
  OP.OP_NUMEQUALVERIFY,
  OP.OP_SIZE,
  OP.OP_0,
  OP.OP_NUMEQUALVERIFY,
  OP.OP_DROP,
  OP.OP_0,
  OP.OP_NUMEQUALVERIFY,
  OP.OP_EQUAL,
], 'dynamic hashed two-leaf multiproof function');

const buildCommonFunctionDefinitions = ({ cm31 = false } = {}) => concat(
  defineFunction(FUNCTION.HASH_NODE, HASH_NODE_FUNCTION),
  defineFunction(FUNCTION.DECODE_M31, DECODE_M31_FUNCTION),
  ...(cm31
    ? [defineFunction(FUNCTION.FOLD_M31, M31_REDUCE_FUNCTION)]
    : [defineFunction(FUNCTION.FOLD_M31, FOLD_M31_FUNCTION)]),
  defineFunction(FUNCTION.SAMPLE_TRANSCRIPT, SAMPLE_TRANSCRIPT_FUNCTION),
  defineFunction(FUNCTION.SAMPLE_M31_TRANSCRIPT, SAMPLE_M31_TRANSCRIPT_FUNCTION),
  defineFunction(FUNCTION.HASH_M31_LEAF, HASH_M31_LEAF_FUNCTION),
  defineFunction(FUNCTION.LOOKUP4, LOOKUP4_FUNCTION),
  defineFunction(FUNCTION.MULTIPROOF4, buildBchM31Multiproof4VerificationBytecode()),
  defineFunction(FUNCTION.HASHED_MULTIPROOF2, HASHED_MULTIPROOF2_FUNCTION),
  defineFunction(FUNCTION.SORT4, SORT4_FUNCTION),
);

const FUNCTION_DEFINITIONS = buildCommonFunctionDefinitions();

const encodeFinalCodeword = (values) => concat(...values.map((value) => (
  isCm31(value) ? concat(encodeM31(value.re), encodeM31(value.im)) : encodeM31(value)
)));

const derivePublicProofDigest = ({ witness, parameters, protocolContext }) => {
  let state = initializeCircleFriTranscriptState(protocolContext);
  state = absorbCircleFriTranscriptState(state, 'fri-parameters', encodeCircleFriParameters(parameters));
  state = absorbCircleFriTranscriptState(
    state,
    CIRCLE_FRI_DIMENSION_GAP_LAMBDA_LABEL,
    encodeCircleFriDimensionGapLambda(),
  );
  for (let round = 0; round < parameters.logDegreeBound; round += 1) {
    state = absorbCircleFriTranscriptState(state, `fri-layer-root-${round}`, witness.roots[round]);
    if (circleFriUsesCm31Fold(parameters)) {
      state = sampleCircleFriTranscriptCm31({
        state,
        label: `fri-fold-beta-${round}`,
      }).state;
    } else {
      state = sampleCircleFriTranscriptState({
        state,
        label: `fri-fold-beta-${round}`,
        upperBound: Number(M31_MODULUS),
      }).state;
    }
  }
  return absorbCircleFriTranscriptState(
    state,
    'fri-final-codeword',
    encodeFinalCodeword(witness.finalCodeword),
  );
};

/** Validate and freeze one exact q2 operand for the public query schedule. */
export const createBchCircleFriQ2BatchFixture = ({
  witness,
  expected,
  protocolContext = new Uint8Array(),
  airLdeOpening = null,
  airLdeRoot = null,
  airNoteFelts = null,
}) => {
  const parameters = assertCircleFriParameters(expected);
  const batchCount = publicBatchCount(parameters);
  require(witness !== null && typeof witness === 'object', 'q2 witness is required');
  require(
    Array.isArray(witness.queryOrdinals)
      && witness.queryOrdinals.length === BATCH_SIZE
      && witness.queryOrdinals[0] % BATCH_SIZE === 0
      && witness.queryOrdinals[1] === witness.queryOrdinals[0] + 1,
    'q2 witness must cover one aligned consecutive query batch',
  );
  const batchOrdinal = witness.queryOrdinals[0] / BATCH_SIZE;
  require(
    Number.isInteger(batchOrdinal) && batchOrdinal >= 0 && batchOrdinal < batchCount,
    'q2 witness batch ordinal is out of range',
  );
  const verdict = verifyCircleFriQ2BatchWitness({
    witness,
    expected: parameters,
    protocolContext,
    queryOrdinals: [batchOrdinal * BATCH_SIZE, batchOrdinal * BATCH_SIZE + 1],
  });
  require(verdict.ok, `q2 witness must verify before BCH lowering: ${verdict.reason ?? 'invalid'}`);
  const fourToOne = circleFriUsesFourToOne(parameters);
  const laterLayerOk = (layer, round) => {
    const length = parameters.domainLength / (2 ** round);
    const pairCount = fourToOne && round > 0 ? 2 : 4;
    return layer.values.length === pairCount
      || (layer.siblings.length === 0 && layer.values.length === length);
  };
  require(
    witness.layers[0]?.values.length === 4
      && witness.layers.slice(1).every((layer, index) => laterLayerOk(layer, index + 1)),
    fourToOne
      ? 'q2 4-to-1 profile requires four leaves in round 0 and two-leaf or full small later rounds'
      : 'q2 independent profile requires four leaves in every Merkle layer or a full small layer',
  );
  const topologyRoot = parameters.logDegreeBound >= 8
    ? clusteredTopologyRoot(parameters)
    : buildCircleFriTopologyTable(parameters).root;
  require(equalBytes(witness.topology.root, topologyRoot), 'q2 witness topology root is not canonical');
  const encodedWitness = encodeCircleFriQ2BatchWitness(witness);
  const publicProofDigest = derivePublicProofDigest({ witness, parameters, protocolContext });
  return Object.freeze({
    kind: 'bch-circle-fri-q2-batch-component-v1',
    proofVersion: 3,
    queryBatchSize: BATCH_SIZE,
    transactionBatchCount: batchCount,
    batchOrdinal,
    parameters,
    protocolContext: new Uint8Array(protocolContext),
    topologyRoot: new Uint8Array(topologyRoot),
    topologyRecordBytes: circleFriCodecTopologyRecordBytes(parameters),
    publicProofDigest: new Uint8Array(publicProofDigest),
    encodedWitness,
    witness,
    airLdeOpening: airLdeOpening instanceof Uint8Array ? new Uint8Array(airLdeOpening) : null,
    airLdeRoot: airLdeRoot instanceof Uint8Array ? new Uint8Array(airLdeRoot) : null,
    airNoteFelts: airNoteFelts instanceof Uint8Array ? new Uint8Array(airNoteFelts) : null,
  });
};

const assertBatchFixture = (fixture) => {
  require(fixture?.kind === 'bch-circle-fri-q2-batch-component-v1', 'q2 batch fixture is required');
  publicBatchCount(fixture.parameters);
  require(fixture.publicProofDigest instanceof Uint8Array && fixture.publicProofDigest.length === 32, 'public proof digest must be 32 bytes');
  require(fixture.encodedWitness instanceof Uint8Array, 'encoded q2 witness is required');
  return fixture;
};

const extractInputProofDigestPrefix = (inputIndex) => [
  ...pushNumber(inputIndex),
  OP.OP_INPUTBYTECODE,
  ...pushNumber(33),
  OP.OP_SPLIT,
  OP.OP_DROP,
  OP.OP_1,
  OP.OP_SPLIT,
  OP.OP_SWAP,
  ...encodeMinimalDataPush(Uint8Array.of(0x20)),
  OP.OP_EQUALVERIFY,
];

/** Second unlocking push is packed u32le query indices (after the 33-byte digest push). */
const extractPackedQueryIndicesFromInput = (inputIndex, queryCount) => {
  const packedLen = queryCount * 4;
  const prefixLen = encodeMinimalDataPush(new Uint8Array(packedLen)).length - packedLen;
  return [
    ...pushNumber(inputIndex),
    OP.OP_INPUTBYTECODE,
    ...pushNumber(33),
    OP.OP_SPLIT,
    OP.OP_NIP,
    ...pushNumber(prefixLen),
    OP.OP_SPLIT,
    OP.OP_NIP,
    ...pushNumber(packedLen),
    OP.OP_SPLIT,
    OP.OP_DROP,
  ];
};

const packedBetasLength = (parameters) => (
  parameters.logDegreeBound * (circleFriUsesCm31Fold(parameters) ? 8 : 4)
);

/** Third unlocking push is packed fold betas (after digest + packed queries). */
const extractPackedBetasFromInput = (inputIndex, queryCount, parameters) => {
  const packedLen = queryCount * 4;
  const packedPushLen = encodeMinimalDataPush(new Uint8Array(packedLen)).length;
  const betasLen = packedBetasLength(parameters);
  const prefixLen = encodeMinimalDataPush(new Uint8Array(betasLen)).length - betasLen;
  return [
    ...pushNumber(inputIndex),
    OP.OP_INPUTBYTECODE,
    ...pushNumber(33 + packedPushLen),
    OP.OP_SPLIT,
    OP.OP_NIP,
    ...pushNumber(prefixLen),
    OP.OP_SPLIT,
    OP.OP_NIP,
    ...pushNumber(betasLen),
    OP.OP_SPLIT,
    OP.OP_DROP,
  ];
};

const encodePackedBetas = (fixture) => {
  const { parameters, protocolContext, witness } = fixture;
  const cm31 = circleFriUsesCm31Fold(parameters);
  let state = initializeCircleFriTranscriptState(protocolContext);
  state = absorbCircleFriTranscriptState(state, 'fri-parameters', encodeCircleFriParameters(parameters));
  state = absorbCircleFriTranscriptState(
    state,
    CIRCLE_FRI_DIMENSION_GAP_LAMBDA_LABEL,
    encodeCircleFriDimensionGapLambda(),
  );
  const parts = [];
  for (let round = 0; round < parameters.logDegreeBound; round += 1) {
    state = absorbCircleFriTranscriptState(state, `fri-layer-root-${round}`, witness.roots[round]);
    if (cm31) {
      const sampled = sampleCircleFriTranscriptCm31({
        state,
        label: `fri-fold-beta-${round}`,
      });
      state = sampled.state;
      parts.push(encodeM31(sampled.value.re), encodeM31(sampled.value.im));
    } else {
      const sampled = sampleCircleFriTranscriptState({
        state,
        label: `fri-fold-beta-${round}`,
        upperBound: Number(M31_MODULUS),
      });
      state = sampled.state;
      parts.push(encodeM31(BigInt(sampled.value)));
    }
  }
  return concat(...parts);
};

const buildCrossInputProofDigestBinding = (batchCount) => {
  require(Number.isSafeInteger(batchCount) && batchCount >= 1, 'batchCount must be a positive integer');
  if (batchCount === 2) {
    return [
      OP.OP_TXINPUTCOUNT,
      OP.OP_2,
      OP.OP_NUMEQUALVERIFY,
      OP.OP_INPUTINDEX,
      OP.OP_0,
      OP.OP_2,
      OP.OP_WITHIN,
      OP.OP_VERIFY,
      ...[0, 1].flatMap((inputIndex) => extractInputProofDigestPrefix(inputIndex)),
      OP.OP_EQUALVERIFY,
    ];
  }
  return [
    OP.OP_TXINPUTCOUNT,
    ...pushNumber(batchCount),
    OP.OP_NUMEQUALVERIFY,
    OP.OP_INPUTINDEX,
    OP.OP_0,
    ...pushNumber(batchCount),
    OP.OP_WITHIN,
    OP.OP_VERIFY,
    OP.OP_INPUTINDEX,
    OP.OP_0,
    OP.OP_NUMEQUAL,
    OP.OP_IF,
    ...extractInputProofDigestPrefix(1),
    OP.OP_ELSE,
    ...extractInputProofDigestPrefix(0),
    OP.OP_ENDIF,
    ...pushNumber(2),
    OP.OP_PICK,
    OP.OP_EQUALVERIFY,
  ];
};

const firstFoldPairOfTop = (parameters) => [
  OP.OP_DUP,
  ...pushNumber(parameters.firstFoldPairCount),
  OP.OP_LESSTHAN,
  OP.OP_IF,
  OP.OP_ELSE,
  ...pushNumber(parameters.domainLength - 1),
  OP.OP_SWAP,
  OP.OP_SUB,
  OP.OP_ENDIF,
];

/** TOS query index → 21-byte round-0 J-plan: current||2P||2P+1||P||coord0||side0. */
const packRound0PlanFromQueryTop = (parameters) => [
  OP.OP_DUP,
  ...firstFoldPairOfTop(parameters),
  OP.OP_TOALTSTACK,
  OP.OP_FROMALTSTACK,
  OP.OP_DUP,
  OP.OP_TOALTSTACK,
  OP.OP_DUP,
  OP.OP_ADD,
  OP.OP_DUP,
  OP.OP_1ADD,
  OP.OP_FROMALTSTACK,
  ...pushNumber(4),
  OP.OP_NUM2BIN,
  OP.OP_TOALTSTACK,
  ...pushNumber(4),
  OP.OP_NUM2BIN,
  OP.OP_TOALTSTACK,
  ...pushNumber(4),
  OP.OP_NUM2BIN,
  OP.OP_TOALTSTACK,
  ...pushNumber(4),
  OP.OP_NUM2BIN,
  OP.OP_FROMALTSTACK,
  OP.OP_CAT,
  OP.OP_FROMALTSTACK,
  OP.OP_CAT,
  OP.OP_FROMALTSTACK,
  OP.OP_CAT,
  ...encodeMinimalDataPush(new Uint8Array(4)),
  OP.OP_CAT,
  OP.OP_0,
  ...pushNumber(1),
  OP.OP_NUM2BIN,
  OP.OP_CAT,
];

/** TOS 8-byte selectedQueries → plan0, plan1 (Q0 then Q1). */
const synthesizeRound0PlansFromSelected = (parameters) => [
  OP.OP_DUP,
  ...extractTopBytes(0, 4),
  ...decodeUnsignedTop(),
  ...packRound0PlanFromQueryTop(parameters),
  OP.OP_SWAP,
  ...extractTopBytes(4, 4),
  ...decodeUnsignedTop(),
  ...packRound0PlanFromQueryTop(parameters),
];

/** π-sibling of a J-pair index P on the x-line is N/2 − 1 − P. */
const fourToOnePartnerOfPairTop = (parameters) => [
  ...pushNumber(parameters.firstFoldPairCount - 1),
  OP.OP_SWAP,
  OP.OP_SUB,
];

const pushFirstFoldUniquenessFlag = (parameters, query) => {
  const script = [OP.OP_1];
  for (let prior = 0; prior < query; prior += 1) {
    script.push(
      OP.OP_OVER,
      ...firstFoldPairOfTop(parameters),
      ...pushNumber(query + 3 - prior),
      OP.OP_PICK,
      ...firstFoldPairOfTop(parameters),
      OP.OP_NUMNOTEQUAL,
      OP.OP_MUL,
    );
  }
  return script;
};

const buildCanonicalQueryDerivationAll = (parameters) => {
  const fourToOne = circleFriUsesFourToOne(parameters);
  const script = [];
  for (let query = 0; query < parameters.queryCount; query += 1) {
    if (fourToOne && query % 2 === 1) {
      script.push(
        ...pushNumber(1),
        OP.OP_PICK,
        ...firstFoldPairOfTop(parameters),
        ...fourToOnePartnerOfPairTop(parameters),
        OP.OP_1,
      );
      for (let prior = 0; prior < query; prior += 1) {
        script.push(
          ...pushNumber(1),
          OP.OP_PICK,
          ...pushNumber(query + 3 - prior),
          OP.OP_PICK,
          ...firstFoldPairOfTop(parameters),
          OP.OP_NUMNOTEQUAL,
          OP.OP_MUL,
        );
      }
      script.push(OP.OP_VERIFY);
    } else {
      if (query > 0) script.push(OP.OP_BEGIN);
      script.push(...buildTranscriptChallenge({
        label: CIRCLE_FRI_QUERY_CANDIDATE_LABEL,
        upperBound: parameters.domainLength,
      }));
      if (query > 0) {
        script.push(
          ...pushFirstFoldUniquenessFlag(parameters, query),
          OP.OP_IF,
          OP.OP_1,
          OP.OP_ELSE,
          OP.OP_DROP,
          OP.OP_0,
          OP.OP_ENDIF,
          OP.OP_UNTIL,
        );
      }
    }
    script.push(OP.OP_SWAP);
  }
  return script;
};

/** Byte length of the unrolled uniqueness schedule actually used by the q4 redeem. */
export const measureBchCircleFriQ2UnrolledQueryDerivationBytes = (parameters) => (
  compileScript(
    buildCanonicalQueryDerivationAll(assertCircleFriParameters(parameters)),
    'unrolled query derivation',
  ).length
);

/**
 * Packed uniqueness loop: same transcript and first-fold-pair rejection as
 * the unrolled q4 schedule, with redeem size independent of queryCount.
 * Input: transcript state. Output: packed u32le indices, state.
 *
 * Loop ABI: [state, packedIndices, count] and altstack [packedPairs].
 */
const packedPairSearch = (parameters) => [
  OP.OP_FROMALTSTACK,
  OP.OP_SIZE,
  OP.OP_NOT,
  OP.OP_IF,
  OP.OP_1,
  OP.OP_ELSE,
  OP.OP_DUP,
  OP.OP_BEGIN,
  OP.OP_SIZE,
  OP.OP_NOT,
  OP.OP_IF,
  OP.OP_DROP,
  OP.OP_1,
  OP.OP_1,
  OP.OP_ELSE,
  ...pushNumber(4),
  OP.OP_SPLIT,
  OP.OP_SWAP,
  ...decodeUnsignedTop(),
  OP.OP_DUP,
  ...pushNumber(4),
  OP.OP_PICK,
  OP.OP_NUMEQUAL,
  OP.OP_IF,
  OP.OP_DROP,
  OP.OP_DROP,
  OP.OP_0,
  OP.OP_1,
  OP.OP_ELSE,
  ...pushNumber(parameters.firstFoldPairCount - 1),
  OP.OP_SWAP,
  OP.OP_SUB,
  ...pushNumber(3),
  OP.OP_PICK,
  OP.OP_NUMEQUAL,
  OP.OP_IF,
  OP.OP_DROP,
  OP.OP_0,
  OP.OP_1,
  OP.OP_ELSE,
  OP.OP_0,
  OP.OP_ENDIF,
  OP.OP_ENDIF,
  OP.OP_ENDIF,
  OP.OP_UNTIL,
  OP.OP_ENDIF,
];

const packedAcceptIndex = () => [
  OP.OP_SWAP,
  ...pushNumber(4),
  OP.OP_NUM2BIN,
  OP.OP_CAT,
  OP.OP_TOALTSTACK,
  OP.OP_SWAP,
  OP.OP_TOALTSTACK,
  ...pushNumber(2),
  OP.OP_ROLL,
  OP.OP_OVER,
  ...pushNumber(4),
  OP.OP_NUM2BIN,
  OP.OP_CAT,
  OP.OP_NIP,
  OP.OP_SWAP,
  OP.OP_1ADD,
  OP.OP_FROMALTSTACK,
  ...pushNumber(2),
  OP.OP_ROLL,
  ...pushNumber(2),
  OP.OP_ROLL,
];

/** Accept the query index without appending a first-fold pair (4-to-1 partner). */
const packedAcceptIndexOnly = () => [
  OP.OP_TOALTSTACK,
  OP.OP_DROP,
  OP.OP_SWAP,
  OP.OP_TOALTSTACK,
  ...pushNumber(2),
  OP.OP_ROLL,
  OP.OP_OVER,
  ...pushNumber(4),
  OP.OP_NUM2BIN,
  OP.OP_CAT,
  OP.OP_NIP,
  OP.OP_SWAP,
  OP.OP_1ADD,
  OP.OP_FROMALTSTACK,
  ...pushNumber(2),
  OP.OP_ROLL,
  ...pushNumber(2),
  OP.OP_ROLL,
];

const packedRejectIndex = () => [
  OP.OP_TOALTSTACK,
  OP.OP_DROP,
  ...pushNumber(2),
  OP.OP_ROLL,
  ...pushNumber(2),
  OP.OP_ROLL,
];

/** TOS=offset, second=blob → TOS=u32, second=blob. Offset is a small scriptnum. */
const loadU32AtOffset = () => [
  OP.OP_OVER,
  OP.OP_SWAP,
  OP.OP_SPLIT,
  OP.OP_NIP,
  ...pushNumber(4),
  OP.OP_SPLIT,
  OP.OP_SWAP,
  OP.OP_NIP,
  ...decodeUnsignedTop(),
];

/**
 * TOS=key (scriptnum), second=sorted u32le blob.
 * Insert key at the first offset whose value is greater than key.
 * SPLIT indexes are small scriptnums (0, 4, 8, …), never a 4-byte pair encoding.
 * Fail if key is already present. Leaves the new sorted blob.
 */
const insertKeyIntoSortedU32Blob = () => [
  OP.OP_OVER,
  OP.OP_SIZE,
  OP.OP_NIP,
  OP.OP_0,
  OP.OP_BEGIN,
  OP.OP_2DUP,
  OP.OP_GREATERTHANOREQUAL,
  OP.OP_IF,
  OP.OP_2DROP,
  ...pushNumber(4),
  OP.OP_NUM2BIN,
  OP.OP_CAT,
  OP.OP_1,
  OP.OP_ELSE,
  ...pushNumber(3),
  OP.OP_PICK,
  OP.OP_OVER,
  ...loadU32AtOffset(),
  OP.OP_NIP,
  ...pushNumber(3),
  OP.OP_PICK,
  OP.OP_OVER,
  OP.OP_NUMNOTEQUAL,
  OP.OP_VERIFY,
  OP.OP_SWAP,
  OP.OP_GREATERTHAN,
  OP.OP_IF,
  OP.OP_TOALTSTACK,
  OP.OP_DROP,
  OP.OP_SWAP,
  OP.OP_FROMALTSTACK,
  OP.OP_SPLIT,
  OP.OP_TOALTSTACK,
  OP.OP_SWAP,
  ...pushNumber(4),
  OP.OP_NUM2BIN,
  OP.OP_CAT,
  OP.OP_FROMALTSTACK,
  OP.OP_CAT,
  OP.OP_1,
  OP.OP_ELSE,
  ...pushNumber(4),
  OP.OP_ADD,
  OP.OP_0,
  OP.OP_ENDIF,
  OP.OP_ENDIF,
  OP.OP_UNTIL,
];

/**
 * TOS sorted u32le blob. Fail if any two values sum to partnerSum.
 * Leaves the blob.
 */
const assertSortedU32BlobNoPartnerSum = (n, partnerSum) => {
  if (n < 2) return [];
  const lastOffset = 4 * (n - 1);
  return [
    ...pushNumber(0),
    ...pushNumber(lastOffset),
    OP.OP_BEGIN,
    OP.OP_2DUP,
    OP.OP_GREATERTHANOREQUAL,
    OP.OP_IF,
    OP.OP_2DROP,
    OP.OP_1,
    OP.OP_ELSE,
    ...pushNumber(2),
    OP.OP_PICK,
    ...pushNumber(2),
    OP.OP_PICK,
    ...loadU32AtOffset(),
    OP.OP_NIP,
    ...pushNumber(3),
    OP.OP_PICK,
    ...pushNumber(2),
    OP.OP_PICK,
    ...loadU32AtOffset(),
    OP.OP_NIP,
    OP.OP_ADD,
    OP.OP_DUP,
    ...pushNumber(partnerSum),
    OP.OP_NUMNOTEQUAL,
    OP.OP_VERIFY,
    ...pushNumber(partnerSum),
    OP.OP_LESSTHAN,
    OP.OP_IF,
    OP.OP_SWAP,
    ...pushNumber(4),
    OP.OP_ADD,
    OP.OP_SWAP,
    OP.OP_ELSE,
    ...pushNumber(4),
    OP.OP_SUB,
    OP.OP_ENDIF,
    OP.OP_0,
    OP.OP_ENDIF,
    OP.OP_UNTIL,
  ];
};

/** TOS packed u32le sample pairs → same blob, or fail on duplicate or 4-to-1 partner. */
const assertPackedPairsDistinct = (parameters) => {
  const n = parameters.queryCount / 2;
  const partnerSum = parameters.firstFoldPairCount - 1;
  if (!Number.isInteger(n) || n < 2) return [];
  return [
    OP.OP_TOALTSTACK,
    OP.OP_0,
    OP.OP_BEGIN,
    OP.OP_FROMALTSTACK,
    OP.OP_SIZE,
    OP.OP_NOT,
    OP.OP_IF,
    OP.OP_DROP,
    OP.OP_1,
    OP.OP_ELSE,
    ...pushNumber(4),
    OP.OP_SPLIT,
    OP.OP_SWAP,
    OP.OP_BIN2NUM,
    OP.OP_SWAP,
    OP.OP_TOALTSTACK,
    ...insertKeyIntoSortedU32Blob(),
    OP.OP_0,
    OP.OP_ENDIF,
    OP.OP_UNTIL,
    ...assertSortedU32BlobNoPartnerSum(n, partnerSum),
    OP.OP_DROP,
  ];
};

const buildPackedSampleOnce = (parameters) => {
  const { domainLength, firstFoldPairCount } = parameters;
  return [
    ...pushNumber(2),
    OP.OP_ROLL,
    ...buildTranscriptChallenge({
      label: CIRCLE_FRI_QUERY_CANDIDATE_LABEL,
      upperBound: domainLength,
    }),
    OP.OP_DUP,
    OP.OP_DUP,
    ...pushNumber(firstFoldPairCount),
    OP.OP_LESSTHAN,
    OP.OP_IF,
    OP.OP_ELSE,
    ...pushNumber(domainLength - 1),
    OP.OP_SWAP,
    OP.OP_SUB,
    OP.OP_ENDIF,
    OP.OP_FROMALTSTACK,
    ...packedAcceptIndex(),
  ];
};

const buildPackedFourToOnePartnerOnce = (parameters) => [
  OP.OP_OVER,
  OP.OP_SIZE,
  OP.OP_NIP,
  ...pushNumber(4),
  OP.OP_SUB,
  ...pushNumber(2),
  OP.OP_PICK,
  OP.OP_SWAP,
  ...extractTopBytesRuntime(4),
  ...decodeUnsignedTop(),
  ...firstFoldPairOfTop(parameters),
  ...pushNumber(parameters.firstFoldPairCount - 1),
  OP.OP_SWAP,
  OP.OP_SUB,
  OP.OP_TOALTSTACK,
  ...pushNumber(2),
  OP.OP_ROLL,
  OP.OP_FROMALTSTACK,
  OP.OP_DUP,
  OP.OP_FROMALTSTACK,
  ...packedAcceptIndexOnly(),
];

const buildPackedUniqueQueryDerivation = (parameters) => {
  const { queryCount } = parameters;
  const fourToOne = circleFriUsesFourToOne(parameters);
  const body = fourToOne
    ? [
        OP.OP_DUP,
        OP.OP_2,
        OP.OP_MOD,
        OP.OP_IF,
        ...buildPackedFourToOnePartnerOnce(parameters),
        OP.OP_ELSE,
        ...buildPackedSampleOnce(parameters),
        OP.OP_ENDIF,
      ]
    : buildPackedSampleOnce(parameters);
  return [
    ...encodeMinimalDataPush(new Uint8Array()),
    OP.OP_TOALTSTACK,
    ...encodeMinimalDataPush(new Uint8Array()),
    OP.OP_0,
    OP.OP_BEGIN,
    ...body,
    OP.OP_DUP,
    ...pushNumber(queryCount),
    OP.OP_NUMEQUAL,
    OP.OP_UNTIL,
    OP.OP_DROP,
    OP.OP_FROMALTSTACK,
    // packedPairs is a search copy of packedIndices. Derivation already
    // rejects duplicate and 4-to-1-partner samples; the O(n²) insertion
    // post-pass is redundant and dominates density at large k.
    OP.OP_DROP,
    OP.OP_SWAP,
  ];
};

const buildQ4TranscriptQuerySelection = (offsets) => [
    // Witness depth from TOS is unchanged: roots sit *under* the witness.
    ...pushNumber(6),
    OP.OP_PICK,
    ...extractTopBytes(offsets.queryOrdinals, 4),
    OP.OP_INPUTINDEX,
    OP.OP_IF,
    ...encodeMinimalDataPush(concat(u16le(2), u16le(3))),
    OP.OP_ELSE,
    ...encodeMinimalDataPush(concat(u16le(0), u16le(1))),
    OP.OP_ENDIF,
    OP.OP_EQUALVERIFY,
    OP.OP_DROP,

    // Retain the active batch's two transcript-derived query indices as u32le.
    ...pushNumber(5),
    OP.OP_PICK,
    ...extractTopBytes(offsets.queryIndices, 8),
    OP.OP_TOALTSTACK,
    OP.OP_INPUTINDEX,
    OP.OP_IF,
    ...pushNumber(1),
    OP.OP_PICK,
    ...pushNumber(4),
    OP.OP_NUM2BIN,
    ...pushNumber(1),
    OP.OP_PICK,
    ...pushNumber(4),
    OP.OP_NUM2BIN,
    OP.OP_CAT,
    OP.OP_ELSE,
    ...pushNumber(3),
    OP.OP_PICK,
    ...pushNumber(4),
    OP.OP_NUM2BIN,
    ...pushNumber(3),
    OP.OP_PICK,
    ...pushNumber(4),
    OP.OP_NUM2BIN,
    OP.OP_CAT,
    OP.OP_ENDIF,
    OP.OP_DUP,
    OP.OP_FROMALTSTACK,
    OP.OP_EQUALVERIFY,
    OP.OP_TOALTSTACK,
    OP.OP_2DROP,
    OP.OP_2DROP,
    OP.OP_FROMALTSTACK,
];

const buildPackedTranscriptQuerySelection = (offsets, queryCount) => [
    ...pushNumber(3),
    OP.OP_PICK,
    ...extractTopBytes(offsets.queryOrdinals, 4),
    OP.OP_INPUTINDEX,
    OP.OP_DUP,
    OP.OP_2,
    OP.OP_MUL,
    ...pushNumber(2),
    OP.OP_NUM2BIN,
    OP.OP_SWAP,
    OP.OP_2,
    OP.OP_MUL,
    OP.OP_1ADD,
    ...pushNumber(2),
    OP.OP_NUM2BIN,
    OP.OP_CAT,
    OP.OP_EQUALVERIFY,
    OP.OP_DROP,
    ...pushNumber(2),
    OP.OP_PICK,
    ...extractTopBytes(offsets.queryIndices, 8),
    OP.OP_TOALTSTACK,
    OP.OP_DUP,
    OP.OP_SIZE,
    ...pushNumber(queryCount * 4),
    OP.OP_NUMEQUALVERIFY,
    OP.OP_DROP,
    OP.OP_INPUTINDEX,
    ...pushNumber(8),
    OP.OP_MUL,
    OP.OP_SPLIT,
    OP.OP_NIP,
    ...pushNumber(8),
    OP.OP_SPLIT,
    OP.OP_DROP,
    OP.OP_DUP,
    OP.OP_FROMALTSTACK,
    OP.OP_EQUALVERIFY,
    OP.OP_TOALTSTACK,
    OP.OP_FROMALTSTACK,
];

/**
 * TOS = numeric cluster base, encoded as u32le so 0 is not empty.
 * hasTranscript: unique-derivation layout [d, r, w, b, packed, t, base4]
 *   (PICK 4 = witness; SWAP DROP transcript).
 * no transcript: [d, r, w, b, packed, base4] (PICK 3 = witness).
 * savePacked: OVER-copy packed onto alt before consuming it, so a later
 * cluster can unique-once.
 */
const buildPackedTranscriptQuerySelectionFromBase = (
  offsets,
  queryCount,
  { hasTranscript = true, savePacked = false } = {},
) => [
    ...pushNumber(4),
    OP.OP_NUM2BIN,
    ...pushNumber(hasTranscript ? 4 : 3),
    OP.OP_PICK,
    ...extractTopBytes(offsets.queryOrdinals, 4),
    OP.OP_OVER,
    OP.OP_BIN2NUM,
    OP.OP_DUP,
    OP.OP_2,
    OP.OP_MUL,
    ...pushNumber(2),
    OP.OP_NUM2BIN,
    OP.OP_SWAP,
    OP.OP_2,
    OP.OP_MUL,
    OP.OP_1ADD,
    ...pushNumber(2),
    OP.OP_NUM2BIN,
    OP.OP_CAT,
    OP.OP_EQUALVERIFY,
    ...(hasTranscript ? [OP.OP_SWAP, OP.OP_DROP] : []),
    ...(savePacked ? [OP.OP_OVER, OP.OP_TOALTSTACK] : []),
    ...pushNumber(3),
    OP.OP_PICK,
    ...extractTopBytes(offsets.queryIndices, 8),
    OP.OP_TOALTSTACK,
    OP.OP_OVER,
    OP.OP_SIZE,
    ...pushNumber(queryCount * 4),
    OP.OP_NUMEQUALVERIFY,
    OP.OP_DROP,
    OP.OP_DUP,
    OP.OP_BIN2NUM,
    ...pushNumber(8),
    OP.OP_MUL,
    OP.OP_NIP,
    OP.OP_SPLIT,
    OP.OP_NIP,
    ...pushNumber(8),
    OP.OP_SPLIT,
    OP.OP_DROP,
    OP.OP_DUP,
    OP.OP_FROMALTSTACK,
    OP.OP_EQUALVERIFY,
    OP.OP_TOALTSTACK,
    OP.OP_FROMALTSTACK,
];

const extractTopBytesRuntime = (length) => [
  OP.OP_SPLIT,
  OP.OP_SWAP,
  OP.OP_DROP,
  ...pushNumber(length),
  OP.OP_SPLIT,
  OP.OP_DROP,
];

const pushUtf8Decimal = () => [
  OP.OP_DUP,
  ...pushNumber(10),
  OP.OP_LESSTHAN,
  OP.OP_IF,
  ...pushNumber(0x30),
  OP.OP_ADD,
  ...pushNumber(1),
  OP.OP_NUM2BIN,
  OP.OP_ELSE,
  OP.OP_DUP,
  ...pushNumber(10),
  OP.OP_DIV,
  ...pushNumber(0x30),
  OP.OP_ADD,
  ...pushNumber(1),
  OP.OP_NUM2BIN,
  OP.OP_SWAP,
  ...pushNumber(10),
  OP.OP_MOD,
  ...pushNumber(0x30),
  OP.OP_ADD,
  ...pushNumber(1),
  OP.OP_NUM2BIN,
  OP.OP_CAT,
  OP.OP_ENDIF,
];

/** packedDepth: PICK the packed-beta blob, SIZE, drop the copy, /betaBytes = round. */
const copyRoundFromPacked = (packedDepth, betaBytes = 4) => [
  ...pushNumber(packedDepth),
  OP.OP_PICK,
  OP.OP_SIZE,
  OP.OP_NIP,
  ...pushNumber(betaBytes),
  OP.OP_DIV,
];

const pushLabelWithRound = (prefix, packedDepth, betaBytes = 4) => [
  ...copyRoundFromPacked(packedDepth, betaBytes),
  ...pushUtf8Decimal(),
  ...encodeMinimalDataPush(utf8(prefix)),
  OP.OP_SWAP,
  OP.OP_CAT,
];

const framePrefixFromLabelOnTop = (payloadLength) => [
  OP.OP_DUP,
  OP.OP_SIZE,
  OP.OP_NIP,
  ...pushNumber(2),
  OP.OP_NUM2BIN,
  OP.OP_SWAP,
  OP.OP_CAT,
  ...encodeMinimalDataPush(u32le(payloadLength)),
  OP.OP_CAT,
];

/** Top = label, then payload, then state. Leaves new state. */
const absorbPayloadWithLabelOnTop = (payloadLength) => [
  ...framePrefixFromLabelOnTop(payloadLength),
  OP.OP_SWAP,
  OP.OP_SIZE,
  ...pushNumber(payloadLength),
  OP.OP_NUMEQUALVERIFY,
  OP.OP_CAT,
  OP.OP_CAT,
  OP.OP_SHA256,
];

/** Top = state. Builds fri-fold-beta-{round}{suffix} frames from packed SIZE/betaBytes and samples. */
const buildRuntimeTranscriptChallenge = (labelPrefix, { suffix = '', betaBytes = 4 } = {}) => [
  ...pushLabelWithRound(labelPrefix, 1, betaBytes),
  ...(suffix === '' ? [] : [
    ...encodeMinimalDataPush(utf8(suffix)),
    OP.OP_CAT,
  ]),
  OP.OP_DUP,
  ...encodeMinimalDataPush(concat(u16le(5), utf8('label'))),
  OP.OP_SWAP,
  OP.OP_DUP,
  OP.OP_SIZE,
  OP.OP_NIP,
  ...pushNumber(4),
  OP.OP_NUM2BIN,
  OP.OP_SWAP,
  OP.OP_CAT,
  OP.OP_CAT,
  ...encodeMinimalDataPush(framePrefix('attempt', 4)),
  OP.OP_CAT,
  OP.OP_SWAP,
  ...encodeMinimalDataPush(concat(u16le(24), utf8('accepted-challenge-label'))),
  OP.OP_SWAP,
  OP.OP_DUP,
  OP.OP_SIZE,
  OP.OP_NIP,
  ...pushNumber(4),
  OP.OP_NUM2BIN,
  OP.OP_SWAP,
  OP.OP_CAT,
  OP.OP_CAT,
  ...invokeFunction(FUNCTION.SAMPLE_M31_TRANSCRIPT),
];

const encodeSampledChallenge = () => [
  ...pushNumber(4),
  OP.OP_NUM2BIN,
];

/** One squeeze → two M31 (re||im). TOS = state; packed betas at depth 1. */
const sampleCm31FoldBeta = () => [
  ...pushLabelWithRound('fri-fold-beta-', 1, 8),
  OP.OP_DUP,
  ...encodeMinimalDataPush(concat(u16le(5), utf8('label'))),
  OP.OP_SWAP,
  OP.OP_DUP,
  OP.OP_SIZE,
  OP.OP_NIP,
  ...pushNumber(4),
  OP.OP_NUM2BIN,
  OP.OP_SWAP,
  OP.OP_CAT,
  OP.OP_CAT,
  ...encodeMinimalDataPush(framePrefix('attempt', 4)),
  OP.OP_CAT,
  OP.OP_SWAP,
  ...encodeMinimalDataPush(concat(u16le(24), utf8('accepted-challenge-label'))),
  OP.OP_SWAP,
  OP.OP_DUP,
  OP.OP_SIZE,
  OP.OP_NIP,
  ...pushNumber(4),
  OP.OP_NUM2BIN,
  OP.OP_SWAP,
  OP.OP_CAT,
  OP.OP_CAT,
  ...pushNumber(M31_MODULUS),
  ...pushNumber(Number(M31_MODULUS) * 2),
  OP.OP_0,
  OP.OP_BEGIN,
  ...pushNumber(5),
  OP.OP_PICK,
  ...encodeMinimalDataPush(CIRCLE_FRI_SQUEEZE_DOMAIN),
  OP.OP_SWAP,
  OP.OP_CAT,
  ...pushNumber(5),
  OP.OP_PICK,
  OP.OP_CAT,
  OP.OP_OVER,
  ...pushNumber(4),
  OP.OP_NUM2BIN,
  OP.OP_CAT,
  OP.OP_SHA256,
  OP.OP_DUP,
  ...pushNumber(4),
  OP.OP_SPLIT,
  OP.OP_SWAP,
  OP.OP_TOALTSTACK,
  ...pushNumber(4),
  OP.OP_SPLIT,
  OP.OP_DROP,
  OP.OP_FROMALTSTACK,
  ...encodeMinimalDataPush(ZERO_BYTE),
  OP.OP_CAT,
  OP.OP_BIN2NUM,
  OP.OP_SWAP,
  ...encodeMinimalDataPush(ZERO_BYTE),
  OP.OP_CAT,
  OP.OP_BIN2NUM,
  OP.OP_OVER,
  ...pushNumber(5),
  OP.OP_PICK,
  OP.OP_LESSTHAN,
  OP.OP_TOALTSTACK,
  OP.OP_DUP,
  ...pushNumber(5),
  OP.OP_PICK,
  OP.OP_LESSTHAN,
  OP.OP_FROMALTSTACK,
  OP.OP_BOOLAND,
  OP.OP_IF,
  OP.OP_OVER,
  ...pushNumber(6),
  OP.OP_PICK,
  OP.OP_MOD,
  OP.OP_TOALTSTACK,
  OP.OP_DUP,
  ...pushNumber(6),
  OP.OP_PICK,
  OP.OP_MOD,
  OP.OP_TOALTSTACK,
  OP.OP_2DROP,
  ...pushNumber(6),
  OP.OP_PICK,
  ...pushNumber(5),
  OP.OP_PICK,
  OP.OP_CAT,
  ...encodeMinimalDataPush(framePrefix('accepted-challenge-digest', 32)),
  OP.OP_CAT,
  OP.OP_OVER,
  OP.OP_CAT,
  ...encodeMinimalDataPush(framePrefix('accepted-challenge-attempt', 4)),
  OP.OP_CAT,
  ...pushNumber(2),
  OP.OP_PICK,
  ...pushNumber(4),
  OP.OP_NUM2BIN,
  OP.OP_CAT,
  OP.OP_SHA256,
  OP.OP_TOALTSTACK,
  OP.OP_2DROP,
  OP.OP_2DROP,
  OP.OP_2DROP,
  OP.OP_DROP,
  OP.OP_FROMALTSTACK,
  OP.OP_FROMALTSTACK,
  OP.OP_FROMALTSTACK,
  OP.OP_SWAP,
  ...packCm31Top(),
  OP.OP_1,
  OP.OP_ELSE,
  OP.OP_2DROP,
  OP.OP_DROP,
  OP.OP_1ADD,
  OP.OP_0,
  OP.OP_ENDIF,
  OP.OP_UNTIL,
];

/**
 * One FRI transcript round. ABI top-to-bottom: state, packedBetas, witness, rootsBlob.
 * Round is packedBetas.length/betaBytes. Roots are the redeem blob under the witness (no CAT).
 * Does not park round on alt — SAMPLE_TRANSCRIPT owns alt.
 */
const buildTranscriptLayerFunction = ({ cm31 = false } = {}) => {
  const betaBytes = cm31 ? 8 : 4;
  const sampleAndEncode = (suffix) => [
    ...buildRuntimeTranscriptChallenge('fri-fold-beta-', { suffix, betaBytes }),
    ...encodeSampledChallenge(),
  ];
  return compileScript([
    ...copyRoundFromPacked(1, betaBytes),
    ...pushNumber(32),
    OP.OP_MUL,
    ...pushNumber(4),
    OP.OP_PICK,
    OP.OP_SWAP,
    ...extractTopBytesRuntime(32),
    ...pushLabelWithRound('fri-layer-root-', 2, betaBytes),
    ...absorbPayloadWithLabelOnTop(32),
    ...(cm31 ? sampleCm31FoldBeta() : sampleAndEncode('')),
    OP.OP_TOALTSTACK,
    OP.OP_SWAP,
    OP.OP_FROMALTSTACK,
    OP.OP_CAT,
    OP.OP_SWAP,
  ], 'one FRI transcript absorb+challenge round');
};

const buildLoopedTranscriptLayers = (parameters, { cm31 = false } = {}) => [
  OP.OP_BEGIN,
  ...invokeFunction(FUNCTION.TRANSCRIPT_LAYER),
  OP.OP_OVER,
  OP.OP_SIZE,
  OP.OP_NIP,
  ...pushNumber(parameters.logDegreeBound * (cm31 ? 8 : 4)),
  OP.OP_NUMEQUAL,
  OP.OP_UNTIL,
];

const buildTranscriptReplay = (fixture, offsets, { deferQuerySelection = false } = {}) => {
  const cm31 = circleFriUsesCm31Fold(fixture.parameters);
  const feltBytes = cm31 ? 8 : 4;
  const script = [
    OP.OP_0,
    ...buildTranscriptInitialization({
      protocolContext: fixture.protocolContext,
      parameters: fixture.parameters,
    }),
  ];
  if (fixture.parameters.logDegreeBound >= 8) {
    script.push(...buildLoopedTranscriptLayers(fixture.parameters, { cm31 }));
  } else {
    for (let round = 0; round < fixture.parameters.logDegreeBound; round += 1) {
      script.push(
        ...pushNumber(3),
        OP.OP_PICK,
        ...extractTopBytes(round * 32, 32),
        ...buildTranscriptAbsorbRuntime(`fri-layer-root-${round}`, 32),
        ...buildTranscriptChallenge({
          label: `fri-fold-beta-${round}`,
          upperBound: Number(M31_MODULUS),
        }),
        ...pushNumber(4),
        OP.OP_NUM2BIN,
        OP.OP_TOALTSTACK,
        OP.OP_SWAP,
        OP.OP_FROMALTSTACK,
        OP.OP_CAT,
        OP.OP_SWAP,
      );
    }
  }
  script.push(
    ...pushNumber(2),
    OP.OP_PICK,
    ...extractTopBytes(offsets.finalCodeword, fixture.parameters.blowup * feltBytes),
    ...buildTranscriptAbsorbRuntime('fri-final-codeword', fixture.parameters.blowup * feltBytes),
    OP.OP_DUP,
    ...pushNumber(5),
    OP.OP_PICK,
    OP.OP_EQUALVERIFY,
  );
  if (deferQuerySelection) {
    script.push(...buildPackedUniqueQueryDerivation(fixture.parameters));
  } else if (fixture.parameters.queryCount === 4) {
    script.push(
      ...buildCanonicalQueryDerivationAll(fixture.parameters),
      ...buildQ4TranscriptQuerySelection(offsets),
    );
  } else {
    script.push(
      ...buildPackedUniqueQueryDerivation(fixture.parameters),
      ...buildPackedTranscriptQuerySelection(offsets, fixture.parameters.queryCount),
    );
  }
  return script;
};

/** Input: the fixed-width final codeword. Output: its canonical constant blob or M31. */
const buildFinalConstantValidation = (blowup, { cm31 = false } = {}) => {
  const feltBytes = cm31 ? 8 : 4;
  const script = [
    OP.OP_DUP,
    ...extractTopBytes(0, feltBytes),
    ...(cm31 ? [] : invokeFunction(FUNCTION.DECODE_M31)),
    OP.OP_TOALTSTACK,
  ];
  for (let index = 1; index < blowup; index += 1) {
    script.push(
      OP.OP_DUP,
      ...extractTopBytes(index * feltBytes, feltBytes),
      OP.OP_1,
      OP.OP_PICK,
      ...extractTopBytes(0, feltBytes),
      OP.OP_EQUALVERIFY,
    );
  }
  script.push(OP.OP_DROP, OP.OP_FROMALTSTACK);
  return script;
};

const buildCountedFrontierSplit = () => [
  OP.OP_2,
  OP.OP_SPLIT,
  OP.OP_SWAP,
  ...decodeUnsignedTop(),
  ...pushNumber(32),
  OP.OP_MUL,
  OP.OP_SPLIT,
  OP.OP_SWAP,
];

const hashTopologyRecord = (recordBytes) => [
  OP.OP_SIZE,
  ...pushNumber(recordBytes),
  OP.OP_NUMEQUALVERIFY,
  ...encodeMinimalDataPush(CIRCLE_FRI_TOPOLOGY_LEAF_DOMAIN),
  OP.OP_SWAP,
  OP.OP_CAT,
  OP.OP_HASH256,
];

/** Input layout: betas, selectedQueries, final, roots, rec0, rec1, remainder. */
const buildTopologyVerification = () => [
  // Records are bound to this batch's query indices. Pair geometry is
  // checked by the FRI fold; the 32768-leaf topology Merkle is omitted
  // from the v2 codec (fold consistency already rejects forged pairs).
  ...pushNumber(2),
  OP.OP_PICK,
  ...extractTopBytes(10, 4),
  ...pushNumber(2),
  OP.OP_PICK,
  ...extractTopBytes(10, 4),
  OP.OP_CAT,
  OP.OP_TOALTSTACK,
  ...pushNumber(5),
  OP.OP_PICK,
  OP.OP_DUP,
  ...extractTopBytes(0, 4),
  ...decodeUnsignedTop(),
  ...pushNumber(1),
  OP.OP_ROLL,
  ...extractTopBytes(4, 4),
  ...decodeUnsignedTop(),
  ...compareExchangeTop(),
  OP.OP_TOALTSTACK,
  ...pushNumber(4),
  OP.OP_NUM2BIN,
  OP.OP_FROMALTSTACK,
  ...pushNumber(4),
  OP.OP_NUM2BIN,
  OP.OP_CAT,
  OP.OP_FROMALTSTACK,
  OP.OP_EQUALVERIFY,
];

const packSortedIndices = () => [
  ...pushNumber(4),
  OP.OP_NUM2BIN,
  OP.OP_TOALTSTACK,
  ...pushNumber(4),
  OP.OP_NUM2BIN,
  OP.OP_TOALTSTACK,
  ...pushNumber(4),
  OP.OP_NUM2BIN,
  OP.OP_TOALTSTACK,
  ...pushNumber(4),
  OP.OP_NUM2BIN,
  OP.OP_FROMALTSTACK,
  OP.OP_CAT,
  OP.OP_FROMALTSTACK,
  OP.OP_CAT,
  OP.OP_FROMALTSTACK,
  OP.OP_CAT,
];

const lookupRecordValue = ({ recordDepth, fieldOffset, indicesDepth, valuesDepth }) => [
  ...pushNumber(recordDepth),
  OP.OP_PICK,
  ...extractTopBytes(fieldOffset, 4),
  ...decodeUnsignedTop(),
  OP.OP_TOALTSTACK,
  ...pushNumber(indicesDepth),
  OP.OP_PICK,
  ...pushNumber(valuesDepth + 1),
  OP.OP_PICK,
  OP.OP_FROMALTSTACK,
  ...invokeFunction(FUNCTION.LOOKUP4),
  ...invokeFunction(FUNCTION.DECODE_M31),
];

const buildSortedPlanIndices = ({ plan0Depth, plan1Depth }) => [
  ...pushNumber(plan0Depth),
  OP.OP_PICK,
  ...extractTopBytes(4, 4),
  ...decodeUnsignedTop(),
  ...pushNumber(plan0Depth + 1),
  OP.OP_PICK,
  ...extractTopBytes(8, 4),
  ...decodeUnsignedTop(),
  ...pushNumber(plan1Depth + 2),
  OP.OP_PICK,
  ...extractTopBytes(4, 4),
  ...decodeUnsignedTop(),
  ...pushNumber(plan1Depth + 3),
  OP.OP_PICK,
  ...extractTopBytes(8, 4),
  ...decodeUnsignedTop(),
  ...invokeFunction(FUNCTION.SORT4),
];

const buildPlanInverse = ({
  queryDepth, selectedDepth, headerDepth, inv0Offset = 4, inv1Offset = 8,
}) => [
  ...pushNumber(queryDepth),
  OP.OP_PICK,
  ...pushNumber(selectedDepth + 1),
  OP.OP_PICK,
  OP.OP_EQUAL,
  OP.OP_IF,
  ...pushNumber(headerDepth),
  OP.OP_PICK,
  ...extractTopBytes(inv0Offset, 4),
  OP.OP_ELSE,
  ...pushNumber(headerDepth),
  OP.OP_PICK,
  ...extractTopBytes(inv1Offset, 4),
  OP.OP_ENDIF,
  ...invokeFunction(FUNCTION.DECODE_M31),
];


/**
 * Reusable per-layer ABI (bottom-to-top): previousFoldBytes, remainingCodec,
 * plan0, plan1, recordQuery0, recordQuery1, selectedOrdinal0, betaRaw, root,
 * treeWidth, firstRoundFlag. Output: nextFoldBytes, remainingCodec.
 */
const buildVerifyLayerFunction = ({ toCm31 = false } = {}) => compileScript([
  ...pushNumber(9),
  OP.OP_ROLL,
  ...pushNumber(28),
  OP.OP_SPLIT,
  OP.OP_OVER,
  ...extractTopBytes(0, 2),
  ...encodeMinimalDataPush(u16le(4)),
  OP.OP_EQUALVERIFY,
  OP.OP_OVER,
  ...extractTopBytes(2, 2),
  ...decodeUnsignedTop(),
  ...pushNumber(32),
  OP.OP_MUL,
  OP.OP_SPLIT,
  OP.OP_SWAP,
  // TOS: frontier, following, header, flag, width, root, ...
  OP.OP_SWAP,
  OP.OP_TOALTSTACK,
  // TOS: frontier, header, flag, width, root, ... ; following parked

  ...buildSortedPlanIndices({ plan0Depth: 10, plan1Depth: 9 }),
  ...[0, 1, 2, 3].flatMap((value) => [
    ...pushNumber(5 + value),
    OP.OP_PICK,
    ...extractTopBytes(12 + value * 4, 4),
  ]),
  ...pushNumber(8),
  OP.OP_ROLL,
  OP.OP_TOALTSTACK,
  OP.OP_TOALTSTACK,
  OP.OP_TOALTSTACK,
  OP.OP_TOALTSTACK,
  OP.OP_TOALTSTACK,
  OP.OP_TOALTSTACK,
  OP.OP_TOALTSTACK,
  OP.OP_TOALTSTACK,
  OP.OP_TOALTSTACK,
  ...pushNumber(3),
  OP.OP_PICK,
  OP.OP_FROMALTSTACK,
  OP.OP_FROMALTSTACK,
  OP.OP_FROMALTSTACK,
  OP.OP_FROMALTSTACK,
  OP.OP_FROMALTSTACK,
  OP.OP_FROMALTSTACK,
  OP.OP_FROMALTSTACK,
  OP.OP_FROMALTSTACK,
  OP.OP_FROMALTSTACK,
  ...pushNumber(12),
  OP.OP_PICK,
  ...invokeFunction(FUNCTION.MULTIPROOF4),
  OP.OP_VERIFY,

  // Pack the authenticated sorted index/value table for both fold chains.
  ...buildSortedPlanIndices({ plan0Depth: 9, plan1Depth: 8 }),
  ...packSortedIndices(),
  ...pushNumber(1),
  OP.OP_PICK,
  ...extractTopBytes(12, 16),

  // Non-initial layers must continue from both prior authenticated folds.
  ...pushNumber(3),
  OP.OP_PICK,
  OP.OP_IF,
  OP.OP_ELSE,
  ...lookupRecordValue({ recordDepth: 11, fieldOffset: 0, indicesDepth: 1, valuesDepth: 0 }),
  ...pushNumber(13),
  OP.OP_PICK,
  ...extractTopBytes(0, 4),
  ...invokeFunction(FUNCTION.DECODE_M31),
  OP.OP_NUMEQUALVERIFY,
  ...lookupRecordValue({ recordDepth: 10, fieldOffset: 0, indicesDepth: 1, valuesDepth: 0 }),
  ...pushNumber(13),
  OP.OP_PICK,
  ...extractTopBytes(4, 4),
  ...invokeFunction(FUNCTION.DECODE_M31),
  OP.OP_NUMEQUALVERIFY,
  OP.OP_ENDIF,

  // Fold authenticated record 0.
  ...lookupRecordValue({ recordDepth: 11, fieldOffset: 4, indicesDepth: 1, valuesDepth: 0 }),
  ...lookupRecordValue({ recordDepth: 12, fieldOffset: 8, indicesDepth: 2, valuesDepth: 1 }),
  ...buildPlanInverse({ queryDepth: 11, selectedDepth: 9, headerDepth: 4 }),
  ...pushNumber(9),
  OP.OP_PICK,
  ...(toCm31
    ? [...unpackCm31Blob(), ...invokeFunction(FUNCTION.FOLD_M31_TO_CM31)]
    : [...invokeFunction(FUNCTION.DECODE_M31), ...invokeFunction(FUNCTION.FOLD_M31)]),

  // Fold authenticated record 1.
  ...lookupRecordValue({
    recordDepth: toCm31 ? 12 : 11,
    fieldOffset: 4,
    indicesDepth: toCm31 ? 3 : 2,
    valuesDepth: toCm31 ? 2 : 1,
  }),
  ...lookupRecordValue({
    recordDepth: toCm31 ? 13 : 12,
    fieldOffset: 8,
    indicesDepth: toCm31 ? 4 : 3,
    valuesDepth: toCm31 ? 3 : 2,
  }),
  ...buildPlanInverse({
    queryDepth: toCm31 ? 12 : 11,
    selectedDepth: toCm31 ? 11 : 10,
    headerDepth: toCm31 ? 6 : 5,
  }),
  ...pushNumber(toCm31 ? 11 : 10),
  OP.OP_PICK,
  ...(toCm31
    ? [...unpackCm31Blob(), ...invokeFunction(FUNCTION.FOLD_M31_TO_CM31)]
    : [...invokeFunction(FUNCTION.DECODE_M31), ...invokeFunction(FUNCTION.FOLD_M31)]),

  ...(toCm31
    ? [
        ...packCm31Top(),
        OP.OP_TOALTSTACK,
        ...packCm31Top(),
        OP.OP_FROMALTSTACK,
        OP.OP_CAT,
      ]
    : [
        ...pushNumber(4),
        OP.OP_NUM2BIN,
        OP.OP_TOALTSTACK,
        ...pushNumber(4),
        OP.OP_NUM2BIN,
        OP.OP_FROMALTSTACK,
        OP.OP_CAT,
      ]),
  OP.OP_TOALTSTACK,
  OP.OP_2DROP,
  OP.OP_2DROP,
  OP.OP_2DROP,
  OP.OP_2DROP,
  OP.OP_2DROP,
  OP.OP_2DROP,
  OP.OP_DROP,
  OP.OP_FROMALTSTACK,
  OP.OP_FROMALTSTACK,
], 'reusable q2 layer function');

const VERIFY_LAYER_FUNCTION = buildVerifyLayerFunction();

/**
 * Later 4-to-1 rounds: two authenticated leaves. Caller still pushes
 * firstRoundFlag; this function drops it. Sorted (min||max) indices match
 * layer values, which are canonical. plan1 must be the same π-pair as plan0.
 */
const sortedPairFromPlan = (planDepth) => [
  ...pushNumber(planDepth),
  OP.OP_PICK,
  ...extractTopBytes(4, 4),
  ...decodeUnsignedTop(),
  ...pushNumber(planDepth + 1),
  OP.OP_PICK,
  ...extractTopBytes(8, 4),
  ...decodeUnsignedTop(),
];

const packU32Pair = () => [
  ...pushNumber(4),
  OP.OP_NUM2BIN,
  OP.OP_TOALTSTACK,
  ...pushNumber(4),
  OP.OP_NUM2BIN,
  OP.OP_FROMALTSTACK,
  OP.OP_CAT,
];

/** wanted on top; packed 16-byte indices then values below at the given depths. */
const lookup4FromPacked = ({ indicesDepth, valuesDepth, valueBytes = 8 }) => [
  OP.OP_DUP,
  ...pushNumber(indicesDepth + 1),
  OP.OP_PICK,
  ...extractTopBytes(0, 4),
  ...decodeUnsignedTop(),
  OP.OP_EQUAL,
  OP.OP_IF,
  ...pushNumber(valuesDepth),
  OP.OP_PICK,
  ...extractTopBytes(0, valueBytes),
  OP.OP_ELSE,
  OP.OP_DUP,
  ...pushNumber(indicesDepth + 1),
  OP.OP_PICK,
  ...extractTopBytes(4, 4),
  ...decodeUnsignedTop(),
  OP.OP_EQUAL,
  OP.OP_IF,
  ...pushNumber(valuesDepth),
  OP.OP_PICK,
  ...extractTopBytes(valueBytes, valueBytes),
  OP.OP_ELSE,
  OP.OP_DUP,
  ...pushNumber(indicesDepth + 1),
  OP.OP_PICK,
  ...extractTopBytes(8, 4),
  ...decodeUnsignedTop(),
  OP.OP_EQUAL,
  OP.OP_IF,
  ...pushNumber(valuesDepth),
  OP.OP_PICK,
  ...extractTopBytes(2 * valueBytes, valueBytes),
  OP.OP_ELSE,
  OP.OP_DUP,
  ...pushNumber(indicesDepth + 1),
  OP.OP_PICK,
  ...extractTopBytes(12, 4),
  ...decodeUnsignedTop(),
  OP.OP_EQUALVERIFY,
  ...pushNumber(valuesDepth),
  OP.OP_PICK,
  ...extractTopBytes(3 * valueBytes, valueBytes),
  OP.OP_ENDIF,
  OP.OP_ENDIF,
  OP.OP_ENDIF,
  OP.OP_NIP,
];

/** wanted on top; packed indices then values below at the given depths. */
const lookup2FromPacked = ({ indicesDepth, valuesDepth, valueBytes = 4 }) => [
  OP.OP_DUP,
  ...pushNumber(indicesDepth + 1),
  OP.OP_PICK,
  ...extractTopBytes(0, 4),
  ...decodeUnsignedTop(),
  OP.OP_EQUAL,
  OP.OP_IF,
  ...pushNumber(valuesDepth),
  OP.OP_PICK,
  ...extractTopBytes(0, valueBytes),
  OP.OP_ELSE,
  OP.OP_DUP,
  ...pushNumber(indicesDepth + 1),
  OP.OP_PICK,
  ...extractTopBytes(4, 4),
  ...decodeUnsignedTop(),
  OP.OP_EQUALVERIFY,
  ...pushNumber(valuesDepth),
  OP.OP_PICK,
  ...extractTopBytes(valueBytes, valueBytes),
  OP.OP_ENDIF,
  OP.OP_NIP,
  ...(valueBytes === 4 ? [OP.OP_BIN2NUM] : []),
];

/** Tournament Merkle of n leaves on alt (top = lowest index). Consumes the packed codeword. */
const hashCodewordTournament = (n, { cm31 = false } = {}) => {
  const leafBytes = cm31 ? 8 : 4;
  const hashLeaf = cm31 ? FUNCTION.HASH_CM31_LEAF : FUNCTION.HASH_M31_LEAF;
  const script = [];
  for (let i = 1; i < n; i += 1) {
    script.push(
      OP.OP_SIZE,
      ...pushNumber(leafBytes),
      OP.OP_SUB,
      OP.OP_SPLIT,
      ...invokeFunction(hashLeaf),
      OP.OP_TOALTSTACK,
    );
  }
  script.push(
    ...invokeFunction(hashLeaf),
    OP.OP_TOALTSTACK,
  );
  let count = n;
  while (count > 1) {
    for (let i = 0; i < count / 2; i += 1) {
      script.push(
        OP.OP_FROMALTSTACK,
        OP.OP_FROMALTSTACK,
        ...invokeFunction(FUNCTION.HASH_NODE),
      );
    }
    count /= 2;
    if (count > 1) {
      for (let i = 0; i < count; i += 1) script.push(OP.OP_TOALTSTACK);
    }
  }
  return script;
};

/** Input: packed 16 M31 or CM31 felts. Output: Merkle root. */
const HASH_CODEWORD_BODY = hashCodewordTournament(16);
const HASH_CODEWORD_BODY_CM31 = hashCodewordTournament(16, { cm31: true });

/** TOS: left-blob, right-blob, inv, beta-blob → out_re, out_im. */
const foldCm31FromBlobs = () => [
  ...unpackCm31Blob(),
  OP.OP_TOALTSTACK,
  OP.OP_TOALTSTACK,
  OP.OP_TOALTSTACK,
  ...unpackCm31Blob(),
  OP.OP_TOALTSTACK,
  OP.OP_TOALTSTACK,
  ...unpackCm31Blob(),
  OP.OP_FROMALTSTACK,
  OP.OP_FROMALTSTACK,
  OP.OP_FROMALTSTACK,
  OP.OP_FROMALTSTACK,
  OP.OP_FROMALTSTACK,
  ...invokeFunction(FUNCTION.FOLD_CM31),
];

const buildLayer2FoldAfter = ({ parked = true, cm31 = false } = {}) => {
  const p = parked ? 0 : 1;
  const foldBytes = cm31 ? 8 : 4;
  const foldInvoke = cm31
    ? foldCm31FromBlobs()
    : [...invokeFunction(FUNCTION.DECODE_M31), ...invokeFunction(FUNCTION.FOLD_M31)];
  const continuityEq = cm31
    ? [OP.OP_EQUALVERIFY]
    : [...invokeFunction(FUNCTION.DECODE_M31), OP.OP_NUMEQUALVERIFY];
  // 4-to-1 later rounds EQUALVERIFY the two plans as the same π-pair, so
  // both folds are identical. Pack once and DUP.
  const packFolds = cm31
    ? [
        ...packCm31Top(),
        OP.OP_DUP,
        OP.OP_CAT,
      ]
    : [
        ...pushNumber(4),
        OP.OP_NUM2BIN,
        OP.OP_DUP,
        OP.OP_CAT,
      ];
  return [
    ...sortedPairFromPlan(9 + p),
    ...packU32Pair(),
    ...pushNumber(1 + p),
    OP.OP_PICK,
    ...extractTopBytes(cm31 ? 10 : 10, 2 * foldBytes),

    ...pushNumber(11 + p),
    OP.OP_PICK,
    ...extractTopBytes(0, 4),
    ...decodeUnsignedTop(),
    ...lookup2FromPacked({ indicesDepth: 2, valuesDepth: 1, valueBytes: foldBytes }),
    ...pushNumber(13 + p),
    OP.OP_PICK,
    ...extractTopBytes(0, foldBytes),
    ...continuityEq,
    ...pushNumber(10 + p),
    OP.OP_PICK,
    ...extractTopBytes(0, 4),
    ...decodeUnsignedTop(),
    ...lookup2FromPacked({ indicesDepth: 2, valuesDepth: 1, valueBytes: foldBytes }),
    ...pushNumber(13 + p),
    OP.OP_PICK,
    ...extractTopBytes(foldBytes, foldBytes),
    ...continuityEq,

    ...pushNumber(11 + p),
    OP.OP_PICK,
    ...extractTopBytes(4, 4),
    ...decodeUnsignedTop(),
    ...lookup2FromPacked({ indicesDepth: 2, valuesDepth: 1, valueBytes: foldBytes }),
    ...pushNumber(12 + p),
    OP.OP_PICK,
    ...extractTopBytes(8, 4),
    ...decodeUnsignedTop(),
    ...lookup2FromPacked({ indicesDepth: 3, valuesDepth: 2, valueBytes: foldBytes }),
    ...buildPlanInverse({
      queryDepth: 11 + p,
      selectedDepth: 9 + p,
      headerDepth: 4 + p,
      inv0Offset: 2,
      inv1Offset: 6,
    }),
    ...pushNumber(9 + p),
    OP.OP_PICK,
    ...foldInvoke,

    ...packFolds,
    OP.OP_TOALTSTACK,
    ...(parked
      ? [
          OP.OP_2DROP,
          OP.OP_2DROP,
          OP.OP_2DROP,
          OP.OP_2DROP,
          OP.OP_2DROP,
          OP.OP_2DROP,
          OP.OP_DROP,
        ]
      : [
          OP.OP_2DROP,
          OP.OP_TOALTSTACK,
          OP.OP_2DROP,
          OP.OP_2DROP,
          OP.OP_2DROP,
          OP.OP_2DROP,
          OP.OP_2DROP,
          OP.OP_DROP,
        ]),
    OP.OP_FROMALTSTACK,
    OP.OP_FROMALTSTACK,
    ...(parked ? [] : [OP.OP_SWAP]),
  ];
};

const VERIFY_LAYER2_FOLD_AFTER_MERKLE = [
  ...sortedPairFromPlan(10),
  ...packU32Pair(),
  ...pushNumber(2),
  OP.OP_PICK,
  ...extractTopBytes(12, 8),

  ...pushNumber(12),
  OP.OP_PICK,
  ...extractTopBytes(0, 4),
  ...decodeUnsignedTop(),
  ...lookup2FromPacked({ indicesDepth: 2, valuesDepth: 1 }),
  ...pushNumber(14),
  OP.OP_PICK,
  ...extractTopBytes(0, 4),
  ...invokeFunction(FUNCTION.DECODE_M31),
  OP.OP_NUMEQUALVERIFY,
  ...pushNumber(11),
  OP.OP_PICK,
  ...extractTopBytes(0, 4),
  ...decodeUnsignedTop(),
  ...lookup2FromPacked({ indicesDepth: 2, valuesDepth: 1 }),
  ...pushNumber(14),
  OP.OP_PICK,
  ...extractTopBytes(4, 4),
  ...invokeFunction(FUNCTION.DECODE_M31),
  OP.OP_NUMEQUALVERIFY,

  ...pushNumber(12),
  OP.OP_PICK,
  ...extractTopBytes(4, 4),
  ...decodeUnsignedTop(),
  ...lookup2FromPacked({ indicesDepth: 2, valuesDepth: 1 }),
  ...pushNumber(13),
  OP.OP_PICK,
  ...extractTopBytes(8, 4),
  ...decodeUnsignedTop(),
  ...lookup2FromPacked({ indicesDepth: 3, valuesDepth: 2 }),
  ...buildPlanInverse({ queryDepth: 12, selectedDepth: 10, headerDepth: 5 }),
  ...pushNumber(10),
  OP.OP_PICK,
  ...invokeFunction(FUNCTION.DECODE_M31),
  ...invokeFunction(FUNCTION.FOLD_M31),

  ...pushNumber(13),
  OP.OP_PICK,
  ...extractTopBytes(4, 4),
  ...decodeUnsignedTop(),
  ...lookup2FromPacked({ indicesDepth: 3, valuesDepth: 2 }),
  ...pushNumber(14),
  OP.OP_PICK,
  ...extractTopBytes(8, 4),
  ...decodeUnsignedTop(),
  ...lookup2FromPacked({ indicesDepth: 4, valuesDepth: 3 }),
  ...buildPlanInverse({ queryDepth: 13, selectedDepth: 11, headerDepth: 6 }),
  ...pushNumber(11),
  OP.OP_PICK,
  ...invokeFunction(FUNCTION.DECODE_M31),
  ...invokeFunction(FUNCTION.FOLD_M31),

  ...packU32Pair(),
  OP.OP_TOALTSTACK,
  OP.OP_2DROP,
  OP.OP_TOALTSTACK,
  OP.OP_2DROP,
  OP.OP_2DROP,
  OP.OP_2DROP,
  OP.OP_2DROP,
  OP.OP_2DROP,
  OP.OP_DROP,
  OP.OP_FROMALTSTACK,
  OP.OP_FROMALTSTACK,
  OP.OP_SWAP,
];

/**
 * VERIFY_LAYER2 entry has TOS = following (remaining codec). Park it so
 * fold PICKs duplicate the 20-byte header, not the multi-hundred-byte rest.
 * VERIFY_FULL / FOLD_ONLY keep VERIFY_LAYER2_FOLD_AFTER_MERKLE (DEFINE).
 */
const VERIFY_LAYER2_FOLD_AFTER_PARKED = [
  ...sortedPairFromPlan(9),
  ...packU32Pair(),
  ...pushNumber(1),
  OP.OP_PICK,
  ...extractTopBytes(12, 8),

  ...pushNumber(11),
  OP.OP_PICK,
  ...extractTopBytes(0, 4),
  ...decodeUnsignedTop(),
  ...lookup2FromPacked({ indicesDepth: 2, valuesDepth: 1 }),
  ...pushNumber(13),
  OP.OP_PICK,
  ...extractTopBytes(0, 4),
  ...invokeFunction(FUNCTION.DECODE_M31),
  OP.OP_NUMEQUALVERIFY,
  ...pushNumber(10),
  OP.OP_PICK,
  ...extractTopBytes(0, 4),
  ...decodeUnsignedTop(),
  ...lookup2FromPacked({ indicesDepth: 2, valuesDepth: 1 }),
  ...pushNumber(13),
  OP.OP_PICK,
  ...extractTopBytes(4, 4),
  ...invokeFunction(FUNCTION.DECODE_M31),
  OP.OP_NUMEQUALVERIFY,

  ...pushNumber(11),
  OP.OP_PICK,
  ...extractTopBytes(4, 4),
  ...decodeUnsignedTop(),
  ...lookup2FromPacked({ indicesDepth: 2, valuesDepth: 1 }),
  ...pushNumber(12),
  OP.OP_PICK,
  ...extractTopBytes(8, 4),
  ...decodeUnsignedTop(),
  ...lookup2FromPacked({ indicesDepth: 3, valuesDepth: 2 }),
  ...buildPlanInverse({ queryDepth: 11, selectedDepth: 9, headerDepth: 4 }),
  ...pushNumber(9),
  OP.OP_PICK,
  ...invokeFunction(FUNCTION.DECODE_M31),
  ...invokeFunction(FUNCTION.FOLD_M31),

  ...pushNumber(12),
  OP.OP_PICK,
  ...extractTopBytes(4, 4),
  ...decodeUnsignedTop(),
  ...lookup2FromPacked({ indicesDepth: 3, valuesDepth: 2 }),
  ...pushNumber(13),
  OP.OP_PICK,
  ...extractTopBytes(8, 4),
  ...decodeUnsignedTop(),
  ...lookup2FromPacked({ indicesDepth: 4, valuesDepth: 3 }),
  ...buildPlanInverse({ queryDepth: 12, selectedDepth: 10, headerDepth: 5 }),
  ...pushNumber(10),
  OP.OP_PICK,
  ...invokeFunction(FUNCTION.DECODE_M31),
  ...invokeFunction(FUNCTION.FOLD_M31),

  ...packU32Pair(),
  OP.OP_TOALTSTACK,
  OP.OP_2DROP,
  OP.OP_2DROP,
  OP.OP_2DROP,
  OP.OP_2DROP,
  OP.OP_2DROP,
  OP.OP_2DROP,
  OP.OP_DROP,
  OP.OP_FROMALTSTACK,
  OP.OP_FROMALTSTACK,
];

const buildVerifyLayer2Function = ({ cm31 = false } = {}) => {
  const headerBytes = cm31 ? 26 : 18;
  const valueBytes = cm31 ? 8 : 4;
  const hashLeaf = cm31 ? FUNCTION.HASH_CM31_LEAF : FUNCTION.HASH_M31_LEAF;
  return compileScript([
  // Same ABI as VERIFY_LAYER, including firstRoundFlag (always 0 here).
  // Later 2-leaf header omits valueCount: sibCount||inv||values.
  ...pushNumber(9),
  OP.OP_ROLL,
  ...pushNumber(headerBytes),
  OP.OP_SPLIT,
  ...pushNumber(1),
  OP.OP_PICK,
  ...extractTopBytes(0, 2),
  ...decodeUnsignedTop(),
  ...pushNumber(32),
  OP.OP_MUL,
  OP.OP_SPLIT,
  OP.OP_SWAP,
  // TOS: siblings, following, header, ...
  OP.OP_SWAP,
  OP.OP_TOALTSTACK,
  // siblings, header, flag, width, root, ... ; following parked
  ...sortedPairFromPlan(10),
  ...sortedPairFromPlan(11),
  OP.OP_TOALTSTACK,
  OP.OP_ROT,
  OP.OP_EQUALVERIFY,
  OP.OP_FROMALTSTACK,
  OP.OP_EQUALVERIFY,
  ...sortedPairFromPlan(10),
  ...domainPairToMerklePair(),
  ...pushNumber(3),
  OP.OP_PICK,
  ...extractTopBytes(10, valueBytes),
  ...invokeFunction(hashLeaf),
  ...pushNumber(4),
  OP.OP_PICK,
  ...extractTopBytes(10 + valueBytes, valueBytes),
  ...invokeFunction(hashLeaf),
  ...pushNumber(4),
  OP.OP_ROLL,
  OP.OP_TOALTSTACK,
  OP.OP_TOALTSTACK,
  OP.OP_TOALTSTACK,
  OP.OP_TOALTSTACK,
  OP.OP_TOALTSTACK,
  ...pushNumber(2),
  OP.OP_PICK,
  ...pushNumber(4),
  OP.OP_PICK,
  OP.OP_FROMALTSTACK,
  OP.OP_FROMALTSTACK,
  OP.OP_FROMALTSTACK,
  OP.OP_FROMALTSTACK,
  OP.OP_FROMALTSTACK,
  ...invokeFunction(FUNCTION.HASHED_MULTIPROOF2),
  OP.OP_VERIFY,
  ...buildLayer2FoldAfter({ parked: true, cm31 }),
], 'reusable q2 two-leaf layer function');
};

const VERIFY_LAYER2_FUNCTION = buildVerifyLayer2Function();

/** Pack two independent domain pairs in merkle order (by pairIndex = min). */
const packTwoDomainPairsMerkleOrder = () => [
  ...pushNumber(3),
  OP.OP_PICK,
  ...pushNumber(2),
  OP.OP_PICK,
  OP.OP_GREATERTHAN,
  OP.OP_IF,
  OP.OP_2SWAP,
  OP.OP_ENDIF,
  ...packSortedIndices(),
];

/**
 * Later independent rounds: four authenticated CM31 leaves (two π-pairs).
 * packed indices are domain min||max||min||max in merkle order.
 */
const buildLayer4FoldAfter = ({ parked = true } = {}) => {
  const p = parked ? 0 : 1;
  return [
    ...sortedPairFromPlan(9 + p),
    ...sortedPairFromPlan(10 + p),
    ...packTwoDomainPairsMerkleOrder(),
    ...pushNumber(1 + p),
    OP.OP_PICK,
    ...extractTopBytes(12, 32),

    ...pushNumber(11 + p),
    OP.OP_PICK,
    ...extractTopBytes(0, 4),
    ...decodeUnsignedTop(),
    ...lookup4FromPacked({ indicesDepth: 2, valuesDepth: 1, valueBytes: 8 }),
    ...pushNumber(13 + p),
    OP.OP_PICK,
    ...extractTopBytes(0, 8),
    OP.OP_EQUALVERIFY,
    ...pushNumber(10 + p),
    OP.OP_PICK,
    ...extractTopBytes(0, 4),
    ...decodeUnsignedTop(),
    ...lookup4FromPacked({ indicesDepth: 2, valuesDepth: 1, valueBytes: 8 }),
    ...pushNumber(13 + p),
    OP.OP_PICK,
    ...extractTopBytes(8, 8),
    OP.OP_EQUALVERIFY,

    ...pushNumber(11 + p),
    OP.OP_PICK,
    ...extractTopBytes(4, 4),
    ...decodeUnsignedTop(),
    ...lookup4FromPacked({ indicesDepth: 2, valuesDepth: 1, valueBytes: 8 }),
    ...pushNumber(12 + p),
    OP.OP_PICK,
    ...extractTopBytes(8, 4),
    ...decodeUnsignedTop(),
    ...lookup4FromPacked({ indicesDepth: 3, valuesDepth: 2, valueBytes: 8 }),
    ...buildPlanInverse({
      queryDepth: 11 + p,
      selectedDepth: 9 + p,
      headerDepth: 4 + p,
    }),
    ...pushNumber(9 + p),
    OP.OP_PICK,
    ...foldCm31FromBlobs(),

    ...pushNumber(13 + p),
    OP.OP_PICK,
    ...extractTopBytes(4, 4),
    ...decodeUnsignedTop(),
    ...lookup4FromPacked({ indicesDepth: 4, valuesDepth: 3, valueBytes: 8 }),
    ...pushNumber(14 + p),
    OP.OP_PICK,
    ...extractTopBytes(8, 4),
    ...decodeUnsignedTop(),
    ...lookup4FromPacked({ indicesDepth: 5, valuesDepth: 4, valueBytes: 8 }),
    ...buildPlanInverse({
      queryDepth: 13 + p,
      selectedDepth: 11 + p,
      headerDepth: 6 + p,
    }),
    ...pushNumber(11 + p),
    OP.OP_PICK,
    ...foldCm31FromBlobs(),

    ...packCm31Top(),
    OP.OP_TOALTSTACK,
    ...packCm31Top(),
    OP.OP_FROMALTSTACK,
    OP.OP_CAT,
    OP.OP_TOALTSTACK,
    ...(parked
      ? [
          OP.OP_2DROP,
          OP.OP_2DROP,
          OP.OP_2DROP,
          OP.OP_2DROP,
          OP.OP_2DROP,
          OP.OP_2DROP,
          OP.OP_DROP,
        ]
      : [
          OP.OP_2DROP,
          OP.OP_TOALTSTACK,
          OP.OP_2DROP,
          OP.OP_2DROP,
          OP.OP_2DROP,
          OP.OP_2DROP,
          OP.OP_2DROP,
          OP.OP_DROP,
        ]),
    OP.OP_FROMALTSTACK,
    OP.OP_FROMALTSTACK,
    ...(parked ? [] : [OP.OP_SWAP]),
  ];
};

const buildVerifyLayer4Function = () => compileScript([
  ...pushNumber(9),
  OP.OP_ROLL,
  ...pushNumber(44),
  OP.OP_SPLIT,
  ...pushNumber(1),
  OP.OP_PICK,
  ...extractTopBytes(0, 2),
  ...encodeMinimalDataPush(u16le(4)),
  OP.OP_EQUALVERIFY,
  ...pushNumber(1),
  OP.OP_PICK,
  ...extractTopBytes(2, 2),
  ...decodeUnsignedTop(),
  ...pushNumber(32),
  OP.OP_MUL,
  OP.OP_SPLIT,
  OP.OP_SWAP,
  OP.OP_SWAP,
  OP.OP_TOALTSTACK,
  ...sortedPairFromPlan(10),
  ...domainPairToMerklePair(),
  ...sortedPairFromPlan(11),
  ...domainPairToMerklePair(),
  ...pushNumber(3),
  OP.OP_PICK,
  ...pushNumber(2),
  OP.OP_PICK,
  OP.OP_GREATERTHAN,
  OP.OP_IF,
  OP.OP_2SWAP,
  OP.OP_ENDIF,
  ...[0, 1, 2, 3].flatMap((slot) => [
    ...pushNumber(5 + slot),
    OP.OP_PICK,
    ...extractTopBytes(12 + slot * 8, 8),
    ...invokeFunction(FUNCTION.HASH_CM31_LEAF),
  ]),
  ...pushNumber(8),
  OP.OP_ROLL,
  OP.OP_TOALTSTACK,
  OP.OP_TOALTSTACK,
  OP.OP_TOALTSTACK,
  OP.OP_TOALTSTACK,
  OP.OP_TOALTSTACK,
  OP.OP_TOALTSTACK,
  OP.OP_TOALTSTACK,
  OP.OP_TOALTSTACK,
  OP.OP_TOALTSTACK,
  ...pushNumber(3),
  OP.OP_PICK,
  OP.OP_FROMALTSTACK,
  OP.OP_FROMALTSTACK,
  OP.OP_FROMALTSTACK,
  OP.OP_FROMALTSTACK,
  OP.OP_FROMALTSTACK,
  OP.OP_FROMALTSTACK,
  OP.OP_FROMALTSTACK,
  OP.OP_FROMALTSTACK,
  OP.OP_FROMALTSTACK,
  ...pushNumber(12),
  OP.OP_PICK,
  ...invokeFunction(FUNCTION.HASHED_MULTIPROOF4),
  OP.OP_VERIFY,
  ...buildLayer4FoldAfter({ parked: true }),
], 'reusable q2 four-leaf CM31 layer function');


/**
 * Domain ≤16: remaining codec is a full codeword. Hash it to the layer root,
 * rebuild a 20-byte 2-leaf header, then the same fold as VERIFY_LAYER2.
 */
const extractCodewordFelt = (valueBytes, widthMul, pickDepth) => [
  OP.OP_DUP,
  widthMul,
  OP.OP_MUL,
  ...pushNumber(pickDepth),
  OP.OP_PICK,
  OP.OP_SWAP,
  ...extractTopBytesRuntime(valueBytes),
];

const buildVerifyFullLayerFunction = ({ cm31 = false, independent = false } = {}) => {
  const valueBytes = cm31 ? 8 : 4;
  const widthMul = cm31 ? OP.OP_8 : OP.OP_4;
  const hashBody = cm31 ? HASH_CODEWORD_BODY_CM31 : HASH_CODEWORD_BODY;
  const leafCount = independent ? 4 : 2;
  const extractLeaves = independent
    ? [
        ...sortedPairFromPlan(10),
        ...domainPairToMerklePair(),
        ...extractCodewordFelt(valueBytes, widthMul, 3),
        OP.OP_TOALTSTACK,
        OP.OP_DROP,
        ...extractCodewordFelt(valueBytes, widthMul, 2),
        OP.OP_FROMALTSTACK,
        OP.OP_SWAP,
        OP.OP_CAT,
        OP.OP_NIP,
        OP.OP_TOALTSTACK,
        OP.OP_DROP,
        ...sortedPairFromPlan(10),
        ...domainPairToMerklePair(),
        ...extractCodewordFelt(valueBytes, widthMul, 3),
        OP.OP_TOALTSTACK,
        OP.OP_DROP,
        ...extractCodewordFelt(valueBytes, widthMul, 2),
        OP.OP_FROMALTSTACK,
        OP.OP_SWAP,
        OP.OP_CAT,
        OP.OP_NIP,
        OP.OP_TOALTSTACK,
        OP.OP_DROP,
        OP.OP_FROMALTSTACK,
        OP.OP_SWAP,
        OP.OP_CAT,
      ]
    : [
        ...sortedPairFromPlan(10),
        ...domainPairToMerklePair(),
        ...extractCodewordFelt(valueBytes, widthMul, 3),
        OP.OP_TOALTSTACK,
        OP.OP_DROP,
        ...extractCodewordFelt(valueBytes, widthMul, 2),
        OP.OP_FROMALTSTACK,
        OP.OP_CAT,
        OP.OP_NIP,
        OP.OP_TOALTSTACK,
        OP.OP_DROP,
      ];
  return compileScript([
  ...pushNumber(9),
  OP.OP_ROLL,
  ...pushNumber(2),
  OP.OP_PICK,
  widthMul,
  OP.OP_MUL,
  ...pushNumber(12),
  OP.OP_ADD,
  OP.OP_SPLIT,
  OP.OP_TOALTSTACK,
  OP.OP_DUP,
  ...pushNumber(12),
  OP.OP_SPLIT,
  OP.OP_NIP,
  ...hashBody,
  ...pushNumber(4),
  OP.OP_PICK,
  OP.OP_EQUALVERIFY,
  OP.OP_DUP,
  ...pushNumber(12),
  OP.OP_SPLIT,
  OP.OP_NIP,
  ...extractLeaves,
  OP.OP_DUP,
  ...extractTopBytes(4, 8),
  ...(independent
    ? [
        ...encodeMinimalDataPush(u16le(leafCount)),
        ...encodeMinimalDataPush(u16le(0)),
        OP.OP_CAT,
        OP.OP_SWAP,
        OP.OP_CAT,
      ]
    : [
        ...encodeMinimalDataPush(u16le(0)),
        OP.OP_SWAP,
        OP.OP_CAT,
      ]),
  OP.OP_FROMALTSTACK,
  OP.OP_CAT,
  OP.OP_NIP,
  ...(independent
    ? [OP.OP_FROMALTSTACK]
    : []),
  ...invokeFunction(FUNCTION.FOLD_AFTER_MERKLE),
], 'reusable q2 full-codeword layer function');
};

const VERIFY_FULL_LAYER_FUNCTION = buildVerifyFullLayerFunction();

/** Domain <16 after a full-eval: 2-leaf or independent 4-leaf header, no merkle. */
const buildVerifyFoldOnlyFunction = ({ cm31 = false, independent = false } = {}) => compileScript([
  ...pushNumber(9),
  OP.OP_ROLL,
  ...pushNumber(independent ? 44 : (cm31 ? 26 : 18)),
  OP.OP_SPLIT,
  OP.OP_TOALTSTACK,
  OP.OP_DUP,
  ...(independent
    ? [
        ...extractTopBytes(0, 2),
        ...encodeMinimalDataPush(u16le(4)),
        OP.OP_EQUALVERIFY,
        OP.OP_DUP,
        ...extractTopBytes(2, 2),
        ...decodeUnsignedTop(),
        OP.OP_0,
        OP.OP_NUMEQUALVERIFY,
      ]
    : [
        ...extractTopBytes(0, 2),
        ...decodeUnsignedTop(),
        OP.OP_0,
        OP.OP_NUMEQUALVERIFY,
      ]),
  ...(independent
    ? [OP.OP_FROMALTSTACK]
    : []),
  ...invokeFunction(FUNCTION.FOLD_AFTER_MERKLE),
], 'reusable q2 fold-only small layer');

const VERIFY_FOLD_ONLY_FUNCTION = buildVerifyFoldOnlyFunction();

const buildLayerInvocation = (fixture, round) => {
  const omitRecords = fixture.parameters.logDegreeBound >= 8;
  const roundOffset = omitRecords ? 0 : 14 + round * 21;
  const queryOffset = omitRecords ? 0 : 10;
  const layerLength = fixture.parameters.domainLength / (2 ** round);
  const clustered = circleFriUsesFourToOne(fixture.parameters) && round > 0;
  return [
    ...pushNumber(3),
    OP.OP_PICK,
    ...extractTopBytes(roundOffset, 21),
    ...pushNumber(3),
    OP.OP_PICK,
    ...extractTopBytes(roundOffset, 21),
    ...pushNumber(5),
    OP.OP_PICK,
    ...extractTopBytes(queryOffset, 4),
    ...pushNumber(5),
    OP.OP_PICK,
    ...extractTopBytes(queryOffset, 4),
    ...pushNumber(omitRecords ? 8 : 10),
    OP.OP_PICK,
    ...extractTopBytes(0, 4),
    ...pushNumber(omitRecords ? 11 : 12),
    OP.OP_PICK,
    ...extractTopBytes(
      round * (circleFriUsesCm31Fold(fixture.parameters) ? 8 : 4),
      circleFriUsesCm31Fold(fixture.parameters) ? 8 : 4,
    ),
    ...pushNumber(omitRecords ? 13 : 10),
    OP.OP_PICK,
    ...extractTopBytes(round * 32, 32),
    ...pushNumber(layerLength),
    ...(round === 0 ? [OP.OP_1] : [OP.OP_0]),
    ...invokeFunction(clustered ? FUNCTION.VERIFY_LAYER2 : FUNCTION.VERIFY_LAYER),
  ];
};

const copyRoundFromAlt = () => [
  OP.OP_FROMALTSTACK,
  OP.OP_DUP,
  OP.OP_TOALTSTACK,
];

/** Copy alt item at depth (0 = round on top) onto the main stack. */
const copyAltDepth = (depth) => {
  const script = [];
  for (let index = 0; index <= depth; index += 1) script.push(OP.OP_FROMALTSTACK);
  script.push(OP.OP_DUP, OP.OP_TOALTSTACK);
  for (let index = 0; index < depth; index += 1) {
    script.push(OP.OP_SWAP, OP.OP_TOALTSTACK);
  }
  return script;
};

/** P, N → 12-byte later plan: current||left||right with left/right = min/max(P, N-1-P). */
const packLaterPlan = () => [
  OP.OP_1SUB,
  OP.OP_OVER,
  OP.OP_SUB,
  OP.OP_2DUP,
  OP.OP_MIN,
  OP.OP_TOALTSTACK,
  OP.OP_2DUP,
  OP.OP_MAX,
  OP.OP_NIP,
  OP.OP_FROMALTSTACK,
  ...pushNumber(2),
  OP.OP_PICK,
  ...pushNumber(4),
  OP.OP_NUM2BIN,
  OP.OP_1,
  OP.OP_PICK,
  ...pushNumber(4),
  OP.OP_NUM2BIN,
  OP.OP_CAT,
  ...pushNumber(2),
  OP.OP_PICK,
  ...pushNumber(4),
  OP.OP_NUM2BIN,
  OP.OP_CAT,
  OP.OP_NIP,
  OP.OP_NIP,
  OP.OP_NIP,
];

const PACK_LATER_PLAN_FUNCTION = compileScript(packLaterPlan(), 'pack later topology plan');

/** Later rounds: derive left/right as N-1-P; round-0 nextIndex seeds current. */
const buildClusteredLaterLayerLoop = (fixture) => {
  const { logDegreeBound, domainLength } = fixture.parameters;
  const cm31 = circleFriUsesCm31Fold(fixture.parameters);
  const betaBytes = cm31 ? 8 : 4;
  const foldOnly = buildVerifyFoldOnlyFunction({
    cm31,
    independent: !circleFriUsesFourToOne(fixture.parameters),
  });
  return [
    ...pushNumber(3),
    OP.OP_PICK,
    ...extractTopBytes(fixture.parameters.logDegreeBound >= 8 ? 12 : 26, 4),
    ...decodeUnsignedTop(),
    ...pushNumber(3),
    OP.OP_PICK,
    ...extractTopBytes(fixture.parameters.logDegreeBound >= 8 ? 12 : 26, 4),
    ...decodeUnsignedTop(),
    OP.OP_TOALTSTACK,
    OP.OP_TOALTSTACK,
    ...pushNumber(domainLength / 2),
    OP.OP_TOALTSTACK,
    ...pushNumber(1),
    OP.OP_TOALTSTACK,
    OP.OP_BEGIN,
    ...copyAltDepth(1),
    OP.OP_DUP,
    ...copyAltDepth(2),
    OP.OP_ROT,
    ...invokeFunction(FUNCTION.PACK_LATER_PLAN),
    OP.OP_SWAP,
    ...copyAltDepth(3),
    OP.OP_SWAP,
    ...invokeFunction(FUNCTION.PACK_LATER_PLAN),
    ...pushNumber(5),
    OP.OP_PICK,
    ...extractTopBytes(0, 4),
    ...pushNumber(5),
    OP.OP_PICK,
    ...extractTopBytes(0, 4),
    ...pushNumber(8),
    OP.OP_PICK,
    ...extractTopBytes(0, 4),
    ...pushNumber(11),
    OP.OP_PICK,
    ...copyRoundFromAlt(),
    ...pushNumber(betaBytes),
    OP.OP_MUL,
    ...extractTopBytesRuntime(betaBytes),
    ...pushNumber(13),
    OP.OP_PICK,
    ...copyRoundFromAlt(),
    ...pushNumber(32),
    OP.OP_MUL,
    ...extractTopBytesRuntime(32),
    OP.OP_FROMALTSTACK,
    OP.OP_FROMALTSTACK,
    OP.OP_DUP,
    OP.OP_TOALTSTACK,
    OP.OP_SWAP,
    OP.OP_TOALTSTACK,
    OP.OP_DUP,
    ...pushNumber(16),
    OP.OP_GREATERTHAN,
    OP.OP_IF,
    ...copyRoundFromAlt(),
    ...pushNumber(CIRCLE_FRI_MERKLE_STRIDE),
    OP.OP_MOD,
    OP.OP_IF,
    OP.OP_0,
    ...foldOnly,
    OP.OP_ELSE,
    OP.OP_0,
    ...invokeFunction(FUNCTION.VERIFY_LAYER2),
    OP.OP_ENDIF,
    OP.OP_ELSE,
    OP.OP_DUP,
    ...pushNumber(16),
    OP.OP_NUMEQUAL,
    OP.OP_IF,
    OP.OP_0,
    ...invokeFunction(FUNCTION.VERIFY_FULL_LAYER),
    OP.OP_ELSE,
    OP.OP_0,
    ...foldOnly,
    OP.OP_ENDIF,
    OP.OP_ENDIF,
    OP.OP_FROMALTSTACK,
    OP.OP_1ADD,
    OP.OP_DUP,
    ...pushNumber(logDegreeBound),
    OP.OP_NUMEQUAL,
    OP.OP_IF,
    OP.OP_DROP,
    OP.OP_FROMALTSTACK,
    OP.OP_DROP,
    OP.OP_FROMALTSTACK,
    OP.OP_DROP,
    OP.OP_FROMALTSTACK,
    OP.OP_DROP,
    OP.OP_1,
    OP.OP_ELSE,
    OP.OP_FROMALTSTACK,
    OP.OP_FROMALTSTACK,
    OP.OP_OVER,
    OP.OP_1SUB,
    OP.OP_OVER,
    OP.OP_SUB,
    OP.OP_MIN,
    OP.OP_FROMALTSTACK,
    ...pushNumber(2),
    OP.OP_PICK,
    OP.OP_1SUB,
    OP.OP_OVER,
    OP.OP_SUB,
    OP.OP_MIN,
    OP.OP_TOALTSTACK,
    OP.OP_TOALTSTACK,
    OP.OP_2,
    OP.OP_DIV,
    OP.OP_TOALTSTACK,
    OP.OP_TOALTSTACK,
    OP.OP_0,
    OP.OP_ENDIF,
    OP.OP_UNTIL,
  ];
};

const buildVerifyClusterAfterTranscript = (fixture, offsets) => {
  const parameters = fixture.parameters;
  const cm31 = circleFriUsesCm31Fold(parameters);
  const feltBytes = cm31 ? 8 : 4;
  const omitRecords = parameters.logDegreeBound >= 8;
  const record0 = offsets.finalCodeword + parameters.blowup * feltBytes;
  const record1 = record0 + fixture.topologyRecordBytes;
  const afterRecords = omitRecords ? record0 : record1 + fixture.topologyRecordBytes;
  const script = [
    ...pushNumber(2),
    OP.OP_PICK,
    ...extractTopBytes(offsets.finalCodeword, parameters.blowup * feltBytes),
    ...buildFinalConstantValidation(parameters.blowup, { cm31 }),
    ...(omitRecords
      ? [
          ...pushNumber(1),
          OP.OP_PICK,
          ...synthesizeRound0PlansFromSelected(parameters),
          ...pushNumber(5),
          OP.OP_ROLL,
          ...pushNumber(afterRecords),
          OP.OP_SPLIT,
          OP.OP_SWAP,
          OP.OP_DROP,
        ]
      : [
          ...pushNumber(4),
          OP.OP_PICK,
          ...pushNumber(4),
          OP.OP_PICK,
          ...extractTopBytes(record0, fixture.topologyRecordBytes),
          ...pushNumber(5),
          OP.OP_PICK,
          ...extractTopBytes(record1, fixture.topologyRecordBytes),
          ...pushNumber(6),
          OP.OP_ROLL,
          ...pushNumber(afterRecords),
          OP.OP_SPLIT,
          OP.OP_SWAP,
          OP.OP_DROP,
          ...pushNumber(7),
          OP.OP_ROLL,
          OP.OP_DROP,
          ...buildTopologyVerification(),
        ]),
    OP.OP_0,
    OP.OP_SWAP,
  ];
  if (parameters.logDegreeBound >= 8) {
    script.push(...buildLayerInvocation(fixture, 0));
    script.push(...buildClusteredLaterLayerLoop(fixture));
  } else {
    for (let round = 0; round < parameters.logDegreeBound; round += 1) {
      script.push(...buildLayerInvocation(fixture, round));
    }
  }
  script.push(
    OP.OP_SIZE,
    OP.OP_0,
    OP.OP_NUMEQUALVERIFY,
    OP.OP_DROP,
    OP.OP_DUP,
    ...extractTopBytes(0, feltBytes),
    ...(cm31
      ? [
          ...pushNumber(omitRecords ? 4 : 5),
          OP.OP_PICK,
          OP.OP_EQUALVERIFY,
        ]
      : [
          ...invokeFunction(FUNCTION.DECODE_M31),
          ...pushNumber(5),
          OP.OP_PICK,
          OP.OP_NUMEQUALVERIFY,
        ]),
    OP.OP_DUP,
    ...extractTopBytes(feltBytes, feltBytes),
    ...(cm31
      ? [
          ...pushNumber(omitRecords ? 4 : 5),
          OP.OP_PICK,
          OP.OP_EQUALVERIFY,
        ]
      : [
          ...invokeFunction(FUNCTION.DECODE_M31),
          ...pushNumber(5),
          OP.OP_PICK,
          OP.OP_NUMEQUALVERIFY,
        ]),
  );
  return script;
};

const compileQ2RedeemScript = (fixture, digestBinding, { clustersPerInput = 1 } = {}) => {
  assertBatchFixture(fixture);
  const parameters = fixture.parameters;
  const cm31 = circleFriUsesCm31Fold(parameters);
  const offsets = Object.freeze({
    queryOrdinals: 10,
    queryIndices: 14,
    finalCodeword: 22,
  });
  const fixedHeader = concat(
    utf8('CFBW'),
    Uint8Array.of(QUERY_BATCH_WITNESS_VERSION),
    encodeCircleFriParameters(parameters),
  );
  const dual = clustersPerInput > 1;
  const clusterBody = buildVerifyClusterAfterTranscript(fixture, offsets);
  const script = [
    ...buildCommonFunctionDefinitions({ cm31 }),
    ...(cm31
      ? concat(
        defineFunction(FUNCTION.HASH_CM31_LEAF, HASH_CM31_LEAF_FUNCTION),
        defineFunction(FUNCTION.FOLD_M31_TO_CM31, FOLD_M31_TO_CM31_FUNCTION),
        defineFunction(FUNCTION.FOLD_CM31, FOLD_CM31_FUNCTION),
      )
      : new Uint8Array()),
    ...defineFunction(FUNCTION.VERIFY_LAYER, buildVerifyLayerFunction({ toCm31: cm31 })),
    ...(parameters.logDegreeBound >= 8
      ? concat(
        ...(circleFriUsesFourToOne(parameters)
          ? []
          : [defineFunction(
            FUNCTION.HASHED_MULTIPROOF4,
            buildBchM31Multiproof4VerificationBytecode({ hashedLeaves: true }),
          )]),
        defineFunction(
          FUNCTION.VERIFY_LAYER2,
          circleFriUsesFourToOne(parameters)
            ? buildVerifyLayer2Function({ cm31 })
            : buildVerifyLayer4Function(),
        ),
        defineFunction(FUNCTION.TRANSCRIPT_LAYER, buildTranscriptLayerFunction({ cm31 })),
        defineFunction(FUNCTION.FOLD_AFTER_MERKLE, compileScript(
          circleFriUsesFourToOne(parameters)
            ? buildLayer2FoldAfter({ parked: true, cm31 })
            : buildLayer4FoldAfter({ parked: false }),
          'q2 fold after merkle',
        )),
        defineFunction(FUNCTION.VERIFY_FULL_LAYER, buildVerifyFullLayerFunction({
          cm31,
          independent: !circleFriUsesFourToOne(parameters),
        })),
        defineFunction(FUNCTION.PACK_LATER_PLAN, PACK_LATER_PLAN_FUNCTION),
      )
      : []),
    ...(fixture.airLdeOpening instanceof Uint8Array
      ? defineFunction(
        FUNCTION.VERIFY_AIR_LDE,
        buildVerifyAirLdeFunction(fixture.airLdeRoot),
      )
      : new Uint8Array()),
    ...(dual
      ? concat(
        defineFunction(FUNCTION.VERIFY_CLUSTER, compileScript(clusterBody, 'q2 cluster body')),
        defineFunction(FUNCTION.TRANSCRIPT_UNIQUE, compileScript([
          OP.OP_INPUTINDEX,
          OP.OP_0,
          OP.OP_NUMEQUAL,
          OP.OP_IF,
          ...buildTranscriptReplay(fixture, offsets, { deferQuerySelection: true }),
          OP.OP_TOALTSTACK,
          OP.OP_SIZE,
          OP.OP_NOT,
          OP.OP_IF,
          OP.OP_DROP,
          OP.OP_ENDIF,
          OP.OP_FROMALTSTACK,
          OP.OP_OVER,
          OP.OP_FROMALTSTACK,
          OP.OP_EQUALVERIFY,
          OP.OP_2,
          OP.OP_PICK,
          OP.OP_FROMALTSTACK,
          OP.OP_EQUALVERIFY,
          OP.OP_ELSE,
          OP.OP_FROMALTSTACK,
          OP.OP_DUP,
          ...extractPackedQueryIndicesFromInput(0, parameters.queryCount),
          OP.OP_EQUALVERIFY,
          OP.OP_FROMALTSTACK,
          OP.OP_DUP,
          ...extractPackedBetasFromInput(0, parameters.queryCount, parameters),
          OP.OP_EQUALVERIFY,
          OP.OP_SWAP,
          OP.OP_0,
          OP.OP_ENDIF,
        ], 'q2 transcript unique')),
      )
      : new Uint8Array()),
    ...digestBinding,
    OP.OP_DUP,
    ...extractTopBytes(0, fixedHeader.length),
    ...encodeMinimalDataPush(fixedHeader),
    OP.OP_EQUALVERIFY,
    // Roots live in redeem. Park the blob under the witness (no full-witness CAT).
    ...encodeMinimalDataPush(concat(...fixture.witness.roots)),
    OP.OP_SWAP,
    ...(dual ? [] : buildTranscriptReplay(fixture, offsets, { deferQuerySelection: false })),
  ];
  if (!dual) {
    script.push(
      ...clusterBody,
      OP.OP_2DROP,
      OP.OP_2DROP,
      OP.OP_2DROP,
      OP.OP_2DROP,
      OP.OP_1,
    );
  } else {
    script.push(
      ...invokeFunction(FUNCTION.TRANSCRIPT_UNIQUE),
    );
    for (let cluster = 0; cluster < clustersPerInput; cluster += 1) {
      if (cluster > 0) {
        script.push(
          OP.OP_2DROP,
          OP.OP_2DROP,
          OP.OP_DROP,
          OP.OP_FROMALTSTACK,
          OP.OP_FROMALTSTACK,
          OP.OP_SWAP,
          OP.OP_ROT,
          OP.OP_SWAP,
        );
      }
      script.push(
        OP.OP_INPUTINDEX,
        ...pushNumber(clustersPerInput),
        OP.OP_MUL,
        ...pushNumber(cluster),
        OP.OP_ADD,
        ...buildPackedTranscriptQuerySelectionFromBase(offsets, parameters.queryCount, {
          hasTranscript: cluster === 0,
          savePacked: cluster < clustersPerInput - 1,
        }),
        ...invokeFunction(FUNCTION.VERIFY_CLUSTER),
      );
    }
    script.push(
      OP.OP_2DROP,
      OP.OP_2DROP,
      OP.OP_2DROP,
      OP.OP_2DROP,
      OP.OP_1,
    );
  }
  const redeem = compileScript(script, 'q2 batch redeem');
  require(
    redeem.length <= 10_000,
    `q2 batch redeem exceeds the BCH script limit: ${redeem.length} bytes`,
  );
  return redeem;
};

/** Compile the one fixed-parameter redeem shared by both q2 batch inputs. */
export const buildBchCircleFriQ2BatchRedeemBytecode = (fixture) => compileQ2RedeemScript(
  fixture,
  buildCrossInputProofDigestBinding(publicBatchCount(fixture.parameters)),
);

const buildInput0OnlyDigestBinding = (batchCount, { clustersPerInput = 1, verifyAirLde = false } = {}) => [
  OP.OP_TXINPUTCOUNT,
  ...pushNumber(batchCount),
  OP.OP_NUMEQUALVERIFY,
  OP.OP_INPUTINDEX,
  OP.OP_0,
  ...pushNumber(batchCount),
  OP.OP_WITHIN,
  OP.OP_VERIFY,
  OP.OP_DROP,
  // Density pad was TOS. Optional AIR note-squeeze LDE opening is next.
  ...(verifyAirLde ? invokeFunction(FUNCTION.VERIFY_AIR_LDE) : []),
  // Operand is digest, packed, witness, extras.
  // Park extras then packed so OVER copies digest. Input 0 derives packed
  // and EQUALVERIFYes this copy; later inputs FROMALTSTACK it.
  ...Array.from({ length: Math.max(0, clustersPerInput - 1) }, () => OP.OP_TOALTSTACK),
  ...(clustersPerInput > 1
    ? [OP.OP_SWAP, OP.OP_TOALTSTACK, OP.OP_SWAP, OP.OP_TOALTSTACK]
    : []),
  OP.OP_OVER,
  ...extractInputProofDigestPrefix(0),
  OP.OP_EQUALVERIFY,
];

export const PARTITION_UNLOCKING_FLOOR = 10_000;
export const OP_INPUTBYTECODE = 0xca;

/** Count OP_INPUTBYTECODE opcodes, skipping push-data payloads. */
export const countOpInputBytecode = (bytecode) => {
  require(bytecode instanceof Uint8Array, 'bytecode must be a Uint8Array');
  let count = 0;
  let offset = 0;
  while (offset < bytecode.length) {
    const opcode = bytecode[offset];
    if (opcode === 0) {
      offset += 1;
      continue;
    }
    if (opcode <= 75) {
      offset += 1 + opcode;
      continue;
    }
    if (opcode === 0x4c) {
      if (offset + 1 >= bytecode.length) break;
      offset += 2 + bytecode[offset + 1];
      continue;
    }
    if (opcode === 0x4d) {
      if (offset + 2 >= bytecode.length) break;
      offset += 3 + bytecode[offset + 1] + bytecode[offset + 2] * 256;
      continue;
    }
    if (opcode === 0x4e) {
      if (offset + 4 >= bytecode.length) break;
      const length = bytecode[offset + 1]
        + bytecode[offset + 2] * 256
        + bytecode[offset + 3] * 65536
        + bytecode[offset + 4] * 16777216;
      offset += 5 + length;
      continue;
    }
    if (opcode === OP.OP_INPUTBYTECODE) count += 1;
    offset += 1;
  }
  return count;
};

export const buildBchCircleFriQ2PartitionRedeemBytecode = (
  fixture,
  { clustersPerInput = 1 } = {},
) => {
  const batchCount = publicBatchCount(fixture.parameters);
  require(
    Number.isInteger(clustersPerInput)
      && clustersPerInput >= 1
      && batchCount % clustersPerInput === 0,
    'clustersPerInput must divide the q2 batch count',
  );
  return compileQ2RedeemScript(
    fixture,
    buildInput0OnlyDigestBinding(batchCount / clustersPerInput, {
      clustersPerInput,
      verifyAirLde: fixture.airLdeOpening instanceof Uint8Array,
    }),
    { clustersPerInput },
  );
};

const encodeUnlockingWithPad = ({ operand, redeem, floor }) => {
  const redeemPush = encodeMinimalDataPush(redeem);
  const unpadded = concat(operand, encodeMinimalDataPush(new Uint8Array(0)), redeemPush);
  if (unpadded.length > floor) {
    return { unlockingBytecode: unpadded, padLength: 0 };
  }
  for (let padLength = 0; padLength <= floor; padLength += 1) {
    const padPush = encodeMinimalDataPush(new Uint8Array(padLength));
    const unlocking = concat(operand, padPush, redeemPush);
    if (unlocking.length === floor) return { unlockingBytecode: unlocking, padLength };
    if (unlocking.length > floor) break;
  }
  throw new TypeError('partition unlocking cannot be padded to the density floor');
};

export const materializeBchCircleFriQ2PartitionP2sh32 = (
  fixture,
  { unlockingFloor = PARTITION_UNLOCKING_FLOOR } = {},
) => {
  assertBatchFixture(fixture);
  const redeemBytecode = buildBchCircleFriQ2PartitionRedeemBytecode(fixture);
  const operandUnlockingBytecode = buildBchCircleFriQ2BatchOperandUnlockingBytecode(fixture);
  const { unlockingBytecode, padLength } = encodeUnlockingWithPad({
    operand: operandUnlockingBytecode,
    redeem: redeemBytecode,
    floor: unlockingFloor,
  });
  const lockingBytecode = encodeLockingBytecodeP2sh32(hash256(redeemBytecode));
  return Object.freeze({
    ...fixture,
    redeemBytecode,
    operandUnlockingBytecode,
    unlockingBytecode,
    lockingBytecode,
    padLength,
    unlockingFloor,
  });
};

const encodeP2sUnlockingWithPad = ({ operand, floor }) => {
  const unpadded = concat(operand, encodeMinimalDataPush(new Uint8Array(0)));
  if (unpadded.length > floor) {
    return { unlockingBytecode: unpadded, padLength: 0 };
  }
  for (let padLength = 0; padLength <= floor; padLength += 1) {
    const unlocking = concat(operand, encodeMinimalDataPush(new Uint8Array(padLength)));
    if (unlocking.length === floor) return { unlockingBytecode: unlocking, padLength };
    if (unlocking.length > floor) break;
  }
  throw new TypeError('P2S unlocking cannot be padded to the density floor');
};

export const materializeBchCircleFriQ2PartitionP2s = (
  fixture,
  { unlockingFloor = PARTITION_UNLOCKING_FLOOR, clustersPerInput = 1 } = {},
) => {
  assertBatchFixture(fixture);
  const redeemBytecode = buildBchCircleFriQ2PartitionRedeemBytecode(fixture, { clustersPerInput });
  const operandUnlockingBytecode = buildBchCircleFriQ2BatchOperandUnlockingBytecode(fixture);
  const { unlockingBytecode, padLength } = encodeP2sUnlockingWithPad({
    operand: operandUnlockingBytecode,
    floor: unlockingFloor,
  });
  return Object.freeze({
    ...fixture,
    redeemBytecode,
    operandUnlockingBytecode,
    unlockingBytecode,
    lockingBytecode: redeemBytecode,
    padLength,
    unlockingFloor,
    carrier: 'p2s',
  });
};

export const encodeBchCircleFriQ2PartitionP2sTransactionFixture = (
  fixtures,
  { unlockingFloor = PARTITION_UNLOCKING_FLOOR, clustersPerInput = 1 } = {},
) => {
  require(Array.isArray(fixtures) && fixtures.length >= 1, 'q2 partition requires fixtures');
  require(
    Number.isInteger(clustersPerInput) && clustersPerInput >= 1
      && fixtures.length % clustersPerInput === 0,
    'fixtures length must be divisible by clustersPerInput',
  );
  const packedQueryIndices = clustersPerInput > 1
    ? concat(...fixtures.map((item) => item.encodedWitness.subarray(14, 22)))
    : null;
  const packedBetas = clustersPerInput > 1 ? encodePackedBetas(fixtures[0]) : null;
  const grouped = [];
  for (let index = 0; index < fixtures.length; index += clustersPerInput) {
    const slice = fixtures.slice(index, index + clustersPerInput);
    grouped.push({
      ...slice[0],
      partnerWitnesses: slice.slice(1).map((item) => item.encodedWitness),
      packedQueryIndices,
      packedBetas,
      clustersPerInput,
    });
  }
  const floorForInput = (inputIndex) => {
    if (typeof unlockingFloor === 'number') return unlockingFloor;
    if (unlockingFloor !== null && typeof unlockingFloor === 'object') {
      if (Array.isArray(unlockingFloor)) return unlockingFloor[inputIndex] ?? unlockingFloor.at(-1);
      return inputIndex === 0
        ? (unlockingFloor.input0 ?? unlockingFloor.other ?? PARTITION_UNLOCKING_FLOOR)
        : (unlockingFloor.other ?? unlockingFloor.input0 ?? PARTITION_UNLOCKING_FLOOR);
    }
    return PARTITION_UNLOCKING_FLOOR;
  };
  const materialized = grouped.map((fixture, inputIndex) => (
    materializeBchCircleFriQ2PartitionP2s(fixture, {
      unlockingFloor: floorForInput(inputIndex),
      clustersPerInput,
    })
  ));
  const sourceOutputs = materialized.map(({ lockingBytecode }) => ({
    lockingBytecode,
    valueSatoshis: 1_000n,
  }));
  const transaction = {
    version: 2,
    inputs: materialized.map(({ unlockingBytecode }, inputIndex) => ({
      outpointTransactionHash: new Uint8Array(32).fill(0x31 + (inputIndex % 200)),
      outpointIndex: inputIndex,
      sequenceNumber: 0xffff_ffff,
      unlockingBytecode,
    })),
    outputs: [{
      lockingBytecode: Uint8Array.of(OP.OP_1),
      valueSatoshis: BigInt(materialized.length) * 1_000n,
    }],
    locktime: 0,
  };
  const transactionWire = encodeTransaction(transaction);
  const sourceOutputsWire = encodeTransactionOutputs(sourceOutputs);
  return Object.freeze({
    materialized,
    transaction,
    sourceOutputs,
    transactionHex: binToHex(transactionWire),
    sourceOutputsHex: binToHex(sourceOutputsWire),
    transactionBytes: transactionWire.length,
    sourceOutputsBytes: sourceOutputsWire.length,
    transactionDigestSha256: binToHex(sha256(transactionWire)),
    sourceOutputsDigestSha256: binToHex(sha256(sourceOutputsWire)),
    carrier: 'p2s',
  });
};

export const encodeBchCircleFriQ2PartitionTransactionFixture = (
  fixtures,
  { unlockingFloor = PARTITION_UNLOCKING_FLOOR } = {},
) => {
  const wires = encodeBchCircleFriQ2BatchTransactionFixture(fixtures);
  const materialized = fixtures.map((fixture) => (
    materializeBchCircleFriQ2PartitionP2sh32(fixture, { unlockingFloor })
  ));
  const sourceOutputs = materialized.map(({ lockingBytecode }) => ({
    lockingBytecode,
    valueSatoshis: 1_000n,
  }));
  const transaction = {
    version: 2,
    inputs: materialized.map(({ unlockingBytecode }, inputIndex) => ({
      outpointTransactionHash: new Uint8Array(32).fill(0x31 + (inputIndex % 200)),
      outpointIndex: inputIndex,
      sequenceNumber: 0xffff_ffff,
      unlockingBytecode,
    })),
    outputs: [{
      lockingBytecode: Uint8Array.of(OP.OP_1),
      valueSatoshis: BigInt(materialized.length) * 1_000n,
    }],
    locktime: 0,
  };
  const transactionWire = encodeTransaction(transaction);
  const sourceOutputsWire = encodeTransactionOutputs(sourceOutputs);
  return Object.freeze({
    ...wires,
    materialized,
    transaction,
    sourceOutputs,
    transactionHex: binToHex(transactionWire),
    sourceOutputsHex: binToHex(sourceOutputsWire),
    transactionBytes: transactionWire.length,
    sourceOutputsBytes: sourceOutputsWire.length,
    transactionDigestSha256: binToHex(sha256(transactionWire)),
    sourceOutputsDigestSha256: binToHex(sha256(sourceOutputsWire)),
  });
};

export const evaluateBchCircleFriQ2PartitionTransactionFixture = (
  wires,
) => evaluateBchCircleFriQ2BatchTransactionFixture(wires);

/** Build the exact two-operand prefix; the redeem push is appended separately. */
export const buildBchCircleFriQ2BatchOperandUnlockingBytecode = (fixture) => {
  assertBatchFixture(fixture);
  const partners = fixture.partnerWitnesses ?? [];
  const packed = fixture.packedQueryIndices;
  const betas = fixture.packedBetas;
  return concat(
    encodeMinimalDataPush(fixture.publicProofDigest),
    ...(packed instanceof Uint8Array && packed.length > 0
      ? [encodeMinimalDataPush(packed)]
      : []),
    ...(betas instanceof Uint8Array && betas.length > 0
      ? [encodeMinimalDataPush(betas)]
      : []),
    encodeMinimalDataPush(fixture.encodedWitness),
    ...partners.map((witness) => encodeMinimalDataPush(witness)),
    ...(fixture.airLdeOpening instanceof Uint8Array
      ? [encodeMinimalDataPush(fixture.airLdeOpening)]
      : []),
  );
};

// The fixed redeem compiler is defined below the reusable Script fragments.
export const materializeBchCircleFriQ2BatchP2sh32 = (fixture) => {
  assertBatchFixture(fixture);
  const redeemBytecode = buildBchCircleFriQ2BatchRedeemBytecode(fixture);
  const operandUnlockingBytecode = buildBchCircleFriQ2BatchOperandUnlockingBytecode(fixture);
  const unlockingBytecode = concat(operandUnlockingBytecode, encodeMinimalDataPush(redeemBytecode));
  const lockingBytecode = encodeLockingBytecodeP2sh32(hash256(redeemBytecode));
  return Object.freeze({
    ...fixture,
    redeemBytecode,
    operandUnlockingBytecode,
    unlockingBytecode,
    lockingBytecode,
  });
};

/** Encode one complete multi-input q2-batch component transaction. */
export const encodeBchCircleFriQ2BatchTransactionFixture = (fixtures) => {
  require(Array.isArray(fixtures) && fixtures.length >= 1, 'q2 transaction requires at least one q2 fixture');
  fixtures.forEach(assertBatchFixture);
  const batchCount = publicBatchCount(fixtures[0].parameters);
  require(fixtures.length === batchCount, `q2 transaction requires exactly ${batchCount} q2 fixtures`);
  require(
    fixtures.every((fixture, index) => (
      fixture.batchOrdinal === index
      && fixture.parameters.queryCount === fixtures[0].parameters.queryCount
      && fixture.parameters.logDegreeBound === fixtures[0].parameters.logDegreeBound
      && fixture.parameters.logBlowup === fixtures[0].parameters.logBlowup
    )),
    'q2 fixtures must be ordered by batch ordinal and share one public schedule',
  );
  require(
    fixtures.every(({ publicProofDigest }) => equalBytes(publicProofDigest, fixtures[0].publicProofDigest)),
    'q2 fixtures must bind one public proof transcript',
  );
  const materialized = fixtures.map(materializeBchCircleFriQ2BatchP2sh32);
  require(
    materialized.every(({ lockingBytecode }) => equalBytes(lockingBytecode, materialized[0].lockingBytecode)),
    'q2 fixtures must share one fixed-parameter P2SH32 locking bytecode',
  );
  const sourceOutputs = materialized.map(({ lockingBytecode }) => ({
    lockingBytecode,
    valueSatoshis: 1_000n,
  }));
  const transaction = {
    version: 2,
    inputs: materialized.map(({ unlockingBytecode }, inputIndex) => ({
      outpointTransactionHash: new Uint8Array(32).fill(0x31 + (inputIndex % 200)),
      outpointIndex: inputIndex,
      sequenceNumber: 0xffff_ffff,
      unlockingBytecode,
    })),
    outputs: [{
      lockingBytecode: Uint8Array.of(OP.OP_1),
      valueSatoshis: BigInt(batchCount) * 1_000n,
    }],
    locktime: 0,
  };
  const transactionWire = encodeTransaction(transaction);
  const sourceOutputsWire = encodeTransactionOutputs(sourceOutputs);
  return Object.freeze({
    materialized,
    transaction,
    sourceOutputs,
    transactionHex: binToHex(transactionWire),
    sourceOutputsHex: binToHex(sourceOutputsWire),
    transactionBytes: transactionWire.length,
    sourceOutputsBytes: sourceOutputsWire.length,
    transactionDigestSha256: binToHex(sha256(transactionWire)),
    sourceOutputsDigestSha256: binToHex(sha256(sourceOutputsWire)),
  });
};

const isStrictSuccess = (state) => state.error === undefined
  && state.stack.length === 1
  && state.stack[0].length === 1
  && state.stack[0][0] === 1
  && state.alternateStack.length === 0
  && state.controlStack.length === 0;

/** Evaluate both active inputs using the standard BCH-2026 Libauth VM. */
export const evaluateBchCircleFriQ2BatchTransactionFixture = ({
  materialized,
  transaction,
  sourceOutputs,
}) => {
  require(Array.isArray(materialized) && materialized.length >= 1, 'materialized q2 inputs are required');
  require(Array.isArray(transaction?.inputs), 'q2 transaction inputs are required');
  require(Array.isArray(sourceOutputs), 'q2 source outputs are required');
  const vm = createVirtualMachineBch2026(true);
  return Object.freeze(materialized.map(({ lockingBytecode, unlockingBytecode }, inputIndex) => {
    const trace = vm.debug({ inputIndex, sourceOutputs, transaction }, { maskProgramState: true });
    const state = trace.at(-1);
    require(state !== undefined, 'Libauth BCH-2026 q2 debug trace is empty');
    return Object.freeze({
      inputIndex,
      accepted: isStrictSuccess(state),
      error: state.error ?? null,
      standard: true,
      metrics: Object.freeze(rawMetricProjection(state.metrics)),
      lockingHex: binToHex(lockingBytecode),
      unlockingHex: binToHex(unlockingBytecode),
    });
  }));
};

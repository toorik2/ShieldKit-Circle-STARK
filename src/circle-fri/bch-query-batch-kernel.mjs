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
  CIRCLE_FRI_QUERY_CANDIDATE_LABEL,
  assertCircleFriParameters,
  circleFriUsesCm31Fold,
  encodeCircleFriDimensionGapLambda,
  encodeCircleFriParameters,
} from './query-proof.mjs';

import {
  encodeCircleFriQ2BatchWitness,
  verifyCircleFriQ2BatchWitness,
} from './query-batch-witness.mjs';

import {
  CIRCLE_FRI_SQUEEZE_DOMAIN,
  CIRCLE_FRI_TRANSCRIPT_DOMAIN,
  absorbCircleFriTranscriptState,
  initializeCircleFriTranscriptState,
  sampleCircleFriTranscriptState,
} from './transcript.mjs';

import {
  CIRCLE_FRI_TOPOLOGY_LEAF_DOMAIN,
  buildCircleFriTopologyTable,
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
  ...invokeM31WrapSub(),
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
  ...invokeM31WrapSub(),
  OP.OP_OVER,
  OP.OP_MUL,
  ...m31Reduce(),
  OP.OP_TOALTSTACK,
  ...pushNumber(3),
  OP.OP_PICK,
  ...pushNumber(2),
  OP.OP_PICK,
  OP.OP_SUB,
  ...invokeM31WrapSub(),
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
  ...pushNumber(1),
  OP.OP_PICK,
  ...pushNumber(5),
  OP.OP_PICK,
  OP.OP_MUL,
  ...invokeM31Reduce(),
  ...pushNumber(3),
  OP.OP_PICK,
  OP.OP_ADD,
  ...invokeM31Reduce(),
  ...pushNumber(1),
  OP.OP_PICK,
  ...pushNumber(7),
  OP.OP_PICK,
  OP.OP_MUL,
  ...invokeM31Reduce(),
  OP.OP_SUB,
  ...invokeM31WrapSub(),
  OP.OP_TOALTSTACK,
  ...pushNumber(1),
  OP.OP_PICK,
  ...pushNumber(6),
  OP.OP_PICK,
  OP.OP_MUL,
  ...invokeM31Reduce(),
  ...pushNumber(4),
  OP.OP_PICK,
  OP.OP_ADD,
  ...invokeM31Reduce(),
  ...pushNumber(1),
  OP.OP_PICK,
  ...pushNumber(6),
  OP.OP_PICK,
  OP.OP_MUL,
  ...invokeM31Reduce(),
  OP.OP_ADD,
  ...invokeM31Reduce(),
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
  OP.OP_1,
  OP.OP_ROLL,
  OP.OP_TOALTSTACK,
  OP.OP_TOALTSTACK,
  OP.OP_FROMALTSTACK,
  OP.OP_FROMALTSTACK,
  OP.OP_FROMALTSTACK,
  OP.OP_FROMALTSTACK,
  OP.OP_FROMALTSTACK,

  // Adjacent π-pair Merkle leaves (2p, 2p+1) are siblings at layer 0.
  // Bit-complements still meet as the root's children.
  ...currentIndicesAreSiblings2(),
  OP.OP_IF,
  OP.OP_ELSE,
  OP.OP_BEGIN,
  ...stepBothPaths2(),
  OP.OP_FROMALTSTACK,
  OP.OP_2,
  OP.OP_DIV,
  OP.OP_TOALTSTACK,
  ...currentIndicesAreSiblings2(),
  OP.OP_UNTIL,
  OP.OP_ENDIF,
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
  OP.OP_TOALTSTACK,
  OP.OP_FROMALTSTACK,
  OP.OP_DUP,
  OP.OP_TOALTSTACK,
  OP.OP_1,
  OP.OP_NUMEQUAL,
  OP.OP_IF,
  OP.OP_ELSE,
  OP.OP_BEGIN,
  ...pushNumber(2),
  OP.OP_ROLL,
  ...pushNumber(2),
  OP.OP_ROLL,
  ...pushNumber(2),
  OP.OP_ROLL,
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
      state = sampleCircleFriTranscriptState({
        state,
        label: `fri-fold-beta-${round}-re`,
        upperBound: Number(M31_MODULUS),
      }).state;
      state = sampleCircleFriTranscriptState({
        state,
        label: `fri-fold-beta-${round}-im`,
        upperBound: Number(M31_MODULUS),
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
  const fourToOne = witness.logDegreeBound >= 8;
  const laterLayerOk = (layer, round) => {
    const length = parameters.domainLength / (2 ** round);
    return layer.values.length === 2
      || (layer.siblings.length === 0 && layer.values.length === length);
  };
  require(
    fourToOne
      ? (witness.layers[0]?.values.length === 4
        && witness.layers.slice(1).every((layer, index) => laterLayerOk(layer, index + 1)))
      : witness.layers.every((layer) => layer.values.length === 4),
    fourToOne
      ? 'q2 4-to-1 profile requires four leaves in round 0 and two-leaf or full small later rounds'
      : 'current BCH q2 profile requires four distinct authenticated leaves in every layer',
  );
  const topologyTable = buildCircleFriTopologyTable(parameters);
  require(equalBytes(witness.topology.root, topologyTable.root), 'q2 witness topology root is not canonical');
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
    topologyRoot: new Uint8Array(topologyTable.root),
    topologyRecordBytes: circleFriCodecTopologyRecordBytes(parameters),
    publicProofDigest: new Uint8Array(publicProofDigest),
    encodedWitness,
    witness,
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
  const script = [
    OP.OP_TXINPUTCOUNT,
    ...pushNumber(batchCount),
    OP.OP_NUMEQUALVERIFY,
    OP.OP_INPUTINDEX,
    OP.OP_0,
    ...pushNumber(batchCount),
    OP.OP_WITHIN,
    OP.OP_VERIFY,
    ...extractInputProofDigestPrefix(0),
  ];
  for (let inputIndex = 1; inputIndex < batchCount; inputIndex += 1) {
    script.push(
      ...extractInputProofDigestPrefix(inputIndex),
      OP.OP_OVER,
      OP.OP_EQUALVERIFY,
    );
  }
  script.push(OP.OP_DROP);
  return script;
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
  const fourToOne = parameters.logDegreeBound >= 8;
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
const packedPairSearch = () => [
  OP.OP_FROMALTSTACK,
  OP.OP_SIZE,
  OP.OP_0,
  OP.OP_NUMEQUAL,
  OP.OP_IF,
  OP.OP_1,
  OP.OP_ELSE,
  OP.OP_0,
  OP.OP_BEGIN,
  OP.OP_DUP,
  ...pushNumber(4),
  OP.OP_MUL,
  ...pushNumber(2),
  OP.OP_PICK,
  OP.OP_SWAP,
  OP.OP_SPLIT,
  OP.OP_NIP,
  ...pushNumber(4),
  OP.OP_SPLIT,
  OP.OP_DROP,
  ...decodeUnsignedTop(),
  ...pushNumber(3),
  OP.OP_PICK,
  OP.OP_NUMEQUAL,
  OP.OP_IF,
  OP.OP_DROP,
  OP.OP_0,
  OP.OP_1,
  OP.OP_ELSE,
  OP.OP_1ADD,
  OP.OP_DUP,
  ...pushNumber(6),
  OP.OP_PICK,
  OP.OP_LESSTHAN,
  OP.OP_IF,
  OP.OP_0,
  OP.OP_ELSE,
  OP.OP_DROP,
  OP.OP_1,
  OP.OP_1,
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

const packedRejectIndex = () => [
  OP.OP_TOALTSTACK,
  OP.OP_2DROP,
  ...pushNumber(2),
  OP.OP_ROLL,
  ...pushNumber(2),
  OP.OP_ROLL,
];

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
    ...packedPairSearch(),
    OP.OP_IF,
    ...packedAcceptIndex(),
    OP.OP_ELSE,
    ...packedRejectIndex(),
    OP.OP_ENDIF,
  ];
};

const buildPackedFourToOnePartnerOnce = (parameters) => [
  ...pushNumber(1),
  OP.OP_PICK,
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
  ...packedPairSearch(),
  OP.OP_VERIFY,
  ...packedAcceptIndex(),
];

const buildPackedUniqueQueryDerivation = (parameters) => {
  const { queryCount } = parameters;
  const fourToOne = parameters.logDegreeBound >= 8;
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
    ...(cm31
      ? [
          ...sampleAndEncode('-re'),
          OP.OP_TOALTSTACK,
          ...sampleAndEncode('-im'),
          OP.OP_FROMALTSTACK,
          OP.OP_SWAP,
          OP.OP_CAT,
        ]
      : sampleAndEncode('')),
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
  ...pushNumber(1),
  OP.OP_PICK,
  OP.OP_SIZE,
  OP.OP_NIP,
  ...pushNumber(parameters.logDegreeBound * (cm31 ? 8 : 4)),
  OP.OP_NUMEQUAL,
  OP.OP_UNTIL,
];

const buildTranscriptReplay = (fixture, offsets) => {
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
    ...(fixture.parameters.queryCount === 4
      ? [
          ...buildCanonicalQueryDerivationAll(fixture.parameters),
          ...buildQ4TranscriptQuerySelection(offsets),
        ]
      : [
          ...buildPackedUniqueQueryDerivation(fixture.parameters),
          ...buildPackedTranscriptQuerySelection(offsets, fixture.parameters.queryCount),
        ]),
  );
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

const buildPlanInverse = ({ queryDepth, selectedDepth, headerDepth }) => [
  ...pushNumber(queryDepth),
  OP.OP_PICK,
  ...pushNumber(selectedDepth + 1),
  OP.OP_PICK,
  OP.OP_EQUAL,
  OP.OP_IF,
  ...pushNumber(headerDepth),
  OP.OP_PICK,
  ...extractTopBytes(4, 4),
  OP.OP_ELSE,
  ...pushNumber(headerDepth),
  OP.OP_PICK,
  ...extractTopBytes(8, 4),
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
  OP.OP_2DUP,
  OP.OP_MIN,
  OP.OP_TOALTSTACK,
  OP.OP_MAX,
  OP.OP_FROMALTSTACK,
  OP.OP_SWAP,
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
  const packFolds = cm31
    ? [
        ...packCm31Top(),
        OP.OP_TOALTSTACK,
        ...packCm31Top(),
        OP.OP_FROMALTSTACK,
        OP.OP_CAT,
      ]
    : packU32Pair();
  return [
    ...sortedPairFromPlan(9 + p),
    ...packU32Pair(),
    ...pushNumber(1 + p),
    OP.OP_PICK,
    ...extractTopBytes(12, 2 * foldBytes),

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
    }),
    ...pushNumber(9 + p),
    OP.OP_PICK,
    ...foldInvoke,

    ...pushNumber(12 + p + (cm31 ? 1 : 0)),
    OP.OP_PICK,
    ...extractTopBytes(4, 4),
    ...decodeUnsignedTop(),
    ...lookup2FromPacked({
      indicesDepth: 3 + (cm31 ? 1 : 0),
      valuesDepth: 2 + (cm31 ? 1 : 0),
      valueBytes: foldBytes,
    }),
    ...pushNumber(13 + p + (cm31 ? 1 : 0)),
    OP.OP_PICK,
    ...extractTopBytes(8, 4),
    ...decodeUnsignedTop(),
    ...lookup2FromPacked({
      indicesDepth: 4 + (cm31 ? 1 : 0),
      valuesDepth: 3 + (cm31 ? 1 : 0),
      valueBytes: foldBytes,
    }),
    ...buildPlanInverse({
      queryDepth: 12 + p + (cm31 ? 1 : 0),
      selectedDepth: 10 + p + (cm31 ? 1 : 0),
      headerDepth: 5 + p + (cm31 ? 1 : 0),
    }),
    ...pushNumber(10 + p + (cm31 ? 1 : 0)),
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
  const headerBytes = cm31 ? 28 : 20;
  const valueBytes = cm31 ? 8 : 4;
  const hashLeaf = cm31 ? FUNCTION.HASH_CM31_LEAF : FUNCTION.HASH_M31_LEAF;
  return compileScript([
  // Same ABI as VERIFY_LAYER, including firstRoundFlag (always 0 here).
  ...pushNumber(9),
  OP.OP_ROLL,
  ...pushNumber(headerBytes),
  OP.OP_SPLIT,
  ...pushNumber(1),
  OP.OP_PICK,
  ...(cm31 ? [] : [
    ...extractTopBytes(0, 2),
    ...encodeMinimalDataPush(u16le(2)),
    OP.OP_EQUALVERIFY,
    ...pushNumber(1),
    OP.OP_PICK,
  ]),
  ...extractTopBytes(cm31 ? 2 : 2, 2),
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
  ...extractTopBytes(12, valueBytes),
  ...invokeFunction(hashLeaf),
  ...pushNumber(4),
  OP.OP_PICK,
  ...extractTopBytes(12 + valueBytes, valueBytes),
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

/**
 * Domain ≤16: remaining codec is a full codeword. Hash it to the layer root,
 * rebuild a 20-byte 2-leaf header, then the same fold as VERIFY_LAYER2.
 */
const buildVerifyFullLayerFunction = ({ cm31 = false } = {}) => {
  const valueBytes = cm31 ? 8 : 4;
  const widthMul = cm31 ? OP.OP_8 : OP.OP_4;
  const hashBody = cm31 ? HASH_CODEWORD_BODY_CM31 : HASH_CODEWORD_BODY;
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
  ...sortedPairFromPlan(10),
  ...domainPairToMerklePair(),
  OP.OP_DUP,
  widthMul,
  OP.OP_MUL,
  ...pushNumber(3),
  OP.OP_PICK,
  OP.OP_SWAP,
  ...extractTopBytesRuntime(valueBytes),
  OP.OP_TOALTSTACK,
  OP.OP_DROP,
  OP.OP_DUP,
  widthMul,
  OP.OP_MUL,
  ...pushNumber(2),
  OP.OP_PICK,
  OP.OP_SWAP,
  ...extractTopBytesRuntime(valueBytes),
  OP.OP_FROMALTSTACK,
  OP.OP_CAT,
  OP.OP_NIP,
  OP.OP_TOALTSTACK,
  OP.OP_DROP,
  OP.OP_DUP,
  ...extractTopBytes(4, 8),
  ...encodeMinimalDataPush(u16le(2)),
  ...encodeMinimalDataPush(u16le(0)),
  OP.OP_CAT,
  OP.OP_SWAP,
  OP.OP_CAT,
  OP.OP_FROMALTSTACK,
  OP.OP_CAT,
  OP.OP_NIP,
  OP.OP_FROMALTSTACK,
  ...invokeFunction(FUNCTION.FOLD_AFTER_MERKLE),
], 'reusable q2 full-codeword layer function');
};

const VERIFY_FULL_LAYER_FUNCTION = buildVerifyFullLayerFunction();

/** Domain <16 after a full-eval: 20-byte 2-leaf header, no merkle. */
const buildVerifyFoldOnlyFunction = ({ cm31 = false } = {}) => compileScript([
  ...pushNumber(9),
  OP.OP_ROLL,
  ...pushNumber(cm31 ? 28 : 20),
  OP.OP_SPLIT,
  OP.OP_TOALTSTACK,
  OP.OP_DUP,
  ...extractTopBytes(0, 2),
  ...encodeMinimalDataPush(u16le(2)),
  OP.OP_EQUALVERIFY,
  OP.OP_DUP,
  ...extractTopBytes(2, 2),
  ...decodeUnsignedTop(),
  OP.OP_0,
  OP.OP_NUMEQUALVERIFY,
  OP.OP_FROMALTSTACK,
  ...invokeFunction(FUNCTION.FOLD_AFTER_MERKLE),
], 'reusable q2 fold-only small layer');

const VERIFY_FOLD_ONLY_FUNCTION = buildVerifyFoldOnlyFunction();

const buildLayerInvocation = (fixture, round) => {
  const roundOffset = 14 + round * 21;
  const layerLength = fixture.parameters.domainLength / (2 ** round);
  const clustered = fixture.parameters.logDegreeBound >= 8 && round > 0;
  return [
    ...pushNumber(3),
    OP.OP_PICK,
    ...extractTopBytes(roundOffset, 21),
    ...pushNumber(3),
    OP.OP_PICK,
    ...extractTopBytes(roundOffset, 21),
    ...pushNumber(5),
    OP.OP_PICK,
    ...extractTopBytes(10, 4),
    ...pushNumber(5),
    OP.OP_PICK,
    ...extractTopBytes(10, 4),
    ...pushNumber(10),
    OP.OP_PICK,
    ...extractTopBytes(0, 4),
    ...pushNumber(12),
    OP.OP_PICK,
    ...extractTopBytes(
      round * (circleFriUsesCm31Fold(fixture.parameters) ? 8 : 4),
      circleFriUsesCm31Fold(fixture.parameters) ? 8 : 4,
    ),
    ...pushNumber(10),
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
  const foldOnly = buildVerifyFoldOnlyFunction({ cm31 });
  return [
    ...pushNumber(3),
    OP.OP_PICK,
    ...extractTopBytes(26, 4),
    ...decodeUnsignedTop(),
    ...pushNumber(3),
    OP.OP_PICK,
    ...extractTopBytes(26, 4),
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
    ...extractTopBytes(10, 4),
    ...pushNumber(5),
    OP.OP_PICK,
    ...extractTopBytes(10, 4),
    ...pushNumber(10),
    OP.OP_PICK,
    ...extractTopBytes(0, 4),
    ...pushNumber(12),
    OP.OP_PICK,
    ...copyRoundFromAlt(),
    ...pushNumber(betaBytes),
    OP.OP_MUL,
    ...extractTopBytesRuntime(betaBytes),
    ...pushNumber(10),
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
    OP.OP_0,
    ...invokeFunction(FUNCTION.VERIFY_LAYER2),
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

const compileQ2RedeemScript = (fixture, digestBinding) => {
  assertBatchFixture(fixture);
  const parameters = fixture.parameters;
  const cm31 = circleFriUsesCm31Fold(parameters);
  const feltBytes = cm31 ? 8 : 4;
  const offsets = Object.freeze({
    queryOrdinals: 10,
    queryIndices: 14,
    finalCodeword: 22,
  });
  const record0 = offsets.finalCodeword + parameters.blowup * feltBytes;
  const record1 = record0 + fixture.topologyRecordBytes;
  const afterRecords = record1 + fixture.topologyRecordBytes;
  const fixedHeader = concat(
    utf8('CFBW'),
    Uint8Array.of(3),
    encodeCircleFriParameters(parameters),
  );
  const script = [
    ...buildCommonFunctionDefinitions({ cm31 }),
    ...(cm31
      ? concat(
        defineFunction(FUNCTION.M31_WRAP_SUB, M31_WRAP_SUB_FUNCTION),
        defineFunction(FUNCTION.HASH_CM31_LEAF, HASH_CM31_LEAF_FUNCTION),
        defineFunction(FUNCTION.FOLD_M31_TO_CM31, FOLD_M31_TO_CM31_FUNCTION),
        defineFunction(FUNCTION.FOLD_CM31, FOLD_CM31_FUNCTION),
      )
      : new Uint8Array()),
    ...defineFunction(FUNCTION.VERIFY_LAYER, buildVerifyLayerFunction({ toCm31: cm31 })),
    ...(parameters.logDegreeBound >= 8
      ? concat(
        defineFunction(FUNCTION.VERIFY_LAYER2, buildVerifyLayer2Function({ cm31 })),
        defineFunction(FUNCTION.TRANSCRIPT_LAYER, buildTranscriptLayerFunction({ cm31 })),
        defineFunction(FUNCTION.FOLD_AFTER_MERKLE, compileScript(
          buildLayer2FoldAfter({ parked: false, cm31 }),
          'q2 fold after merkle',
        )),
        defineFunction(FUNCTION.VERIFY_FULL_LAYER, buildVerifyFullLayerFunction({ cm31 })),
        defineFunction(FUNCTION.PACK_LATER_PLAN, PACK_LATER_PLAN_FUNCTION),
      )
      : []),
    ...digestBinding,
    OP.OP_DUP,
    ...extractTopBytes(0, fixedHeader.length),
    ...encodeMinimalDataPush(fixedHeader),
    OP.OP_EQUALVERIFY,
    // Roots live in redeem. Park the blob under the witness (no full-witness CAT).
    ...encodeMinimalDataPush(concat(...fixture.witness.roots)),
    OP.OP_SWAP,
    ...buildTranscriptReplay(fixture, offsets),
    ...pushNumber(2),
    OP.OP_PICK,
    ...extractTopBytes(offsets.finalCodeword, parameters.blowup * feltBytes),
    ...buildFinalConstantValidation(parameters.blowup, { cm31 }),
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
          ...pushNumber(5),
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
          ...pushNumber(5),
          OP.OP_PICK,
          OP.OP_EQUALVERIFY,
        ]
      : [
          ...invokeFunction(FUNCTION.DECODE_M31),
          ...pushNumber(5),
          OP.OP_PICK,
          OP.OP_NUMEQUALVERIFY,
        ]),
    OP.OP_2DROP,
    OP.OP_2DROP,
    OP.OP_2DROP,
    OP.OP_2DROP,
    OP.OP_1,
  );
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

const buildInput0OnlyDigestBinding = (batchCount) => [
  OP.OP_TXINPUTCOUNT,
  ...pushNumber(batchCount),
  OP.OP_NUMEQUALVERIFY,
  OP.OP_INPUTINDEX,
  OP.OP_0,
  ...pushNumber(batchCount),
  OP.OP_WITHIN,
  OP.OP_VERIFY,
  OP.OP_DROP,
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

export const buildBchCircleFriQ2PartitionRedeemBytecode = (fixture) => compileQ2RedeemScript(
  fixture,
  buildInput0OnlyDigestBinding(publicBatchCount(fixture.parameters)),
);

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
  { unlockingFloor = PARTITION_UNLOCKING_FLOOR } = {},
) => {
  assertBatchFixture(fixture);
  const redeemBytecode = buildBchCircleFriQ2PartitionRedeemBytecode(fixture);
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
  { unlockingFloor = PARTITION_UNLOCKING_FLOOR } = {},
) => {
  const materialized = fixtures.map((fixture) => (
    materializeBchCircleFriQ2PartitionP2s(fixture, { unlockingFloor })
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
  return concat(
    encodeMinimalDataPush(fixture.publicProofDigest),
    encodeMinimalDataPush(fixture.encodedWitness),
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

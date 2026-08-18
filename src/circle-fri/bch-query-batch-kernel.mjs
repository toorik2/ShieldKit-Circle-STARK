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
  decodeFixedM31Top,
  encodeM31,
  rawMetricProjection,
} from '../../research-lanes/bch-shielded-pool-design/p2/bch-kernels/m31-kernel.mjs';

import {
  M31_MODULUS,
} from '../../research-lanes/bch-shielded-pool-design/p2/reference/m31.mjs';

import {
  M31_MERKLE_LEAF_DOMAIN,
  M31_MERKLE_NODE_DOMAIN,
} from './commitment.mjs';

import {
  buildBchM31Multiproof4VerificationBytecode,
} from './bch-multiproof4-kernel.mjs';

import {
  CIRCLE_FRI_QUERY_CANDIDATE_LABEL,
  assertCircleFriParameters,
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
  OP_1ADD: 0x8b,
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
  require(Number.isSafeInteger(identifier) && identifier >= 1 && identifier <= 16, 'function identifier is out of range');
  return Uint8Array.of(0x50 + identifier);
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

const decodeUnsignedTop = () => [
  ...encodeMinimalDataPush(ZERO_BYTE),
  OP.OP_CAT,
  OP.OP_BIN2NUM,
];

const framePrefix = (label, payloadLength) => {
  const labelBytes = utf8(label);
  return concat(u16le(labelBytes.length), labelBytes, u32le(payloadLength));
};

const HASH_NODE_FUNCTION = compileScript([
  OP.OP_1,
  OP.OP_PICK,
  OP.OP_SIZE,
  ...pushNumber(32),
  OP.OP_NUMEQUALVERIFY,
  OP.OP_DROP,
  OP.OP_SIZE,
  ...pushNumber(32),
  OP.OP_NUMEQUALVERIFY,
  OP.OP_CAT,
  ...encodeMinimalDataPush(M31_MERKLE_NODE_DOMAIN),
  OP.OP_SWAP,
  OP.OP_CAT,
  OP.OP_HASH256,
], 'hash-node function');

const HASH_M31_LEAF_FUNCTION = compileScript([
  OP.OP_DUP,
  ...decodeFixedM31Top(),
  OP.OP_DROP,
  ...encodeMinimalDataPush(M31_MERKLE_LEAF_DOMAIN),
  OP.OP_SWAP,
  OP.OP_CAT,
  OP.OP_HASH256,
], 'hash-M31-leaf function');

const DECODE_M31_FUNCTION = compileScript(decodeFixedM31Top(), 'decode-M31 function');

const FOLD_M31_FUNCTION = compileScript([
  // Input: left, right, inverse(2*x), x, beta.
  OP.OP_TOALTSTACK,
  OP.OP_1,
  OP.OP_PICK,
  OP.OP_1,
  OP.OP_PICK,
  OP.OP_2,
  OP.OP_MUL,
  OP.OP_MUL,
  ...pushNumber(M31_MODULUS),
  OP.OP_MOD,
  OP.OP_1,
  OP.OP_NUMEQUALVERIFY,
  OP.OP_DROP,
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
  OP.OP_2,
  OP.OP_ROLL,
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
  ...pushNumber(2),
  OP.OP_ROLL,
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
  OP.OP_0,
  OP.OP_GREATERTHANOREQUAL,
  OP.OP_VERIFY,
  ...pushNumber(3),
  OP.OP_PICK,
  OP.OP_0,
  OP.OP_GREATERTHANOREQUAL,
  OP.OP_VERIFY,
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
  ...pushNumber(4),
  OP.OP_PICK,
  ...pushNumber(4),
  OP.OP_PICK,
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
  ...popFrontierAndHashStep2(),
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

const FUNCTION_DEFINITIONS = concat(
  defineFunction(FUNCTION.HASH_NODE, HASH_NODE_FUNCTION),
  defineFunction(FUNCTION.DECODE_M31, DECODE_M31_FUNCTION),
  defineFunction(FUNCTION.FOLD_M31, FOLD_M31_FUNCTION),
  defineFunction(FUNCTION.SAMPLE_TRANSCRIPT, SAMPLE_TRANSCRIPT_FUNCTION),
  defineFunction(FUNCTION.SAMPLE_M31_TRANSCRIPT, SAMPLE_M31_TRANSCRIPT_FUNCTION),
  defineFunction(FUNCTION.HASH_M31_LEAF, HASH_M31_LEAF_FUNCTION),
  defineFunction(FUNCTION.LOOKUP4, LOOKUP4_FUNCTION),
  defineFunction(FUNCTION.MULTIPROOF4, buildBchM31Multiproof4VerificationBytecode()),
  defineFunction(FUNCTION.HASHED_MULTIPROOF2, HASHED_MULTIPROOF2_FUNCTION),
  defineFunction(FUNCTION.SORT4, SORT4_FUNCTION),
);

const encodeFinalCodeword = (values) => concat(...values.map(encodeM31));

const derivePublicProofDigest = ({ witness, parameters, protocolContext }) => {
  let state = initializeCircleFriTranscriptState(protocolContext);
  state = absorbCircleFriTranscriptState(state, 'fri-parameters', encodeCircleFriParameters(parameters));
  for (let round = 0; round < parameters.logDegreeBound; round += 1) {
    state = absorbCircleFriTranscriptState(state, `fri-layer-root-${round}`, witness.roots[round]);
    state = sampleCircleFriTranscriptState({
      state,
      label: `fri-fold-beta-${round}`,
      upperBound: Number(M31_MODULUS),
    }).state;
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
  require(
    witness.layers.every((layer) => layer.values.length === 4),
    'current BCH q2 profile requires four distinct authenticated leaves in every layer',
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
    topologyRecordBytes: circleFriTopologyRecordBytes(parameters),
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

const buildCanonicalQueryDerivationAll = (parameters) => {
  const script = [];
  for (let query = 0; query < parameters.queryCount; query += 1) {
    if (query > 0) script.push(OP.OP_BEGIN);
    script.push(...buildTranscriptChallenge({
      label: CIRCLE_FRI_QUERY_CANDIDATE_LABEL,
      upperBound: parameters.domainLength,
    }));
    if (query > 0) {
      script.push(OP.OP_1);
      for (let prior = 0; prior < query; prior += 1) {
        script.push(
          OP.OP_OVER,
          OP.OP_DUP,
          ...pushNumber(parameters.firstFoldPairCount),
          OP.OP_LESSTHAN,
          OP.OP_IF,
          OP.OP_ELSE,
          ...pushNumber(parameters.domainLength - 1),
          OP.OP_SWAP,
          OP.OP_SUB,
          OP.OP_ENDIF,
          ...pushNumber(query + 3 - prior),
          OP.OP_PICK,
          OP.OP_DUP,
          ...pushNumber(parameters.firstFoldPairCount),
          OP.OP_LESSTHAN,
          OP.OP_IF,
          OP.OP_ELSE,
          ...pushNumber(parameters.domainLength - 1),
          OP.OP_SWAP,
          OP.OP_SUB,
          OP.OP_ENDIF,
          OP.OP_NUMNOTEQUAL,
          OP.OP_MUL,
        );
      }
      script.push(
        OP.OP_IF,
        OP.OP_1,
        OP.OP_ELSE,
        OP.OP_DROP,
        OP.OP_0,
        OP.OP_ENDIF,
        OP.OP_UNTIL,
      );
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
const buildPackedUniqueQueryDerivation = (parameters) => {
  const { queryCount, domainLength, firstFoldPairCount } = parameters;
  const firstFoldTop = () => [
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
  ];
  return [
    ...encodeMinimalDataPush(new Uint8Array()),
    OP.OP_TOALTSTACK,
    ...encodeMinimalDataPush(new Uint8Array()),
    OP.OP_0,
    OP.OP_BEGIN,
    ...pushNumber(2),
    OP.OP_ROLL,
    ...buildTranscriptChallenge({
      label: CIRCLE_FRI_QUERY_CANDIDATE_LABEL,
      upperBound: domainLength,
    }),
    ...firstFoldTop(),
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
    OP.OP_IF,
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
    OP.OP_ELSE,
    OP.OP_TOALTSTACK,
    OP.OP_2DROP,
    ...pushNumber(2),
    OP.OP_ROLL,
    ...pushNumber(2),
    OP.OP_ROLL,
    OP.OP_ENDIF,
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
    // The codec's two ordinals are fixed by this active input's batch ordinal.
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

const buildTranscriptReplay = (fixture, offsets) => {
  const script = [
    OP.OP_0,
    ...buildTranscriptInitialization({
      protocolContext: fixture.protocolContext,
      parameters: fixture.parameters,
    }),
  ];
  for (let round = 0; round < fixture.parameters.logDegreeBound; round += 1) {
    script.push(
      ...pushNumber(2),
      OP.OP_PICK,
      ...extractTopBytes(offsets.roots + round * 32, 32),
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
  script.push(
    ...pushNumber(2),
    OP.OP_PICK,
    ...extractTopBytes(offsets.finalCodeword, fixture.parameters.blowup * 4),
    ...buildTranscriptAbsorbRuntime('fri-final-codeword', fixture.parameters.blowup * 4),
    OP.OP_DUP,
    ...pushNumber(4),
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

/** Input: the fixed-width final codeword. Output: its canonical constant. */
const buildFinalConstantValidation = (blowup) => {
  const script = [
    OP.OP_DUP,
    ...extractTopBytes(0, 4),
    ...invokeFunction(FUNCTION.DECODE_M31),
    OP.OP_TOALTSTACK,
  ];
  for (let index = 1; index < blowup; index += 1) {
    script.push(
      OP.OP_DUP,
      ...extractTopBytes(index * 4, 4),
      OP.OP_1,
      OP.OP_PICK,
      ...extractTopBytes(0, 4),
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
const buildTopologyVerification = (fixture) => [
  // The authenticated records are sorted; bind their index set to this batch.
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

  // Parse the exact topology frontier, leaving the first layer remainder.
  ...buildCountedFrontierSplit(),

  // Construct the two runtime leaf hashes and invoke the fixed-root verifier.
  ...pushNumber(3),
  OP.OP_PICK,
  ...extractTopBytes(10, 4),
  ...decodeUnsignedTop(),
  ...pushNumber(3),
  OP.OP_PICK,
  ...extractTopBytes(10, 4),
  ...decodeUnsignedTop(),
  ...pushNumber(5),
  OP.OP_PICK,
  ...hashTopologyRecord(fixture.topologyRecordBytes),
  ...pushNumber(5),
  OP.OP_PICK,
  ...hashTopologyRecord(fixture.topologyRecordBytes),
  ...pushNumber(4),
  OP.OP_ROLL,
  OP.OP_TOALTSTACK,
  OP.OP_TOALTSTACK,
  OP.OP_TOALTSTACK,
  OP.OP_TOALTSTACK,
  OP.OP_TOALTSTACK,
  ...pushNumber(fixture.parameters.domainLength),
  ...encodeMinimalDataPush(fixture.topologyRoot),
  OP.OP_FROMALTSTACK,
  OP.OP_FROMALTSTACK,
  OP.OP_FROMALTSTACK,
  OP.OP_FROMALTSTACK,
  OP.OP_FROMALTSTACK,
  ...invokeFunction(FUNCTION.HASHED_MULTIPROOF2),
  OP.OP_VERIFY,
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
const VERIFY_LAYER_FUNCTION = compileScript([
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

  // Suffix now ends header, followingCodec, frontier.
  ...buildSortedPlanIndices({ plan0Depth: 11, plan1Depth: 10 }),
  ...[0, 1, 2, 3].flatMap((value) => [
    ...pushNumber(6 + value),
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
  ...pushNumber(4),
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
  ...pushNumber(13),
  OP.OP_PICK,
  ...invokeFunction(FUNCTION.MULTIPROOF4),
  OP.OP_VERIFY,

  // Pack the authenticated sorted index/value table for both fold chains.
  ...buildSortedPlanIndices({ plan0Depth: 10, plan1Depth: 9 }),
  ...packSortedIndices(),
  ...pushNumber(2),
  OP.OP_PICK,
  ...extractTopBytes(12, 16),

  // Non-initial layers must continue from both prior authenticated folds.
  ...pushNumber(4),
  OP.OP_PICK,
  OP.OP_IF,
  OP.OP_ELSE,
  ...lookupRecordValue({ recordDepth: 12, fieldOffset: 0, indicesDepth: 1, valuesDepth: 0 }),
  ...pushNumber(14),
  OP.OP_PICK,
  ...extractTopBytes(0, 4),
  ...invokeFunction(FUNCTION.DECODE_M31),
  OP.OP_NUMEQUALVERIFY,
  ...lookupRecordValue({ recordDepth: 11, fieldOffset: 0, indicesDepth: 1, valuesDepth: 0 }),
  ...pushNumber(14),
  OP.OP_PICK,
  ...extractTopBytes(4, 4),
  ...invokeFunction(FUNCTION.DECODE_M31),
  OP.OP_NUMEQUALVERIFY,
  OP.OP_ENDIF,

  // Fold authenticated record 0.
  ...lookupRecordValue({ recordDepth: 12, fieldOffset: 4, indicesDepth: 1, valuesDepth: 0 }),
  ...lookupRecordValue({ recordDepth: 13, fieldOffset: 8, indicesDepth: 2, valuesDepth: 1 }),
  ...buildPlanInverse({ queryDepth: 12, selectedDepth: 10, headerDepth: 5 }),
  ...pushNumber(15),
  OP.OP_PICK,
  ...extractTopBytes(16, 4),
  ...invokeFunction(FUNCTION.DECODE_M31),
  ...pushNumber(11),
  OP.OP_PICK,
  ...invokeFunction(FUNCTION.DECODE_M31),
  ...invokeFunction(FUNCTION.FOLD_M31),

  // Fold authenticated record 1.
  ...lookupRecordValue({ recordDepth: 12, fieldOffset: 4, indicesDepth: 2, valuesDepth: 1 }),
  ...lookupRecordValue({ recordDepth: 13, fieldOffset: 8, indicesDepth: 3, valuesDepth: 2 }),
  ...buildPlanInverse({ queryDepth: 12, selectedDepth: 11, headerDepth: 6 }),
  ...pushNumber(15),
  OP.OP_PICK,
  ...extractTopBytes(16, 4),
  ...invokeFunction(FUNCTION.DECODE_M31),
  ...pushNumber(12),
  OP.OP_PICK,
  ...invokeFunction(FUNCTION.DECODE_M31),
  ...invokeFunction(FUNCTION.FOLD_M31),

  ...pushNumber(4),
  OP.OP_NUM2BIN,
  OP.OP_TOALTSTACK,
  ...pushNumber(4),
  OP.OP_NUM2BIN,
  OP.OP_FROMALTSTACK,
  OP.OP_CAT,
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
], 'reusable q2 layer function');

const buildLayerInvocation = (fixture, round) => {
  const roundOffset = 14 + round * 21;
  const layerLength = fixture.parameters.domainLength / (2 ** round);
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
    ...extractTopBytes(round * 4, 4),
    ...pushNumber(10),
    OP.OP_PICK,
    ...extractTopBytes(round * 32, 32),
    ...pushNumber(layerLength),
    ...(round === 0 ? [OP.OP_1] : [OP.OP_0]),
    ...invokeFunction(FUNCTION.VERIFY_LAYER),
  ];
};

const compileQ2RedeemScript = (fixture, digestBinding) => {
  assertBatchFixture(fixture);
  const parameters = fixture.parameters;
  const offsets = Object.freeze({
    queryOrdinals: 10,
    queryIndices: 14,
    roots: 22,
    finalCodeword: 22 + parameters.logDegreeBound * 32,
  });
  const topologyRoot = offsets.finalCodeword + parameters.blowup * 4;
  const record0 = topologyRoot + 32;
  const record1 = record0 + fixture.topologyRecordBytes;
  const afterRecords = record1 + fixture.topologyRecordBytes;
  const fixedHeader = concat(
    utf8('CFBW'),
    Uint8Array.of(1),
    encodeCircleFriParameters(parameters),
  );
  const script = [
    ...FUNCTION_DEFINITIONS,
    ...defineFunction(FUNCTION.VERIFY_LAYER, VERIFY_LAYER_FUNCTION),
    ...digestBinding,
    OP.OP_DUP,
    ...extractTopBytes(0, fixedHeader.length),
    ...encodeMinimalDataPush(fixedHeader),
    OP.OP_EQUALVERIFY,
    ...buildTranscriptReplay(fixture, offsets),
    ...pushNumber(2),
    OP.OP_PICK,
    ...extractTopBytes(offsets.finalCodeword, parameters.blowup * 4),
    ...buildFinalConstantValidation(parameters.blowup),
    ...pushNumber(3),
    OP.OP_PICK,
    ...extractTopBytes(offsets.roots, parameters.logDegreeBound * 32),
    ...pushNumber(4),
    OP.OP_PICK,
    ...extractTopBytes(record0, fixture.topologyRecordBytes),
    ...pushNumber(5),
    OP.OP_PICK,
    ...extractTopBytes(record1, fixture.topologyRecordBytes),
    ...pushNumber(6),
    OP.OP_PICK,
    ...extractTopBytes(topologyRoot, 32),
    ...encodeMinimalDataPush(fixture.topologyRoot),
    OP.OP_EQUALVERIFY,
    ...pushNumber(6),
    OP.OP_ROLL,
    ...pushNumber(afterRecords),
    OP.OP_SPLIT,
    OP.OP_SWAP,
    OP.OP_DROP,
    ...pushNumber(7),
    OP.OP_ROLL,
    OP.OP_DROP,
    ...buildTopologyVerification(fixture),
    OP.OP_0,
    OP.OP_SWAP,
  ];
  for (let round = 0; round < parameters.logDegreeBound; round += 1) {
    script.push(...buildLayerInvocation(fixture, round));
  }
  script.push(
    OP.OP_SIZE,
    OP.OP_0,
    OP.OP_NUMEQUALVERIFY,
    OP.OP_DROP,
    OP.OP_DUP,
    ...extractTopBytes(0, 4),
    ...invokeFunction(FUNCTION.DECODE_M31),
    ...pushNumber(5),
    OP.OP_PICK,
    OP.OP_NUMEQUALVERIFY,
    OP.OP_DUP,
    ...extractTopBytes(4, 4),
    ...invokeFunction(FUNCTION.DECODE_M31),
    ...pushNumber(5),
    OP.OP_PICK,
    OP.OP_NUMEQUALVERIFY,
    OP.OP_2DROP,
    OP.OP_2DROP,
    OP.OP_2DROP,
    OP.OP_DROP,
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

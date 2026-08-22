/**
 * On-chain Poseidon2 AIR residual C/Z=Q at the transcript zeta LDE opening.
 *
 * Host identity (poseidon2-air evaluateAirConstraintComposition + π^9(x)):
 *   C = Σ_phase sel_phase Σ_col β_col (next[col] - snapshot_phase(state)[col])
 *     + absorb-fresh + absorb-cont + public binds
 *   Q = C * inv(π^9(x))
 *
 * Round constants stay in the DEFINE payload (public Grain constants).
 * Residual DEFINEs live in the shared redeem (consensus MAX_SCRIPT_SIZE
 * 10000). HASH256 collision of the DEFINE body is the same as any other
 * redeem byte.
 */

import {
  M31_MODULUS,
  add,
  encodeM31,
  inverse,
  mul,
  sub,
} from '../../research-lanes/bch-shielded-pool-design/p2/reference/m31.mjs';

import {
  concatBytes,
} from './bytes.mjs';

import {
  POSEIDON2_RATE,
  POSEIDON2_ROUNDS,
  POSEIDON2_ROUND_CONSTANTS,
  POSEIDON2_T,
  applyPoseidon2External,
  nextPoseidon2Snapshot,
} from './poseidon2-m31.mjs';

export const FUNCTION_AIR_POW5 = 26;
export const FUNCTION_AIR_SNAPSHOT = 27;
export const FUNCTION_AIR_RESIDUAL = 28;
export const FUNCTION_AIR_ACCUM16 = 29;

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
  OP_2DROP: 0x6d,
  OP_2DUP: 0x6e,
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
  OP_NUMEQUAL: 0x9c,
  OP_NUMEQUALVERIFY: 0x9d,
  OP_LESSTHAN: 0x9f,
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

const invokeFunction = (identifier) => concat(
  pushFunctionId(identifier),
  Uint8Array.of(OP.OP_INVOKE),
);

const compileScript = (script, name = 'compiled script') => {
  require(Array.isArray(script), `${name} must be an array`);
  require(
    script.every((byte) => Number.isInteger(byte) && byte >= 0 && byte <= 0xff),
    `${name} contains an invalid or undefined byte`,
  );
  return Uint8Array.from(script);
};

const flatten = (parts) => {
  const bytes = [];
  for (const part of parts) {
    if (part instanceof Uint8Array) bytes.push(...part);
    else if (Array.isArray(part)) bytes.push(...flatten(part));
    else bytes.push(part);
  }
  return bytes;
};

const compile = (parts, name) => compileScript(flatten(parts), name);

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

/** TOS x → x^5. */
export const buildPow5Function = () => compile([
  OP.OP_DUP,
  OP.OP_DUP,
  OP.OP_MUL,
  ...m31Reduce(),
  OP.OP_DUP,
  OP.OP_MUL,
  ...m31Reduce(),
  OP.OP_MUL,
  ...m31Reduce(),
], 'air pow5');

/**
 * TOS packed 64-byte state, index 0..15 → cell ScriptNum. Consumes both.
 */
const decodeU8 = () => [
  OP.OP_0,
  ...pushNumber(1),
  OP.OP_NUM2BIN,
  OP.OP_CAT,
  OP.OP_BIN2NUM,
];

const decodeU32leAdd = () => [
  ...pushNumber(1),
  OP.OP_SPLIT,
  OP.OP_SWAP,
  ...decodeU8(),
  OP.OP_SWAP,
  ...pushNumber(1),
  OP.OP_SPLIT,
  OP.OP_SWAP,
  ...decodeU8(),
  OP.OP_SWAP,
  ...pushNumber(1),
  OP.OP_SPLIT,
  OP.OP_SWAP,
  ...decodeU8(),
  OP.OP_SWAP,
  ...decodeU8(),
  ...pushNumber(1 << 24),
  OP.OP_MUL,
  OP.OP_SWAP,
  ...pushNumber(1 << 16),
  OP.OP_MUL,
  OP.OP_ADD,
  OP.OP_SWAP,
  ...pushNumber(1 << 8),
  OP.OP_MUL,
  OP.OP_ADD,
  OP.OP_ADD,
];

const extractPackedCell = () => [
  ...pushNumber(4),
  OP.OP_MUL,
  OP.OP_DUP,
  OP.OP_NOT,
  OP.OP_IF,
  OP.OP_DROP,
  OP.OP_ELSE,
  OP.OP_SPLIT,
  OP.OP_SWAP,
  OP.OP_DROP,
  OP.OP_ENDIF,
  ...pushNumber(4),
  OP.OP_SPLIT,
  OP.OP_DROP,
  OP.OP_BIN2NUM,
];

/** TOS packed → 16 ScriptNums, s0 at bottom, s15 on TOS. Consumes packed. */
const unpackState = () => {
  const script = [];
  for (let index = 0; index < POSEIDON2_T; index += 1) {
    script.push(
      ...pushNumber(4),
      OP.OP_SPLIT,
      OP.OP_SWAP,
      OP.OP_BIN2NUM,
      OP.OP_SWAP,
    );
  }
  script.push(OP.OP_DROP);
  return script;
};

/** TOS s15 .. bottom s0 → packed 64 bytes. */
const packState = () => {
  const script = [];
  for (let index = 0; index < POSEIDON2_T; index += 1) {
    script.push(
      ...pushNumber(4),
      OP.OP_NUM2BIN,
      OP.OP_TOALTSTACK,
    );
  }
  script.push(OP.OP_FROMALTSTACK);
  for (let index = 1; index < POSEIDON2_T; index += 1) {
    script.push(OP.OP_FROMALTSTACK, OP.OP_CAT);
  }
  return script;
};

/** Packed TOS → sum of 16 cells under the packed blob: packed, sum. */
const packedSum = () => {
  const script = [OP.OP_0];
  for (let index = 0; index < POSEIDON2_T; index += 1) {
    script.push(
      OP.OP_OVER,
      ...pushNumber(index),
      ...extractPackedCell(),
      OP.OP_ADD,
      ...m31Reduce(),
    );
  }
  return script;
};

/** Packed TOS → packed after circ(2,1,…,1). */
const applyExternalPacked = () => {
  const script = [...packedSum(), OP.OP_SWAP, OP.OP_TOALTSTACK, OP.OP_0];
  for (let index = 0; index < POSEIDON2_T; index += 1) {
    script.push(
      OP.OP_FROMALTSTACK,
      OP.OP_DUP,
      OP.OP_TOALTSTACK,
      ...pushNumber(index),
      ...extractPackedCell(),
      ...pushNumber(2),
      OP.OP_PICK,
      OP.OP_ADD,
      ...m31Reduce(),
      ...pushNumber(4),
      OP.OP_NUM2BIN,
      OP.OP_CAT,
    );
  }
  script.push(OP.OP_NIP, OP.OP_FROMALTSTACK, OP.OP_DROP);
  return script;
};

/** Packed TOS → packed after internal sparse mix. */
const applyInternalPacked = () => {
  const script = [
    ...packedSum(),
    OP.OP_OVER,
    ...pushNumber(0),
    ...extractPackedCell(),
    OP.OP_DUP,
    OP.OP_TOALTSTACK,
    OP.OP_SWAP,
    OP.OP_OVER,
    OP.OP_ADD,
    ...m31Reduce(),
    OP.OP_NIP,
    OP.OP_TOALTSTACK,
    OP.OP_0,
    OP.OP_FROMALTSTACK,
    ...pushNumber(4),
    OP.OP_NUM2BIN,
    OP.OP_CAT,
    OP.OP_FROMALTSTACK,
    OP.OP_DUP,
    OP.OP_TOALTSTACK,
  ];
  for (let index = 1; index < POSEIDON2_T; index += 1) {
    script.push(
      ...pushNumber(2),
      OP.OP_PICK,
      ...pushNumber(index),
      ...extractPackedCell(),
      OP.OP_OVER,
      OP.OP_ADD,
      ...m31Reduce(),
      ...pushNumber(4),
      OP.OP_NUM2BIN,
      OP.OP_SWAP,
      OP.OP_TOALTSTACK,
      OP.OP_CAT,
      OP.OP_FROMALTSTACK,
    );
  }
  script.push(OP.OP_DROP, OP.OP_NIP, OP.OP_FROMALTSTACK, OP.OP_DROP);
  return script;
};

/** 16 state nums (s15 TOS). Replaces with mixed state (circ 2,1,…,1). */
const applyExternalNums = () => {
  const script = [OP.OP_0];
  for (let index = 0; index < POSEIDON2_T; index += 1) {
    script.push(...pushNumber(index + 1), OP.OP_PICK, OP.OP_ADD);
  }
  for (let index = 0; index < POSEIDON2_T; index += 1) {
    script.push(OP.OP_SWAP, OP.OP_OVER, OP.OP_ADD, ...m31Reduce(), OP.OP_TOALTSTACK);
  }
  script.push(OP.OP_DROP);
  for (let index = 0; index < POSEIDON2_T; index += 1) script.push(OP.OP_FROMALTSTACK);
  return script;
};

/** 16 state nums (s15 TOS). Internal sparse mix. */
const applyInternalNums = () => {
  const script = [OP.OP_0];
  for (let index = 0; index < POSEIDON2_T; index += 1) {
    script.push(...pushNumber(index + 1), OP.OP_PICK, OP.OP_ADD);
  }
  script.push(
    ...pushNumber(POSEIDON2_T),
    OP.OP_PICK,
    OP.OP_ADD,
    ...m31Reduce(),
  );
  for (let index = 0; index < POSEIDON2_T; index += 1) {
    script.push(OP.OP_SWAP, OP.OP_TOALTSTACK);
  }
  for (let index = 0; index < POSEIDON2_T; index += 1) script.push(OP.OP_FROMALTSTACK);
  for (let index = 0; index < POSEIDON2_T - 1; index += 1) {
    script.push(
      ...pushNumber(POSEIDON2_T - 1 - index),
      OP.OP_PICK,
      OP.OP_ADD,
      ...m31Reduce(),
      OP.OP_TOALTSTACK,
    );
  }
  script.push(OP.OP_DROP);
  for (let index = 0; index < POSEIDON2_T - 1; index += 1) script.push(OP.OP_FROMALTSTACK);
  return script;
};

/** TOS 16 nums s15. One snapshot phase, leave 16 expected nums. Immediate Grain RC. */
const snapshotPhaseNums = (phase) => {
  const half = 4;
  if (phase < half || phase >= half + 14) {
    const start = phase < half
      ? phase * POSEIDON2_T
      : (half * POSEIDON2_T) + 14 + ((phase - half - 14) * POSEIDON2_T);
    const script = [];
    for (let col = POSEIDON2_T - 1; col >= 0; col -= 1) {
      script.push(
        ...pushNumber(POSEIDON2_ROUND_CONSTANTS[start + col]),
        OP.OP_ADD,
        ...m31Reduce(),
        ...invokeFunction(FUNCTION_AIR_POW5),
        OP.OP_TOALTSTACK,
      );
    }
    for (let col = 0; col < POSEIDON2_T; col += 1) script.push(OP.OP_FROMALTSTACK);
    script.push(...applyExternalNums());
    return script;
  }
  const cursor = (half * POSEIDON2_T) + (phase - half);
  const script = [];
  for (let index = 0; index < POSEIDON2_T - 1; index += 1) script.push(OP.OP_TOALTSTACK);
  script.push(
    ...pushNumber(POSEIDON2_ROUND_CONSTANTS[cursor]),
    OP.OP_ADD,
    ...m31Reduce(),
    ...invokeFunction(FUNCTION_AIR_POW5),
  );
  for (let index = 0; index < POSEIDON2_T - 1; index += 1) script.push(OP.OP_FROMALTSTACK);
  script.push(...applyInternalNums());
  return script;
};

/** INVOKE: TOS phase, 16 nums → 16 expected. */
const buildSnapshotNumsFunction = () => {
  const branches = [];
  for (let phase = 0; phase < POSEIDON2_ROUNDS; phase += 1) {
    branches.push(
      OP.OP_DUP,
      ...pushNumber(phase),
      OP.OP_NUMEQUAL,
      OP.OP_IF,
      OP.OP_DROP,
      ...snapshotPhaseNums(phase),
      OP.OP_ELSE,
    );
  }
  branches.push(OP.OP_DROP, OP.OP_VERIFY);
  for (let phase = 0; phase < POSEIDON2_ROUNDS; phase += 1) branches.push(OP.OP_ENDIF);
  return compile(branches, 'air snapshot nums');
};

const copy16 = () => {
  const script = [];
  for (let index = 0; index < POSEIDON2_T; index += 1) {
    script.push(...pushNumber(POSEIDON2_T - 1), OP.OP_PICK);
  }
  return script;
};

const drop16 = () => {
  const script = [];
  for (let index = 0; index < POSEIDON2_T / 2; index += 1) script.push(OP.OP_2DROP);
  return script;
};

const RC_BLOB = concatBytes(...POSEIDON2_ROUND_CONSTANTS.map((value) => encodeM31(value)));

const lookupRc = () => [
  ...encodeMinimalDataPush(RC_BLOB),
  OP.OP_SWAP,
  ...extractPackedCell(),
];

/** TOS packed, cursor → packed after 16 s-boxes + external mix. */
const fullRoundFromCursor = () => {
  const script = [
    ...encodeMinimalDataPush(RC_BLOB),
    OP.OP_ROT,
    ...unpackState(),
  ];
  for (let col = POSEIDON2_T - 1; col >= 0; col -= 1) {
    script.push(
      ...pushNumber(col + 2),
      OP.OP_PICK,
      ...pushNumber(col),
      OP.OP_ADD,
      ...pushNumber(col + 2),
      OP.OP_PICK,
      OP.OP_SWAP,
      ...extractPackedCell(),
      OP.OP_ADD,
      ...m31Reduce(),
      ...invokeFunction(FUNCTION_AIR_POW5),
      OP.OP_TOALTSTACK,
    );
  }
  script.push(OP.OP_2DROP);
  for (let col = 0; col < POSEIDON2_T; col += 1) script.push(OP.OP_FROMALTSTACK);
  script.push(...applyExternalNums(), ...packState());
  return script;
};

const partialRoundFromCursor = () => [
  OP.OP_TOALTSTACK,
  OP.OP_DUP,
  ...pushNumber(0),
  ...extractPackedCell(),
  OP.OP_FROMALTSTACK,
  ...lookupRc(),
  OP.OP_ADD,
  ...m31Reduce(),
  ...invokeFunction(FUNCTION_AIR_POW5),
  ...pushNumber(4),
  OP.OP_NUM2BIN,
  OP.OP_SWAP,
  ...pushNumber(4),
  OP.OP_SPLIT,
  OP.OP_NIP,
  OP.OP_CAT,
  ...applyInternalPacked(),
];

/**
 * TOS packed state, phase 0..21 → packed next snapshot.
 * Full rounds: phase in [0,4) U [18,22). Partial: [4,18).
 */
export const buildSnapshotFunction = () => compile([
  OP.OP_DUP,
  ...pushNumber(4),
  OP.OP_LESSTHAN,
  OP.OP_IF,
  ...pushNumber(POSEIDON2_T),
  OP.OP_MUL,
  ...fullRoundFromCursor(),
  OP.OP_ELSE,
  OP.OP_DUP,
  ...pushNumber(18),
  OP.OP_LESSTHAN,
  OP.OP_IF,
  ...pushNumber(4),
  OP.OP_SUB,
  ...pushNumber(64),
  OP.OP_ADD,
  ...partialRoundFromCursor(),
  OP.OP_ELSE,
  ...pushNumber(18),
  OP.OP_SUB,
  ...pushNumber(POSEIDON2_T),
  OP.OP_MUL,
  ...pushNumber(64 + 14),
  OP.OP_ADD,
  ...fullRoundFromCursor(),
  OP.OP_ENDIF,
  OP.OP_ENDIF,
], 'air snapshot');

const constraintBetas = () => Array.from({ length: POSEIDON2_T }, (_, index) => BigInt(index + 1));

const absorbExpectedSnapshot = (state, carry) => {
  const pre = carry.slice();
  for (let index = 0; index < POSEIDON2_RATE; index += 1) {
    pre[index] = add(pre[index], state[index]);
  }
  return applyPoseidon2External(pre);
};

export const encodePackedState = (values) => {
  require(Array.isArray(values) && values.length === POSEIDON2_T, 'packed state needs 16 M31');
  return concatBytes(...values.map((value) => encodeM31(value)));
};

const decodePackedState = (bytes) => {
  require(bytes instanceof Uint8Array && bytes.length === 64, 'packed state is 64 bytes');
  const values = [];
  for (let index = 0; index < POSEIDON2_T; index += 1) {
    const slice = bytes.subarray(index * 4, index * 4 + 4);
    values.push(BigInt(slice[0]) | (BigInt(slice[1]) << 8n) | (BigInt(slice[2]) << 16n) | (BigInt(slice[3]) << 24n));
  }
  return values;
};

const piIter = (x, n) => {
  let value = x;
  for (let index = 0; index < n; index += 1) {
    value = sub(mul(2n, mul(value, value)), 1n);
  }
  return value;
};

/**
 * Host residual at one LDE point. Matches on-chain C/Z=Q.
 */
export const evaluateConstraintResidualAt = ({
  state,
  next,
  prev,
  snapSelectors,
  freshSelector,
  contSelector,
  publicBinds = [],
  x,
}) => {
  let acc = 0n;
  const betas = constraintBetas();
  for (let phase = 0; phase < POSEIDON2_ROUNDS; phase += 1) {
    const selector = snapSelectors[phase];
    if (selector === 0n) continue;
    const expected = nextPoseidon2Snapshot(state, phase);
    for (let col = 0; col < POSEIDON2_T; col += 1) {
      acc = add(acc, mul(mul(betas[col], selector), sub(next[col], expected[col])));
    }
  }
  const addAbsorb = (selector, carry) => {
    if (selector === 0n) return;
    const expected = absorbExpectedSnapshot(state, carry);
    for (let col = 0; col < POSEIDON2_T; col += 1) {
      acc = add(acc, mul(mul(betas[col], selector), sub(next[col], expected[col])));
    }
  };
  addAbsorb(freshSelector ?? 0n, new Array(POSEIDON2_T).fill(0n));
  addAbsorb(contSelector ?? 0n, prev ?? new Array(POSEIDON2_T).fill(0n));
  for (const bind of publicBinds) {
    if (bind.selector === 0n) continue;
    for (let col = 0; col < bind.width; col += 1) {
      acc = add(acc, mul(mul(betas[col], bind.selector), sub(state[col], bind.values[col])));
    }
  }
  const vanishing = piIter(x, 9);
  require(vanishing !== 0n, 'Z_H vanished');
  const expectedQ = mul(acc, inverse(vanishing));
  return Object.freeze({
    constraint: acc,
    vanishing,
    expectedQ,
    invZ: inverse(vanishing),
  });
};

const FIXED_BIND_SLOTS = 6;
const PUBLIC_SELECTOR_OFFSET = 192;
const PUBLIC_FRESH_OFFSET = 192 + POSEIDON2_ROUNDS * 4;
const PUBLIC_CONT_OFFSET = PUBLIC_FRESH_OFFSET + 4;
const PUBLIC_BIND_OFFSET = PUBLIC_CONT_OFFSET + 4;
const PUBLIC_BIND_SLOT_BYTES = 4 + POSEIDON2_T * 4;

export const encodeAirResidualPublic = ({
  snapSelectors,
  freshSelector,
  contSelector,
  publicBinds = [],
  x,
  expectedQ,
  invZ,
}) => {
  const parts = [
    ...snapSelectors.map((value) => encodeM31(value)),
    encodeM31(freshSelector),
    encodeM31(contSelector),
  ];
  const slots = publicBinds.slice(0, FIXED_BIND_SLOTS).map((bind) => {
    const values = new Array(POSEIDON2_T).fill(0n);
    const width = bind.width ?? POSEIDON2_T;
    for (let col = 0; col < width; col += 1) values[col] = bind.values[col] ?? 0n;
    return { selector: bind.selector ?? 0n, values };
  });
  while (slots.length < FIXED_BIND_SLOTS) {
    slots.push({ selector: 0n, values: new Array(POSEIDON2_T).fill(0n) });
  }
  for (const bind of slots) {
    parts.push(encodeM31(bind.selector), ...bind.values.map((value) => encodeM31(value)));
  }
  parts.push(encodeM31(x), encodeM31(expectedQ), encodeM31(invZ));
  return concatBytes(...parts);
};

/**
 * Accumulate one column: TOS expected_packed, next_packed, selector, acc
 * → acc' after 16 columns. Too heavy as one function; use JS-generated loop
 * over columns with extractPackedCell.
 */

const accumDiff16 = () => [
  OP.OP_0,
  OP.OP_TOALTSTACK,
  OP.OP_BEGIN,
  OP.OP_FROMALTSTACK,
  OP.OP_DUP,
  ...pushNumber(POSEIDON2_T),
  OP.OP_NUMEQUAL,
  OP.OP_IF,
  OP.OP_DROP,
  OP.OP_1,
  OP.OP_ELSE,
  OP.OP_DUP,
  OP.OP_1ADD,
  OP.OP_TOALTSTACK,
  ...pushNumber(4),
  OP.OP_PICK,
  OP.OP_OVER,
  ...extractPackedCell(),
  OP.OP_TOALTSTACK,
  ...pushNumber(3),
  OP.OP_PICK,
  OP.OP_OVER,
  ...extractPackedCell(),
  OP.OP_FROMALTSTACK,
  OP.OP_SUB,
  ...m31WrapSub(),
  ...pushNumber(3),
  OP.OP_PICK,
  OP.OP_MUL,
  ...m31Reduce(),
  OP.OP_OVER,
  OP.OP_1ADD,
  OP.OP_MUL,
  ...m31Reduce(),
  OP.OP_ADD,
  ...m31Reduce(),
  OP.OP_NIP,
  OP.OP_0,
  OP.OP_ENDIF,
  OP.OP_UNTIL,
];

export const buildAccum16Function = () => compile(accumDiff16(), 'air accum16');

const pi9 = () => {
  const script = [];
  for (let index = 0; index < 9; index += 1) {
    script.push(
      OP.OP_DUP,
      OP.OP_MUL,
      ...m31Reduce(),
      OP.OP_DUP,
      OP.OP_ADD,
      ...m31Reduce(),
      ...pushNumber(1),
      OP.OP_SUB,
      ...m31WrapSub(),
    );
  }
  return script;
};

const buildOnePassResidual = () => {
  const script = [
    OP.OP_DUP,
    ...extractSlice(64, 64),
    ...unpackState(),
    ...pushNumber(POSEIDON2_T),
    OP.OP_ROLL,
    OP.OP_DUP,
    ...extractSlice(0, 64),
    ...unpackState(),
    ...pushNumber(POSEIDON2_T),
    OP.OP_ROLL,
    OP.OP_TOALTSTACK,
    OP.OP_0,
    OP.OP_TOALTSTACK,
  ];
  for (let phase = 0; phase < POSEIDON2_ROUNDS; phase += 1) {
    script.push(
      ...copy16(),
      ...snapshotPhaseNums(phase),
      OP.OP_FROMALTSTACK,
      OP.OP_FROMALTSTACK,
      OP.OP_DUP,
      OP.OP_TOALTSTACK,
      ...extractSlice(192 + phase * 4, 4),
      OP.OP_BIN2NUM,
      OP.OP_TOALTSTACK,
      OP.OP_TOALTSTACK,
    );
    for (let col = POSEIDON2_T - 1; col >= 0; col -= 1) {
      script.push(
        ...pushNumber(15 - col),
        OP.OP_PICK,
        ...pushNumber(18 + col),
        OP.OP_PICK,
        OP.OP_SUB,
        ...m31WrapSub(),
        OP.OP_FROMALTSTACK,
        OP.OP_FROMALTSTACK,
        OP.OP_DUP,
        OP.OP_TOALTSTACK,
        OP.OP_ROT,
        OP.OP_MUL,
        ...m31Reduce(),
        ...pushNumber(col + 1),
        OP.OP_MUL,
        ...m31Reduce(),
        OP.OP_ADD,
        ...m31Reduce(),
        OP.OP_TOALTSTACK,
      );
    }
    script.push(
      OP.OP_FROMALTSTACK,
      OP.OP_FROMALTSTACK,
      OP.OP_DROP,
      OP.OP_TOALTSTACK,
      ...drop16(),
    );
  }
  script.push(
    ...drop16(),
    ...drop16(),
    OP.OP_FROMALTSTACK,
    ...closeResidual(),
  );
  return script;
};

/**
 * One-pass 16-cell C/Z=Q. Tape TOS: state(64)||next(64)||prev(64)||public.
 * Copies state with PICK, snapshots in-nums with immediate Grain RC, no
 * pack/unpack per phase. Consumes tape, leaves 1.
 */
export const buildAirResidualFunction = () => compile([
  ...buildOnePassResidual(),
], 'air residual onepass');

/**
 * Tape: one blob
 *   state(64) || next(64) || prev(64) || public
 * TOS = tape. Function consumes tape, leaves 1.
 */
export const encodeAirResidualTape = ({
  state,
  next,
  prev,
  publicBlob,
}) => concatBytes(
  encodePackedState(state),
  encodePackedState(next),
  encodePackedState(prev),
  publicBlob,
);

const extractSlice = (offset, length) => {
  const script = [];
  if (offset > 0) {
    script.push(...pushNumber(offset), OP.OP_SPLIT, OP.OP_NIP);
  }
  script.push(...pushNumber(length), OP.OP_SPLIT, OP.OP_DROP);
  return script;
};

const buildAirResidualFunctionTape = () => {
  const script = [
    OP.OP_DUP,
    ...extractSlice(0, 64),
    OP.OP_TOALTSTACK,
    OP.OP_DUP,
    ...extractSlice(64, 64),
    OP.OP_TOALTSTACK,
    OP.OP_DUP,
    ...extractSlice(128, 64),
    OP.OP_DROP,
    OP.OP_FROMALTSTACK,
    OP.OP_FROMALTSTACK,
    OP.OP_SWAP,
    // main: tape, next, state   wait FROMALT next then state → TOS state, under next, tape
    // Want acc on stack. Park tape on alt.
    OP.OP_ROT,
    OP.OP_TOALTSTACK,
    // main: next, state. alt: tape
    OP.OP_SWAP,
    OP.OP_0,
    // main: state, next, acc
  ];
  for (let phase = 0; phase < POSEIDON2_ROUNDS; phase += 1) {
    script.push(
      // state, next, acc
      OP.OP_ROT,
      OP.OP_DUP,
      ...pushNumber(phase),
      ...invokeFunction(FUNCTION_AIR_SNAPSHOT),
      // next, acc, state, expected
      OP.OP_FROMALTSTACK,
      OP.OP_DUP,
      OP.OP_TOALTSTACK,
      ...extractSlice(192 + phase * 4, 4),
      OP.OP_BIN2NUM,
      // next, acc, state, expected, tape, sel
      OP.OP_NIP,
      OP.OP_TOALTSTACK,
      // next, acc, state, expected   alt: tape, sel
      OP.OP_SWAP,
      OP.OP_FROMALTSTACK,
      OP.OP_FROMALTSTACK,
      OP.OP_SWAP,
      OP.OP_TOALTSTACK,
      // next, acc, expected, state, sel   alt: tape
      // Want: expected, next, sel, acc for accumDiff16 — next is buried.
      // Pull next from under acc: stack is next, acc, expected, state, sel
      ...pushNumber(4),
      OP.OP_ROLL,
      // acc, expected, state, sel, next
      OP.OP_SWAP,
      OP.OP_TOALTSTACK,
      OP.OP_SWAP,
      OP.OP_TOALTSTACK,
      OP.OP_SWAP,
      // acc, next, expected   alt: tape, sel, state
      OP.OP_ROT,
      OP.OP_FROMALTSTACK,
      OP.OP_FROMALTSTACK,
      // expected, acc, next, state, sel? Let's stop and use a cleaner accum.
    );
    break;
  }
  return compile([
    ...buildTapeResidualUnrolled(),
  ], 'air residual tape');
};

/**
 * Snapshot-constraint C at zeta, then C * invZ = Q and π^9(x) * invZ = 1.
 * Tape stays on alt. Initial TOS: tape.
 */
const buildTapeResidualUnrolled = () => {
  const script = [
    OP.OP_DUP,
    ...extractSlice(0, 64),
    OP.OP_SWAP,
    OP.OP_TOALTSTACK,
    OP.OP_0,
  ];
  const accumPhase = (phase, selectorOffset) => [
    OP.OP_OVER,
    ...pushNumber(phase),
    ...invokeFunction(FUNCTION_AIR_SNAPSHOT),
    OP.OP_FROMALTSTACK,
    OP.OP_DUP,
    OP.OP_TOALTSTACK,
    ...extractSlice(64, 64),
    OP.OP_FROMALTSTACK,
    OP.OP_DUP,
    OP.OP_TOALTSTACK,
    ...extractSlice(selectorOffset, 4),
    OP.OP_BIN2NUM,
    ...pushNumber(3),
    OP.OP_ROLL,
    ...invokeFunction(FUNCTION_AIR_ACCUM16),
    OP.OP_NIP,
    OP.OP_NIP,
    OP.OP_NIP,
  ];
  for (let phase = 0; phase < POSEIDON2_ROUNDS; phase += 1) {
    script.push(...accumPhase(phase, 192 + phase * 4));
  }
  script.push(OP.OP_NIP, ...closeResidual());
  return script;
};

/** Add packed carry (offset in tape) into state's first 8 cells, external, accum vs next. */
const absorbAccum = (selectorOffset, carryOffset) => {
  const script = [
    OP.OP_OVER,
    // state, acc, state
  ];
  if (carryOffset === 0) {
    script.push(
      // zeros carry: packed state is already the pre-add for capacity; need rate += 0.
      // absorbExpectedSnapshot zeros: pre = state.rate unchanged (add 0), then external.
    );
  }
  script.push(
    OP.OP_FROMALTSTACK,
    OP.OP_DUP,
    OP.OP_TOALTSTACK,
    ...extractSlice(selectorOffset, 4),
    OP.OP_BIN2NUM,
    OP.OP_TOALTSTACK,
  );
  if (carryOffset === 0) {
    script.push(
      OP.OP_DUP,
      ...unpackState(),
      ...applyExternalNums(),
      ...packState(),
    );
  } else {
    script.push(
      OP.OP_DUP,
      OP.OP_FROMALTSTACK,
      OP.OP_DUP,
      OP.OP_TOALTSTACK,
      ...extractSlice(carryOffset, 64),
      OP.OP_SWAP,
      ...addRatePack(),
      ...unpackState(),
      ...applyExternalNums(),
      ...packState(),
    );
  }
  script.push(
    OP.OP_FROMALTSTACK,
    OP.OP_FROMALTSTACK,
    OP.OP_DUP,
    OP.OP_TOALTSTACK,
    ...extractSlice(64, 64),
    OP.OP_SWAP,
    OP.OP_DROP,
    OP.OP_SWAP,
    OP.OP_FROMALTSTACK,
    // state, acc, expected, next, sel
    OP.OP_TOALTSTACK,
    OP.OP_SWAP,
    OP.OP_FROMALTSTACK,
    OP.OP_SWAP,
    ...pushNumber(3),
    OP.OP_ROLL,
    ...accumDiff16(),
    OP.OP_NIP,
    OP.OP_NIP,
    OP.OP_NIP,
  );
  return script;
};

const addRatePack = () => {
  const script = [];
  for (let col = 0; col < POSEIDON2_RATE; col += 1) {
    script.push(
      // TOS carry_packed, under state_packed
      OP.OP_OVER,
      ...pushNumber(col),
      ...extractPackedCell(),
      OP.OP_TOALTSTACK,
      OP.OP_DUP,
      ...pushNumber(col),
      ...extractPackedCell(),
      OP.OP_FROMALTSTACK,
      OP.OP_ADD,
      ...m31Reduce(),
      ...pushNumber(4),
      OP.OP_NUM2BIN,
      OP.OP_TOALTSTACK,
    );
  }
  script.push(
    OP.OP_SWAP,
    ...pushNumber(POSEIDON2_RATE * 4),
    OP.OP_SPLIT,
    OP.OP_NIP,
    OP.OP_FROMALTSTACK,
  );
  for (let col = 1; col < POSEIDON2_RATE; col += 1) {
    script.push(OP.OP_FROMALTSTACK, OP.OP_SWAP, OP.OP_CAT);
  }
  script.push(OP.OP_SWAP, OP.OP_CAT);
  return script;
};

const publicBindAccum = () => [
  // Skip-on-chain public binds are still required. Parse bindCount from tape
  // offset 192+96 = 288.
  OP.OP_FROMALTSTACK,
  OP.OP_DUP,
  OP.OP_TOALTSTACK,
  ...extractSlice(288, 1),
  OP.OP_BIN2NUM,
  OP.OP_TOALTSTACK,
  ...bindLoop(),
];

const bindLoop = () => [
  // For v1, public binds are encoded after bindCount. Walk with a cursor on alt.
  // Cursor starts at 289. Loop bindCount times.
  ...pushNumber(289),
  OP.OP_TOALTSTACK,
  OP.OP_FROMALTSTACK,
  OP.OP_DUP,
  OP.OP_NOT,
  OP.OP_IF,
  OP.OP_DROP,
  OP.OP_FROMALTSTACK,
  OP.OP_DROP,
  OP.OP_ELSE,
  OP.OP_BEGIN,
  OP.OP_FROMALTSTACK,
  OP.OP_1SUB,
  OP.OP_DUP,
  OP.OP_TOALTSTACK,
  OP.OP_NOT,
  OP.OP_IF,
  OP.OP_1,
  OP.OP_ELSE,
  ...onePublicBind(),
  OP.OP_0,
  OP.OP_ENDIF,
  OP.OP_UNTIL,
  OP.OP_FROMALTSTACK,
  OP.OP_DROP,
  OP.OP_FROMALTSTACK,
  OP.OP_DROP,
  OP.OP_ENDIF,
];

const onePublicBind = () => {
  const script = [
    OP.OP_FROMALTSTACK,
    OP.OP_FROMALTSTACK,
    OP.OP_DUP,
    OP.OP_TOALTSTACK,
    OP.OP_OVER,
    OP.OP_SPLIT,
    OP.OP_SWAP,
    OP.OP_DROP,
    ...pushNumber(4),
    OP.OP_SPLIT,
    OP.OP_SWAP,
    OP.OP_BIN2NUM,
    OP.OP_TOALTSTACK,
    ...pushNumber(1),
    OP.OP_SPLIT,
    OP.OP_SWAP,
    OP.OP_BIN2NUM,
    OP.OP_DUP,
    OP.OP_TOALTSTACK,
    ...pushNumber(4),
    OP.OP_MUL,
    OP.OP_SPLIT,
    OP.OP_SWAP,
    OP.OP_TOALTSTACK,
    // values blob TOS, rest under? This is getting too sloppy.
    OP.OP_DROP,
    OP.OP_DROP,
    OP.OP_FROMALTSTACK,
    OP.OP_DROP,
    OP.OP_FROMALTSTACK,
    OP.OP_DROP,
    OP.OP_FROMALTSTACK,
    OP.OP_DROP,
    OP.OP_FROMALTSTACK,
    OP.OP_TOALTSTACK,
  ];
  return script;
};

/** IN: C, tape, sel, col, valOff. OUT: C', tape, sel. */
export const buildBindColFunction = () => compile([
  ...pushNumber(3),
  OP.OP_PICK,
  ...pushNumber(2),
  OP.OP_PICK,
  ...extractPackedCell(),
  OP.OP_SWAP,
  ...pushNumber(4),
  OP.OP_PICK,
  OP.OP_SWAP,
  OP.OP_SPLIT,
  OP.OP_NIP,
  ...pushNumber(4),
  OP.OP_SPLIT,
  OP.OP_DROP,
  OP.OP_BIN2NUM,
  OP.OP_SUB,
  ...m31WrapSub(),
  OP.OP_SWAP,
  OP.OP_1ADD,
  ...pushNumber(2),
  OP.OP_PICK,
  OP.OP_ROT,
  OP.OP_MUL,
  ...m31Reduce(),
  OP.OP_MUL,
  ...m31Reduce(),
  ...pushNumber(3),
  OP.OP_ROLL,
  OP.OP_ADD,
  ...m31Reduce(),
  OP.OP_ROT,
  OP.OP_ROT,
], 'air public-bind column');

/** TOS = tape, under = C. Adds squeeze-vs-publicFelts into C. Leaves C', tape.
 * Slot 0 is width t=16 (statement row); later slots are rate-width. */
const addPublicBindSlots = () => {
  const script = [];
  for (let slot = 0; slot < FIXED_BIND_SLOTS; slot += 1) {
    const width = slot === 0 ? POSEIDON2_T : POSEIDON2_RATE;
    const slotOff = PUBLIC_BIND_OFFSET + slot * PUBLIC_BIND_SLOT_BYTES;
    const valBase = slotOff + 4;
    script.push(
      OP.OP_DUP,
      ...extractSlice(slotOff, 4),
      OP.OP_BIN2NUM,
      OP.OP_DUP,
      OP.OP_NOT,
      OP.OP_IF,
      OP.OP_DROP,
      OP.OP_ELSE,
      OP.OP_0,
      OP.OP_TOALTSTACK,
      OP.OP_BEGIN,
      OP.OP_FROMALTSTACK,
      OP.OP_DUP,
      OP.OP_TOALTSTACK,
      OP.OP_DUP,
      ...pushNumber(4),
      OP.OP_MUL,
      ...pushNumber(valBase),
      OP.OP_ADD,
      ...invokeFunction(FUNCTION_AIR_BINDCOL),
      OP.OP_FROMALTSTACK,
      OP.OP_1ADD,
      OP.OP_DUP,
      OP.OP_TOALTSTACK,
      ...pushNumber(width),
      OP.OP_NUMEQUAL,
      OP.OP_UNTIL,
      OP.OP_FROMALTSTACK,
      OP.OP_DROP,
      OP.OP_DROP,
      OP.OP_ENDIF,
    );
  }
  return script;
};

const closeResidual = (airResidualQ, zetaX) => {
  const zetaXBytes = typeof zetaX === 'bigint' ? encodeM31(zetaX) : zetaX;
  return [
    OP.OP_FROMALTSTACK,
    OP.OP_SIZE,
    ...pushNumber(12),
    OP.OP_SUB,
    OP.OP_SPLIT,
    OP.OP_NIP,
    ...pushNumber(4),
    OP.OP_SPLIT,
    OP.OP_SWAP,
    ...(zetaXBytes instanceof Uint8Array && zetaXBytes.length === 4
      ? [OP.OP_DUP, ...encodeMinimalDataPush(zetaXBytes), OP.OP_EQUALVERIFY]
      : []),
    OP.OP_BIN2NUM,
    OP.OP_TOALTSTACK,
    ...pushNumber(4),
    OP.OP_SPLIT,
    OP.OP_SWAP,
    ...(airResidualQ instanceof Uint8Array && airResidualQ.length === 4
      ? [OP.OP_DUP, ...encodeMinimalDataPush(airResidualQ), OP.OP_EQUALVERIFY]
      : []),
    OP.OP_BIN2NUM,
    OP.OP_TOALTSTACK,
    OP.OP_BIN2NUM,
    OP.OP_DUP,
    OP.OP_TOALTSTACK,
    OP.OP_MUL,
    ...m31Reduce(),
    OP.OP_FROMALTSTACK,
    OP.OP_FROMALTSTACK,
    OP.OP_ROT,
    OP.OP_NUMEQUALVERIFY,
    OP.OP_FROMALTSTACK,
    ...pi9(),
    OP.OP_MUL,
    ...m31Reduce(),
    OP.OP_1,
    OP.OP_NUMEQUALVERIFY,
    OP.OP_1,
  ];
};

export const buildAirResidualDefinitions = () => concat(
  defineFunction(FUNCTION_AIR_POW5, buildPow5Function()),
  defineFunction(FUNCTION_AIR_RESIDUAL, buildAirResidualFunction()),
);

export const invokeAirResidual = () => invokeFunction(FUNCTION_AIR_RESIDUAL);

export const residualKernelInternals = Object.freeze({
  compile,
  concat,
  defineFunction,
  encodeMinimalDataPush,
  extractPackedCell,
  extractSlice,
  invokeFunction,
  packState,
  unpackState,
  applyExternalNums,
  applyInternalNums,
  applyExternalPacked,
  applyInternalPacked,
  packedSum,
  buildPow5Function,
  buildSnapshotFunction,
  pi9,
  decodePackedState,
  pushNumber,
  OP,
  copy16,
  drop16,
  snapshotPhaseNums,
});

const consumeRcPow5Inline = () => [
  ...pushNumber(4),
  OP.OP_SPLIT,
  OP.OP_SWAP,
  OP.OP_BIN2NUM,
  OP.OP_ROT,
  OP.OP_ADD,
  OP.OP_DUP,
  OP.OP_DUP,
  OP.OP_MUL,
  OP.OP_DUP,
  OP.OP_MUL,
  OP.OP_MUL,
  ...m31Reduce(),
  OP.OP_TOALTSTACK,
];

export const FUNCTION_AIR_FULL = 27;
export const FUNCTION_AIR_PART = 29;
export const FUNCTION_AIR_ACCUM_NEXT = 26;
export const FUNCTION_AIR_COPY16 = 30;
export const FUNCTION_AIR_EXT = 31;
export const FUNCTION_AIR_LOADSEL = 32;
export const FUNCTION_AIR_RESTORE = 33;
export const FUNCTION_AIR_BINDCOL = 34;

export const buildApplyExternalFunction = () => compile(applyExternalNums(), 'air external mix');

export const buildFullRoundFunction = () => compile([
  ...Array.from({ length: POSEIDON2_T }, () => consumeRcPow5Inline()).flat(),
  ...Array.from({ length: POSEIDON2_T }, () => OP.OP_FROMALTSTACK),
  ...invokeFunction(FUNCTION_AIR_EXT),
  ...pushNumber(POSEIDON2_T),
  OP.OP_ROLL,
], 'air full round nums');

export const buildPartialRoundFunction = () => compile([
  ...Array.from({ length: POSEIDON2_T - 1 }, () => [OP.OP_SWAP, OP.OP_TOALTSTACK]).flat(),
  ...consumeRcPow5Inline(),
  ...Array.from({ length: POSEIDON2_T }, () => OP.OP_FROMALTSTACK),
  ...applyInternalNums(),
  ...pushNumber(POSEIDON2_T),
  OP.OP_ROLL,
], 'air partial round nums');

export const encodeRcStream = () => {
  const parts = [];
  for (let phase = 0; phase < POSEIDON2_ROUNDS; phase += 1) {
    if (phase < 4 || phase >= 18) {
      const start = phase < 4
        ? phase * POSEIDON2_T
        : (POSEIDON2_T * 4) + 14 + ((phase - 18) * POSEIDON2_T);
      for (let col = POSEIDON2_T - 1; col >= 0; col -= 1) {
        parts.push(encodeM31(POSEIDON2_ROUND_CONSTANTS[start + col]));
      }
    } else {
      parts.push(encodeM31(POSEIDON2_ROUND_CONSTANTS[64 + (phase - 4)]));
    }
  }
  return concatBytes(...parts);
};

/**
 * TOS expected[15..0], state[15..0], next[15..0] (next[0] deepest).
 * Alt TOS: selector, acc.
 * Consumes expected. Leaves next, state. Alt TOS: selector, acc.
 */
export const buildAccum16VsNextFunction = () => {
  // loadSelector: alt TOS=sel, then acc. Pull sel onto main; acc stays on alt.
  // TOS=sel for the whole 16-col loop. Expected is consumed from TOS-under-sel.
  const script = [OP.OP_FROMALTSTACK];
  for (let remaining = POSEIDON2_T; remaining >= 1; remaining -= 1) {
    const col = remaining - 1;
    script.push(
      OP.OP_SWAP,
      ...pushNumber(33),
      OP.OP_PICK,
      OP.OP_SWAP,
      OP.OP_SUB,
      OP.OP_OVER,
      OP.OP_SWAP,
      OP.OP_MUL,
      ...(col === 0 ? [] : [...pushNumber(col + 1), OP.OP_MUL]),
      OP.OP_FROMALTSTACK,
      OP.OP_ADD,
      OP.OP_TOALTSTACK,
    );
  }
  script.push(
    OP.OP_FROMALTSTACK,
    ...pushNumber(M31_MODULUS),
    OP.OP_ADD,
    ...pushNumber(M31_MODULUS),
    OP.OP_MOD,
    OP.OP_DUP,
    OP.OP_0,
    OP.OP_LESSTHAN,
    OP.OP_IF,
    ...pushNumber(M31_MODULUS),
    OP.OP_ADD,
    OP.OP_ENDIF,
    OP.OP_TOALTSTACK,
    OP.OP_TOALTSTACK,
  );
  return compile(script, 'air accum16 vs next');
};

export const buildLoadSelectorFunction = () => compile([
  OP.OP_FROMALTSTACK,
  OP.OP_FROMALTSTACK,
  OP.OP_FROMALTSTACK,
  ...pushNumber(4),
  OP.OP_SPLIT,
  OP.OP_SWAP,
  OP.OP_BIN2NUM,
  OP.OP_SWAP,
  OP.OP_TOALTSTACK,
  ...pushNumber(2),
  OP.OP_ROLL,
  OP.OP_TOALTSTACK,
  OP.OP_SWAP,
  OP.OP_TOALTSTACK,
  OP.OP_TOALTSTACK,
], 'air load selector');

const loadSelector = () => invokeFunction(FUNCTION_AIR_LOADSEL);

export const buildRestoreRcAccFunction = () => compile([
  OP.OP_FROMALTSTACK,
  OP.OP_DROP,
  OP.OP_FROMALTSTACK,
  OP.OP_FROMALTSTACK,
  OP.OP_SWAP,
  OP.OP_TOALTSTACK,
  OP.OP_TOALTSTACK,
], 'air restore rc acc');

const restoreRcAcc = () => invokeFunction(FUNCTION_AIR_RESTORE);

export const buildCopy16Function = () => compile(copy16(), 'air copy16');

const oneSnapPhase = (identifier, phase) => [
  ...copy16(),
  OP.OP_FROMALTSTACK,
  ...invokeFunction(identifier),
  OP.OP_TOALTSTACK,
  ...loadSelector(),
  ...invokeFunction(FUNCTION_AIR_ACCUM_NEXT),
  OP.OP_FROMALTSTACK,
  OP.OP_DROP,
  OP.OP_FROMALTSTACK,
  OP.OP_FROMALTSTACK,
  OP.OP_SWAP,
  OP.OP_TOALTSTACK,
  OP.OP_TOALTSTACK,
];

const setupFromTape = () => [
  OP.OP_DUP,
  ...extractSlice(0, 64),
  ...unpackState(),
  ...Array.from({ length: POSEIDON2_T }, () => OP.OP_TOALTSTACK),
  OP.OP_DUP,
  ...extractSlice(64, 64),
  ...unpackState(),
  ...Array.from({ length: POSEIDON2_T }, () => OP.OP_TOALTSTACK),
  OP.OP_DUP,
  ...extractSlice(128, 64),
  OP.OP_TOALTSTACK,
  OP.OP_TOALTSTACK,
  OP.OP_FROMALTSTACK,
  OP.OP_FROMALTSTACK,
  ...Array.from({ length: POSEIDON2_T * 2 }, () => OP.OP_FROMALTSTACK),
  ...pushNumber(32),
  OP.OP_ROLL,
  OP.OP_TOALTSTACK,
  ...pushNumber(32),
  OP.OP_ROLL,
  OP.OP_TOALTSTACK,
  OP.OP_FROMALTSTACK,
  OP.OP_DUP,
  ...extractSlice(PUBLIC_SELECTOR_OFFSET, (POSEIDON2_ROUNDS + 2) * 4),
  OP.OP_SWAP,
  OP.OP_TOALTSTACK,
  OP.OP_TOALTSTACK,
  OP.OP_0,
  OP.OP_TOALTSTACK,
  ...encodeMinimalDataPush(encodeRcStream()),
  OP.OP_TOALTSTACK,
];

const absorbFreshPhase = () => [
  ...invokeFunction(FUNCTION_AIR_COPY16),
  OP.OP_2DROP,
  OP.OP_2DROP,
  OP.OP_2DROP,
  OP.OP_2DROP,
  OP.OP_0,
  OP.OP_0,
  OP.OP_0,
  OP.OP_0,
  OP.OP_0,
  OP.OP_0,
  OP.OP_0,
  OP.OP_0,
  ...invokeFunction(FUNCTION_AIR_EXT),
  ...loadSelector(),
  ...invokeFunction(FUNCTION_AIR_ACCUM_NEXT),
  ...restoreRcAcc(),
];

const absorbContPhase = () => {
  const script = [
    OP.OP_FROMALTSTACK,
    OP.OP_FROMALTSTACK,
    OP.OP_FROMALTSTACK,
    OP.OP_FROMALTSTACK,
    OP.OP_FROMALTSTACK,
    OP.OP_DUP,
    OP.OP_TOALTSTACK,
    OP.OP_SWAP,
    OP.OP_TOALTSTACK,
    OP.OP_SWAP,
    OP.OP_TOALTSTACK,
    OP.OP_SWAP,
    OP.OP_TOALTSTACK,
    OP.OP_SWAP,
    OP.OP_TOALTSTACK,
  ];
  // Park capacity first (col 15..8) then rate (col 7..0) so FROMALT leaves s15 TOS.
  for (let col = POSEIDON2_T - 1; col >= 0; col -= 1) {
    script.push(
      OP.OP_DUP,
      ...pushNumber(col),
      ...extractPackedCell(),
    );
    if (col < POSEIDON2_RATE) {
      script.push(
        ...pushNumber(POSEIDON2_T - col + 1),
        OP.OP_PICK,
        OP.OP_ADD,
        ...m31Reduce(),
      );
    }
    script.push(OP.OP_TOALTSTACK);
  }
  script.push(OP.OP_DROP);
  for (let col = 0; col < POSEIDON2_T; col += 1) script.push(OP.OP_FROMALTSTACK);
  script.push(
    ...invokeFunction(FUNCTION_AIR_EXT),
    ...loadSelector(),
    ...invokeFunction(FUNCTION_AIR_ACCUM_NEXT),
    ...restoreRcAcc(),
  );
  return script;
};

export const buildLoopResidualFromLeaf = ({ airResidualQ, zetaX } = {}) => compile([
  ...setupFromTape(),
  ...[0, 1, 2, 3].flatMap((phase) => oneSnapPhase(FUNCTION_AIR_FULL, phase)),
  ...Array.from({ length: 14 }, (_, index) => oneSnapPhase(FUNCTION_AIR_PART, index + 4)).flat(),
  ...[18, 19, 20, 21].flatMap((phase) => oneSnapPhase(FUNCTION_AIR_FULL, phase)),
  ...absorbFreshPhase(),
  ...absorbContPhase(),
  ...drop16(),
  ...drop16(),
  OP.OP_FROMALTSTACK,
  OP.OP_DROP,
  OP.OP_FROMALTSTACK,
  OP.OP_FROMALTSTACK,
  OP.OP_DROP,
  OP.OP_FROMALTSTACK,
  OP.OP_FROMALTSTACK,
  OP.OP_DROP,
  ...addPublicBindSlots(),
  OP.OP_TOALTSTACK,
  ...closeResidual(airResidualQ, zetaX),
], 'air residual C/Z=Q from tape');

export const buildAirResidualUnlockingDefs = ({ airResidualQ, zetaX } = {}) => concat(
  defineFunction(FUNCTION_AIR_COPY16, buildCopy16Function()),
  defineFunction(FUNCTION_AIR_EXT, buildApplyExternalFunction()),
  defineFunction(FUNCTION_AIR_LOADSEL, buildLoadSelectorFunction()),
  defineFunction(FUNCTION_AIR_RESTORE, buildRestoreRcAccFunction()),
  defineFunction(FUNCTION_AIR_ACCUM_NEXT, buildAccum16VsNextFunction()),
  defineFunction(FUNCTION_AIR_FULL, buildFullRoundFunction()),
  defineFunction(FUNCTION_AIR_PART, buildPartialRoundFunction()),
  defineFunction(FUNCTION_AIR_BINDCOL, buildBindColFunction()),
  defineFunction(FUNCTION_AIR_RESIDUAL, buildLoopResidualFromLeaf({ airResidualQ, zetaX })),
);

export const residualLoopInternals = Object.freeze({
  setupFromTape,
  loadSelector,
  restoreRcAcc,
  oneSnapPhase,
  absorbFreshPhase,
  absorbContPhase,
  closeResidual,
  PUBLIC_SELECTOR_OFFSET,
});

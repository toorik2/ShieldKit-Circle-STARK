import { SHA256_IV, SHA256_K, sha256Pad } from "./sha256-primitives.ts";
import { M31, type M31El } from "../backends/circle/m31.ts";
import {
  QM31_ZERO,
  QM31_ONE,
  liftM31,
  qmAdd,
  qmEq,
  qmInv,
  qmMul,
  qmNeg,
  qmSub,
  type QM31El,
} from "../backends/circle/qm31.ts";
import { QM31_FIELD_BITS } from "../backends/circle/qm31.ts";
import {
  LOCAL_WORD_FRI_LOG_BLOWUP,
  LOCAL_WORD_QUERIES,
  LOCAL_WORD_QUERY_CONJECTURE_BITS,
} from "../backends/circle/local-word-successor-params.ts";

/**
 * Replacement SHA relation prototype.
 *
 * This is deliberately a circuit, not another proof layer. Each row produces
 * one 32-bit word from at most two earlier words. Words are eight base-16
 * limbs. A single four-bit lookup table validates XOR/range/unaligned shifts;
 * one static copy relation connects row ports. The proof integration will
 * commit these columns through the same successor seal and transcript.
 */

export const LOCAL_SHA_LIMB_BITS = 4;
export const LOCAL_SHA_LIMBS = 32 / LOCAL_SHA_LIMB_BITS;
export const LOCAL_SHA_RADIX = 1 << LOCAL_SHA_LIMB_BITS;

export const LOCAL_SHA_OPERATION_KINDS = [
  "input",
  "mask",
  "constant",
  "rotr",
  "xor",
  "and",
  "add",
  "nonzero",
] as const;
export type LocalShaOperationKind = typeof LOCAL_SHA_OPERATION_KINDS[number];
export type LocalShaPort = "a" | "b" | "out";

export type LocalShaRow = {
  readonly operation: LocalShaOperationKind;
  readonly out: number;
  readonly a?: number;
  readonly b?: number;
  readonly literal?: number;
  readonly shift?: number;
  readonly input?: number;
  readonly label: string;
};

export type LocalShaProgram = {
  readonly rows: readonly LocalShaRow[];
  readonly inputLabels: readonly string[];
  readonly inputWires: readonly number[];
  readonly outputs: readonly (readonly number[])[];
  readonly jobBlockCounts: readonly number[];
  /** Explicit static equality classes; aliases may join individual nibbles. */
  readonly copyAliases: readonly LocalShaCopyAlias[];
  /** Whole-word semantic equalities, kept distinct for the word permutation. */
  readonly wordAliases: readonly LocalShaWordAlias[];
};

export type LocalShaWireCell = { readonly wire: number; readonly limb: number };
export type LocalShaCopyAlias = readonly [LocalShaWireCell, LocalShaWireCell];
export type LocalShaWordAlias = readonly [number, number];

export type LocalShaExecution = {
  readonly wireValues: readonly number[];
  readonly inputs: readonly number[];
};

export type LocalShaTraceRow = {
  readonly a: readonly M31El[];
  readonly b: readonly M31El[];
  readonly out: readonly M31El[];
  /** Base-16 carry before limb 0 through carry after limb 7. */
  readonly carry: readonly M31El[];
};

export type LocalShaTrace = {
  readonly rows: readonly LocalShaTraceRow[];
};

export type LocalShaViolation = {
  readonly row: number;
  readonly constraint: string;
};

export type LocalShaCopyCell = {
  readonly row: number;
  readonly port: LocalShaPort;
  readonly limb: number;
  readonly wire: number;
  readonly wireLimb: number;
  readonly identity: M31El;
  readonly sigma: M31El;
};

export type LocalShaCopyPermutation = {
  /** Row-major, then port A/B/out order, then limb; zero means inactive. */
  readonly identities: Uint32Array;
  readonly sigmas: Uint32Array;
};

export type LocalShaLookupEntry = {
  /** RANGE, COPY, XOR, AND, ADD, right-stitch 1..3, BITMASK, NONZERO. */
  readonly tag: 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9;
  readonly a: M31El;
  readonly b: M31El;
  readonly carryIn: M31El;
  readonly out: M31El;
  readonly carryOut: M31El;
};

export type LocalShaRelationFrame = {
  readonly row: number;
  /** A, B, output, carries, table multiplicity. */
  readonly original: readonly M31El[];
  /** Instruction tag/literal, copy id/sigma pairs, active, table tuple. */
  readonly preprocessed: readonly M31El[];
};

export type LocalShaCopyChallenges = {
  readonly gamma: QM31El;
  readonly identity: QM31El;
  readonly value: QM31El;
};

export type LocalShaLookupChallenges = {
  readonly gamma: QM31El;
  readonly tuple: readonly [QM31El, QM31El, QM31El, QM31El, QM31El, QM31El];
};

export type LocalShaInteractionChallenges = {
  readonly lookup: LocalShaLookupChallenges;
  readonly copy: readonly [LocalShaCopyChallenges, LocalShaCopyChallenges];
};

export type LocalShaInteractionTrace = {
  readonly relationRows: number;
  readonly tableMultiplicities: readonly M31El[];
  /** Quadratic LogUp cumulative columns, one per fraction, in QM31. */
  readonly columns: readonly (readonly QM31El[])[];
  readonly claimedSum: QM31El;
};

/** A, B, output, nine carries, and one sealed table-multiplicity column. */
export const LOCAL_SHA_ORIGINAL_COLUMNS = LOCAL_SHA_LIMBS * 3 + (LOCAL_SHA_LIMBS + 1) + 1;
/** Tag, literal, 24 id/sigma pairs, and the active+six-column universal table. */
export const LOCAL_SHA_PREPROCESSED_COLUMNS = 1 + LOCAL_SHA_LIMBS + LOCAL_SHA_LIMBS * 3 * 2 + 7;
export const LOCAL_SHA_MAX_LOOKUPS_PER_ROW = LOCAL_SHA_LIMBS;
export const LOCAL_SHA_COPY_CELLS_PER_ROW = LOCAL_SHA_LIMBS * 3;
export const LOCAL_SHA_COPY_LANES = 2;
/** Reserved self-loop identity for an inactive A/B/out slot. */
export const LOCAL_SHA_COPY_INACTIVE_ID = M31 - 1n;
export const LOCAL_SHA_INTERACTION_FRACTIONS = 9 +
  2 * LOCAL_SHA_COPY_CELLS_PER_ROW * LOCAL_SHA_COPY_LANES;
/** One accumulator per fraction avoids a cubic pair-compressed quotient. */
export const LOCAL_SHA_INTERACTION_QM31_COLUMNS = LOCAL_SHA_INTERACTION_FRACTIONS;
export const LOCAL_SHA_INTERACTION_M31_COLUMNS = LOCAL_SHA_INTERACTION_QM31_COLUMNS * 4;
/** Only the final core accumulator has a cyclic predecessor dependency. */
export const LOCAL_SHA_INTERACTION_PREVIOUS_QM31_COLUMNS = 1;
export const LOCAL_SHA_LOOKUP_TABLE_ROWS = 1_841;

const PORTS: readonly LocalShaPort[] = ["a", "b", "out"];

function u32(value: number): number {
  if (!Number.isInteger(value)) throw new Error("local SHA word");
  return value >>> 0;
}

function rotr(value: number, shift: number): number {
  return ((value >>> shift) | (value << (32 - shift))) >>> 0;
}

function nextPowerOfTwo(value: number): number {
  if (!Number.isInteger(value) || value < 1) throw new Error("local SHA row count");
  let result = 1;
  while (result < value) result *= 2;
  return result;
}

function localShaRelationRows(program: LocalShaProgram): number {
  return nextPowerOfTwo(Math.max(program.rows.length, LOCAL_SHA_LOOKUP_TABLE_ROWS));
}

function wordFromBlock(block: Uint8Array, word: number): number {
  const offset = word * 4;
  return ((block[offset]! << 24) |
    (block[offset + 1]! << 16) |
    (block[offset + 2]! << 8) |
    block[offset + 3]!) >>> 0;
}

/** Canonical SHA big-endian words for a byte string already aligned to words. */
export function localShaWordsFromBytes(bytes: Uint8Array): readonly number[] {
  if (bytes.length % 4 !== 0) throw new Error("local SHA byte alignment");
  return Array.from({ length: bytes.length / 4 }, (_, word) => wordFromBlock(bytes, word));
}

export function localShaWordLimbs(value: number): readonly M31El[] {
  const word = u32(value);
  return Array.from({ length: LOCAL_SHA_LIMBS }, (_, limb) =>
    BigInt((word >>> (limb * LOCAL_SHA_LIMB_BITS)) & (LOCAL_SHA_RADIX - 1)));
}

export function localShaLimbsWord(limbs: readonly M31El[]): number {
  if (limbs.length !== LOCAL_SHA_LIMBS) throw new Error("local SHA limb width");
  let result = 0;
  for (let limb = 0; limb < LOCAL_SHA_LIMBS; limb += 1) {
    const value = limbs[limb]!;
    if (value < 0n || value >= BigInt(LOCAL_SHA_RADIX)) throw new Error("local SHA limb range");
    result = (result | (Number(value) << (limb * LOCAL_SHA_LIMB_BITS))) >>> 0;
  }
  return result;
}

export class LocalShaCircuitBuilder {
  readonly rows: LocalShaRow[] = [];
  readonly inputLabels: string[] = [];
  readonly inputWires: number[] = [];
  readonly copyAliases: LocalShaCopyAlias[] = [];
  readonly wordAliases: LocalShaWordAlias[] = [];
  readonly constants = new Map<number, number>();

  private push(row: Omit<LocalShaRow, "out">): number {
    const out = this.rows.length;
    this.rows.push({ ...row, out });
    return out;
  }

  input(label: string): number {
    const input = this.inputLabels.length;
    this.inputLabels.push(label);
    const wire = this.push({ operation: "input", input, label });
    this.inputWires.push(wire);
    return wire;
  }

  mask(label: string): number {
    const input = this.inputLabels.length;
    this.inputLabels.push(label);
    const wire = this.push({ operation: "mask", input, label });
    this.inputWires.push(wire);
    for (let limb = 1; limb < LOCAL_SHA_LIMBS; limb += 1) {
      this.copyAliases.push([{ wire, limb: 0 }, { wire, limb }]);
    }
    return wire;
  }

  constant(value: number): number {
    const literal = u32(value);
    const existing = this.constants.get(literal);
    if (existing !== undefined) return existing;
    const out = this.push({ operation: "constant", literal, label: `constant:${literal.toString(16)}` });
    this.constants.set(literal, out);
    return out;
  }

  rotate(a: number, shift: number, label: string): number {
    if (!Number.isInteger(shift) || shift < 1 || shift > 31 || a >= this.rows.length) {
      throw new Error("local SHA unary operation");
    }
    return this.push({ operation: "rotr", a, shift, label });
  }

  binary(operation: "xor" | "and" | "add", a: number, b: number, label: string): number {
    if (a < 0 || b < 0 || a >= this.rows.length || b >= this.rows.length) {
      throw new Error("local SHA binary operation");
    }
    return this.push({ operation, a, b, label });
  }

  xor(a: number, b: number, label: string): number {
    return this.binary("xor", a, b, label);
  }

  and(a: number, b: number, label: string): number {
    return this.binary("and", a, b, label);
  }

  add(a: number, b: number, label: string): number {
    return this.binary("add", a, b, label);
  }

  equalWord(left: number, right: number): void {
    if (left < 0 || right < 0 || left >= this.rows.length || right >= this.rows.length) {
      throw new Error("local SHA equality wire");
    }
    this.wordAliases.push([left, right]);
  }

  equalCell(left: LocalShaWireCell, right: LocalShaWireCell): void {
    if (left.wire < 0 || right.wire < 0 || left.wire >= this.rows.length || right.wire >= this.rows.length ||
      left.limb < 0 || right.limb < 0 || left.limb >= LOCAL_SHA_LIMBS || right.limb >= LOCAL_SHA_LIMBS) {
      throw new Error("local SHA equality cell");
    }
    this.copyAliases.push([left, right]);
  }

  equalWords(left: readonly number[], right: readonly number[]): void {
    if (left.length !== right.length) throw new Error("local SHA equality width");
    left.forEach((wire, index) => this.equalWord(wire, right[index]!));
  }

  or(a: number, b: number, label: string): number {
    return this.xor(
      this.xor(a, b, `${label}:xor`),
      this.and(a, b, `${label}:and`),
      `${label}:out`,
    );
  }

  /** Assert that every four-bit limb is non-zero; output is the same word. */
  nonzero(a: number, label: string): number {
    if (a < 0 || a >= this.rows.length) throw new Error("local SHA nonzero operation");
    return this.push({ operation: "nonzero", a, label });
  }

  /** Reduce any number of words and assert that at least one bit is set. */
  assertSomeNonzero(values: readonly number[], label: string): number {
    if (values.length < 1) throw new Error("local SHA nonzero arity");
    let aggregate = values[0]!;
    for (let index = 1; index < values.length; index += 1) {
      aggregate = this.or(aggregate, values[index]!, `${label}:word:${index}`);
    }
    for (const shift of [4, 8, 16]) {
      aggregate = this.or(
        aggregate,
        this.rotate(aggregate, shift, `${label}:reduce:${shift}:rotate`),
        `${label}:reduce:${shift}`,
      );
    }
    return this.nonzero(aggregate, `${label}:assert`);
  }

  /** `mask` is constrained to all-zero or all-one bits. */
  select(mask: number, whenZero: number, whenOne: number, label: string): number {
    const difference = this.xor(whenZero, whenOne, `${label}:difference`);
    const selected = this.and(mask, difference, `${label}:selected`);
    return this.xor(whenZero, selected, `${label}:out`);
  }

  finish(outputs: readonly (readonly number[])[], jobBlockCounts: readonly number[]): LocalShaProgram {
    return {
      rows: this.rows,
      inputLabels: this.inputLabels,
      inputWires: this.inputWires,
      outputs: outputs.map((output) => [...output]),
      jobBlockCounts: [...jobBlockCounts],
      copyAliases: [...this.copyAliases],
      wordAliases: [...this.wordAliases],
    };
  }
}

function xor3(builder: LocalShaCircuitBuilder, a: number, b: number, c: number, label: string): number {
  return builder.xor(builder.xor(a, b, `${label}:xor-0`), c, `${label}:xor-1`);
}

/** A logical shift is one rotation and one ordinary AND with a public mask. */
function logicalShift(builder: LocalShaCircuitBuilder, x: number, shift: number, label: string): number {
  const rotated = builder.rotate(x, shift, `${label}:rotate`);
  const mask = builder.constant(0xffff_ffff >>> shift);
  return builder.and(rotated, mask, `${label}:mask`);
}

function smallSigma0(builder: LocalShaCircuitBuilder, x: number, label: string): number {
  return xor3(
    builder,
    builder.rotate(x, 7, `${label}:rotr-7`),
    builder.rotate(x, 18, `${label}:rotr-18`),
    logicalShift(builder, x, 3, `${label}:shr-3`),
    label,
  );
}

function smallSigma1(builder: LocalShaCircuitBuilder, x: number, label: string): number {
  return xor3(
    builder,
    builder.rotate(x, 17, `${label}:rotr-17`),
    builder.rotate(x, 19, `${label}:rotr-19`),
    logicalShift(builder, x, 10, `${label}:shr-10`),
    label,
  );
}

function bigSigma0(builder: LocalShaCircuitBuilder, x: number, label: string): number {
  return xor3(
    builder,
    builder.rotate(x, 2, `${label}:rotr-2`),
    builder.rotate(x, 13, `${label}:rotr-13`),
    builder.rotate(x, 22, `${label}:rotr-22`),
    label,
  );
}

function bigSigma1(builder: LocalShaCircuitBuilder, x: number, label: string): number {
  return xor3(
    builder,
    builder.rotate(x, 6, `${label}:rotr-6`),
    builder.rotate(x, 11, `${label}:rotr-11`),
    builder.rotate(x, 25, `${label}:rotr-25`),
    label,
  );
}

/** Ch(x,y,z) = z XOR (x AND (y XOR z)). */
function choose(builder: LocalShaCircuitBuilder, x: number, y: number, z: number, label: string): number {
  const difference = builder.xor(y, z, `${label}:difference`);
  const selected = builder.and(x, difference, `${label}:selected`);
  return builder.xor(z, selected, `${label}:out`);
}

/** Maj(x,y,z) = (x AND y) XOR (z AND (x XOR y)). */
function majority(builder: LocalShaCircuitBuilder, x: number, y: number, z: number, label: string): number {
  const xyAnd = builder.and(x, y, `${label}:xy-and`);
  const xyXor = builder.xor(x, y, `${label}:xy-xor`);
  const zAnd = builder.and(z, xyXor, `${label}:z-and`);
  return builder.xor(xyAnd, zAnd, `${label}:out`);
}

function addMany(builder: LocalShaCircuitBuilder, values: readonly number[], label: string): number {
  if (values.length < 2) throw new Error("local SHA addition arity");
  let result = builder.add(values[0]!, values[1]!, `${label}:1`);
  for (let i = 2; i < values.length; i += 1) {
    result = builder.add(result, values[i]!, `${label}:${i}`);
  }
  return result;
}

function compression(
  builder: LocalShaCircuitBuilder,
  state: readonly number[],
  message: readonly number[],
  label: string,
): readonly number[] {
  if (state.length !== 8 || message.length !== 16) throw new Error("local SHA compression shape");
  const schedule = [...message];
  for (let round = 16; round < 64; round += 1) {
    schedule.push(addMany(builder, [
      smallSigma1(builder, schedule[round - 2]!, `${label}:schedule:${round}:sigma1`),
      schedule[round - 7]!,
      smallSigma0(builder, schedule[round - 15]!, `${label}:schedule:${round}:sigma0`),
      schedule[round - 16]!,
    ], `${label}:schedule:${round}:add`));
  }

  let [a, b, c, d, e, f, g, h] = state as [number, number, number, number, number, number, number, number];
  for (let round = 0; round < 64; round += 1) {
    const sigmaE = bigSigma1(builder, e, `${label}:round:${round}:sigma-e`);
    const ch = choose(builder, e, f, g, `${label}:round:${round}:ch`);
    const t1 = addMany(builder, [h, sigmaE, ch, builder.constant(SHA256_K[round]!), schedule[round]!],
      `${label}:round:${round}:t1`);
    const sigmaA = bigSigma0(builder, a, `${label}:round:${round}:sigma-a`);
    const maj = majority(builder, a, b, c, `${label}:round:${round}:maj`);
    const t2 = builder.add(sigmaA, maj, `${label}:round:${round}:t2`);
    const nextA = builder.add(t1, t2, `${label}:round:${round}:next-a`);
    const nextE = builder.add(d, t1, `${label}:round:${round}:next-e`);
    [a, b, c, d, e, f, g, h] = [nextA, a, b, c, nextE, e, f, g];
  }
  return [a, b, c, d, e, f, g, h].map((word, index) =>
    builder.add(state[index]!, word, `${label}:digest:${index}`));
}

/**
 * Hash one word-aligned message inside an existing static circuit. Message
 * words may be shared with other hashes; canonical padding and IV are public
 * constants, and chaining never leaves the copy ledger.
 */
export function localShaHashWords(
  builder: LocalShaCircuitBuilder,
  message: readonly number[],
  messageBytes: number,
  label: string,
): readonly number[] {
  if (!Number.isInteger(messageBytes) || messageBytes < 0 || messageBytes % 4 !== 0 ||
    message.length !== messageBytes / 4) {
    throw new Error("local SHA message geometry");
  }
  const padded = sha256Pad(new Uint8Array(messageBytes));
  const paddedWords = localShaWordsFromBytes(padded);
  const words = [
    ...message,
    ...paddedWords.slice(message.length).map((word) => builder.constant(word)),
  ];
  let state: readonly number[] = SHA256_IV.map((value) => builder.constant(value));
  for (let block = 0; block < padded.length / 64; block += 1) {
    state = compression(builder, state, words.slice(block * 16, block * 16 + 16), `${label}:block:${block}`);
  }
  return state;
}

/**
 * Compile the fixed SHA circuit for a list of independently padded jobs.
 * Private message words are the only inputs. IV and round constants are public
 * microcode, shared by every job. Multi-block state is connected by the same
 * static wire graph as all other values.
 */
export function compileLocalShaProgram(jobBlockCounts: readonly number[]): LocalShaProgram {
  if (jobBlockCounts.length < 1 || jobBlockCounts.some((count) => !Number.isInteger(count) || count < 1)) {
    throw new Error("local SHA jobs");
  }
  const builder = new LocalShaCircuitBuilder();
  const iv = SHA256_IV.map((value) => builder.constant(value));
  const outputs: number[][] = [];
  for (let job = 0; job < jobBlockCounts.length; job += 1) {
    let state: readonly number[] = iv;
    for (let block = 0; block < jobBlockCounts[job]!; block += 1) {
      const words = Array.from({ length: 16 }, (_, word) => {
        return builder.input(`job:${job}:block:${block}:word:${word}`);
      });
      state = compression(builder, state, words, `job:${job}:block:${block}`);
    }
    outputs.push([...state]);
  }
  return builder.finish(outputs, jobBlockCounts);
}

function assertWireCell(program: LocalShaProgram, cell: LocalShaWireCell): void {
  if (!Number.isInteger(cell.wire) || cell.wire < 0 || cell.wire >= program.rows.length ||
    !Number.isInteger(cell.limb) || cell.limb < 0 || cell.limb >= LOCAL_SHA_LIMBS) {
    throw new Error("local SHA alias cell");
  }
}

/** Add semantic equalities to the one static copy relation. */
export function withLocalShaCopyAliases(
  program: LocalShaProgram,
  aliases: readonly LocalShaCopyAlias[],
): LocalShaProgram {
  for (const [left, right] of aliases) {
    assertWireCell(program, left);
    assertWireCell(program, right);
  }
  return { ...program, copyAliases: [...program.copyAliases, ...aliases] };
}

export function localShaProgramForMessages(messages: readonly Uint8Array[]): {
  readonly program: LocalShaProgram;
  readonly inputs: readonly number[];
} {
  if (messages.length < 1) throw new Error("local SHA messages");
  const padded = messages.map(sha256Pad);
  const program = compileLocalShaProgram(padded.map((message) => message.length / 64));
  const inputs = padded.flatMap((message) => Array.from({ length: message.length / 4 }, (_, word) =>
    wordFromBlock(message, word)));
  if (inputs.length !== program.inputLabels.length) throw new Error("local SHA input geometry");
  return { program, inputs };
}

export function executeLocalShaProgram(program: LocalShaProgram, inputs: readonly number[]): LocalShaExecution {
  if (inputs.length !== program.inputLabels.length) throw new Error("local SHA input count");
  const wireValues: number[] = [];
  for (let row = 0; row < program.rows.length; row += 1) {
    const instruction = program.rows[row]!;
    const a = instruction.a === undefined ? 0 : wireValues[instruction.a]!;
    const b = instruction.b === undefined ? 0 : wireValues[instruction.b]!;
    let out: number;
    if (instruction.operation === "input" || instruction.operation === "mask") {
      out = u32(inputs[instruction.input!]!);
    }
    else if (instruction.operation === "constant") out = instruction.literal!;
    else if (instruction.operation === "nonzero") out = a;
    else if (instruction.operation === "rotr") out = rotr(a, instruction.shift!);
    else if (instruction.operation === "xor") out = (a ^ b) >>> 0;
    else if (instruction.operation === "and") out = (a & b) >>> 0;
    else out = (a + b) >>> 0;
    wireValues.push(out);
  }
  return { wireValues, inputs: [...inputs] };
}

/** Fast exact check of the semantic aliases before constructing the full LogUp. */
export function verifyLocalShaExplicitAliases(
  program: LocalShaProgram,
  execution: LocalShaExecution,
): LocalShaViolation | undefined {
  if (execution.wireValues.length !== program.rows.length) return { row: -1, constraint: "execution-width" };
  for (const [left, right] of program.copyAliases) {
    assertWireCell(program, left);
    assertWireCell(program, right);
    const leftValue = (execution.wireValues[left.wire]! >>> (left.limb * LOCAL_SHA_LIMB_BITS)) & 15;
    const rightValue = (execution.wireValues[right.wire]! >>> (right.limb * LOCAL_SHA_LIMB_BITS)) & 15;
    if (leftValue !== rightValue) return { row: left.wire, constraint: "explicit-copy-alias" };
  }
  for (const [left, right] of program.wordAliases) {
    if (left < 0 || right < 0 || left >= program.rows.length || right >= program.rows.length ||
      execution.wireValues[left] !== execution.wireValues[right]) {
      return { row: left, constraint: "explicit-word-alias" };
    }
  }
  return undefined;
}

function zeroWord(): readonly M31El[] {
  return Array<M31El>(LOCAL_SHA_LIMBS).fill(0n);
}

export function buildLocalShaTrace(program: LocalShaProgram, execution: LocalShaExecution): LocalShaTrace {
  if (execution.wireValues.length !== program.rows.length) throw new Error("local SHA execution width");
  const rows = program.rows.map((_, row) => localShaTraceRowAt(program, execution, row));
  return { rows };
}

/** Construct one relation row without materializing the complete matrix. */
export function localShaTraceRowAt(
  program: LocalShaProgram,
  execution: LocalShaExecution,
  row: number,
): LocalShaTraceRow {
  const instruction = program.rows[row];
  if (!instruction || execution.wireValues.length !== program.rows.length) throw new Error("local SHA trace row");
  const aWord = instruction.a === undefined ? 0 : execution.wireValues[instruction.a]!;
  const bWord = instruction.b === undefined ? 0 : execution.wireValues[instruction.b]!;
  const outWord = execution.wireValues[row]!;
  const carry = Array<M31El>(LOCAL_SHA_LIMBS + 1).fill(0n);
  if (instruction.operation === "add") {
    const a = localShaWordLimbs(aWord);
    const b = localShaWordLimbs(bWord);
    for (let limb = 0; limb < LOCAL_SHA_LIMBS; limb += 1) {
      const sum = Number(a[limb]!) + Number(b[limb]!) + Number(carry[limb]!);
      carry[limb + 1] = BigInt(Math.floor(sum / LOCAL_SHA_RADIX));
    }
  }
  let a = instruction.a === undefined ? zeroWord() : localShaWordLimbs(aWord);
  let b = instruction.b === undefined ? zeroWord() : localShaWordLimbs(bWord);
  if (instruction.operation === "rotr") {
    const source = localShaWordLimbs(aWord);
    const limbShift = Math.floor(instruction.shift! / LOCAL_SHA_LIMB_BITS);
    a = Array.from({ length: LOCAL_SHA_LIMBS }, (_, limb) => source[(limb + limbShift) % LOCAL_SHA_LIMBS]!);
    b = instruction.shift! % LOCAL_SHA_LIMB_BITS === 0
      ? zeroWord()
      : Array.from({ length: LOCAL_SHA_LIMBS }, (_, limb) => source[(limb + limbShift + 1) % LOCAL_SHA_LIMBS]!);
  }
  return { a, b, out: localShaWordLimbs(outWord), carry };
}

function tracePort(row: LocalShaTraceRow, port: LocalShaPort): readonly M31El[] {
  return row[port];
}

export function compileLocalShaCopyCells(program: LocalShaProgram): readonly LocalShaCopyCell[] {
  const cellCount = program.rows.length * LOCAL_SHA_LIMBS;
  const parent = Int32Array.from({ length: cellCount }, (_, index) => index);
  const find = (cell: number): number => {
    let root = cell;
    while (parent[root] !== root) root = parent[root]!;
    while (parent[cell] !== cell) {
      const next = parent[cell]!;
      parent[cell] = root;
      cell = next;
    }
    return root;
  };
  const union = (left: LocalShaWireCell, right: LocalShaWireCell): void => {
    assertWireCell(program, left);
    assertWireCell(program, right);
    const leftRoot = find(left.wire * LOCAL_SHA_LIMBS + left.limb);
    const rightRoot = find(right.wire * LOCAL_SHA_LIMBS + right.limb);
    if (leftRoot !== rightRoot) parent[rightRoot] = leftRoot;
  };
  for (const [left, right] of program.copyAliases) union(left, right);
  for (const [left, right] of program.wordAliases) {
    if (left < 0 || right < 0 || left >= program.rows.length || right >= program.rows.length) {
      throw new Error("local SHA word alias");
    }
    for (let limb = 0; limb < LOCAL_SHA_LIMBS; limb += 1) {
      union({ wire: left, limb }, { wire: right, limb });
    }
  }

  const occurrences = new Map<number, Array<{
    row: number;
    port: LocalShaPort;
    limb: number;
    wire: number;
    wireLimb: number;
    identity: M31El;
  }>>();
  let identity = 1n;
  const addOccurrence = (
    row: number,
    port: LocalShaPort,
    limb: number,
    wire: number,
    wireLimb: number,
  ): void => {
    const key = find(wire * LOCAL_SHA_LIMBS + wireLimb);
    const cells = occurrences.get(key) ?? [];
    cells.push({ row, port, limb, wire, wireLimb, identity });
    occurrences.set(key, cells);
    identity += 1n;
  };
  for (let row = 0; row < program.rows.length; row += 1) {
    const instruction = program.rows[row]!;
    for (let limb = 0; limb < LOCAL_SHA_LIMBS; limb += 1) {
      addOccurrence(row, "out", limb, instruction.out, limb);
      if (instruction.a !== undefined) {
        const mapped = instruction.operation === "rotr"
          ? (limb + Math.floor(instruction.shift! / LOCAL_SHA_LIMB_BITS)) % LOCAL_SHA_LIMBS
          : limb;
        addOccurrence(row, "a", limb, instruction.a, mapped);
      }
      if (instruction.b !== undefined ||
        (instruction.operation === "rotr" && instruction.shift! % LOCAL_SHA_LIMB_BITS !== 0)) {
        const wire = instruction.operation === "rotr" ? instruction.a! : instruction.b!;
        const mapped = instruction.operation === "rotr"
          ? (limb + Math.floor(instruction.shift! / LOCAL_SHA_LIMB_BITS) + 1) % LOCAL_SHA_LIMBS
          : limb;
        addOccurrence(row, "b", limb, wire, mapped);
      }
    }
  }
  if (identity >= M31) throw new Error("local SHA copy identities exceed M31");
  const result: LocalShaCopyCell[] = [];
  for (const cells of occurrences.values()) {
    for (let i = 0; i < cells.length; i += 1) {
      result.push({ ...cells[i]!, sigma: cells[(i + 1) % cells.length]!.identity });
    }
  }
  return result.sort((left, right) => left.row - right.row ||
    PORTS.indexOf(left.port) - PORTS.indexOf(right.port) || left.limb - right.limb);
}

/**
 * Compact copy permutation for the full 2^18 graph. Unlike the object-rich
 * diagnostic compiler above, this stays in typed arrays and is suitable for
 * exact query-frame construction.
 */
export function compileLocalShaCopyPermutation(program: LocalShaProgram): LocalShaCopyPermutation {
  const wireCellCount = program.rows.length * LOCAL_SHA_LIMBS;
  const slotCount = localShaRelationRows(program) * LOCAL_SHA_COPY_CELLS_PER_ROW;
  const parent = Int32Array.from({ length: wireCellCount }, (_, index) => index);
  const find = (cell: number): number => {
    let root = cell;
    while (parent[root] !== root) root = parent[root]!;
    while (parent[cell] !== cell) {
      const next = parent[cell]!;
      parent[cell] = root;
      cell = next;
    }
    return root;
  };
  const union = (left: LocalShaWireCell, right: LocalShaWireCell): void => {
    assertWireCell(program, left);
    assertWireCell(program, right);
    const leftRoot = find(left.wire * LOCAL_SHA_LIMBS + left.limb);
    const rightRoot = find(right.wire * LOCAL_SHA_LIMBS + right.limb);
    if (leftRoot !== rightRoot) parent[rightRoot] = leftRoot;
  };
  for (const [left, right] of program.copyAliases) union(left, right);
  for (const [left, right] of program.wordAliases) {
    if (left < 0 || right < 0 || left >= program.rows.length || right >= program.rows.length) {
      throw new Error("local SHA word alias");
    }
    for (let limb = 0; limb < LOCAL_SHA_LIMBS; limb += 1) {
      union({ wire: left, limb }, { wire: right, limb });
    }
  }

  const identities = new Uint32Array(slotCount);
  const sigmas = new Uint32Array(slotCount);
  identities.fill(Number(LOCAL_SHA_COPY_INACTIVE_ID));
  sigmas.fill(Number(LOCAL_SHA_COPY_INACTIVE_ID));
  const firstIdentity = new Uint32Array(wireCellCount);
  const lastSlot = new Int32Array(wireCellCount);
  lastSlot.fill(-1);
  let identity = 1;
  const add = (row: number, port: LocalShaPort, limb: number, wire: number, wireLimb: number): void => {
    const slot = row * LOCAL_SHA_COPY_CELLS_PER_ROW + PORTS.indexOf(port) * LOCAL_SHA_LIMBS + limb;
    const root = find(wire * LOCAL_SHA_LIMBS + wireLimb);
    identities[slot] = identity;
    const previous = lastSlot[root]!;
    if (previous < 0) firstIdentity[root] = identity;
    else sigmas[previous] = identity;
    lastSlot[root] = slot;
    identity += 1;
  };
  for (let row = 0; row < program.rows.length; row += 1) {
    const instruction = program.rows[row]!;
    for (let limb = 0; limb < LOCAL_SHA_LIMBS; limb += 1) {
      add(row, "out", limb, instruction.out, limb);
      if (instruction.a !== undefined) {
        const mapped = instruction.operation === "rotr"
          ? (limb + Math.floor(instruction.shift! / LOCAL_SHA_LIMB_BITS)) % LOCAL_SHA_LIMBS
          : limb;
        add(row, "a", limb, instruction.a, mapped);
      }
      if (instruction.b !== undefined ||
        (instruction.operation === "rotr" && instruction.shift! % LOCAL_SHA_LIMB_BITS !== 0)) {
        const wire = instruction.operation === "rotr" ? instruction.a! : instruction.b!;
        const mapped = instruction.operation === "rotr"
          ? (limb + Math.floor(instruction.shift! / LOCAL_SHA_LIMB_BITS) + 1) % LOCAL_SHA_LIMBS
          : limb;
        add(row, "b", limb, wire, mapped);
      }
    }
  }
  if (identity >= Number(M31)) throw new Error("local SHA copy identities exceed M31");
  for (let root = 0; root < lastSlot.length; root += 1) {
    const slot = lastSlot[root]!;
    if (slot >= 0) sigmas[slot] = firstIdentity[root]!;
  }
  return { identities, sigmas };
}

function qmLinear(challenges: readonly QM31El[], values: readonly M31El[], gamma: QM31El): QM31El {
  if (challenges.length !== values.length) throw new Error("local SHA relation arity");
  let result = gamma;
  for (let i = 0; i < values.length; i += 1) {
    result = qmAdd(result, qmMul(challenges[i]!, liftM31(values[i]!)));
  }
  return result;
}

/** Reference value of the fixed copy LogUp. Honest traces sum to zero. */
export function localShaCopyLogupSum(
  program: LocalShaProgram,
  trace: LocalShaTrace,
  challenges: LocalShaCopyChallenges,
): QM31El {
  if (trace.rows.length !== program.rows.length) {
    throw new Error("local SHA copy LogUp shape");
  }
  let sum = QM31_ZERO;
  for (const cell of compileLocalShaCopyCells(program)) {
    const value = tracePort(trace.rows[cell.row]!, cell.port)[cell.limb]!;
    const identityDenominator = qmLinear(
      [challenges.identity, challenges.value],
      [cell.identity, value],
      challenges.gamma,
    );
    const sigmaDenominator = qmLinear(
      [challenges.identity, challenges.value],
      [cell.sigma, value],
      challenges.gamma,
    );
    sum = qmAdd(sum, qmSub(qmInv(identityDenominator), qmInv(sigmaDenominator)));
  }
  return sum;
}

function stitch(bits: 1 | 2 | 3, a: number, b: number): number {
  return ((a >>> bits) | ((b & ((1 << bits) - 1)) << (LOCAL_SHA_LIMB_BITS - bits))) &
    (LOCAL_SHA_RADIX - 1);
}

export function localShaLookupEntries(program: LocalShaProgram, trace: LocalShaTrace): readonly LocalShaLookupEntry[] {
  if (trace.rows.length !== program.rows.length) throw new Error("local SHA lookup trace");
  return program.rows.flatMap((instruction, row) => localShaLookupEntriesAtRow(instruction, trace.rows[row]!));
}

function localShaLookupEntriesAtRow(
  instruction: LocalShaRow,
  values: LocalShaTraceRow,
): readonly LocalShaLookupEntry[] {
  const tag = localShaInstructionLookupTag(instruction);
  const literal = instruction.operation === "constant" ? localShaWordLimbs(instruction.literal!) : undefined;
  return Array.from({ length: LOCAL_SHA_LIMBS }, (_, limb) => ({
    tag,
    // Uniform AIR tuple: fixed literal is nonzero only on constant rows.
    a: values.a[limb]! + (literal?.[limb] ?? 0n),
    b: values.b[limb]!,
    carryIn: values.carry[limb]!,
    out: values.out[limb]!,
    carryOut: values.carry[limb + 1]!,
  }));
}

export function localShaInstructionLookupTag(instruction: LocalShaRow): LocalShaLookupEntry["tag"] {
  return instruction.operation === "input" ? 0
    : instruction.operation === "mask" ? 8
    : instruction.operation === "constant" ? 1
    : instruction.operation === "xor" ? 2
    : instruction.operation === "and" ? 3
    : instruction.operation === "add" ? 4
    : instruction.operation === "nonzero" ? 9
    : instruction.shift! % LOCAL_SHA_LIMB_BITS === 0 ? 1
    : (4 + instruction.shift! % LOCAL_SHA_LIMB_BITS) as 5 | 6 | 7;
}

export function localShaLookupTable(): readonly LocalShaLookupEntry[] {
  const result: LocalShaLookupEntry[] = [];
  for (let out = 0; out < LOCAL_SHA_RADIX; out += 1) {
    result.push({ tag: 0, a: 0n, b: 0n, carryIn: 0n, out: BigInt(out), carryOut: 0n });
    result.push({ tag: 1, a: BigInt(out), b: 0n, carryIn: 0n, out: BigInt(out), carryOut: 0n });
  }
  for (const out of [0n, 15n]) {
    result.push({ tag: 8, a: 0n, b: 0n, carryIn: 0n, out, carryOut: 0n });
  }
  for (let value = 1n; value < 16n; value += 1n) {
    result.push({ tag: 9, a: value, b: 0n, carryIn: 0n, out: value, carryOut: 0n });
  }
  for (let a = 0; a < LOCAL_SHA_RADIX; a += 1) {
    for (let b = 0; b < LOCAL_SHA_RADIX; b += 1) {
      result.push({ tag: 2, a: BigInt(a), b: BigInt(b), carryIn: 0n, out: BigInt(a ^ b), carryOut: 0n });
      result.push({ tag: 3, a: BigInt(a), b: BigInt(b), carryIn: 0n, out: BigInt(a & b), carryOut: 0n });
      for (let carryIn = 0; carryIn <= 1; carryIn += 1) {
        const sum = a + b + carryIn;
        result.push({
          tag: 4,
          a: BigInt(a),
          b: BigInt(b),
          carryIn: BigInt(carryIn),
          out: BigInt(sum % LOCAL_SHA_RADIX),
          carryOut: BigInt(Math.floor(sum / LOCAL_SHA_RADIX)),
        });
      }
      for (let bits = 1 as 1 | 2 | 3; bits <= 3; bits = (bits + 1) as 1 | 2 | 3) {
        result.push({
          tag: (4 + bits) as 5 | 6 | 7,
          a: BigInt(a),
          b: BigInt(b),
          carryIn: 0n,
          out: BigInt(stitch(bits, a, b)),
          carryOut: 0n,
        });
      }
    }
  }
  if (result.length !== LOCAL_SHA_LOOKUP_TABLE_ROWS) throw new Error("local SHA universal table size");
  return result;
}

/** Exact universal-table access multiplicities without a full object trace. */
export function localShaTableMultiplicitiesForExecution(
  program: LocalShaProgram,
  execution: LocalShaExecution,
): Uint32Array {
  if (execution.wireValues.length !== program.rows.length) throw new Error("local SHA multiplicity execution");
  const table = localShaLookupTable();
  const tableIndex = new Map(table.map((entry, index) => [lookupKey(entry), index]));
  const multiplicities = new Uint32Array(table.length);
  for (let row = 0; row < program.rows.length; row += 1) {
    const traceRow = localShaTraceRowAt(program, execution, row);
    for (const entry of localShaLookupEntriesAtRow(program.rows[row]!, traceRow)) {
      const index = tableIndex.get(lookupKey(entry));
      if (index === undefined) throw new Error(`local SHA invalid lookup row ${row}`);
      multiplicities[index] += 1;
    }
  }
  if (multiplicities.some((value) => BigInt(value) >= M31)) throw new Error("local SHA table multiplicity M31");
  return multiplicities;
}

/** One exact relation-domain original/preprocessed frame for cross-language KATs. */
export function localShaRelationFrameAt(
  program: LocalShaProgram,
  execution: LocalShaExecution,
  permutation: LocalShaCopyPermutation,
  multiplicities: Uint32Array,
  row: number,
): LocalShaRelationFrame {
  const relationRows = localShaRelationRows(program);
  if (!Number.isInteger(row) || row < 0 || row >= relationRows ||
    permutation.identities.length !== relationRows * LOCAL_SHA_COPY_CELLS_PER_ROW ||
    permutation.sigmas.length !== permutation.identities.length ||
    multiplicities.length !== LOCAL_SHA_LOOKUP_TABLE_ROWS) {
    throw new Error("local SHA relation frame geometry");
  }
  const instruction = program.rows[row];
  const trace = instruction ? localShaTraceRowAt(program, execution, row) : {
    a: zeroWord(),
    b: zeroWord(),
    out: zeroWord(),
    carry: Array<M31El>(LOCAL_SHA_LIMBS + 1).fill(0n),
  };
  const original = [
    ...trace.a,
    ...trace.b,
    ...trace.out,
    ...trace.carry,
    BigInt(multiplicities[row] ?? 0),
  ];
  const literal = instruction?.operation === "constant"
    ? localShaWordLimbs(instruction.literal!)
    : zeroWord();
  const copy: M31El[] = [];
  const slotStart = row * LOCAL_SHA_COPY_CELLS_PER_ROW;
  for (let slot = 0; slot < LOCAL_SHA_COPY_CELLS_PER_ROW; slot += 1) {
    const index = slotStart + slot;
    copy.push(BigInt(permutation.identities[index] ?? 0), BigInt(permutation.sigmas[index] ?? 0));
  }
  const table = localShaLookupTable()[row];
  const preprocessed = [
    BigInt(instruction ? localShaInstructionLookupTag(instruction) : 0),
    ...literal,
    ...copy,
    instruction ? 1n : 0n,
    ...(table
      ? [BigInt(table.tag), table.a, table.b, table.carryIn, table.out, table.carryOut]
      : Array<M31El>(6).fill(0n)),
  ];
  if (original.length !== LOCAL_SHA_ORIGINAL_COLUMNS || preprocessed.length !== LOCAL_SHA_PREPROCESSED_COLUMNS) {
    throw new Error("local SHA relation frame width");
  }
  return { row, original, preprocessed };
}

function lookupKey(entry: LocalShaLookupEntry): string {
  return `${entry.tag}:${entry.a}:${entry.b}:${entry.carryIn}:${entry.out}:${entry.carryOut}`;
}

function paddingLookupEntry(): LocalShaLookupEntry {
  return { tag: 0, a: 0n, b: 0n, carryIn: 0n, out: 0n, carryOut: 0n };
}

/** Reference value of the universal four-bit lookup LogUp. Honest ledgers sum to zero. */
export function localShaLookupLogupSum(
  program: LocalShaProgram,
  trace: LocalShaTrace,
  challenges: LocalShaLookupChallenges,
): QM31El {
  const accesses = localShaLookupEntries(program, trace);
  const multiplicities = new Map<string, number>();
  for (const entry of accesses) multiplicities.set(lookupKey(entry), (multiplicities.get(lookupKey(entry)) ?? 0) + 1);
  let sum = QM31_ZERO;
  const denominator = (entry: LocalShaLookupEntry): QM31El => qmLinear(
    challenges.tuple,
    [BigInt(entry.tag), entry.a, entry.b, entry.carryIn, entry.out, entry.carryOut],
    challenges.gamma,
  );
  for (const entry of accesses) sum = qmAdd(sum, qmInv(denominator(entry)));
  for (const entry of localShaLookupTable()) {
    const multiplicity = multiplicities.get(lookupKey(entry)) ?? 0;
    if (multiplicity === 0) continue;
    sum = qmSub(sum, qmMul(liftM31(BigInt(multiplicity)), qmInv(denominator(entry))));
  }
  return sum;
}

type LocalShaFraction = { readonly numerator: QM31El; readonly denominator: QM31El };

function lookupDenominator(entry: LocalShaLookupEntry, challenges: LocalShaLookupChallenges): QM31El {
  return qmLinear(
    challenges.tuple,
    [BigInt(entry.tag), entry.a, entry.b, entry.carryIn, entry.out, entry.carryOut],
    challenges.gamma,
  );
}

function copyDenominator(
  identity: M31El,
  value: M31El,
  challenges: LocalShaCopyChallenges,
): QM31El {
  return qmLinear(
    [challenges.identity, challenges.value],
    [identity, value],
    challenges.gamma,
  );
}

function localShaTableMultiplicities(
  program: LocalShaProgram,
  trace: LocalShaTrace,
): readonly M31El[] {
  const table = localShaLookupTable();
  const tableIndex = new Map(table.map((entry, index) => [lookupKey(entry), index]));
  const multiplicities = Array<M31El>(table.length).fill(0n);
  const activeEntries = localShaLookupEntries(program, trace);
  for (const entry of activeEntries) {
    const index = tableIndex.get(lookupKey(entry));
    if (index === undefined) throw new Error("local SHA invalid lookup access");
    multiplicities[index] = multiplicities[index]! + 1n;
  }
  if (multiplicities.some((value) => value >= M31)) throw new Error("local SHA table multiplicity M31");
  return multiplicities;
}

function localShaInteractionFractionsAtRow(args: {
  readonly program: LocalShaProgram;
  readonly trace: LocalShaTrace;
  readonly row: number;
  readonly table: readonly LocalShaLookupEntry[];
  readonly tableMultiplicities: readonly M31El[];
  readonly copyByCell: ReadonlyMap<string, LocalShaCopyCell>;
  readonly challenges: LocalShaInteractionChallenges;
}): readonly LocalShaFraction[] {
  const instruction = args.program.rows[args.row];
  const traceRow = args.trace.rows[args.row];
  const accesses = instruction && traceRow
    ? localShaLookupEntriesAtRow(instruction, traceRow)
    : Array.from({ length: LOCAL_SHA_LIMBS }, paddingLookupEntry);
  if (accesses.length !== LOCAL_SHA_LIMBS) throw new Error("local SHA row lookup count");
  const fractions: LocalShaFraction[] = accesses.map((entry) => ({
    numerator: instruction ? QM31_ONE : QM31_ZERO,
    denominator: lookupDenominator(entry, args.challenges.lookup),
  }));
  const tableEntry = args.table[args.row];
  fractions.push(tableEntry === undefined
    ? { numerator: QM31_ZERO, denominator: QM31_ONE }
    : {
      numerator: qmNeg(liftM31(args.tableMultiplicities[args.row]!)),
      denominator: lookupDenominator(tableEntry, args.challenges.lookup),
    });
  for (const challenges of args.challenges.copy) {
    for (const port of PORTS) {
      for (let limb = 0; limb < LOCAL_SHA_LIMBS; limb += 1) {
        const cell = args.copyByCell.get(`${args.row}:${port}:${limb}`);
        if (!cell) {
          const value = traceRow ? tracePort(traceRow, port)[limb]! : 0n;
          fractions.push(
            {
              numerator: QM31_ONE,
              denominator: copyDenominator(LOCAL_SHA_COPY_INACTIVE_ID, value, challenges),
            },
            {
              numerator: qmNeg(QM31_ONE),
              denominator: copyDenominator(LOCAL_SHA_COPY_INACTIVE_ID, value, challenges),
            },
          );
          continue;
        }
        const value = tracePort(traceRow, port)[limb]!;
        fractions.push(
          { numerator: QM31_ONE, denominator: copyDenominator(cell.identity, value, challenges) },
          { numerator: qmNeg(QM31_ONE), denominator: copyDenominator(cell.sigma, value, challenges) },
        );
      }
    }
  }
  if (fractions.length !== LOCAL_SHA_INTERACTION_FRACTIONS) {
    throw new Error("local SHA interaction fraction count");
  }
  return fractions;
}

function localShaInteractionFractionGroups(
  fractions: readonly LocalShaFraction[],
): readonly (readonly LocalShaFraction[])[] {
  if (fractions.length !== LOCAL_SHA_INTERACTION_FRACTIONS) {
    throw new Error("local SHA interaction fraction geometry");
  }
  const groups = fractions.map((fraction) => [fraction]);
  if (groups.length !== LOCAL_SHA_INTERACTION_QM31_COLUMNS) {
    throw new Error("local SHA interaction group count");
  }
  return groups;
}

/**
 * Build the exact quadratic relation-domain LogUp columns. Each fraction owns
 * one cumulative column, keeping the quotient quadratic and locally checkable.
 */
export function buildLocalShaInteractionTrace(
  program: LocalShaProgram,
  trace: LocalShaTrace,
  challenges: LocalShaInteractionChallenges,
): LocalShaInteractionTrace {
  if (trace.rows.length !== program.rows.length) throw new Error("local SHA interaction trace shape");
  const relationRows = localShaRelationRows(program);
  const table = localShaLookupTable();
  const tableMultiplicities = localShaTableMultiplicities(program, trace);
  const copyByCell = new Map(compileLocalShaCopyCells(program).map((cell) =>
    [`${cell.row}:${cell.port}:${cell.limb}`, cell]));
  const columns: QM31El[][] = Array.from({ length: LOCAL_SHA_INTERACTION_QM31_COLUMNS }, () =>
    Array<QM31El>(relationRows).fill(QM31_ZERO));
  let claimedSum = QM31_ZERO;
  for (let row = 0; row < relationRows; row += 1) {
    const fractions = localShaInteractionFractionsAtRow({
      program,
      trace,
      row,
      table,
      tableMultiplicities,
      copyByCell,
      challenges,
    });
    const groups = localShaInteractionFractionGroups(fractions);
    let rowCumulative = QM31_ZERO;
    for (let column = 0; column < groups.length - 1; column += 1) {
      for (const fraction of groups[column]!) {
        if (!qmEq(fraction.numerator, QM31_ZERO)) {
          rowCumulative = qmAdd(rowCumulative, qmMul(fraction.numerator, qmInv(fraction.denominator)));
        }
      }
      columns[column]![row] = rowCumulative;
    }
    for (const fraction of groups.at(-1)!) {
      if (!qmEq(fraction.numerator, QM31_ZERO)) {
        rowCumulative = qmAdd(rowCumulative, qmMul(fraction.numerator, qmInv(fraction.denominator)));
      }
    }
    claimedSum = qmAdd(claimedSum, rowCumulative);
    columns[columns.length - 1]![row] = claimedSum;
  }
  if (!qmEq(claimedSum, QM31_ZERO)) throw new Error("local SHA interaction claimed sum");
  return { relationRows, tableMultiplicities, columns, claimedSum };
}

/** First exact relation-domain LogUp failure, or undefined. */
export function verifyLocalShaInteractionTrace(
  program: LocalShaProgram,
  trace: LocalShaTrace,
  interaction: LocalShaInteractionTrace,
  challenges: LocalShaInteractionChallenges,
): LocalShaViolation | undefined {
  const relationRows = localShaRelationRows(program);
  if (interaction.relationRows !== relationRows ||
    interaction.columns.length !== LOCAL_SHA_INTERACTION_QM31_COLUMNS ||
    interaction.columns.some((column) => column.length !== relationRows)) {
    return { row: -1, constraint: "interaction-shape" };
  }
  const table = localShaLookupTable();
  const expectedMultiplicities = localShaTableMultiplicities(program, trace);
  if (interaction.tableMultiplicities.length !== expectedMultiplicities.length ||
    interaction.tableMultiplicities.some((value, index) => value !== expectedMultiplicities[index])) {
    return { row: -1, constraint: "interaction-multiplicity" };
  }
  const copyByCell = new Map(compileLocalShaCopyCells(program).map((cell) =>
    [`${cell.row}:${cell.port}:${cell.limb}`, cell]));
  for (let row = 0; row < relationRows; row += 1) {
    const fractions = localShaInteractionFractionsAtRow({
      program,
      trace,
      row,
      table,
      tableMultiplicities: interaction.tableMultiplicities,
      copyByCell,
      challenges,
    });
    const groups = localShaInteractionFractionGroups(fractions);
    let previousColumn = QM31_ZERO;
    for (let column = 0; column < groups.length; column += 1) {
      const current = interaction.columns[column]![row]!;
      const difference = column === groups.length - 1
        ? qmSub(qmSub(current, interaction.columns[column]![row === 0 ? relationRows - 1 : row - 1]!), previousColumn)
        : qmSub(current, previousColumn);
      const expected = groups[column]!.reduce((sum, fraction) => qmEq(fraction.numerator, QM31_ZERO)
        ? sum
        : qmAdd(sum, qmMul(fraction.numerator, qmInv(fraction.denominator))), QM31_ZERO);
      if (!qmEq(difference, expected)) {
        return { row, constraint: `interaction:${column}` };
      }
      previousColumn = current;
    }
  }
  if (!qmEq(interaction.claimedSum, QM31_ZERO) ||
    !qmEq(interaction.columns[interaction.columns.length - 1]![relationRows - 1]!, QM31_ZERO)) {
    return { row: relationRows - 1, constraint: "interaction-boundary" };
  }
  return undefined;
}

function allZero(values: readonly M31El[]): boolean {
  return values.every((value) => value === 0n);
}

function sameWord(left: readonly M31El[], right: readonly M31El[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

export function verifyLocalShaTrace(program: LocalShaProgram, trace: LocalShaTrace): LocalShaViolation | undefined {
  if (trace.rows.length !== program.rows.length) return { row: -1, constraint: "row-count" };
  for (let row = 0; row < program.rows.length; row += 1) {
    const instruction = program.rows[row]!;
    const values = trace.rows[row]!;
    if ([values.a, values.b, values.out].some((word) => word.length !== LOCAL_SHA_LIMBS) ||
      values.carry.length !== LOCAL_SHA_LIMBS + 1) {
      return { row, constraint: "row-width" };
    }
    if ([...values.a, ...values.b, ...values.out].some((value) => value < 0n || value >= 16n)) {
      return { row, constraint: "limb-range" };
    }
    if (values.carry.some((value) => value !== 0n && value !== 1n)) return { row, constraint: "carry-bit" };
    if (instruction.a === undefined && !allZero(values.a)) return { row, constraint: "unused-a" };
    if (instruction.b === undefined &&
      (instruction.operation !== "rotr" || instruction.shift! % LOCAL_SHA_LIMB_BITS === 0) &&
      !allZero(values.b)) {
      return { row, constraint: "unused-b" };
    }
    if (instruction.operation !== "add" && !allZero(values.carry)) return { row, constraint: "unused-carry" };
    const out = localShaLimbsWord(values.out);
    if (instruction.operation === "constant" && out !== instruction.literal) return { row, constraint: "constant" };
    if (instruction.operation === "add") {
      if (values.carry[0] !== 0n) return { row, constraint: "add-carry-start" };
      for (let limb = 0; limb < LOCAL_SHA_LIMBS; limb += 1) {
        if (values.a[limb]! + values.b[limb]! + values.carry[limb]! !==
          values.out[limb]! + 16n * values.carry[limb + 1]!) {
          return { row, constraint: "add-identity" };
        }
      }
    }
  }
  const copyCells = compileLocalShaCopyCells(program);
  const byIdentity = new Map(copyCells.map((cell) => [cell.identity, cell]));
  for (const cell of copyCells) {
    const next = byIdentity.get(cell.sigma);
    const value = tracePort(trace.rows[cell.row]!, cell.port)[cell.limb];
    const nextValue = next === undefined ? undefined : tracePort(trace.rows[next.row]!, next.port)[next.limb];
    if (nextValue === undefined || value !== nextValue) {
      return { row: cell.row, constraint: `copy:${cell.port}` };
    }
  }
  const table = new Set(localShaLookupTable().map(lookupKey));
  const invalid = localShaLookupEntries(program, trace).find((entry) => !table.has(lookupKey(entry)));
  if (invalid) return { row: -1, constraint: "lookup" };
  return undefined;
}

export function localShaOutputWords(program: LocalShaProgram, execution: LocalShaExecution, job: number): readonly number[] {
  const outputs = program.outputs[job];
  if (!outputs) throw new Error("local SHA output job");
  return outputs.map((wire) => execution.wireValues[wire]!);
}

export function localShaOutputBytes(program: LocalShaProgram, execution: LocalShaExecution, job: number): Uint8Array {
  const bytes = new Uint8Array(32);
  for (const [word, value] of localShaOutputWords(program, execution, job).entries()) {
    bytes[word * 4] = value >>> 24;
    bytes[word * 4 + 1] = value >>> 16;
    bytes[word * 4 + 2] = value >>> 8;
    bytes[word * 4 + 3] = value;
  }
  return bytes;
}

export type LocalShaGeometry = {
  readonly activeRows: number;
  readonly relationRows: number;
  readonly sealedDegreeBound: number;
  readonly quotientDegreeBound: number;
  readonly ldeRows: number;
  readonly openedM31ValuesPerQuery: number;
  readonly directValueBytes: number;
};

export type LocalShaSoundnessProjection = {
  readonly lookupTerms: number;
  readonly copyTermsPerLane: number;
  readonly lookupBits: number;
  readonly singleCopyLaneBits: number;
  readonly independentCopyLanesBits: number;
  readonly friQueryConjectureBits: number;
  readonly conservativeUnionBits: number;
  readonly meetsFloor: boolean;
  readonly claimBoundary: "projection-pending-quotient-and-transcript-integration";
};

function unionBits(bits: readonly number[]): number {
  return -Math.log2(bits.reduce((probability, security) => probability + 2 ** -security, 0));
}

/** Geometry if this machine replaces, rather than wraps, the wide SHA AIR. */
export function localShaGeometry(
  program: LocalShaProgram,
  queries = LOCAL_WORD_QUERIES,
  quotientBlowupLog = LOCAL_WORD_FRI_LOG_BLOWUP,
): LocalShaGeometry {
  const relationRows = localShaRelationRows(program);
  const sealedDegreeBound = relationRows * 2;
  const quotientDegreeBound = nextPowerOfTwo(sealedDegreeBound * 2);
  const ldeRows = quotientDegreeBound * 2 ** quotientBlowupLog;
  const openedM31ValuesPerQuery = LOCAL_SHA_ORIGINAL_COLUMNS + LOCAL_SHA_PREPROCESSED_COLUMNS +
    LOCAL_SHA_INTERACTION_M31_COLUMNS + 4 * LOCAL_SHA_INTERACTION_PREVIOUS_QM31_COLUMNS;
  return {
    activeRows: program.rows.length,
    relationRows,
    sealedDegreeBound,
    quotientDegreeBound,
    ldeRows,
    openedM31ValuesPerQuery,
    directValueBytes: openedM31ValuesPerQuery * 4 * queries,
  };
}

/**
 * Conservative ROM worksheet for the replacement relation. It charges the
 * active row count for the eight lookup accesses and the full padded row count
 * for all 24 fixed copy slots. Two copy lanes are independently sampled. The
 * 112/114-bit terms retain the wider predecessor's constraint/oracle bounds
 * until the replacement quotient fixes smaller exact counts.
 */
export function localShaSoundnessProjection(
  program: LocalShaProgram,
  floorBits = 100,
): LocalShaSoundnessProjection {
  const geometry = localShaGeometry(program);
  const lookupTerms = program.rows.length * LOCAL_SHA_MAX_LOOKUPS_PER_ROW + LOCAL_SHA_LOOKUP_TABLE_ROWS;
  const copyTermsPerLane = geometry.relationRows * LOCAL_SHA_COPY_CELLS_PER_ROW;
  const lookupBits = QM31_FIELD_BITS - Math.log2(lookupTerms);
  const singleCopyLaneBits = QM31_FIELD_BITS - Math.log2(copyTermsPerLane);
  const independentCopyLanesBits = singleCopyLaneBits * LOCAL_SHA_COPY_LANES;
  const friQueryConjectureBits = LOCAL_WORD_QUERY_CONJECTURE_BITS;
  const conservativeUnionBits = unionBits([
    112,
    114,
    lookupBits,
    independentCopyLanesBits,
    friQueryConjectureBits,
  ]);
  return {
    lookupTerms,
    copyTermsPerLane,
    lookupBits,
    singleCopyLaneBits,
    independentCopyLanesBits,
    friQueryConjectureBits,
    conservativeUnionBits,
    meetsFloor: conservativeUnionBits >= floorBits,
    claimBoundary: "projection-pending-quotient-and-transcript-integration",
  };
}

export function localShaQm31IsZero(value: QM31El): boolean {
  return qmEq(value, QM31_ZERO);
}

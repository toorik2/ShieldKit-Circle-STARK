import { binToHex, cashAssemblyToBin } from "@bitauth/libauth";
import {
  LOCAL_WORD_MATRIX_NAMES,
  LOCAL_WORD_MATRIX_ROW_WIDTHS,
  localWordProofStaticOffsets,
} from "../backends/circle/local-word-sealed-proof.ts";
import { LOCAL_WORD_RELATION_STATEMENT_DIGEST_WORDS } from
  "../backends/circle/local-word-public-statement.ts";
import {
  LOCAL_WORD_PRODUCTION_PARAMETERS,
  localWordFriFoldCounts,
  validateLocalWordProofParameters,
  type LocalWordProofParameters,
} from "../backends/circle/local-word-successor-params.ts";
import { encodeQm31 } from "../backends/circle/qm31.ts";
import { CIRCLE_GEN, scalarMul } from "../backends/circle/group.ts";
import { v17ProofFrameOffset } from "../backends/circle/v17-proof-layout.ts";
import { V17_PRODUCTION_ROUND_GRINDING } from "../construction/v17-graph.ts";
import { V17_THEOREM_ROUND_IDS } from "../backends/circle/v17-round-transcript.ts";
import { V17_FRI_CURRENT_DENOMINATOR_COUNT } from
  "../backends/circle/v17-fri-arithmetic.ts";
import {
  V17_BATCH_LEADER_CELL_BYTES,
  V17_BATCH_LEADER_CELL_FIELD_COUNT,
  V17_BATCH_LEADER_CELL_FLAGS,
  V17_BATCH_LEADER_CELL_HEADER_BYTES,
  V17_BATCH_LEADER_CELL_MAGIC,
  V17_BATCH_LEADER_CELL_VERSION,
} from "../backends/circle/v17-batch-leader-cell.ts";
import { concatBytes, writeU32LE } from "../pool/bytes.ts";
import { LOCAL_WORD_BATCH_LEADER_INPUT_INDEX } from "./local-word-proof-carriers.ts";
import {
  localWordProofLengthAssembly,
  localWordReadDynamicAssembly,
  type LocalWordProofReader,
} from "./local-word-balanced-vm.ts";
import { M31_ADD, M31_INV, M31_MUL, M31_P, M31_SUB } from "./m31-asm.ts";
import {
  BLOB_TO_QM31_ASM,
  QM31_ADD_ASM,
  QM31_REDUCE_COEFFICIENTS_ASM,
  QM31_MUL_ASM,
  QM31_MUL_M31_ASM,
  QM31_TO_BLOB_ASM,
  copy4,
} from "./qm31-asm.ts";
import { v17M31BatchInverseBlobAssembly } from "./v17-fri-arithmetic-vm.ts";
import {
  v17OodsCandidateAcceptanceAssembly,
  v17OodsDigestToTAssembly,
  v17OodsSelectDigestAssembly,
} from "./v17-oods-vm.ts";

const READ_BYTES = 0;
const READ_QM31 = 1;
const READ_CANONICAL_QM31 = 2;
const QM31_MUL = 3;
const QM31_MUL_M31 = 4;
const QM31_ADD = 5;
const QM31_SUB = 6;
const QM31_TO_BLOB = 7;
const M31_INVERSE = 8;
const CIRCLE_ADD = 9;
const CIRCLE_SCALAR_MUL = 10;
const QM31_BLOB_MUL = 11;
const QM31_BLOB_MUL_M31 = 12;
const QM31_BLOB_ADD = 13;
const QM31_BLOB_SUB = 14;
const FRI_FOLD_PAIR = 15;
const FRI_FOLD_LAYER2 = 16;
const FRI_FOLD_LAYER1 = 17;
const FRI_LINEAR_COMBINATION = 18;
const FRI_FINAL_EVALUATION = 19;
const FRI_DOMAIN_TWIDDLES = 20;
const FRI_BATCH_INVERT_TWIDDLES = 21;
const V17_OODS_CANDIDATE = 22;
const V17_LIFT_M31_ROW = 23;
const V17_QM31_WIDE_PACK_BLOB = 24;
const V17_QM31_WIDE_REDUCE_PRODUCT = 25;
const V17_QM31_FUSED_DOT = 26;
const V17_FRI_BATCH_SEMANTIC_BODY = 27;
const V17_FRI_BATCH_LEADER_AUTH = 28;
const V17_FRI_BATCH_OUTER_KERNEL = 29;
const V17_FRI_FOLD_OUTER_KERNEL = 30;
const V17_FRI_FOLD_FROM_INVERSE = 31;
const V17_QM31_PACK_BETA_WEIGHTS = 32;
const V17_QM31_DOT_PACKED_WEIGHTS = 33;
const V17_FRI_BATCH_LOCAL_ORCHESTRATOR = 34;
const V17_FRI_FOLD_LOCAL_ORCHESTRATOR = 35;

const V17_QM31_FUSED_BITS = 72;
const V17_QM31_FUSED_WORD_BYTES = V17_QM31_FUSED_BITS / 8;
const V17_QM31_FUSED_PRODUCT_BYTES = V17_QM31_FUSED_WORD_BYTES * 9;
const V17_QM31_FUSED_MAX_TERMS = 10;
const V17_QM31_PACKED_ELEMENT_BYTES = 40;
function compile(assembly: string, label: string): Uint8Array {
  const result = cashAssemblyToBin(assembly);
  if (typeof result === "string") throw new Error(`${label}: ${result}`);
  if (result.length > 10_000) throw new Error(`${label} locking limit ${result.length}`);
  return result;
}

function define(assembly: string, id: number, label: string): string {
  const bytecode = compile(assembly, label);
  return `<0x${binToHex(bytecode)}> <${id}> OP_DEFINE`;
}

function canonicalQm31Assembly(): string {
  const check = (depth: number): string => `<${depth}> OP_PICK
OP_DUP OP_0 OP_GREATERTHANOREQUAL OP_VERIFY
OP_DUP <${M31_P}> OP_LESSTHAN OP_VERIFY OP_DROP`;
  return `${BLOB_TO_QM31_ASM}
${Array.from({ length: 4 }, (_, depth) => check(depth)).join("\n")}`;
}

function v17BatchLeaderCellHeader(profile: 0 | 1 | 2): Uint8Array {
  return concatBytes(
    V17_BATCH_LEADER_CELL_MAGIC,
    Uint8Array.of(
      V17_BATCH_LEADER_CELL_VERSION,
      profile,
      V17_BATCH_LEADER_CELL_FIELD_COUNT,
      V17_BATCH_LEADER_CELL_FLAGS,
    ),
  );
}

/**
 * Read query zero's exact second push. Query zero alone authenticates and
 * canonicalizes the cell; followers consume that graph-owned result under the
 * transaction-wide conjunction rather than repeating its 13 field checks.
 */
function v17BatchLeaderCellFromInputAssembly(): string {
  return `<${LOCAL_WORD_BATCH_LEADER_INPUT_INDEX}> OP_INPUTBYTECODE
<1> OP_SPLIT OP_SWAP <0x4d> OP_EQUALVERIFY
<2> OP_SPLIT OP_SWAP OP_BIN2NUM
OP_DUP <256> OP_GREATERTHANOREQUAL OP_VERIFY
OP_DUP <10000> OP_LESSTHANOREQUAL OP_VERIFY
OP_SPLIT OP_NIP
<1> OP_SPLIT OP_SWAP <0x4c> OP_EQUALVERIFY
<1> OP_SPLIT OP_SWAP <0x${V17_BATCH_LEADER_CELL_BYTES.toString(16)}> OP_EQUALVERIFY
<${V17_BATCH_LEADER_CELL_BYTES}> OP_SPLIT OP_DROP`;
}

/** Move the top item beneath exactly `depth` existing items. */
function insertTopBelowAssembly(depth: number): string {
  if (!Number.isInteger(depth) || depth < 1) throw new Error("v17 batch insert depth");
  return Array.from({ length: depth }, () => `<${depth}> OP_ROLL`).join("\n");
}

function qm31SubtractAssembly(): string {
  return `<4> OP_PICK OP_1 OP_PICK ${M31_SUB} OP_TOALTSTACK
<5> OP_PICK <2> OP_PICK ${M31_SUB} OP_TOALTSTACK
<6> OP_PICK <3> OP_PICK ${M31_SUB} OP_TOALTSTACK
<7> OP_PICK <4> OP_PICK ${M31_SUB} OP_TOALTSTACK
OP_2DROP OP_2DROP OP_2DROP OP_2DROP
OP_FROMALTSTACK OP_FROMALTSTACK OP_FROMALTSTACK OP_FROMALTSTACK`;
}

function rowBlobAssembly(args: {
  readonly existing: number;
  readonly rankOffset: number;
  readonly rankLimit: number;
  readonly rowWidth: number;
  readonly rowsStartOffset: number;
}): string {
  return `${prefetchedBlobAssembly(args.existing, args.rankOffset, 1)}
<0x00> OP_CAT OP_BIN2NUM
OP_DUP OP_0 OP_GREATERTHANOREQUAL OP_VERIFY
OP_DUP <${args.rankLimit}> OP_LESSTHAN OP_VERIFY
<${args.rowWidth}> OP_MUL
${prefetchedBlobAssembly(args.existing + 1, args.rowsStartOffset, 4)}
OP_REVERSEBYTES OP_BIN2NUM OP_ADD
<${args.existing}> OP_PICK OP_SWAP <${args.rowWidth}> <${READ_BYTES}> OP_INVOKE OP_NIP`;
}

function staticBlobAssembly(existing: number, offset: number, width: number): string {
  return `<${existing - 1}> OP_PICK <${offset}> <${width}> <${READ_BYTES}> OP_INVOKE OP_NIP`;
}

/** Slice one fixed-prefix field from the single retained [0, openingBodies) frame. */
function prefetchedBlobAssembly(existing: number, offset: number, width: number): string {
  if (!Number.isInteger(existing) || existing < 2 || !Number.isInteger(offset) || offset < 0 ||
    !Number.isInteger(width) || width < 1) {
    throw new Error("local-word prefetched proof field");
  }
  // proofLength is base zero and the retained fixed prefix is base one.
  return `<${existing - 2}> OP_PICK <${offset}> OP_SPLIT OP_NIP
<${width}> OP_SPLIT OP_DROP`;
}

/**
 * Slice a query-indexed fixed-prefix field while retaining the runtime query
 * beneath helper-local alternate-stack work.
 */
function prefetchedRuntimeQueryBlobAssembly(args: {
  readonly existing: number;
  readonly offset: number;
  readonly stride: number;
  readonly width: number;
}): string {
  if (!Number.isInteger(args.existing) || args.existing < 2 ||
    !Number.isInteger(args.offset) || args.offset < 0 ||
    !Number.isInteger(args.stride) || args.stride < 1 ||
    !Number.isInteger(args.width) || args.width < 1) {
    throw new Error("local-word runtime-query proof field");
  }
  // The runtime query is retained on the alternate stack. Copy it without
  // consuming it, then select the graph-fixed field from the retained prefix.
  return `<${args.existing - 2}> OP_PICK
OP_FROMALTSTACK OP_DUP OP_TOALTSTACK
<${args.stride}> OP_MUL <${args.offset}> OP_ADD
OP_SPLIT OP_NIP <${args.width}> OP_SPLIT OP_DROP`;
}

function runtimeQueryGuardAssembly(minimum: number, limit: number): string {
  if (!Number.isInteger(minimum) || minimum < 0 || !Number.isInteger(limit) ||
    limit <= minimum) {
    throw new Error("local-word runtime query bounds");
  }
  return `OP_DUP <${minimum}> OP_GREATERTHANOREQUAL OP_VERIFY
OP_DUP <${limit}> OP_LESSTHAN OP_VERIFY
OP_TOALTSTACK`;
}

function runtimeQueryRowBlobAssembly(args: {
  readonly existing: number;
  readonly rankOffset: number;
  readonly rankLimit: number;
  readonly rowWidth: number;
  readonly rowsStartOffset: number;
}): string {
  return `${prefetchedRuntimeQueryBlobAssembly({
    existing: args.existing,
    offset: args.rankOffset,
    stride: 1,
    width: 1,
  })}
<0x00> OP_CAT OP_BIN2NUM
OP_DUP OP_0 OP_GREATERTHANOREQUAL OP_VERIFY
OP_DUP <${args.rankLimit}> OP_LESSTHAN OP_VERIFY
<${args.rowWidth}> OP_MUL
${prefetchedBlobAssembly(args.existing + 1, args.rowsStartOffset, 4)}
OP_REVERSEBYTES OP_BIN2NUM OP_ADD
<${args.existing}> OP_PICK OP_SWAP <${args.rowWidth}> <${READ_BYTES}> OP_INVOKE OP_NIP`;
}

function friQueryRowBlobAssembly(args: {
  readonly existing: number;
  readonly query: number;
  readonly offsets: ReturnType<typeof localWordProofStaticOffsets>;
  readonly parameters: LocalWordProofParameters;
}): string {
  const arity = 2 ** args.parameters.fri.foldLog;
  const directoryOffset = args.offsets.openingDirectory + LOCAL_WORD_MATRIX_NAMES.length * 20;
  return `${prefetchedBlobAssembly(
    args.existing,
    args.offsets.friCosetRanks + args.query,
    1,
  )}
<0x00> OP_CAT OP_BIN2NUM
OP_DUP OP_0 OP_GREATERTHANOREQUAL OP_VERIFY
OP_DUP <${args.parameters.fri.queries * arity}> OP_LESSTHAN OP_VERIFY
${prefetchedBlobAssembly(args.existing + 1, args.offsets.queries + args.query * 4, 4)}
OP_REVERSEBYTES OP_BIN2NUM <${arity}> OP_MOD OP_ADD
<16> OP_MUL
${prefetchedBlobAssembly(args.existing + 1, directoryOffset + 4, 4)}
OP_REVERSEBYTES OP_BIN2NUM OP_ADD
<${args.existing}> OP_PICK OP_SWAP <16> <${READ_BYTES}> OP_INVOKE OP_NIP`;
}

function runtimeFriQueryRowBlobAssembly(args: {
  readonly existing: number;
  readonly offsets: ReturnType<typeof localWordProofStaticOffsets>;
  readonly parameters: LocalWordProofParameters;
}): string {
  const arity = 2 ** args.parameters.fri.foldLog;
  const directoryOffset = args.offsets.openingDirectory + LOCAL_WORD_MATRIX_NAMES.length * 20;
  return `${prefetchedRuntimeQueryBlobAssembly({
    existing: args.existing,
    offset: args.offsets.friCosetRanks,
    stride: 1,
    width: 1,
  })}
<0x00> OP_CAT OP_BIN2NUM
OP_DUP OP_0 OP_GREATERTHANOREQUAL OP_VERIFY
OP_DUP <${args.parameters.fri.queries * arity}> OP_LESSTHAN OP_VERIFY
${prefetchedRuntimeQueryBlobAssembly({
    existing: args.existing + 1,
    offset: args.offsets.queries,
    stride: 4,
    width: 4,
  })}
OP_REVERSEBYTES OP_BIN2NUM <${arity}> OP_MOD OP_ADD
<16> OP_MUL
${prefetchedBlobAssembly(args.existing + 1, directoryOffset + 4, 4)}
OP_REVERSEBYTES OP_BIN2NUM OP_ADD
<${args.existing}> OP_PICK OP_SWAP <16> <${READ_BYTES}> OP_INVOKE OP_NIP`;
}

class BlobAssembly {
  readonly lines: string[] = [];
  extra = 0;

  constructor(readonly baseCount: number) {}

  private depth(base: number, added = 0): number {
    return this.baseCount + this.extra + added - 1 - base;
  }

  readQm31(base: number, byteOffset = 0, canonical = false): void {
    this.lines.push(`<${this.depth(base)}> OP_PICK <${byteOffset}> OP_SPLIT OP_NIP
<16> OP_SPLIT OP_DROP <${canonical ? READ_CANONICAL_QM31 : READ_QM31}> OP_INVOKE`);
    this.extra += 4;
  }

  readM31(base: number): void {
    this.lines.push(`<${this.depth(base)}> OP_PICK`);
    this.extra += 1;
  }

  qmMul(): void {
    this.lines.push(`<${QM31_MUL}> OP_INVOKE`);
    this.extra -= 4;
  }

  qmMulM31(): void {
    this.lines.push(`<${QM31_MUL_M31}> OP_INVOKE`);
    this.extra -= 1;
  }

  qmAdd(): void {
    this.lines.push(`<${QM31_ADD}> OP_INVOKE`);
    this.extra -= 4;
  }

  qmSub(): void {
    this.lines.push(`<${QM31_SUB}> OP_INVOKE`);
    this.extra -= 4;
  }

  encode(): void {
    this.lines.push(`<${QM31_TO_BLOB}> OP_INVOKE`);
    this.extra -= 3;
  }
}

/** Tiny compile-time stack tracker for blob-level verifier functions. */
class ElementAssembly {
  readonly lines: string[] = [];

  constructor(readonly stack: string[]) {}

  private depth(name: string): number {
    const index = this.stack.lastIndexOf(name);
    if (index < 0) throw new Error(`local-word algebra missing ${name}`);
    return this.stack.length - 1 - index;
  }

  copy(name: string, copy: string): void {
    this.lines.push(`<${this.depth(name)}> OP_PICK`);
    this.stack.push(copy);
  }

  constant(bytes: Uint8Array, name: string): void {
    this.lines.push(`<0x${binToHex(bytes)}>`);
    this.stack.push(name);
  }

  slice(name: string, offset: number, width: number, result: string): void {
    this.lines.push(`<${this.depth(name)}> OP_PICK <${offset}> OP_SPLIT OP_NIP
<${width}> OP_SPLIT OP_DROP`);
    this.stack.push(result);
  }

  m31(name: string, offset: number, result: string): void {
    this.slice(name, offset, 4, result);
    this.lines.push("OP_BIN2NUM");
  }

  liftM31(name: string, offset: number, result: string): void {
    this.slice(name, offset, 4, result);
    this.lines.push("<0x000000000000000000000000> OP_CAT");
  }

  derivedM31(name: string, assembly: string, result: string): void {
    this.copy(name, `${result}:input`);
    this.lines.push(assembly);
    this.stack.pop();
    this.stack.push(result);
  }

  call(id: number, inputs: readonly string[], result: string): void {
    inputs.forEach((input, index) => this.copy(input, `${result}:arg${index}`));
    this.lines.push(`<${id}> OP_INVOKE`);
    this.stack.splice(this.stack.length - inputs.length, inputs.length, result);
  }

  callMany(id: number, inputs: readonly string[], results: readonly string[]): void {
    if (results.length < 1) throw new Error("local-word algebra empty call result");
    inputs.forEach((input, index) => this.copy(input, `${results[0]}:arg${index}`));
    this.lines.push(`<${id}> OP_INVOKE`);
    this.stack.splice(this.stack.length - inputs.length, inputs.length, ...results);
  }

  invokeTop(id: number, count: number, result: string): void {
    this.lines.push(`<${id}> OP_INVOKE`);
    this.stack.splice(this.stack.length - count, count, result);
  }

  concat(inputs: readonly string[], result: string): void {
    if (inputs.length < 1) throw new Error("local-word algebra empty concatenation");
    inputs.forEach((input, index) => this.copy(input, `${result}:part${index}`));
    this.lines.push(...Array.from({ length: inputs.length - 1 }, () => "OP_CAT"));
    this.stack.splice(this.stack.length - inputs.length, inputs.length, result);
  }

  finish(result: string): string {
    if (this.stack.at(-1) !== result) this.copy(result, `${result}:final`);
    this.lines.push("OP_TOALTSTACK");
    this.stack.pop();
    this.lines.push(...Array.from({ length: this.stack.length }, () => "OP_DROP"));
    this.lines.push("OP_FROMALTSTACK");
    this.stack.splice(0, this.stack.length, result);
    return this.lines.join("\n");
  }

  verifyEqualAndFinish(left: string, right: string): string {
    this.copy(left, `${left}:check`);
    this.copy(right, `${right}:check`);
    this.lines.push("OP_EQUALVERIFY");
    this.stack.splice(this.stack.length - 2, 2);
    this.lines.push(
      ...Array.from({ length: Math.floor(this.stack.length / 2) }, () => "OP_2DROP"),
      ...(this.stack.length % 2 === 1 ? ["OP_DROP"] : []),
    );
    this.stack.splice(0);
    return this.lines.join("\n");
  }
}

/** Stack: packed little-endian M31 row -> one canonical lifted QM31 blob per limb. */
function v17LiftM31RowAssembly(): string {
  return `OP_DUP OP_SIZE OP_NIP
OP_DUP OP_0 OP_GREATERTHAN OP_VERIFY <4> OP_MOD OP_0 OP_NUMEQUALVERIFY
OP_0 OP_SWAP
OP_BEGIN
  <4> OP_SPLIT OP_TOALTSTACK
  <0x000000000000000000000000> OP_CAT OP_CAT
  OP_FROMALTSTACK
  OP_DUP OP_SIZE OP_NIP OP_0 OP_NUMEQUAL
OP_UNTIL
OP_DROP`;
}

/** Four canonical M31 limbs -> one carry-separated radix-2^72 integer. */
function v17Qm31WidePackBlobAssembly(): string {
  return `${BLOB_TO_QM31_ASM}
<${4 * V17_QM31_FUSED_BITS}> OP_LSHIFTNUM
OP_SWAP <${3 * V17_QM31_FUSED_BITS}> OP_LSHIFTNUM OP_ADD
OP_SWAP <${V17_QM31_FUSED_BITS}> OP_LSHIFTNUM OP_ADD OP_ADD`;
}

/** One 81-byte sum of at most ten convolutions -> canonical QM31 blob. */
function v17Qm31WideReduceProductAssembly(): string {
  return `${Array.from({ length: 9 }, () =>
    `<${V17_QM31_FUSED_WORD_BYTES}> OP_SPLIT OP_SWAP <0x00> OP_CAT OP_BIN2NUM <${M31_P}> OP_MOD OP_SWAP`).join("\n")}
OP_DROP
${QM31_REDUCE_COEFFICIENTS_ASM}
<${QM31_TO_BLOB}> OP_INVOKE`;
}

/** Stack: valuesBlob, weightsBlob -> sum_i values_i*weights_i. */
function v17Qm31FusedDotAssembly(): string {
  return `OP_2DUP
OP_SIZE OP_NIP OP_SWAP OP_SIZE OP_NIP OP_NUMEQUALVERIFY
OP_DUP OP_SIZE OP_NIP
OP_DUP <16> OP_GREATERTHANOREQUAL OP_VERIFY
OP_DUP <${16 * V17_QM31_FUSED_MAX_TERMS}> OP_LESSTHANOREQUAL OP_VERIFY
<16> OP_MOD OP_0 OP_NUMEQUALVERIFY
OP_0 OP_ROT OP_ROT
OP_BEGIN
  <16> OP_SPLIT <2> OP_ROLL <16> OP_SPLIT
  OP_TOALTSTACK OP_SWAP OP_TOALTSTACK
  <1> OP_PICK <${V17_QM31_WIDE_PACK_BLOB}> OP_INVOKE
  <1> OP_PICK <${V17_QM31_WIDE_PACK_BLOB}> OP_INVOKE
  OP_MUL OP_TOALTSTACK OP_2DROP OP_FROMALTSTACK OP_ADD
  OP_FROMALTSTACK OP_FROMALTSTACK OP_SWAP
  OP_DUP OP_SIZE OP_NIP OP_0 OP_NUMEQUAL
OP_UNTIL
OP_2DROP
<${V17_QM31_FUSED_PRODUCT_BYTES}> OP_NUM2BIN
<${V17_QM31_WIDE_REDUCE_PRODUCT}> OP_INVOKE`;
}

/**
 * Decode one FRI pair once, keep every intermediate as four M31 limbs, and
 * encode only the final fold. This is the same relation as the historical
 * five blob operations without their four avoidable encode/decode round trips.
 * Stack: leftBlob rightBlob inverseM31 alphaBlob -> foldedBlob.
 */
function v17FriFoldFromInverseAssembly(): string {
  const body = new ElementAssembly(["left", "right", "inverse", "alpha"]);
  const limbs = (prefix: string): readonly [string, string, string, string] =>
    [`${prefix}0`, `${prefix}1`, `${prefix}2`, `${prefix}3`];
  const left = limbs("leftLimb");
  const right = limbs("rightLimb");
  const alpha = limbs("alphaLimb");
  const sum = limbs("sum");
  const difference = limbs("difference");
  const odd = limbs("odd");
  const mixed = limbs("mixed");
  const folded = limbs("folded");
  body.callMany(READ_QM31, ["left"], left);
  body.callMany(READ_QM31, ["right"], right);
  body.callMany(READ_QM31, ["alpha"], alpha);
  body.callMany(QM31_ADD, [...left, ...right], sum);
  body.callMany(QM31_SUB, [...left, ...right], difference);
  body.callMany(QM31_MUL_M31, [...difference, "inverse"], odd);
  body.callMany(QM31_MUL, [...alpha, ...odd], mixed);
  body.callMany(QM31_ADD, [...sum, ...mixed], folded);
  body.call(QM31_TO_BLOB, folded, "foldedBlob");
  return body.finish("foldedBlob");
}

/**
 * Pack the ten beta powers once for all ten full Horner blocks. The packed
 * values are local arithmetic state, never proof bytes or prover hints.
 * Stack: 160-byte QM31 vector -> 400-byte packed vector.
 */
function v17Qm31PackBetaWeightsAssembly(): string {
  const pack = `<16> OP_SPLIT OP_SWAP
<${V17_QM31_WIDE_PACK_BLOB}> OP_INVOKE
<${V17_QM31_PACKED_ELEMENT_BYTES}> OP_NUM2BIN OP_TOALTSTACK`;
  return `OP_DUP OP_SIZE OP_NIP <${16 * V17_QM31_FUSED_MAX_TERMS}> OP_NUMEQUALVERIFY
${Array.from({ length: V17_QM31_FUSED_MAX_TERMS }, () => pack).join("\n")}
OP_DROP
OP_FROMALTSTACK
${Array.from(
    { length: V17_QM31_FUSED_MAX_TERMS - 1 },
    () => "OP_FROMALTSTACK OP_SWAP OP_CAT",
  ).join("\n")}`;
}

/**
 * Dot ten QM31 values against already-packed beta powers. Reusing the 400-byte
 * vector removes ninety duplicate wide-pack evaluations per batch relation.
 * Stack: valuesBlob160 packedWeights400 -> one QM31 blob.
 */
function v17Qm31DotPackedWeightsAssembly(): string {
  return `OP_OVER OP_SIZE OP_NIP <${16 * V17_QM31_FUSED_MAX_TERMS}> OP_NUMEQUALVERIFY
OP_DUP OP_SIZE OP_NIP <${V17_QM31_PACKED_ELEMENT_BYTES * V17_QM31_FUSED_MAX_TERMS}> OP_NUMEQUALVERIFY
OP_0 OP_ROT OP_ROT
OP_BEGIN
  <${V17_QM31_PACKED_ELEMENT_BYTES}> OP_SPLIT OP_TOALTSTACK
  OP_SWAP <16> OP_SPLIT OP_TOALTSTACK
  <${V17_QM31_WIDE_PACK_BLOB}> OP_INVOKE
  OP_SWAP <0x00> OP_CAT OP_BIN2NUM
  OP_MUL OP_ADD
  OP_FROMALTSTACK OP_FROMALTSTACK
  <1> OP_PICK OP_SIZE OP_NIP OP_0 OP_NUMEQUAL
OP_UNTIL
OP_2DROP
<${V17_QM31_FUSED_PRODUCT_BYTES}> OP_NUM2BIN
<${V17_QM31_WIDE_REDUCE_PRODUCT}> OP_INVOKE`;
}

/** Historical blob-roundtrip oracle retained only inside focused KAT gates. */
function v17LegacyFriFoldFromInverseAssembly(): string {
  const body = new ElementAssembly(["left", "right", "inverse", "alpha"]);
  body.call(QM31_BLOB_ADD, ["left", "right"], "sum");
  body.call(QM31_BLOB_SUB, ["left", "right"], "difference");
  body.call(QM31_BLOB_MUL_M31, ["difference", "inverse"], "odd");
  body.call(QM31_BLOB_MUL, ["alpha", "odd"], "mixed");
  body.call(QM31_BLOB_ADD, ["sum", "mixed"], "folded");
  return body.finish("folded");
}

/**
 * Test-only differential: the limb-local fold must equal both the former blob
 * lowering and one caller-supplied independent reference result.
 */
export function compileV17FriFoldPurificationKatGate(expected: Uint8Array): Uint8Array {
  if (expected.length !== 16) throw new Error("v17 FRI fold purification KAT");
  const legacy = 34;
  return compile(`${define(BLOB_TO_QM31_ASM, READ_QM31, "v17 fold KAT decode")}
${define(QM31_MUL_ASM, QM31_MUL, "v17 fold KAT multiply")}
${define(QM31_MUL_M31_ASM, QM31_MUL_M31, "v17 fold KAT scalar multiply")}
${define(QM31_ADD_ASM, QM31_ADD, "v17 fold KAT add")}
${define(qm31SubtractAssembly(), QM31_SUB, "v17 fold KAT subtract")}
${define(QM31_TO_BLOB_ASM, QM31_TO_BLOB, "v17 fold KAT encode")}
${define(qm31BlobBinaryAssembly(QM31_MUL), QM31_BLOB_MUL,
    "v17 fold KAT blob multiply")}
${define(qm31BlobScalarAssembly(), QM31_BLOB_MUL_M31,
    "v17 fold KAT blob scalar multiply")}
${define(qm31BlobBinaryAssembly(QM31_ADD), QM31_BLOB_ADD, "v17 fold KAT blob add")}
${define(qm31BlobBinaryAssembly(QM31_SUB), QM31_BLOB_SUB, "v17 fold KAT blob subtract")}
${define(v17LegacyFriFoldFromInverseAssembly(), legacy, "v17 fold KAT legacy")}
${define(v17FriFoldFromInverseAssembly(), V17_FRI_FOLD_FROM_INVERSE,
    "v17 fold KAT limb local")}
${copy4(3, 2, 1, 0)}
<${legacy}> OP_INVOKE OP_TOALTSTACK
<${V17_FRI_FOLD_FROM_INVERSE}> OP_INVOKE
OP_FROMALTSTACK OP_2DUP OP_EQUALVERIFY
<0x${binToHex(expected)}> OP_EQUAL OP_NIP`, "v17 FRI fold purification KAT");
}

/**
 * Test-only differential: one packed-weight dot must equal the prior fused dot
 * and one caller-supplied independent reference result.
 */
export function compileV17PackedBetaDotPurificationKatGate(expected: Uint8Array): Uint8Array {
  if (expected.length !== 16) throw new Error("v17 packed beta dot purification KAT");
  return compile(`${define(QM31_TO_BLOB_ASM, QM31_TO_BLOB, "v17 dot KAT encode")}
${define(v17Qm31WidePackBlobAssembly(), V17_QM31_WIDE_PACK_BLOB,
    "v17 dot KAT wide pack")}
${define(v17Qm31WideReduceProductAssembly(), V17_QM31_WIDE_REDUCE_PRODUCT,
    "v17 dot KAT wide reduce")}
${define(v17Qm31FusedDotAssembly(), V17_QM31_FUSED_DOT, "v17 dot KAT prior dot")}
${define(v17Qm31PackBetaWeightsAssembly(), V17_QM31_PACK_BETA_WEIGHTS,
    "v17 dot KAT pack weights")}
${define(v17Qm31DotPackedWeightsAssembly(), V17_QM31_DOT_PACKED_WEIGHTS,
    "v17 dot KAT packed dot")}
OP_2DUP <${V17_QM31_FUSED_DOT}> OP_INVOKE OP_TOALTSTACK
<${V17_QM31_PACK_BETA_WEIGHTS}> OP_INVOKE
<${V17_QM31_DOT_PACKED_WEIGHTS}> OP_INVOKE
OP_FROMALTSTACK OP_2DUP OP_EQUALVERIFY
<0x${binToHex(expected)}> OP_EQUAL OP_NIP`, "v17 packed beta dot purification KAT");
}

function qm31BlobBinaryAssembly(operation: number): string {
  const body = new BlobAssembly(2);
  body.readQm31(0);
  body.readQm31(1);
  body.lines.push(`<${operation}> OP_INVOKE`);
  body.extra -= 4;
  body.encode();
  if (body.extra !== 1) throw new Error("local-word QM31 blob binary stack");
  return `${body.lines.join("\n")}
OP_TOALTSTACK OP_2DROP OP_FROMALTSTACK`;
}

function qm31BlobScalarAssembly(): string {
  const body = new BlobAssembly(2);
  body.readQm31(0);
  body.readM31(1);
  body.qmMulM31();
  body.encode();
  if (body.extra !== 1) throw new Error("local-word QM31 blob scalar stack");
  return `${body.lines.join("\n")}
OP_TOALTSTACK OP_2DROP OP_FROMALTSTACK`;
}

function friFoldPairAssembly(): string {
  const body = new ElementAssembly(["left", "right", "twiddle", "alpha"]);
  body.call(QM31_BLOB_ADD, ["left", "right"], "sum");
  body.call(QM31_BLOB_SUB, ["left", "right"], "difference");
  body.derivedM31("twiddle", `<${M31_INVERSE}> OP_INVOKE`, "inverse");
  body.call(QM31_BLOB_MUL_M31, ["difference", "inverse"], "odd");
  body.call(QM31_BLOB_MUL, ["alpha", "odd"], "mixed");
  body.call(QM31_BLOB_ADD, ["sum", "mixed"], "folded");
  return body.finish("folded");
}

function friFoldLayerAssembly(arity: 2 | 4, fusedFromInverses = false): string {
  const body = new ElementAssembly(["row", "twiddles", "alphas"]);
  body.slice("alphas", 0, 16, "alpha0");
  body.slice("row", 0, 16, "value0");
  body.slice("row", 16, 16, "value1");
  body.m31("twiddles", 0, "twiddle0");
  if (fusedFromInverses) {
    body.call(V17_FRI_FOLD_FROM_INVERSE,
      ["value0", "value1", "twiddle0", "alpha0"], "fold0");
  } else {
    body.call(FRI_FOLD_PAIR, ["value0", "value1", "twiddle0", "alpha0"], "fold0");
  }
  if (arity === 2) return body.finish("fold0");
  body.slice("alphas", 16, 16, "alpha1");
  body.slice("row", 32, 16, "value2");
  body.slice("row", 48, 16, "value3");
  body.m31("twiddles", 4, "twiddle1");
  if (fusedFromInverses) {
    body.call(V17_FRI_FOLD_FROM_INVERSE,
      ["value2", "value3", "twiddle1", "alpha0"], "fold1");
  } else {
    body.call(FRI_FOLD_PAIR, ["value2", "value3", "twiddle1", "alpha0"], "fold1");
  }
  body.m31("twiddles", 8, "twiddle2");
  if (fusedFromInverses) {
    body.call(V17_FRI_FOLD_FROM_INVERSE,
      ["fold0", "fold1", "twiddle2", "alpha1"], "folded");
  } else {
    body.call(FRI_FOLD_PAIR, ["fold0", "fold1", "twiddle2", "alpha1"], "folded");
  }
  return body.finish("folded");
}

function friLinearCombinationAssembly(): string {
  const body = new ElementAssembly(["left", "right", "factor"]);
  body.call(QM31_BLOB_MUL_M31, ["right", "factor"], "scaled");
  body.call(QM31_BLOB_ADD, ["left", "scaled"], "combined");
  return body.finish("combined");
}

function doubleXAssembly(): string {
  return `OP_DUP ${M31_MUL} <2> ${M31_MUL} <1> ${M31_SUB}`;
}

function friFinalEvaluationAssembly(): string {
  const body = new ElementAssembly(["coefficients", "x"]);
  body.derivedM31("x", doubleXAssembly(), "x2");
  body.derivedM31("x2", doubleXAssembly(), "x4");
  for (let coefficient = 0; coefficient < 8; coefficient += 1) {
    body.slice("coefficients", coefficient * 16, 16, `coefficient${coefficient}`);
    body.copy(`coefficient${coefficient}`, `canonical${coefficient}`);
    body.lines.push(`<${READ_CANONICAL_QM31}> OP_INVOKE OP_2DROP OP_2DROP`);
    body.stack.splice(body.stack.length - 1, 1);
  }
  const ordered = [0, 4, 2, 6, 1, 5, 3, 7];
  const low = Array.from({ length: 4 }, (_, pair) => {
    const result = `low${pair}`;
    body.call(FRI_LINEAR_COMBINATION, [
      `coefficient${ordered[2 * pair]!}`,
      `coefficient${ordered[2 * pair + 1]!}`,
      "x4",
    ], result);
    return result;
  });
  body.call(FRI_LINEAR_COMBINATION, [low[0]!, low[1]!, "x2"], "middle0");
  body.call(FRI_LINEAR_COMBINATION, [low[2]!, low[3]!, "x2"], "middle1");
  body.call(FRI_LINEAR_COMBINATION, ["middle0", "middle1", "x"], "evaluation");
  return body.finish("evaluation");
}

export function circleAddAssembly(): string {
  return `<3> OP_PICK <2> OP_PICK ${M31_MUL}
<3> OP_PICK <2> OP_PICK ${M31_MUL} ${M31_SUB} OP_TOALTSTACK
<3> OP_PICK OP_1 OP_PICK ${M31_MUL}
<3> OP_PICK <3> OP_PICK ${M31_MUL} ${M31_ADD} OP_TOALTSTACK
OP_2DROP OP_2DROP OP_FROMALTSTACK OP_FROMALTSTACK OP_SWAP`;
}

export function circleScalarMulAssembly(bits: number): string {
  const oneBit = `OP_DUP <2> OP_MOD
OP_IF
  OP_TOALTSTACK
  <3> OP_PICK <3> OP_PICK <3> OP_PICK <3> OP_PICK <${CIRCLE_ADD}> OP_INVOKE
  OP_TOALTSTACK OP_TOALTSTACK OP_2SWAP OP_2DROP
  OP_FROMALTSTACK OP_FROMALTSTACK OP_2SWAP OP_FROMALTSTACK
OP_ENDIF
OP_TOALTSTACK OP_2DUP <${CIRCLE_ADD}> OP_INVOKE
OP_FROMALTSTACK <2> OP_DIV`;
  return `OP_TOALTSTACK OP_TOALTSTACK
<1> <0>
OP_FROMALTSTACK OP_FROMALTSTACK <4> OP_ROLL
${Array.from({ length: bits }, () => oneBit).join("\n")}
OP_DROP OP_2DROP`;
}

/**
 * Fixed-base BCH lowering for a verifier-key circle point. Four-bit windows
 * replace the generic double-and-add loop with one checked table selection and
 * one circle addition per window. The caller still supplies the public base;
 * the body verifies it so the stack contract remains identical to
 * `circleScalarMulAssembly` and no proof-selected table is admitted.
 */
function circleFixedBaseScalarMulAssembly(
  base: typeof CIRCLE_GEN,
  bits: number,
): string {
  if (!Number.isInteger(bits) || bits < 1 || bits > 31) {
    throw new Error("local-word fixed-base scalar bits");
  }
  const windowBits = 4;
  const radix = 2 ** windowBits;
  const windows = Math.ceil(bits / windowBits);
  const tables = Array.from({ length: windows }, (_, window) => concatBytes(
    ...Array.from({ length: radix }, (_, digit) => {
      const point = scalarMul(base, BigInt(digit) << BigInt(window * windowBits));
      return concatBytes(writeU32LE(Number(point.x)), writeU32LE(Number(point.y)));
    }),
  ));
  const addWindow = (table: Uint8Array): string => `<2> OP_PICK <${radix}> OP_MOD <8> OP_MUL
<0x${binToHex(table)}> OP_SWAP OP_SPLIT OP_NIP <8> OP_SPLIT OP_DROP
<4> OP_SPLIT OP_SWAP OP_BIN2NUM OP_SWAP OP_BIN2NUM
<4> OP_ROLL <${radix}> OP_DIV OP_TOALTSTACK
<${CIRCLE_ADD}> OP_INVOKE
OP_FROMALTSTACK OP_ROT OP_ROT`;
  return `<1> OP_PICK <${base.x}> OP_NUMEQUALVERIFY
OP_DUP <${base.y}> OP_NUMEQUALVERIFY
OP_2DROP
OP_DUP OP_0 OP_GREATERTHANOREQUAL OP_VERIFY
OP_DUP <${2 ** bits}> OP_LESSTHAN OP_VERIFY
<1> <0>
${tables.map(addWindow).join("\n")}
<2> OP_ROLL OP_0 OP_NUMEQUALVERIFY`;
}

export function bitReverseAssembly(bits: number): string {
  return `OP_0 OP_SWAP
${Array.from({ length: bits }, () => `OP_DUP <2> OP_MOD
<2> OP_ROLL <2> OP_MUL OP_ADD
OP_SWAP <2> OP_DIV`).join("\n")}
OP_DROP`;
}

function m31NegAssembly(): string {
  return `OP_0 OP_SWAP ${M31_SUB}`;
}

/** Stack: position x y blob -> shiftedPosition advancedPointX advancedPointY blob. */
function advanceDomainPointAssembly(doubles: 1 | 2, positionDivisor: 2 | 4): string {
  const double = `OP_TOALTSTACK
OP_2DUP <${CIRCLE_ADD}> OP_INVOKE
OP_FROMALTSTACK`;
  const dividePosition = `OP_TOALTSTACK OP_TOALTSTACK OP_TOALTSTACK
<${positionDivisor}> OP_DIV
OP_FROMALTSTACK OP_FROMALTSTACK OP_FROMALTSTACK`;
  return `${Array.from({ length: doubles }, () => double).join("\n")}
${dividePosition}`;
}

/** Re-anchor the actual line-domain point to its four-opening coset base. */
function normalizeLineCosetPointAssembly(): string {
  return `OP_TOALTSTACK
<2> OP_PICK <2> OP_MOD
OP_IF
  OP_SWAP ${m31NegAssembly()} OP_SWAP ${m31NegAssembly()}
OP_ENDIF
<2> OP_PICK <2> OP_DIV <2> OP_MOD
OP_IF
  OP_SWAP OP_TOALTSTACK ${m31NegAssembly()} OP_FROMALTSTACK
OP_ENDIF
OP_FROMALTSTACK`;
}

/** Re-anchor the last, binary FRI opening without erasing its pair selector. */
function normalizeLinePairPointAssembly(): string {
  return `OP_TOALTSTACK
<2> OP_PICK <2> OP_MOD
OP_IF
  OP_SWAP ${m31NegAssembly()} OP_SWAP ${m31NegAssembly()}
OP_ENDIF
OP_FROMALTSTACK`;
}

function appendM31Assembly(depth: number, negate = false): string {
  return `<${depth}> OP_PICK ${negate ? m31NegAssembly() : ""} <4> OP_NUM2BIN OP_CAT`;
}

/** Query index -> 17 exact FRI twiddles and the final line-domain x. */
function friDomainTwiddlesAssembly(parameters: LocalWordProofParameters): string {
  const initialGenerator = scalarMul(CIRCLE_GEN, 1n << BigInt(30 - parameters.evalLog));
  const circle = `${appendM31Assembly(1)}
${appendM31Assembly(1, true)}
${appendM31Assembly(2)}
${advanceDomainPointAssembly(1, 4)}
${normalizeLineCosetPointAssembly()}`;
  const line = `${appendM31Assembly(2)}
${appendM31Assembly(1)}
<2> OP_PICK ${doubleXAssembly()} <4> OP_NUM2BIN OP_CAT
${advanceDomainPointAssembly(2, 4)}
${normalizeLineCosetPointAssembly()}`;
  const binaryTail = `${appendM31Assembly(2)}
${appendM31Assembly(1)}
<2> OP_PICK ${doubleXAssembly()} <4> OP_NUM2BIN OP_CAT
${advanceDomainPointAssembly(2, 4)}
${normalizeLinePairPointAssembly()}`;
  const final = `${appendM31Assembly(2)}
${advanceDomainPointAssembly(1, 2)}
OP_TOALTSTACK OP_DROP OP_SWAP OP_DROP OP_FROMALTSTACK OP_SWAP`;
  return `OP_DUP OP_0 OP_GREATERTHANOREQUAL OP_VERIFY
OP_DUP <${2 ** parameters.evalLog}> OP_LESSTHAN OP_VERIFY
OP_DUP <4> OP_DIV
${bitReverseAssembly(parameters.evalLog - 2)}
<4> OP_MUL OP_1ADD
<${initialGenerator.x}> <${initialGenerator.y}> <${CIRCLE_SCALAR_MUL}> OP_INVOKE
OP_0
${circle}
${Array.from({ length: 6 }, () => line).join("\n")}
${binaryTail}
${final}`;
}

function friCosetRowsBlobAssembly(args: {
  readonly existing: number;
  readonly query: number;
  readonly layer: number;
  readonly offsets: ReturnType<typeof localWordProofStaticOffsets>;
  readonly parameters: LocalWordProofParameters;
}): string {
  const folds = localWordFriFoldCounts(args.parameters)[args.layer]!;
  const arity = 2 ** folds;
  const directoryOffset = args.offsets.openingDirectory +
    (LOCAL_WORD_MATRIX_NAMES.length + args.layer) * 20;
  return `${prefetchedBlobAssembly(
    args.existing,
    args.offsets.friCosetRanks + args.layer * args.parameters.fri.queries + args.query,
    1,
  )} <0x00> OP_CAT OP_BIN2NUM
OP_DUP OP_0 OP_GREATERTHANOREQUAL OP_VERIFY
OP_DUP <${args.parameters.fri.queries * arity}> OP_LESSTHAN OP_VERIFY
<16> OP_MUL
${prefetchedBlobAssembly(args.existing + 1, directoryOffset + 4, 4)}
OP_REVERSEBYTES OP_BIN2NUM OP_ADD
<${args.existing}> OP_PICK OP_SWAP <${arity * 16}> <${READ_BYTES}> OP_INVOKE OP_NIP`;
}

function runtimeFriCosetRowsBlobAssembly(args: {
  readonly existing: number;
  readonly layer: number;
  readonly offsets: ReturnType<typeof localWordProofStaticOffsets>;
  readonly parameters: LocalWordProofParameters;
}): string {
  const folds = localWordFriFoldCounts(args.parameters)[args.layer]!;
  const arity = 2 ** folds;
  const directoryOffset = args.offsets.openingDirectory +
    (LOCAL_WORD_MATRIX_NAMES.length + args.layer) * 20;
  return `${prefetchedRuntimeQueryBlobAssembly({
    existing: args.existing,
    offset: args.offsets.friCosetRanks + args.layer * args.parameters.fri.queries,
    stride: 1,
    width: 1,
  })} <0x00> OP_CAT OP_BIN2NUM
OP_DUP OP_0 OP_GREATERTHANOREQUAL OP_VERIFY
OP_DUP <${args.parameters.fri.queries * arity}> OP_LESSTHAN OP_VERIFY
<16> OP_MUL
${prefetchedBlobAssembly(args.existing + 1, directoryOffset + 4, 4)}
OP_REVERSEBYTES OP_BIN2NUM OP_ADD
<${args.existing}> OP_PICK OP_SWAP <${arity * 16}> <${READ_BYTES}> OP_INVOKE OP_NIP`;
}

function compareFriFoldLinkAssembly(args: {
  readonly queryDepth: number;
  readonly completedFolds: number;
  readonly arity: number;
}): string {
  return `OP_DUP OP_SIZE <${args.arity * 16}> OP_NUMEQUALVERIFY
<${args.queryDepth}> OP_PICK <${2 ** args.completedFolds}> OP_DIV
<${args.arity}> OP_MOD <16> OP_MUL
OP_DUP <${args.arity * 16}> OP_LESSTHAN OP_VERIFY
OP_SPLIT OP_NIP <16> OP_SPLIT OP_DROP
<2> OP_ROLL OP_EQUALVERIFY`;
}

/** Executable KAT for the dynamic Circle/line-domain twiddle derivation. */
export function compileLocalWordFriDomainKatGate(args: {
  readonly query: number;
  readonly expectedTwiddles: Uint8Array;
  readonly expectedFinalX: number;
  readonly parameters?: LocalWordProofParameters;
}): Uint8Array {
  const parameters = validateLocalWordProofParameters(
    args.parameters ?? LOCAL_WORD_PRODUCTION_PARAMETERS,
  );
  if (!Number.isInteger(args.query) || args.query < 0 || args.query >= 2 ** parameters.evalLog ||
    args.expectedTwiddles.length !== 25 * 4 || !Number.isInteger(args.expectedFinalX) ||
    args.expectedFinalX < 0 || args.expectedFinalX >= M31_P) {
    throw new Error("local-word FRI domain KAT");
  }
  const initialGenerator = scalarMul(CIRCLE_GEN, 1n << BigInt(30 - parameters.evalLog));
  return compile(`OP_DROP
${define(circleAddAssembly(), CIRCLE_ADD, "local-word FRI KAT circle add")}
${define(circleFixedBaseScalarMulAssembly(initialGenerator, parameters.evalLog),
    CIRCLE_SCALAR_MUL, "local-word FRI KAT fixed-base scalar multiply")}
<${args.query}> ${friDomainTwiddlesAssembly(parameters)}
<${args.expectedFinalX}> OP_NUMEQUALVERIFY
<0x${binToHex(args.expectedTwiddles)}> OP_EQUAL`, "local-word FRI domain KAT");
}

function matrixRowsStartOffset(
  offsets: ReturnType<typeof localWordProofStaticOffsets>,
  matrix: number,
): number {
  return offsets.openingDirectory + matrix * 20 + 4;
}

function v17TranscriptAbsorbSuffix(label: string, dataBytes: number): Uint8Array {
  const labelBytes = new TextEncoder().encode(label);
  if (labelBytes.length < 1 || labelBytes.length > 96) throw new Error("v17 batch transcript label");
  return concatBytes(Uint8Array.of(labelBytes.length), labelBytes, writeU32LE(dataBytes));
}

function v17TheoremRoundBytes(id: typeof V17_THEOREM_ROUND_IDS[number]): Uint8Array {
  const ordinal = V17_THEOREM_ROUND_IDS.indexOf(id);
  const name = new TextEncoder().encode(id);
  if (ordinal < 0 || ordinal > 0xff || name.length > 0xff) throw new Error("v17 batch theorem round");
  return Uint8Array.of(17, ordinal, name.length, ...name);
}

/** Derive the accepted OODS Cayley parameter from checked transcript caches. */
function v17OodsTFromProofAssembly(
  existing: number,
  offsets: ReturnType<typeof localWordProofStaticOffsets>,
): string {
  const round = V17_PRODUCTION_ROUND_GRINDING.find(({ id }) => id === "air:ood");
  if (!round || round.bits !== 3) throw new Error("v17 batch OODS round");
  const quotientRoot = offsets.matrixRoots + LOCAL_WORD_MATRIX_NAMES.indexOf("quotientAndFriMask") * 32;
  const rootSuffix = v17TranscriptAbsorbSuffix("local-word-v17-quotient-and-fri-mask-root", 32);
  const namedRound = v17TheoremRoundBytes("air:ood");
  const roundSuffix = concatBytes(
    v17TranscriptAbsorbSuffix("v17-theorem-round", namedRound.length),
    namedRound,
  );
  const powSuffix = concatBytes(
    v17TranscriptAbsorbSuffix("pow", 5),
    Uint8Array.of(round.bits),
  );
  return `${prefetchedBlobAssembly(existing, offsets.compositionDigest, 32)}
${prefetchedBlobAssembly(existing + 1, quotientRoot, 32)}
OP_TOALTSTACK <0x00> OP_SWAP OP_CAT <0x${binToHex(rootSuffix)}> OP_CAT
OP_FROMALTSTACK OP_CAT OP_SHA256
<0x00> OP_SWAP OP_CAT <0x${binToHex(roundSuffix)}> OP_CAT OP_SHA256
${prefetchedBlobAssembly(existing + 1, v17ProofFrameOffset("roundNonce:air:ood"), 4)}
OP_REVERSEBYTES
<1> OP_PICK <0x03> OP_SWAP OP_CAT <0x${round.bits.toString(16).padStart(2, "0")}> OP_CAT
<1> OP_PICK OP_CAT OP_SHA256
<1> OP_SPLIT OP_DROP OP_BIN2NUM
OP_DUP OP_0 OP_GREATERTHANOREQUAL OP_VERIFY <${2 ** (8 - round.bits)}> OP_LESSTHAN OP_VERIFY
OP_TOALTSTACK <0x00> OP_SWAP OP_CAT <0x${binToHex(powSuffix)}> OP_CAT
OP_FROMALTSTACK OP_CAT OP_SHA256
${v17OodsSelectDigestAssembly(V17_OODS_CANDIDATE)}
${v17OodsDigestToTAssembly()}
<${QM31_TO_BLOB}> OP_INVOKE`;
}

/** Query index -> exact lifted base-circle point P=(x,y), left as two M31 limbs. */
function v17BatchPointAssembly(parameters: LocalWordProofParameters): string {
  const half = 2 ** (parameters.evalLog - 1);
  const initial = 1n << BigInt(30 - parameters.evalLog);
  const step = 1n << BigInt(32 - parameters.evalLog);
  const order = 1n << 31n;
  return `${bitReverseAssembly(parameters.evalLog)}
OP_DUP <${half}> OP_LESSTHAN
OP_IF
  <${step}> OP_MUL <${initial}> OP_ADD
OP_ELSE
  <${half}> OP_SUB <${step}> OP_MUL <${initial}> OP_ADD <${order}> OP_SWAP OP_SUB
OP_ENDIF
<${CIRCLE_GEN.x}> <${CIRCLE_GEN.y}> <${CIRCLE_SCALAR_MUL}> OP_INVOKE`;
}

type LocalWordAlgebraGateFragments = {
  readonly definitions: string;
  readonly sharedDefinitions: string;
  readonly localDefinitions: string;
  readonly body: string;
};

export type LocalWordFriBatchGateArgs = {
  readonly profile: 0 | 1 | 2;
  readonly query: number;
  readonly parameters?: LocalWordProofParameters;
  readonly reader?: LocalWordProofReader;
};

function localWordFriBatchFragments(
  args: LocalWordFriBatchGateArgs,
  runtimeFollower = false,
): LocalWordAlgebraGateFragments {
  const parameters = validateLocalWordProofParameters(
    args.parameters ?? LOCAL_WORD_PRODUCTION_PARAMETERS,
  );
  if (!Number.isInteger(args.query) || args.query < 0 || args.query >= parameters.fri.queries) {
    throw new Error("local-word FRI batch verifier key");
  }
  const publicWordCount = LOCAL_WORD_RELATION_STATEMENT_DIGEST_WORDS;
  const offsets = localWordProofStaticOffsets(publicWordCount, parameters);
  const matrix = (name: typeof LOCAL_WORD_MATRIX_NAMES[number]): number =>
    LOCAL_WORD_MATRIX_NAMES.indexOf(name);
  const baseDefinitionEntries: readonly (readonly [number, string])[] = [
    [READ_BYTES,
      define(localWordReadDynamicAssembly(args.reader), READ_BYTES, "local-word batch reader")],
    [READ_QM31, define(BLOB_TO_QM31_ASM, READ_QM31, "local-word batch QM31 reader")],
    [READ_CANONICAL_QM31, define(canonicalQm31Assembly(), READ_CANONICAL_QM31,
      "local-word batch canonical QM31 reader")],
    [QM31_MUL, define(QM31_MUL_ASM, QM31_MUL, "local-word batch QM31 multiply")],
    [QM31_MUL_M31,
      define(QM31_MUL_M31_ASM, QM31_MUL_M31, "local-word batch QM31 scalar multiply")],
    [QM31_ADD, define(QM31_ADD_ASM, QM31_ADD, "local-word batch QM31 add")],
    [QM31_SUB, define(qm31SubtractAssembly(), QM31_SUB, "local-word batch QM31 subtract")],
    [QM31_TO_BLOB, define(QM31_TO_BLOB_ASM, QM31_TO_BLOB, "local-word batch QM31 encode")],
    [CIRCLE_ADD, define(circleAddAssembly(), CIRCLE_ADD, "local-word batch circle add")],
    [CIRCLE_SCALAR_MUL,
      define(circleFixedBaseScalarMulAssembly(CIRCLE_GEN, 31), CIRCLE_SCALAR_MUL,
        "local-word batch fixed-base scalar multiply")],
    [QM31_BLOB_MUL,
      define(qm31BlobBinaryAssembly(QM31_MUL), QM31_BLOB_MUL,
        "local-word batch blob multiply")],
    [QM31_BLOB_MUL_M31,
      define(qm31BlobScalarAssembly(), QM31_BLOB_MUL_M31,
        "local-word batch blob scalar multiply")],
    [QM31_BLOB_ADD,
      define(qm31BlobBinaryAssembly(QM31_ADD), QM31_BLOB_ADD,
        "local-word batch blob add")],
    [QM31_BLOB_SUB,
      define(qm31BlobBinaryAssembly(QM31_SUB), QM31_BLOB_SUB,
        "local-word batch blob subtract")],
    ...(!runtimeFollower && args.query === 0
      ? [[V17_OODS_CANDIDATE, define(v17OodsCandidateAcceptanceAssembly(), V17_OODS_CANDIDATE,
        "local-word batch OODS candidate")] as const]
      : []),
    [V17_LIFT_M31_ROW,
      define(v17LiftM31RowAssembly(), V17_LIFT_M31_ROW, "local-word batch lift M31 row")],
    [V17_QM31_WIDE_PACK_BLOB,
      define(v17Qm31WidePackBlobAssembly(), V17_QM31_WIDE_PACK_BLOB,
        "local-word batch widened QM31 pack")],
    [V17_QM31_WIDE_REDUCE_PRODUCT,
      define(v17Qm31WideReduceProductAssembly(), V17_QM31_WIDE_REDUCE_PRODUCT,
        "local-word batch widened QM31 reduce")],
    [V17_QM31_FUSED_DOT,
      define(v17Qm31FusedDotAssembly(), V17_QM31_FUSED_DOT,
        "local-word batch fused QM31 dot product")],
    [V17_QM31_PACK_BETA_WEIGHTS,
      define(v17Qm31PackBetaWeightsAssembly(), V17_QM31_PACK_BETA_WEIGHTS,
        "v17 batch pack reusable beta weights")],
    [V17_QM31_DOT_PACKED_WEIGHTS,
      define(v17Qm31DotPackedWeightsAssembly(), V17_QM31_DOT_PACKED_WEIGHTS,
        "v17 batch dot with packed beta weights")],
  ];
  const baseDefinitions = baseDefinitionEntries.map(([, definition]) => definition).join("\n");
  const preprocessed = matrix("preprocessed");
  const original = matrix("original");
  const interaction = matrix("interaction");
  const global = matrix("interactionGlobal");
  const quotientAndFriMask = matrix("quotientAndFriMask");
  const leader = !runtimeFollower && args.query === 0;
  if (runtimeFollower && args.query === 0) {
    throw new Error("local-word FRI batch leader cannot use follower kernel");
  }
  const queryRankOffset = (base: number): number => base + (runtimeFollower ? 0 : args.query);
  const currentRank = queryRankOffset(offsets.currentRanks);
  const globalRank = queryRankOffset(offsets.globalCurrentRanks);
  const globalPreviousRank = queryRankOffset(offsets.globalPreviousRanks);
  const setup: string[] = [
    ...(runtimeFollower ? [runtimeQueryGuardAssembly(1, parameters.fri.queries)] : []),
    localWordProofLengthAssembly(),
    staticBlobAssembly(1, 0, offsets.openingBodies),
  ];
  let baseCount = 2;
  const appendStatic = (offset: number, width: number): void => {
    setup.push(prefetchedBlobAssembly(baseCount, offset, width));
    baseCount += 1;
  };
  const appendRow = (rowArgs: Omit<Parameters<typeof rowBlobAssembly>[0], "existing">): void => {
    setup.push(runtimeFollower
      ? runtimeQueryRowBlobAssembly({ ...rowArgs, existing: baseCount })
      : rowBlobAssembly({ ...rowArgs, existing: baseCount }));
    baseCount += 1;
  };
  appendStatic(offsets.batchBeta, 16);
  if (leader) appendStatic(offsets.oodValues, 98 * 16);
  appendRow({ rankOffset: currentRank, rankLimit: parameters.fri.queries,
    rowWidth: LOCAL_WORD_MATRIX_ROW_WIDTHS[preprocessed]!,
    rowsStartOffset: matrixRowsStartOffset(offsets, preprocessed) });
  appendRow({ rankOffset: currentRank, rankLimit: parameters.fri.queries,
    rowWidth: LOCAL_WORD_MATRIX_ROW_WIDTHS[original]!,
    rowsStartOffset: matrixRowsStartOffset(offsets, original) });
  appendRow({ rankOffset: currentRank, rankLimit: parameters.fri.queries,
    rowWidth: LOCAL_WORD_MATRIX_ROW_WIDTHS[interaction]!,
    rowsStartOffset: matrixRowsStartOffset(offsets, interaction) });
  appendRow({ rankOffset: globalRank, rankLimit: 2 * parameters.fri.queries,
    rowWidth: LOCAL_WORD_MATRIX_ROW_WIDTHS[global]!,
    rowsStartOffset: matrixRowsStartOffset(offsets, global) });
  appendRow({ rankOffset: globalPreviousRank, rankLimit: 2 * parameters.fri.queries,
    rowWidth: LOCAL_WORD_MATRIX_ROW_WIDTHS[global]!,
    rowsStartOffset: matrixRowsStartOffset(offsets, global) });
  appendRow({ rankOffset: currentRank, rankLimit: parameters.fri.queries,
    rowWidth: LOCAL_WORD_MATRIX_ROW_WIDTHS[quotientAndFriMask]!,
    rowsStartOffset: matrixRowsStartOffset(offsets, quotientAndFriMask) });
  setup.push(runtimeFollower
    ? runtimeFriQueryRowBlobAssembly({ existing: baseCount, offsets, parameters })
    : friQueryRowBlobAssembly({ existing: baseCount, query: args.query, offsets, parameters }));
  baseCount += 1;
  if (leader) {
    setup.push(v17OodsTFromProofAssembly(baseCount, offsets));
    baseCount += 1;
  }
  setup.push(`${runtimeFollower
    ? prefetchedRuntimeQueryBlobAssembly({
      existing: baseCount,
      offset: offsets.queries,
      stride: 4,
      width: 4,
    })
    : prefetchedBlobAssembly(baseCount, offsets.queries + args.query * 4, 4)}
OP_REVERSEBYTES OP_BIN2NUM ${v17BatchPointAssembly(parameters)}`);
  baseCount += 2;
  // All fixed fields have been extracted; the retained prefix is not hidden state.
  setup.push(`<${baseCount - 2}> OP_ROLL OP_DROP`);
  baseCount -= 1;
  if (runtimeFollower) setup.push("OP_FROMALTSTACK OP_DROP");
  if (baseCount !== (leader ? 13 : 11)) throw new Error("v17 batch base geometry");
  setup.push(leader
    ? "OP_FROMALTSTACK"
    : v17BatchLeaderCellFromInputAssembly());
  setup.push(insertTopBelowAssembly(baseCount));
  baseCount += 1;

  const fusedBatch = (
    body: ElementAssembly,
    source: string,
    innerPowers: string,
    prefix: string,
  ): string => {
    const packedWeights = `${prefix}PackedWeights`;
    body.call(V17_QM31_PACK_BETA_WEIGHTS, [innerPowers], packedWeights);
    body.slice(source, 90 * 16, 8 * 16, `${prefix}HighValues`);
    body.slice(innerPowers, 0, 8 * 16, `${prefix}HighWeights`);
    body.call(
      V17_QM31_FUSED_DOT,
      [`${prefix}HighValues`, `${prefix}HighWeights`],
      `${prefix}Acc10`,
    );
    let accumulator = `${prefix}Acc10`;
    for (let block = 9; block >= 0; block -= 1) {
      const values = `${prefix}Values${block}`;
      const terms = `${prefix}Terms${block}`;
      const next = `${prefix}Acc${block}`;
      body.slice(source, block * 9 * 16, 9 * 16, values);
      body.concat([values, accumulator], terms);
      body.call(V17_QM31_DOT_PACKED_WEIGHTS, [terms, packedWeights], next);
      accumulator = next;
    }
    return accumulator;
  };

  const leaderAuth = new ElementAssembly(["cell", "beta", "oods", "oodT"]);
  leaderAuth.constant(encodeQm31([1n, 0n, 0n, 0n]), "one");
  const authBetaPowers = ["one", "beta"];
  for (let exponent = 2; exponent <= 9; exponent += 1) {
    const power = `beta${exponent}`;
    leaderAuth.call(QM31_BLOB_MUL, [authBetaPowers.at(-1)!, "beta"], power);
    authBetaPowers.push(power);
  }
  leaderAuth.concat(authBetaPowers, "innerPowers");
  const authAtQ = fusedBatch(leaderAuth, "oods", "innerPowers", "oodBatch");
  leaderAuth.call(QM31_BLOB_MUL, ["oodT", "oodT"], "t2");
  leaderAuth.call(QM31_BLOB_ADD, ["one", "t2"], "cayleyDenominator");
  leaderAuth.call(QM31_BLOB_SUB, ["one", "t2"], "qxNumerator");
  leaderAuth.call(QM31_BLOB_ADD, ["oodT", "oodT"], "qyNumerator");
  leaderAuth.call(QM31_BLOB_MUL, ["beta9", "beta9"], "beta18");
  leaderAuth.call(QM31_BLOB_MUL, ["beta18", "beta18"], "beta36");
  leaderAuth.call(QM31_BLOB_MUL, ["beta36", "beta36"], "beta72");
  leaderAuth.call(QM31_BLOB_MUL, ["beta72", "beta18"], "beta90");
  leaderAuth.call(QM31_BLOB_MUL, ["beta90", "beta9"], "beta99");
  leaderAuth.call(QM31_BLOB_MUL, ["beta99", "cayleyDenominator"], "cellK");
  leaderAuth.constant(v17BatchLeaderCellHeader(args.profile), "cellHeader");
  leaderAuth.concat([
    "cellHeader",
    ...authBetaPowers.slice(2),
    authAtQ,
    "cayleyDenominator",
    "qxNumerator",
    "qyNumerator",
    "cellK",
  ], "expectedCell");
  const leaderAuthBody = leaderAuth.verifyEqualAndFinish("cell", "expectedCell");

  const body = new ElementAssembly([
    "cell", "proofLength", "beta", "preprocessed", "original", "interaction",
    "globalCurrent", "globalPrevious", "quotientAndMask", "fri0", "pointX", "pointY",
  ]);
  body.constant(encodeQm31([1n, 0n, 0n, 0n]), "one");
  const betaPowers = ["one", "beta"];
  for (let exponent = 2; exponent <= 9; exponent += 1) {
    const power = `beta${exponent}`;
    body.slice(
      "cell",
      V17_BATCH_LEADER_CELL_HEADER_BYTES + (exponent - 2) * 16,
      16,
      power,
    );
    betaPowers.push(power);
  }
  body.concat(betaPowers, "innerPowers");
  body.slice("cell", V17_BATCH_LEADER_CELL_HEADER_BYTES + 8 * 16, 16, "batchAtQ");
  body.slice("cell", V17_BATCH_LEADER_CELL_HEADER_BYTES + 9 * 16, 16, "cayleyDenominator");
  body.slice("cell", V17_BATCH_LEADER_CELL_HEADER_BYTES + 10 * 16, 16, "qxNumerator");
  body.slice("cell", V17_BATCH_LEADER_CELL_HEADER_BYTES + 11 * 16, 16, "qyNumerator");
  body.slice("cell", V17_BATCH_LEADER_CELL_HEADER_BYTES + 12 * 16, 16, "cellK");

  body.call(V17_LIFT_M31_ROW, ["preprocessed"], "preprocessedQm31");
  body.call(V17_LIFT_M31_ROW, ["original"], "originalQm31");
  const currentColumns = [0, 1, 2, 3, 4, 5, 6, 7, 9, 10, 11, 12, 13, 15] as const;
  const globalColumns = [8, 14, 16] as const;
  const interactionColumns = Array.from({ length: 17 }, (_, column) => {
    const name = `interactionColumn${column}`;
    const current = currentColumns.indexOf(column as never);
    const globalColumn = globalColumns.indexOf(column as never);
    if (current >= 0) body.slice("interaction", current * 16, 16, name);
    else if (globalColumn >= 0) body.slice("globalCurrent", globalColumn * 16, 16, name);
    else throw new Error("v17 batch interaction order");
    return name;
  });
  body.concat(interactionColumns, "interactionQm31");
  body.slice("quotientAndMask", 0, 16, "quotient");
  body.concat([
    "preprocessedQm31",
    "originalQm31",
    "interactionQm31",
    "globalPrevious",
    "quotient",
  ], "functionsAtPoint");
  // Exact radix-beta^9 Horner for the opened function values. B_Q and the
  // static Cayley factors are authenticated once by query zero's leader cell.
  const atPoint = fusedBatch(body, "functionsAtPoint", "innerPowers", "pointBatch");

  body.constant(encodeQm31([0n, 0n, 0n, 0n]), "zero");
  body.constant(encodeQm31([0n, 1n, 0n, 0n]), "i");
  body.call(QM31_BLOB_MUL_M31, ["qxNumerator", "pointX"], "pxQx");
  body.call(QM31_BLOB_MUL_M31, ["qyNumerator", "pointY"], "pyQy");
  body.call(QM31_BLOB_ADD, ["pxQx", "pyQy"], "relativeXNumerator");
  body.call(QM31_BLOB_MUL_M31, ["qyNumerator", "pointX"], "pxQy");
  body.call(QM31_BLOB_SUB, ["zero", "pxQy"], "negativePxQy");
  body.call(QM31_BLOB_MUL_M31, ["qxNumerator", "pointY"], "pyQx");
  body.call(QM31_BLOB_ADD, ["negativePxQy", "pyQx"], "relativeYNumerator");
  body.call(QM31_BLOB_MUL, ["i", "relativeYNumerator"], "iRelativeY");
  body.call(QM31_BLOB_ADD, ["relativeXNumerator", "iRelativeY"], "relativeNumerator");
  body.call(QM31_BLOB_SUB, ["cayleyDenominator", "relativeNumerator"], "vanishingNumerator");

  body.slice("quotientAndMask", 16, 16, "mask");
  body.call(QM31_BLOB_MUL, ["beta", atPoint], "betaAtPoint");
  body.call(QM31_BLOB_SUB, ["fri0", "mask"], "batchWithoutMask");
  body.call(QM31_BLOB_SUB, ["batchWithoutMask", "betaAtPoint"], "uncorrected");
  body.call(QM31_BLOB_SUB, [atPoint, "batchAtQ"], "evaluationDifference");
  body.call(QM31_BLOB_MUL, ["uncorrected", "vanishingNumerator"], "left");
  body.call(QM31_BLOB_MUL, ["cellK", "evaluationDifference"], "right");
  const semanticBody = body.verifyEqualAndFinish("left", "right");
  const leaderCheck = leader
    ? `<13> OP_PICK <12> OP_PICK <12> OP_PICK <5> OP_PICK
<${V17_FRI_BATCH_LEADER_AUTH}> OP_INVOKE
<2> OP_ROLL OP_DROP <9> OP_ROLL OP_DROP`
    : "";
  const semanticDefinition = define(semanticBody, V17_FRI_BATCH_SEMANTIC_BODY,
    "local-word FRI batch semantic body");
  const leaderAuthenticationDefinition = leader
    ? define(leaderAuthBody, V17_FRI_BATCH_LEADER_AUTH,
      "local-word FRI batch leader authentication")
    : "";
  const sharedDefinitions = [
    baseDefinitionEntries.find(([id]) => id === CIRCLE_SCALAR_MUL)?.[1],
    semanticDefinition,
  ];
  if (sharedDefinitions.some((definition) => definition === undefined)) {
    throw new Error("v17 batch shared definition inventory");
  }
  return {
    definitions: `${baseDefinitions}
${semanticDefinition}
${leaderAuthenticationDefinition}`,
    sharedDefinitions: sharedDefinitions.join("\n"),
    localDefinitions: baseDefinitionEntries.filter(([id]) => id !== CIRCLE_SCALAR_MUL)
      .map(([, definition]) => definition).join("\n"),
    body: `${leader ? "OP_TOALTSTACK\n" : ""}${setup.join("\n")}
${leaderCheck}
<${V17_FRI_BATCH_SEMANTIC_BODY}> OP_INVOKE`,
  };
}

/** Bind every opened oracle value at one query to the first FRI codeword. */
export function compileLocalWordFriBatchGate(args: LocalWordFriBatchGateArgs): Uint8Array {
  const fragments = localWordFriBatchFragments(args, args.query !== 0);
  if (args.query !== 0) {
    return compile(`OP_DROP
${define(fragments.sharedDefinitions, V17_FRI_BATCH_OUTER_KERNEL,
    "v17 FRI batch shared initializer")}
<${V17_FRI_BATCH_OUTER_KERNEL}> OP_INVOKE
${define(`${fragments.localDefinitions}\n${fragments.body}`,
    V17_FRI_BATCH_LOCAL_ORCHESTRATOR, "v17 FRI batch local orchestrator")}
<${args.query}> <${V17_FRI_BATCH_LOCAL_ORCHESTRATOR}> OP_INVOKE
OP_1`, `local-word FRI batch ${args.query}`);
  }
  return compile(`OP_DROP
${fragments.definitions}
${fragments.body}
OP_1`, `local-word FRI batch ${args.query}`);
}

export type LocalWordFriFoldGateArgs = {
  readonly profile: 0 | 1 | 2;
  readonly query: number;
  readonly parameters?: LocalWordProofParameters;
  readonly reader?: LocalWordProofReader;
};

function compileLocalWordFriFoldGateMode(
  args: LocalWordFriFoldGateArgs,
  batchInvertTwiddles: boolean,
  runtimeOuterKernel = false,
): Uint8Array {
  const parameters = validateLocalWordProofParameters(
    args.parameters ?? LOCAL_WORD_PRODUCTION_PARAMETERS,
  );
  if (!Number.isInteger(args.query) || args.query < 0 || args.query >= parameters.fri.queries) {
    throw new Error("local-word FRI fold verifier key");
  }
  const publicWordCount = LOCAL_WORD_RELATION_STATEMENT_DIGEST_WORDS;
  const offsets = localWordProofStaticOffsets(publicWordCount, parameters);
  const definitionEntries: readonly (readonly [number, string])[] = [
    [READ_BYTES, define(localWordReadDynamicAssembly(args.reader), READ_BYTES,
      "local-word FRI reader")],
    [READ_QM31, define(BLOB_TO_QM31_ASM, READ_QM31, "local-word FRI QM31 reader")],
    [READ_CANONICAL_QM31, define(canonicalQm31Assembly(), READ_CANONICAL_QM31,
      "local-word FRI canonical QM31 reader")],
    [QM31_MUL, define(QM31_MUL_ASM, QM31_MUL, "local-word FRI QM31 multiply")],
    [QM31_MUL_M31,
      define(QM31_MUL_M31_ASM, QM31_MUL_M31, "local-word FRI QM31 scalar multiply")],
    [QM31_ADD, define(QM31_ADD_ASM, QM31_ADD, "local-word FRI QM31 add")],
    [QM31_SUB, define(qm31SubtractAssembly(), QM31_SUB, "local-word FRI QM31 subtract")],
    [QM31_TO_BLOB, define(QM31_TO_BLOB_ASM, QM31_TO_BLOB, "local-word FRI QM31 encode")],
    [M31_INVERSE, define(M31_INV, M31_INVERSE, "local-word FRI M31 inverse")],
    [CIRCLE_ADD, define(circleAddAssembly(), CIRCLE_ADD, "local-word FRI circle add")],
    [CIRCLE_SCALAR_MUL, define(batchInvertTwiddles
      ? circleFixedBaseScalarMulAssembly(
        scalarMul(CIRCLE_GEN, 1n << BigInt(30 - parameters.evalLog)),
        parameters.evalLog,
      )
      : circleScalarMulAssembly(parameters.evalLog), CIRCLE_SCALAR_MUL,
    batchInvertTwiddles
      ? "local-word FRI fixed-base circle scalar multiply"
      : "local-word FRI circle scalar multiply")],
    ...(!batchInvertTwiddles
      ? [[QM31_BLOB_MUL, define(qm31BlobBinaryAssembly(QM31_MUL), QM31_BLOB_MUL,
        "local-word FRI blob multiply")] as const]
      : []),
    [QM31_BLOB_MUL_M31, define(qm31BlobScalarAssembly(), QM31_BLOB_MUL_M31,
      "local-word FRI blob scalar multiply")],
    [QM31_BLOB_ADD, define(qm31BlobBinaryAssembly(QM31_ADD), QM31_BLOB_ADD,
      "local-word FRI blob add")],
    ...(!batchInvertTwiddles
      ? [[QM31_BLOB_SUB, define(qm31BlobBinaryAssembly(QM31_SUB), QM31_BLOB_SUB,
        "local-word FRI blob subtract")] as const]
      : []),
    ...(!batchInvertTwiddles
      ? [[FRI_FOLD_PAIR, define(friFoldPairAssembly(), FRI_FOLD_PAIR,
        "local-word FRI fold pair")] as const]
      : [[V17_FRI_FOLD_FROM_INVERSE,
        define(v17FriFoldFromInverseAssembly(), V17_FRI_FOLD_FROM_INVERSE,
          "v17 limb-local FRI fold from inverse")] as const]),
    [FRI_FOLD_LAYER2, define(friFoldLayerAssembly(4, batchInvertTwiddles), FRI_FOLD_LAYER2,
      batchInvertTwiddles ? "v17 fused FRI two-fold layer" : "local-word FRI two-fold layer")],
    [FRI_FOLD_LAYER1, define(friFoldLayerAssembly(2, batchInvertTwiddles), FRI_FOLD_LAYER1,
      batchInvertTwiddles ? "v17 fused FRI one-fold layer" : "local-word FRI one-fold layer")],
    [FRI_LINEAR_COMBINATION,
      define(friLinearCombinationAssembly(), FRI_LINEAR_COMBINATION,
        "local-word FRI linear combination")],
    [FRI_FINAL_EVALUATION,
      define(friFinalEvaluationAssembly(), FRI_FINAL_EVALUATION,
        "local-word FRI final evaluation")],
    [FRI_DOMAIN_TWIDDLES,
      define(friDomainTwiddlesAssembly(parameters), FRI_DOMAIN_TWIDDLES,
        "local-word FRI domain twiddles")],
    ...(batchInvertTwiddles
      ? [[FRI_BATCH_INVERT_TWIDDLES, define(
        v17M31BatchInverseBlobAssembly(
          V17_FRI_CURRENT_DENOMINATOR_COUNT,
          `<${M31_INVERSE}> OP_INVOKE`,
        ),
        FRI_BATCH_INVERT_TWIDDLES,
        "v17 FRI verifier-derived twiddle batch inverse",
      )] as const]
      : []),
  ];
  const definitions = definitionEntries.map(([, definition]) => definition).join("\n");

  const foldCounts = localWordFriFoldCounts(parameters);
  let completedFolds = 0;
  let twiddleOffset = 0;
  let challengeOffset = 0;
  const rounds = foldCounts.map((folds, layer) => {
    const arity = 2 ** folds;
    const rows = runtimeOuterKernel
      ? runtimeFriCosetRowsBlobAssembly({
        existing: layer === 0 ? 6 : 7,
        layer,
        offsets,
        parameters,
      })
      : friCosetRowsBlobAssembly({
        existing: layer === 0 ? 6 : 7,
        query: args.query,
        layer,
        offsets,
        parameters,
      });
    const compare = layer === 0 ? "" : compareFriFoldLinkAssembly({
      queryDepth: 6,
      completedFolds,
      arity,
    });
    const twiddles = `<3> OP_PICK <${twiddleOffset}> OP_SPLIT OP_NIP
<${folds === 2 ? 12 : 4}> OP_SPLIT OP_DROP`;
    const alpha = `<2> OP_PICK <${challengeOffset}> OP_SPLIT OP_NIP
<${folds * 16}> OP_SPLIT OP_DROP`;
    twiddleOffset += folds === 2 ? 12 : 4;
    challengeOffset += folds * 16;
    completedFolds += folds;
    return `${rows}
${compare}
${twiddles}
${alpha}
<${folds === 2 ? FRI_FOLD_LAYER2 : FRI_FOLD_LAYER1}> OP_INVOKE`;
  }).join("\n");
  if (completedFolds !== parameters.fri.queryOrbitLog || challengeOffset !== 17 * 16 ||
    twiddleOffset !== V17_FRI_CURRENT_DENOMINATOR_COUNT * 4) {
    throw new Error("local-word FRI fold geometry");
  }

  const consumer = `${runtimeOuterKernel
    ? `${runtimeQueryGuardAssembly(0, parameters.fri.queries)}\n`
    : ""}${localWordProofLengthAssembly()}
${staticBlobAssembly(1, 0, offsets.openingBodies)}
${runtimeOuterKernel
    ? prefetchedRuntimeQueryBlobAssembly({
      existing: 2,
      offset: offsets.queries,
      stride: 4,
      width: 4,
    })
    : prefetchedBlobAssembly(2, offsets.queries + args.query * 4, 4)}
OP_REVERSEBYTES OP_BIN2NUM OP_DUP <${FRI_DOMAIN_TWIDDLES}> OP_INVOKE
${batchInvertTwiddles ? `OP_SWAP <${FRI_BATCH_INVERT_TWIDDLES}> OP_INVOKE OP_SWAP` : ""}
${prefetchedBlobAssembly(5, offsets.friAlphas, challengeOffset)}
${rounds}
${runtimeOuterKernel ? "OP_FROMALTSTACK OP_DROP" : ""}
${prefetchedBlobAssembly(7, offsets.finalCoefficients, offsets.finalCoefficientCount * 16)}
<6> OP_ROLL OP_DROP
<3> OP_PICK <${FRI_FINAL_EVALUATION}> OP_INVOKE
OP_EQUALVERIFY OP_2DROP OP_2DROP OP_DROP`;
  if (runtimeOuterKernel) {
    const sharedDefinitionIds = new Set([FRI_DOMAIN_TWIDDLES, FRI_BATCH_INVERT_TWIDDLES]);
    const sharedDefinitions = definitionEntries.filter(([id]) => sharedDefinitionIds.has(id))
      .map(([, definition]) => definition).join("\n");
    const localDefinitions = definitionEntries.filter(([id]) => !sharedDefinitionIds.has(id))
      .map(([, definition]) => definition).join("\n");
    return compile(`OP_DROP
${define(sharedDefinitions, V17_FRI_FOLD_OUTER_KERNEL, "v17 FRI fold shared initializer")}
<${V17_FRI_FOLD_OUTER_KERNEL}> OP_INVOKE
${define(`${localDefinitions}\n${consumer}`, V17_FRI_FOLD_LOCAL_ORCHESTRATOR,
    "v17 FRI fold local orchestrator")}
<${args.query}> <${V17_FRI_FOLD_LOCAL_ORCHESTRATOR}> OP_INVOKE
OP_1`,
    `${batchInvertTwiddles ? "v17 " : ""}local-word FRI folds ${args.query}`);
  }
  return compile(`OP_DROP
${definitions}
${consumer}
OP_1`,
  `${batchInvertTwiddles ? "v17 " : ""}local-word FRI folds ${args.query}`);
}

/** Per-denominator-inversion oracle retained only for v17 differential qualification. */
export function compileLocalWordFriFoldGate(args: LocalWordFriFoldGateArgs): Uint8Array {
  return compileLocalWordFriFoldGateMode(args, false);
}

/** Production v17 gate: derive one inverse batch before all 25 pair folds. */
export function compileV17LocalWordFriFoldGate(args: LocalWordFriFoldGateArgs): Uint8Array {
  return compileLocalWordFriFoldGateMode(args, true, true);
}

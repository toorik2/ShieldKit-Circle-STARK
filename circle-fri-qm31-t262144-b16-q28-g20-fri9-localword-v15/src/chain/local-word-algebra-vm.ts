import { binToHex, cashAssemblyToBin } from "@bitauth/libauth";
import {
  LOCAL_WORD_AIR_PARTIAL_WIDTHS,
  localWordRelationZerofierAtBitReversed,
} from "../backends/circle/local-word-air.ts";
import {
  LOCAL_WORD_MATRIX_NAMES,
  LOCAL_WORD_MATRIX_ROW_WIDTHS,
  localWordProofStaticOffsets,
} from "../backends/circle/local-word-sealed-proof.ts";
import {
  LOCAL_WORD_PRODUCTION_PARAMETERS,
  localWordFriFoldCounts,
  validateLocalWordProofParameters,
  type LocalWordProofParameters,
} from "../backends/circle/local-word-successor-params.ts";
import { CIRCLE_GEN, scalarMul } from "../backends/circle/group.ts";
import { concatBytes, writeU32LE } from "../pool/bytes.ts";
import {
  localWordProofLengthAssembly,
  localWordReadDynamicAssembly,
} from "./local-word-balanced-vm.ts";
import { M31_ADD, M31_INV, M31_MUL, M31_P, M31_SUB } from "./m31-asm.ts";
import {
  BLOB_TO_QM31_ASM,
  QM31_ADD_ASM,
  QM31_MUL_ASM,
  QM31_MUL_M31_ASM,
  QM31_TO_BLOB_ASM,
  copy4,
} from "./qm31-asm.ts";

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
  return `<${args.existing - 1}> OP_PICK <${args.rankOffset}> <1> <${READ_BYTES}> OP_INVOKE OP_NIP
<0x00> OP_CAT OP_BIN2NUM
OP_DUP OP_0 OP_GREATERTHANOREQUAL OP_VERIFY
OP_DUP <${args.rankLimit}> OP_LESSTHAN OP_VERIFY
<${args.rowWidth}> OP_MUL
<${args.existing}> OP_PICK <${args.rowsStartOffset}> <4> <${READ_BYTES}> OP_INVOKE OP_NIP
OP_REVERSEBYTES OP_BIN2NUM OP_ADD
<${args.existing}> OP_PICK OP_SWAP <${args.rowWidth}> <${READ_BYTES}> OP_INVOKE OP_NIP`;
}

function staticBlobAssembly(existing: number, offset: number, width: number): string {
  return `<${existing - 1}> OP_PICK <${offset}> <${width}> <${READ_BYTES}> OP_INVOKE OP_NIP`;
}

function friQueryRowBlobAssembly(args: {
  readonly existing: number;
  readonly query: number;
  readonly offsets: ReturnType<typeof localWordProofStaticOffsets>;
  readonly parameters: LocalWordProofParameters;
}): string {
  const arity = 2 ** args.parameters.fri.foldLog;
  const directoryOffset = args.offsets.openingDirectory + LOCAL_WORD_MATRIX_NAMES.length * 20;
  return `<${args.existing - 1}> OP_PICK <${args.offsets.friCosetRanks + args.query}> <1> <${READ_BYTES}> OP_INVOKE OP_NIP
<0x00> OP_CAT OP_BIN2NUM
OP_DUP OP_0 OP_GREATERTHANOREQUAL OP_VERIFY
OP_DUP <${args.parameters.fri.queries * arity}> OP_LESSTHAN OP_VERIFY
<${args.existing}> OP_PICK <${args.offsets.queries + args.query * 4}> <4> <${READ_BYTES}> OP_INVOKE OP_NIP
OP_REVERSEBYTES OP_BIN2NUM <${arity}> OP_MOD OP_ADD
<16> OP_MUL
<${args.existing}> OP_PICK <${directoryOffset + 4}> <4> <${READ_BYTES}> OP_INVOKE OP_NIP
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

  slice(name: string, offset: number, width: number, result: string): void {
    this.lines.push(`<${this.depth(name)}> OP_PICK <${offset}> OP_SPLIT OP_NIP
<${width}> OP_SPLIT OP_DROP`);
    this.stack.push(result);
  }

  m31(name: string, offset: number, result: string): void {
    this.slice(name, offset, 4, result);
    this.lines.push("OP_BIN2NUM");
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

  invokeTop(id: number, count: number, result: string): void {
    this.lines.push(`<${id}> OP_INVOKE`);
    this.stack.splice(this.stack.length - count, count, result);
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

function friFoldLayerAssembly(arity: 2 | 4): string {
  const body = new ElementAssembly(["row", "twiddles", "alpha"]);
  body.slice("row", 0, 16, "value0");
  body.slice("row", 16, 16, "value1");
  body.m31("twiddles", 0, "twiddle0");
  body.call(FRI_FOLD_PAIR, ["value0", "value1", "twiddle0", "alpha"], "fold0");
  if (arity === 2) return body.finish("fold0");
  body.slice("row", 32, 16, "value2");
  body.slice("row", 48, 16, "value3");
  body.m31("twiddles", 4, "twiddle1");
  body.call(FRI_FOLD_PAIR, ["value2", "value3", "twiddle1", "alpha"], "fold1");
  body.call(QM31_BLOB_MUL, ["alpha", "alpha"], "alpha2");
  body.m31("twiddles", 8, "twiddle2");
  body.call(FRI_FOLD_PAIR, ["fold0", "fold1", "twiddle2", "alpha2"], "folded");
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

function circleAddAssembly(): string {
  return `<3> OP_PICK <2> OP_PICK ${M31_MUL}
<3> OP_PICK <2> OP_PICK ${M31_MUL} ${M31_SUB} OP_TOALTSTACK
<3> OP_PICK OP_1 OP_PICK ${M31_MUL}
<3> OP_PICK <3> OP_PICK ${M31_MUL} ${M31_ADD} OP_TOALTSTACK
OP_2DROP OP_2DROP OP_FROMALTSTACK OP_FROMALTSTACK OP_SWAP`;
}

function circleScalarMulAssembly(bits: number): string {
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

function bitReverseAssembly(bits: number): string {
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
  return `<${args.existing - 1}> OP_PICK
<${args.offsets.friCosetRanks + args.layer * args.parameters.fri.queries + args.query}>
<1> <${READ_BYTES}> OP_INVOKE OP_NIP <0x00> OP_CAT OP_BIN2NUM
OP_DUP OP_0 OP_GREATERTHANOREQUAL OP_VERIFY
OP_DUP <${args.parameters.fri.queries * arity}> OP_LESSTHAN OP_VERIFY
<16> OP_MUL
<${args.existing}> OP_PICK <${directoryOffset + 4}> <4> <${READ_BYTES}> OP_INVOKE OP_NIP
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
  return compile(`OP_DROP
${define(circleAddAssembly(), CIRCLE_ADD, "local-word FRI KAT circle add")}
${define(circleScalarMulAssembly(parameters.evalLog), CIRCLE_SCALAR_MUL,
    "local-word FRI KAT scalar multiply")}
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

function zerofierTable(parameters: LocalWordProofParameters): Uint8Array {
  const orbitCount = 2 ** (parameters.evalLog - parameters.relationLog);
  return concatBytes(...Array.from({ length: orbitCount }, (_, orbit) =>
    writeU32LE(Number(localWordRelationZerofierAtBitReversed(
      orbit * 2 ** parameters.relationLog,
      parameters,
    )))));
}

export type LocalWordCompositionQuotientGateArgs = {
  readonly profile: 0 | 1 | 2;
  readonly query: number;
  readonly parameters?: LocalWordProofParameters;
};

type LocalWordAlgebraGateFragments = {
  readonly definitions: string;
  readonly body: string;
};

function localWordCompositionQuotientFragments(
  args: LocalWordCompositionQuotientGateArgs,
): LocalWordAlgebraGateFragments {
  const parameters = validateLocalWordProofParameters(
    args.parameters ?? LOCAL_WORD_PRODUCTION_PARAMETERS,
  );
  if (!Number.isInteger(args.query) || args.query < 0 || args.query >= parameters.fri.queries) {
    throw new Error("local-word composition quotient verifier key");
  }
  const publicWordCount = args.profile === 0 ? 18 : args.profile === 1 ? 26 : 34;
  const offsets = localWordProofStaticOffsets(publicWordCount, parameters);
  const qmask = LOCAL_WORD_MATRIX_NAMES.indexOf("quotientAndFriMask");
  const qmaskWidth = LOCAL_WORD_MATRIX_ROW_WIDTHS[qmask]!;
  const definitions = [
    define(localWordReadDynamicAssembly(), READ_BYTES, "local-word algebra reader"),
    define(BLOB_TO_QM31_ASM, READ_QM31, "local-word algebra QM31 reader"),
    define(canonicalQm31Assembly(), READ_CANONICAL_QM31, "local-word algebra canonical QM31 reader"),
    define(QM31_MUL_ASM, QM31_MUL, "local-word algebra QM31 multiply"),
    define(QM31_MUL_M31_ASM, QM31_MUL_M31, "local-word algebra QM31 scalar multiply"),
    define(QM31_ADD_ASM, QM31_ADD, "local-word algebra QM31 add"),
    define(qm31SubtractAssembly(), QM31_SUB, "local-word algebra QM31 subtract"),
    define(QM31_TO_BLOB_ASM, QM31_TO_BLOB, "local-word algebra QM31 encode"),
  ].join("\n");

  const partialOffset = offsets.compositionPartials + args.query * 3 * 16;
  const firstPower = LOCAL_WORD_AIR_PARTIAL_WIDTHS[0];
  const secondPower = firstPower + LOCAL_WORD_AIR_PARTIAL_WIDTHS[1];
  const multiplyCurrentByAlpha = `${copy4(7, 6, 5, 4)} <${QM31_MUL}> OP_INVOKE`;
  const powers = `${staticBlobAssembly(1, offsets.constraintAlpha, 16)} <${READ_QM31}> OP_INVOKE
${copy4(3, 2, 1, 0)}
${Array.from({ length: firstPower - 1 }, () => multiplyCurrentByAlpha).join("\n")}
${copy4(3, 2, 1, 0)} <${QM31_TO_BLOB}> OP_INVOKE OP_TOALTSTACK
${Array.from({ length: secondPower - firstPower }, () => multiplyCurrentByAlpha).join("\n")}
<${QM31_TO_BLOB}> OP_INVOKE OP_TOALTSTACK
OP_2DROP OP_2DROP
OP_FROMALTSTACK OP_FROMALTSTACK OP_SWAP`;

  const composition = new BlobAssembly(6);
  composition.readQm31(4, 0, true);
  composition.readQm31(1);
  composition.qmMul();
  composition.readQm31(5, 0, true);
  composition.readQm31(2);
  composition.qmMul();
  composition.qmAdd();
  composition.readQm31(3, 0, true);
  composition.qmAdd();
  composition.encode();
  if (composition.extra !== 1) throw new Error("local-word composition stack");

  const quotient = new BlobAssembly(4);
  quotient.readQm31(2, 0);
  quotient.readM31(3);
  quotient.qmMulM31();
  quotient.readQm31(1);
  quotient.qmSub();
  quotient.encode();
  if (quotient.extra !== 1) throw new Error("local-word quotient stack");

  const table = zerofierTable(parameters);
  const orbitLog = parameters.relationLog;
  const orbitCount = 2 ** (parameters.evalLog - parameters.relationLog);
  return {
    definitions,
    body: `${localWordProofLengthAssembly()}
${powers}
${staticBlobAssembly(3, partialOffset, 16)}
${staticBlobAssembly(4, partialOffset + 16, 16)}
${staticBlobAssembly(5, partialOffset + 32, 16)}
${composition.lines.join("\n")}
OP_TOALTSTACK
${Array.from({ length: 6 }, () => "OP_DROP").join("\n")}
${localWordProofLengthAssembly()}
OP_FROMALTSTACK
${rowBlobAssembly({
    existing: 2,
    rankOffset: offsets.currentRanks + args.query,
    rankLimit: parameters.fri.queries,
    rowWidth: qmaskWidth,
    rowsStartOffset: matrixRowsStartOffset(offsets, qmask),
  })}
${staticBlobAssembly(3, offsets.queries + args.query * 4, 4)}
OP_REVERSEBYTES OP_BIN2NUM <${orbitLog}> OP_RSHIFTNUM
OP_DUP OP_0 OP_GREATERTHANOREQUAL OP_VERIFY
OP_DUP <${orbitCount}> OP_LESSTHAN OP_VERIFY
<4> OP_MUL ${`<0x${binToHex(table)}>`} OP_SWAP OP_SPLIT OP_NIP
<4> OP_SPLIT OP_DROP OP_BIN2NUM
${quotient.lines.join("\n")}
<0x00000000000000000000000000000000> OP_EQUALVERIFY
${Array.from({ length: 4 }, () => "OP_DROP").join("\n")}`,
  };
}

/** Combine the three checked AIR parts and enforce the sealed-trace quotient identity. */
export function compileLocalWordCompositionQuotientGate(
  args: LocalWordCompositionQuotientGateArgs,
): Uint8Array {
  const fragments = localWordCompositionQuotientFragments(args);
  return compile(`OP_DROP
${fragments.definitions}
${fragments.body}
OP_1`, `local-word composition quotient ${args.query}`);
}

export type LocalWordFriBatchGateArgs = {
  readonly profile: 0 | 1 | 2;
  readonly query: number;
  readonly parameters?: LocalWordProofParameters;
};

function localWordFriBatchFragments(
  args: LocalWordFriBatchGateArgs,
): LocalWordAlgebraGateFragments {
  const parameters = validateLocalWordProofParameters(
    args.parameters ?? LOCAL_WORD_PRODUCTION_PARAMETERS,
  );
  if (!Number.isInteger(args.query) || args.query < 0 || args.query >= parameters.fri.queries) {
    throw new Error("local-word FRI batch verifier key");
  }
  const publicWordCount = args.profile === 0 ? 18 : args.profile === 1 ? 26 : 34;
  const offsets = localWordProofStaticOffsets(publicWordCount, parameters);
  const matrix = (name: typeof LOCAL_WORD_MATRIX_NAMES[number]): number =>
    LOCAL_WORD_MATRIX_NAMES.indexOf(name);
  const definitions = [
    define(localWordReadDynamicAssembly(), READ_BYTES, "local-word batch reader"),
    define(BLOB_TO_QM31_ASM, READ_QM31, "local-word batch QM31 reader"),
    define(QM31_MUL_ASM, QM31_MUL, "local-word batch QM31 multiply"),
    define(QM31_ADD_ASM, QM31_ADD, "local-word batch QM31 add"),
    define(QM31_TO_BLOB_ASM, QM31_TO_BLOB, "local-word batch QM31 encode"),
  ].join("\n");

  // Bases: proof length, beta, original, interaction, global, quotient/FRI mask, FRI row.
  const batch = new BlobAssembly(7);
  batch.readQm31(2, 0);
  const absorb = (base: number, byteOffset: number): void => {
    batch.readQm31(1);
    batch.qmMul();
    batch.readQm31(base, byteOffset);
    batch.qmAdd();
  };
  for (let chunk = 1; chunk < 8; chunk += 1) absorb(2, chunk * 16);
  batch.readQm31(1);
  batch.qmMul();
  batch.lines.push(`<${batch.baseCount + batch.extra - 1 - 2}> OP_PICK <128> OP_SPLIT OP_NIP
<8> OP_SPLIT OP_DROP <0x0000000000000000> OP_CAT <${READ_QM31}> OP_INVOKE`);
  batch.extra += 4;
  batch.qmAdd();
  for (let value = 0; value < 14; value += 1) absorb(3, value * 16);
  for (let value = 0; value < 3; value += 1) absorb(4, value * 16);
  absorb(5, 0);
  batch.readQm31(5, 16);
  batch.qmAdd();
  batch.encode();
  if (batch.extra !== 1) throw new Error("local-word FRI batch stack");

  const currentRank = offsets.currentRanks + args.query;
  const globalRank = offsets.globalCurrentRanks + args.query;
  return {
    definitions,
    body: `${localWordProofLengthAssembly()}
${staticBlobAssembly(1, offsets.batchBeta, 16)}
${rowBlobAssembly({
    existing: 2,
    rankOffset: currentRank,
    rankLimit: parameters.fri.queries,
    rowWidth: LOCAL_WORD_MATRIX_ROW_WIDTHS[matrix("original")]!,
    rowsStartOffset: matrixRowsStartOffset(offsets, matrix("original")),
  })}
${rowBlobAssembly({
    existing: 3,
    rankOffset: currentRank,
    rankLimit: parameters.fri.queries,
    rowWidth: LOCAL_WORD_MATRIX_ROW_WIDTHS[matrix("interaction")]!,
    rowsStartOffset: matrixRowsStartOffset(offsets, matrix("interaction")),
  })}
${rowBlobAssembly({
    existing: 4,
    rankOffset: globalRank,
    rankLimit: 2 * parameters.fri.queries,
    rowWidth: LOCAL_WORD_MATRIX_ROW_WIDTHS[matrix("interactionGlobal")]!,
    rowsStartOffset: matrixRowsStartOffset(offsets, matrix("interactionGlobal")),
  })}
${rowBlobAssembly({
    existing: 5,
    rankOffset: currentRank,
    rankLimit: parameters.fri.queries,
    rowWidth: LOCAL_WORD_MATRIX_ROW_WIDTHS[matrix("quotientAndFriMask")]!,
    rowsStartOffset: matrixRowsStartOffset(offsets, matrix("quotientAndFriMask")),
  })}
${friQueryRowBlobAssembly({ existing: 6, query: args.query, offsets, parameters })}
${batch.lines.join("\n")}
OP_EQUALVERIFY
${Array.from({ length: 6 }, () => "OP_DROP").join("\n")}`,
  };
}

/** Bind every opened oracle value at one query to the first FRI codeword. */
export function compileLocalWordFriBatchGate(args: LocalWordFriBatchGateArgs): Uint8Array {
  const fragments = localWordFriBatchFragments(args);
  return compile(`OP_DROP
${fragments.definitions}
${fragments.body}
OP_1`, `local-word FRI batch ${args.query}`);
}

/** Share one reader and one QM31 lowering across quotient and FRI batching. */
export function compileLocalWordCompositionBatchGate(
  args: LocalWordCompositionQuotientGateArgs,
): Uint8Array {
  const quotient = localWordCompositionQuotientFragments(args);
  const batch = localWordFriBatchFragments(args);
  return compile(`OP_DROP
${quotient.definitions}
${quotient.body}
${batch.body}
OP_1`, `local-word composition and FRI batch ${args.query}`);
}

export type LocalWordFriFoldGateArgs = {
  readonly profile: 0 | 1 | 2;
  readonly query: number;
  readonly parameters?: LocalWordProofParameters;
};

/** Verify every committed FRI fold and the final polynomial for one query. */
export function compileLocalWordFriFoldGate(args: LocalWordFriFoldGateArgs): Uint8Array {
  const parameters = validateLocalWordProofParameters(
    args.parameters ?? LOCAL_WORD_PRODUCTION_PARAMETERS,
  );
  if (!Number.isInteger(args.query) || args.query < 0 || args.query >= parameters.fri.queries) {
    throw new Error("local-word FRI fold verifier key");
  }
  const publicWordCount = args.profile === 0 ? 18 : args.profile === 1 ? 26 : 34;
  const offsets = localWordProofStaticOffsets(publicWordCount, parameters);
  const definitions = [
    define(localWordReadDynamicAssembly(), READ_BYTES, "local-word FRI reader"),
    define(BLOB_TO_QM31_ASM, READ_QM31, "local-word FRI QM31 reader"),
    define(canonicalQm31Assembly(), READ_CANONICAL_QM31, "local-word FRI canonical QM31 reader"),
    define(QM31_MUL_ASM, QM31_MUL, "local-word FRI QM31 multiply"),
    define(QM31_MUL_M31_ASM, QM31_MUL_M31, "local-word FRI QM31 scalar multiply"),
    define(QM31_ADD_ASM, QM31_ADD, "local-word FRI QM31 add"),
    define(qm31SubtractAssembly(), QM31_SUB, "local-word FRI QM31 subtract"),
    define(QM31_TO_BLOB_ASM, QM31_TO_BLOB, "local-word FRI QM31 encode"),
    define(M31_INV, M31_INVERSE, "local-word FRI M31 inverse"),
    define(circleAddAssembly(), CIRCLE_ADD, "local-word FRI circle add"),
    define(circleScalarMulAssembly(parameters.evalLog), CIRCLE_SCALAR_MUL,
      "local-word FRI circle scalar multiply"),
    define(qm31BlobBinaryAssembly(QM31_MUL), QM31_BLOB_MUL, "local-word FRI blob multiply"),
    define(qm31BlobScalarAssembly(), QM31_BLOB_MUL_M31, "local-word FRI blob scalar multiply"),
    define(qm31BlobBinaryAssembly(QM31_ADD), QM31_BLOB_ADD, "local-word FRI blob add"),
    define(qm31BlobBinaryAssembly(QM31_SUB), QM31_BLOB_SUB, "local-word FRI blob subtract"),
    define(friFoldPairAssembly(), FRI_FOLD_PAIR, "local-word FRI fold pair"),
    define(friFoldLayerAssembly(4), FRI_FOLD_LAYER2, "local-word FRI two-fold layer"),
    define(friFoldLayerAssembly(2), FRI_FOLD_LAYER1, "local-word FRI one-fold layer"),
    define(friLinearCombinationAssembly(), FRI_LINEAR_COMBINATION,
      "local-word FRI linear combination"),
    define(friFinalEvaluationAssembly(), FRI_FINAL_EVALUATION,
      "local-word FRI final evaluation"),
    define(friDomainTwiddlesAssembly(parameters), FRI_DOMAIN_TWIDDLES,
      "local-word FRI domain twiddles"),
  ].join("\n");

  const foldCounts = localWordFriFoldCounts(parameters);
  let completedFolds = 0;
  let twiddleOffset = 0;
  const rounds = foldCounts.map((folds, layer) => {
    const arity = 2 ** folds;
    const rows = friCosetRowsBlobAssembly({
      existing: layer === 0 ? 5 : 6,
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
    const alpha = `<2> OP_PICK <${layer * 16}> OP_SPLIT OP_NIP
<16> OP_SPLIT OP_DROP`;
    twiddleOffset += folds === 2 ? 12 : 4;
    completedFolds += folds;
    return `${rows}
${compare}
${twiddles}
${alpha}
<${folds === 2 ? FRI_FOLD_LAYER2 : FRI_FOLD_LAYER1}> OP_INVOKE`;
  }).join("\n");
  if (completedFolds !== parameters.fri.queryOrbitLog || twiddleOffset !== 25 * 4) {
    throw new Error("local-word FRI fold geometry");
  }

  return compile(`OP_DROP
${definitions}
${localWordProofLengthAssembly()}
${staticBlobAssembly(1, offsets.queries + args.query * 4, 4)}
OP_REVERSEBYTES OP_BIN2NUM OP_DUP <${FRI_DOMAIN_TWIDDLES}> OP_INVOKE
${staticBlobAssembly(4, offsets.friAlphas, foldCounts.length * 16)}
${rounds}
${staticBlobAssembly(6, offsets.finalCoefficients, offsets.finalCoefficientCount * 16)}
<3> OP_PICK <${FRI_FINAL_EVALUATION}> OP_INVOKE
OP_EQUALVERIFY OP_2DROP OP_2DROP OP_DROP OP_1`, `local-word FRI folds ${args.query}`);
}

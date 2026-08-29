import { cashAssemblyToBin } from "@bitauth/libauth";
import { LOCAL_WORD_AIR_PARTIAL_WIDTHS } from "../backends/circle/local-word-air.ts";
import {
  LOCAL_WORD_MATRIX_NAMES,
  LOCAL_WORD_MATRIX_ROW_WIDTHS,
  localWordProofStaticOffsets,
} from "../backends/circle/local-word-sealed-proof.ts";
import {
  LOCAL_WORD_PRODUCTION_PARAMETERS,
  validateLocalWordProofParameters,
  type LocalWordProofParameters,
} from "../backends/circle/local-word-successor-params.ts";
import { LOCAL_WORD_INTERACTION_CHALLENGE_COUNT } from
  "../backends/circle/local-word-transcript.ts";
import {
  LOCAL_SHA_LIMBS,
} from "./sha256-local-word-machine.ts";
import {
  localWordProofLengthAssembly,
  localWordReadDynamicAssembly,
} from "./local-word-balanced-vm.ts";
import {
  BLOB_TO_QM31_ASM,
  QM31_ADD_ASM,
  QM31_MUL_KRONECKER_ASM,
  QM31_MUL_M31_ASM,
  QM31_TO_BLOB_ASM,
} from "./qm31-asm.ts";
import { M31_ADD, M31_MUL, M31_SUB } from "./m31-asm.ts";

const READ_BYTES = 0;
const READ_QM31 = 2;
const QM31_MUL = 3;
const QM31_MUL_M31 = 4;
const QM31_ADD = 5;
const QM31_SUB = 6;
const QM31_TO_BLOB = 7;

const CHALLENGE = {
  lookupGamma: 0,
  lookupTuple: 1,
  wordCopyGamma: 7,
  wordCopyIdentity: 8,
  wordCopyLimbs: 9,
  boundaryGamma: 17,
  boundaryIdentity: 18,
  boundaryLimbs: 19,
} as const;

const CURRENT_INTERACTION_COLUMNS = [0, 1, 2, 3, 4, 5, 6, 7, 9, 10, 11, 12, 13, 15] as const;
const GLOBAL_INTERACTION_COLUMNS = [8, 14, 16] as const;

function compile(assembly: string, label: string): Uint8Array {
  const result = cashAssemblyToBin(assembly);
  if (typeof result === "string") throw new Error(`${label}: ${result}`);
  if (result.length > 10_000) throw new Error(`${label} locking limit ${result.length}`);
  return result;
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function define(assembly: string, id: number, label: string): string {
  const bytecode = compile(assembly, label);
  return `<0x${hex(bytecode)}> <${id}> OP_DEFINE`;
}

/** Canonicality is owned once by the matrix-field gates, not repeated in AIR. */
const READ_QM31_ASM = BLOB_TO_QM31_ASM;

type Qm31Positions = readonly [number, number, number, number];

type BaseLayout = {
  readonly count: number;
  readonly preprocessed: readonly number[];
  readonly original: readonly number[];
  readonly interaction: readonly Qm31Positions[];
  readonly globalCurrent?: readonly Qm31Positions[];
  readonly globalPrevious?: readonly Qm31Positions[];
  readonly challenges: readonly Qm31Positions[];
  readonly alpha: Qm31Positions;
  readonly claimedSum?: Qm31Positions;
};

class AirAssembly {
  readonly lines: string[] = [];
  extra = 0;

  constructor(
    readonly bases: BaseLayout,
  ) {}

  emit(line: string): void {
    this.lines.push(line);
  }

  private depth(base: number, added = 0): number {
    return this.bases.count + 4 + this.extra + added - 1 - base;
  }

  readM31(base: "preprocessed" | "original", byteOffset: number): void {
    const positions = this.bases[base];
    const position = positions[byteOffset / 4];
    if (!Number.isInteger(byteOffset / 4) || position === undefined) {
      throw new Error(`local-word AIR missing ${base}:${byteOffset}`);
    }
    this.emit(`<${this.depth(position)}> OP_PICK`);
    this.extra += 1;
  }

  readQm31(
    base: "interaction" | "globalCurrent" | "globalPrevious" | "challenges" |
      "alpha" | "claimedSum",
    byteOffset: number,
  ): void {
    const value = base === "alpha" || base === "claimedSum"
      ? this.bases[base]
      : this.bases[base]?.[byteOffset / 16];
    if (!Number.isInteger(byteOffset / 16) || value === undefined) {
      throw new Error(`local-word AIR missing ${base}:${byteOffset}`);
    }
    value.forEach((position, limb) => this.emit(`<${this.depth(position, limb)}> OP_PICK`));
    this.extra += 4;
  }

  readChallenge(index: number): void {
    this.readQm31("challenges", index * 16);
  }

  readAlpha(): void {
    this.readQm31("alpha", 0);
  }

  m31Add(): void {
    this.emit(M31_ADD);
    this.extra -= 1;
  }

  m31Mul(): void {
    this.emit(M31_MUL);
    this.extra -= 1;
  }

  qmMul(): void {
    this.emit(`<${QM31_MUL}> OP_INVOKE`);
    this.extra -= 4;
  }

  qmMulM31(): void {
    this.emit(`<${QM31_MUL_M31}> OP_INVOKE`);
    this.extra -= 1;
  }

  qmAdd(): void {
    this.emit(`<${QM31_ADD}> OP_INVOKE`);
    this.extra -= 4;
  }

  qmSub(): void {
    this.emit(`<${QM31_SUB}> OP_INVOKE`);
    this.extra -= 4;
  }

  liftM31(): void {
    this.emit("OP_0 OP_0 OP_0");
    this.extra += 3;
  }

  parkQm31(): void {
    this.emit("OP_TOALTSTACK OP_TOALTSTACK OP_TOALTSTACK OP_TOALTSTACK");
    this.extra -= 4;
  }

  restoreQm31(): void {
    this.emit("OP_FROMALTSTACK OP_FROMALTSTACK OP_FROMALTSTACK OP_FROMALTSTACK");
    this.extra += 4;
  }

  readOriginal(column: number): void {
    this.readM31("original", column * 4);
  }

  readPreprocessed(column: number): void {
    this.readM31("preprocessed", column * 4);
  }

  readInteraction(column: number, previous = false): void {
    const current = CURRENT_INTERACTION_COLUMNS.indexOf(column as never);
    const global = GLOBAL_INTERACTION_COLUMNS.indexOf(column as never);
    if (!previous && current >= 0) this.readQm31("interaction", current * 16);
    else if (global >= 0) {
      this.readQm31(previous ? "globalPrevious" : "globalCurrent", global * 16);
    } else throw new Error("local-word AIR interaction column");
  }

  linear(gamma: number, terms: readonly { readonly challenge: number; readonly value: () => void }[]): void {
    this.readChallenge(gamma);
    for (const term of terms) {
      this.readChallenge(term.challenge);
      term.value();
      this.qmMulM31();
      this.qmAdd();
    }
  }

  lookupDenominator(limb: number): void {
    this.linear(CHALLENGE.lookupGamma, [
      { challenge: CHALLENGE.lookupTuple + 0, value: () => this.readPreprocessed(0) },
      { challenge: CHALLENGE.lookupTuple + 1, value: () => {
        this.readOriginal(limb);
        this.readPreprocessed(1 + limb);
        this.m31Add();
      } },
      { challenge: CHALLENGE.lookupTuple + 2, value: () => this.readOriginal(8 + limb) },
      { challenge: CHALLENGE.lookupTuple + 3, value: () => this.readOriginal(24 + limb) },
      { challenge: CHALLENGE.lookupTuple + 4, value: () => this.readOriginal(16 + limb) },
      { challenge: CHALLENGE.lookupTuple + 5, value: () => this.readOriginal(25 + limb) },
    ]);
  }

  tableDenominator(): void {
    this.linear(CHALLENGE.lookupGamma, Array.from({ length: 6 }, (_, term) => ({
      challenge: CHALLENGE.lookupTuple + term,
      value: () => this.readPreprocessed(34 + term),
    })));
  }

  compressedPort(port: number): void {
    const originalStart = port === 0 ? 0 : port === 1 ? 8 : 16;
    let terms = 0;
    const term = (challenge: number, selector: number, original: number): void => {
      this.readChallenge(challenge);
      this.readPreprocessed(selector);
      this.readOriginal(original);
      this.m31Mul();
      this.qmMulM31();
      if (terms > 0) this.qmAdd();
      terms += 1;
    };
    if (port === 2) {
      for (let limb = 0; limb < LOCAL_SHA_LIMBS; limb += 1) {
        term(CHALLENGE.wordCopyLimbs + limb, 31, originalStart + limb);
      }
    } else {
      const selectorStart = port === 0 ? 9 : 17;
      for (let shift = 0; shift < LOCAL_SHA_LIMBS; shift += 1) {
        for (let limb = 0; limb < LOCAL_SHA_LIMBS; limb += 1) {
          term(
            CHALLENGE.wordCopyLimbs + (limb + shift) % LOCAL_SHA_LIMBS,
            selectorStart + shift,
            originalStart + limb,
          );
        }
      }
    }
    if (terms < 1) throw new Error("local-word AIR compressed port");
  }

  wordTerm(idColumn: number, compressedColumn: number): void {
    this.readChallenge(CHALLENGE.wordCopyGamma);
    this.readChallenge(CHALLENGE.wordCopyIdentity);
    this.readPreprocessed(idColumn);
    this.qmMulM31();
    this.qmAdd();
    this.readInteraction(compressedColumn);
    this.qmAdd();
  }

  boundaryDenominator(): void {
    this.linear(CHALLENGE.boundaryGamma, [
      { challenge: CHALLENGE.boundaryIdentity, value: () => this.readPreprocessed(41) },
      ...Array.from({ length: LOCAL_SHA_LIMBS }, (_, limb) => ({
        challenge: CHALLENGE.boundaryLimbs + limb,
        value: () => this.readOriginal(16 + limb),
      })),
    ]);
  }

  lookupFractionResidual(limb: number): void {
    this.readInteraction(limb);
    if (limb > 0) {
      this.readInteraction(limb - 1);
      this.qmSub();
    }
    this.lookupDenominator(limb);
    this.qmMul();
    this.readPreprocessed(31);
    this.liftM31();
    this.qmSub();
  }

  lookupTableResidual(): void {
    this.readInteraction(8);
    this.readInteraction(8, true);
    this.readInteraction(7);
    this.qmAdd();
    this.qmSub();
    this.tableDenominator();
    this.qmMul();
    this.readOriginal(33);
    this.liftM31();
    this.qmAdd();
  }

  compressionResidual(port: number): void {
    this.readInteraction(9 + port);
    this.compressedPort(port);
    this.qmSub();
  }

  wordProductResidual(port: number): void {
    this.readInteraction(12 + port);
    this.wordTerm(26 + 2 * port, 9 + port);
    this.qmMul();
    this.readInteraction(port === 0 ? 14 : 11 + port, port === 0);
    this.wordTerm(25 + 2 * port, 9 + port);
    this.qmMul();
    this.qmSub();
  }

  wordProductAnchorResidual(): void {
    this.readInteraction(14);
    this.emit("OP_1 OP_0 OP_0 OP_0");
    this.extra += 4;
    this.qmSub();
    this.readPreprocessed(33);
    this.qmMulM31();
  }

  maskResidual(limb: number): void {
    this.readOriginal(16 + limb);
    this.readOriginal(16);
    this.emit(M31_SUB);
    this.extra -= 1;
    this.readPreprocessed(32);
    this.m31Mul();
    this.liftM31();
  }

  boundaryAccessResidual(): void {
    this.readInteraction(15);
    this.boundaryDenominator();
    this.qmMul();
    this.readPreprocessed(40);
    this.liftM31();
    this.qmSub();
  }

  boundaryGlobalResidual(): void {
    this.readInteraction(16);
    this.readInteraction(16, true);
    this.qmSub();
    this.readInteraction(15);
    this.qmSub();
    this.readQm31("claimedSum", 0);
    this.readPreprocessed(42);
    this.qmMulM31();
    this.qmAdd();
  }

  residual(index: number): void {
    if (index < 8) this.lookupFractionResidual(index);
    else if (index === 8) this.lookupTableResidual();
    else if (index < 12) this.compressionResidual(index - 9);
    else if (index < 15) this.wordProductResidual(index - 12);
    else if (index === 15) this.wordProductAnchorResidual();
    else if (index < 23) this.maskResidual(index - 15);
    else if (index === 23) this.boundaryAccessResidual();
    else if (index === 24) this.boundaryGlobalResidual();
    else throw new Error("local-word AIR residual index");
    if (this.extra !== 4) throw new Error(`local-word AIR residual stack ${index}:${this.extra}`);
  }
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

/** Replace one row blob with its little-endian M31 limbs, preserving row order. */
function parsedM31BlobAssembly(limbs: number): string {
  return `${Array.from({ length: limbs }, () =>
    "<4> OP_SPLIT OP_SWAP OP_BIN2NUM OP_SWAP").join("\n")}
OP_DROP`;
}

/** Replace one row blob with contiguous a0,a1,a2,a3 QM31 stack limbs. */
function parsedQm31BlobAssembly(values: number): string {
  return `${Array.from({ length: values }, () =>
    `<16> OP_SPLIT OP_SWAP <${READ_QM31}> OP_INVOKE <4> OP_ROLL`).join("\n")}
OP_DROP`;
}

function qm31Positions(start: number): Qm31Positions {
  return [start, start + 1, start + 2, start + 3];
}

function matrixRowsStartOffset(
  offsets: ReturnType<typeof localWordProofStaticOffsets>,
  matrix: number,
): number {
  return offsets.openingDirectory + matrix * 20 + 4;
}

export type LocalWordAirPartialGateArgs = {
  readonly profile: 0 | 1 | 2;
  readonly query: number;
  readonly part: 0 | 1 | 2;
  readonly parameters?: LocalWordProofParameters;
};

export type LocalWordAirPartsGateArgs = Omit<LocalWordAirPartialGateArgs, "part"> & {
  readonly parts: readonly (0 | 1 | 2)[];
};

/** Evaluate one or more canonical AIR Horner segments from one shared frame. */
export function compileLocalWordAirPartsGate(args: LocalWordAirPartsGateArgs): Uint8Array {
  const parameters = validateLocalWordProofParameters(
    args.parameters ?? LOCAL_WORD_PRODUCTION_PARAMETERS,
  );
  const parts = [...args.parts];
  if (!Number.isInteger(args.query) || args.query < 0 || args.query >= parameters.fri.queries ||
    parts.length < 1 || new Set(parts).size !== parts.length ||
    parts.some((part) => !Number.isInteger(part) || part < 0 ||
      part >= LOCAL_WORD_AIR_PARTIAL_WIDTHS.length)) {
    throw new Error("local-word AIR verifier key");
  }
  const publicWordCount = args.profile === 0 ? 18 : args.profile === 1 ? 26 : 34;
  const offsets = localWordProofStaticOffsets(publicWordCount, parameters);
  const preprocessed = LOCAL_WORD_MATRIX_NAMES.indexOf("preprocessed");
  const original = LOCAL_WORD_MATRIX_NAMES.indexOf("original");
  const interaction = LOCAL_WORD_MATRIX_NAMES.indexOf("interaction");
  const global = LOCAL_WORD_MATRIX_NAMES.indexOf("interactionGlobal");
  const currentRank = offsets.currentRanks + args.query;
  const setup: string[] = [];
  let baseCount = 1; // proofLength
  const appendM31Row = (rowArgs: Omit<Parameters<typeof rowBlobAssembly>[0], "existing">) => {
    setup.push(rowBlobAssembly({ ...rowArgs, existing: baseCount }));
    const count = rowArgs.rowWidth / 4;
    if (!Number.isInteger(count)) throw new Error("local-word AIR M31 row width");
    const positions = Array.from({ length: count }, (_, limb) => baseCount + limb);
    setup.push(parsedM31BlobAssembly(count));
    baseCount += count;
    return positions;
  };
  const appendQm31Row = (rowArgs: Omit<Parameters<typeof rowBlobAssembly>[0], "existing">) => {
    setup.push(rowBlobAssembly({ ...rowArgs, existing: baseCount }));
    const count = rowArgs.rowWidth / 16;
    if (!Number.isInteger(count)) throw new Error("local-word AIR QM31 row width");
    const positions = Array.from({ length: count }, (_, value) => qm31Positions(baseCount + value * 4));
    setup.push(parsedQm31BlobAssembly(count));
    baseCount += count * 4;
    return positions;
  };
  const appendStaticQm31 = (offset: number, count: number) => {
    setup.push(staticBlobAssembly(baseCount, offset, count * 16));
    const positions = Array.from({ length: count }, (_, value) => qm31Positions(baseCount + value * 4));
    setup.push(parsedQm31BlobAssembly(count));
    baseCount += count * 4;
    return positions;
  };
  const preprocessedPositions = appendM31Row({
    rankOffset: currentRank, rankLimit: parameters.fri.queries,
    rowWidth: LOCAL_WORD_MATRIX_ROW_WIDTHS[preprocessed]!,
    rowsStartOffset: matrixRowsStartOffset(offsets, preprocessed),
  });
  const originalPositions = appendM31Row({
    rankOffset: currentRank, rankLimit: parameters.fri.queries,
    rowWidth: LOCAL_WORD_MATRIX_ROW_WIDTHS[original]!,
    rowsStartOffset: matrixRowsStartOffset(offsets, original),
  });
  const interactionPositions = appendQm31Row({
    rankOffset: currentRank, rankLimit: parameters.fri.queries,
    rowWidth: LOCAL_WORD_MATRIX_ROW_WIDTHS[interaction]!,
    rowsStartOffset: matrixRowsStartOffset(offsets, interaction),
  });
  const globalCurrentPositions = appendQm31Row({
    rankOffset: offsets.globalCurrentRanks + args.query,
    rankLimit: parameters.fri.queries * 2,
    rowWidth: LOCAL_WORD_MATRIX_ROW_WIDTHS[global]!,
    rowsStartOffset: matrixRowsStartOffset(offsets, global),
  });
  const globalPreviousPositions = appendQm31Row({
    rankOffset: offsets.globalPreviousRanks + args.query,
    rankLimit: parameters.fri.queries * 2,
    rowWidth: LOCAL_WORD_MATRIX_ROW_WIDTHS[global]!,
    rowsStartOffset: matrixRowsStartOffset(offsets, global),
  });
  const challengePositions = appendStaticQm31(
    offsets.interactionChallenges,
    LOCAL_WORD_INTERACTION_CHALLENGE_COUNT,
  );
  const alphaPositions = appendStaticQm31(offsets.constraintAlpha, 1)[0]!;
  const claimedSumPositions = parts.includes(2)
    ? appendStaticQm31(offsets.publicClaimedSum, 1)[0]!
    : undefined;
  const expectedPositions = parts.map((part) => {
    const expectedPartial = offsets.compositionPartials +
      (args.query * LOCAL_WORD_AIR_PARTIAL_WIDTHS.length + part) * 16;
    setup.push(staticBlobAssembly(baseCount, expectedPartial, 16));
    const position = baseCount;
    baseCount += 1;
    return position;
  });
  const bases: BaseLayout = {
    count: baseCount,
    preprocessed: preprocessedPositions,
    original: originalPositions,
    interaction: interactionPositions,
    globalCurrent: globalCurrentPositions,
    globalPrevious: globalPreviousPositions,
    challenges: challengePositions,
    alpha: alphaPositions,
    claimedSum: claimedSumPositions,
  };

  const checks = parts.map((part, partIndex) => {
    const air = new AirAssembly(bases);
    const start = LOCAL_WORD_AIR_PARTIAL_WIDTHS
      .slice(0, part)
      .reduce((sum, width) => sum + width, 0);
    const width = LOCAL_WORD_AIR_PARTIAL_WIDTHS[part]!;
    for (let residual = start + width - 1; residual >= start; residual -= 1) {
      air.readAlpha();
      air.qmMul();
      air.residual(residual);
      air.qmAdd();
      if (air.extra !== 0) throw new Error(`local-word AIR Horner stack ${residual}:${air.extra}`);
    }
    return `OP_0 OP_0 OP_0 OP_0
${air.lines.join("\n")}
<${QM31_TO_BLOB}> OP_INVOKE
<${baseCount - expectedPositions[partIndex]!}> OP_PICK
OP_EQUALVERIFY`;
  });
  const definitions = [
    define(localWordReadDynamicAssembly(), READ_BYTES, "local-word AIR reader"),
    define(READ_QM31_ASM, READ_QM31, "local-word AIR QM31 reader"),
    define(QM31_MUL_KRONECKER_ASM, QM31_MUL, "local-word AIR QM31 multiply"),
    define(QM31_MUL_M31_ASM, QM31_MUL_M31, "local-word AIR QM31 scalar multiply"),
    define(QM31_ADD_ASM, QM31_ADD, "local-word AIR QM31 add"),
    define(`<4> OP_PICK OP_1 OP_PICK ${M31_SUB} OP_TOALTSTACK
<5> OP_PICK <2> OP_PICK ${M31_SUB} OP_TOALTSTACK
<6> OP_PICK <3> OP_PICK ${M31_SUB} OP_TOALTSTACK
<7> OP_PICK <4> OP_PICK ${M31_SUB} OP_TOALTSTACK
OP_2DROP OP_2DROP OP_2DROP OP_2DROP
OP_FROMALTSTACK OP_FROMALTSTACK OP_FROMALTSTACK OP_FROMALTSTACK`, QM31_SUB, "local-word AIR QM31 subtract"),
    define(QM31_TO_BLOB_ASM, QM31_TO_BLOB, "local-word AIR QM31 encode"),
  ].join("\n");
  return compile(`OP_DROP
${definitions}
${localWordProofLengthAssembly()}
${setup.join("\n")}
${checks.join("\n")}
${Array.from({ length: bases.count }, () => "OP_DROP").join("\n")}
OP_1`, `local-word AIR ${args.query}:${parts.join("+")}`);
}

/** Evaluate one canonical AIR partial. */
export function compileLocalWordAirPartialGate(args: LocalWordAirPartialGateArgs): Uint8Array {
  return compileLocalWordAirPartsGate({ ...args, parts: [args.part] });
}

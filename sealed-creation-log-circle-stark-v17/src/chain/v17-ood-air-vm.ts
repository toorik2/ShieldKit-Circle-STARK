/**
 * BCH-2026 singleton for the theorem-facing v17 OOD AIR identity.
 *
 * This role consumes exactly the 98 graph-owned QM31 claims. It reconstructs
 * all 25 AIR residuals and checks one whole quotient identity. The OODS point
 * is derived from the transcript-verified composition-digest snapshot; no
 * composition partial, Cayley inverse, or zerofier inverse is serialized.
 */
import { binToHex, cashAssemblyToBin } from "@bitauth/libauth";
import {
  LOCAL_WORD_AIR_CONSTRAINTS,
  LOCAL_WORD_INTERACTION_QM31_COLUMNS,
  LOCAL_WORD_PREPROCESSED_COLUMNS,
} from "../backends/circle/local-word-air.ts";
import { LOCAL_WORD_INTERACTION_CHALLENGE_COUNT } from
  "../backends/circle/local-word-transcript.ts";
import {
  V17_OOD_FUNCTION_COUNT,
  V17_OOD_PREDECESSOR_INTERACTION_COLUMNS,
} from "../backends/circle/v17-ood-air.ts";
import {
  v17ProofFrame,
  v17ProofFrameOffset,
  type V17GeneratedProofFrameId,
} from "../backends/circle/v17-proof-layout.ts";
import { V17_THEOREM_ROUND_IDS } from "../backends/circle/v17-round-transcript.ts";
import { V17_GENERATED_FOUNDATION } from "../construction/generated/v17-layout.ts";
import { V17_PRODUCTION_ROUND_GRINDING } from "../construction/v17-graph.ts";
import { writeU32LE } from "../pool/bytes.ts";
import {
  localWordProofLengthAssembly,
  localWordReadWideAssembly,
  type LocalWordProofReader,
} from "./local-word-balanced-vm.ts";
import { localWordRequiredChunkBytes } from "./local-word-role-budget.ts";
import { M31_P } from "./m31-asm.ts";
import {
  BLOB_TO_QM31_ASM,
  QM31_REDUCE_COEFFICIENTS_ASM,
} from "./qm31-asm.ts";
import {
  LOCAL_SHA_LIMBS,
  LOCAL_SHA_ORIGINAL_COLUMNS,
} from "./sha256-local-word-machine.ts";
import {
  V17_OODS_VM_FUNCTION_IDS,
  v17OodsDefinitions,
  v17OodsDigestToTAssembly,
  v17OodsSelectDigestAssembly,
} from "./v17-oods-vm.ts";

const READ_BYTES = 9;
const PACK_WIDE_QM31 = 10;
const REDUCE_WIDE_QM31 = 11;
const READ_QM31_DECODE = 12;
const CHECK_CANONICAL_QM31 = 13;
const ZERO_QM31_BLOB = "00".repeat(16);
const OOD_ROUND_ID = "air:ood" as const;
export const V17_FUSED_QM31_KRONECKER_BITS = 72;
export const V17_FUSED_QM31_WORD_BYTES = V17_FUSED_QM31_KRONECKER_BITS / 8;
export const V17_FUSED_QM31_BLOB_BYTES = V17_FUSED_QM31_WORD_BYTES * 9;

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

type Qm31Positions = readonly [number, number, number, number];

type OodAirLayout = {
  readonly count: number;
  readonly t: Qm31Positions;
  /** Canonical 16-byte blobs are decoded only at their point of use. */
  readonly claims: readonly number[];
  readonly challenges: readonly number[];
  readonly alpha: number;
  readonly claimedSum: number;
};

export type V17OodAirVmArgs = {
  readonly profile: 0 | 1 | 2;
  readonly reader?: LocalWordProofReader;
};

export type V17OodAirVmMeasurement = {
  readonly profile: 0 | 1 | 2;
  readonly lockingBytes: number;
  readonly operationCost: number;
  readonly requiredCarrierChunkBytes: number;
  readonly persistentStackItems: number;
  readonly topLevelStackItems: number;
  readonly claimCount: 98;
  readonly residualCount: 25;
  readonly transcriptSource: "checked-composition-digest-snapshot";
  readonly inverseHints: 0;
};

function compile(assembly: string, label: string): Uint8Array {
  const result = cashAssemblyToBin(assembly);
  if (typeof result === "string") throw new Error(`${label}: ${result}`);
  if (result.length > 10_000) throw new Error(`${label} locking limit ${result.length}`);
  return result;
}

function define(assembly: string, identifier: number, label: string): string {
  return `<0x${binToHex(compile(assembly, label))}> <${identifier}> OP_DEFINE`;
}

function hexPush(bytes: Uint8Array): string {
  return `<0x${binToHex(bytes)}>`;
}

function frameShape(id: V17GeneratedProofFrameId, itemBytes: number, itemCount: number): void {
  const frame = v17ProofFrame(id);
  if (frame.itemBytes !== itemBytes || frame.itemCount !== itemCount ||
    frame.totalBytes !== itemBytes * itemCount) {
    throw new Error(`v17 OOD AIR generated frame shape ${id}`);
  }
}

function staticBlobAssembly(existing: number, offset: number, width: number): string {
  return `<${existing - 1}> OP_PICK <${offset}> <${width}> <${READ_BYTES}> OP_INVOKE OP_NIP`;
}

/** Replace one contiguous frame with its ordered 16-byte QM31 blobs. */
function splitQm31BlobAssembly(values: number): string {
  return `${Array.from({ length: values }, () => "<16> OP_SPLIT").join("\n")}
OP_DROP`;
}

function qm31Positions(start: number): Qm31Positions {
  return [start, start + 1, start + 2, start + 3];
}

/** Four M31 limbs -> a carry-separated QM31 convolution operand. */
export const V17_FUSED_QM31_PACK_ASM = `<${4 * V17_FUSED_QM31_KRONECKER_BITS}> OP_LSHIFTNUM
OP_SWAP <${3 * V17_FUSED_QM31_KRONECKER_BITS}> OP_LSHIFTNUM OP_ADD
OP_SWAP <${V17_FUSED_QM31_KRONECKER_BITS}> OP_LSHIFTNUM OP_ADD OP_ADD`;

/** Nine widened convolution coefficients -> one reduced QM31 element. */
export const V17_FUSED_QM31_REDUCE_ASM = `${Array.from({ length: 9 }, () =>
  `<${V17_FUSED_QM31_WORD_BYTES}> OP_SPLIT OP_SWAP <0x00> OP_CAT OP_BIN2NUM <${M31_P}> OP_MOD OP_SWAP`).join("\n")}
OP_DROP
${QM31_REDUCE_COEFFICIENTS_ASM}`;

/** SuccessorTranscript.absorb for a statically known label and data width. */
function transcriptAbsorbAssembly(label: string, dataBytes: number): string {
  const labelBytes = new TextEncoder().encode(label);
  if (labelBytes.length < 1 || labelBytes.length > 96 || dataBytes < 0) {
    throw new Error("v17 OOD AIR transcript label");
  }
  const suffix = Uint8Array.of(labelBytes.length, ...labelBytes, ...writeU32LE(dataBytes));
  // Stack: digest data -> SHA256(0x00 || digest || label-frame || data).
  return `<0x00> OP_ROT OP_CAT ${hexPush(suffix)} OP_CAT OP_SWAP OP_CAT OP_SHA256`;
}

function roundBytes(): Uint8Array {
  const ordinal = V17_THEOREM_ROUND_IDS.indexOf(OOD_ROUND_ID);
  const id = new TextEncoder().encode(OOD_ROUND_ID);
  if (ordinal < 0 || ordinal > 0xff || id.length > 0xff) {
    throw new Error("v17 OOD AIR theorem round");
  }
  return Uint8Array.of(17, ordinal, id.length, ...id);
}

function oodGrindingBits(): number {
  const round = V17_PRODUCTION_ROUND_GRINDING.find(({ id }) => id === OOD_ROUND_ID);
  if (!round || round.bits < 0 || round.bits > 8) {
    throw new Error("v17 OOD AIR grinding schedule");
  }
  return round.bits;
}

/** Stack: digest nonceLE -> successor digest after exact named-round PoW. */
function theoremRoundPowAssembly(bits: number): string {
  const threshold = 2 ** (8 - bits);
  const bitsByte = Uint8Array.of(bits);
  return `OP_OVER
<0x03> OP_SWAP OP_CAT ${hexPush(bitsByte)} OP_CAT
<1> OP_PICK OP_CAT OP_SHA256
<1> OP_SPLIT OP_DROP <0x00> OP_CAT OP_BIN2NUM <${threshold}> OP_LESSTHAN OP_VERIFY
${hexPush(bitsByte)} OP_SWAP OP_CAT
${transcriptAbsorbAssembly("pow", 5)}`;
}

class OodAirAssembly {
  readonly lines: string[] = [];
  extra = 0;
  maximumExtra = 0;

  constructor(readonly bases: OodAirLayout) {}

  private adjust(delta: number): void {
    this.extra += delta;
    if (this.extra < 0) throw new Error("v17 OOD AIR negative assembly stack");
    this.maximumExtra = Math.max(this.maximumExtra, this.extra);
  }

  private depth(base: number, added = 0): number {
    // Four implicit limbs above the persistent bases hold the Horner accumulator.
    return this.bases.count + 4 + this.extra + added - 1 - base;
  }

  emit(line: string): void {
    this.lines.push(line);
  }

  readPositions(value: Qm31Positions): void {
    value.forEach((position, limb) => this.emit(`<${this.depth(position, limb)}> OP_PICK`));
    this.adjust(4);
  }

  readBlob(position: number): void {
    // Canonicality is checked once for every serialized frame before the AIR.
    this.emit(`<${this.depth(position)}> OP_PICK <${READ_QM31_DECODE}> OP_INVOKE`);
    this.adjust(4);
  }

  readClaim(index: number): void {
    const value = this.bases.claims[index];
    if (value === undefined) throw new Error(`v17 OOD AIR claim ${index}`);
    this.readBlob(value);
  }

  readChallenge(index: number): void {
    const value = this.bases.challenges[index];
    if (value === undefined) throw new Error(`v17 OOD AIR challenge ${index}`);
    this.readBlob(value);
  }

  readAlpha(): void {
    this.readBlob(this.bases.alpha);
  }

  readClaimedSum(): void {
    this.readBlob(this.bases.claimedSum);
  }

  readT(): void {
    this.readPositions(this.bases.t);
  }

  readPreprocessed(column: number): void {
    this.readClaim(column);
  }

  readOriginal(column: number): void {
    this.readClaim(LOCAL_WORD_PREPROCESSED_COLUMNS + column);
  }

  readInteraction(column: number, previous = false): void {
    if (!previous) {
      this.readClaim(LOCAL_WORD_PREPROCESSED_COLUMNS + LOCAL_SHA_ORIGINAL_COLUMNS + column);
      return;
    }
    const predecessor = V17_OOD_PREDECESSOR_INTERACTION_COLUMNS.indexOf(column as never);
    if (predecessor < 0) throw new Error(`v17 OOD AIR predecessor column ${column}`);
    this.readClaim(
      LOCAL_WORD_PREPROCESSED_COLUMNS + LOCAL_SHA_ORIGINAL_COLUMNS +
        LOCAL_WORD_INTERACTION_QM31_COLUMNS + predecessor,
    );
  }

  readQuotient(): void {
    this.readClaim(V17_OOD_FUNCTION_COUNT - 1);
  }

  pushZero(): void {
    this.emit("OP_0 OP_0 OP_0 OP_0");
    this.adjust(4);
  }

  pushOne(): void {
    this.emit("OP_1 OP_0 OP_0 OP_0");
    this.adjust(4);
  }

  qmMul(): void {
    this.emit(`<${V17_OODS_VM_FUNCTION_IDS.qm31Mul}> OP_INVOKE`);
    this.adjust(-4);
  }

  qmAdd(): void {
    this.emit(`<${V17_OODS_VM_FUNCTION_IDS.qm31Add}> OP_INVOKE`);
    this.adjust(-4);
  }

  qmSub(): void {
    this.emit(`<${V17_OODS_VM_FUNCTION_IDS.qm31Sub}> OP_INVOKE`);
    this.adjust(-4);
  }

  duplicateQm31AtBlockDepth(blocksFromTop: number): void {
    if (!Number.isInteger(blocksFromTop) || blocksFromTop < 0) {
      throw new Error("v17 OOD AIR QM31 copy depth");
    }
    this.emit(Array.from({ length: 4 }, () => `<${blocksFromTop * 4 + 3}> OP_PICK`).join("\n"));
    this.adjust(4);
  }

  parkQm31(): void {
    this.emit("OP_TOALTSTACK OP_TOALTSTACK OP_TOALTSTACK OP_TOALTSTACK");
    this.adjust(-4);
  }

  restoreQm31(): void {
    this.emit("OP_FROMALTSTACK OP_FROMALTSTACK OP_FROMALTSTACK OP_FROMALTSTACK");
    this.adjust(4);
  }

  dropQm31(): void {
    this.emit("OP_2DROP OP_2DROP");
    this.adjust(-4);
  }

  encodeQm31(): void {
    this.emit(`<${V17_OODS_VM_FUNCTION_IDS.qm31ToBlob}> OP_INVOKE`);
    this.adjust(-3);
  }

  verifyZeroQm31(): void {
    this.encodeQm31();
    this.emit(`<0x${ZERO_QM31_BLOB}> OP_EQUALVERIFY`);
    this.adjust(-1);
  }

  /**
   * Sum QM31 products with one final reduction. Radix 2^72 leaves eight
   * carry bits above every single-product coefficient, while every use below
   * has at most nine terms.
   */
  sumProducts(
    terms: readonly {
      readonly left: () => void;
      readonly right: () => void;
    }[],
  ): void {
    if (terms.length < 1 || terms.length > 9) {
      throw new Error("v17 OOD AIR fused product arity");
    }
    const before = this.extra;
    terms.forEach((term, index) => {
      term.left();
      term.right();
      this.emit(`<${PACK_WIDE_QM31}> OP_INVOKE OP_TOALTSTACK
<${PACK_WIDE_QM31}> OP_INVOKE OP_FROMALTSTACK OP_MUL`);
      this.adjust(-7); // eight limbs -> one exact convolution integer
      if (index > 0) {
        this.emit("OP_ADD");
        this.adjust(-1);
      }
    });
    this.emit(`<${V17_FUSED_QM31_BLOB_BYTES}> OP_NUM2BIN <${REDUCE_WIDE_QM31}> OP_INVOKE`);
    this.adjust(3); // one convolution integer -> four reduced limbs
    if (this.extra !== before + 4) {
      throw new Error("v17 OOD AIR fused product stack");
    }
  }

  private linear(
    gamma: number,
    terms: readonly { readonly challenge: number; readonly value: () => void }[],
  ): void {
    this.readChallenge(gamma);
    this.sumProducts(terms.map((term) => ({
      left: () => this.readChallenge(term.challenge),
      right: term.value,
    })));
    this.qmAdd();
  }

  private lookupDenominator(limb: number): void {
    this.linear(CHALLENGE.lookupGamma, [
      { challenge: CHALLENGE.lookupTuple + 0, value: () => this.readPreprocessed(0) },
      { challenge: CHALLENGE.lookupTuple + 1, value: () => {
        this.readOriginal(limb);
        this.readPreprocessed(1 + limb);
        this.qmAdd();
      } },
      { challenge: CHALLENGE.lookupTuple + 2, value: () => this.readOriginal(8 + limb) },
      { challenge: CHALLENGE.lookupTuple + 3, value: () => this.readOriginal(24 + limb) },
      { challenge: CHALLENGE.lookupTuple + 4, value: () => this.readOriginal(16 + limb) },
      { challenge: CHALLENGE.lookupTuple + 5, value: () => this.readOriginal(25 + limb) },
    ]);
  }

  private tableDenominator(): void {
    this.linear(CHALLENGE.lookupGamma, Array.from({ length: 6 }, (_, term) => ({
      challenge: CHALLENGE.lookupTuple + term,
      value: () => this.readPreprocessed(34 + term),
    })));
  }

  private compressedPort(port: number): void {
    const originalStart = port === 0 ? 0 : port === 1 ? 8 : 16;
    if (port === 2) {
      this.sumProducts(Array.from({ length: LOCAL_SHA_LIMBS }, (_, limb) => ({
        left: () => this.readChallenge(CHALLENGE.wordCopyLimbs + limb),
        right: () => this.readOriginal(originalStart + limb),
      })));
      this.readPreprocessed(31);
      this.qmMul();
      return;
    }
    const selectorStart = port === 0 ? 9 : 17;
    this.sumProducts(Array.from({ length: LOCAL_SHA_LIMBS }, (_, shift) => ({
      left: () => this.sumProducts(Array.from({ length: LOCAL_SHA_LIMBS }, (_, limb) => ({
        left: () => this.readChallenge(
          CHALLENGE.wordCopyLimbs + (limb + shift) % LOCAL_SHA_LIMBS,
        ),
        right: () => this.readOriginal(originalStart + limb),
      }))),
      right: () => this.readPreprocessed(selectorStart + shift),
    })));
  }

  private wordTerm(idColumn: number, compressedColumn: number): void {
    this.readChallenge(CHALLENGE.wordCopyGamma);
    this.readChallenge(CHALLENGE.wordCopyIdentity);
    this.readPreprocessed(idColumn);
    this.qmMul();
    this.qmAdd();
    this.readInteraction(compressedColumn);
    this.qmAdd();
  }

  private boundaryDenominator(): void {
    this.linear(CHALLENGE.boundaryGamma, [
      { challenge: CHALLENGE.boundaryIdentity, value: () => this.readPreprocessed(41) },
      ...Array.from({ length: LOCAL_SHA_LIMBS }, (_, limb) => ({
        challenge: CHALLENGE.boundaryLimbs + limb,
        value: () => this.readOriginal(16 + limb),
      })),
    ]);
  }

  private lookupFractionResidual(limb: number): void {
    this.readInteraction(limb);
    if (limb > 0) {
      this.readInteraction(limb - 1);
      this.qmSub();
    }
    this.lookupDenominator(limb);
    this.qmMul();
    this.readPreprocessed(31);
    this.qmSub();
  }

  private lookupTableResidual(): void {
    this.readInteraction(8);
    this.readInteraction(8, true);
    this.readInteraction(7);
    this.qmAdd();
    this.qmSub();
    this.tableDenominator();
    this.qmMul();
    this.readOriginal(33);
    this.qmAdd();
  }

  private compressionResidual(port: number): void {
    this.readInteraction(9 + port);
    this.compressedPort(port);
    this.qmSub();
  }

  private wordProductResidual(port: number): void {
    this.readInteraction(12 + port);
    this.wordTerm(26 + 2 * port, 9 + port);
    this.qmMul();
    this.readInteraction(port === 0 ? 14 : 11 + port, port === 0);
    this.wordTerm(25 + 2 * port, 9 + port);
    this.qmMul();
    this.qmSub();
  }

  private wordProductAnchorResidual(): void {
    this.readInteraction(14);
    this.pushOne();
    this.qmSub();
    this.readPreprocessed(33);
    this.qmMul();
  }

  private maskResidual(limb: number): void {
    this.readPreprocessed(32);
    this.readOriginal(16 + limb);
    this.readOriginal(16);
    this.qmSub();
    this.qmMul();
  }

  private boundaryAccessResidual(): void {
    this.readInteraction(15);
    this.boundaryDenominator();
    this.qmMul();
    this.readPreprocessed(40);
    this.qmSub();
  }

  private boundaryGlobalResidual(): void {
    this.readInteraction(16);
    this.readInteraction(16, true);
    this.qmSub();
    this.readInteraction(15);
    this.qmSub();
    this.readPreprocessed(42);
    this.readClaimedSum();
    this.qmMul();
    this.qmAdd();
  }

  residual(index: number): void {
    const before = this.extra;
    if (index < 8) this.lookupFractionResidual(index);
    else if (index === 8) this.lookupTableResidual();
    else if (index < 12) this.compressionResidual(index - 9);
    else if (index < 15) this.wordProductResidual(index - 12);
    else if (index === 15) this.wordProductAnchorResidual();
    else if (index < 23) this.maskResidual(index - 15);
    else if (index === 23) this.boundaryAccessResidual();
    else if (index === 24) this.boundaryGlobalResidual();
    else throw new Error("v17 OOD AIR residual index");
    if (this.extra !== before + 4) {
      throw new Error(`v17 OOD AIR residual stack ${index}:${before}->${this.extra}`);
    }
  }

  /** (n/d) -> ((2n^2-d^2)/d^2), preserving the Horner accumulator below. */
  traceDoubleAngle(): void {
    if (this.extra !== 8) throw new Error("v17 OOD AIR zerofier recurrence input");
    this.duplicateQm31AtBlockDepth(0);
    this.duplicateQm31AtBlockDepth(0);
    this.qmMul();
    this.parkQm31();
    this.duplicateQm31AtBlockDepth(1);
    this.duplicateQm31AtBlockDepth(0);
    this.qmMul();
    this.duplicateQm31AtBlockDepth(0);
    this.qmAdd();
    this.restoreQm31();
    this.duplicateQm31AtBlockDepth(0);
    this.parkQm31();
    this.qmSub();
    this.restoreQm31();
    this.parkQm31();
    this.parkQm31();
    this.dropQm31();
    this.dropQm31();
    this.restoreQm31();
    this.restoreQm31();
    if (this.extra !== 8) throw new Error("v17 OOD AIR zerofier recurrence output");
  }
}

function generatedGeometryChecks(): void {
  frameShape("profile", 1, 1);
  frameShape("compositionDigest", 32, 1);
  frameShape("matrixRoot:quotientAndFriMask", 32, 1);
  frameShape("roundNonce:air:ood", 4, 1);
  frameShape("oodValues", 16, V17_OOD_FUNCTION_COUNT);
  frameShape("interactionChallenges", 16, LOCAL_WORD_INTERACTION_CHALLENGE_COUNT);
  frameShape("constraintAlpha", 16, 1);
  frameShape("publicClaimedSum", 16, 1);
  if (V17_OOD_FUNCTION_COUNT !== 98 || LOCAL_WORD_AIR_CONSTRAINTS !== 25 ||
    V17_GENERATED_FOUNDATION.oodValueCount !== V17_OOD_FUNCTION_COUNT ||
    V17_GENERATED_FOUNDATION.relationLog !== 18) {
    throw new Error("v17 OOD AIR generated geometry");
  }
}

function compileArtifact(args: V17OodAirVmArgs): {
  readonly lockingBytecode: Uint8Array;
  readonly persistentStackItems: number;
  readonly topLevelStackItems: number;
} {
  if (args.profile !== 0 && args.profile !== 1 && args.profile !== 2) {
    throw new Error("v17 OOD AIR profile");
  }
  generatedGeometryChecks();
  const setup: string[] = [];
  let baseCount = 1; // proofLength

  setup.push(`${staticBlobAssembly(baseCount, v17ProofFrameOffset("profile"), 1)}
${hexPush(Uint8Array.of(args.profile))} OP_EQUALVERIFY`);

  setup.push(staticBlobAssembly(baseCount, v17ProofFrameOffset("compositionDigest"), 32));
  baseCount += 1;
  setup.push(staticBlobAssembly(
    baseCount,
    v17ProofFrameOffset("matrixRoot:quotientAndFriMask"),
    32,
  ));
  baseCount += 1;
  setup.push(transcriptAbsorbAssembly("local-word-v17-quotient-and-fri-mask-root", 32));
  baseCount -= 1;
  setup.push(`${hexPush(roundBytes())}
${transcriptAbsorbAssembly("v17-theorem-round", roundBytes().length)}`);
  setup.push(`${staticBlobAssembly(
    baseCount,
    v17ProofFrameOffset("roundNonce:air:ood"),
    4,
  )}
OP_REVERSEBYTES
${theoremRoundPowAssembly(oodGrindingBits())}
${v17OodsSelectDigestAssembly(V17_OODS_VM_FUNCTION_IDS.candidateAccepts)}
${v17OodsDigestToTAssembly()}`);
  baseCount += 3; // one digest is replaced by four t limbs
  const tPositions = qm31Positions(baseCount - 4);

  const appendStaticQm31 = (id: V17GeneratedProofFrameId, count: number) => {
    const offset = v17ProofFrameOffset(id);
    setup.push(staticBlobAssembly(baseCount, offset, count * 16));
    const positions = Array.from({ length: count }, (_, value) => baseCount + value);
    setup.push(splitQm31BlobAssembly(count));
    baseCount += count;
    return positions;
  };
  const claimPositions = appendStaticQm31("oodValues", V17_OOD_FUNCTION_COUNT);
  const challengePositions = appendStaticQm31(
    "interactionChallenges",
    LOCAL_WORD_INTERACTION_CHALLENGE_COUNT,
  );
  const alphaPosition = appendStaticQm31("constraintAlpha", 1)[0]!;
  const claimedSumPosition = appendStaticQm31("publicClaimedSum", 1)[0]!;
  const bases: OodAirLayout = {
    count: baseCount,
    t: tPositions,
    claims: claimPositions,
    challenges: challengePositions,
    alpha: alphaPosition,
    claimedSum: claimedSumPosition,
  };
  const serializedQm31Positions = [
    ...claimPositions,
    ...challengePositions,
    alphaPosition,
    claimedSumPosition,
  ];
  setup.push(serializedQm31Positions.map((position) =>
    `<${bases.count - 1 - position}> OP_PICK <${CHECK_CANONICAL_QM31}> OP_INVOKE`).join("\n"));

  const air = new OodAirAssembly(bases);
  for (let residual = LOCAL_WORD_AIR_CONSTRAINTS - 1; residual >= 0; residual -= 1) {
    air.readAlpha();
    air.qmMul();
    air.residual(residual);
    air.qmAdd();
    if (air.extra !== 0) throw new Error(`v17 OOD AIR Horner stack ${residual}:${air.extra}`);
  }

  // Qx=(1-t^2)/(1+t^2). Carry Z_H(Q) as n/d through 17 doublings.
  air.pushOne();
  air.readT();
  air.readT();
  air.qmMul();
  air.qmSub();
  air.pushOne();
  air.readT();
  air.readT();
  air.qmMul();
  air.qmAdd();
  for (let round = 1; round < V17_GENERATED_FOUNDATION.relationLog; round += 1) {
    air.traceDoubleAngle();
  }

  // q(Q) * n == composition(Q) * d. No inverse or partial-composition hint.
  air.parkQm31();
  air.readQuotient();
  air.qmMul();
  air.restoreQm31();
  air.duplicateQm31AtBlockDepth(2);
  air.duplicateQm31AtBlockDepth(1);
  air.qmMul();
  air.parkQm31();
  air.dropQm31();
  air.parkQm31();
  air.restoreQm31();
  air.restoreQm31();
  air.qmSub();
  air.verifyZeroQm31();
  if (air.extra !== 0) throw new Error(`v17 OOD AIR identity stack ${air.extra}`);

  const definitions = `${v17OodsDefinitions()}
${define(localWordReadWideAssembly(args.reader), READ_BYTES, "v17 OOD AIR proof reader")}
${define(V17_FUSED_QM31_PACK_ASM, PACK_WIDE_QM31, "v17 OOD AIR widened QM31 pack")}
${define(V17_FUSED_QM31_REDUCE_ASM, REDUCE_WIDE_QM31, "v17 OOD AIR widened QM31 reduce")}
${define(BLOB_TO_QM31_ASM, READ_QM31_DECODE, "v17 OOD AIR checked-frame decoder")}
${define(`<${V17_OODS_VM_FUNCTION_IDS.readCanonicalQm31}> OP_INVOKE OP_2DROP OP_2DROP`, CHECK_CANONICAL_QM31, "v17 OOD AIR canonical frame check")}`;
  const lockingBytecode = compile(`OP_DROP
${definitions}
${localWordProofLengthAssembly()}
${setup.join("\n")}
OP_0 OP_0 OP_0 OP_0
${air.lines.join("\n")}
OP_2DROP OP_2DROP
${Array.from({ length: Math.floor(bases.count / 2) }, () => "OP_2DROP").join("\n")}
${bases.count % 2 === 0 ? "" : "OP_DROP"}
OP_1`, "v17 singleton OOD AIR");
  return {
    lockingBytecode,
    persistentStackItems: bases.count,
    topLevelStackItems: bases.count + 4 + air.maximumExtra,
  };
}

/** Compile the one theorem-facing OOD AIR/quotient role for a v17 profile. */
export function compileV17OodAirQuotientGate(args: V17OodAirVmArgs): Uint8Array {
  return compileArtifact(args).lockingBytecode;
}

/** Attach measured BCH-2026 opcost/density to the compiler's static geometry. */
export function measureV17OodAirQuotientGate(
  args: V17OodAirVmArgs & { readonly operationCost: number },
): V17OodAirVmMeasurement {
  if (!Number.isSafeInteger(args.operationCost) || args.operationCost < 0) {
    throw new Error("v17 OOD AIR operation cost");
  }
  const artifact = compileArtifact(args);
  return {
    profile: args.profile,
    lockingBytes: artifact.lockingBytecode.length,
    operationCost: args.operationCost,
    requiredCarrierChunkBytes: localWordRequiredChunkBytes(args.operationCost),
    persistentStackItems: artifact.persistentStackItems,
    topLevelStackItems: artifact.topLevelStackItems,
    claimCount: 98,
    residualCount: 25,
    transcriptSource: "checked-composition-digest-snapshot",
    inverseHints: 0,
  };
}

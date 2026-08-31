import {
  decodeAuthenticationInstructions,
  decodeTransaction,
} from "@bitauth/libauth";
import {
  decodeLocalWordSealedProof,
  frameLocalWordSealedProof,
  LOCAL_WORD_MATRIX_NAMES,
  LOCAL_WORD_MATRIX_ROW_WIDTHS,
  localWordOpeningSchedules,
  type LocalWordProofContext,
  type LocalWordSealedProof,
} from "./local-word-sealed-proof.ts";
import {
  LOCAL_WORD_PRODUCTION_PARAMETERS,
  validateLocalWordProofParameters,
  type LocalWordProofParameters,
} from "./local-word-successor-params.ts";
import {
  LOCAL_WORD_PREPROCESSED_COLUMNS,
  localWordRelationZerofierAtBitReversed,
} from "./local-word-air.ts";
import {
  successorCirclePointAtBitReversed,
} from "./successor-domain.ts";
import {
  M31,
  add as mAdd,
  encodeLe as encodeM31Le,
  inv as mInv,
  mul as mMul,
  neg as mNeg,
  sub as mSub,
  type M31El,
} from "./m31.ts";
import {
  QM31_ONE,
  QM31_ZERO,
  encodeQm31,
  qmAdd,
  qmEq,
  qmMul,
  qmSub,
  type QM31El,
} from "./qm31.ts";
import {
  replayV17ProofTranscript,
} from "./v17-proof-transcript.ts";
import {
  v17Qm31CircleOnCurve,
  v17Qm31CirclePointIsBase,
  type V17Qm31CirclePoint,
} from "./v17-oods.ts";
import {
  v17TraceVanishingAtPoint,
} from "./v17-ood-air.ts";
import {
  LOCAL_WORD_CARRIER_INPUTS,
  partitionLocalWordProofBytes,
} from "../../chain/local-word-proof-carriers.ts";
import {
  V17_BOOTSTRAP_AFFINE_ALLOCATION,
  validateV17AffineAllocation,
  type V17AffineAllocation,
} from "../../chain/v17-affine-allocation.ts";
import {
  decodeLocalWordEdgeData,
  decodeLocalWordNullifierData,
  localWordEdgeDataOutputIndex,
  localWordNullifierDataOutputIndex,
} from "../../chain/local-word-envelope.ts";
import {
  concatBytes,
  readU32LE,
  sha256,
  writeU32BE,
} from "../../pool/bytes.ts";

export type LocalWordProtectedTraceRecoveryAudit = {
  /** Computed from the rank certificate and compensating witness; never assumed. */
  readonly recovered: boolean;
  readonly result: "not-uniquely-recoverable-from-algebraic-opening-view";
  readonly schedule: {
    readonly source: "strict-decoded-proof-and-transcript-replay";
    readonly queryOrderEntries: number;
    readonly currentIndices: number;
    readonly globalIndices: number;
    readonly friLayers: number;
    readonly checkedOpeningFamilies: number;
    readonly sha256Hex: string;
  };
  readonly observedValues: {
    readonly originalColumns: number;
    readonly baseDomainPointsPerColumn: number;
    readonly oodQm31PointsPerColumn: 0 | 1;
    readonly oodM31CoordinatesPerColumn: 0 | 4;
    readonly sha256Hex: string;
  };
  readonly linearSystem: {
    readonly field: "M31";
    readonly traceDimensionsPerColumn: number;
    readonly maskDimensionsPerColumn: number;
    readonly equationsPerColumn: number;
    readonly certifiedRankPerColumn: number;
    readonly conditionedMaskNullityPerColumn: number;
    readonly jointTraceAndMaskNullityPerColumn: number;
    readonly basis: "Stwo Circle FFT coefficient basis in bit-reversed order";
  };
  readonly compensatingWitness: {
    readonly traceDelta: "constant-one Circle polynomial";
    readonly maskCoefficientCount: number;
    readonly nonzeroMaskCoefficients: number;
    readonly maskCoefficientsSha256Hex: string;
    readonly allOpeningResidualsZero: true;
    readonly changesProtectedTrace: true;
  };
  readonly claimBoundary:
    "algebraic opening non-uniqueness only; AIR-valid semantic alternatives and statistical or QROM zero knowledge are not claimed";
};

export type LocalWordObserverLedger = {
  readonly proofVersion: number;
  readonly transactionBytes: number;
  readonly proofBytes: number;
  readonly carrierInputs: number;
  readonly carrierUnionExact: true;
  readonly carrierAllocation: {
    readonly status: V17AffineAllocation["status"];
    readonly minimumProofBytes: number;
    readonly exactOwnershipReplay: true;
  };
  readonly framing: LocalWordObserverFraming;
  readonly transactionShape: {
    readonly inputs: number;
    readonly outputs: number;
    readonly publicNullifierPathNodes: number;
    /** Canonical public wallet-rebuild data; zero only on a full withdrawal. */
    readonly publicEdgePathNodes: number;
    readonly publicCreationHandles: 0 | 1;
  };
  readonly roots: {
    readonly relationAndAuxiliary: number;
    readonly fri: number;
  };
  readonly directOpenings: {
    readonly currentPoints: number;
    readonly globalPoints: number;
    /** One QM31 claim is four M31-linear equations for each original column. */
    readonly originalOodQm31Points: 0 | 1;
    readonly originalM31Values: number;
    readonly interactionM31Values: number;
    readonly interactionGlobalM31Values: number;
    readonly quotientQm31Values: number;
    readonly friMaskQm31Values: number;
  };
  readonly fri: {
    readonly layerQm31Values: number;
    readonly finalQm31Coefficients: number;
    readonly authenticationNodes: number;
  };
  readonly authenticationNodes: number;
  readonly maskBudget: {
    readonly original: {
      readonly dimensionsPerColumn: number;
      readonly directOpeningEquationsPerColumn: number;
    };
    readonly interaction: {
      readonly dimensionsPerColumn: number;
      readonly directOpeningEquationsPerColumn: number;
    };
    readonly interactionGlobal: {
      readonly dimensionsPerColumn: number;
      readonly directOpeningEquationsPerColumn: number;
    };
    readonly friIsolator: {
      readonly dimensions: number;
      readonly directOpeningEquations: number;
    };
  };
  readonly quotient: {
    readonly decomposition: "none";
    readonly extraWitnessFormsAtQueries: 0;
    readonly reason: "determined by sealed AIR openings";
  };
  readonly protectedTraceRecovery: LocalWordProtectedTraceRecoveryAudit & {
    /** Compatibility counter for base-domain query openings only. */
    readonly observedPointsPerOriginalColumn: number;
    readonly privateTraceRows: number;
  };
  readonly claimBoundary: {
    readonly algebraicIop:
      "opening-view non-uniqueness only; complete honest-verifier simulation not claimed";
    readonly badDenominatorDistanceBits:
      | "unresolved for v16 relation"
      | "unresolved for v17 relation";
    readonly merkleAndFiatShamir:
      "classical programmable-ROM transcript and soundness model; no complete ZK claim";
    readonly qrom: "unresolved";
  };
};

export type LocalWordObserverFraming = {
  readonly layout: "generated-v17" | "experimental-legacy";
  readonly generatedFrameOrder: boolean;
  readonly exactPartition: true;
  readonly fixedPrefixBytes: number;
  readonly dynamicMixedMerkleBodyBytes: number;
  readonly oodQm31Values: number;
  readonly namedRoundNonces: number;
  readonly independentFriAlphas: number;
  readonly terminalDirectoryEntries: number;
  readonly dynamicBodyFrames: number;
};

type ProtectedTraceLinearCertificate = Pick<
  LocalWordProtectedTraceRecoveryAudit,
  "recovered" | "result" | "linearSystem" | "compensatingWitness" | "claimBoundary"
>;

const PRIVACY_AUDIT_DOMAIN = new TextEncoder().encode(
  "ShieldKit/V17ProtectedTraceRecoveryAudit/v1",
);

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function sameNumbers(left: readonly number[], right: readonly number[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function assertExactOpeningSchedule(
  actual: readonly number[],
  expected: readonly number[],
  label: string,
): void {
  if (new Set(actual).size !== actual.length) {
    throw new Error(`local-word privacy duplicate ${label} schedule`);
  }
  if (actual.some((value, index) => !Number.isSafeInteger(value) || value < 0 ||
    (index > 0 && actual[index - 1]! >= value))) {
    throw new Error(`local-word privacy malformed ${label} schedule`);
  }
  if (!sameNumbers(actual, expected)) {
    throw new Error(`local-word privacy ${label} schedule drift`);
  }
}

function encodedIndexVector(indices: readonly number[]): Uint8Array {
  return concatBytes(writeU32BE(indices.length), ...indices.map(writeU32BE));
}

function baseFftFactors(point: { readonly x: M31El; readonly y: M31El }, logSize: number): M31El[] {
  const factors = [point.y];
  let x = point.x;
  for (let level = 1; level < logSize; level += 1) {
    factors.push(x);
    x = mSub(mMul(2n, mMul(x, x)), 1n);
  }
  return factors.reverse();
}

function qm31FftFactors(point: V17Qm31CirclePoint, logSize: number): QM31El[] {
  const factors = [point.y];
  let x = point.x;
  for (let level = 1; level < logSize; level += 1) {
    factors.push(x);
    const square = qmMul(x, x);
    x = qmSub(qmAdd(square, square), QM31_ONE);
  }
  return factors.reverse();
}

/** Evaluate one coefficient of Stwo's bit-reversed Circle FFT basis. */
function baseFftBasisValue(
  factors: readonly M31El[],
  coefficient: number,
): M31El {
  let value = 1n;
  for (let position = 0; position < factors.length; position += 1) {
    const bit = factors.length - 1 - position;
    if ((coefficient & 2 ** bit) !== 0) value = mMul(value, factors[position]!);
  }
  return value;
}

function qm31FftBasisValue(
  factors: readonly QM31El[],
  coefficient: number,
): QM31El {
  let value = QM31_ONE;
  for (let position = 0; position < factors.length; position += 1) {
    const bit = factors.length - 1 - position;
    if ((coefficient & 2 ** bit) !== 0) value = qmMul(value, factors[position]!);
  }
  return value;
}

function solveFullRowRankM31(
  matrix: readonly (readonly M31El[])[],
  rightHandSide: readonly M31El[],
): { readonly rank: number; readonly solution: readonly M31El[] } {
  if (matrix.length === 0 || matrix.length !== rightHandSide.length ||
    matrix.some((row) => row.length !== matrix.length)) {
    throw new Error("local-word privacy rank geometry");
  }
  const width = matrix.length;
  const rows = matrix.map((row, index) => [...row, rightHandSide[index]!]);
  const pivotColumns: number[] = [];
  let rank = 0;
  for (let column = 0; column < width && rank < rows.length; column += 1) {
    let pivot = rank;
    while (pivot < rows.length && rows[pivot]![column] === 0n) pivot += 1;
    if (pivot === rows.length) continue;
    [rows[rank], rows[pivot]] = [rows[pivot]!, rows[rank]!];
    const inverse = mInv(rows[rank]![column]!);
    for (let item = column; item <= width; item += 1) {
      rows[rank]![item] = mMul(rows[rank]![item]!, inverse);
    }
    for (let other = 0; other < rows.length; other += 1) {
      if (other === rank) continue;
      const factor = rows[other]![column]!;
      if (factor === 0n) continue;
      for (let item = column; item <= width; item += 1) {
        rows[other]![item] = mSub(
          rows[other]![item]!,
          mMul(factor, rows[rank]![item]!),
        );
      }
    }
    pivotColumns.push(column);
    rank += 1;
  }
  if (rank !== matrix.length) {
    throw new Error(`local-word privacy opening rank ${rank}/${matrix.length}`);
  }
  const solution = Array.from({ length: width }, () => 0n);
  pivotColumns.forEach((column, row) => {
    solution[column] = rows[row]![width]!;
  });
  return { rank, solution };
}

/**
 * Construct and verify one concrete ambiguity witness for the exact opening
 * points. The trace delta is the constant-one Circle polynomial. The returned
 * mask delta solves `1 + Z_H(P) * delta_r(P) = 0` at every base opening and,
 * for v17, in all four M31 coordinates of the QM31 OOD opening.
 *
 * This is deliberately only an algebraic opening-view certificate. It does
 * not assert that the altered trace satisfies the AIR, nor does it turn the
 * classical programmable-ROM argument into statistical or QROM zero knowledge.
 */
export function certifyLocalWordProtectedTraceOpeningNonUniqueness(args: {
  readonly currentIndices: readonly number[];
  readonly oodPoint?: V17Qm31CirclePoint;
  readonly parameters?: LocalWordProofParameters;
}): ProtectedTraceLinearCertificate {
  const parameters = validateLocalWordProofParameters(
    args.parameters ?? LOCAL_WORD_PRODUCTION_PARAMETERS,
  );
  const current = [...args.currentIndices];
  if (current.length < 1 || new Set(current).size !== current.length ||
    current.some((index, item) => !Number.isSafeInteger(index) || index < 0 ||
      index >= 2 ** parameters.evalLog || (item > 0 && current[item - 1]! >= index))) {
    throw new Error("local-word privacy malformed current schedule");
  }
  if (args.oodPoint !== undefined &&
    (!v17Qm31CircleOnCurve(args.oodPoint) || v17Qm31CirclePointIsBase(args.oodPoint))) {
    throw new Error("local-word privacy OOD rank point");
  }
  const oodCoordinates = args.oodPoint === undefined ? 0 : 4;
  const equationCount = current.length + oodCoordinates;
  const dimensions = 2 ** parameters.relationLog;
  if (equationCount > dimensions) {
    throw new Error(`local-word privacy mask dimensions ${equationCount}/${dimensions}`);
  }

  const matrix: M31El[][] = [];
  const rightHandSide: M31El[] = [];
  for (const index of current) {
    const point = successorCirclePointAtBitReversed(parameters.evalLog, index);
    const zerofier = localWordRelationZerofierAtBitReversed(index, parameters);
    if (zerofier === 0n) throw new Error("local-word privacy base opening in trace domain");
    const factors = baseFftFactors(point, parameters.relationLog);
    matrix.push(Array.from({ length: equationCount }, (_, coefficient) =>
      mMul(zerofier, baseFftBasisValue(factors, coefficient))));
    rightHandSide.push(mNeg(1n));
  }
  if (args.oodPoint !== undefined) {
    const factors = qm31FftFactors(args.oodPoint, parameters.relationLog);
    const zerofier = v17TraceVanishingAtPoint(args.oodPoint, parameters.relationLog);
    if (qmEq(zerofier, QM31_ZERO)) throw new Error("local-word privacy OOD in trace domain");
    const columns = Array.from({ length: equationCount }, (_, coefficient) =>
      qmMul(zerofier, qm31FftBasisValue(factors, coefficient)));
    for (let coordinate = 0; coordinate < 4; coordinate += 1) {
      matrix.push(columns.map((value) => value[coordinate]));
      rightHandSide.push(coordinate === 0 ? mNeg(1n) : 0n);
    }
  }

  const solved = solveFullRowRankM31(matrix, rightHandSide);
  const residualsZero = matrix.every((row, rowIndex) =>
    row.reduce(
      (sum, coefficient, column) => mAdd(sum, mMul(coefficient, solved.solution[column]!)),
      0n,
    ) === rightHandSide[rowIndex]);
  const nonzeroMaskCoefficients = solved.solution.filter((value) => value !== 0n).length;
  const changesProtectedTrace = mAdd(0n, 1n) !== 0n;
  const ambiguityCertified = solved.rank === equationCount && residualsZero &&
    nonzeroMaskCoefficients > 0 && changesProtectedTrace;
  const recovered = !ambiguityCertified;
  if (recovered) throw new Error("local-word privacy ambiguity witness");

  return {
    recovered,
    result: "not-uniquely-recoverable-from-algebraic-opening-view",
    linearSystem: {
      field: "M31",
      traceDimensionsPerColumn: dimensions,
      maskDimensionsPerColumn: dimensions,
      equationsPerColumn: equationCount,
      certifiedRankPerColumn: solved.rank,
      conditionedMaskNullityPerColumn: dimensions - solved.rank,
      jointTraceAndMaskNullityPerColumn: 2 * dimensions - solved.rank,
      basis: "Stwo Circle FFT coefficient basis in bit-reversed order",
    },
    compensatingWitness: {
      traceDelta: "constant-one Circle polynomial",
      maskCoefficientCount: solved.solution.length,
      nonzeroMaskCoefficients,
      maskCoefficientsSha256Hex: hex(sha256(concatBytes(
        PRIVACY_AUDIT_DOMAIN,
        ...solved.solution.map(encodeM31Le),
      ))),
      allOpeningResidualsZero: true,
      changesProtectedTrace: true,
    },
    claimBoundary:
      "algebraic opening non-uniqueness only; AIR-valid semantic alternatives and statistical or QROM zero knowledge are not claimed",
  };
}

/**
 * Recheck every schedule independently of the codec and bind the rank witness
 * to the decoded opening bytes. Call only after strict canonical decoding.
 */
export function auditLocalWordProtectedTraceRecovery(
  proof: LocalWordSealedProof,
  context: LocalWordProofContext,
  parameters: LocalWordProofParameters = LOCAL_WORD_PRODUCTION_PARAMETERS,
): LocalWordProtectedTraceRecoveryAudit {
  validateLocalWordProofParameters(parameters);
  const schedules = localWordOpeningSchedules(proof.queries, parameters);
  const matrixExpected: Readonly<Record<(typeof LOCAL_WORD_MATRIX_NAMES)[number], readonly number[]>> = {
    preprocessed: schedules.current,
    original: schedules.current,
    interaction: schedules.current,
    interactionGlobal: schedules.global,
    quotientAndFriMask: schedules.current,
  };
  LOCAL_WORD_MATRIX_NAMES.forEach((name) =>
    assertExactOpeningSchedule(proof.matrices[name].indices, matrixExpected[name], `matrix ${name}`));
  if (proof.fri.layers.length !== schedules.fri.length) {
    throw new Error("local-word privacy FRI schedule count");
  }
  proof.fri.layers.forEach((layer, round) =>
    assertExactOpeningSchedule(layer.indices, schedules.fri[round]!, `FRI ${round}`));

  const original = proof.matrices.original;
  if (original.rowWidth !== LOCAL_WORD_MATRIX_ROW_WIDTHS[1] ||
    original.rows.length !== schedules.current.length ||
    original.rows.some((row) => row.length !== original.rowWidth)) {
    throw new Error("local-word privacy original opening geometry");
  }
  original.rows.forEach((row) => {
    for (let offset = 0; offset < row.length; offset += 4) {
      if (BigInt(readU32LE(row, offset)) >= M31) {
        throw new Error("local-word privacy original field element");
      }
    }
  });

  const hasOodValues = proof.oodValues !== undefined;
  const hasRoundNonces = proof.roundNonces !== undefined;
  if (hasOodValues !== hasRoundNonces) throw new Error("local-word privacy OOD transcript geometry");
  let oodPoint: V17Qm31CirclePoint | undefined;
  let originalOodValues: readonly QM31El[] = [];
  if (hasOodValues) {
    if (proof.profile < 0 || proof.profile > 2) throw new Error("local-word privacy profile");
    const replay = replayV17ProofTranscript({
      initial: context.transcriptInitial,
      version: 17,
      profile: proof.profile as 0 | 1 | 2,
      protocolId: proof.protocolId,
      preprocessedRoot: proof.matrices.preprocessed.root,
      originalRoot: proof.matrices.original.root,
      publicBoundaryInverses: proof.publicBoundaryInverses,
      publicBoundaryClaimedSum: proof.publicBoundaryClaimedSum,
      interactionRoot: proof.matrices.interaction.root,
      interactionGlobalRoot: proof.matrices.interactionGlobal.root,
      quotientAndFriMaskRoot: proof.matrices.quotientAndFriMask.root,
      oodValues: proof.oodValues!,
      friRoots: proof.fri.layers.map((layer) => layer.root),
      finalCoefficients: proof.fri.finalCoefficients,
      roundNonces: proof.roundNonces!,
    });
    if (!sameNumbers(replay.queries, proof.queries)) {
      throw new Error("local-word privacy transcript query schedule");
    }
    oodPoint = replay.oods.point;
    originalOodValues = proof.oodValues!.slice(
      LOCAL_WORD_PREPROCESSED_COLUMNS,
      LOCAL_WORD_PREPROCESSED_COLUMNS + original.rowWidth / 4,
    );
    if (originalOodValues.length !== original.rowWidth / 4) {
      throw new Error("local-word privacy original OOD geometry");
    }
  }

  const linear = certifyLocalWordProtectedTraceOpeningNonUniqueness({
    currentIndices: schedules.current,
    ...(oodPoint === undefined ? {} : { oodPoint }),
    parameters,
  });
  const scheduleEncoding = concatBytes(
    PRIVACY_AUDIT_DOMAIN,
    encodedIndexVector(proof.queries),
    encodedIndexVector(schedules.current),
    encodedIndexVector(schedules.global),
    ...schedules.fri.map(encodedIndexVector),
  );
  const observedEncoding = concatBytes(
    PRIVACY_AUDIT_DOMAIN,
    encodedIndexVector(schedules.current),
    ...original.rows,
    ...originalOodValues.map(encodeQm31),
  );
  return {
    ...linear,
    schedule: {
      source: "strict-decoded-proof-and-transcript-replay",
      queryOrderEntries: proof.queries.length,
      currentIndices: schedules.current.length,
      globalIndices: schedules.global.length,
      friLayers: schedules.fri.length,
      checkedOpeningFamilies: LOCAL_WORD_MATRIX_NAMES.length + schedules.fri.length,
      sha256Hex: hex(sha256(scheduleEncoding)),
    },
    observedValues: {
      originalColumns: original.rowWidth / 4,
      baseDomainPointsPerColumn: schedules.current.length,
      oodQm31PointsPerColumn: oodPoint === undefined ? 0 : 1,
      oodM31CoordinatesPerColumn: oodPoint === undefined ? 0 : 4,
      sha256Hex: hex(sha256(observedEncoding)),
    },
  };
}

/** Pure observer-side inventory over the canonical frame ownership map. */
export function inspectLocalWordProofFraming(
  proof: LocalWordSealedProof,
  parameters: LocalWordProofParameters = LOCAL_WORD_PRODUCTION_PARAMETERS,
): LocalWordObserverFraming {
  const frames = frameLocalWordSealedProof(proof, parameters);
  if (frames.length === 0 || frames[0]!.start !== 0 ||
    frames.at(-1)!.end !== proof.proofLength || frames.some((frame, index) =>
      index > 0 && frames[index - 1]!.end !== frame.start)) {
    throw new Error("local-word observer proof frame partition");
  }
  const generated = frames.some(({ generatedFrameId }) => generatedFrameId === "oodValues");
  const dynamicKinds = new Set([
    "matrix-row", "matrix-sibling", "matrix-frontier",
    "fri-value", "fri-sibling", "fri-frontier", "opening-stage-directory",
  ]);
  const dynamic = frames.filter(({ generatedFrameId, kind }) =>
    generatedFrameId === "openingBodies" || dynamicKinds.has(kind));
  const firstDynamic = dynamic[0]?.start ?? proof.proofLength;
  const directoryWords = frames.filter(({ kind }) => kind === "opening-directory-word").length;
  if (directoryWords % 5 !== 0 || (generated && dynamic.length === 0)) {
    throw new Error("local-word observer proof framing geometry");
  }
  return {
    layout: generated ? "generated-v17" : "experimental-legacy",
    generatedFrameOrder: generated,
    exactPartition: true,
    fixedPrefixBytes: firstDynamic,
    dynamicMixedMerkleBodyBytes: proof.proofLength - firstDynamic,
    oodQm31Values: frames.filter(({ kind }) => kind === "ood-value").length,
    namedRoundNonces: frames.filter(({ kind }) => kind === "round-nonce").length,
    independentFriAlphas: frames.filter(({ kind }) => kind === "fri-alpha").length,
    terminalDirectoryEntries: directoryWords / 5,
    dynamicBodyFrames: dynamic.length,
  };
}

function firstPush(unlockingBytecode: Uint8Array, input: number): Uint8Array {
  const instructions = decodeAuthenticationInstructions(unlockingBytecode);
  if (typeof instructions === "string") {
    throw new Error(`local-word observer unlocking ${input}: ${instructions}`);
  }
  const first = instructions[0];
  if (!first || !("data" in first) || first.data.length < 1) {
    throw new Error(`local-word observer carrier push ${input}`);
  }
  return first.data;
}

/**
 * Adversarially recover the one public proof byte string from serialized
 * transaction inputs. No prover objects, notes, traces, or carrier metadata
 * are trusted by this parser.
 */
export function extractLocalWordProofFromTransaction(
  raw: Uint8Array,
  allocation: V17AffineAllocation,
): Uint8Array {
  validateV17AffineAllocation(allocation);
  const transaction = decodeTransaction(raw);
  if (typeof transaction === "string") {
    throw new Error(`local-word observer transaction: ${transaction}`);
  }
  if (transaction.inputs.length < LOCAL_WORD_CARRIER_INPUTS) {
    throw new Error("local-word observer carrier count");
  }
  const chunks = transaction.inputs.slice(0, LOCAL_WORD_CARRIER_INPUTS).map((input, index) =>
    firstPush(input.unlockingBytecode, index));
  const proof = concatBytes(...chunks);
  const expected = partitionLocalWordProofBytes(proof, allocation);
  if (expected.some((carrier, index) =>
    carrier.chunk.length !== chunks[index]!.length ||
    carrier.chunk.some((byte, offset) => byte !== chunks[index]![offset]))) {
    throw new Error("local-word observer carrier placement");
  }
  return proof;
}

/** Historical bootstrap-envelope replay. Never use this for a final v17 artifact. */
export function extractLegacyLocalWordProofFromTransaction(raw: Uint8Array): Uint8Array {
  return extractLocalWordProofFromTransaction(raw, V17_BOOTSTRAP_AFFINE_ALLOCATION);
}

function ledgerFromProof(
  proof: LocalWordSealedProof,
  context: LocalWordProofContext,
  transactionBytes: number,
  transactionShape: LocalWordObserverLedger["transactionShape"],
  allocation: V17AffineAllocation,
  parameters: LocalWordProofParameters,
): LocalWordObserverLedger {
  const framing = inspectLocalWordProofFraming(proof, parameters);
  const protectedTraceRecovery = auditLocalWordProtectedTraceRecovery(
    proof,
    context,
    parameters,
  );
  const current = proof.matrices.original.indices.length;
  const global = proof.matrices.interactionGlobal.indices.length;
  const oodRank = protectedTraceRecovery.observedValues.oodM31CoordinatesPerColumn;
  const relationAuthentication = LOCAL_WORD_MATRIX_NAMES.reduce(
    (sum, name) => sum + proof.matrices[name].siblings.length,
    0,
  );
  const friAuthentication = proof.fri.layers.reduce(
    (sum, layer) => sum + layer.siblings.length,
    0,
  );
  return {
    proofVersion: proof.version,
    transactionBytes,
    proofBytes: proof.proofLength,
    carrierInputs: LOCAL_WORD_CARRIER_INPUTS,
    carrierUnionExact: true,
    carrierAllocation: {
      status: allocation.status,
      minimumProofBytes: allocation.minimumProofBytes,
      exactOwnershipReplay: true,
    },
    framing,
    transactionShape,
    roots: {
      relationAndAuxiliary: LOCAL_WORD_MATRIX_NAMES.length,
      fri: proof.fri.layers.length,
    },
    directOpenings: {
      currentPoints: current,
      globalPoints: global,
      originalOodQm31Points: protectedTraceRecovery.observedValues.oodQm31PointsPerColumn,
      originalM31Values: current * 34,
      interactionM31Values: current * 56,
      interactionGlobalM31Values: global * 12,
      quotientQm31Values: current,
      friMaskQm31Values: current,
    },
    fri: {
      layerQm31Values: proof.fri.layers.reduce((sum, layer) => sum + layer.values.length, 0),
      finalQm31Coefficients: proof.fri.finalCoefficients.length,
      authenticationNodes: friAuthentication,
    },
    authenticationNodes: relationAuthentication + friAuthentication,
    maskBudget: {
      original: {
        dimensionsPerColumn: 2 ** parameters.relationLog,
        directOpeningEquationsPerColumn: current + oodRank,
      },
      interaction: {
        dimensionsPerColumn: 2 ** parameters.relationLog,
        directOpeningEquationsPerColumn: current + oodRank,
      },
      interactionGlobal: {
        dimensionsPerColumn: 2 ** parameters.relationLog,
        directOpeningEquationsPerColumn: global + oodRank,
      },
      friIsolator: {
        dimensions: parameters.quotientDegreeRows,
        directOpeningEquations: current,
      },
    },
    quotient: {
      decomposition: "none",
      extraWitnessFormsAtQueries: 0,
      reason: "determined by sealed AIR openings",
    },
    protectedTraceRecovery: {
      ...protectedTraceRecovery,
      observedPointsPerOriginalColumn: current,
      privateTraceRows: 2 ** parameters.relationLog,
    },
    claimBoundary: {
      algebraicIop:
        "opening-view non-uniqueness only; complete honest-verifier simulation not claimed",
      badDenominatorDistanceBits: framing.layout === "generated-v17"
        ? "unresolved for v17 relation"
        : "unresolved for v16 relation",
      merkleAndFiatShamir:
        "classical programmable-ROM transcript and soundness model; no complete ZK claim",
      qrom: "unresolved",
    },
  };
}

function analyzeLocalWordObserverTransactionWithAllocation(
  raw: Uint8Array,
  context: LocalWordProofContext,
  allocation: V17AffineAllocation,
  parameters: LocalWordProofParameters,
): LocalWordObserverLedger {
  validateV17AffineAllocation(allocation);
  const proofBytes = extractLocalWordProofFromTransaction(raw, allocation);
  const proof = decodeLocalWordSealedProof(proofBytes, context, parameters);
  const transaction = decodeTransaction(raw);
  if (typeof transaction === "string") {
    throw new Error(`local-word observer transaction: ${transaction}`);
  }
  let publicNullifierPathNodes = 0;
  const infrastructureInputs = proof.profile === 0
    ? transaction.inputs.length - 1
    : transaction.inputs.length;
  if (infrastructureInputs < LOCAL_WORD_CARRIER_INPUTS) {
    throw new Error("local-word observer infrastructure count");
  }
  if (proof.profile !== 0) {
    const data = transaction.outputs[localWordNullifierDataOutputIndex(infrastructureInputs)];
    if (!data) throw new Error("local-word observer nullifier output");
    publicNullifierPathNodes = decodeLocalWordNullifierData(data.lockingBytecode).path.length;
  }
  const profile = proof.profile === 0
    ? "deposit"
    : proof.profile === 1
      ? "withdraw-full"
      : "withdraw-change";
  const edgeOutputIndex = localWordEdgeDataOutputIndex(profile, infrastructureInputs);
  let publicEdgePathNodes = 0;
  let publicCreationHandles: 0 | 1 = 0;
  if (edgeOutputIndex !== undefined) {
    const data = transaction.outputs[edgeOutputIndex];
    if (!data) throw new Error("local-word observer edge output");
    publicEdgePathNodes = decodeLocalWordEdgeData(data.lockingBytecode).path.length;
    publicCreationHandles = 1;
  }
  return ledgerFromProof(proof, context, raw.length, {
    inputs: transaction.inputs.length,
    outputs: transaction.outputs.length,
    publicNullifierPathNodes,
    publicEdgePathNodes,
    publicCreationHandles,
  }, allocation, parameters);
}

/**
 * Complete observer ledger for a final v17 artifact. Final carrier ownership
 * is meaningful only under the exact post-link measured allocation.
 */
export function analyzeLocalWordObserverTransaction(
  raw: Uint8Array,
  context: LocalWordProofContext,
  allocation: V17AffineAllocation,
  parameters: LocalWordProofParameters = LOCAL_WORD_PRODUCTION_PARAMETERS,
): LocalWordObserverLedger {
  validateV17AffineAllocation(allocation);
  if (allocation.status !== "measured") {
    throw new Error("local-word observer final allocation must be measured");
  }
  return analyzeLocalWordObserverTransactionWithAllocation(
    raw,
    context,
    allocation,
    parameters,
  );
}

/** Explicit historical analyzer for bootstrap-partitioned research fixtures. */
export function analyzeLegacyLocalWordObserverTransaction(
  raw: Uint8Array,
  context: LocalWordProofContext,
  parameters: LocalWordProofParameters = LOCAL_WORD_PRODUCTION_PARAMETERS,
): LocalWordObserverLedger {
  return analyzeLocalWordObserverTransactionWithAllocation(
    raw,
    context,
    V17_BOOTSTRAP_AFFINE_ALLOCATION,
    parameters,
  );
}

import {
  concatBytes,
  eq32,
  readU32BE,
  readU32LE,
  writeU32BE,
} from "../../pool/bytes.ts";
import {
  poolLocalBoundaryClaimForWords,
  type PoolLocalBoundaryWord,
} from "../../chain/pool-relation-local-word-boundary.ts";
import { M31 } from "./m31.ts";
import { decodeQm31, encodeQm31, qmEq, type QM31El } from "./qm31.ts";
import { successorTraceOffsetIndex } from "./successor-domain.ts";
import type { SuccessorFriLayerProof, SuccessorFriProof } from "./successor-fri.ts";
import {
  LOCAL_WORD_FRI_LOG_BLOWUP,
  LOCAL_WORD_GRIND_BITS,
  LOCAL_WORD_LDE_LOG,
  LOCAL_WORD_PRODUCTION_PARAMETERS,
  LOCAL_WORD_QUERIES,
  LOCAL_WORD_TRACE_LOG,
  localWordFriFoldCounts,
  localWordFriLayerLogs,
  validateLocalWordProofParameters,
  type LocalWordProofParameters,
} from "./local-word-successor-params.ts";
import {
  LOCAL_WORD_INTERACTION_CHALLENGE_COUNT,
  localWordCompositionTranscript,
  localWordInteractionChallengeValues,
  localWordInteractionTranscript,
  localWordPublicBoundaryTranscript,
  localWordQueryIndices,
  type LocalWordInteractionChallenges,
} from "./local-word-transcript.ts";
import {
  canonicalMerkleFrontier4,
  encodeCanonicalMerkleFrontier4,
} from "./canonical-merkle.ts";
import {
  encodeV17MerkleCutFrontiers,
  maximumV17MerkleOpening,
  v17MerkleCutFrontiers,
  v17MerkleOpeningRoot,
  v17MerkleSchedule,
  v17ProductionMerkleDescriptors,
  type V17MerkleDescriptor,
} from "./v17-merkle.ts";
import {
  planV17ProtocolMerkleStages,
  v17Q44MeasuredMerkleCuts,
  type V17MerklePlan,
} from "../../chain/v17-merkle-planner.ts";
import {
  V17_PROOF_FIXED_PREFIX_BYTES,
  V17_PROOF_FRAMES,
  V17_PROOF_PROTOCOL_ID,
  v17ProofFrame,
  v17ProofFrameOffset,
  type V17GeneratedProofFrameId,
} from "./v17-proof-layout.ts";
import {
  V17_THEOREM_ROUND_IDS,
  type V17TheoremRoundId,
} from "./v17-round-transcript.ts";
import {
  flattenV17FriAlphas,
  replayV17ProofTranscript,
} from "./v17-proof-transcript.ts";
import {
  V17_CONSTRUCTION_GRAPH,
  V17_MATRIX_NAMES,
  type V17MatrixName,
} from "../../construction/v17-graph.ts";

const MAGIC = new TextEncoder().encode("SKLW");
export const LOCAL_WORD_PROOF_VERSION = 17;
export const LOCAL_WORD_PROOF_LENGTH_OFFSET = 4 + 1 + 1 + 32;
/** Graph-generated end of all fixed-width proof frames. */
export const LOCAL_WORD_PROOF_FIXED_PREFIX_BYTES = V17_PROOF_FIXED_PREFIX_BYTES;
export const LOCAL_WORD_PROOF_HEADER_BYTES = LOCAL_WORD_PROOF_LENGTH_OFFSET + 4;
export const LOCAL_WORD_PROOF_MAX_BYTES = V17_CONSTRUCTION_GRAPH.allocation.maximumProofBytes;
export const LOCAL_WORD_FRI_FINAL_LOG_DEGREE = 3;
export const LOCAL_WORD_FRI_LAYERS =
  localWordFriFoldCounts(LOCAL_WORD_PRODUCTION_PARAMETERS).length;
export const LOCAL_WORD_MATRIX_ROW_WIDTHS = [172, 136, 224, 48, 32] as const;
export const LOCAL_WORD_MATRIX_NAMES = V17_MATRIX_NAMES;
export type LocalWordMatrixName = V17MatrixName;
/**
 * Fixed verifier cuts are part of the canonical construction. They are the
 * widest cuts whose measured BCH-VM roles remain below one input's absolute
 * May-2026 operation-cost ceiling at the production query schedule.
 */
export const LOCAL_WORD_MERKLE_FRONTIER_LEVEL = 4;
export const LOCAL_WORD_GLOBAL_MERKLE_FIRST_STAGE_LEVELS = 1;
export const LOCAL_WORD_GLOBAL_MERKLE_STAGE_LEVELS = 2;
export const LOCAL_WORD_FRI_MERKLE_FIRST_STAGE_LEVELS = 1;
export const LOCAL_WORD_FRI_MERKLE_STAGE_LEVELS = 3;
export const LOCAL_WORD_INTERACTION_MERKLE_STAGE_LEVELS = 5;

export type LocalWordMerkleStageGeometry = {
  readonly firstLevel: number;
  readonly levelsPerStage: number;
};

export function localWordMatrixMerkleStageGeometry(
  matrix: LocalWordMatrixName,
): LocalWordMerkleStageGeometry {
  return matrix === "interaction"
    ? { firstLevel: 0, levelsPerStage: LOCAL_WORD_INTERACTION_MERKLE_STAGE_LEVELS }
    : matrix === "interactionGlobal"
      ? {
        firstLevel: LOCAL_WORD_GLOBAL_MERKLE_FIRST_STAGE_LEVELS,
        levelsPerStage: LOCAL_WORD_GLOBAL_MERKLE_STAGE_LEVELS,
      }
      : { firstLevel: LOCAL_WORD_MERKLE_FRONTIER_LEVEL, levelsPerStage: LOCAL_WORD_MERKLE_FRONTIER_LEVEL };
}

export const LOCAL_WORD_FRI_MERKLE_STAGE_GEOMETRY: LocalWordMerkleStageGeometry = {
  firstLevel: LOCAL_WORD_FRI_MERKLE_FIRST_STAGE_LEVELS,
  levelsPerStage: LOCAL_WORD_FRI_MERKLE_STAGE_LEVELS,
};

const MATRIX_LABELS: Readonly<Record<LocalWordMatrixName, string>> = {
  preprocessed: "local-word:preprocessed",
  original: "local-word:original",
  interaction: "local-word:interaction",
  interactionGlobal: "local-word:interaction-global",
  quotientAndFriMask: "local-word:quotient-and-fri-mask",
};

export function localWordV17MatrixMerkleDescriptor(
  matrix: LocalWordMatrixName,
  parameters: LocalWordProofParameters = LOCAL_WORD_PRODUCTION_PARAMETERS,
): V17MerkleDescriptor {
  validateLocalWordProofParameters(parameters);
  const base = v17ProductionMerkleDescriptors().matrices[matrix];
  return { ...base, logRows: parameters.evalLog };
}

export function localWordV17FriMerkleDescriptor(
  layer: number,
  parameters: LocalWordProofParameters = LOCAL_WORD_PRODUCTION_PARAMETERS,
): V17MerkleDescriptor {
  validateLocalWordProofParameters(parameters);
  const logs = localWordFriLayerLogs(parameters);
  const folds = localWordFriFoldCounts(parameters);
  if (!Number.isInteger(layer) || layer < 0 || layer >= logs.length) {
    throw new Error("local-word v17 FRI descriptor");
  }
  return {
    shape: folds[layer] === 2 ? "quartet-first" : "binary",
    label: `fri:layer:${layer}`,
    logRows: logs[layer]!,
    rowWidth: 16,
  };
}

export function localWordV17MerklePlan(args: {
  readonly matrix?: LocalWordMatrixName;
  readonly friLayer?: number;
  readonly parameters?: LocalWordProofParameters;
}): V17MerklePlan {
  const parameters = args.parameters ?? LOCAL_WORD_PRODUCTION_PARAMETERS;
  if ((args.matrix === undefined) === (args.friLayer === undefined)) {
    throw new Error("local-word v17 Merkle plan kind");
  }
  if (args.matrix !== undefined) {
    return planV17ProtocolMerkleStages({
      descriptor: localWordV17MatrixMerkleDescriptor(args.matrix, parameters),
      opening: {
        openedLeaves: parameters.fri.queries * (args.matrix === "interactionGlobal" ? 2 : 1),
      },
      kind: "matrix",
    });
  }
  return planV17ProtocolMerkleStages({
    descriptor: localWordV17FriMerkleDescriptor(args.friLayer!, parameters),
    opening: { completeFirstGroups: parameters.fri.queries },
    kind: "fri",
  });
}

/**
 * Canonical serialized frontier language. Level zero is not a planner choice:
 * it is the checked join between the transcript/rank schedule, raw opening
 * rows, and all parent-stage Merkle roles. The measured planner chooses only
 * the internal parent cuts which follow it.
 */
export function localWordV17MerkleCuts(args: {
  readonly matrix?: LocalWordMatrixName;
  readonly friLayer?: number;
  readonly parameters?: LocalWordProofParameters;
}): readonly number[] {
  const parameters = args.parameters ?? LOCAL_WORD_PRODUCTION_PARAMETERS;
  const descriptor = args.matrix !== undefined
    ? localWordV17MatrixMerkleDescriptor(args.matrix, parameters)
    : localWordV17FriMerkleDescriptor(args.friLayer!, parameters);
  const parentCuts = parameters.fri.queries === V17_CONSTRUCTION_GRAPH.foundation.queries &&
    parameters.evalLog === V17_CONSTRUCTION_GRAPH.foundation.evaluationLog
    ? v17Q44MeasuredMerkleCuts(descriptor)
    : localWordV17MerklePlan(args).cuts;
  if (parentCuts.some((bits) => bits <= 0)) {
    throw new Error("local-word v17 parent cut collides with leaf frontier");
  }
  return [0, ...parentCuts];
}

export type LocalWordProofStaticOffsets = {
  readonly protocolId: number;
  readonly totalLength: number;
  readonly publicInverses: number;
  readonly publicClaimedSum: number;
  readonly matrixRoots: number;
  readonly friRoots: number;
  readonly finalCoefficients: number;
  readonly grindNonce: number;
  readonly interactionChallenges: number;
  readonly interactionDigest: number;
  readonly constraintAlpha: number;
  readonly compositionDigest: number;
  readonly oodValues: number;
  readonly batchBeta: number;
  readonly batchDigest: number;
  readonly friAlphas: number;
  readonly friMidDigest: number;
  readonly friRootsDigest: number;
  readonly queryDigest: number;
  readonly roundNonces: number;
  readonly queries: number;
  readonly currentIndices: number;
  readonly currentRanks: number;
  readonly globalCurrentRanks: number;
  readonly globalPreviousRanks: number;
  readonly friCosetRanks: number;
  readonly openingDirectory: number;
  readonly openingBodies: number;
  readonly friLayerCount: number;
  readonly finalCoefficientCount: number;
};

/** Single authoritative layout for every fixed-width proof frame. */
export function localWordProofStaticOffsets(
  publicWordCount: number,
  parameters: LocalWordProofParameters = LOCAL_WORD_PRODUCTION_PARAMETERS,
): LocalWordProofStaticOffsets {
  validateLocalWordProofParameters(parameters);
  if (!Number.isInteger(publicWordCount) || publicWordCount < 1 || publicWordCount > 1024) {
    throw new Error("local-word proof static offsets public words");
  }
  const friLayerCount = localWordFriFoldCounts(parameters).length;
  const finalCoefficientCount = 2 ** parameters.fri.finalLogDegree;
  const foundation = V17_CONSTRUCTION_GRAPH.foundation;
  const productionGeometry = publicWordCount === 8 &&
    parameters.relationLog === foundation.relationLog &&
    parameters.evalLog === foundation.evaluationLog &&
    Math.log2(parameters.quotientDegreeRows) === foundation.quotientDegreeLog &&
    parameters.fri.logBlowup === foundation.friLogBlowup &&
    parameters.fri.finalLogDegree === foundation.finalLogDegree &&
    parameters.fri.queries === foundation.queries &&
    friLayerCount === foundation.friFoldLogs.length;
  if (productionGeometry) {
    return {
      protocolId: v17ProofFrameOffset("protocolId"),
      totalLength: v17ProofFrameOffset("totalLength"),
      publicInverses: v17ProofFrameOffset("publicInverses"),
      publicClaimedSum: v17ProofFrameOffset("publicClaimedSum"),
      matrixRoots: v17ProofFrameOffset("matrixRoot:preprocessed"),
      friRoots: v17ProofFrameOffset("friRoot:0"),
      finalCoefficients: v17ProofFrameOffset("finalCoefficients"),
      grindNonce: v17ProofFrameOffset("roundNonce:fri:query"),
      interactionChallenges: v17ProofFrameOffset("interactionChallenges"),
      interactionDigest: v17ProofFrameOffset("interactionDigest"),
      constraintAlpha: v17ProofFrameOffset("constraintAlpha"),
      compositionDigest: v17ProofFrameOffset("compositionDigest"),
      oodValues: v17ProofFrameOffset("oodValues"),
      batchBeta: v17ProofFrameOffset("batchBeta"),
      batchDigest: v17ProofFrameOffset("batchDigest"),
      friAlphas: v17ProofFrameOffset("friAlpha:0:0"),
      friMidDigest: v17ProofFrameOffset("friMidDigest"),
      friRootsDigest: v17ProofFrameOffset("friRootsDigest"),
      queryDigest: v17ProofFrameOffset("queryDigest"),
      roundNonces: v17ProofFrameOffset("roundNonce:air:logup"),
      queries: v17ProofFrameOffset("queries"),
      currentIndices: v17ProofFrameOffset("currentIndices"),
      currentRanks: v17ProofFrameOffset("currentRanks"),
      globalCurrentRanks: v17ProofFrameOffset("globalCurrentRanks"),
      globalPreviousRanks: v17ProofFrameOffset("globalPreviousRanks"),
      friCosetRanks: v17ProofFrameOffset("friCosetRanks"),
      openingDirectory: v17ProofFrameOffset("openingDirectory"),
      openingBodies: V17_PROOF_FIXED_PREFIX_BYTES,
      friLayerCount,
      finalCoefficientCount,
    };
  }

  // Explicitly non-production geometry retained for small differential tests.
  const protocolId = 6;
  const totalLength = LOCAL_WORD_PROOF_LENGTH_OFFSET;
  const publicInverses = LOCAL_WORD_PROOF_HEADER_BYTES;
  const publicClaimedSum = publicInverses + publicWordCount * 16;
  const matrixRoots = publicClaimedSum + 16;
  const friRoots = matrixRoots + LOCAL_WORD_MATRIX_NAMES.length * 32;
  const finalCoefficients = friRoots + friLayerCount * 32;
  const grindNonce = finalCoefficients + finalCoefficientCount * 16;
  const interactionChallenges = grindNonce + 4;
  const interactionDigest = interactionChallenges + LOCAL_WORD_INTERACTION_CHALLENGE_COUNT * 16;
  const constraintAlpha = interactionDigest + 32;
  const compositionDigest = constraintAlpha + 16;
  const oodValues = compositionDigest + 32;
  const batchBeta = oodValues;
  const batchDigest = batchBeta + 16;
  const friAlphas = batchDigest + 32;
  const friMidDigest = friAlphas + friLayerCount * 16;
  const friRootsDigest = friMidDigest + 32;
  const queryDigest = friRootsDigest + 32;
  const queries = queryDigest + 32;
  const currentIndices = queries + parameters.fri.queries * 4;
  const currentRanks = currentIndices + parameters.fri.queries * 4;
  const globalCurrentRanks = currentRanks + parameters.fri.queries;
  const globalPreviousRanks = globalCurrentRanks + parameters.fri.queries;
  const friCosetRanks = globalPreviousRanks + parameters.fri.queries;
  const openingDirectory = friCosetRanks + friLayerCount * parameters.fri.queries;
  const openingBodies = openingDirectory +
    (LOCAL_WORD_MATRIX_NAMES.length + friLayerCount) * 20;
  return {
    protocolId,
    totalLength,
    publicInverses,
    publicClaimedSum,
    matrixRoots,
    friRoots,
    finalCoefficients,
    grindNonce,
    interactionChallenges,
    interactionDigest,
    constraintAlpha,
    compositionDigest,
    oodValues,
    batchBeta,
    batchDigest,
    friAlphas,
    friMidDigest,
    friRootsDigest,
    queryDigest,
    roundNonces: grindNonce,
    queries,
    currentIndices,
    currentRanks,
    globalCurrentRanks,
    globalPreviousRanks,
    friCosetRanks,
    openingDirectory,
    openingBodies,
    friLayerCount,
    finalCoefficientCount,
  };
}

export type LocalWordMatrixOpening = {
  readonly root: Uint8Array;
  readonly rowWidth: number;
  readonly indices: readonly number[];
  readonly rows: readonly Uint8Array[];
  readonly siblings: readonly Uint8Array[];
};

/**
 * One transcript manifest for stateless VM partitioning. Every value is
 * re-derived by a dedicated transcript role before relation roles consume it.
 */
export type LocalWordTranscriptManifest = {
  readonly interactionChallenges: readonly QM31El[];
  readonly interactionDigest: Uint8Array;
  readonly constraintAlpha: QM31El;
  readonly compositionDigest: Uint8Array;
  readonly batchBeta: QM31El;
  readonly batchDigest: Uint8Array;
  readonly friAlphas: readonly QM31El[];
  readonly friMidDigest: Uint8Array;
  readonly friRootsDigest: Uint8Array;
  readonly queryDigest: Uint8Array;
};

export type LocalWordSealedProof = {
  readonly version: number;
  readonly profile: number;
  /** Graph-generated protocol identity serialized in the proof header. */
  readonly protocolId: Uint8Array;
  readonly proofLength: number;
  readonly publicBoundaryInverses: readonly QM31El[];
  /** Public sum of the checked inverses; one VM role owns this derived cache. */
  readonly publicBoundaryClaimedSum: QM31El;
  readonly matrices: Readonly<Record<LocalWordMatrixName, LocalWordMatrixOpening>>;
  readonly fri: SuccessorFriProof;
  readonly transcriptManifest: LocalWordTranscriptManifest;
  /** V17 Protocol-4 claims; required by production geometry. */
  readonly oodValues?: readonly QM31El[];
  /** Fourteen u32 nonces in V17_THEOREM_ROUND_IDS order. */
  readonly roundNonces?: readonly number[];
  /** Transcript-derived and serialized once as a VM-checked manifest. */
  readonly queries: readonly number[];
};

export type LocalWordProofContext = {
  readonly profile: number;
  readonly transcriptInitial: Uint8Array;
  readonly constructionDescriptor: Uint8Array;
  readonly publicWords: readonly PoolLocalBoundaryWord[];
  readonly expectedPreprocessedRoot: Uint8Array;
};

export type LocalWordProofFrame = {
  readonly kind:
    | "header"
    | "magic"
    | "proof-version"
    | "profile"
    | "protocol-id"
    | "total-length"
    | "public-inverse"
    | "public-claimed-sum"
    | "matrix-root"
    | "fri-root"
    | "fri-final"
    | "grind-nonce"
    | "interaction-challenge"
    | "interaction-digest"
    | "constraint-alpha"
    | "composition-digest"
    | "ood-value"
    | "batch-beta"
    | "batch-digest"
    | "fri-alpha"
    | "fri-mid-digest"
    | "fri-roots-digest"
    | "round-nonce"
    | "query-digest"
    | "query"
    | "current-index"
    | "current-rank"
    | "global-current-rank"
    | "global-previous-rank"
    | "fri-coset-rank"
    | "opening-directory-word"
    | "opening-stage-directory"
    | "opening-index"
    | "matrix-row"
    | "matrix-sibling"
    | "matrix-frontier"
    | "fri-value"
    | "fri-sibling"
    | "fri-frontier";
  readonly start: number;
  readonly end: number;
  readonly matrix?: LocalWordMatrixName;
  readonly layer?: number;
  readonly item?: number;
  /** Present for production v17; dynamic-body items use `openingBodies`. */
  readonly generatedFrameId?: V17GeneratedProofFrameId | "openingBodies";
  readonly round?: V17TheoremRoundId;
};

class Cursor {
  offset = 0;
  constructor(readonly bytes: Uint8Array) {}

  take(count: number): Uint8Array {
    if (!Number.isSafeInteger(count) || count < 0 || this.offset + count > this.bytes.length) {
      throw new Error("truncated local-word proof");
    }
    const result = this.bytes.slice(this.offset, this.offset + count);
    this.offset += count;
    return result;
  }

  u8(): number {
    return this.take(1)[0]!;
  }

  u32(): number {
    const start = this.offset;
    this.take(4);
    return readU32BE(this.bytes, start);
  }

  qm31(): QM31El {
    return decodeQm31(this.take(16));
  }
}

function takeGeneratedFrame(
  cursor: Cursor,
  id: V17GeneratedProofFrameId,
): Uint8Array {
  const frame = v17ProofFrame(id);
  if (cursor.offset !== frame.offsetBytes) {
    throw new Error(`local-word v17 generated frame order ${id}`);
  }
  return cursor.take(frame.totalBytes);
}

function decodeQm31Items(bytes: Uint8Array, count: number): QM31El[] {
  if (bytes.length !== count * 16) throw new Error("local-word QM31 frame width");
  return Array.from({ length: count }, (_, item) =>
    decodeQm31(bytes.slice(item * 16, (item + 1) * 16)));
}

function decodeU32Items(bytes: Uint8Array, count: number): number[] {
  if (bytes.length !== count * 4) throw new Error("local-word u32 frame width");
  return Array.from({ length: count }, (_, item) => readU32BE(bytes, item * 4));
}

function equal(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((byte, index) => byte === right[index]);
}

function sortedUnique(values: readonly number[]): number[] {
  return [...new Set(values)].sort((left, right) => left - right);
}

export function localWordCanonicalSiblingCount(
  indices: readonly number[],
  rowCount: number,
): number {
  const logRows = Math.log2(rowCount);
  if (!Number.isSafeInteger(rowCount) || rowCount < 4 || !Number.isInteger(logRows) || logRows % 2 !== 0 ||
    indices.length < 1 || indices.some((index) => !Number.isSafeInteger(index) || index < 0 || index >= rowCount) ||
    indices.some((index, position) => position > 0 && indices[position - 1]! >= index)) {
    throw new Error("local-word multiproof indices");
  }
  let frontier = [...indices];
  let siblings = 0;
  for (let level = 0; level < logRows / 2; level += 1) {
    const present = new Set(frontier);
    const parents = sortedUnique(frontier.map((index) => index >>> 2));
    for (const parent of parents) {
      for (let child = 0; child < 4; child += 1) {
        if (!present.has(parent * 4 + child)) siblings += 1;
      }
    }
    frontier = parents;
  }
  if (frontier.length !== 1 || frontier[0] !== 0) throw new Error("local-word multiproof frontier");
  return siblings;
}

export type LocalWordMerkleFrontierSchedule = {
  readonly level: number;
  readonly indices: readonly number[];
  readonly siblingCount: number;
};

/** Fixed verifier-key cuts; short ladders remain unsplit. */
export function localWordMerkleFrontierSchedules(
  indices: readonly number[],
  rowCount: number,
  geometry: number | LocalWordMerkleStageGeometry = LOCAL_WORD_MERKLE_FRONTIER_LEVEL,
): readonly LocalWordMerkleFrontierSchedule[] {
  // Reuse the full validator before deriving the prefix schedule.
  localWordCanonicalSiblingCount(indices, rowCount);
  const height = Math.log2(rowCount) / 2;
  const firstLevel = typeof geometry === "number" ? geometry : geometry.firstLevel;
  const levelsPerStage = typeof geometry === "number" ? geometry : geometry.levelsPerStage;
  if (!Number.isInteger(firstLevel) || firstLevel < 0 || firstLevel >= height ||
    !Number.isInteger(levelsPerStage) || levelsPerStage < 1) {
    throw new Error("local-word Merkle stage height");
  }
  let frontier = [...indices];
  let siblingCount = 0;
  const schedules: LocalWordMerkleFrontierSchedule[] = [];
  let nextCut = firstLevel;
  if (nextCut === 0) {
    schedules.push({ level: 0, indices: [...frontier], siblingCount: 0 });
    nextCut = levelsPerStage;
  }
  for (let current = 0; current < height; current += 1) {
    const present = new Set(frontier);
    const parents = sortedUnique(frontier.map((index) => index >>> 2));
    for (const parent of parents) {
      for (let child = 0; child < 4; child += 1) {
        if (!present.has(parent * 4 + child)) siblingCount += 1;
      }
    }
    frontier = parents;
    const level = current + 1;
    if (level < height && level === nextCut) {
      schedules.push({ level, indices: [...frontier], siblingCount });
      nextCut += levelsPerStage;
    }
  }
  return schedules;
}

export function localWordMerkleFrontierLevels(
  treeLevels: number,
  geometry: LocalWordMerkleStageGeometry,
): readonly number[] {
  if (!Number.isInteger(treeLevels) || treeLevels < 1 ||
    !Number.isInteger(geometry.firstLevel) || geometry.firstLevel < 0 ||
    geometry.firstLevel >= treeLevels || !Number.isInteger(geometry.levelsPerStage) ||
    geometry.levelsPerStage < 1) {
    throw new Error("local-word Merkle frontier levels");
  }
  const levels: number[] = [];
  for (let level = geometry.firstLevel; level < treeLevels; level += geometry.levelsPerStage) {
    levels.push(level);
  }
  return levels;
}

/** Generated v17 cut schedule; `level` is the number of consumed domain bits. */
export function localWordV17MerkleFrontierSchedules(
  descriptor: V17MerkleDescriptor,
  indices: readonly number[],
  cuts: readonly number[],
): readonly LocalWordMerkleFrontierSchedule[] {
  const schedule = v17MerkleSchedule(descriptor, indices);
  const byBits = new Map<number, { readonly indices: readonly number[]; readonly siblingCount: number }>();
  let siblingCount = 0;
  byBits.set(0, { indices: schedule.indices, siblingCount });
  for (const level of schedule.levels) {
    siblingCount += level.siblingIndices.length;
    byBits.set(level.nextConsumedBits, { indices: level.parentIndices, siblingCount });
  }
  return cuts.map((level) => {
    const frontier = byBits.get(level);
    if (frontier === undefined || level >= descriptor.logRows) {
      throw new Error("local-word v17 Merkle cut");
    }
    return { level, indices: [...frontier.indices], siblingCount: frontier.siblingCount };
  });
}

export function localWordFriOpeningIndices(
  queries: readonly number[],
  foldCounts: readonly number[],
): number[][] {
  let positions = [...queries];
  return foldCounts.map((folds) => {
    const arity = 2 ** folds;
    const opened = sortedUnique(positions.flatMap((index) => {
      const base = index & ~(arity - 1);
      return Array.from({ length: arity }, (_, offset) => base + offset);
    }));
    positions = sortedUnique(positions.map((index) => index >>> folds));
    return opened;
  });
}

function maximumRadix4SiblingCount(openedNodes: number, treeLevels: number): number {
  if (!Number.isSafeInteger(openedNodes) || openedNodes < 1 ||
    !Number.isInteger(treeLevels) || treeLevels < 1 || openedNodes > 4 ** treeLevels) {
    throw new Error("local-word maximum Merkle geometry");
  }
  let frontier = openedNodes;
  let siblings = 0;
  for (let level = 0; level < treeLevels; level += 1) {
    const parents = Math.min(frontier, 4 ** (treeLevels - level - 1));
    siblings += 4 * parents - frontier;
    frontier = parents;
  }
  if (frontier !== 1) throw new Error("local-word maximum Merkle root");
  return siblings;
}

function maximumRadix4FrontierNodes(
  openedNodes: number,
  treeLevels: number,
  geometry: LocalWordMerkleStageGeometry,
): number {
  return localWordMerkleFrontierLevels(treeLevels, geometry).reduce(
    (sum, level) => sum + Math.min(openedNodes, 4 ** (treeLevels - level)),
    0,
  );
}

/** Exact all-transcript upper bound under the graph-derived v17 language. */
export function localWordMaximumCanonicalProofBytes(
  publicWordCount: number,
  parameters: LocalWordProofParameters = LOCAL_WORD_PRODUCTION_PARAMETERS,
): number {
  validateLocalWordProofParameters(parameters);
  const queryCount = parameters.fri.queries;
  let bytes = localWordProofStaticOffsets(publicWordCount, parameters).openingBodies;
  LOCAL_WORD_MATRIX_NAMES.forEach((matrix, index) => {
    const opened = matrix === "interactionGlobal" ? 2 * queryCount : queryCount;
    const descriptor = localWordV17MatrixMerkleDescriptor(matrix, parameters);
    const cuts = localWordV17MerkleCuts({ matrix, parameters });
    const maximum = maximumV17MerkleOpening(descriptor, { openedLeaves: opened });
    const byBits = new Map<number, number>([[0, maximum.frontierNodes[0]!]]);
    maximum.levels.forEach((level, levelIndex) =>
      byBits.set(level.nextConsumedBits, maximum.frontierNodes[levelIndex + 1]!));
    bytes += opened * LOCAL_WORD_MATRIX_ROW_WIDTHS[index]! +
      maximum.siblingCount * 32 + cuts.length * 12 +
      cuts.reduce((sum, bits) => sum + byBits.get(bits)! * 36, 0);
  });
  localWordFriFoldCounts(parameters).forEach((foldCount, round) => {
    const descriptor = localWordV17FriMerkleDescriptor(round, parameters);
    const cuts = localWordV17MerkleCuts({ friLayer: round, parameters });
    const maximum = maximumV17MerkleOpening(descriptor, { completeFirstGroups: queryCount });
    const byBits = new Map<number, number>([[0, maximum.frontierNodes[0]!]]);
    maximum.levels.forEach((level, levelIndex) =>
      byBits.set(level.nextConsumedBits, maximum.frontierNodes[levelIndex + 1]!));
    bytes += queryCount * 2 ** foldCount * 16 + maximum.siblingCount * 32 +
      cuts.length * 12 +
      cuts.reduce((sum, bits) => sum + byBits.get(bits)! * 36, 0);
  });
  if (!Number.isSafeInteger(bytes) || bytes > LOCAL_WORD_PROOF_MAX_BYTES) {
    throw new Error(`local-word maximum proof bytes ${bytes}/${LOCAL_WORD_PROOF_MAX_BYTES}`);
  }
  return bytes;
}

export function localWordOpeningSchedules(
  queries: readonly number[],
  parameters?: LocalWordProofParameters,
): {
  readonly current: readonly number[];
  readonly global: readonly number[];
  readonly fri: readonly (readonly number[])[];
};
export function localWordOpeningSchedules(
  queries: readonly number[],
  parameters: LocalWordProofParameters = LOCAL_WORD_PRODUCTION_PARAMETERS,
): {
  readonly current: readonly number[];
  readonly global: readonly number[];
  readonly fri: readonly (readonly number[])[];
} {
  validateLocalWordProofParameters(parameters);
  if (queries.length !== parameters.fri.queries || new Set(queries).size !== queries.length ||
    queries.some((index) => !Number.isSafeInteger(index) || index < 0 || index >= 2 ** parameters.evalLog)) {
    throw new Error("local-word query schedule");
  }
  const current = sortedUnique(queries);
  const global = sortedUnique(current.flatMap((index) => [
    index,
    successorTraceOffsetIndex(index, parameters.relationLog, parameters.evalLog, -1),
  ]));
  const foldCounts = localWordFriFoldCounts(parameters);
  const fri = localWordFriOpeningIndices(current, foldCounts);
  if (global.length !== 2 * current.length || fri.some(
    (indices, round) => indices.length !== current.length * 2 ** foldCounts[round]!,
  )) {
    throw new Error("local-word opening schedule collision");
  }
  return {
    current,
    global,
    fri,
  };
}

export type LocalWordOpeningDirectoryEntry = {
  readonly indicesStart: number;
  readonly rowsStart: number;
  readonly siblingsStart: number;
  readonly stageDirectoryStart: number;
  readonly end: number;
  readonly frontiers: readonly {
    readonly level: number;
    readonly siblingCut: number;
    readonly start: number;
    readonly end: number;
  }[];
};

export type LocalWordProofDirectory = {
  readonly currentIndices: readonly number[];
  readonly currentRanks: readonly number[];
  readonly globalCurrentRanks: readonly number[];
  readonly globalPreviousRanks: readonly number[];
  readonly friCosetRanks: readonly (readonly number[])[];
  readonly openings: readonly LocalWordOpeningDirectoryEntry[];
  readonly bytes: Uint8Array;
};

/**
 * Compact checked ownership map. Ranks point from transcript-order queries to
 * unique sorted rows; opening entries partition every body byte exactly once.
 */
export function localWordProofDirectory(
  queries: readonly number[],
  publicWordCount: number,
  parameters: LocalWordProofParameters = LOCAL_WORD_PRODUCTION_PARAMETERS,
): LocalWordProofDirectory {
  const offsets = localWordProofStaticOffsets(publicWordCount, parameters);
  const schedules = localWordOpeningSchedules(queries, parameters);
  const rankMap = (indices: readonly number[]): Map<number, number> =>
    new Map(indices.map((index, rank) => [index, rank]));
  const rank = (map: ReadonlyMap<number, number>, index: number, label: string): number => {
    const value = map.get(index);
    if (value === undefined || value > 0xff) throw new Error(`local-word ${label} rank`);
    return value;
  };
  const currentMap = rankMap(schedules.current);
  const globalMap = rankMap(schedules.global);
  const currentRanks = queries.map((query) => rank(currentMap, query, "current"));
  const predecessors = queries.map((query) => successorTraceOffsetIndex(
    query,
    parameters.relationLog,
    parameters.evalLog,
    -1,
  ));
  const globalCurrentRanks = queries.map((query) => rank(globalMap, query, "global current"));
  const globalPreviousRanks = predecessors.map((previous) => rank(globalMap, previous, "global previous"));
  const foldCounts = localWordFriFoldCounts(parameters);
  let completedFolds = 0;
  const friCosetRanks = schedules.fri.map((indices, round) => {
    const map = rankMap(indices);
    const arity = 2 ** foldCounts[round]!;
    const ranks = queries.map((query) => rank(
      map,
      (query >>> completedFolds) & ~(arity - 1),
      "FRI coset",
    ));
    completedFolds += foldCounts[round]!;
    return ranks;
  });
  const openings: LocalWordOpeningDirectoryEntry[] = [];
  let cursor = offsets.openingBodies;
  const opening = (
    indices: readonly number[],
    descriptor: V17MerkleDescriptor,
    cuts: readonly number[],
  ): void => {
    const siblingCount = v17MerkleSchedule(descriptor, indices).siblingCount;
    const frontiers = localWordV17MerkleFrontierSchedules(descriptor, indices, cuts);
    const indicesStart = cursor;
    const rowsStart = indicesStart;
    const siblingsStart = rowsStart + indices.length * descriptor.rowWidth;
    const stageDirectoryStart = siblingsStart + siblingCount * 32;
    let frontierCursor = stageDirectoryStart + frontiers.length * 12;
    const directoryFrontiers = frontiers.map((frontier) => {
      const start = frontierCursor;
      frontierCursor += frontier.indices.length * 36;
      return {
        level: frontier.level,
        siblingCut: siblingsStart + frontier.siblingCount * 32,
        start,
        end: frontierCursor,
      };
    });
    const end = frontierCursor;
    openings.push({ indicesStart, rowsStart, siblingsStart, stageDirectoryStart, end,
      frontiers: directoryFrontiers });
    cursor = end;
  };
  LOCAL_WORD_MATRIX_NAMES.forEach((matrix) => opening(
    matrix === "interactionGlobal" ? schedules.global : schedules.current,
    localWordV17MatrixMerkleDescriptor(matrix, parameters),
    localWordV17MerkleCuts({ matrix, parameters }),
  ));
  schedules.fri.forEach((indices, round) => opening(
    indices,
    localWordV17FriMerkleDescriptor(round, parameters),
    localWordV17MerkleCuts({ friLayer: round, parameters }),
  ));
  const rankBytes = Uint8Array.from([
    ...currentRanks,
    ...globalCurrentRanks,
    ...globalPreviousRanks,
    ...friCosetRanks.flat(),
  ]);
  const entryBytes = openings.flatMap((entry) => [
    writeU32BE(entry.indicesStart),
    writeU32BE(entry.rowsStart),
    writeU32BE(entry.siblingsStart),
    writeU32BE(entry.stageDirectoryStart),
    writeU32BE(entry.end),
  ]);
  const bytes = concatBytes(rankBytes, ...entryBytes);
  if (bytes.length !== offsets.openingBodies - offsets.currentRanks) {
    throw new Error("local-word proof directory width");
  }
  return {
    currentIndices: schedules.current,
    currentRanks,
    globalCurrentRanks,
    globalPreviousRanks,
    friCosetRanks,
    openings,
    bytes,
  };
}

function matrixOpenings(proof: LocalWordSealedProof): readonly LocalWordMatrixOpening[] {
  return LOCAL_WORD_MATRIX_NAMES.map((name) => proof.matrices[name]);
}

function openingFrontierBundle(
  descriptor: V17MerkleDescriptor,
  indices: readonly number[],
  rows: readonly Uint8Array[],
  siblings: readonly Uint8Array[],
  cuts: readonly number[],
  entry: LocalWordOpeningDirectoryEntry,
): Uint8Array {
  const schedules = localWordV17MerkleFrontierSchedules(descriptor, indices, cuts);
  if (entry.frontiers.length !== schedules.length) {
    throw new Error("local-word Merkle frontier directory");
  }
  const frontiers = v17MerkleCutFrontiers({
    descriptor,
    rows: indices.map((index, position) => ({ index, raw: rows[position]! })),
    siblings,
    cutBits: cuts,
  });
  const blobs = schedules.map((schedule, item) => {
    const frontier = frontiers[item]!;
    const expected = entry.frontiers[item]!;
    const bytes = encodeV17MerkleCutFrontiers([frontier]);
    if (frontier.consumedBits !== schedule.level ||
      frontier.nodes.some(({ index }, position) => index !== schedule.indices[position]) ||
      expected.level !== schedule.level ||
      expected.siblingCut !== entry.siblingsStart + schedule.siblingCount * 32 ||
      expected.end - expected.start !== bytes.length) {
      throw new Error("local-word Merkle frontier schedule");
    }
    return bytes;
  });
  return concatBytes(
    ...entry.frontiers.flatMap((frontier) => [
      writeU32BE(frontier.siblingCut),
      writeU32BE(frontier.start),
      writeU32BE(frontier.end),
    ]),
    ...blobs,
  );
}

function validateRoot(root: Uint8Array, label: string): void {
  if (root.length !== 32) throw new Error(`${label} root width`);
}

function validateMatrix(
  opening: LocalWordMatrixOpening,
  expectedRoot: Uint8Array,
  descriptor: V17MerkleDescriptor,
  indices: readonly number[],
): void {
  validateRoot(opening.root, "local-word matrix");
  if (!eq32(opening.root, expectedRoot) || opening.rowWidth !== descriptor.rowWidth ||
    opening.indices.length !== indices.length || opening.indices.some((index, at) => index !== indices[at]) ||
    opening.rows.length !== indices.length || opening.rows.some((row) => row.length !== descriptor.rowWidth) ||
    opening.rows.some((row) => Array.from({ length: descriptor.rowWidth / 4 }, (_, limb) =>
      BigInt(readU32LE(row, limb * 4))).some((value) => value >= M31)) ||
    opening.siblings.length !== v17MerkleSchedule(descriptor, indices).siblingCount ||
    opening.siblings.some((sibling) => sibling.length !== 32)) {
    throw new Error("local-word matrix opening shape");
  }
  const root = v17MerkleOpeningRoot({
    descriptor,
    rows: indices.map((index, position) => ({ index, raw: opening.rows[position]! })),
    siblings: opening.siblings,
  });
  if (!eq32(root, expectedRoot)) throw new Error("local-word matrix Merkle root");
}

function validateTranscriptManifest(
  manifest: LocalWordTranscriptManifest,
  friLayers: number,
  production: boolean,
): void {
  const digests = [
    manifest.interactionDigest,
    manifest.compositionDigest,
    manifest.batchDigest,
    manifest.friMidDigest,
    manifest.friRootsDigest,
    manifest.queryDigest,
  ];
  const friChallengeCount = production
    ? V17_CONSTRUCTION_GRAPH.foundation.friFoldChallengeCounts.reduce((sum, count) => sum + count, 0)
    : friLayers;
  if (manifest.interactionChallenges.length !== LOCAL_WORD_INTERACTION_CHALLENGE_COUNT ||
    manifest.friAlphas.length !== friChallengeCount || digests.some((digest) => digest.length !== 32)) {
    throw new Error("local-word transcript manifest shape");
  }
  [
    ...manifest.interactionChallenges,
    manifest.constraintAlpha,
    manifest.batchBeta,
    ...manifest.friAlphas,
  ].forEach(encodeQm31);
}

/**
 * Canonical dual codec: graph-generated v17 fixed frames followed by one
 * index-free mixed-Merkle body, or the frozen small-geometry legacy layout.
 */
export function encodeLocalWordSealedProof(
  proof: LocalWordSealedProof,
  parameters: LocalWordProofParameters = LOCAL_WORD_PRODUCTION_PARAMETERS,
): Uint8Array {
  validateLocalWordProofParameters(parameters);
  const layers = localWordFriFoldCounts(parameters).length;
  const rowCount = 2 ** parameters.evalLog;
  if (proof.version !== LOCAL_WORD_PROOF_VERSION || proof.profile < 0 || proof.profile > 2 ||
    proof.protocolId.length !== 32 || proof.publicBoundaryInverses.length < 1 ||
    proof.publicBoundaryInverses.length > 1024 || proof.queries.length !== parameters.fri.queries ||
    proof.fri.layers.length !== layers ||
    proof.fri.finalCoefficients.length !== 2 ** parameters.fri.finalLogDegree) {
    throw new Error("local-word proof shape");
  }
  encodeQm31(proof.publicBoundaryClaimedSum);
  const production = localWordProofStaticOffsets(
    proof.publicBoundaryInverses.length,
    parameters,
  ).openingBodies === V17_PROOF_FIXED_PREFIX_BYTES;
  validateTranscriptManifest(proof.transcriptManifest, layers, production);
  if (production && (!proof.oodValues || proof.oodValues.length !== 98 ||
    !proof.roundNonces || proof.roundNonces.length !== V17_THEOREM_ROUND_IDS.length ||
    proof.roundNonces.some((nonce) => !Number.isSafeInteger(nonce) || nonce < 0 || nonce > 0xffff_ffff) ||
    proof.fri.grindNonce !== proof.roundNonces.at(-1) ||
    !eq32(proof.protocolId, V17_PROOF_PROTOCOL_ID))) {
    throw new Error("local-word v17 theorem manifest shape");
  }
  const schedules = localWordOpeningSchedules(proof.queries, parameters);
  const directory = localWordProofDirectory(
    proof.queries,
    proof.publicBoundaryInverses.length,
    parameters,
  );
  const openings = matrixOpenings(proof);
  openings.forEach((opening, index) => validateMatrix(
    opening,
    opening.root,
    localWordV17MatrixMerkleDescriptor(LOCAL_WORD_MATRIX_NAMES[index]!, parameters),
    index === 3 ? schedules.global : schedules.current,
  ));
  proof.fri.layers.forEach((layer, round) => {
    const expected = schedules.fri[round]!;
    const descriptor = localWordV17FriMerkleDescriptor(round, parameters);
    validateRoot(layer.root, "local-word FRI");
    if (layer.indices.length !== expected.length || layer.indices.some((index, at) => index !== expected[at]) ||
      layer.values.length !== expected.length ||
      layer.siblings.length !== v17MerkleSchedule(descriptor, expected).siblingCount ||
      layer.siblings.some((sibling) => sibling.length !== 32)) {
      throw new Error("local-word FRI opening shape");
    }
    const root = v17MerkleOpeningRoot({
      descriptor,
      rows: expected.map((index, position) => ({ index, raw: encodeQm31(layer.values[position]!) })),
      siblings: layer.siblings,
    });
    if (!eq32(root, layer.root)) throw new Error("local-word FRI Merkle root");
  });

  const bodyParts: Uint8Array[] = [];
  for (const [matrix, opening] of openings.entries()) {
    const name = LOCAL_WORD_MATRIX_NAMES[matrix]!;
    bodyParts.push(
      ...opening.rows,
      ...opening.siblings,
      openingFrontierBundle(
        localWordV17MatrixMerkleDescriptor(name, parameters),
        opening.indices,
        opening.rows,
        opening.siblings,
        localWordV17MerkleCuts({ matrix: name, parameters }),
        directory.openings[matrix]!,
      ),
    );
  }
  for (const [round, layer] of proof.fri.layers.entries()) {
    const rows = layer.values.map(encodeQm31);
    bodyParts.push(
      ...rows,
      ...layer.siblings,
      openingFrontierBundle(
        localWordV17FriMerkleDescriptor(round, parameters),
        layer.indices,
        rows,
        layer.siblings,
        localWordV17MerkleCuts({ friLayer: round, parameters }),
        directory.openings[LOCAL_WORD_MATRIX_NAMES.length + round]!,
      ),
    );
  }
  const body = concatBytes(...bodyParts);
  let encoded: Uint8Array;
  if (production) {
    encoded = new Uint8Array(V17_PROOF_FIXED_PREFIX_BYTES + body.length);
    const written = new Set<V17GeneratedProofFrameId>();
    const put = (id: V17GeneratedProofFrameId, value: Uint8Array): void => {
      const frame = v17ProofFrame(id);
      if (value.length !== frame.totalBytes) {
        throw new Error(`local-word v17 frame width ${id}: ${value.length}/${frame.totalBytes}`);
      }
      if (written.has(id)) throw new Error(`local-word duplicate v17 frame ${id}`);
      encoded.set(value, frame.offsetBytes);
      written.add(id);
    };
    put("magic", MAGIC);
    put("proofVersion", Uint8Array.of(proof.version));
    put("profile", Uint8Array.of(proof.profile));
    put("protocolId", proof.protocolId);
    put("totalLength", writeU32BE(encoded.length));
    put("publicInverses", concatBytes(...proof.publicBoundaryInverses.map(encodeQm31)));
    put("publicClaimedSum", encodeQm31(proof.publicBoundaryClaimedSum));
    LOCAL_WORD_MATRIX_NAMES.forEach((name) => put(`matrixRoot:${name}`, proof.matrices[name].root));
    put("interactionChallenges", concatBytes(
      ...proof.transcriptManifest.interactionChallenges.map(encodeQm31),
    ));
    put("interactionDigest", proof.transcriptManifest.interactionDigest);
    put("constraintAlpha", encodeQm31(proof.transcriptManifest.constraintAlpha));
    put("compositionDigest", proof.transcriptManifest.compositionDigest);
    put("oodValues", concatBytes(...proof.oodValues!.map(encodeQm31)));
    put("batchBeta", encodeQm31(proof.transcriptManifest.batchBeta));
    put("batchDigest", proof.transcriptManifest.batchDigest);
    proof.fri.layers.forEach((layer, round) =>
      put(`friRoot:${round}` as V17GeneratedProofFrameId, layer.root));
    proof.transcriptManifest.friAlphas.forEach((alpha, index) => {
      const group = index < 16 ? Math.floor(index / 2) : 8;
      const subfold = index < 16 ? index % 2 : 0;
      put(`friAlpha:${group}:${subfold}` as V17GeneratedProofFrameId, encodeQm31(alpha));
    });
    put("finalCoefficients", concatBytes(...proof.fri.finalCoefficients.map(encodeQm31)));
    put("friMidDigest", proof.transcriptManifest.friMidDigest);
    put("friRootsDigest", proof.transcriptManifest.friRootsDigest);
    V17_THEOREM_ROUND_IDS.forEach((id, index) =>
      put(`roundNonce:${id}`, writeU32BE(proof.roundNonces![index]!)));
    put("queryDigest", proof.transcriptManifest.queryDigest);
    put("queries", concatBytes(...proof.queries.map(writeU32BE)));
    put("currentIndices", concatBytes(...schedules.current.map(writeU32BE)));
    put("currentRanks", Uint8Array.from(directory.currentRanks));
    put("globalCurrentRanks", Uint8Array.from(directory.globalCurrentRanks));
    put("globalPreviousRanks", Uint8Array.from(directory.globalPreviousRanks));
    put("friCosetRanks", Uint8Array.from(directory.friCosetRanks.flat()));
    const openingDirectoryBytes = directory.bytes.slice(
      directory.bytes.length - v17ProofFrame("openingDirectory").totalBytes,
    );
    put("openingDirectory", openingDirectoryBytes);
    if (written.size !== V17_PROOF_FRAMES.length ||
      V17_PROOF_FRAMES.some(({ id }) => !written.has(id))) {
      throw new Error("local-word incomplete v17 fixed-frame ownership");
    }
    encoded.set(body, V17_PROOF_FIXED_PREFIX_BYTES);
  } else {
    encoded = concatBytes(
      MAGIC,
      Uint8Array.of(proof.version, proof.profile),
      proof.protocolId,
      new Uint8Array(4),
      ...proof.publicBoundaryInverses.map(encodeQm31),
      encodeQm31(proof.publicBoundaryClaimedSum),
      ...openings.map((opening) => opening.root),
      ...proof.fri.layers.map((layer) => layer.root),
      ...proof.fri.finalCoefficients.map(encodeQm31),
      writeU32BE(proof.fri.grindNonce),
      ...proof.transcriptManifest.interactionChallenges.map(encodeQm31),
      proof.transcriptManifest.interactionDigest,
      encodeQm31(proof.transcriptManifest.constraintAlpha),
      proof.transcriptManifest.compositionDigest,
      encodeQm31(proof.transcriptManifest.batchBeta),
      proof.transcriptManifest.batchDigest,
      ...proof.transcriptManifest.friAlphas.map(encodeQm31),
      proof.transcriptManifest.friMidDigest,
      proof.transcriptManifest.friRootsDigest,
      proof.transcriptManifest.queryDigest,
      ...proof.queries.map(writeU32BE),
      ...schedules.current.map(writeU32BE),
      directory.bytes,
      body,
    );
  }
  if (encoded.length > LOCAL_WORD_PROOF_MAX_BYTES) throw new Error("local-word proof byte length");
  if (!production) encoded.set(writeU32BE(encoded.length), LOCAL_WORD_PROOF_LENGTH_OFFSET);
  return encoded;
}

function decodeMatrix(
  cursor: Cursor,
  root: Uint8Array,
  descriptor: V17MerkleDescriptor,
  indices: readonly number[],
  cuts: readonly number[],
  entry: LocalWordOpeningDirectoryEntry,
): LocalWordMatrixOpening {
  const rows = Array.from({ length: indices.length }, () => cursor.take(descriptor.rowWidth));
  rows.forEach((row) => {
    for (let offset = 0; offset < row.length; offset += 4) {
      if (BigInt(readU32LE(row, offset)) >= M31) throw new Error("local-word matrix field element");
    }
  });
  const siblings = Array.from(
    { length: v17MerkleSchedule(descriptor, indices).siblingCount },
    () => cursor.take(32),
  );
  const expectedFrontier = openingFrontierBundle(
    descriptor, indices, rows, siblings, cuts, entry,
  );
  if (!equal(cursor.take(expectedFrontier.length), expectedFrontier)) {
    throw new Error("local-word matrix frontier");
  }
  const computedRoot = v17MerkleOpeningRoot({
    descriptor,
    rows: indices.map((index, position) => ({ index, raw: rows[position]! })),
    siblings,
  });
  if (!eq32(computedRoot, root)) throw new Error("local-word matrix Merkle root");
  return { root, rowWidth: descriptor.rowWidth, indices: [...indices], rows, siblings };
}

export function decodeLocalWordSealedProof(
  bytes: Uint8Array,
  context: LocalWordProofContext,
  parameters: LocalWordProofParameters = LOCAL_WORD_PRODUCTION_PARAMETERS,
): LocalWordSealedProof {
  validateLocalWordProofParameters(parameters);
  const layerCount = localWordFriFoldCounts(parameters).length;
  const rowCount = 2 ** parameters.evalLog;
  const staticOffsets = localWordProofStaticOffsets(context.publicWords.length, parameters);
  const production = staticOffsets.openingBodies === V17_PROOF_FIXED_PREFIX_BYTES;
  if (bytes.length < staticOffsets.openingBodies || bytes.length > LOCAL_WORD_PROOF_MAX_BYTES ||
    context.profile < 0 || context.profile > 2 || context.transcriptInitial.length < 1 ||
    context.constructionDescriptor.length < 1 || context.publicWords.length < 1 ||
    context.publicWords.length > 1024 || context.expectedPreprocessedRoot.length !== 32) {
    throw new Error("local-word proof context");
  }
  const cursor = new Cursor(bytes);
  const fixed = (id: V17GeneratedProofFrameId, legacyWidth: number): Uint8Array =>
    production ? takeGeneratedFrame(cursor, id) : cursor.take(legacyWidth);
  if (!equal(fixed("magic", 4), MAGIC)) throw new Error("local-word proof magic");
  const version = fixed("proofVersion", 1)[0]!;
  const profile = fixed("profile", 1)[0]!;
  if (version !== LOCAL_WORD_PROOF_VERSION || profile !== context.profile) {
    throw new Error("local-word proof version");
  }
  const protocolId = fixed("protocolId", 32);
  if (!eq32(protocolId, V17_PROOF_PROTOCOL_ID)) {
    throw new Error("local-word protocol id");
  }
  const proofLength = readU32BE(fixed("totalLength", 4), 0);
  if (proofLength !== bytes.length) throw new Error("local-word proof byte length");
  const publicBoundaryInverses = production
    ? decodeQm31Items(fixed("publicInverses", 8 * 16), context.publicWords.length)
    : Array.from({ length: context.publicWords.length }, () => cursor.qm31());
  const publicBoundaryClaimedSum = production
    ? decodeQm31(fixed("publicClaimedSum", 16))
    : cursor.qm31();
  const roots = production
    ? LOCAL_WORD_MATRIX_NAMES.map((name) => fixed(`matrixRoot:${name}`, 32))
    : Array.from({ length: LOCAL_WORD_MATRIX_NAMES.length }, () => cursor.take(32));
  if (!eq32(roots[0]!, context.expectedPreprocessedRoot)) throw new Error("local-word preprocessed root");
  let friRoots: Uint8Array[];
  let finalCoefficients: QM31El[];
  let grindNonce: number;
  let oodValues: QM31El[] | undefined;
  let roundNonces: number[] | undefined;
  let transcriptManifest: LocalWordTranscriptManifest;
  if (production) {
    const interactionChallenges = decodeQm31Items(
      takeGeneratedFrame(cursor, "interactionChallenges"),
      LOCAL_WORD_INTERACTION_CHALLENGE_COUNT,
    );
    const interactionDigest = takeGeneratedFrame(cursor, "interactionDigest");
    const constraintAlpha = decodeQm31(takeGeneratedFrame(cursor, "constraintAlpha"));
    const compositionDigest = takeGeneratedFrame(cursor, "compositionDigest");
    oodValues = decodeQm31Items(takeGeneratedFrame(cursor, "oodValues"), 98);
    const batchBeta = decodeQm31(takeGeneratedFrame(cursor, "batchBeta"));
    const batchDigest = takeGeneratedFrame(cursor, "batchDigest");
    friRoots = Array.from({ length: layerCount }, (_, layer) =>
      takeGeneratedFrame(cursor, `friRoot:${layer}` as V17GeneratedProofFrameId));
    const friAlphas = Array.from({ length: 17 }, (_, index) => {
      const group = index < 16 ? Math.floor(index / 2) : 8;
      const subfold = index < 16 ? index % 2 : 0;
      return decodeQm31(takeGeneratedFrame(
        cursor,
        `friAlpha:${group}:${subfold}` as V17GeneratedProofFrameId,
      ));
    });
    finalCoefficients = decodeQm31Items(
      takeGeneratedFrame(cursor, "finalCoefficients"),
      2 ** parameters.fri.finalLogDegree,
    );
    const friMidDigest = takeGeneratedFrame(cursor, "friMidDigest");
    const friRootsDigest = takeGeneratedFrame(cursor, "friRootsDigest");
    roundNonces = V17_THEOREM_ROUND_IDS.map((id) =>
      readU32BE(takeGeneratedFrame(cursor, `roundNonce:${id}`), 0));
    grindNonce = roundNonces.at(-1)!;
    transcriptManifest = {
      interactionChallenges,
      interactionDigest,
      constraintAlpha,
      compositionDigest,
      batchBeta,
      batchDigest,
      friAlphas,
      friMidDigest,
      friRootsDigest,
      queryDigest: takeGeneratedFrame(cursor, "queryDigest"),
    };
  } else {
    friRoots = Array.from({ length: layerCount }, () => cursor.take(32));
    finalCoefficients = Array.from(
      { length: 2 ** parameters.fri.finalLogDegree },
      () => cursor.qm31(),
    );
    grindNonce = cursor.u32();
    transcriptManifest = {
      interactionChallenges: Array.from(
        { length: LOCAL_WORD_INTERACTION_CHALLENGE_COUNT },
        () => cursor.qm31(),
      ),
      interactionDigest: cursor.take(32),
      constraintAlpha: cursor.qm31(),
      compositionDigest: cursor.take(32),
      batchBeta: cursor.qm31(),
      batchDigest: cursor.take(32),
      friAlphas: Array.from({ length: layerCount }, () => cursor.qm31()),
      friMidDigest: cursor.take(32),
      friRootsDigest: cursor.take(32),
      queryDigest: cursor.take(32),
    };
  }
  let queryManifest: number[];
  let currentIndexManifest: number[];
  let directoryBytes: Uint8Array;
  if (production) {
    queryManifest = decodeU32Items(
      takeGeneratedFrame(cursor, "queries"),
      parameters.fri.queries,
    );
    currentIndexManifest = decodeU32Items(
      takeGeneratedFrame(cursor, "currentIndices"),
      parameters.fri.queries,
    );
    directoryBytes = concatBytes(
      takeGeneratedFrame(cursor, "currentRanks"),
      takeGeneratedFrame(cursor, "globalCurrentRanks"),
      takeGeneratedFrame(cursor, "globalPreviousRanks"),
      takeGeneratedFrame(cursor, "friCosetRanks"),
      takeGeneratedFrame(cursor, "openingDirectory"),
    );
    if (cursor.offset !== V17_PROOF_FIXED_PREFIX_BYTES) {
      throw new Error("local-word v17 fixed-prefix coverage");
    }
  } else {
    queryManifest = Array.from({ length: parameters.fri.queries }, () => cursor.u32());
    currentIndexManifest = Array.from({ length: parameters.fri.queries }, () => cursor.u32());
    directoryBytes = cursor.take(staticOffsets.openingBodies - staticOffsets.currentRanks);
  }

  let challenges: LocalWordInteractionChallenges;
  let queries: readonly number[];
  if (production) {
    const replay = replayV17ProofTranscript({
      initial: context.transcriptInitial,
      version: 17,
      profile: profile as 0 | 1 | 2,
      protocolId,
      preprocessedRoot: roots[0]!,
      originalRoot: roots[1]!,
      publicBoundaryInverses,
      publicBoundaryClaimedSum,
      interactionRoot: roots[2]!,
      interactionGlobalRoot: roots[3]!,
      quotientAndFriMaskRoot: roots[4]!,
      oodValues: oodValues!,
      friRoots,
      finalCoefficients,
      roundNonces: roundNonces!,
    });
    challenges = replay.interactionChallenges;
    queries = replay.queries;
    const flatAlphas = flattenV17FriAlphas(replay.friAlphas);
    if (transcriptManifest.interactionChallenges.some((challenge, index) =>
      !qmEq(challenge, replay.interactionChallengeValues[index]!)) ||
      !eq32(transcriptManifest.interactionDigest, replay.interactionDigest) ||
      !qmEq(transcriptManifest.constraintAlpha, replay.constraintAlpha) ||
      !eq32(transcriptManifest.compositionDigest, replay.compositionDigest) ||
      !qmEq(transcriptManifest.batchBeta, replay.batchBeta) ||
      !eq32(transcriptManifest.batchDigest, replay.batchDigest) ||
      transcriptManifest.friAlphas.some((alpha, index) => !qmEq(alpha, flatAlphas[index]!)) ||
      !eq32(transcriptManifest.friMidDigest, replay.friMidDigest) ||
      !eq32(transcriptManifest.friRootsDigest, replay.friRootsDigest) ||
      !eq32(transcriptManifest.queryDigest, replay.queryDigest)) {
      throw new Error("local-word v17 transcript snapshot");
    }
  } else {
    const legacy = localWordInteractionTranscript(
      context.transcriptInitial,
      protocolId,
      roots[0]!,
      roots[1]!,
    );
    const transcript = legacy.transcript;
    challenges = legacy.challenges;
    const expectedInteractionChallenges = localWordInteractionChallengeValues(challenges);
    if (transcriptManifest.interactionChallenges.some((challenge, index) =>
      !qmEq(challenge, expectedInteractionChallenges[index]!))) {
      throw new Error("local-word interaction challenge manifest");
    }
    localWordPublicBoundaryTranscript(transcript, publicBoundaryInverses);
    if (!eq32(transcriptManifest.interactionDigest, transcript.digest)) {
      throw new Error("local-word interaction digest manifest");
    }
    const composition = localWordCompositionTranscript(transcript, roots[2]!, roots[3]!);
    if (!qmEq(transcriptManifest.constraintAlpha, composition.constraintAlpha) ||
      !eq32(transcriptManifest.compositionDigest, composition.digest)) {
      throw new Error("local-word composition manifest");
    }
    transcript.absorb("local-word-quotient-and-fri-mask-root", roots[4]!);
    const batchBeta = transcript.challengeQm31("local-word-batch-beta");
    if (!qmEq(transcriptManifest.batchBeta, batchBeta) ||
      !eq32(transcriptManifest.batchDigest, transcript.digest)) {
      throw new Error("local-word batch manifest");
    }
    const friAlphas: QM31El[] = [];
    let friMidDigest = new Uint8Array();
    const friSplit = Math.ceil(layerCount / 2);
    friRoots.forEach((root, round) => {
      transcript.absorb(`fri-root:${round}`, root);
      friAlphas.push(transcript.challengeQm31(`fri-alpha:${round}`));
      if (round + 1 === friSplit) friMidDigest = transcript.digest;
    });
    if (friAlphas.some((alpha, index) => !qmEq(alpha, transcriptManifest.friAlphas[index]!)) ||
      !eq32(friMidDigest, transcriptManifest.friMidDigest) ||
      !eq32(transcript.digest, transcriptManifest.friRootsDigest)) {
      throw new Error("local-word FRI root manifest");
    }
    transcript.absorb("fri-final", concatBytes(...finalCoefficients.map(encodeQm31)));
    if (!transcript.acceptGrind(parameters.fri.grindBits, grindNonce)) {
      throw new Error("local-word FRI grind");
    }
    if (!eq32(transcript.digest, transcriptManifest.queryDigest)) {
      throw new Error("local-word query digest manifest");
    }
    queries = localWordQueryIndices(transcript, parameters);
  }
  const expectedClaim = poolLocalBoundaryClaimForWords(context.publicWords, challenges.boundary);
  if (publicBoundaryInverses.length !== expectedClaim.publicInverses.length ||
    publicBoundaryInverses.some((inverse, index) => !qmEq(inverse, expectedClaim.publicInverses[index]!)) ||
    !qmEq(publicBoundaryClaimedSum, expectedClaim.claimedSum)) {
    throw new Error("local-word public boundary inverses");
  }
  if (queries.some((query, index) => query !== queryManifest[index])) {
    throw new Error("local-word query manifest");
  }
  const expectedDirectory = localWordProofDirectory(queries, context.publicWords.length, parameters);
  if (currentIndexManifest.some((index, item) => index !== expectedDirectory.currentIndices[item])) {
    throw new Error("local-word current index manifest");
  }
  if (!equal(directoryBytes, expectedDirectory.bytes)) {
    throw new Error("local-word proof directory");
  }
  const schedules = localWordOpeningSchedules(queries, parameters);

  const decodedMatrices = LOCAL_WORD_MATRIX_NAMES.map((name, index) => [
    name,
    decodeMatrix(
      cursor,
      roots[index]!,
      localWordV17MatrixMerkleDescriptor(name, parameters),
      index === 3 ? schedules.global : schedules.current,
      localWordV17MerkleCuts({ matrix: name, parameters }),
      expectedDirectory.openings[index]!,
    ),
  ] as const);
  const matrices = Object.fromEntries(decodedMatrices) as Record<LocalWordMatrixName, LocalWordMatrixOpening>;
  const layers: SuccessorFriLayerProof[] = schedules.fri.map((indices, round) => {
    const descriptor = localWordV17FriMerkleDescriptor(round, parameters);
    const values = Array.from({ length: indices.length }, () => cursor.qm31());
    const siblings = Array.from(
      { length: v17MerkleSchedule(descriptor, indices).siblingCount },
      () => cursor.take(32),
    );
    const expectedFrontier = openingFrontierBundle(
      descriptor,
      indices,
      values.map(encodeQm31),
      siblings,
      localWordV17MerkleCuts({ friLayer: round, parameters }),
      expectedDirectory.openings[LOCAL_WORD_MATRIX_NAMES.length + round]!,
    );
    if (!equal(cursor.take(expectedFrontier.length), expectedFrontier)) {
      throw new Error("local-word FRI frontier");
    }
    const computedRoot = v17MerkleOpeningRoot({
      descriptor,
      rows: indices.map((index, position) => ({ index, raw: encodeQm31(values[position]!) })),
      siblings,
    });
    if (!eq32(computedRoot, friRoots[round]!)) throw new Error("local-word FRI Merkle root");
    return { root: friRoots[round]!, indices, values, siblings };
  });
  if (cursor.offset !== bytes.length) throw new Error("trailing local-word proof bytes");
  const proof: LocalWordSealedProof = {
    version,
    profile,
    protocolId,
    proofLength,
    publicBoundaryInverses,
    publicBoundaryClaimedSum,
    matrices,
    fri: { layers, finalCoefficients, grindNonce },
    transcriptManifest,
    ...(production ? { oodValues: oodValues!, roundNonces: roundNonces! } : {}),
    queries,
  };
  if (!equal(encodeLocalWordSealedProof(proof, parameters), bytes)) throw new Error("non-canonical local-word proof");
  return proof;
}

/** Exact byte ownership map; generated fixed frames and dynamic bodies partition the proof. */
export function frameLocalWordSealedProof(
  proof: LocalWordSealedProof,
  parameters: LocalWordProofParameters = LOCAL_WORD_PRODUCTION_PARAMETERS,
): LocalWordProofFrame[] {
  const frames: LocalWordProofFrame[] = [];
  const schedules = localWordOpeningSchedules(proof.queries, parameters);
  const directory = localWordProofDirectory(
    proof.queries,
    proof.publicBoundaryInverses.length,
    parameters,
  );
  const production = localWordProofStaticOffsets(
    proof.publicBoundaryInverses.length,
    parameters,
  ).openingBodies === V17_PROOF_FIXED_PREFIX_BYTES;
  let offset = 0;
  const take = (width: number, frame: Omit<LocalWordProofFrame, "start" | "end">): void => {
    frames.push({ ...frame, start: offset, end: offset + width });
    offset += width;
  };
  if (production) {
    const generated = (
      frameId: V17GeneratedProofFrameId,
      item: number,
      start: number,
      end: number,
      semantic: Omit<LocalWordProofFrame, "start" | "end" | "generatedFrameId">,
    ): void => {
      if (start !== offset) throw new Error(`local-word v17 frame ownership gap ${frameId}`);
      frames.push({ ...semantic, generatedFrameId: frameId, start, end });
      offset = end;
    };
    for (const source of V17_PROOF_FRAMES) {
      if (source.id === "openingDirectory") {
        for (let entry = 0; entry < source.itemCount; entry += 1) {
          for (let word = 0; word < 5; word += 1) {
            const start = source.offsetBytes + entry * source.itemBytes + word * 4;
            generated(source.id, entry * 5 + word, start, start + 4, {
              kind: "opening-directory-word",
              item: entry * 5 + word,
            });
          }
        }
        continue;
      }
      for (let item = 0; item < source.itemCount; item += 1) {
        const start = source.offsetBytes + item * source.itemBytes;
        const end = start + source.itemBytes;
        const id = source.id;
        if (id === "magic") generated(id, item, start, end, { kind: "magic" });
        else if (id === "proofVersion") generated(id, item, start, end, { kind: "proof-version" });
        else if (id === "profile") generated(id, item, start, end, { kind: "profile" });
        else if (id === "protocolId") generated(id, item, start, end, { kind: "protocol-id" });
        else if (id === "totalLength") generated(id, item, start, end, { kind: "total-length" });
        else if (id === "publicInverses") generated(id, item, start, end,
          { kind: "public-inverse", item });
        else if (id === "publicClaimedSum") generated(id, item, start, end,
          { kind: "public-claimed-sum" });
        else if (id.startsWith("matrixRoot:")) {
          const matrix = id.slice("matrixRoot:".length) as LocalWordMatrixName;
          generated(id, item, start, end, { kind: "matrix-root", matrix });
        } else if (id === "interactionChallenges") generated(id, item, start, end,
          { kind: "interaction-challenge", item });
        else if (id === "interactionDigest") generated(id, item, start, end,
          { kind: "interaction-digest" });
        else if (id === "constraintAlpha") generated(id, item, start, end,
          { kind: "constraint-alpha" });
        else if (id === "compositionDigest") generated(id, item, start, end,
          { kind: "composition-digest" });
        else if (id === "oodValues") generated(id, item, start, end,
          { kind: "ood-value", item });
        else if (id === "batchBeta") generated(id, item, start, end, { kind: "batch-beta" });
        else if (id === "batchDigest") generated(id, item, start, end, { kind: "batch-digest" });
        else if (id.startsWith("friRoot:")) {
          const layer = Number(id.slice("friRoot:".length));
          generated(id, item, start, end, { kind: "fri-root", layer });
        } else if (id.startsWith("friAlpha:")) {
          const [, group, subfold] = id.split(":");
          generated(id, item, start, end, {
            kind: "fri-alpha",
            layer: Number(group),
            item: Number(subfold),
          });
        } else if (id === "finalCoefficients") generated(id, item, start, end,
          { kind: "fri-final", item });
        else if (id === "friMidDigest") generated(id, item, start, end,
          { kind: "fri-mid-digest" });
        else if (id === "friRootsDigest") generated(id, item, start, end,
          { kind: "fri-roots-digest" });
        else if (id.startsWith("roundNonce:")) {
          const round = id.slice("roundNonce:".length) as V17TheoremRoundId;
          generated(id, item, start, end, { kind: "round-nonce", round });
        } else if (id === "queryDigest") generated(id, item, start, end,
          { kind: "query-digest" });
        else if (id === "queries") generated(id, item, start, end, { kind: "query", item });
        else if (id === "currentIndices") generated(id, item, start, end,
          { kind: "current-index", item });
        else if (id === "currentRanks") generated(id, item, start, end,
          { kind: "current-rank", item });
        else if (id === "globalCurrentRanks") generated(id, item, start, end,
          { kind: "global-current-rank", item });
        else if (id === "globalPreviousRanks") generated(id, item, start, end,
          { kind: "global-previous-rank", item });
        else if (id === "friCosetRanks") generated(id, item, start, end, {
          kind: "fri-coset-rank",
          layer: Math.floor(item / parameters.fri.queries),
          item: item % parameters.fri.queries,
        });
        else throw new Error(`local-word unmapped v17 generated frame ${id}`);
      }
    }
    if (offset !== V17_PROOF_FIXED_PREFIX_BYTES) {
      throw new Error("local-word v17 fixed frame coverage");
    }
  } else {
    // Frozen experimental codec: preserve its byte order and one-grind manifest.
    take(LOCAL_WORD_PROOF_HEADER_BYTES, { kind: "header" });
    proof.publicBoundaryInverses.forEach((_, item) => take(16, { kind: "public-inverse", item }));
    take(16, { kind: "public-claimed-sum" });
    LOCAL_WORD_MATRIX_NAMES.forEach((matrix) => take(32, { kind: "matrix-root", matrix }));
    proof.fri.layers.forEach((_, layer) => take(32, { kind: "fri-root", layer }));
    proof.fri.finalCoefficients.forEach((_, item) => take(16, { kind: "fri-final", item }));
    take(4, { kind: "grind-nonce" });
    proof.transcriptManifest.interactionChallenges.forEach((_, item) =>
      take(16, { kind: "interaction-challenge", item }));
    take(32, { kind: "interaction-digest" });
    take(16, { kind: "constraint-alpha" });
    take(32, { kind: "composition-digest" });
    take(16, { kind: "batch-beta" });
    take(32, { kind: "batch-digest" });
    proof.transcriptManifest.friAlphas.forEach((_, item) => take(16, { kind: "fri-alpha", item }));
    take(32, { kind: "fri-mid-digest" });
    take(32, { kind: "fri-roots-digest" });
    take(32, { kind: "query-digest" });
    proof.queries.forEach((_, item) => take(4, { kind: "query", item }));
    schedules.current.forEach((_, item) => take(4, { kind: "current-index", item }));
    proof.queries.forEach((_, item) => take(1, { kind: "current-rank", item }));
    proof.queries.forEach((_, item) => take(1, { kind: "global-current-rank", item }));
    proof.queries.forEach((_, item) => take(1, { kind: "global-previous-rank", item }));
    proof.fri.layers.forEach((_, layer) => proof.queries.forEach((__, item) =>
      take(1, { kind: "fri-coset-rank", layer, item })));
    directory.openings.forEach((_, opening) => Array.from({ length: 5 }, (__, word) =>
      take(4, { kind: "opening-directory-word", item: opening * 5 + word })));
  }
  const bodyFrame = { generatedFrameId: production ? "openingBodies" as const : undefined };
  LOCAL_WORD_MATRIX_NAMES.forEach((matrix) => {
    const opening = proof.matrices[matrix];
    opening.rows.forEach((row, item) => take(row.length,
      { kind: "matrix-row", matrix, item, ...bodyFrame }));
    opening.siblings.forEach((_, item) => take(32,
      { kind: "matrix-sibling", matrix, item, ...bodyFrame }));
    const descriptor = localWordV17MatrixMerkleDescriptor(matrix, parameters);
    const frontiers = localWordV17MerkleFrontierSchedules(
      descriptor,
      opening.indices,
      localWordV17MerkleCuts({ matrix, parameters }),
    );
    frontiers.forEach((_, item) => take(12,
      { kind: "opening-stage-directory", matrix, item, ...bodyFrame }));
    frontiers.forEach((frontier, boundary) => frontier.indices.forEach((_, item) =>
      take(36, { kind: "matrix-frontier", matrix,
        item: boundary * 256 + item, ...bodyFrame })));
  });
  proof.fri.layers.forEach((layer, round) => {
    layer.values.forEach((_, item) => take(16,
      { kind: "fri-value", layer: round, item, ...bodyFrame }));
    layer.siblings.forEach((_, item) => take(32,
      { kind: "fri-sibling", layer: round, item, ...bodyFrame }));
    const descriptor = localWordV17FriMerkleDescriptor(round, parameters);
    const frontiers = localWordV17MerkleFrontierSchedules(
      descriptor,
      layer.indices,
      localWordV17MerkleCuts({ friLayer: round, parameters }),
    );
    frontiers.forEach((_, item) => take(12,
      { kind: "opening-stage-directory", layer: round, item, ...bodyFrame }));
    frontiers.forEach((frontier, boundary) => frontier.indices.forEach((_, item) =>
      take(36, { kind: "fri-frontier", layer: round,
        item: boundary * 256 + item, ...bodyFrame })));
  });
  if (offset !== proof.proofLength) throw new Error("local-word proof frame coverage");
  return frames;
}

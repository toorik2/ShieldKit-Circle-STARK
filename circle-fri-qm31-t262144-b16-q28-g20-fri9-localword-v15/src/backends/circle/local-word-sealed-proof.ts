import {
  concatBytes,
  eq32,
  readU32BE,
  readU32LE,
  sha256,
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
} from "./local-word-transcript.ts";
import {
  canonicalMerkleFrontier4,
  encodeCanonicalMerkleFrontier4,
} from "./canonical-merkle.ts";

const MAGIC = new TextEncoder().encode("SKLW");
export const LOCAL_WORD_PROOF_VERSION = 15;
export const LOCAL_WORD_PROOF_LENGTH_OFFSET = 4 + 1 + 1 + 32;
export const LOCAL_WORD_PROOF_FIXED_PREFIX_BYTES = LOCAL_WORD_PROOF_LENGTH_OFFSET + 4;
export const LOCAL_WORD_PROOF_MAX_BYTES = 1_000_000;
export const LOCAL_WORD_FRI_FINAL_LOG_DEGREE = 3;
export const LOCAL_WORD_FRI_LAYERS =
  localWordFriFoldCounts(LOCAL_WORD_PRODUCTION_PARAMETERS).length;
export const LOCAL_WORD_MATRIX_ROW_WIDTHS = [172, 136, 224, 48, 32] as const;
export const LOCAL_WORD_MATRIX_NAMES = [
  "preprocessed",
  "original",
  "interaction",
  "interactionGlobal",
  "quotientAndFriMask",
] as const;
export type LocalWordMatrixName = typeof LOCAL_WORD_MATRIX_NAMES[number];
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

export type LocalWordProofStaticOffsets = {
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
  readonly batchBeta: number;
  readonly batchDigest: number;
  readonly friAlphas: number;
  readonly friMidDigest: number;
  readonly friRootsDigest: number;
  readonly queryDigest: number;
  readonly queries: number;
  readonly currentIndices: number;
  readonly currentRanks: number;
  readonly globalCurrentRanks: number;
  readonly globalPreviousRanks: number;
  readonly friCosetRanks: number;
  readonly openingDirectory: number;
  readonly compositionPartials: number;
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
  const publicInverses = LOCAL_WORD_PROOF_FIXED_PREFIX_BYTES;
  const publicClaimedSum = publicInverses + publicWordCount * 16;
  const matrixRoots = publicClaimedSum + 16;
  const friRoots = matrixRoots + LOCAL_WORD_MATRIX_NAMES.length * 32;
  const finalCoefficients = friRoots + friLayerCount * 32;
  const grindNonce = finalCoefficients + finalCoefficientCount * 16;
  const interactionChallenges = grindNonce + 4;
  const interactionDigest = interactionChallenges + LOCAL_WORD_INTERACTION_CHALLENGE_COUNT * 16;
  const constraintAlpha = interactionDigest + 32;
  const compositionDigest = constraintAlpha + 16;
  const batchBeta = compositionDigest + 32;
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
  const compositionPartials = openingDirectory +
    (LOCAL_WORD_MATRIX_NAMES.length + friLayerCount) * 20;
  const openingBodies = compositionPartials + parameters.fri.queries * 3 * 16;
  return {
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
    batchBeta,
    batchDigest,
    friAlphas,
    friMidDigest,
    friRootsDigest,
    queryDigest,
    queries,
    currentIndices,
    currentRanks,
    globalCurrentRanks,
    globalPreviousRanks,
    friCosetRanks,
    openingDirectory,
    compositionPartials,
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
  readonly constructionDigest: Uint8Array;
  readonly proofLength: number;
  readonly publicBoundaryInverses: readonly QM31El[];
  /** Public sum of the checked inverses; one VM role owns this derived cache. */
  readonly publicBoundaryClaimedSum: QM31El;
  readonly matrices: Readonly<Record<LocalWordMatrixName, LocalWordMatrixOpening>>;
  readonly fri: SuccessorFriProof;
  readonly transcriptManifest: LocalWordTranscriptManifest;
  /** Three checked contiguous AIR Horner segments per transcript query. */
  readonly compositionPartials: readonly (readonly [QM31El, QM31El, QM31El])[];
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
    | "batch-beta"
    | "batch-digest"
    | "fri-alpha"
    | "fri-mid-digest"
    | "fri-roots-digest"
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
    | "composition-partial"
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

/**
 * Exact upper bound for every collision-free canonical proof under the fixed
 * radix-4 schedules. FRI quartets collapse without siblings at level zero;
 * the final binary fold contributes exactly two missing children per query in
 * its worst placement. No transcript outcome can serialize more bytes.
 */
export function localWordMaximumCanonicalProofBytes(
  publicWordCount: number,
  parameters: LocalWordProofParameters = LOCAL_WORD_PRODUCTION_PARAMETERS,
): number {
  validateLocalWordProofParameters(parameters);
  const queryCount = parameters.fri.queries;
  const matrixTreeLevels = parameters.evalLog / 2;
  let bytes = localWordProofStaticOffsets(publicWordCount, parameters).openingBodies;
  LOCAL_WORD_MATRIX_NAMES.forEach((matrix, index) => {
    const opened = matrix === "interactionGlobal" ? 2 * queryCount : queryCount;
    const geometry = localWordMatrixMerkleStageGeometry(matrix);
    const stageCount = localWordMerkleFrontierLevels(matrixTreeLevels, geometry).length;
    bytes += (matrix === "interactionGlobal" ? opened * 4 : 0) +
      opened * LOCAL_WORD_MATRIX_ROW_WIDTHS[index]! +
      maximumRadix4SiblingCount(opened, matrixTreeLevels) * 32 +
      stageCount * 12 +
      maximumRadix4FrontierNodes(opened, matrixTreeLevels, geometry) * 36;
  });
  const folds = localWordFriFoldCounts(parameters);
  const layerLogs = localWordFriLayerLogs(parameters);
  folds.forEach((foldCount, round) => {
    if (foldCount !== 1 && foldCount !== 2) throw new Error("local-word maximum FRI fold");
    const treeLevels = layerLogs[round]! / 2;
    const opened = queryCount * 2 ** foldCount;
    const firstLevelSiblings = foldCount === 1 ? 2 * queryCount : 0;
    const siblings = firstLevelSiblings +
      maximumRadix4SiblingCount(queryCount, treeLevels - 1);
    const stageCount = localWordMerkleFrontierLevels(
      treeLevels,
      LOCAL_WORD_FRI_MERKLE_STAGE_GEOMETRY,
    ).length;
    bytes += opened * 4 + opened * 16 + siblings * 32 + stageCount * 12 +
      maximumRadix4FrontierNodes(
        queryCount,
        treeLevels,
        LOCAL_WORD_FRI_MERKLE_STAGE_GEOMETRY,
      ) * 36;
  });
  if (!Number.isSafeInteger(bytes) || bytes > LOCAL_WORD_PROOF_MAX_BYTES) {
    throw new Error("local-word maximum proof bytes");
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
    rowWidth: number,
    rowCount: number,
    geometry: LocalWordMerkleStageGeometry,
    serializeIndices: boolean,
  ): void => {
    const siblingCount = localWordCanonicalSiblingCount(indices, rowCount);
    const frontiers = localWordMerkleFrontierSchedules(indices, rowCount, geometry);
    const indicesStart = cursor;
    const rowsStart = indicesStart + (serializeIndices ? indices.length * 4 : 0);
    const siblingsStart = rowsStart + indices.length * rowWidth;
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
  LOCAL_WORD_MATRIX_ROW_WIDTHS.forEach((rowWidth, matrix) => opening(
    matrix === 3 ? schedules.global : schedules.current,
    rowWidth,
    2 ** parameters.evalLog,
    localWordMatrixMerkleStageGeometry(LOCAL_WORD_MATRIX_NAMES[matrix]!),
    matrix === 3,
  ));
  const friLayerLogs = localWordFriLayerLogs(parameters);
  schedules.fri.forEach((indices, round) => opening(
    indices,
    16,
    2 ** friLayerLogs[round]!,
    LOCAL_WORD_FRI_MERKLE_STAGE_GEOMETRY,
    true,
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
  if (bytes.length !== offsets.compositionPartials - offsets.currentRanks) {
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
  label: string,
  indices: readonly number[],
  rows: readonly Uint8Array[],
  siblings: readonly Uint8Array[],
  rowCount: number,
  geometry: LocalWordMerkleStageGeometry,
  entry: LocalWordOpeningDirectoryEntry,
): Uint8Array {
  const schedules = localWordMerkleFrontierSchedules(indices, rowCount, geometry);
  if (entry.frontiers.length !== schedules.length) {
    throw new Error("local-word Merkle frontier directory");
  }
  const blobs = schedules.map((schedule, item) => {
    const frontier = canonicalMerkleFrontier4(
      label,
      indices.map((index, position) => ({ index, raw: rows[position]! })),
      siblings,
      rowCount,
      schedule.level,
    );
    const expected = entry.frontiers[item]!;
    const bytes = encodeCanonicalMerkleFrontier4(frontier);
    if (frontier.siblingCount !== schedule.siblingCount ||
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
  rowWidth: number,
  indices: readonly number[],
  rowCount: number,
): void {
  validateRoot(opening.root, "local-word matrix");
  if (!eq32(opening.root, expectedRoot) || opening.rowWidth !== rowWidth ||
    opening.indices.length !== indices.length || opening.indices.some((index, at) => index !== indices[at]) ||
    opening.rows.length !== indices.length || opening.rows.some((row) => row.length !== rowWidth) ||
    opening.rows.some((row) => Array.from({ length: rowWidth / 4 }, (_, limb) =>
      BigInt(readU32LE(row, limb * 4))).some((value) => value >= M31)) ||
    opening.siblings.length !== localWordCanonicalSiblingCount(indices, rowCount) ||
    opening.siblings.some((sibling) => sibling.length !== 32)) {
    throw new Error("local-word matrix opening shape");
  }
}

function validateTranscriptManifest(
  manifest: LocalWordTranscriptManifest,
  friLayers: number,
): void {
  const digests = [
    manifest.interactionDigest,
    manifest.compositionDigest,
    manifest.batchDigest,
    manifest.friMidDigest,
    manifest.friRootsDigest,
    manifest.queryDigest,
  ];
  if (manifest.interactionChallenges.length !== LOCAL_WORD_INTERACTION_CHALLENGE_COUNT ||
    manifest.friAlphas.length !== friLayers || digests.some((digest) => digest.length !== 32)) {
    throw new Error("local-word transcript manifest shape");
  }
  [
    ...manifest.interactionChallenges,
    manifest.constraintAlpha,
    manifest.batchBeta,
    ...manifest.friAlphas,
  ].forEach(encodeQm31);
}

/** One root, one value body, and no serialized transcript-derived geometry. */
export function encodeLocalWordSealedProof(
  proof: LocalWordSealedProof,
  parameters: LocalWordProofParameters = LOCAL_WORD_PRODUCTION_PARAMETERS,
): Uint8Array {
  validateLocalWordProofParameters(parameters);
  const layers = localWordFriFoldCounts(parameters).length;
  const rowCount = 2 ** parameters.evalLog;
  if (proof.version !== LOCAL_WORD_PROOF_VERSION || proof.profile < 0 || proof.profile > 2 ||
    proof.constructionDigest.length !== 32 || proof.publicBoundaryInverses.length < 1 ||
    proof.publicBoundaryInverses.length > 1024 || proof.queries.length !== parameters.fri.queries ||
    proof.fri.layers.length !== layers ||
    proof.fri.finalCoefficients.length !== 2 ** parameters.fri.finalLogDegree ||
    proof.compositionPartials.length !== parameters.fri.queries) {
    throw new Error("local-word proof shape");
  }
  encodeQm31(proof.publicBoundaryClaimedSum);
  validateTranscriptManifest(proof.transcriptManifest, layers);
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
    LOCAL_WORD_MATRIX_ROW_WIDTHS[index]!,
    index === 3 ? schedules.global : schedules.current,
    rowCount,
  ));
  proof.fri.layers.forEach((layer, round) => {
    const expected = schedules.fri[round]!;
    validateRoot(layer.root, "local-word FRI");
    if (layer.indices.length !== expected.length || layer.indices.some((index, at) => index !== expected[at]) ||
      layer.values.length !== expected.length ||
      layer.siblings.length !== localWordCanonicalSiblingCount(
        expected,
        2 ** localWordFriLayerLogs(parameters)[round]!,
      ) ||
      layer.siblings.some((sibling) => sibling.length !== 32)) {
      throw new Error("local-word FRI opening shape");
    }
  });

  const parts: Uint8Array[] = [
    MAGIC,
    Uint8Array.of(proof.version, proof.profile),
    proof.constructionDigest,
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
    ...proof.compositionPartials.flatMap((partials) => partials.map(encodeQm31)),
  ];
  for (const [matrix, opening] of openings.entries()) {
    parts.push(
      ...(matrix === 3 ? opening.indices.map(writeU32BE) : []),
      ...opening.rows,
      ...opening.siblings,
      openingFrontierBundle(
        MATRIX_LABELS[LOCAL_WORD_MATRIX_NAMES[matrix]!],
        opening.indices,
        opening.rows,
        opening.siblings,
        rowCount,
        localWordMatrixMerkleStageGeometry(LOCAL_WORD_MATRIX_NAMES[matrix]!),
        directory.openings[matrix]!,
      ),
    );
  }
  const friLayerLogs = localWordFriLayerLogs(parameters);
  for (const [round, layer] of proof.fri.layers.entries()) {
    const rows = layer.values.map(encodeQm31);
    parts.push(
      ...layer.indices.map(writeU32BE),
      ...rows,
      ...layer.siblings,
      openingFrontierBundle(
        `fri:layer:${round}`,
        layer.indices,
        rows,
        layer.siblings,
        2 ** friLayerLogs[round]!,
        LOCAL_WORD_FRI_MERKLE_STAGE_GEOMETRY,
        directory.openings[LOCAL_WORD_MATRIX_NAMES.length + round]!,
      ),
    );
  }
  const encoded = concatBytes(...parts);
  if (encoded.length > LOCAL_WORD_PROOF_MAX_BYTES) throw new Error("local-word proof byte length");
  encoded.set(writeU32BE(encoded.length), LOCAL_WORD_PROOF_LENGTH_OFFSET);
  return encoded;
}

function decodeMatrix(
  cursor: Cursor,
  root: Uint8Array,
  label: string,
  rowWidth: number,
  indices: readonly number[],
  rowCount: number,
  geometry: LocalWordMerkleStageGeometry,
  entry: LocalWordOpeningDirectoryEntry,
  serializeIndices: boolean,
): LocalWordMatrixOpening {
  if (serializeIndices && indices.some((index) => cursor.u32() !== index)) {
    throw new Error("local-word matrix index manifest");
  }
  const rows = Array.from({ length: indices.length }, () => cursor.take(rowWidth));
  rows.forEach((row) => {
    for (let offset = 0; offset < row.length; offset += 4) {
      if (BigInt(readU32LE(row, offset)) >= M31) throw new Error("local-word matrix field element");
    }
  });
  const siblings = Array.from(
    { length: localWordCanonicalSiblingCount(indices, rowCount) },
    () => cursor.take(32),
  );
  const expectedFrontier = openingFrontierBundle(
    label, indices, rows, siblings, rowCount, geometry, entry,
  );
  if (!equal(cursor.take(expectedFrontier.length), expectedFrontier)) {
    throw new Error("local-word matrix frontier");
  }
  return { root, rowWidth, indices: [...indices], rows, siblings };
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
  if (bytes.length < LOCAL_WORD_PROOF_FIXED_PREFIX_BYTES || bytes.length > LOCAL_WORD_PROOF_MAX_BYTES ||
    context.profile < 0 || context.profile > 2 || context.transcriptInitial.length < 1 ||
    context.constructionDescriptor.length < 1 || context.publicWords.length < 1 ||
    context.publicWords.length > 1024 || context.expectedPreprocessedRoot.length !== 32) {
    throw new Error("local-word proof context");
  }
  const cursor = new Cursor(bytes);
  if (!equal(cursor.take(4), MAGIC)) throw new Error("local-word proof magic");
  const version = cursor.u8();
  const profile = cursor.u8();
  if (version !== LOCAL_WORD_PROOF_VERSION || profile !== context.profile) {
    throw new Error("local-word proof version");
  }
  const constructionDigest = cursor.take(32);
  if (!eq32(constructionDigest, sha256(context.constructionDescriptor))) {
    throw new Error("local-word construction digest");
  }
  const proofLength = cursor.u32();
  if (proofLength !== bytes.length) throw new Error("local-word proof byte length");
  const publicBoundaryInverses = Array.from({ length: context.publicWords.length }, () => cursor.qm31());
  const publicBoundaryClaimedSum = cursor.qm31();
  const roots = Array.from({ length: LOCAL_WORD_MATRIX_NAMES.length }, () => cursor.take(32));
  if (!eq32(roots[0]!, context.expectedPreprocessedRoot)) throw new Error("local-word preprocessed root");
  const friRoots = Array.from({ length: layerCount }, () => cursor.take(32));
  const finalCoefficients = Array.from(
    { length: 2 ** parameters.fri.finalLogDegree },
    () => cursor.qm31(),
  );
  const grindNonce = cursor.u32();
  const transcriptManifest: LocalWordTranscriptManifest = {
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
  const queryManifest = Array.from({ length: parameters.fri.queries }, () => cursor.u32());
  const currentIndexManifest = Array.from({ length: parameters.fri.queries }, () => cursor.u32());
  const directoryBytes = cursor.take(staticOffsets.compositionPartials - staticOffsets.currentRanks);
  const compositionPartials = Array.from(
    { length: parameters.fri.queries },
    () => [cursor.qm31(), cursor.qm31(), cursor.qm31()] as const,
  );

  const { transcript, challenges } = localWordInteractionTranscript(
    context.transcriptInitial,
    constructionDigest,
    roots[0]!,
    roots[1]!,
  );
  const expectedInteractionChallenges = localWordInteractionChallengeValues(challenges);
  if (transcriptManifest.interactionChallenges.some((challenge, index) =>
    !qmEq(challenge, expectedInteractionChallenges[index]!))) {
    throw new Error("local-word interaction challenge manifest");
  }
  const expectedClaim = poolLocalBoundaryClaimForWords(context.publicWords, challenges.boundary);
  if (publicBoundaryInverses.length !== expectedClaim.publicInverses.length ||
    publicBoundaryInverses.some((inverse, index) => !qmEq(inverse, expectedClaim.publicInverses[index]!)) ||
    !qmEq(publicBoundaryClaimedSum, expectedClaim.claimedSum)) {
    throw new Error("local-word public boundary inverses");
  }
  localWordPublicBoundaryTranscript(transcript, publicBoundaryInverses);
  if (!eq32(transcriptManifest.interactionDigest, transcript.digest)) {
    throw new Error("local-word interaction digest manifest");
  }
  const composition = localWordCompositionTranscript(
    transcript,
    roots[2]!,
    roots[3]!,
  );
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
  if (!transcript.acceptGrind(parameters.fri.grindBits, grindNonce)) throw new Error("local-word FRI grind");
  if (!eq32(transcript.digest, transcriptManifest.queryDigest)) {
    throw new Error("local-word query digest manifest");
  }
  const queries = localWordQueryIndices(transcript, parameters);
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
      MATRIX_LABELS[name],
      LOCAL_WORD_MATRIX_ROW_WIDTHS[index]!,
      index === 3 ? schedules.global : schedules.current,
      rowCount,
      localWordMatrixMerkleStageGeometry(name),
      expectedDirectory.openings[index]!,
      index === 3,
    ),
  ] as const);
  const matrices = Object.fromEntries(decodedMatrices) as Record<LocalWordMatrixName, LocalWordMatrixOpening>;
  const layers: SuccessorFriLayerProof[] = schedules.fri.map((indices, round) => {
    if (indices.some((index) => cursor.u32() !== index)) {
      throw new Error("local-word FRI index manifest");
    }
    const values = Array.from({ length: indices.length }, () => cursor.qm31());
    const siblings = Array.from(
      { length: localWordCanonicalSiblingCount(
        indices,
        2 ** localWordFriLayerLogs(parameters)[round]!,
      ) },
      () => cursor.take(32),
    );
    const expectedFrontier = openingFrontierBundle(
      `fri:layer:${round}`,
      indices,
      values.map(encodeQm31),
      siblings,
      2 ** localWordFriLayerLogs(parameters)[round]!,
      LOCAL_WORD_FRI_MERKLE_STAGE_GEOMETRY,
      expectedDirectory.openings[LOCAL_WORD_MATRIX_NAMES.length + round]!,
    );
    if (!equal(cursor.take(expectedFrontier.length), expectedFrontier)) {
      throw new Error("local-word FRI frontier");
    }
    return { root: friRoots[round]!, indices, values, siblings };
  });
  if (cursor.offset !== bytes.length) throw new Error("trailing local-word proof bytes");
  const proof: LocalWordSealedProof = {
    version,
    profile,
    constructionDigest,
    proofLength,
    publicBoundaryInverses,
    publicBoundaryClaimedSum,
    matrices,
    fri: { layers, finalCoefficients, grindNonce },
    transcriptManifest,
    compositionPartials,
    queries,
  };
  if (!equal(encodeLocalWordSealedProof(proof, parameters), bytes)) throw new Error("non-canonical local-word proof");
  return proof;
}

/** Exact byte ownership map; frames partition the canonical proof without repacking. */
export function frameLocalWordSealedProof(proof: LocalWordSealedProof): LocalWordProofFrame[] {
  const frames: LocalWordProofFrame[] = [];
  const schedules = localWordOpeningSchedules(proof.queries);
  const directory = localWordProofDirectory(proof.queries, proof.publicBoundaryInverses.length);
  let offset = 0;
  const take = (width: number, frame: Omit<LocalWordProofFrame, "start" | "end">): void => {
    frames.push({ ...frame, start: offset, end: offset + width });
    offset += width;
  };
  take(LOCAL_WORD_PROOF_FIXED_PREFIX_BYTES, { kind: "header" });
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
  proof.compositionPartials.forEach((partials, item) => partials.forEach((_, layer) =>
    take(16, { kind: "composition-partial", item, layer })));
  LOCAL_WORD_MATRIX_NAMES.forEach((matrix, matrixIndex) => {
    const opening = proof.matrices[matrix];
    if (matrixIndex === 3) opening.indices.forEach((_, item) =>
      take(4, { kind: "opening-index", matrix, item }));
    opening.rows.forEach((row, item) => take(row.length, { kind: "matrix-row", matrix, item }));
    opening.siblings.forEach((_, item) => take(32, { kind: "matrix-sibling", matrix, item }));
    const frontiers = localWordMerkleFrontierSchedules(
      opening.indices,
      2 ** LOCAL_WORD_LDE_LOG,
      localWordMatrixMerkleStageGeometry(matrix),
    );
    frontiers.forEach((_, item) => take(12, { kind: "opening-stage-directory", matrix, item }));
    frontiers.forEach((frontier, boundary) => frontier.indices.forEach((_, item) =>
      take(36, { kind: "matrix-frontier", matrix, item: boundary * 256 + item })));
  });
  proof.fri.layers.forEach((layer, round) => {
    layer.indices.forEach((_, item) => take(4, { kind: "opening-index", layer: round, item }));
    layer.values.forEach((_, item) => take(16, { kind: "fri-value", layer: round, item }));
    layer.siblings.forEach((_, item) => take(32, { kind: "fri-sibling", layer: round, item }));
    const frontiers = localWordMerkleFrontierSchedules(
      layer.indices,
      2 ** localWordFriLayerLogs(LOCAL_WORD_PRODUCTION_PARAMETERS)[round]!,
      LOCAL_WORD_FRI_MERKLE_STAGE_GEOMETRY,
    );
    frontiers.forEach((_, item) => take(12, { kind: "opening-stage-directory", layer: round, item }));
    frontiers.forEach((frontier, boundary) => frontier.indices.forEach((_, item) =>
      take(36, { kind: "fri-frontier", layer: round, item: boundary * 256 + item })));
  });
  if (offset !== proof.proofLength) throw new Error("local-word proof frame coverage");
  return frames;
}

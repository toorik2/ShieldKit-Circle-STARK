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
  QM31_FIELD_BITS,
  type QM31El,
} from "../backends/circle/qm31.ts";
import type { PoolLocalShaGraph, PoolLocalShaInput } from "./pool-relation-local-word-machine.ts";
import { LOCAL_WORD_QUERIES } from "../backends/circle/local-word-successor-params.ts";
import {
  LOCAL_SHA_LIMBS,
  executeLocalShaProgram,
  localShaGeometry,
  localShaWordLimbs,
  type LocalShaExecution,
  type LocalShaGeometry,
  type LocalShaViolation,
} from "./sha256-local-word-machine.ts";

export type PoolLocalBoundaryChallenges = {
  readonly gamma: QM31El;
  readonly identity: QM31El;
  readonly limbs: readonly QM31El[];
};

export type PoolLocalBoundaryWord = {
  readonly id: bigint;
  readonly row: number;
  readonly expected: number;
};

export type PoolLocalBoundaryTrace = {
  readonly words: readonly PoolLocalBoundaryWord[];
  /** Public, verifier-checked inverses of the statement-owned denominators. */
  readonly publicInverses: readonly QM31El[];
  /** Row-local witness fraction, then the global access-minus-table sum. */
  readonly columns: readonly [readonly QM31El[], readonly QM31El[]];
  /** Sum of `publicInverses`, injected once by the fixed impulse column. */
  readonly claimedSum: QM31El;
};

export type PoolLocalBoundaryPublicClaim = {
  readonly words: readonly PoolLocalBoundaryWord[];
  readonly publicInverses: readonly QM31El[];
  readonly claimedSum: QM31El;
};

export type PoolLocalShaGeometry = LocalShaGeometry & {
  readonly publicBoundaryPreprocessedColumns: 3;
  readonly publicBoundaryInteractionQm31Columns: 2;
};

export type PoolLocalShaSoundnessProjection = {
  readonly boundaryTerms: number;
  readonly boundaryBits: number;
  readonly conservativeUnionBits: number;
  readonly meetsFloor: boolean;
  readonly claimBoundary: "projection-pending-quotient-and-transcript-integration";
};

function publicWords(graph: PoolLocalShaGraph): readonly PoolLocalShaInput[] {
  return graph.inputLayout.filter((input) => input.visibility === "public");
}

export function poolLocalBoundaryPublicClaim(
  graph: PoolLocalShaGraph,
  challenges: PoolLocalBoundaryChallenges,
): PoolLocalBoundaryPublicClaim {
  const words = publicWords(graph).map((input, index): PoolLocalBoundaryWord => ({
    id: BigInt(index + 1),
    row: input.wire,
    expected: input.value,
  }));
  return poolLocalBoundaryClaimForWords(words, challenges);
}

/** Statement-only boundary claim shared by proof codecs and the relation builder. */
export function poolLocalBoundaryClaimForWords(
  words: readonly PoolLocalBoundaryWord[],
  challenges: PoolLocalBoundaryChallenges,
): PoolLocalBoundaryPublicClaim {
  if (words.length < 1 || words.length > 1024 || words.some((word, index) =>
    word.id !== BigInt(index + 1) || !Number.isInteger(word.row) || word.row < 0 ||
    !Number.isInteger(word.expected) || word.expected < 0 || word.expected > 0xffff_ffff)) {
    throw new Error("pool local boundary public words");
  }
  const publicInverses = words.map((word) => qmInv(factor(word.id, word.expected, challenges)));
  return {
    words,
    publicInverses,
    claimedSum: publicInverses.reduce(qmAdd, QM31_ZERO),
  };
}

function factor(
  id: bigint,
  value: number,
  challenges: PoolLocalBoundaryChallenges,
): QM31El {
  if (challenges.limbs.length !== LOCAL_SHA_LIMBS) throw new Error("pool local boundary challenges");
  let result = qmAdd(challenges.gamma, qmMul(challenges.identity, liftM31(id)));
  const limbs = localShaWordLimbs(value);
  for (let limb = 0; limb < LOCAL_SHA_LIMBS; limb += 1) {
    result = qmAdd(result, qmMul(challenges.limbs[limb]!, liftM31(limbs[limb]!)));
  }
  return result;
}

/**
 * One LogUp access column binds public-row witness words to a verifier-computed
 * public sum. Expected values never enter a proof-controlled preprocessing root.
 */
export function buildPoolLocalBoundaryTrace(
  graph: PoolLocalShaGraph,
  execution: LocalShaExecution,
  challenges: PoolLocalBoundaryChallenges,
): PoolLocalBoundaryTrace {
  if (execution.wireValues.length !== graph.program.rows.length) throw new Error("pool local boundary execution");
  const { words, publicInverses, claimedSum } = poolLocalBoundaryPublicClaim(graph, challenges);
  const byRow = new Map(words.map((word) => [word.row, word]));
  if (byRow.size !== words.length) throw new Error("pool local boundary row uniqueness");
  const relationRows = graph.relationRows;
  const accessColumn: QM31El[] = [];
  const globalColumn: QM31El[] = [];
  let global = QM31_ZERO;
  for (let row = 0; row < relationRows; row += 1) {
    const word = byRow.get(row);
    const access = word ? qmInv(factor(word.id, execution.wireValues[row]!, challenges)) : QM31_ZERO;
    accessColumn.push(access);
    global = qmAdd(global, access);
    if (row === 0) global = qmSub(global, claimedSum);
    globalColumn.push(global);
  }
  if (!qmEq(global, QM31_ZERO)) throw new Error("pool local boundary LogUp");
  return { words, publicInverses, columns: [accessColumn, globalColumn], claimedSum };
}

/** First recurrence or terminal mismatch. */
export function verifyPoolLocalBoundaryTrace(
  graph: PoolLocalShaGraph,
  execution: LocalShaExecution,
  trace: PoolLocalBoundaryTrace,
  challenges: PoolLocalBoundaryChallenges,
): LocalShaViolation | undefined {
  const relationRows = graph.relationRows;
  const expectedWords = publicWords(graph).map((input, index): PoolLocalBoundaryWord => ({
    id: BigInt(index + 1), row: input.wire, expected: input.value,
  }));
  if (trace.columns.length !== 2 || trace.columns.some((column) => column.length !== relationRows) ||
    trace.words.length !== expectedWords.length || trace.publicInverses.length !== expectedWords.length ||
    trace.words.some((word, index) => word.id !== expectedWords[index]!.id ||
      word.row !== expectedWords[index]!.row || word.expected !== expectedWords[index]!.expected)) {
    return { row: -1, constraint: "public-boundary-shape" };
  }
  let claimedSum = QM31_ZERO;
  for (let index = 0; index < expectedWords.length; index += 1) {
    const word = expectedWords[index]!;
    const inverse = trace.publicInverses[index]!;
    if (!qmEq(qmMul(inverse, factor(word.id, word.expected, challenges)), QM31_ONE)) {
      return { row: -1, constraint: `public-boundary-inverse:${index}` };
    }
    claimedSum = qmAdd(claimedSum, inverse);
  }
  if (!qmEq(claimedSum, trace.claimedSum)) {
    return { row: -1, constraint: "public-boundary-claimed-sum" };
  }
  const byRow = new Map(trace.words.map((word) => [word.row, word]));
  for (let row = 0; row < relationRows; row += 1) {
    const previousGlobal = trace.columns[1]![row === 0 ? relationRows - 1 : row - 1]!;
    const word = byRow.get(row);
    const selector = word ? QM31_ONE : QM31_ZERO;
    const accessDenominator = word
      ? factor(word.id, execution.wireValues[row]!, challenges)
      : challenges.gamma;
    if (!qmEq(qmMul(trace.columns[0]![row]!, accessDenominator), selector)) {
      return { row, constraint: "public-boundary-access" };
    }
    const globalDifference = qmSub(
      qmSub(trace.columns[1]![row]!, previousGlobal),
      trace.columns[0]![row]!,
    );
    const expectedDifference = row === 0 ? qmNeg(trace.claimedSum) : QM31_ZERO;
    if (!qmEq(globalDifference, expectedDifference)) {
      return { row, constraint: "public-boundary-global" };
    }
  }
  if (!qmEq(trace.columns[1]![relationRows - 1]!, QM31_ZERO)) {
    return { row: relationRows - 1, constraint: "public-boundary-sum" };
  }
  return undefined;
}

/** Complete pool direct-opening geometry, including the public boundary product. */
export function poolLocalShaGeometry(graph: PoolLocalShaGraph, queries = LOCAL_WORD_QUERIES): PoolLocalShaGeometry {
  const base = localShaGeometry(graph.program, queries, undefined, graph.relationRows);
  // Current access+global values are opened; only the global column needs its predecessor.
  const openedM31ValuesPerQuery = base.openedM31ValuesPerQuery + 3 + 2 * 4 + 4;
  return {
    ...base,
    openedM31ValuesPerQuery,
    directValueBytes: openedM31ValuesPerQuery * 4 * queries,
    publicBoundaryPreprocessedColumns: 3,
    publicBoundaryInteractionQm31Columns: 2,
  };
}

/** Fixed selector/id and one-row sum impulse appended to the core microcode table. */
export function poolLocalBoundaryPreprocessedAt(
  graph: PoolLocalShaGraph,
  row: number,
): readonly bigint[] {
  const words = publicWords(graph);
  const index = words.findIndex((input) => input.wire === row);
  return [index < 0 ? 0n : 1n, index < 0 ? 0n : BigInt(index + 1), row === 0 ? 1n : 0n];
}

/** Conservative random-product term for the complete public word boundary. */
export function poolLocalShaSoundnessProjection(
  graph: PoolLocalShaGraph,
  baseConservativeUnionBits: number,
  floorBits = 100,
): PoolLocalShaSoundnessProjection {
  const boundaryTerms = graph.relationRows * (LOCAL_SHA_LIMBS + 1);
  const boundaryBits = QM31_FIELD_BITS - Math.log2(boundaryTerms);
  const conservativeUnionBits = -Math.log2(
    2 ** -baseConservativeUnionBits + 2 ** -boundaryBits,
  );
  return {
    boundaryTerms,
    boundaryBits,
    conservativeUnionBits,
    meetsFloor: conservativeUnionBits >= floorBits,
    claimBoundary: "projection-pending-quotient-and-transcript-integration",
  };
}

export function executePoolLocalShaGraph(graph: PoolLocalShaGraph): LocalShaExecution {
  return executeLocalShaProgram(graph.program, graph.inputs);
}

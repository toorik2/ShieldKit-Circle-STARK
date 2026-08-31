import { maximumV17MerkleOpening } from "../backends/circle/v17-merkle.ts";
import {
  maximumAllowedAdjustedRound,
  minimalGrindingBits,
  v17FriJohnsonBounds,
  type V17FriJohnsonBounds,
} from "./v17-soundness.ts";
import {
  rational,
  rAdd,
  rSub,
  type Rational,
  ONE,
} from "./rational.ts";

export type V17FriParameterCandidate = {
  readonly logBlowup: number;
  readonly evaluationLog: number;
  /** The exact M used by the Theorem-19 batching bound. */
  readonly batchWidth: number;
  readonly queries: number;
  readonly theta: Rational;
  readonly friRoundCount: number;
  /** Seventeen exact binary reductions, before deterministic commitment grouping. */
  readonly binaryFoldBounds: readonly Rational[];
  /** Eight radix-four commitment rounds and one binary tail. */
  readonly foldChallengeCounts: readonly (1 | 2)[];
  readonly grindingBits: {
    readonly batch: number;
    readonly folds: readonly number[];
    readonly query: number;
    readonly maximum: number;
    readonly total: number;
  };
  /** Rows and sibling hashes, before generated cut frontiers and transaction code. */
  readonly proofCoreCeiling: {
    readonly fixedBytes: number;
    readonly openedRowBytes: number;
    readonly authenticationNodes: number;
    readonly authenticationBytes: number;
    readonly totalBytes: number;
  };
  readonly bounds: V17FriJohnsonBounds;
};

export type V17FriSynthesisInput = {
  readonly logBlowups: readonly number[];
  readonly minimumQueries: number;
  readonly maximumQueries: number;
  readonly maximumRoundGrindingBits: number;
  readonly batchWidth: number;
  /** Number of non-FRI public-coin rounds included in the BCS round count. */
  readonly precedingRounds: number;
  readonly thetaGridDenominator?: number;
};

function productionBinaryFoldDomainLogs(evaluationLog: number): readonly number[] {
  return Array.from({ length: 17 }, (_, round) => evaluationLog - 1 - round);
}

export function groupV17BinaryFoldBounds(
  errors: readonly Rational[],
): readonly Rational[] {
  if (errors.length !== 17) throw new Error("v17 production binary fold count");
  return Array.from({ length: 9 }, (_, group) => group < 8
    ? rAdd(errors[2 * group]!, errors[2 * group + 1]!)
    : errors[16]!);
}

function proofCoreCeiling(logBlowup: number, queries: number): V17FriParameterCandidate["proofCoreCeiling"] {
  const evaluationLog = 20 + logBlowup;
  const matrix = (openedLeaves: number): number => maximumV17MerkleOpening({
    shape: "binary",
    label: "synthesis:matrix",
    logRows: evaluationLog,
    rowWidth: 16,
  }, { openedLeaves }).siblingCount;
  const matrixNodes = 4 * matrix(queries) + matrix(2 * queries);
  let friNodes = 0;
  for (let layer = 0; layer < 9; layer += 1) {
    friNodes += maximumV17MerkleOpening({
      shape: layer < 8 ? "quartet-first" : "binary",
      label: `synthesis:fri:${layer}`,
      logRows: evaluationLog - 2 * layer,
      rowWidth: 16,
    }, { completeFirstGroups: queries }).siblingCount;
  }
  const authenticationNodes = matrixNodes + friNodes;
  // Non-query fixed prefix is 1,846 bytes; query/rank manifests are 20q.
  const fixedBytes = 1_846 + 20 * queries;
  // Five matrix bodies: 660q. FRI bodies: eight quartets plus one pair = 544q.
  const openedRowBytes = 1_204 * queries;
  const authenticationBytes = 32 * authenticationNodes;
  return {
    fixedBytes,
    openedRowBytes,
    authenticationNodes,
    authenticationBytes,
    totalBytes: fixedBytes + openedRowBytes + authenticationBytes,
  };
}

function safeInteger(value: number, label: string): number {
  if (!Number.isSafeInteger(value) || value < 1) throw new Error(`v17 synthesis ${label}`);
  return value;
}

function candidateOrder(left: V17FriParameterCandidate, right: V17FriParameterCandidate): number {
  return left.proofCoreCeiling.totalBytes - right.proofCoreCeiling.totalBytes ||
    left.grindingBits.total - right.grindingBits.total ||
    left.grindingBits.maximum - right.grindingBits.maximum ||
    left.logBlowup - right.logBlowup ||
    left.queries - right.queries ||
    Number(left.theta.numerator * right.theta.denominator -
      right.theta.numerator * left.theta.denominator);
}

function rDivExact(left: Rational, right: Rational): Rational {
  if (right.numerator === 0n) throw new Error("v17 synthesis rational division");
  return rational(left.numerator * right.denominator, left.denominator * right.numerator);
}

function reducedPower(base: Rational, exponent: number): Rational {
  // `base` is already reduced, so independently exponentiating its numerator
  // and denominator remains reduced; avoid an unnecessary large gcd.
  return {
    numerator: base.numerator ** BigInt(exponent),
    denominator: base.denominator ** BigInt(exponent),
  };
}

/**
 * Enumerate only S-two Theorem-19 Johnson parameters. This numerical search
 * cannot qualify a construction: AIR reduction, grouped-fold correspondence,
 * cut frontiers, linker output, and the exact transaction remain separate
 * fail-closed gates.
 */
export function synthesizeV17FriParameters(
  input: V17FriSynthesisInput,
): readonly V17FriParameterCandidate[] {
  safeInteger(input.minimumQueries, "minimum queries");
  safeInteger(input.maximumQueries, "maximum queries");
  safeInteger(input.maximumRoundGrindingBits, "maximum grinding");
  safeInteger(input.batchWidth, "batch width");
  safeInteger(input.precedingRounds, "preceding rounds");
  if (input.minimumQueries > input.maximumQueries || input.maximumRoundGrindingBits > 255 ||
    input.logBlowups.length < 1 || input.logBlowups.some((log) =>
      !Number.isSafeInteger(log) || log < 2 || log > 10 || (log & 1) !== 0)) {
    throw new Error("v17 synthesis range");
  }
  const denominator = input.thetaGridDenominator ?? 256;
  safeInteger(denominator, "theta denominator");
  const candidates: V17FriParameterCandidate[] = [];
  const friRoundCount = 11;
  const allowed = maximumAllowedAdjustedRound(input.precedingRounds + friRoundCount);
  const proofCeilings = new Map<string, V17FriParameterCandidate["proofCoreCeiling"]>();
  for (const logBlowup of input.logBlowups) {
    const evaluationLog = 20 + logBlowup;
    const rate = rational(1n, 1n << BigInt(logBlowup));
    const lower = rDivExact(rSub(ONE, rate), rational(2n));
    const sqrtRate = rational(1n, 1n << BigInt(logBlowup / 2));
    const upper = rSub(ONE, sqrtRate);
    const firstNumerator = Number((lower.numerator * BigInt(denominator) +
      lower.denominator - 1n) / lower.denominator);
    const lastNumeratorExclusive = Number(
      (upper.numerator * BigInt(denominator) + upper.denominator - 1n) / upper.denominator,
    );
    for (let thetaNumerator = firstNumerator;
      thetaNumerator < lastNumeratorExclusive;
      thetaNumerator += 1) {
      const theta = rational(BigInt(thetaNumerator), BigInt(denominator));
      // Compute field rounds once per theta; only the query term changes with q.
      let base: V17FriJohnsonBounds;
      let binaryFoldBounds: readonly Rational[];
      try {
        const binary = v17FriJohnsonBounds({
          logBlowup,
          evaluationLog,
          batchWidth: input.batchWidth,
          foldDomainLogs: productionBinaryFoldDomainLogs(evaluationLog),
          queries: 1,
          theta,
        });
        binaryFoldBounds = binary.folds;
        base = { ...binary, folds: groupV17BinaryFoldBounds(binary.folds) };
      } catch {
        continue;
      }
      const fixedErrors = [base.batch, ...base.folds];
      const fixedBits = fixedErrors.map((error) => minimalGrindingBits(error, allowed));
      const alpha = rSub(ONE, theta);
      for (let queries = input.minimumQueries; queries <= input.maximumQueries; queries += 1) {
        const query = reducedPower(alpha, queries);
        const bounds: V17FriJohnsonBounds = { ...base, query };
        const bits = [...fixedBits, minimalGrindingBits(query, allowed)];
        const maximum = Math.max(...bits);
        if (maximum > input.maximumRoundGrindingBits) continue;
        const batch = bits[0]!;
        const folds = bits.slice(1, -1);
        const queryBits = bits.at(-1)!;
        candidates.push({
          logBlowup,
          evaluationLog,
          batchWidth: input.batchWidth,
          queries,
          theta,
          friRoundCount,
          binaryFoldBounds,
          foldChallengeCounts: [2, 2, 2, 2, 2, 2, 2, 2, 1],
          grindingBits: {
            batch,
            folds,
            query: queryBits,
            maximum,
            total: bits.reduce((sum, value) => sum + value, 0),
          },
          proofCoreCeiling: (() => {
            const key = `${logBlowup}:${queries}`;
            const cached = proofCeilings.get(key);
            if (cached !== undefined) return cached;
            const ceiling = proofCoreCeiling(logBlowup, queries);
            proofCeilings.set(key, ceiling);
            return ceiling;
          })(),
          bounds,
        });
      }
    }
  }
  return candidates.sort(candidateOrder);
}

export function defaultV17FriParameterCandidates(): readonly V17FriParameterCandidate[] {
  return synthesizeV17FriParameters({
    logBlowups: [4, 6],
    minimumQueries: 29,
    maximumQueries: 64,
    maximumRoundGrindingBits: 32,
    batchWidth: 27,
    precedingRounds: 3,
    thetaGridDenominator: 256,
  });
}

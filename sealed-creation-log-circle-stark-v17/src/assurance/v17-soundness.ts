import {
  ONE,
  ZERO,
  rational,
  rAdd,
  rCeil,
  rCompare,
  rDiv,
  rMax,
  rMin,
  rMul,
  rPow,
  rPow2,
  rSqrtInterval,
  rSub,
  type Rational,
} from "./rational.ts";

export const V17_RANDOM_ORACLE_BITS = 256;
export const V17_WORK_FACTOR_BITS = 100;
export const V17_ATTACKER_QUERY_LIMIT_EXCLUSIVE = 1n << 128n;
export const V17_QM31_MODULUS = (1n << 31n) - 1n;
export const V17_QM31_CARDINALITY = V17_QM31_MODULUS ** 4n;

export type TheoremStatus =
  | "cited"
  | "proved"
  | "conjectural"
  | "unresolved"
  | "skipped"
  | "cache-only";

export type V17SoundnessRound = {
  readonly id: string;
  readonly dependsOn: readonly string[];
  readonly rawError: Rational;
  readonly grindBits: number;
  readonly status: TheoremStatus;
  readonly theorem: string;
};

export type V17WorkFactorCertificate = {
  readonly qualified: boolean;
  readonly reasons: readonly string[];
  readonly rounds: number;
  readonly weakestAdjustedRound: Rational;
  readonly maximumAllowedRound: Rational;
  readonly endpoints: readonly {
    readonly attackerQueries: bigint;
    readonly perQueryError: Rational;
    readonly passes: boolean;
  }[];
};

function validateRoundDag(rounds: readonly V17SoundnessRound[]): void {
  if (rounds.length < 1) throw new Error("v17 soundness round DAG empty");
  const seen = new Set<string>();
  for (const round of rounds) {
    if (!/^[a-z0-9][a-z0-9:-]*$/.test(round.id) || seen.has(round.id) ||
      !Number.isSafeInteger(round.grindBits) || round.grindBits < 0 || round.grindBits > 255 ||
      rCompare(round.rawError, ZERO) < 0 || rCompare(round.rawError, ONE) > 0 || !round.theorem) {
      throw new Error(`v17 soundness round ${round.id}`);
    }
    if (round.dependsOn.some((dependency) => !seen.has(dependency))) {
      throw new Error(`v17 soundness DAG order ${round.id}`);
    }
    seen.add(round.id);
  }
}

export function adjustedRoundError(round: V17SoundnessRound): Rational {
  return rDiv(round.rawError, rPow2(round.grindBits));
}

/**
 * Theorem 22 of the S-two whitepaper, divided by T:
 * (1 + R/T)e + 3(T + 1/T)/2^lambda.
 */
export function bcsPerQueryError(
  attackerQueries: bigint,
  rounds: number,
  weakestRound: Rational,
  lambda = V17_RANDOM_ORACLE_BITS,
): Rational {
  if (attackerQueries < 1n || !Number.isSafeInteger(rounds) || rounds < 1 ||
    !Number.isSafeInteger(lambda) || lambda < 1) {
    throw new Error("v17 BCS parameters");
  }
  const t = rational(attackerQueries);
  const stateRestoration = rMul(
    rAdd(ONE, rDiv(rational(BigInt(rounds)), t)),
    weakestRound,
  );
  const collision = rDiv(
    rMul(rational(3n), rAdd(t, rDiv(ONE, t))),
    rPow2(lambda),
  );
  return rAdd(stateRestoration, collision);
}

export function maximumAllowedAdjustedRound(
  rounds: number,
  workFactorBits = V17_WORK_FACTOR_BITS,
): Rational {
  const target = rPow2(-workFactorBits);
  const endpoints = [1n, V17_ATTACKER_QUERY_LIMIT_EXCLUSIVE - 1n];
  return rMin(endpoints.map((attackerQueries) => {
    const t = rational(attackerQueries);
    const collision = rDiv(
      rMul(rational(3n), rAdd(t, rDiv(ONE, t))),
      rPow2(V17_RANDOM_ORACLE_BITS),
    );
    const remaining = rSub(target, collision);
    if (rCompare(remaining, ZERO) <= 0) throw new Error("v17 collision term exceeds target");
    return rDiv(
      remaining,
      rAdd(ONE, rDiv(rational(BigInt(rounds)), t)),
    );
  }));
}

export function minimalGrindingBits(rawError: Rational, allowed: Rational): number {
  if (rCompare(rawError, ZERO) < 0 || rCompare(allowed, ZERO) <= 0) {
    throw new Error("v17 grinding bound");
  }
  // Compare raw / 2^bits <= allowed without constructing and reducing 256
  // progressively larger rationals. This remains exact and makes parameter
  // enumeration a focused check rather than a minute-long bigint-GCD suite.
  const left = rawError.numerator * allowed.denominator;
  const rightBase = allowed.numerator * rawError.denominator;
  for (let bits = 0; bits <= 255; bits += 1) {
    if (left <= (rightBase << BigInt(bits))) return bits;
  }
  throw new Error("v17 grinding exceeds one-byte encoding");
}

/** Convexity makes the two endpoints sufficient for every integer T in range. */
export function certifyV17WorkFactor(
  rounds: readonly V17SoundnessRound[],
): V17WorkFactorCertificate {
  validateRoundDag(rounds);
  const allowed = maximumAllowedAdjustedRound(rounds.length);
  const weakest = rMax(rounds.map(adjustedRoundError));
  const target = rPow2(-V17_WORK_FACTOR_BITS);
  const endpoints = [1n, V17_ATTACKER_QUERY_LIMIT_EXCLUSIVE - 1n].map((attackerQueries) => {
    const perQueryError = bcsPerQueryError(attackerQueries, rounds.length, weakest);
    return { attackerQueries, perQueryError, passes: rCompare(perQueryError, target) <= 0 };
  });
  const reasons = rounds
    .filter((round) => round.status !== "cited" && round.status !== "proved")
    .map((round) => `${round.id}:${round.status}`);
  if (rCompare(weakest, allowed) > 0) reasons.push("work-factor-floor");
  if (endpoints.some((endpoint) => !endpoint.passes)) reasons.push("BCS-endpoint");
  return {
    qualified: reasons.length === 0,
    reasons,
    rounds: rounds.length,
    weakestAdjustedRound: weakest,
    maximumAllowedRound: allowed,
    endpoints,
  };
}

/** Exact maximum point probability for four fixed SHA-256 reductions mod M31. */
export function qm31ChallengeMaximumProbability(): Rational {
  const sampleSpace = 1n << 256n;
  const maximumCoordinatePreimages = sampleSpace / V17_QM31_MODULUS + 1n;
  return rPow(rational(maximumCoordinatePreimages, sampleSpace), 4);
}

export type V17FriJohnsonInput = {
  readonly logBlowup: number;
  readonly evaluationLog: number;
  readonly batchWidth: number;
  readonly foldDomainLogs: readonly number[];
  readonly queries: number;
  readonly theta: Rational;
};

export type V17FriJohnsonBounds = {
  readonly regime: "johnson";
  readonly batch: Rational;
  readonly folds: readonly Rational[];
  readonly query: Rational;
  readonly listBounds: readonly Rational[];
};

function gsListUpper(theta: Rational, rate: Rational): Rational {
  const { lower: sqrtLower, upper: sqrtUpper } = rSqrtInterval(rate);
  const alpha = rSub(ONE, theta);
  if (rCompare(alpha, sqrtUpper) <= 0 || rCompare(sqrtLower, ZERO) <= 0) {
    throw new Error("v17 Johnson list radius");
  }
  const multiplicity = rCeil(rDiv(
    sqrtUpper,
    rMul(rational(2n), rSub(alpha, sqrtUpper)),
  ));
  const m = multiplicity < 3n ? 3n : multiplicity;
  return rDiv(rational(2n * m + 1n, 2n), sqrtLower);
}

function theorem19FieldRound(
  list: Rational,
  rate: Rational,
  domainSize: bigint,
  leadingFactor: bigint,
): Rational {
  const collisionMultiplicity = rAdd(
    rMul(rDiv(rMul(rational(2n), rPow(list, 4)), rational(3n)), rate),
    ONE,
  );
  return rMul(
    rMul(rMul(rational(leadingFactor), list), collisionMultiplicity),
    rMul(rational(domainSize), qm31ChallengeMaximumProbability()),
  );
}

/** Exact/outward-rounded Johnson-regime instantiation of S-two Theorem 19. */
export function v17FriJohnsonBounds(input: V17FriJohnsonInput): V17FriJohnsonBounds {
  if (!Number.isSafeInteger(input.logBlowup) || input.logBlowup < 1 ||
    !Number.isSafeInteger(input.evaluationLog) || input.evaluationLog < 2 ||
    !Number.isSafeInteger(input.batchWidth) || input.batchWidth < 2 ||
    !Number.isSafeInteger(input.queries) || input.queries < 1 ||
    input.foldDomainLogs.length < 1 || input.foldDomainLogs.some(
      (log) => !Number.isSafeInteger(log) || log < 1 || log > input.evaluationLog,
    )) {
    throw new Error("v17 FRI Johnson input");
  }
  const rate = rPow2(-input.logBlowup);
  const delta = rSub(ONE, rate);
  const sqrtRate = rSqrtInterval(rate);
  if (rCompare(input.theta, rDiv(delta, rational(2n))) < 0 ||
    rCompare(input.theta, rSub(ONE, sqrtRate.lower)) >= 0) {
    throw new Error("v17 FRI outside proven Johnson regime");
  }
  const baseList = gsListUpper(input.theta, rate);
  const batch = theorem19FieldRound(
    baseList,
    rate,
    1n << BigInt(input.evaluationLog),
    BigInt(input.batchWidth - 1),
  );
  const listBounds: Rational[] = [];
  const folds = input.foldDomainLogs.map((domainLog) => {
    const domainSize = 1n << BigInt(domainLog);
    const adjustedRate = rSub(rate, rational(1n, domainSize));
    if (rCompare(adjustedRate, ZERO) <= 0) throw new Error("v17 FRI fold code rate");
    const list = gsListUpper(input.theta, adjustedRate);
    listBounds.push(list);
    return theorem19FieldRound(list, adjustedRate, domainSize, 3n);
  });
  return {
    regime: "johnson",
    batch,
    folds,
    query: rPow(rSub(ONE, input.theta), input.queries),
    listBounds,
  };
}

export function withMinimalGrinding(
  rounds: readonly Omit<V17SoundnessRound, "grindBits">[],
): readonly V17SoundnessRound[] {
  const allowed = maximumAllowedAdjustedRound(rounds.length);
  return rounds.map((round) => ({
    ...round,
    grindBits: minimalGrindingBits(round.rawError, allowed),
  }));
}

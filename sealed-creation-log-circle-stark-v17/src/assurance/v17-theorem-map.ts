import {
  ONE,
  ZERO,
  rational,
  rAdd,
  rCompare,
  rDiv,
  rMul,
  rPow,
  rSub,
  type Rational,
} from "./rational.ts";
import {
  certifyV17WorkFactor,
  minimalGrindingBits,
  maximumAllowedAdjustedRound,
  qm31ChallengeMaximumProbability,
  type TheoremStatus,
  type V17SoundnessRound,
  type V17WorkFactorCertificate,
} from "./v17-soundness.ts";
import type { V17FriParameterCandidate } from "./v17-parameter-synthesis.ts";

/** M31 and the exact cardinalities used by the S-two theorem instantiation. */
export const V17_THEOREM_M31 = (1n << 31n) - 1n;
export const V17_THEOREM_QM31_SIZE = V17_THEOREM_M31 ** 4n;
export const V17_THEOREM_QM31_CIRCLE_SIZE = V17_THEOREM_QM31_SIZE - 1n;
export const V17_THEOREM_M31_CIRCLE_SIZE = V17_THEOREM_M31 + 1n;
export const V17_THEOREM_OOD_POINT_SET_SIZE =
  V17_THEOREM_QM31_CIRCLE_SIZE - V17_THEOREM_M31_CIRCLE_SIZE;

export type V17FlatAirTable = {
  readonly id: string;
  /** N_t in S-two Theorem 15. */
  readonly rows: bigint;
  /** k_t ordinary component constraints. */
  readonly constraints: bigint;
  /** r_t LogUp use messages. */
  readonly uses: bigint;
  /** s_t LogUp yield messages. */
  readonly yields: bigint;
  /** Maximum rho/sigma vector dimension for this table. */
  readonly maximumMessageDimension: bigint;
  /** Proven upper bound on every multiplicity encoded by this table. */
  readonly maximumMultiplicity: bigint;
};

export type V17FlatAirTheoremInput = {
  readonly inputMessages: bigint;
  readonly outputMessages: bigint;
  /** An odd conservative upper bound deg(A), as required by Protocol 1. */
  readonly airDegree: bigint;
  readonly theta: Rational;
  readonly logBlowup: number;
  readonly tables: readonly V17FlatAirTable[];
  /**
   * Maximum mass of the canonical OOD-point sampler. Uniform sampling uses
   * exactly 1 / |C(QM31) \\ C(M31)|. A biased sampler must supply and prove a
   * larger value rather than silently using the uniform theorem.
   */
  readonly oodPointMaximumProbability: Rational;
};

export type V17Theorem15Bounds = {
  readonly listSize: Rational;
  readonly logup: Rational;
  readonly composition: Rational;
  readonly outOfDomain: Rational;
  readonly technicalCondition54: boolean;
  readonly multiplicitiesBelowCharacteristic: boolean;
};

/** Exact combinatorial Johnson list bound in S-two (2026/532), equation 53. */
export function v17Theorem15JohnsonListSize(theta: Rational, logBlowup: number): Rational {
  if (!Number.isSafeInteger(logBlowup) || logBlowup < 1 ||
    rCompare(theta, ZERO) < 0 || rCompare(theta, ONE) >= 0) {
    throw new Error("v17 Theorem 15 Johnson input");
  }
  const rate = rational(1n, 1n << BigInt(logBlowup));
  const alpha = rSub(ONE, theta);
  const denominator = rSub(rPow(alpha, 2), rate);
  if (rCompare(denominator, ZERO) <= 0) {
    throw new Error("v17 Theorem 15 outside Johnson radius");
  }
  return rDiv(rSub(alpha, rate), denominator);
}

function assertNatural(value: bigint, label: string, allowZero = false): void {
  if (value < (allowZero ? 0n : 1n)) throw new Error(`v17 Theorem 15 ${label}`);
}

function maximum(values: readonly bigint[]): bigint {
  if (values.length === 0) throw new Error("v17 Theorem 15 empty maximum");
  return values.reduce((left, right) => left > right ? left : right);
}

/**
 * Instantiate all three pre-FRI rounds of S-two Theorem 15 exactly. The usual
 * D/|F| root-count argument is written as D*mu, where mu is the exact maximum
 * SHA256-to-QM31 challenge mass. This is the elementary max-mass lifting of the
 * cited uniform-challenge bound, and accounts for modulo-reduction bias.
 */
export function v17Theorem15Bounds(input: V17FlatAirTheoremInput): V17Theorem15Bounds {
  assertNatural(input.inputMessages, "input messages", true);
  assertNatural(input.outputMessages, "output messages", true);
  assertNatural(input.airDegree, "AIR degree");
  if ((input.airDegree & 1n) === 0n || input.tables.length === 0) {
    throw new Error("v17 Theorem 15 requires odd AIR degree and a nonempty table set");
  }
  for (const table of input.tables) {
    if (!/^[a-z0-9][a-z0-9:-]*$/.test(table.id)) throw new Error("v17 Theorem 15 table id");
    assertNatural(table.rows, `${table.id} rows`);
    assertNatural(table.constraints, `${table.id} constraints`, true);
    assertNatural(table.uses, `${table.id} uses`, true);
    assertNatural(table.yields, `${table.id} yields`, true);
    assertNatural(table.maximumMessageDimension, `${table.id} message dimension`);
    assertNatural(table.maximumMultiplicity, `${table.id} multiplicity`, true);
  }
  if (new Set(input.tables.map(({ id }) => id)).size !== input.tables.length ||
    rCompare(input.oodPointMaximumProbability, ZERO) <= 0 ||
    rCompare(input.oodPointMaximumProbability, ONE) > 0) {
    throw new Error("v17 Theorem 15 geometry");
  }

  const listSize = v17Theorem15JohnsonListSize(input.theta, input.logBlowup);
  const fieldMaximumMass = qm31ChallengeMaximumProbability();
  const maximumMessageDimension = maximum(
    input.tables.map(({ maximumMessageDimension }) => maximumMessageDimension),
  );
  const logupTerms = input.inputMessages + input.outputMessages + input.tables.reduce(
    (sum, table) => sum + (table.uses + table.yields) * table.rows,
    0n,
  );
  const maximumCompositionTerms = maximum(input.tables.map(
    (table) => table.constraints + table.uses + table.yields,
  ));
  const maximumRows = maximum(input.tables.map(({ rows }) => rows));

  const rate = rational(1n, 1n << BigInt(input.logBlowup));
  const agreement = rSub(ONE, input.theta);
  const technicalCondition54 = input.tables.every((table) => {
    // S-two Theorem 15, equation (54):
    //   1 - theta > (1 - delta) * (1 + 2 / N_t).
    // The parenthesized correction is linear. Squaring it silently imposes a
    // different condition and is not the cited theorem.
    const correction = rAdd(ONE, rational(2n, table.rows));
    return rCompare(agreement, rMul(rate, correction)) > 0;
  });

  return {
    listSize,
    logup: rMul(
      rMul(listSize, rational(maximumMessageDimension * logupTerms)),
      fieldMaximumMass,
    ),
    composition: rMul(
      rMul(listSize, rational(2n + maximumCompositionTerms)),
      fieldMaximumMass,
    ),
    outOfDomain: rMul(
      rMul(listSize, rational(1n + input.airDegree * maximumRows)),
      input.oodPointMaximumProbability,
    ),
    technicalCondition54,
    multiplicitiesBelowCharacteristic: input.tables.every(
      ({ maximumMultiplicity }) => maximumMultiplicity < V17_THEOREM_M31,
    ),
  };
}

export const V17_CORRESPONDENCE_GATE_IDS = [
  "flat-air-shape",
  "logup-messages",
  "composition-quotient",
  "ood-sampler",
  "degree-corrected-batch",
  "grouped-folds",
  "mixed-merkle-bcs",
] as const;
export type V17CorrespondenceGateId = typeof V17_CORRESPONDENCE_GATE_IDS[number];

export type V17CorrespondenceGate = {
  readonly id: V17CorrespondenceGateId;
  readonly status: TheoremStatus;
  readonly evidence: string;
};

export type V17TheoremMap = {
  readonly theorem15: V17Theorem15Bounds;
  readonly gates: readonly V17CorrespondenceGate[];
  readonly rounds: readonly V17SoundnessRound[];
  readonly certificate: V17WorkFactorCertificate;
};

export type V17FirstReductionBound = {
  /** Exact upper bound for the construction-specific first randomized reduction. */
  readonly rawError: Rational;
  readonly theorem: string;
};

function gateMap(gates: readonly V17CorrespondenceGate[]): ReadonlyMap<V17CorrespondenceGateId, V17CorrespondenceGate> {
  if (gates.length !== V17_CORRESPONDENCE_GATE_IDS.length ||
    new Set(gates.map(({ id }) => id)).size !== gates.length ||
    V17_CORRESPONDENCE_GATE_IDS.some((id) => !gates.some((gate) => gate.id === id)) ||
    gates.some(({ evidence }) => evidence.length === 0)) {
    throw new Error("v17 theorem correspondence gate coverage");
  }
  return new Map(gates.map((gate) => [gate.id, gate]));
}

/**
 * One executable theorem DAG. Every pre-FRI and FRI round receives its own
 * minimal PoW salt; a single end-of-proof grind cannot stand in for this map.
 */
export function buildV17TheoremMap(args: {
  readonly air: V17FlatAirTheoremInput;
  readonly fri: V17FriParameterCandidate;
  readonly gates: readonly V17CorrespondenceGate[];
  /**
   * V17 reduces its three custom interaction arguments before viewing the
   * resulting polynomial relation as an augmented r=s=0 flat AIR. When this
   * field is absent, the ordinary Protocol-1 LogUp bound is used.
   */
  readonly firstReduction?: V17FirstReductionBound;
}): V17TheoremMap {
  if (args.air.logBlowup !== args.fri.logBlowup ||
    rCompare(args.air.theta, args.fri.theta) !== 0 ||
    args.fri.bounds.folds.length !== args.fri.grindingBits.folds.length) {
    throw new Error("v17 theorem map parameter correspondence");
  }
  const theorem15 = v17Theorem15Bounds(args.air);
  const byGate = gateMap(args.gates);
  const roundCount = 3 + 1 + args.fri.bounds.folds.length + 1;
  const allowed = maximumAllowedAdjustedRound(roundCount);
  const round = (
    id: string,
    dependsOn: readonly string[],
    rawError: Rational,
    gate: V17CorrespondenceGateId,
    theorem: string,
  ): V17SoundnessRound => ({
    id,
    dependsOn,
    rawError,
    grindBits: minimalGrindingBits(rawError, allowed),
    status: byGate.get(gate)!.status,
    theorem: `${theorem}; ${byGate.get(gate)!.evidence}`,
  });

  const rounds: V17SoundnessRound[] = [];
  rounds.push(round(
    "air:logup",
    [],
    args.firstReduction?.rawError ?? theorem15.logup,
    "logup-messages",
    args.firstReduction?.theorem ?? "S-two Theorem 15.1",
  ));
  rounds.push(round("air:composition", ["air:logup"], theorem15.composition,
    "composition-quotient", "S-two Theorem 15.2"));
  rounds.push(round("air:ood", ["air:composition"], theorem15.outOfDomain,
    "ood-sampler", "S-two Theorem 15.3"));
  rounds.push(round("fri:batch", ["air:ood"], args.fri.bounds.batch,
    "degree-corrected-batch", "S-two Theorem 19 and Theorem 21"));
  args.fri.bounds.folds.forEach((error, index) => {
    rounds.push(round(`fri:fold:${index}`, [index === 0 ? "fri:batch" : `fri:fold:${index - 1}`],
      error, "grouped-folds", "S-two Theorem 19"));
  });
  rounds.push(round("fri:query", [`fri:fold:${args.fri.bounds.folds.length - 1}`],
    args.fri.bounds.query, "mixed-merkle-bcs", "S-two Theorem 19 and Theorem 22"));

  const structuralFailures: string[] = [];
  if (!theorem15.technicalCondition54) structuralFailures.push("theorem-15-condition-54");
  if (!theorem15.multiplicitiesBelowCharacteristic) structuralFailures.push("multiplicity-field-bound");
  if (byGate.get("flat-air-shape")!.status !== "cited" &&
    byGate.get("flat-air-shape")!.status !== "proved") {
    structuralFailures.push(`flat-air-shape:${byGate.get("flat-air-shape")!.status}`);
  }
  const baseCertificate = certifyV17WorkFactor(rounds);
  const certificate: V17WorkFactorCertificate = structuralFailures.length === 0
    ? baseCertificate
    : {
      ...baseCertificate,
      qualified: false,
      reasons: [...structuralFailures, ...baseCertificate.reasons],
    };
  return { theorem15, gates: args.gates, rounds, certificate };
}

export function uniformV17OodPointMaximumProbability(): Rational {
  return rational(1n, V17_THEOREM_OOD_POINT_SET_SIZE);
}

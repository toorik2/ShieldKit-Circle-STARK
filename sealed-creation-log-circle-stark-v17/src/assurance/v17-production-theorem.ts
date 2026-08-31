import {
  LOCAL_WORD_AIR_CONSTRAINTS,
  LOCAL_WORD_INTERACTION_QM31_COLUMNS,
  LOCAL_WORD_PREPROCESSED_COLUMNS,
} from "../backends/circle/local-word-air.ts";
import {
  LOCAL_WORD_GLOBAL_INTERACTION_COLUMNS,
  LOCAL_WORD_INTERACTION_GROUPS,
} from "../backends/circle/local-word-oracle-layout.ts";
import {
  LOCAL_WORD_PRODUCTION_PARAMETERS,
  localWordFriFoldCounts,
} from "../backends/circle/local-word-successor-params.ts";
import {
  v17EvaluationQuotient,
  v17PointVanishing,
  type V17Qm31CirclePoint,
} from "../backends/circle/v17-oods.ts";
import {
  QM31_ONE,
  QM31_ZERO,
  qmAdd,
  qmEq,
  qmInv,
  qmMul,
  qmMulM31,
  qmSub,
  type QM31El,
} from "../backends/circle/qm31.ts";
import { inv as m31Inv, type M31El } from "../backends/circle/m31.ts";
import {
  LOCAL_SHA_LIMBS,
  LOCAL_SHA_LOOKUP_TABLE_ROWS,
  LOCAL_SHA_MAX_LOOKUPS_PER_ROW,
  LOCAL_SHA_ORIGINAL_COLUMNS,
} from "../chain/sha256-local-word-machine.ts";
import { LOCAL_SHA_WORD_COPY_SLOTS_PER_ROW } from
  "../chain/sha256-local-word-permutation.ts";
import {
  V17_CONSTRUCTION_GRAPH,
  type V17ConstructionGraph,
} from "../construction/v17-graph.ts";
import {
  ONE,
  rational,
  rAdd,
  rCompare,
  rDiv,
  rMul,
  rPow2,
  rSub,
  type Rational,
} from "./rational.ts";
import {
  groupV17BinaryFoldBounds,
  synthesizeV17FriParameters,
  type V17FriParameterCandidate,
} from "./v17-parameter-synthesis.ts";
import {
  V17_CORRESPONDENCE_GATE_IDS,
  V17_THEOREM_M31,
  buildV17TheoremMap,
  type V17FirstReductionBound,
  uniformV17OodPointMaximumProbability,
  v17Theorem15JohnsonListSize,
  type V17CorrespondenceGate,
  type V17FlatAirTheoremInput,
  type V17TheoremMap,
} from "./v17-theorem-map.ts";
import {
  qm31ChallengeMaximumProbability,
  type TheoremStatus,
} from "./v17-soundness.ts";

/**
 * Exact production target derived from the local-word AIR and committed row
 * geometry. This module deliberately does not claim that the present proof
 * codec or verifier implements the target: the graph audit below fails closed
 * until those correspondences are supplied and reviewed.
 */
export const V17_PRODUCTION_THETA = rational(181n, 256n);
export const V17_PRODUCTION_BATCH_ORDER = [
  "mask",
  "functions",
  "evaluation-quotients",
] as const;

export type V17ProductionFunctionDimensions = {
  readonly relationRows: number;
  readonly preprocessedBaseFunctions: number;
  readonly originalBaseFunctions: number;
  readonly interactionSemanticFunctions: number;
  readonly interactionCoordinateColumns: number;
  readonly predecessorSemanticFunctions: number;
  readonly predecessorCoordinateColumns: number;
  readonly compositionQuotientSemanticFunctions: 1;
  readonly compositionQuotientCoordinateColumns: 4;
  readonly maskSemanticFunctions: 1;
  readonly maskCoordinateColumns: 4;
  /** Functions whose values at Q are claimed and evaluation-proved. */
  readonly oodValueCount: number;
  readonly oodValueBytes: number;
  /** One degree-correction function for every OOD claim. */
  readonly evaluationQuotientFunctions: number;
  /** Theorem-19 M: mask, all f_i, then all (f_i-f_i(Q))/v_Q. */
  readonly degreeCorrectedBatchWidth: number;
  readonly theorem19BatchLeadingFactor: number;
  /** The stale in-domain packing implemented by the inherited v16 batch. */
  readonly legacyPackedOriginalFunctions: number;
  readonly legacyUncorrectedBatchWidthIncludingMask: number;
};

function commitmentRowBytes(graph: V17ConstructionGraph, id: string): number {
  const commitment = graph.commitments.find((candidate) => candidate.id === id);
  const match = commitment?.leafCodec.match(/:(\d+)-bytes$/);
  if (!match) throw new Error(`v17 production missing commitment geometry ${id}`);
  const bytes = Number(match[1]);
  if (!Number.isSafeInteger(bytes) || bytes < 4 || bytes % 4 !== 0) {
    throw new Error(`v17 production commitment width ${id}`);
  }
  return bytes;
}

/** Derive every function count from imported AIR constants and graph row widths. */
export function deriveV17ProductionFunctionDimensions(
  graph: V17ConstructionGraph = V17_CONSTRUCTION_GRAPH,
): V17ProductionFunctionDimensions {
  const preprocessedCoordinates = commitmentRowBytes(graph, "matrix:preprocessed") / 4;
  const originalCoordinates = commitmentRowBytes(graph, "matrix:original") / 4;
  const interactionCoordinates = (
    commitmentRowBytes(graph, "matrix:interaction") +
    commitmentRowBytes(graph, "matrix:interactionGlobal")
  ) / 4;
  const quotientAndMaskCoordinates =
    commitmentRowBytes(graph, "matrix:quotientAndFriMask") / 4;
  const interactionSemanticFunctions = interactionCoordinates / 4;
  const predecessorSemanticFunctions = LOCAL_WORD_GLOBAL_INTERACTION_COLUMNS.length;
  const predecessorCoordinateColumns = predecessorSemanticFunctions * 4;

  if (preprocessedCoordinates !== LOCAL_WORD_PREPROCESSED_COLUMNS ||
    originalCoordinates !== LOCAL_SHA_ORIGINAL_COLUMNS ||
    interactionSemanticFunctions !== LOCAL_WORD_INTERACTION_QM31_COLUMNS ||
    interactionCoordinates !== LOCAL_WORD_INTERACTION_GROUPS.flat().length * 4 ||
    quotientAndMaskCoordinates !== 8 ||
    !Number.isInteger(interactionSemanticFunctions)) {
    throw new Error("v17 production AIR/proof function geometry mismatch");
  }

  /*
   * The 34 original and 43 preprocessed base polynomials must remain separate
   * at Q. Four base polynomials packed into one QM31 row value are invertible
   * on C(M31), but their four evaluations at Q are themselves QM31 values and
   * cannot be recovered from one packed value. In contrast, each interaction
   * AIR variable is semantically one SecureCirclePoly/QM31 polynomial; its four
   * committed coordinates authenticate one semantic value at Q.
   */
  const oodValueCount = preprocessedCoordinates + originalCoordinates +
    interactionSemanticFunctions + predecessorSemanticFunctions + 1;
  const degreeCorrectedBatchWidth = 1 + 2 * oodValueCount;
  const legacyPackedOriginalFunctions = Math.ceil(originalCoordinates / 4);
  return {
    relationRows: 2 ** LOCAL_WORD_PRODUCTION_PARAMETERS.relationLog,
    preprocessedBaseFunctions: preprocessedCoordinates,
    originalBaseFunctions: originalCoordinates,
    interactionSemanticFunctions,
    interactionCoordinateColumns: interactionCoordinates,
    predecessorSemanticFunctions,
    predecessorCoordinateColumns,
    compositionQuotientSemanticFunctions: 1,
    compositionQuotientCoordinateColumns: 4,
    maskSemanticFunctions: 1,
    maskCoordinateColumns: 4,
    oodValueCount,
    oodValueBytes: oodValueCount * 16,
    evaluationQuotientFunctions: oodValueCount,
    degreeCorrectedBatchWidth,
    theorem19BatchLeadingFactor: degreeCorrectedBatchWidth - 1,
    legacyPackedOriginalFunctions,
    legacyUncorrectedBatchWidthIncludingMask:
      legacyPackedOriginalFunctions + interactionSemanticFunctions + 1 + 1,
  };
}

export const V17_PRODUCTION_FUNCTION_DIMENSIONS =
  deriveV17ProductionFunctionDimensions();

export type V17InteractionReductionCertificate = {
  readonly schema: "ShieldKit/V17InteractionReduction/v1";
  readonly relationRows: number;
  readonly lookupTerms: number;
  readonly wordCopySlots: number;
  readonly publicBoundaryMessages: 8;
  /** Half-open residual ranges in the exact local-word AIR order. */
  readonly residualPartition: {
    readonly lookupRunningSum: readonly [0, 9];
    readonly wordCopyGrandProduct: readonly [9, 16];
    readonly localWordGate: readonly [16, 23];
    readonly publicBoundaryReduction: readonly [23, 25];
  };
  /** Root-degree and zero-denominator events before the conservative envelope. */
  readonly directDegreeTerms: {
    readonly lookupIdentity: number;
    readonly lookupDenominators: number;
    readonly wordCompression: number;
    readonly wordProductIdentity: number;
    readonly wordDenominators: number;
    readonly publicBoundaryIdentity: number;
    readonly publicBoundaryDenominators: number;
    readonly total: number;
  };
  /**
   * The deliberately wider S-two-shaped charge used by the production
   * worksheet: r * (k_in+k_out+(uses+yields)N) with r=9 and 16 row messages.
   */
  readonly chargedEnvelopeTerms: number;
  readonly envelopeDominatesDirectTerms: boolean;
  readonly rawError: Rational;
};

/**
 * Exact first-reduction charge for the three v17 custom interaction arguments.
 *
 * The lookup running sum has exactly K=8N+1,841 possible charged factors:
 * eight accesses per trace row plus the 1,841-row universal 4-bit table. The word-copy
 * argument has S=3N slots and separately charges limb-compression,
 * grand-product, and zero-denominator events. The public boundary compares
 * two eight-element multisets. Each cross-multiplied false identity is a
 * non-zero multivariate polynomial in independently sampled QM31 challenges;
 * Schwartz-Zippel with the exact maximum challenge mass bounds it by degree*mu.
 * The Johnson list factor accounts for the possible theta-close polynomial
 * ensembles before the interaction roots are committed.
 */
export function v17InteractionReductionCertificate(): V17InteractionReductionCertificate {
  const relationRows = V17_PRODUCTION_FUNCTION_DIMENSIONS.relationRows;
  const lookupTerms = relationRows * LOCAL_SHA_MAX_LOOKUPS_PER_ROW +
    LOCAL_SHA_LOOKUP_TABLE_ROWS;
  const wordCopySlots = relationRows * LOCAL_SHA_WORD_COPY_SLOTS_PER_ROW;
  const publicBoundaryMessages = 8 as const;
  const directDegreeTerms = {
    // Numerator degree is at most K-1; charging K is monotone and integral.
    lookupIdentity: lookupTerms,
    lookupDenominators: lookupTerms,
    // One non-zero linear compression equation per compiled sigma edge.
    wordCompression: wordCopySlots,
    wordProductIdentity: wordCopySlots,
    wordDenominators: wordCopySlots,
    // Two eight-element multisets: numerator degree <=15 and <=16 factors.
    publicBoundaryIdentity: 2 * publicBoundaryMessages,
    publicBoundaryDenominators: 2 * publicBoundaryMessages,
    total: 0,
  };
  const total = Object.entries(directDegreeTerms)
    .filter(([id]) => id !== "total")
    .reduce((sum, [, value]) => sum + value, 0);
  const completeDirect = { ...directDegreeTerms, total };
  const maximumMessageDimension = 1 + LOCAL_SHA_LIMBS;
  const logicalRowMessages = 8 + 1 + 3 + 3 + 1;
  const residualPartition = {
    lookupRunningSum: [0, 9],
    wordCopyGrandProduct: [9, 16],
    localWordGate: [16, 23],
    publicBoundaryReduction: [23, 25],
  } as const;
  const chargedEnvelopeTerms = maximumMessageDimension *
    (publicBoundaryMessages + logicalRowMessages * relationRows);
  if (maximumMessageDimension !== 9 || logicalRowMessages !== 16 ||
    residualPartition.publicBoundaryReduction[1] !== LOCAL_WORD_AIR_CONSTRAINTS ||
    chargedEnvelopeTerms < completeDirect.total) {
    throw new Error("v17 interaction reduction envelope");
  }
  const listSize = v17Theorem15JohnsonListSize(V17_PRODUCTION_THETA, 4);
  const rawError = rMul(
    rMul(listSize, rational(BigInt(chargedEnvelopeTerms))),
    qm31ChallengeMaximumProbability(),
  );
  return {
    schema: "ShieldKit/V17InteractionReduction/v1",
    relationRows,
    lookupTerms,
    wordCopySlots,
    publicBoundaryMessages,
    residualPartition,
    directDegreeTerms: completeDirect,
    chargedEnvelopeTerms,
    envelopeDominatesDirectTerms: true,
    rawError,
  };
}

export const V17_INTERACTION_REDUCTION_CERTIFICATE =
  v17InteractionReductionCertificate();

export const V17_PRODUCTION_FIRST_REDUCTION: V17FirstReductionBound = {
  rawError: V17_INTERACTION_REDUCTION_CERTIFICATE.rawError,
  theorem: "V17 custom first-reduction Lemmas L1-L4 (THEOREM.md)",
};

export type V17SealQuotientCertificate = {
  readonly schema: "ShieldKit/V17SealQuotient/v1";
  readonly traceDimension: number;
  readonly randomizerDimension: number;
  readonly sealedDimension: number;
  readonly restrictionKernelDimension: number;
  readonly traceZerofierDegree: number;
  readonly maximumSealedDegree: number;
  readonly maximumConstraintDegree: 2;
  readonly maximumCompositionDegree: number;
  readonly maximumQuotientDegree: number;
  readonly quotientSpaceStrictDegreeCap: number;
  readonly quotientFits: boolean;
};

/**
 * Dimension/degree certificate for s=w+Z_H*r and the one whole quotient.
 * L'_18 has dimension N and degree <=N/2; multiplication by Z_H identifies
 * L'_18 with the N-dimensional kernel of L'_19 -> F^H. The implemented 25
 * residuals are at most quadratic, so the sealed composition has degree <=2N
 * and division by degree-N/2 Z_H leaves degree <=3N/2 < 2N, the L'_20 cap.
 */
export function v17SealQuotientCertificate(): V17SealQuotientCertificate {
  const traceDimension = 2 ** LOCAL_WORD_PRODUCTION_PARAMETERS.relationLog;
  const sealedDimension = 2 ** (LOCAL_WORD_PRODUCTION_PARAMETERS.relationLog + 1);
  const traceZerofierDegree = traceDimension / 2;
  const maximumSealedDegree = traceDimension;
  const maximumCompositionDegree = 2 * maximumSealedDegree;
  const maximumQuotientDegree = maximumCompositionDegree - traceZerofierDegree;
  const quotientSpaceStrictDegreeCap =
    LOCAL_WORD_PRODUCTION_PARAMETERS.quotientDegreeRows / 2;
  const certificate: V17SealQuotientCertificate = {
    schema: "ShieldKit/V17SealQuotient/v1",
    traceDimension,
    randomizerDimension: traceDimension,
    sealedDimension,
    restrictionKernelDimension: sealedDimension - traceDimension,
    traceZerofierDegree,
    maximumSealedDegree,
    maximumConstraintDegree: 2,
    maximumCompositionDegree,
    maximumQuotientDegree,
    quotientSpaceStrictDegreeCap,
    quotientFits: maximumQuotientDegree < quotientSpaceStrictDegreeCap,
  };
  if (certificate.randomizerDimension !== certificate.restrictionKernelDimension ||
    !certificate.quotientFits) {
    throw new Error("v17 seal/quotient degree certificate");
  }
  return certificate;
}

export const V17_SEAL_QUOTIENT_CERTIFICATE = v17SealQuotientCertificate();

function sameRational(left: Rational, right: Rational): boolean {
  return rCompare(left, right) === 0;
}

/** Fail closed on a worksheet candidate that omits functions or round work. */
export function assertV17ProductionFriCandidate(
  candidate: V17FriParameterCandidate,
): V17FriParameterCandidate {
  const dimensions = V17_PRODUCTION_FUNCTION_DIMENSIONS;
  const expectedFoldDomains = [23, 21, 19, 17, 15, 13, 11, 9, 7];
  const expectedFriGrinding = {
    batch: 26,
    folds: [20, 18, 16, 14, 12, 10, 8, 6, 4],
    query: 26,
  } as const;
  if (candidate.logBlowup !== 4 || candidate.evaluationLog !== 24 ||
    candidate.batchWidth !== dimensions.degreeCorrectedBatchWidth ||
    candidate.queries !== 44 || candidate.friRoundCount !== 11 ||
    !sameRational(candidate.theta, V17_PRODUCTION_THETA) ||
    candidate.bounds.folds.length !== expectedFoldDomains.length ||
    candidate.grindingBits.batch !== expectedFriGrinding.batch ||
    candidate.grindingBits.query !== expectedFriGrinding.query ||
    candidate.grindingBits.folds.some((bits, index) =>
      bits !== expectedFriGrinding.folds[index]) ||
    candidate.binaryFoldBounds.length !== 17 ||
    candidate.foldChallengeCounts.join(",") !== "2,2,2,2,2,2,2,2,1" ||
    candidate.grindingBits.maximum !== 26 || candidate.grindingBits.total !== 160 ||
    candidate.proofCoreCeiling.totalBytes !== 317_334) {
    throw new Error("v17 stale or non-production FRI theorem candidate");
  }
  return candidate;
}

function productionFriCandidate(): V17FriParameterCandidate {
  const candidates = synthesizeV17FriParameters({
    logBlowups: [4],
    minimumQueries: 44,
    maximumQueries: 44,
    maximumRoundGrindingBits: 26,
    batchWidth: V17_PRODUCTION_FUNCTION_DIMENSIONS.degreeCorrectedBatchWidth,
    precedingRounds: 3,
    thetaGridDenominator: 256,
  });
  const candidate = candidates.find(({ theta }) => sameRational(theta, V17_PRODUCTION_THETA));
  if (!candidate || candidates[0] !== candidate) {
    throw new Error("v17 production FRI candidate selection");
  }
  return assertV17ProductionFriCandidate(candidate);
}

export const V17_PRODUCTION_FRI_CANDIDATE = productionFriCandidate();

/**
 * The augmented post-interaction AIR used by Protocol-1 Rounds 2 and 3.
 * Lookup, word-copy, and public-boundary consistency have already been reduced
 * by the construction-specific first round above, so this table has r=s=0.
 * Its 25 explicit residual polynomials are the complete component gate.
 */
export function v17ProductionFlatAirInput(
  theta: Rational = V17_PRODUCTION_THETA,
): V17FlatAirTheoremInput {
  const dimensions = V17_PRODUCTION_FUNCTION_DIMENSIONS;
  const publicWords = V17_CONSTRUCTION_GRAPH.proof.frames.find(
    ({ id }) => id === "publicInverses",
  )?.itemCount;
  if (publicWords !== 8) throw new Error("v17 production public message geometry");
  return {
    inputMessages: 0n,
    outputMessages: 0n,
    // The explicit residuals are quadratic. Three is the conservative odd
    // degree cap used by the cited theorem and does not change quotient sizing.
    airDegree: 3n,
    theta,
    logBlowup: 4,
    tables: [{
      id: "local-word",
      rows: BigInt(dimensions.relationRows),
      constraints: BigInt(LOCAL_WORD_AIR_CONSTRAINTS),
      uses: 0n,
      yields: 0n,
      maximumMessageDimension: 1n,
      maximumMultiplicity: 0n,
    }],
    oodPointMaximumProbability: uniformV17OodPointMaximumProbability(),
  };
}

export const V17_PRODUCTION_ASSURANCE_ROW_IDS = [
  "s-two-theorem-formulas",
  "lookup-running-sum",
  "word-copy-grand-product",
  "public-boundary-reduction",
  "augmented-rs-zero-air",
  "full-dimensional-seal",
  "whole-quotient-identity",
  "ood-uniform-sampler",
  "protocol4-width197-batch",
  "grouped-fri-virtual-intermediate",
  "fixed-arity-merkle-forest",
  "product-first-reduction-transcript",
  "product-ood-air-role",
  "product-batch-link-roles",
  "product-grouped-fri-transcript",
  "product-mixed-merkle-codec",
] as const;
export type V17ProductionAssuranceRowId =
  typeof V17_PRODUCTION_ASSURANCE_ROW_IDS[number];

export type V17ProductionAssuranceRow = {
  readonly id: V17ProductionAssuranceRowId;
  readonly status: TheoremStatus;
  readonly statement: string;
  readonly evidence: string;
};

export type V17ProductionAssuranceCertificate = {
  readonly schema: "ShieldKit/V17ProductionAssurance/v1";
  readonly rows: readonly V17ProductionAssuranceRow[];
  readonly qualified: boolean;
  readonly reasons: readonly string[];
};

const QUALIFYING_THEOREM_STATUSES: ReadonlySet<TheoremStatus> =
  new Set(["cited", "proved"]);

/** Every non-cited/non-proved row is a hard, machine-readable stop. */
export function certifyV17ProductionAssuranceRows(
  rows: readonly V17ProductionAssuranceRow[],
): V17ProductionAssuranceCertificate {
  if (rows.length !== V17_PRODUCTION_ASSURANCE_ROW_IDS.length ||
    new Set(rows.map(({ id }) => id)).size !== rows.length ||
    V17_PRODUCTION_ASSURANCE_ROW_IDS.some((id) => !rows.some((row) => row.id === id)) ||
    rows.some(({ statement, evidence }) => statement.length === 0 || evidence.length === 0)) {
    throw new Error("v17 production assurance row coverage");
  }
  const reasons = rows
    .filter(({ status }) => !QUALIFYING_THEOREM_STATUSES.has(status))
    .map(({ id, status }) => `${id}:${status}`);
  return {
    schema: "ShieldKit/V17ProductionAssurance/v1",
    rows,
    qualified: reasons.length === 0,
    reasons,
  };
}

/**
 * Mathematical rows are promoted only where THEOREM.md supplies the complete
 * lemma and the focused tests check its executable geometry. Product rows stay
 * unresolved until the exact serialized verifier path consumes that geometry.
 */
export const V17_PRODUCTION_ASSURANCE_ROWS: readonly V17ProductionAssuranceRow[] = [
  {
    id: "s-two-theorem-formulas",
    status: "cited",
    statement: "S-two Theorems 15, 19, 21, and 22 are instantiated with their printed formulas.",
    evidence: "THEOREM.md sections 2 and 8; ePrint 2026/532, equations 53, 54, 80, and 89",
  },
  {
    id: "lookup-running-sum",
    status: "proved",
    statement: "The nine lookup columns reduce the eight accesses and fixed-table multiplicity multiset to one rational identity.",
    evidence: "THEOREM.md Lemma L1; local-word-air.ts residuals 0..8; V17InteractionReduction/v1",
  },
  {
    id: "word-copy-grand-product",
    status: "proved",
    statement: "Independent limb compression plus the three-slot grand product reduces the compiled word permutation to one product identity.",
    evidence: "THEOREM.md Lemma L2; local-word-air.ts residuals 9..15; V17InteractionReduction/v1",
  },
  {
    id: "public-boundary-reduction",
    status: "proved",
    statement: "The verifier-derived eight-word sum and cyclic access recurrence bind the AIR words to the sole public digest boundary.",
    evidence: "THEOREM.md Lemma L3; local-word-air.ts residuals 23..24; public inverse checks",
  },
  {
    id: "augmented-rs-zero-air",
    status: "proved",
    statement: "After the first reduction the exact 25-residual polynomial relation is an augmented one-table r=s=0 flat AIR for Rounds 2 and 3.",
    evidence: "THEOREM.md Lemma L4; 34 original, 43 preprocessed, 17 interaction, and 3 predecessor functions",
  },
  {
    id: "full-dimensional-seal",
    status: "proved",
    statement: "w+Z_H*r is a uniform affine-fibre seal and restricts to exactly w on H.",
    evidence: "THEOREM.md Lemma L5; V17SealQuotient/v1 kernel and dimension certificate",
  },
  {
    id: "whole-quotient-identity",
    status: "proved",
    statement: "The quadratic sealed composition is divisible by Z_H and its one quotient fits L'_20.",
    evidence: "THEOREM.md Lemma L6; V17SealQuotient/v1 degree certificate",
  },
  {
    id: "ood-uniform-sampler",
    status: "proved",
    statement: "The fail-closed sampler is uniform on C(QM31) minus C(M31), with exact maximum mass.",
    evidence: "v17-oods.ts V17_OODS_FAILURE_CERTIFICATE and focused sampler tests",
  },
  {
    id: "protocol4-width197-batch",
    status: "proved",
    statement: "The 98 OOD claims and their 98 degree corrections plus one independent mask form canonical M=197 Protocol 4 input.",
    evidence: "THEOREM.md Lemma L7; fused/explicit batch KAT and M-1=196 check",
  },
  {
    id: "grouped-fri-virtual-intermediate",
    status: "proved",
    statement: "Each four-way group is two binary reductions with independent challenges and a deterministic uncommitted middle oracle.",
    evidence: "THEOREM.md Lemma L8; 17-to-9 exact adjacent-error sum and mutation KAT",
  },
  {
    id: "fixed-arity-merkle-forest",
    status: "proved",
    statement: "A graph-fixed forest of binary and quartet-first trees has the ordinary partial-decommitment and collision-binding reduction.",
    evidence: "THEOREM.md Lemma L9; descriptor-separated fixed-arity node grammar",
  },
  {
    id: "product-first-reduction-transcript",
    status: "unresolved",
    statement: "The final TS, Rust, and CashVM codecs replay the causally ordered custom first reduction byte for byte.",
    evidence: "Graph order is specified; final cross-language serialized replay has not been recorded",
  },
  {
    id: "product-ood-air-role",
    status: "unresolved",
    statement: "One miner-run OOD AIR role checks all 25 residuals and q(Q)Z_H(Q)=composition(Q) without partial sidecars.",
    evidence: "Graph role is specified; exact linked CashVM role and all-profile meters are pending",
  },
  {
    id: "product-batch-link-roles",
    status: "unresolved",
    statement: "Exactly 44 miner-run workers link authenticated rows to the width-197 batch and FRI0.",
    evidence: "Graph roles are specified; final codec/linker/VM correspondence is pending",
  },
  {
    id: "product-grouped-fri-transcript",
    status: "unresolved",
    statement: "The production proof carries and replays all 17 independently derived fold challenges in nine grouped rounds.",
    evidence: "Graph frames are specified; final TS/Rust/CashVM replay and mutation evidence are pending",
  },
  {
    id: "product-mixed-merkle-codec",
    status: "unresolved",
    statement: "Every production opening, cut frontier, and miner role conforms to the exact graph-fixed mixed-Merkle contract.",
    evidence: "Reference codec exists; final generated cuts, Rust mirror, all-role replay, and identity-bound evidence are pending",
  },
] as const;

export const V17_PRODUCTION_ASSURANCE_CERTIFICATE =
  certifyV17ProductionAssuranceRows(V17_PRODUCTION_ASSURANCE_ROWS);

const GATE_ASSURANCE_ROWS: Readonly<Record<
  typeof V17_CORRESPONDENCE_GATE_IDS[number],
  readonly V17ProductionAssuranceRowId[]
>> = {
  "flat-air-shape": ["s-two-theorem-formulas", "augmented-rs-zero-air", "product-ood-air-role"],
  "logup-messages": ["lookup-running-sum", "word-copy-grand-product",
    "public-boundary-reduction", "product-first-reduction-transcript"],
  "composition-quotient": ["full-dimensional-seal", "whole-quotient-identity",
    "product-ood-air-role"],
  "ood-sampler": ["ood-uniform-sampler"],
  "degree-corrected-batch": ["s-two-theorem-formulas", "protocol4-width197-batch",
    "product-ood-air-role", "product-batch-link-roles"],
  "grouped-folds": ["s-two-theorem-formulas", "grouped-fri-virtual-intermediate",
    "product-grouped-fri-transcript"],
  "mixed-merkle-bcs": ["s-two-theorem-formulas", "fixed-arity-merkle-forest",
    "product-mixed-merkle-codec"],
};

function gateFromAssuranceRows(
  id: typeof V17_CORRESPONDENCE_GATE_IDS[number],
  assuranceRows: readonly V17ProductionAssuranceRow[],
): V17CorrespondenceGate {
  const rowIds = GATE_ASSURANCE_ROWS[id];
  const rows = rowIds.map((rowId) =>
    assuranceRows.find((row) => row.id === rowId)!);
  const failing = rows.find(({ status }) => !QUALIFYING_THEOREM_STATUSES.has(status));
  return {
    id,
    status: failing?.status ?? "proved",
    evidence: rowIds.join(","),
  };
}

/** Derive every theorem correspondence gate from one complete assurance table. */
export function v17CorrespondenceGatesFromAssuranceRows(
  rows: readonly V17ProductionAssuranceRow[],
): readonly V17CorrespondenceGate[] {
  certifyV17ProductionAssuranceRows(rows);
  return V17_CORRESPONDENCE_GATE_IDS.map((id) => gateFromAssuranceRows(id, rows));
}

export const V17_PRODUCTION_CORRESPONDENCE_GATES: readonly V17CorrespondenceGate[] =
  v17CorrespondenceGatesFromAssuranceRows(V17_PRODUCTION_ASSURANCE_ROWS);

if (V17_PRODUCTION_CORRESPONDENCE_GATES.map(({ id }) => id).join("|") !==
  V17_CORRESPONDENCE_GATE_IDS.join("|")) {
  throw new Error("v17 production correspondence gate order");
}

export type V17ProductionAssumption = {
  readonly id: string;
  readonly holds: boolean;
  readonly left?: Rational;
  readonly right?: Rational;
  readonly evidence: string;
};

function productionAssumptions(theoremMap: V17TheoremMap): readonly V17ProductionAssumption[] {
  const air = v17ProductionFlatAirInput();
  const table = air.tables[0]!;
  const blowup = 1n << BigInt(air.logBlowup);
  const rate = rPow2(-air.logBlowup);
  const delta = rSub(ONE, rate);
  const johnsonLower = rDiv(delta, rational(2n));
  const johnsonUpper = rational(3n, 4n); // 1 - sqrt(1/16).
  const theorem21Right = rMul(
    rate,
    rAdd(ONE, rational(2n, table.rows)),
  );
  const agreement = rSub(ONE, air.theta);
  const dimensions = V17_PRODUCTION_FUNCTION_DIMENSIONS;
  return [
    {
      id: "air-degree-capacity",
      holds: air.airDegree <= blowup + 1n && table.rows * blowup * blowup <= 1n << 30n,
      evidence: "deg(A)=3 <= B+1=17 and 2^18*16^2=2^26 <= 2^30",
    },
    {
      id: "johnson-interval",
      holds: rCompare(air.theta, johnsonLower) >= 0 &&
        rCompare(air.theta, johnsonUpper) < 0,
      left: air.theta,
      right: johnsonUpper,
      evidence: "181/256 lies in [15/32,3/4)",
    },
    {
      id: "theorem-21-minimum-height",
      holds: rCompare(agreement, theorem21Right) > 0 &&
        theoremMap.theorem15.technicalCondition54,
      left: agreement,
      right: theorem21Right,
      evidence: "1-theta > 2^-4*(1+2/2^18)",
    },
    {
      id: "multiplicity-characteristic",
      holds: BigInt(V17_INTERACTION_REDUCTION_CERTIFICATE.relationRows *
        LOCAL_SHA_MAX_LOOKUPS_PER_ROW) < V17_THEOREM_M31 &&
        theoremMap.theorem15.multiplicitiesBelowCharacteristic,
      evidence: "custom first reduction proves 8*2^18=2^21 < 2^31-1; augmented AIR has no multiplicities",
    },
    {
      id: "degree-corrected-width",
      holds: dimensions.oodValueCount === 98 &&
        dimensions.evaluationQuotientFunctions === 98 &&
        dimensions.degreeCorrectedBatchWidth === 197 &&
        dimensions.theorem19BatchLeadingFactor === 196,
      evidence: "M=1 mask + 98 functions + 98 single-point quotients; M-1=196",
    },
    {
      id: "round-count",
      holds: theoremMap.rounds.length === 14 &&
        localWordFriFoldCounts(LOCAL_WORD_PRODUCTION_PARAMETERS).length === 9,
      evidence: "3 AIR + batch + 9 folds + query = 14 randomized reductions",
    },
    {
      id: "virtual-intermediate-composition",
      holds: theoremMap.rounds.filter(({ id }) => id.startsWith("fri:fold:")).length === 9 &&
        V17_PRODUCTION_FRI_CANDIDATE.binaryFoldBounds.length === 17 &&
        groupV17BinaryFoldBounds(V17_PRODUCTION_FRI_CANDIDATE.binaryFoldBounds)
          .every((error, index) =>
            rCompare(error, V17_PRODUCTION_FRI_CANDIDATE.bounds.folds[index]!) === 0),
      evidence: "each grouped error is the exact sum of two adjacent binary errors; the tail uses one",
    },
    {
      id: "u32-grinding-restriction",
      holds: theoremMap.rounds.every(({ grindBits }) => grindBits <= 26) &&
        V17_CONSTRUCTION_GRAPH.foundation.grindingNonce.searchSpaceBits === 32 &&
        V17_CONSTRUCTION_GRAPH.foundation.grindingNonce.expectedHitsAtMaximumBits === 64,
      evidence: "u32 restricts the theorem salt space monotonically for soundness; 2^32/2^26=64 expected honest hits",
    },
    {
      id: "bcs-endpoints",
      holds: theoremMap.certificate.endpoints.length === 2 &&
        theoremMap.certificate.endpoints.every(({ passes }) => passes),
      evidence: "Theorem-22 per-query inequality passes exactly at T=1 and T=2^128-1",
    },
  ];
}

export type V17ProductionGrindingRound = {
  readonly id: string;
  readonly grindBits: number;
  /** Canonical proof encoding; the parsed integer is re-encoded LE in the PoW hash. */
  readonly nonceBytes: 4;
  readonly proofCodec: "u32be";
  readonly transcriptEncoding: "u32le";
  readonly transcriptDomain: "v17-theorem-round+pow";
  readonly placement: "before-round-challenge";
};

export type V17ProductionGraphMetadata = {
  readonly schema: "ShieldKit/V17ProductionTheorem/v2";
  readonly traceLog: 18;
  readonly functionDegreeLog: 19;
  readonly quotientDegreeLog: 20;
  readonly evaluationLog: 24;
  readonly theta: { readonly numerator: 181; readonly denominator: 256 };
  readonly logBlowup: 4;
  readonly queries: 44;
  readonly oodValueCount: 98;
  readonly oodValueBytes: 1_568;
  readonly degreeCorrectedBatch: {
    readonly order: typeof V17_PRODUCTION_BATCH_ORDER;
    readonly functionCount: 98;
    readonly quotientCount: 98;
    readonly maskCount: 1;
    readonly width: 197;
    readonly theorem19LeadingFactor: 196;
    readonly fusedForm:
      "mask+beta*A(P)+beta^99*(A(P)-A(Q))/v_Q(P);A=sum(beta^i*f_i)";
  };
  readonly friFoldSchedule: {
    readonly binaryDomainLogs: readonly number[];
    readonly challengeCounts: readonly (1 | 2)[];
    readonly challengeDerivation: "independent-fiat-shamir";
    readonly virtualIntermediate: "deterministic-uncommitted";
    readonly groupedErrorBound: "sum-adjacent-binary-errors";
  };
  readonly rounds: readonly V17ProductionGrindingRound[];
  readonly requiredProofFrames: readonly {
    readonly id: string;
    readonly itemBytes: 4 | 16;
    readonly itemCount: number;
    readonly codec: "u32be" | "qm31";
    readonly beforeRound: string;
  }[];
};

function productionGraphMetadata(theoremMap: V17TheoremMap): V17ProductionGraphMetadata {
  const rounds: readonly V17ProductionGrindingRound[] = theoremMap.rounds.map((round) => ({
    id: round.id,
    grindBits: round.grindBits,
    nonceBytes: 4,
    proofCodec: "u32be",
    transcriptEncoding: "u32le",
    transcriptDomain: "v17-theorem-round+pow",
    placement: "before-round-challenge",
  }));
  const nonceFrames = rounds.map((round) => ({
    id: `roundNonce:${round.id}`,
    itemBytes: 4 as const,
    itemCount: 1,
    codec: "u32be" as const,
    beforeRound: round.id,
  }));
  return {
    schema: "ShieldKit/V17ProductionTheorem/v2",
    traceLog: 18,
    functionDegreeLog: 19,
    quotientDegreeLog: 20,
    evaluationLog: 24,
    theta: { numerator: 181, denominator: 256 },
    logBlowup: 4,
    queries: 44,
    oodValueCount: 98,
    oodValueBytes: 1_568,
    degreeCorrectedBatch: {
      order: V17_PRODUCTION_BATCH_ORDER,
      functionCount: 98,
      quotientCount: 98,
      maskCount: 1,
      width: 197,
      theorem19LeadingFactor: 196,
      fusedForm: "mask+beta*A(P)+beta^99*(A(P)-A(Q))/v_Q(P);A=sum(beta^i*f_i)",
    },
    friFoldSchedule: {
      binaryDomainLogs: Array.from({ length: 17 }, (_, index) => 23 - index),
      challengeCounts: [2, 2, 2, 2, 2, 2, 2, 2, 1],
      challengeDerivation: "independent-fiat-shamir",
      virtualIntermediate: "deterministic-uncommitted",
      groupedErrorBound: "sum-adjacent-binary-errors",
    },
    rounds,
    requiredProofFrames: [
      { id: "oodValues", itemBytes: 16, itemCount: 98, codec: "qm31", beforeRound: "fri:batch" },
      ...nonceFrames,
    ],
  };
}

export function validateV17ProductionGraphMetadata(
  metadata: V17ProductionGraphMetadata,
): V17ProductionGraphMetadata {
  const expectedRoundIds = [
    "air:logup", "air:composition", "air:ood", "fri:batch",
    ...Array.from({ length: 9 }, (_, index) => `fri:fold:${index}`),
    "fri:query",
  ];
  const expectedGrinding = [9, 0, 3, 26, 20, 18, 16, 14, 12, 10, 8, 6, 4, 26];
  const nonceFrames = metadata.requiredProofFrames.filter(({ id }) => id.startsWith("roundNonce:"));
  if (metadata.schema !== "ShieldKit/V17ProductionTheorem/v2" ||
    metadata.traceLog !== 18 || metadata.functionDegreeLog !== 19 ||
    metadata.quotientDegreeLog !== 20 || metadata.evaluationLog !== 24 ||
    metadata.theta.numerator !== 181 || metadata.theta.denominator !== 256 ||
    metadata.logBlowup !== 4 || metadata.queries !== 44 ||
    metadata.oodValueCount !== 98 || metadata.oodValueBytes !== 1_568 ||
    metadata.degreeCorrectedBatch.order.join("|") !==
      V17_PRODUCTION_BATCH_ORDER.join("|") ||
    metadata.degreeCorrectedBatch.functionCount !== 98 ||
    metadata.degreeCorrectedBatch.quotientCount !== 98 ||
    metadata.degreeCorrectedBatch.maskCount !== 1 ||
    metadata.degreeCorrectedBatch.width !== 197 ||
    metadata.degreeCorrectedBatch.theorem19LeadingFactor !== 196 ||
    metadata.degreeCorrectedBatch.fusedForm !==
      "mask+beta*A(P)+beta^99*(A(P)-A(Q))/v_Q(P);A=sum(beta^i*f_i)" ||
    metadata.friFoldSchedule.binaryDomainLogs.join(",") !==
      "23,22,21,20,19,18,17,16,15,14,13,12,11,10,9,8,7" ||
    metadata.friFoldSchedule.challengeCounts.join(",") !== "2,2,2,2,2,2,2,2,1" ||
    metadata.friFoldSchedule.challengeDerivation !== "independent-fiat-shamir" ||
    metadata.friFoldSchedule.virtualIntermediate !== "deterministic-uncommitted" ||
    metadata.friFoldSchedule.groupedErrorBound !== "sum-adjacent-binary-errors" ||
    metadata.rounds.length !== expectedRoundIds.length ||
    metadata.rounds.some((round, index) => round.id !== expectedRoundIds[index] ||
      round.grindBits !== expectedGrinding[index] ||
      round.nonceBytes !== 4 || round.proofCodec !== "u32be" ||
      round.transcriptEncoding !== "u32le" ||
      round.transcriptDomain !== "v17-theorem-round+pow" ||
      round.placement !== "before-round-challenge") ||
    metadata.requiredProofFrames[0]?.id !== "oodValues" ||
    metadata.requiredProofFrames[0]?.itemBytes !== 16 ||
    metadata.requiredProofFrames[0]?.itemCount !== 98 ||
    metadata.requiredProofFrames[0]?.codec !== "qm31" ||
    metadata.requiredProofFrames[0]?.beforeRound !== "fri:batch" ||
    nonceFrames.length !== expectedRoundIds.length ||
    nonceFrames.some((frame, index) => frame.id !== `roundNonce:${expectedRoundIds[index]}` ||
      frame.itemBytes !== 4 || frame.itemCount !== 1 || frame.codec !== "u32be" ||
      frame.beforeRound !== expectedRoundIds[index])) {
    throw new Error("v17 production theorem metadata");
  }
  return metadata;
}

export type V17ProductionAnnotatedConstructionGraph = V17ConstructionGraph & {
  /** Optional external certificate copy; the authoritative parameters live in foundation. */
  readonly productionTheorem?: V17ProductionGraphMetadata;
};

export type V17ProductionGraphAudit = {
  readonly compatible: boolean;
  readonly observedLegacyBatchWidth: number;
  readonly failures: readonly string[];
};

/** Compare the exact target to the current construction graph without blessing it. */
export function auditV17ProductionConstructionGraph(
  graph: V17ProductionAnnotatedConstructionGraph = V17_CONSTRUCTION_GRAPH,
): V17ProductionGraphAudit {
  const dimensions = deriveV17ProductionFunctionDimensions(graph);
  const failures: string[] = [];
  if (graph.version !== 17 || graph.proof.version !== 17) failures.push("stale-v16-proof-version");
  if (graph.verifierKeyDigests.some(({ status }) => status !== "derived-v17")) {
    failures.push("stale-v16-verifier-key");
  }
  const oodFrame = graph.proof.frames.find(({ id }) => id === "oodValues");
  if (!oodFrame || oodFrame.itemBytes !== 16 || oodFrame.itemCount !== 98 ||
    oodFrame.codec !== "qm31") {
    failures.push("missing-exact-ood-values-frame");
  }
  const legacyGrind = graph.proof.frames.find(({ id }) => id === "grindNonce");
  if (legacyGrind || graph.transcript.some(({ id }) => id === "grind")) {
    failures.push("single-grind-layout");
  }
  if (graph.foundation.relationLog !== 18 || graph.foundation.functionDegreeLog !== 19 ||
    graph.foundation.sealedDegreeLog !== 19 || graph.foundation.quotientDegreeLog !== 20 ||
    graph.foundation.evaluationLog !== 24 || graph.foundation.friLogBlowup !== 4 ||
    graph.foundation.theta.numerator !== 181 || graph.foundation.theta.denominator !== 256 ||
    graph.foundation.queries !== 44 || graph.foundation.maximumRoundGrindingBits !== 26 ||
    graph.foundation.oodValueCount !== 98 ||
    graph.foundation.degreeCorrectedBatchWidth !== 197) {
    failures.push("stale-production-parameters");
  }
  const expectedRoundIds = V17_PRODUCTION_CORRESPONDENCE_GATES.length === 7
    ? ["air:logup", "air:composition", "air:ood", "fri:batch",
      ...Array.from({ length: 9 }, (_, index) => `fri:fold:${index}`), "fri:query"]
    : [];
  const expectedGrinds = [9, 0, 3, 26, 20, 18, 16, 14, 12, 10, 8, 6, 4, 26];
  if (graph.foundation.roundGrinding.length !== expectedRoundIds.length ||
    graph.foundation.roundGrinding.some((round, index) =>
      round.id !== expectedRoundIds[index] || round.bits !== expectedGrinds[index]) ||
    graph.foundation.grindingNonce.serializedBytes !== 4 ||
    graph.foundation.grindingNonce.proofCodec !== "u32be" ||
    graph.foundation.grindingNonce.transcriptEncoding !== "u32le" ||
    graph.foundation.grindingNonce.theoremSaltRestriction !==
      "soundness-monotone-completeness-only") {
    failures.push("stale-round-grinding-layout");
  }
  const foldChallengeFrames = graph.proof.frames.filter(({ id }) => id.startsWith("friAlpha:"));
  if (graph.foundation.friFoldChallengeCounts.join(",") !== "2,2,2,2,2,2,2,2,1" ||
    graph.foundation.friChallengeDerivation !== "independent-fiat-shamir" ||
    graph.foundation.virtualIntermediate !== "deterministic-uncommitted" ||
    foldChallengeFrames.length !== 17) {
    failures.push("stale-grouped-fold-challenges");
  }
  let metadataValid = true;
  if (graph.productionTheorem !== undefined) {
    try {
      validateV17ProductionGraphMetadata(graph.productionTheorem);
    } catch {
      metadataValid = false;
      failures.push("invalid-production-theorem-metadata");
    }
  }
  if (dimensions.legacyUncorrectedBatchWidthIncludingMask !== 28 || !metadataValid ||
    graph.foundation.degreeCorrectedBatchWidth !== 197 ||
    graph.productionTheorem?.degreeCorrectedBatch.width === undefined &&
      graph.foundation.degreeCorrectedBatchWidth !== 197) {
    failures.push("uncorrected-batch-layout");
  }
  const requiredFrames = productionGraphMetadata(buildV17TheoremMap({
    air: v17ProductionFlatAirInput(),
    fri: V17_PRODUCTION_FRI_CANDIDATE,
    gates: V17_PRODUCTION_CORRESPONDENCE_GATES,
    firstReduction: V17_PRODUCTION_FIRST_REDUCTION,
  })).requiredProofFrames;
  for (const required of requiredFrames) {
    const frame = graph.proof.frames.find(({ id }) => id === required.id);
    if (!frame || frame.itemBytes !== required.itemBytes || frame.itemCount !== required.itemCount ||
      frame.codec !== required.codec) {
      failures.push(`missing-proof-frame:${required.id}`);
    }
  }
  let lastOrdinal = -1;
  for (const roundId of expectedRoundIds) {
    const phase = graph.transcript.find(({ id }) => id === roundId);
    if (!phase || phase.ordinal <= lastOrdinal ||
      !phase.consumesSections.some(({ id, mode }) =>
        id === `roundNonce:${roundId}` && mode === "named-round-pow")) {
      failures.push(`transcript-round-order:${roundId}`);
      continue;
    }
    lastOrdinal = phase.ordinal;
  }
  return {
    compatible: failures.length === 0,
    observedLegacyBatchWidth: dimensions.legacyUncorrectedBatchWidthIncludingMask,
    failures,
  };
}

function qmPow(value: QM31El, exponent: number): QM31El {
  if (!Number.isSafeInteger(exponent) || exponent < 0) {
    throw new Error("v17 production QM31 exponent");
  }
  let result = QM31_ONE;
  let factor = value;
  let remaining = exponent;
  while (remaining > 0) {
    if ((remaining & 1) === 1) result = qmMul(result, factor);
    factor = qmMul(factor, factor);
    remaining = Math.floor(remaining / 2);
  }
  return result;
}

export type V17IndependentRadixFourFoldInput = {
  readonly values: readonly [QM31El, QM31El, QM31El, QM31El];
  readonly twiddles: readonly [M31El, M31El, M31El];
  readonly challenges: readonly [QM31El, QM31El];
};

export type V17IndependentRadixFourFold = {
  /** Deterministic and therefore not a prover-chosen committed oracle. */
  readonly virtualIntermediate: readonly [QM31El, QM31El];
  readonly folded: QM31El;
};

function v17BinaryFold(
  left: QM31El,
  right: QM31El,
  twiddle: M31El,
  challenge: QM31El,
): QM31El {
  const inverse = m31Inv(twiddle);
  return qmAdd(qmAdd(left, right), qmMul(challenge, qmMulM31(qmSub(left, right), inverse)));
}

/** Two independent binary reductions with an uncommitted deterministic middle oracle. */
export function v17IndependentRadixFourFold(
  input: V17IndependentRadixFourFoldInput,
): V17IndependentRadixFourFold {
  const lower = v17BinaryFold(
    input.values[0], input.values[1], input.twiddles[0], input.challenges[0],
  );
  const upper = v17BinaryFold(
    input.values[2], input.values[3], input.twiddles[1], input.challenges[0],
  );
  return {
    virtualIntermediate: [lower, upper],
    folded: v17BinaryFold(lower, upper, input.twiddles[2], input.challenges[1]),
  };
}

/** Reject any prover-supplied middle value that differs from the deterministic composition. */
export function assertV17VirtualIntermediate(
  input: V17IndependentRadixFourFoldInput,
  claimed: readonly [QM31El, QM31El],
): V17IndependentRadixFourFold {
  const derived = v17IndependentRadixFourFold(input);
  if (!qmEq(derived.virtualIntermediate[0], claimed[0]) ||
    !qmEq(derived.virtualIntermediate[1], claimed[1])) {
    throw new Error("v17 virtual FRI intermediate");
  }
  return derived;
}

/** A(beta)=sum_i beta^i*f_i, with f_0 deliberately not sharing mask's slot. */
export function v17ProductionLinearCombination(
  beta: QM31El,
  values: readonly QM31El[],
): QM31El {
  if (values.length !== V17_PRODUCTION_FUNCTION_DIMENSIONS.oodValueCount) {
    throw new Error("v17 production function vector width");
  }
  let result = QM31_ZERO;
  let power = QM31_ONE;
  for (const value of values) {
    result = qmAdd(result, qmMul(power, value));
    power = qmMul(power, beta);
  }
  return result;
}

export type V17ProductionBatchInput = {
  readonly beta: QM31El;
  readonly maskAtP: QM31El;
  readonly functionsAtP: readonly QM31El[];
  readonly functionsAtQ: readonly QM31El[];
  readonly vanishPoint: V17Qm31CirclePoint;
  readonly point: V17Qm31CirclePoint;
};

/**
 * Minimal exact Protocol-4 batch, with no separate correction commitment:
 *   H(P)=mask(P)+beta*A(P)+beta^(m+1)*(A(P)-A(Q))/v_Q(P).
 */
export function v17ProductionFusedBatchValue(input: V17ProductionBatchInput): QM31El {
  const m = V17_PRODUCTION_FUNCTION_DIMENSIONS.oodValueCount;
  if (input.functionsAtP.length !== m || input.functionsAtQ.length !== m) {
    throw new Error("v17 production batch width");
  }
  const aAtP = v17ProductionLinearCombination(input.beta, input.functionsAtP);
  const aAtQ = v17ProductionLinearCombination(input.beta, input.functionsAtQ);
  const vanishing = v17PointVanishing(input.vanishPoint, input.point);
  const correction = qmMul(qmSub(aAtP, aAtQ), qmInv(vanishing));
  return qmAdd(
    input.maskAtP,
    qmAdd(
      qmMul(input.beta, aAtP),
      qmMul(qmPow(input.beta, m + 1), correction),
    ),
  );
}

/** Slow explicit [mask,f_0..f_97,g_0..g_97] form used as a KAT oracle. */
export function v17ProductionExplicitBatchValue(input: V17ProductionBatchInput): QM31El {
  const m = V17_PRODUCTION_FUNCTION_DIMENSIONS.oodValueCount;
  if (input.functionsAtP.length !== m || input.functionsAtQ.length !== m) {
    throw new Error("v17 production batch width");
  }
  const quotients = input.functionsAtP.map((value, index) => v17EvaluationQuotient(
    value,
    input.functionsAtQ[index]!,
    input.vanishPoint,
    input.point,
  ));
  const vector = [input.maskAtP, ...input.functionsAtP, ...quotients];
  if (vector.length !== V17_PRODUCTION_FUNCTION_DIMENSIONS.degreeCorrectedBatchWidth) {
    throw new Error("v17 production canonical batch vector");
  }
  let result = QM31_ZERO;
  let power = QM31_ONE;
  for (const value of vector) {
    result = qmAdd(result, qmMul(power, value));
    power = qmMul(power, input.beta);
  }
  return result;
}

export type V17ProductionTheoremInstantiation = {
  readonly dimensions: V17ProductionFunctionDimensions;
  readonly air: V17FlatAirTheoremInput;
  readonly fri: V17FriParameterCandidate;
  readonly theoremMap: V17TheoremMap;
  readonly assumptions: readonly V17ProductionAssumption[];
  readonly graphMetadata: V17ProductionGraphMetadata;
  readonly graphAudit: V17ProductionGraphAudit;
  readonly qualified: false;
  readonly reasons: readonly string[];
};

export type V17RuntimeProductionTheoremInstantiation = {
  readonly assurance: V17ProductionAssuranceCertificate;
  readonly dimensions: V17ProductionFunctionDimensions;
  readonly air: V17FlatAirTheoremInput;
  readonly fri: V17FriParameterCandidate;
  readonly theoremMap: V17TheoremMap;
  readonly assumptions: readonly V17ProductionAssumption[];
  readonly graphMetadata: V17ProductionGraphMetadata;
  readonly graphAudit: V17ProductionGraphAudit;
  readonly qualified: boolean;
  readonly reasons: readonly string[];
};

/**
 * Evaluate the theorem against an explicit, identity-bound assurance table.
 * This is the only path which may return `qualified: true`; the static export
 * below deliberately keeps unresolved product rows as a fail-closed default.
 */
export function evaluateV17ProductionTheorem(
  rows: readonly V17ProductionAssuranceRow[],
  graph: V17ProductionAnnotatedConstructionGraph = V17_CONSTRUCTION_GRAPH,
): V17RuntimeProductionTheoremInstantiation {
  const assurance = certifyV17ProductionAssuranceRows(rows);
  const air = v17ProductionFlatAirInput();
  const fri = V17_PRODUCTION_FRI_CANDIDATE;
  const theoremMap = buildV17TheoremMap({
    air,
    fri,
    gates: v17CorrespondenceGatesFromAssuranceRows(rows),
    firstReduction: V17_PRODUCTION_FIRST_REDUCTION,
  });
  const assumptions = productionAssumptions(theoremMap);
  const graphMetadata = validateV17ProductionGraphMetadata(
    productionGraphMetadata(theoremMap),
  );
  const graphAudit = auditV17ProductionConstructionGraph(graph);
  const reasons = [
    ...assurance.reasons.map((reason) => `assurance:${reason}`),
    ...theoremMap.certificate.reasons,
    ...assumptions.filter(({ holds }) => !holds).map(({ id }) => `assumption:${id}`),
    ...graphAudit.failures.map((failure) => `graph:${failure}`),
  ];
  const qualified = assurance.qualified && theoremMap.certificate.qualified &&
    assumptions.every(({ holds }) => holds) && graphAudit.compatible;
  if (qualified !== (reasons.length === 0)) {
    throw new Error("v17 production theorem qualification invariant");
  }
  return {
    assurance,
    dimensions: V17_PRODUCTION_FUNCTION_DIMENSIONS,
    air,
    fri,
    theoremMap,
    assumptions,
    graphMetadata,
    graphAudit,
    qualified,
    reasons,
  };
}

export function instantiateV17ProductionTheorem(
  graph: V17ProductionAnnotatedConstructionGraph = V17_CONSTRUCTION_GRAPH,
): V17ProductionTheoremInstantiation {
  const evaluated = evaluateV17ProductionTheorem(V17_PRODUCTION_ASSURANCE_ROWS, graph);
  if (evaluated.qualified || evaluated.theoremMap.certificate.qualified ||
    evaluated.reasons.length === 0) {
    throw new Error("v17 production theorem fail-closed invariant");
  }
  return {
    dimensions: evaluated.dimensions,
    air: evaluated.air,
    fri: evaluated.fri,
    theoremMap: evaluated.theoremMap,
    assumptions: evaluated.assumptions,
    graphMetadata: evaluated.graphMetadata,
    graphAudit: evaluated.graphAudit,
    qualified: false,
    reasons: evaluated.reasons,
  };
}

export const V17_PRODUCTION_THEOREM = instantiateV17ProductionTheorem();

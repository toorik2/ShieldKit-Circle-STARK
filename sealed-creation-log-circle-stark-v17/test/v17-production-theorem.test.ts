import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { rational, rAdd, rCompare, rMul, rPow } from "../src/assurance/rational.ts";
import { defaultV17FriParameterCandidates, groupV17BinaryFoldBounds } from
  "../src/assurance/v17-parameter-synthesis.ts";
import {
  V17_INTERACTION_REDUCTION_CERTIFICATE,
  V17_PRODUCTION_ASSURANCE_CERTIFICATE,
  V17_PRODUCTION_ASSURANCE_ROW_IDS,
  V17_PRODUCTION_ASSURANCE_ROWS,
  V17_PRODUCTION_CORRESPONDENCE_GATES,
  V17_PRODUCTION_FRI_CANDIDATE,
  V17_PRODUCTION_FUNCTION_DIMENSIONS,
  V17_PRODUCTION_THEOREM,
  V17_SEAL_QUOTIENT_CERTIFICATE,
  assertV17ProductionFriCandidate,
  auditV17ProductionConstructionGraph,
  assertV17VirtualIntermediate,
  certifyV17ProductionAssuranceRows,
  deriveV17ProductionFunctionDimensions,
  validateV17ProductionGraphMetadata,
  v17ProductionExplicitBatchValue,
  v17ProductionFlatAirInput,
  v17ProductionFusedBatchValue,
  v17ProductionLinearCombination,
  v17IndependentRadixFourFold,
  type V17ProductionAnnotatedConstructionGraph,
  type V17ProductionGraphMetadata,
} from "../src/assurance/v17-production-theorem.ts";
import {
  V17_CORRESPONDENCE_GATE_IDS,
} from "../src/assurance/v17-theorem-map.ts";
import { v17FriJohnsonBounds } from "../src/assurance/v17-soundness.ts";
import {
  deriveV17OodsChallenge,
  liftCirclePoint,
} from "../src/backends/circle/v17-oods.ts";
import {
  qm31,
  qmAdd,
  qmEq,
  qmMul,
  qmNeg,
  type QM31El,
} from "../src/backends/circle/qm31.ts";
import { successorCirclePointAtBitReversed } from
  "../src/backends/circle/successor-domain.ts";
import {
  V17_CONSTRUCTION_GRAPH,
  validateV17ConstructionGraph,
} from "../src/construction/v17-graph.ts";

describe("v17 exact production theorem instantiation", () => {
  it("derives the 98 OOD functions and M=197 from actual committed AIR geometry", () => {
    const dimensions = deriveV17ProductionFunctionDimensions();
    assert.deepEqual(dimensions, V17_PRODUCTION_FUNCTION_DIMENSIONS);
    assert.equal(dimensions.relationRows, 2 ** 18);
    assert.equal(dimensions.preprocessedBaseFunctions, 43);
    assert.equal(dimensions.originalBaseFunctions, 34);
    assert.equal(dimensions.interactionSemanticFunctions, 17);
    assert.equal(dimensions.interactionCoordinateColumns, 68);
    assert.equal(dimensions.predecessorSemanticFunctions, 3);
    assert.equal(dimensions.predecessorCoordinateColumns, 12);
    assert.equal(dimensions.compositionQuotientSemanticFunctions, 1);
    assert.equal(dimensions.compositionQuotientCoordinateColumns, 4);
    assert.equal(dimensions.oodValueCount, 43 + 34 + 17 + 3 + 1);
    assert.equal(dimensions.oodValueBytes, 98 * 16);
    assert.equal(dimensions.evaluationQuotientFunctions, 98);
    assert.equal(dimensions.degreeCorrectedBatchWidth, 1 + 2 * 98);
    assert.equal(dimensions.theorem19BatchLeadingFactor, 196);
    assert.equal(dimensions.legacyPackedOriginalFunctions, 9);
    assert.equal(dimensions.legacyUncorrectedBatchWidthIncludingMask, 28);
  });

  it("instantiates Theorems 15, 19, 21, and 22 with exact rational gates", () => {
    const theorem = V17_PRODUCTION_THEOREM;
    assert.equal(theorem.fri.batchWidth, 197);
    assert.deepEqual(theorem.fri.theta, rational(181n, 256n));
    assert.equal(theorem.fri.logBlowup, 4);
    assert.equal(theorem.fri.queries, 44);
    assert.equal(theorem.fri.proofCoreCeiling.totalBytes, 317_334);
    assert.equal(theorem.fri.binaryFoldBounds.length, 17);
    assert.deepEqual(theorem.fri.foldChallengeCounts, [2, 2, 2, 2, 2, 2, 2, 2, 1]);
    assert.deepEqual(theorem.theoremMap.rounds.map(({ grindBits }) => grindBits),
      [9, 0, 3, 26, 20, 18, 16, 14, 12, 10, 8, 6, 4, 26]);
    assert.equal(theorem.theoremMap.rounds.length, 14);
    assert.equal(theorem.assumptions.length, 9);
    assert.ok(theorem.assumptions.every(({ holds }) => holds));
    assert.deepEqual(V17_PRODUCTION_CORRESPONDENCE_GATES.map(({ id }) => id),
      V17_CORRESPONDENCE_GATE_IDS);
    assert.equal(V17_PRODUCTION_CORRESPONDENCE_GATES.length, 7);
    assert.ok(V17_PRODUCTION_CORRESPONDENCE_GATES.some(({ status }) => status === "unresolved"));
    assert.equal(theorem.theoremMap.certificate.qualified, false);
    assert.equal(theorem.qualified, false);
    assert.ok(theorem.reasons.some((reason) => reason.includes("flat-air-shape")));

    const queryRound = theorem.theoremMap.rounds.at(-1)!;
    assert.equal(rCompare(queryRound.rawError, rPow(rational(75n, 256n), 44)), 0);
    assert.ok(theorem.theoremMap.certificate.endpoints.every(({ passes }) => passes));
  });

  it("certifies the custom first reduction and the augmented r=s=0 AIR separately", () => {
    const reduction = V17_INTERACTION_REDUCTION_CERTIFICATE;
    assert.equal(reduction.relationRows, 2 ** 18);
    assert.equal(reduction.lookupTerms, 8 * (2 ** 18) + 1_841);
    assert.equal(reduction.wordCopySlots, 3 * (2 ** 18));
    assert.equal(reduction.publicBoundaryMessages, 8);
    assert.deepEqual(reduction.residualPartition, {
      lookupRunningSum: [0, 9],
      wordCopyGrandProduct: [9, 16],
      localWordGate: [16, 23],
      publicBoundaryReduction: [23, 25],
    });
    assert.equal(reduction.directDegreeTerms.total, 6_557_314);
    assert.equal(reduction.chargedEnvelopeTerms, 37_748_808);
    assert.equal(reduction.envelopeDominatesDirectTerms, true);
    assert.equal(rCompare(
      V17_PRODUCTION_THEOREM.theoremMap.rounds[0]!.rawError,
      reduction.rawError,
    ), 0);

    const air = v17ProductionFlatAirInput();
    assert.equal(air.inputMessages, 0n);
    assert.equal(air.outputMessages, 0n);
    assert.equal(air.tables.length, 1);
    assert.equal(air.tables[0]!.uses, 0n);
    assert.equal(air.tables[0]!.yields, 0n);
    assert.equal(air.tables[0]!.maximumMultiplicity, 0n);
    assert.equal(air.tables[0]!.constraints, 25n);
  });

  it("certifies the full-dimensional affine seal and one whole quotient", () => {
    const seal = V17_SEAL_QUOTIENT_CERTIFICATE;
    assert.equal(seal.traceDimension, 262_144);
    assert.equal(seal.randomizerDimension, 262_144);
    assert.equal(seal.sealedDimension, 524_288);
    assert.equal(seal.restrictionKernelDimension, 262_144);
    assert.equal(seal.traceZerofierDegree, 131_072);
    assert.equal(seal.maximumSealedDegree, 262_144);
    assert.equal(seal.maximumConstraintDegree, 2);
    assert.equal(seal.maximumCompositionDegree, 524_288);
    assert.equal(seal.maximumQuotientDegree, 393_216);
    assert.equal(seal.quotientSpaceStrictDegreeCap, 524_288);
    assert.equal(seal.quotientFits, true);
  });

  it("fails every assurance qualification row closed outside cited/proved", () => {
    assert.deepEqual(V17_PRODUCTION_ASSURANCE_ROWS.map(({ id }) => id),
      V17_PRODUCTION_ASSURANCE_ROW_IDS);
    assert.equal(V17_PRODUCTION_ASSURANCE_CERTIFICATE.qualified, false);
    assert.deepEqual(V17_PRODUCTION_ASSURANCE_CERTIFICATE.reasons, [
      "product-first-reduction-transcript:unresolved",
      "product-ood-air-role:unresolved",
      "product-batch-link-roles:unresolved",
      "product-grouped-fri-transcript:unresolved",
      "product-mixed-merkle-codec:unresolved",
    ]);

    const qualifying = V17_PRODUCTION_ASSURANCE_ROWS.map((row) => ({
      ...row,
      status: row.id === "s-two-theorem-formulas" ? "cited" as const : "proved" as const,
    }));
    assert.equal(certifyV17ProductionAssuranceRows(qualifying).qualified, true);
    for (const status of ["conjectural", "unresolved", "skipped", "cache-only"] as const) {
      const mutated = qualifying.map((row) => row.id === "lookup-running-sum"
        ? { ...row, status }
        : row);
      const certificate = certifyV17ProductionAssuranceRows(mutated);
      assert.equal(certificate.qualified, false, status);
      assert.deepEqual(certificate.reasons, [`lookup-running-sum:${status}`], status);
    }
  });

  it("charges the exact Theorem-19 leading factor M-1=196", () => {
    const candidate = V17_PRODUCTION_FRI_CANDIDATE;
    const width196 = v17FriJohnsonBounds({
      logBlowup: candidate.logBlowup,
      evaluationLog: candidate.evaluationLog,
      batchWidth: 196,
      foldDomainLogs: Array.from({ length: 17 }, (_, index) => 23 - index),
      queries: candidate.queries,
      theta: candidate.theta,
    });
    // epsilon_batch is exactly linear in M-1: 196/195 between M=197 and M=196.
    assert.equal(rCompare(
      rMul(candidate.bounds.batch, rational(195n)),
      rMul(width196.batch, rational(196n)),
    ), 0);
  });

  it("rejects stale theorem parameters while accepting the freshly derived v17 keys", () => {
    assert.throws(
      () => assertV17ProductionFriCandidate(defaultV17FriParameterCandidates()[0]!),
      /stale or non-production/,
    );
    const audit = auditV17ProductionConstructionGraph();
    assert.equal(audit.compatible, true);
    assert.equal(audit.observedLegacyBatchWidth, 28);
    assert.deepEqual(audit.failures, []);

    const staleVersion = {
      ...V17_CONSTRUCTION_GRAPH,
      version: 16,
      proof: { ...V17_CONSTRUCTION_GRAPH.proof, version: 16 },
    } as unknown as V17ProductionAnnotatedConstructionGraph;
    assert.ok(auditV17ProductionConstructionGraph(staleVersion).failures.includes(
      "stale-v16-proof-version",
    ));

    const staleParameters = {
      ...V17_CONSTRUCTION_GRAPH,
      foundation: { ...V17_CONSTRUCTION_GRAPH.foundation, queries: 29 },
    } as unknown as V17ProductionAnnotatedConstructionGraph;
    assert.ok(auditV17ProductionConstructionGraph(staleParameters).failures.includes(
      "stale-production-parameters",
    ));

    const derivedSquare = structuredClone(V17_CONSTRUCTION_GRAPH) as unknown as {
      foundation: { friChallengeDerivation: string };
    };
    derivedSquare.foundation.friChallengeDerivation = "alpha1-is-alpha0-squared";
    assert.throws(() => validateV17ConstructionGraph(
      derivedSquare as unknown as typeof V17_CONSTRUCTION_GRAPH,
    ), /foundation/);
    assert.ok(auditV17ProductionConstructionGraph(
      derivedSquare as unknown as V17ProductionAnnotatedConstructionGraph,
    ).failures.includes("stale-grouped-fold-challenges"));

    assert.equal(validateV17ProductionGraphMetadata(V17_PRODUCTION_THEOREM.graphMetadata),
      V17_PRODUCTION_THEOREM.graphMetadata);
    const wrongWidth = structuredClone(V17_PRODUCTION_THEOREM.graphMetadata) as unknown as
      { degreeCorrectedBatch: { width: number } };
    wrongWidth.degreeCorrectedBatch.width = 55;
    assert.throws(() => validateV17ProductionGraphMetadata(
      wrongWidth as unknown as V17ProductionGraphMetadata,
    ), /metadata/);

    const singleGrind = structuredClone(V17_PRODUCTION_THEOREM.graphMetadata) as
      V17ProductionGraphMetadata & { rounds: V17ProductionGraphMetadata["rounds"] };
    Object.defineProperty(singleGrind, "rounds", {
      value: [singleGrind.rounds.at(-1)!],
      configurable: true,
    });
    assert.throws(() => validateV17ProductionGraphMetadata(singleGrind), /metadata/);
  });

  it("uses independent fold challenges and a deterministic virtual intermediate", () => {
    const binaryBounds = V17_PRODUCTION_FRI_CANDIDATE.binaryFoldBounds;
    const groupedBounds = groupV17BinaryFoldBounds(binaryBounds);
    assert.equal(binaryBounds.length, 17);
    assert.equal(groupedBounds.length, 9);
    for (let group = 0; group < 8; group += 1) {
      assert.equal(rCompare(
        groupedBounds[group]!,
        rAdd(binaryBounds[2 * group]!, binaryBounds[2 * group + 1]!),
      ), 0);
    }
    assert.equal(rCompare(groupedBounds[8]!, binaryBounds[16]!), 0);

    const alpha0 = qm31(2n, 3n, 5n, 7n);
    const alpha1 = qm31(11n, 13n, 17n, 19n);
    const input = {
      values: [
        qm31(1n, 2n, 3n, 4n),
        qm31(5n, 6n, 7n, 8n),
        qm31(9n, 10n, 11n, 12n),
        qm31(13n, 14n, 15n, 16n),
      ],
      twiddles: [3n, 5n, 7n],
      challenges: [alpha0, alpha1],
    } as const;
    const independent = v17IndependentRadixFourFold(input);
    assert.deepEqual(assertV17VirtualIntermediate(input, independent.virtualIntermediate), independent);
    const mutated = [
      qmAdd(independent.virtualIntermediate[0], qm31(1n, 0n, 0n, 0n)),
      independent.virtualIntermediate[1],
    ] as const;
    assert.throws(() => assertV17VirtualIntermediate(input, mutated), /virtual FRI intermediate/);

    const alphaSquared = v17IndependentRadixFourFold({
      ...input,
      challenges: [alpha0, qmMul(alpha0, alpha0)],
    });
    assert.equal(qmEq(independent.folded, alphaSquared.folded), false);
  });

  it("fuses [mask,f_i,g_i] without a correction root or mask/f0 collision", () => {
    const transcriptDigest = Uint8Array.from({ length: 32 }, (_, index) => index);
    const vanishPoint = deriveV17OodsChallenge(transcriptDigest).point;
    const point = liftCirclePoint(successorCirclePointAtBitReversed(24, 0x51f15));
    const beta = qm31(2n, 3n, 5n, 7n);
    const maskAtP = qm31(11n, 13n, 17n, 19n);
    const functionsAtP = Array.from({ length: 98 }, (_, index): QM31El =>
      qm31(BigInt(index + 1), BigInt(index + 2), BigInt(index + 3), BigInt(index + 4)));
    const functionsAtQ = Array.from({ length: 98 }, (_, index): QM31El =>
      qm31(BigInt(index + 101), BigInt(index + 102), BigInt(index + 103), BigInt(index + 104)));
    const input = { beta, maskAtP, functionsAtP, functionsAtQ, vanishPoint, point };
    assert.equal(qmEq(
      v17ProductionFusedBatchValue(input),
      v17ProductionExplicitBatchValue(input),
    ), true);

    const value = qm31(23n, 29n, 31n, 37n);
    const equalAtPAndQ = Array.from({ length: 98 }, (): QM31El => qm31(0n, 0n, 0n, 0n));
    equalAtPAndQ[0] = value;
    const collidingMask = qmNeg(value);
    // The stale mask+A layout cancels identically when mask=-f0.
    assert.equal(qmEq(
      collidingMask,
      qmNeg(v17ProductionLinearCombination(beta, equalAtPAndQ)),
    ), true);
    // Canonical powers are [mask,beta*f0,...], so the same choice cannot cancel.
    assert.equal(qmEq(v17ProductionFusedBatchValue({
      beta,
      maskAtP: collidingMask,
      functionsAtP: equalAtPAndQ,
      functionsAtQ: equalAtPAndQ,
      vanishPoint,
      point,
    }), qm31(0n, 0n, 0n, 0n)), false);
  });
});

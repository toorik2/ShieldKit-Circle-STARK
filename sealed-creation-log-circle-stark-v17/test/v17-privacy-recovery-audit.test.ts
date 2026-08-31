import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  auditLocalWordProtectedTraceRecovery,
  certifyLocalWordProtectedTraceOpeningNonUniqueness,
} from "../src/backends/circle/local-word-observer-view.ts";
import {
  LOCAL_WORD_MATRIX_NAMES,
  LOCAL_WORD_MATRIX_ROW_WIDTHS,
  localWordOpeningSchedules,
  type LocalWordMatrixOpening,
  type LocalWordProofContext,
  type LocalWordSealedProof,
} from "../src/backends/circle/local-word-sealed-proof.ts";
import {
  LOCAL_WORD_PRODUCTION_PARAMETERS,
  type LocalWordProofParameters,
} from "../src/backends/circle/local-word-successor-params.ts";
import {
  successorCirclePointAtBitReversed,
  successorTraceOffsetIndex,
} from "../src/backends/circle/successor-domain.ts";
import { QM31_ZERO } from "../src/backends/circle/qm31.ts";
import {
  liftCirclePoint,
  v17CayleyPoint,
} from "../src/backends/circle/v17-oods.ts";

function fixtureQueries(parameters: LocalWordProofParameters): readonly number[] {
  const rowCount = 2 ** parameters.evalLog;
  const orbitSize = 2 ** parameters.fri.queryOrbitLog;
  const orbitCount = rowCount / orbitSize;
  const queries: number[] = [];
  const global = new Set<number>();
  const usedOrbits = new Set<number>();
  for (let item = 0; item < parameters.fri.queries; item += 1) {
    for (let jitter = 0; jitter < orbitCount; jitter += 1) {
      const orbit = (Math.floor(item * orbitCount / parameters.fri.queries) + jitter) % orbitCount;
      if (usedOrbits.has(orbit)) continue;
      const query = orbit * orbitSize + ((orbit * 37 + 3) % orbitSize);
      const previous = successorTraceOffsetIndex(
        query,
        parameters.relationLog,
        parameters.evalLog,
        -1,
      );
      if (query === previous || global.has(query) || global.has(previous)) continue;
      queries.push(query);
      global.add(query);
      global.add(previous);
      usedOrbits.add(orbit);
      break;
    }
  }
  if (queries.length !== parameters.fri.queries) throw new Error("privacy query fixture");
  return queries;
}

function opening(
  index: number,
  indices: readonly number[],
): LocalWordMatrixOpening {
  const rowWidth = LOCAL_WORD_MATRIX_ROW_WIDTHS[index]!;
  return {
    root: new Uint8Array(32).fill(index + 1),
    rowWidth,
    indices: [...indices],
    rows: indices.map(() => new Uint8Array(rowWidth)),
    siblings: [],
  };
}

function scheduleProof(): LocalWordSealedProof {
  const queries = fixtureQueries(LOCAL_WORD_PRODUCTION_PARAMETERS);
  const schedules = localWordOpeningSchedules(queries);
  const matrices = Object.fromEntries(LOCAL_WORD_MATRIX_NAMES.map((name, index) => [
    name,
    opening(index, name === "interactionGlobal" ? schedules.global : schedules.current),
  ])) as LocalWordSealedProof["matrices"];
  return {
    version: 17,
    profile: 0,
    protocolId: new Uint8Array(32),
    proofLength: 0,
    publicBoundaryInverses: [],
    publicBoundaryClaimedSum: QM31_ZERO,
    matrices,
    fri: {
      layers: schedules.fri.map((indices, round) => ({
        root: new Uint8Array(32).fill(round + 10),
        indices: [...indices],
        values: indices.map(() => QM31_ZERO),
        siblings: [],
      })),
      finalCoefficients: [],
      grindNonce: 0,
    },
    transcriptManifest: {
      interactionChallenges: [],
      interactionDigest: new Uint8Array(32),
      constraintAlpha: QM31_ZERO,
      compositionDigest: new Uint8Array(32),
      batchBeta: QM31_ZERO,
      batchDigest: new Uint8Array(32),
      friAlphas: [],
      friMidDigest: new Uint8Array(32),
      friRootsDigest: new Uint8Array(32),
      queryDigest: new Uint8Array(32),
    },
    queries,
  };
}

const UNUSED_LEGACY_CONTEXT: LocalWordProofContext = {
  profile: 0,
  transcriptInitial: Uint8Array.of(1),
  constructionDescriptor: Uint8Array.of(1),
  publicWords: [],
  expectedPreprocessedRoot: new Uint8Array(32).fill(1),
};

describe("v17 protected-trace recovery audit", () => {
  it("constructs a zero-residual ambiguity witness for all q44 openings and the QM31 OOD claim", () => {
    const proof = scheduleProof();
    const oodPoint = v17CayleyPoint([7n, 11n, 13n, 17n]);
    const audit = certifyLocalWordProtectedTraceOpeningNonUniqueness({
      currentIndices: proof.matrices.original.indices,
      oodPoint,
    });

    assert.equal(audit.recovered, false);
    assert.equal(audit.linearSystem.equationsPerColumn, 48);
    assert.equal(audit.linearSystem.certifiedRankPerColumn, 48);
    assert.equal(audit.linearSystem.conditionedMaskNullityPerColumn, 262_096);
    assert.equal(audit.linearSystem.jointTraceAndMaskNullityPerColumn, 524_240);
    assert.equal(audit.compensatingWitness.maskCoefficientCount, 48);
    assert.ok(audit.compensatingWitness.nonzeroMaskCoefficients > 0);
    assert.equal(audit.compensatingWitness.allOpeningResidualsZero, true);
    assert.equal(audit.compensatingWitness.changesProtectedTrace, true);
  });

  it("binds the legacy no-OOD audit to every exact matrix and FRI schedule", () => {
    const proof = scheduleProof();
    const audit = auditLocalWordProtectedTraceRecovery(proof, UNUSED_LEGACY_CONTEXT);
    assert.equal(audit.recovered, false);
    assert.equal(audit.schedule.checkedOpeningFamilies, 14);
    assert.equal(audit.linearSystem.equationsPerColumn, 44);
    assert.equal(audit.linearSystem.certifiedRankPerColumn, 44);
    assert.equal(audit.observedValues.originalColumns, 34);
    assert.equal(audit.observedValues.oodQm31PointsPerColumn, 0);
    assert.match(audit.schedule.sha256Hex, /^[0-9a-f]{64}$/);
    assert.match(audit.observedValues.sha256Hex, /^[0-9a-f]{64}$/);
  });

  it("fails closed on duplicate queries and duplicate or drifted decoded schedules", () => {
    const duplicateQuery = structuredClone(scheduleProof()) as LocalWordSealedProof;
    const duplicateQueries = [...duplicateQuery.queries];
    duplicateQueries[1] = duplicateQueries[0]!;
    assert.throws(
      () => auditLocalWordProtectedTraceRecovery(
        { ...duplicateQuery, queries: duplicateQueries },
        UNUSED_LEGACY_CONTEXT,
      ),
      /query schedule/,
    );

    const duplicateOriginal = structuredClone(scheduleProof()) as LocalWordSealedProof;
    const duplicateIndices = [...duplicateOriginal.matrices.original.indices];
    duplicateIndices[duplicateIndices.length - 1] = duplicateIndices.at(-2)!;
    assert.throws(
      () => auditLocalWordProtectedTraceRecovery({
        ...duplicateOriginal,
        matrices: {
          ...duplicateOriginal.matrices,
          original: { ...duplicateOriginal.matrices.original, indices: duplicateIndices },
        },
      }, UNUSED_LEGACY_CONTEXT),
      /duplicate matrix original schedule/,
    );

    const driftedFri = structuredClone(scheduleProof()) as LocalWordSealedProof;
    const indices = [...driftedFri.fri.layers[0]!.indices];
    indices[indices.length - 1] = indices.at(-1)! + 1;
    assert.throws(
      () => auditLocalWordProtectedTraceRecovery({
        ...driftedFri,
        fri: {
          ...driftedFri.fri,
          layers: driftedFri.fri.layers.map((layer, round) => round === 0
            ? { ...layer, indices }
            : layer),
        },
      }, UNUSED_LEGACY_CONTEXT),
      /FRI 0 schedule drift/,
    );
  });

  it("fails closed when the dimension or OOD-rank hypotheses are weakened", () => {
    const rankStarved: LocalWordProofParameters = {
      relationLog: 5,
      evalLog: 10,
      quotientDegreeRows: 64,
      fri: {
        logBlowup: 4,
        finalLogDegree: 3,
        foldLog: 2,
        queryOrbitLog: 3,
        queries: 44,
        grindBits: 0,
      },
    };
    assert.throws(
      () => certifyLocalWordProtectedTraceOpeningNonUniqueness({
        currentIndices: Array.from({ length: 44 }, (_, index) => index),
        oodPoint: v17CayleyPoint([7n, 11n, 13n, 17n]),
        parameters: rankStarved,
      }),
      /mask dimensions 48\/32/,
    );

    const basePoint = liftCirclePoint(successorCirclePointAtBitReversed(
      LOCAL_WORD_PRODUCTION_PARAMETERS.evalLog,
      3,
    ));
    assert.throws(
      () => certifyLocalWordProtectedTraceOpeningNonUniqueness({
        currentIndices: scheduleProof().matrices.original.indices,
        oodPoint: basePoint,
      }),
      /OOD rank point/,
    );
  });
});

import assert from "node:assert/strict";
import test from "node:test";

import {
  decodeLocalWordSealedProof,
  encodeLocalWordSealedProof,
  frameLocalWordSealedProof,
  LOCAL_WORD_MATRIX_NAMES,
  localWordOpeningSchedules,
  localWordProofStaticOffsets,
  localWordV17FriMerkleDescriptor,
  localWordV17MatrixMerkleDescriptor,
  type LocalWordSealedProof,
} from "../src/backends/circle/local-word-sealed-proof.ts";
import { inspectLocalWordProofFraming } from
  "../src/backends/circle/local-word-observer-view.ts";
import {
  LOCAL_WORD_PRODUCTION_PARAMETERS,
  localWordFriFoldCounts,
  type LocalWordProofParameters,
} from "../src/backends/circle/local-word-successor-params.ts";
import {
  V17_PROOF_FIXED_PREFIX_BYTES,
  V17_PROOF_FRAMES,
  V17_PROOF_PROTOCOL_ID,
  v17ProofFrameOffset,
} from "../src/backends/circle/v17-proof-layout.ts";
import { V17_THEOREM_ROUND_IDS } from
  "../src/backends/circle/v17-round-transcript.ts";
import {
  QM31_ZERO,
  encodeQm31,
  type QM31El,
} from "../src/backends/circle/qm31.ts";
import {
  v17MerkleOpeningRoot,
  v17MerkleSchedule,
} from "../src/backends/circle/v17-merkle.ts";
import { successorTraceOffsetIndex } from
  "../src/backends/circle/successor-domain.ts";
import { readU32BE } from "../src/pool/bytes.ts";

const SMALL_PARAMETERS: LocalWordProofParameters = {
  relationLog: 6,
  evalLog: 10,
  quotientDegreeRows: 64,
  fri: {
    logBlowup: 4,
    finalLogDegree: 3,
    foldLog: 2,
    queryOrbitLog: 3,
    queries: 8,
    grindBits: 0,
  },
};

function framingQueries(parameters: LocalWordProofParameters): readonly number[] {
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
  if (queries.length !== parameters.fri.queries) throw new Error("v17 framing query fixture");
  localWordOpeningSchedules(queries, parameters);
  return queries;
}

function zeroOpening(
  descriptor: ReturnType<typeof localWordV17MatrixMerkleDescriptor>,
  indices: readonly number[],
): { readonly root: Uint8Array; readonly rows: Uint8Array[]; readonly siblings: Uint8Array[] } {
  const rows = indices.map(() => new Uint8Array(descriptor.rowWidth));
  const siblings = Array.from(
    { length: v17MerkleSchedule(descriptor, indices).siblingCount },
    () => new Uint8Array(32),
  );
  const root = v17MerkleOpeningRoot({
    descriptor,
    rows: indices.map((index, item) => ({ index, raw: rows[item]! })),
    siblings,
  });
  return { root, rows, siblings };
}

function proofFixture(
  parameters: LocalWordProofParameters,
  publicWordCount: number,
): LocalWordSealedProof {
  const queries = framingQueries(parameters);
  const schedules = localWordOpeningSchedules(queries, parameters);
  const matrices = Object.fromEntries(LOCAL_WORD_MATRIX_NAMES.map((matrix) => {
    const descriptor = localWordV17MatrixMerkleDescriptor(matrix, parameters);
    const indices = matrix === "interactionGlobal" ? schedules.global : schedules.current;
    const opening = zeroOpening(descriptor, indices);
    return [matrix, {
      root: opening.root,
      rowWidth: descriptor.rowWidth,
      indices,
      rows: opening.rows,
      siblings: opening.siblings,
    }];
  })) as unknown as LocalWordSealedProof["matrices"];
  const friLayers = schedules.fri.map((indices, layer) => {
    const descriptor = localWordV17FriMerkleDescriptor(layer, parameters);
    const opening = zeroOpening(descriptor, indices);
    return {
      root: opening.root,
      indices,
      values: indices.map((): QM31El => QM31_ZERO),
      siblings: opening.siblings,
    };
  });
  const production = publicWordCount === 8 &&
    parameters === LOCAL_WORD_PRODUCTION_PARAMETERS;
  const roundNonces = production
    ? V17_THEOREM_ROUND_IDS.map(() => 0)
    : undefined;
  const proof: LocalWordSealedProof = {
    version: 17,
    profile: 0,
    protocolId: V17_PROOF_PROTOCOL_ID,
    proofLength: 0,
    publicBoundaryInverses: Array.from({ length: publicWordCount }, (): QM31El => QM31_ZERO),
    publicBoundaryClaimedSum: QM31_ZERO,
    matrices,
    fri: {
      layers: friLayers,
      finalCoefficients: Array.from(
        { length: 2 ** parameters.fri.finalLogDegree },
        (): QM31El => QM31_ZERO,
      ),
      grindNonce: roundNonces?.at(-1) ?? 0,
    },
    transcriptManifest: {
      interactionChallenges: Array.from({ length: 27 }, (): QM31El => QM31_ZERO),
      interactionDigest: new Uint8Array(32),
      constraintAlpha: QM31_ZERO,
      compositionDigest: new Uint8Array(32),
      batchBeta: QM31_ZERO,
      batchDigest: new Uint8Array(32),
      friAlphas: Array.from(
        { length: production ? 17 : localWordFriFoldCounts(parameters).length },
        (): QM31El => QM31_ZERO,
      ),
      friMidDigest: new Uint8Array(32),
      friRootsDigest: new Uint8Array(32),
      queryDigest: new Uint8Array(32),
    },
    ...(production ? {
      oodValues: Array.from({ length: 98 }, (): QM31El => QM31_ZERO),
      roundNonces,
    } : {}),
    queries,
  };
  // Exercise field encoding here so this fixture cannot hide malformed values.
  [...proof.publicBoundaryInverses, ...proof.transcriptManifest.friAlphas].forEach(encodeQm31);
  return proof;
}

test("production proof framing follows every generated fixed frame then one dynamic body", () => {
  const proof = proofFixture(LOCAL_WORD_PRODUCTION_PARAMETERS, 8);
  const encoded = encodeLocalWordSealedProof(proof);
  const framedProof = { ...proof, proofLength: encoded.length };
  const frames = frameLocalWordSealedProof(framedProof);
  assert.equal(frames[0]!.start, 0);
  assert.equal(frames.at(-1)!.end, encoded.length);
  assert.ok(frames.every((frame, index) => index === 0 || frames[index - 1]!.end === frame.start));
  assert.equal(readU32BE(encoded, v17ProofFrameOffset("totalLength")), encoded.length);

  const fixedFrameIds = frames
    .filter(({ generatedFrameId }) => generatedFrameId !== undefined &&
      generatedFrameId !== "openingBodies")
    .map(({ generatedFrameId }) => generatedFrameId!);
  assert.deepEqual([...new Set(fixedFrameIds)], V17_PROOF_FRAMES.map(({ id }) => id));
  assert.equal(frames.filter(({ kind }) => kind === "ood-value").length, 98);
  assert.deepEqual(frames.filter(({ kind }) => kind === "round-nonce").map(({ round }) => round),
    V17_THEOREM_ROUND_IDS);
  assert.equal(frames.filter(({ kind }) => kind === "fri-alpha").length, 17);
  assert.equal(frames.filter(({ kind }) => kind === "opening-directory-word").length, 14 * 5);
  const body = frames.filter(({ generatedFrameId }) => generatedFrameId === "openingBodies");
  assert.ok(body.length > 0);
  assert.equal(body[0]!.start, V17_PROOF_FIXED_PREFIX_BYTES);

  assert.deepEqual(inspectLocalWordProofFraming(framedProof), {
    layout: "generated-v17",
    generatedFrameOrder: true,
    exactPartition: true,
    fixedPrefixBytes: V17_PROOF_FIXED_PREFIX_BYTES,
    dynamicMixedMerkleBodyBytes: encoded.length - V17_PROOF_FIXED_PREFIX_BYTES,
    oodQm31Values: 98,
    namedRoundNonces: 14,
    independentFriAlphas: 17,
    terminalDirectoryEntries: 14,
    dynamicBodyFrames: body.length,
  });

  // This fixture deliberately carries zero PoW nonces. Reaching the named
  // round rejection proves the decoder consumed the generated fixed layout,
  // including the terminal directory, before transcript replay.
  assert.throws(() => decodeLocalWordSealedProof(encoded, {
    profile: 0,
    transcriptInitial: Uint8Array.of(1),
    constructionDescriptor: Uint8Array.of(1),
    publicWords: Array.from({ length: 8 }, (_, item) => ({
      id: BigInt(item + 1),
      row: item,
      expected: 0,
    })),
    expectedPreprocessedRoot: proof.matrices.preprocessed.root,
  }), /v17 transcript PoW/);
});

test("experimental legacy framing retains its original byte order", () => {
  const proof = proofFixture(SMALL_PARAMETERS, 1);
  const encoded = encodeLocalWordSealedProof(proof, SMALL_PARAMETERS);
  const framedProof = { ...proof, proofLength: encoded.length };
  const frames = frameLocalWordSealedProof(framedProof, SMALL_PARAMETERS);
  assert.equal(frames[0]!.kind, "header");
  assert.deepEqual([frames[0]!.start, frames[0]!.end], [0, 42]);
  assert.equal(frames.some(({ generatedFrameId }) => generatedFrameId !== undefined), false);
  assert.equal(frames.at(-1)!.end, encoded.length);
  assert.ok(frames.every((frame, index) => index === 0 || frames[index - 1]!.end === frame.start));
  const observed = inspectLocalWordProofFraming(framedProof, SMALL_PARAMETERS);
  assert.equal(observed.layout, "experimental-legacy");
  assert.equal(observed.fixedPrefixBytes, localWordProofStaticOffsets(1, SMALL_PARAMETERS).openingBodies);
  assert.equal(observed.oodQm31Values, 0);
  assert.equal(observed.namedRoundNonces, 0);
  assert.equal(observed.independentFriAlphas, localWordFriFoldCounts(SMALL_PARAMETERS).length);
  assert.equal(observed.terminalDirectoryEntries,
    LOCAL_WORD_MATRIX_NAMES.length + localWordFriFoldCounts(SMALL_PARAMETERS).length);
  assert.ok(observed.dynamicMixedMerkleBodyBytes > 0);
});

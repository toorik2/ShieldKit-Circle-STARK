import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { encodeTransaction } from "@bitauth/libauth";
import { concatBytes, sha256 } from "../src/pool/bytes.ts";
import { poolLocalBoundaryClaimForWords } from
  "../src/chain/pool-relation-local-word-boundary.ts";
import {
  decodeLocalWordSealedProof,
  encodeLocalWordSealedProof,
  frameLocalWordSealedProof,
  LOCAL_WORD_FRI_FINAL_LOG_DEGREE,
  LOCAL_WORD_FRI_LAYERS,
  LOCAL_WORD_MATRIX_NAMES,
  LOCAL_WORD_MATRIX_ROW_WIDTHS,
  LOCAL_WORD_PROOF_LENGTH_OFFSET,
  LOCAL_WORD_PROOF_VERSION,
  localWordCanonicalSiblingCount,
  localWordMaximumCanonicalProofBytes,
  localWordOpeningSchedules,
  type LocalWordMatrixOpening,
  type LocalWordSealedProof,
} from "../src/backends/circle/local-word-sealed-proof.ts";
import {
  LOCAL_WORD_GRIND_BITS,
  LOCAL_WORD_LDE_LOG,
  LOCAL_WORD_QUERIES,
  LOCAL_WORD_PRODUCTION_PARAMETERS,
  localWordFriLayerLogs,
} from "../src/backends/circle/local-word-successor-params.ts";
import {
  localWordCompositionTranscript,
  localWordInteractionChallengeValues,
  localWordInteractionTranscript,
  localWordQueryIndices,
  localWordPublicBoundaryTranscript,
} from "../src/backends/circle/local-word-transcript.ts";
import { encodeQm31, type QM31El } from "../src/backends/circle/qm31.ts";
import { analyzeLocalWordObserverTransaction } from
  "../src/backends/circle/local-word-observer-view.ts";
import {
  localWordPoolCarrierSequence,
  localWordVerifierCarrierSequence,
  partitionLocalWordProofBytes,
} from
  "../src/chain/local-word-proof-carriers.ts";

const EXPECTED_BYTES = 337_226;
const EXPECTED_SHA256 = "544aa805f861ba4ab5d585c877b0a68dae9f3483fc1bba84abdcd3e8d9f34587";

function fixture(): {
  readonly proof: LocalWordSealedProof;
  readonly context: Parameters<typeof decodeLocalWordSealedProof>[1];
} {
  const transcriptInitial = new TextEncoder().encode("local-word-codec-transcript-v1");
  const constructionDescriptor = new TextEncoder().encode("local-word-codec-construction-v1");
  const constructionDigest = sha256(constructionDescriptor);
  const publicWords = [{ id: 1n, row: 0, expected: 0x1234_5678 }];
  const matrixRoots = Array.from({ length: 5 }, (_, index) => sha256(concatBytes(
    new TextEncoder().encode("local-word-codec-matrix-root"),
    Uint8Array.of(index),
  )));
  const friRoots = Array.from({ length: LOCAL_WORD_FRI_LAYERS }, (_, index) => sha256(concatBytes(
    new TextEncoder().encode("local-word-codec-fri-root"),
    Uint8Array.of(index),
  )));
  const finalCoefficients = Array.from(
    { length: 2 ** LOCAL_WORD_FRI_FINAL_LOG_DEGREE },
    (): QM31El => [0n, 0n, 0n, 0n],
  );
  const { transcript, challenges } = localWordInteractionTranscript(
    transcriptInitial,
    constructionDigest,
    matrixRoots[0]!,
    matrixRoots[1]!,
  );
  const { publicInverses, claimedSum } = poolLocalBoundaryClaimForWords(publicWords, challenges.boundary);
  localWordPublicBoundaryTranscript(transcript, publicInverses);
  const interactionDigest = transcript.digest;
  const composition = localWordCompositionTranscript(
    transcript,
    matrixRoots[2]!,
    matrixRoots[3]!,
  );
  transcript.absorb("local-word-quotient-and-fri-mask-root", matrixRoots[4]!);
  const batchBeta = transcript.challengeQm31("local-word-batch-beta");
  const batchDigest = transcript.digest;
  const friAlphas: QM31El[] = [];
  let friMidDigest = new Uint8Array();
  friRoots.forEach((root, round) => {
    transcript.absorb(`fri-root:${round}`, root);
    friAlphas.push(transcript.challengeQm31(`fri-alpha:${round}`));
    if (round + 1 === Math.ceil(friRoots.length / 2)) friMidDigest = transcript.digest;
  });
  const friRootsDigest = transcript.digest;
  transcript.absorb("fri-final", concatBytes(...finalCoefficients.map(encodeQm31)));
  // Production conditioned grinding is covered separately; pin its known nonce
  // here so the byte KAT stays a sub-second codec check.
  const grindNonce = 441_546;
  assert.equal(transcript.acceptGrind(LOCAL_WORD_GRIND_BITS, grindNonce), true);
  const queries = localWordQueryIndices(transcript);
  const schedules = localWordOpeningSchedules(queries);
  const matrices = Object.fromEntries(LOCAL_WORD_MATRIX_NAMES.map((name, index) => {
    const indices = index === 3 ? schedules.global : schedules.current;
    const rowWidth = LOCAL_WORD_MATRIX_ROW_WIDTHS[index]!;
    const opening: LocalWordMatrixOpening = {
      root: matrixRoots[index]!,
      rowWidth,
      indices,
      rows: Array.from({ length: indices.length }, () => new Uint8Array(rowWidth)),
      siblings: Array.from(
        { length: localWordCanonicalSiblingCount(indices, 2 ** LOCAL_WORD_LDE_LOG) },
        () => new Uint8Array(32),
      ),
    };
    return [name, opening];
  })) as LocalWordSealedProof["matrices"];
  const proof: LocalWordSealedProof = {
    version: LOCAL_WORD_PROOF_VERSION,
    profile: 0,
    constructionDigest,
    proofLength: 0,
    publicBoundaryInverses: publicInverses,
    publicBoundaryClaimedSum: claimedSum,
    matrices,
    fri: {
      layers: schedules.fri.map((indices, round) => ({
        root: friRoots[round]!,
        indices,
        values: Array.from({ length: indices.length }, (): QM31El => [0n, 0n, 0n, 0n]),
        siblings: Array.from(
          { length: localWordCanonicalSiblingCount(
            indices,
            2 ** localWordFriLayerLogs(LOCAL_WORD_PRODUCTION_PARAMETERS)[round]!,
          ) },
          () => new Uint8Array(32),
        ),
      })),
      finalCoefficients,
      grindNonce,
    },
    transcriptManifest: {
      interactionChallenges: localWordInteractionChallengeValues(challenges),
      interactionDigest,
      constraintAlpha: composition.constraintAlpha,
      compositionDigest: composition.digest,
      batchBeta,
      batchDigest,
      friAlphas,
      friMidDigest,
      friRootsDigest,
      queryDigest: transcript.digest,
    },
    compositionPartials: Array.from(
      { length: LOCAL_WORD_QUERIES },
      (): [QM31El, QM31El, QM31El] => [
        [0n, 0n, 0n, 0n],
        [0n, 0n, 0n, 0n],
        [0n, 0n, 0n, 0n],
      ],
    ),
    queries,
  };
  return {
    proof,
    context: {
      profile: 0,
      transcriptInitial,
      constructionDescriptor,
      publicWords,
      expectedPreprocessedRoot: matrixRoots[0]!,
    },
  };
}

const CACHED_FIXTURE = fixture();

describe("canonical local-word sealed proof", () => {
  it("matches the Rust byte KAT and derives every omitted index", () => {
    const { proof, context } = CACHED_FIXTURE;
    const encoded = encodeLocalWordSealedProof(proof);
    console.log("local-word-canonical-proof-measurement", JSON.stringify({
      proofBytes: encoded.length,
      proofSha256: Buffer.from(sha256(encoded)).toString("hex"),
      grindNonce: proof.fri.grindNonce,
      matrixMerkle: LOCAL_WORD_MATRIX_NAMES.map((name) => ({
        matrix: name,
        rows: proof.matrices[name].rows.length,
        siblings: proof.matrices[name].siblings.length,
        parentHashes: (proof.matrices[name].rows.length + proof.matrices[name].siblings.length - 1) / 3,
      })),
      friMerkle: proof.fri.layers.map((layer, round) => ({
        round,
        rows: layer.values.length,
        siblings: layer.siblings.length,
        parentHashes: (layer.values.length + layer.siblings.length - 1) / 3,
      })),
    }));
    assert.equal(encoded.length, EXPECTED_BYTES);
    assert.equal(localWordMaximumCanonicalProofBytes(1), 339_962);
    assert.equal(localWordMaximumCanonicalProofBytes(34), 340_490);
    assert.ok(encoded.length <= localWordMaximumCanonicalProofBytes(1));
    assert.equal(Buffer.from(sha256(encoded)).toString("hex"), EXPECTED_SHA256);
    assert.equal(new DataView(encoded.buffer, encoded.byteOffset).getUint32(LOCAL_WORD_PROOF_LENGTH_OFFSET), encoded.length);

    const decoded = decodeLocalWordSealedProof(encoded, context);
    assert.deepEqual(decoded.queries, proof.queries);
    assert.deepEqual(encodeLocalWordSealedProof(decoded), encoded);
    const frames = frameLocalWordSealedProof(decoded);
    assert.equal(frames[0]!.start, 0);
    assert.equal(frames.at(-1)!.end, encoded.length);
    assert.ok(frames.every((frame, index) => index === 0 || frames[index - 1]!.end === frame.start));

    for (const root of [
      ...LOCAL_WORD_MATRIX_NAMES.map((name) => proof.matrices[name].root),
      ...proof.fri.layers.map((layer) => layer.root),
    ]) {
      let occurrences = 0;
      for (let offset = 0; offset <= encoded.length - root.length; offset += 1) {
        if (root.every((byte, index) => encoded[offset + index] === byte)) occurrences += 1;
      }
      assert.equal(occurrences, 1);
    }
  });

  it("rejects non-canonical framing, non-fields, and a false public statement", () => {
    const { proof, context } = CACHED_FIXTURE;
    const encoded = encodeLocalWordSealedProof(proof);
    assert.throws(() => decodeLocalWordSealedProof(encoded.slice(0, -1), context), /byte length/);
    assert.throws(() => decodeLocalWordSealedProof(concatBytes(encoded, Uint8Array.of(0)), context), /byte length/);

    const nonField = encoded.slice();
    nonField.set(Uint8Array.of(0xff, 0xff, 0xff, 0x7f), 42);
    assert.throws(() => decodeLocalWordSealedProof(nonField, context), /not in \[0, p\)/);

    const falseContext = {
      ...context,
      publicWords: [{ ...context.publicWords[0]!, expected: context.publicWords[0]!.expected ^ 1 }],
    };
    assert.throws(() => decodeLocalWordSealedProof(encoded, falseContext), /public boundary inverses/);
  });

  it("extracts the complete observer view from serialized carrier inputs", () => {
    const { proof, context } = CACHED_FIXTURE;
    const encoded = encodeLocalWordSealedProof(proof);
    const carriers = partitionLocalWordProofBytes(encoded);
    const raw = encodeTransaction({
      version: 2,
      locktime: 0,
      inputs: carriers.map((carrier, index) => ({
        outpointTransactionHash: new Uint8Array(32).fill(index + 1),
        outpointIndex: index,
        sequenceNumber: index === 0
          ? localWordPoolCarrierSequence(encoded.length)
          : localWordVerifierCarrierSequence(index),
        unlockingBytecode: carrier.unlockingBytecode,
      })),
      outputs: [{ lockingBytecode: Uint8Array.of(0x51), valueSatoshis: 1n }],
    });
    const observer = analyzeLocalWordObserverTransaction(raw, context);
    assert.equal(observer.carrierUnionExact, true);
    assert.deepEqual(observer.transactionShape, {
      inputs: carriers.length,
      outputs: 1,
      publicNullifierPathNodes: 0,
    });
    assert.equal(observer.protectedTraceRecovery.recovered, false);
    assert.equal(observer.directOpenings.currentPoints, LOCAL_WORD_QUERIES);
    assert.equal(observer.maskBudget.original.openedRankPerColumn, LOCAL_WORD_QUERIES);
    assert.equal(observer.quotient.extraWitnessFormsAtQueries, 0);
    assert.equal(observer.claimBoundary.badDenominatorDistanceBits, 102.61);
  });
});

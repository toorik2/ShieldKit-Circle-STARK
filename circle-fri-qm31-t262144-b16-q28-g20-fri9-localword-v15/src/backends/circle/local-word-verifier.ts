import { concatBytes, eq32, readU32LE, sha256 } from "../../pool/bytes.ts";
import { poolLocalBoundaryClaimForWords } from
  "../../chain/pool-relation-local-word-boundary.ts";
import { CanonicalMerkleTree4 } from "./canonical-merkle.ts";
import {
  combineLocalWordAirCompositionPartials,
  LOCAL_WORD_INTERACTION_QM31_COLUMNS,
  localWordAirCompositionPartials,
  localWordAirResiduals,
  localWordRelationZerofierAtBitReversed,
  type LocalWordAirFrame,
} from "./local-word-air.ts";
import { LOCAL_WORD_INTERACTION_GROUPS } from "./local-word-oracle-layout.ts";
import {
  decodeLocalWordSealedProof,
  encodeLocalWordSealedProof,
  LOCAL_WORD_PROOF_VERSION,
  localWordOpeningSchedules,
  type LocalWordMatrixName,
  type LocalWordMatrixOpening,
  type LocalWordProofContext,
  type LocalWordSealedProof,
} from "./local-word-sealed-proof.ts";
import {
  LOCAL_WORD_PRODUCTION_PARAMETERS,
  validateLocalWordProofParameters,
  type LocalWordProofParameters,
} from "./local-word-successor-params.ts";
import {
  localWordCompositionTranscript,
  localWordInteractionChallengeValues,
  localWordInteractionTranscript,
  localWordPublicBoundaryTranscript,
  localWordQueryIndices,
} from "./local-word-transcript.ts";
import type { M31El } from "./m31.ts";
import {
  QM31_ZERO,
  qmAdd,
  qmEq,
  qmMul,
  qmMulM31,
  encodeQm31,
  type QM31El,
} from "./qm31.ts";
import { successorTraceOffsetIndex } from "./successor-domain.ts";
import { verifySuccessorFri } from "./successor-fri.ts";

export { localWordRelationZerofierAtBitReversed } from "./local-word-air.ts";

const MATRIX_LABELS: Readonly<Record<LocalWordMatrixName, string>> = {
  preprocessed: "local-word:preprocessed",
  original: "local-word:original",
  interaction: "local-word:interaction",
  interactionGlobal: "local-word:interaction-global",
  quotientAndFriMask: "local-word:quotient-and-fri-mask",
};

function sameNumbers(left: readonly number[], right: readonly number[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function decodeM31Row(row: Uint8Array): M31El[] {
  if (row.length % 4 !== 0) throw new Error("local-word M31 row width");
  return Array.from({ length: row.length / 4 }, (_, index) => BigInt(readU32LE(row, index * 4)));
}

function verifyOpening(
  opening: LocalWordMatrixOpening,
  name: LocalWordMatrixName,
  indices: readonly number[],
  rowCount: number,
): Map<number, M31El[]> {
  if (!sameNumbers(opening.indices, indices) || !CanonicalMerkleTree4.verifyMany(
    MATRIX_LABELS[name],
    opening.indices.map((index, position) => ({ index, raw: opening.rows[position]! })),
    opening.siblings,
    rowCount,
    opening.root,
  )) throw new Error(`${MATRIX_LABELS[name]} Merkle`);
  return new Map(opening.indices.map((index, position) => [index, decodeM31Row(opening.rows[position]!)]));
}

function qFromRow(row: readonly M31El[] | undefined, label: string): QM31El {
  if (!row || row.length !== 4) throw new Error(`${label} QM31 row width`);
  return [row[0]!, row[1]!, row[2]!, row[3]!];
}

function interactionFromRows(rows: readonly (readonly M31El[])[]): QM31El[] {
  if (rows.length !== LOCAL_WORD_INTERACTION_GROUPS.length || rows.some((row, group) =>
    row.length !== LOCAL_WORD_INTERACTION_GROUPS[group]!.length * 4)) {
    throw new Error("local-word committed interaction width");
  }
  const interaction = Array.from(
    { length: LOCAL_WORD_INTERACTION_QM31_COLUMNS },
    (): QM31El => QM31_ZERO,
  );
  LOCAL_WORD_INTERACTION_GROUPS.forEach((columns, group) => {
    columns.forEach((column, position) => {
      const offset = position * 4;
      const row = rows[group]!;
      interaction[column] = [row[offset]!, row[offset + 1]!, row[offset + 2]!, row[offset + 3]!];
    });
  });
  return interaction;
}

function interactionFromPackedRows(
  current: readonly M31El[],
  global: readonly M31El[],
): QM31El[] {
  const currentWidth = LOCAL_WORD_INTERACTION_GROUPS.slice(0, -1)
    .reduce((sum, group) => sum + group.length * 4, 0);
  if (current.length !== currentWidth || global.length !== LOCAL_WORD_INTERACTION_GROUPS.at(-1)!.length * 4) {
    throw new Error("local-word packed interaction width");
  }
  let cursor = 0;
  const currentRows = LOCAL_WORD_INTERACTION_GROUPS.slice(0, -1).map((group) => {
    const end = cursor + group.length * 4;
    const row = current.slice(cursor, end);
    cursor = end;
    return row;
  });
  return interactionFromRows([...currentRows, global]);
}

export function localWordQuotientIdentity(
  composition: QM31El,
  zerofier: M31El,
  quotient: QM31El,
): boolean {
  return qmEq(composition, qmMulM31(quotient, zerofier));
}

export function localWordFriBatchValue(
  beta: QM31El,
  original: readonly M31El[],
  interactionGroups: readonly (readonly M31El[])[],
  quotient: QM31El,
  friMask: QM31El,
): QM31El {
  if (original.length !== 34 || interactionGroups.length !== LOCAL_WORD_INTERACTION_GROUPS.length ||
    interactionGroups.some((row, group) => row.length !== LOCAL_WORD_INTERACTION_GROUPS[group]!.length * 4)) {
    throw new Error("local-word FRI batch value geometry");
  }
  const pack = (row: readonly M31El[]): QM31El[] => Array.from(
    { length: Math.ceil(row.length / 4) },
    (_, item): QM31El => [
      row[item * 4] ?? 0n,
      row[item * 4 + 1] ?? 0n,
      row[item * 4 + 2] ?? 0n,
      row[item * 4 + 3] ?? 0n,
    ],
  );
  const values = [
    ...pack(original),
    ...interactionGroups.flatMap(pack),
    quotient,
  ];
  return qmAdd(values.slice(1).reduce(
    (accumulator, value) => qmAdd(qmMul(accumulator, beta), value),
    values[0]!,
  ), friMask);
}

export type LocalWordVerifyResult =
  | { readonly ok: true; readonly proof: LocalWordSealedProof }
  | { readonly ok: false; readonly reason: string };

/**
 * Independent verifier for a decoded proof. This is the readable source of
 * truth that the measured bounded VM roles must collectively implement.
 */
export function verifyLocalWordSealedProof(
  proof: LocalWordSealedProof,
  context: LocalWordProofContext,
  parameters: LocalWordProofParameters = LOCAL_WORD_PRODUCTION_PARAMETERS,
): LocalWordVerifyResult {
  try {
    validateLocalWordProofParameters(parameters);
    const rowCount = 2 ** parameters.evalLog;
    if (proof.version !== LOCAL_WORD_PROOF_VERSION || proof.profile !== context.profile ||
      !eq32(proof.constructionDigest, sha256(context.constructionDescriptor)) ||
      !eq32(proof.matrices.preprocessed.root, context.expectedPreprocessedRoot) ||
      proof.proofLength !== encodeLocalWordSealedProof(proof, parameters).length ||
      context.publicWords.length < 1 || context.publicWords.some((word) => word.row >= 2 ** parameters.relationLog)) {
      throw new Error("local-word verifier key");
    }

    const { transcript, challenges } = localWordInteractionTranscript(
      context.transcriptInitial,
      proof.constructionDigest,
      proof.matrices.preprocessed.root,
      proof.matrices.original.root,
    );
    const interactionChallengeValues = localWordInteractionChallengeValues(challenges);
    if (proof.transcriptManifest.interactionChallenges.length !== interactionChallengeValues.length ||
      proof.transcriptManifest.interactionChallenges.some((value, index) =>
        !qmEq(value, interactionChallengeValues[index]!))) {
      throw new Error("local-word interaction challenge manifest");
    }
    const boundary = poolLocalBoundaryClaimForWords(context.publicWords, challenges.boundary);
    if (proof.publicBoundaryInverses.length !== boundary.publicInverses.length ||
      proof.publicBoundaryInverses.some((value, index) => !qmEq(value, boundary.publicInverses[index]!))) {
      throw new Error("local-word public boundary inverses");
    }
    if (!qmEq(proof.publicBoundaryClaimedSum, boundary.claimedSum)) {
      throw new Error("local-word public boundary claimed sum");
    }
    localWordPublicBoundaryTranscript(transcript, proof.publicBoundaryInverses);
    if (!eq32(proof.transcriptManifest.interactionDigest, transcript.digest)) {
      throw new Error("local-word interaction digest manifest");
    }
    const { constraintAlpha } = localWordCompositionTranscript(
      transcript,
      proof.matrices.interaction.root,
      proof.matrices.interactionGlobal.root,
    );
    if (!qmEq(proof.transcriptManifest.constraintAlpha, constraintAlpha) ||
      !eq32(proof.transcriptManifest.compositionDigest, transcript.digest)) {
      throw new Error("local-word composition manifest");
    }
    transcript.absorb(
      "local-word-quotient-and-fri-mask-root",
      proof.matrices.quotientAndFriMask.root,
    );
    const beta = transcript.challengeQm31("local-word-batch-beta");
    if (!qmEq(proof.transcriptManifest.batchBeta, beta) ||
      !eq32(proof.transcriptManifest.batchDigest, transcript.digest)) {
      throw new Error("local-word batch manifest");
    }
    const friManifestTranscript = transcript.fork();
    const friAlphas: QM31El[] = [];
    const friSplit = Math.ceil(proof.fri.layers.length / 2);
    let friMidDigest = new Uint8Array();
    proof.fri.layers.forEach((layer, round) => {
      friManifestTranscript.absorb(`fri-root:${round}`, layer.root);
      friAlphas.push(friManifestTranscript.challengeQm31(`fri-alpha:${round}`));
      if (round + 1 === friSplit) friMidDigest = friManifestTranscript.digest;
    });
    if (friAlphas.length !== proof.transcriptManifest.friAlphas.length ||
      friAlphas.some((alpha, index) => !qmEq(alpha, proof.transcriptManifest.friAlphas[index]!)) ||
      !eq32(friMidDigest, proof.transcriptManifest.friMidDigest) ||
      !eq32(friManifestTranscript.digest, proof.transcriptManifest.friRootsDigest)) {
      throw new Error("local-word FRI root manifest");
    }
    friManifestTranscript.absorb(
      "fri-final",
      concatBytes(...proof.fri.finalCoefficients.map(encodeQm31)),
    );
    if (!friManifestTranscript.acceptGrind(parameters.fri.grindBits, proof.fri.grindNonce) ||
      !eq32(friManifestTranscript.digest, proof.transcriptManifest.queryDigest)) {
      throw new Error("local-word query digest manifest");
    }
    const fri = verifySuccessorFri(proof.fri, parameters.evalLog, transcript, parameters.fri);
    if (!fri.ok) throw new Error(fri.reason);
    const queries = localWordQueryIndices(transcript, parameters);
    if (!sameNumbers(proof.queries, queries)) throw new Error("local-word query manifest");
    const schedules = localWordOpeningSchedules(queries, parameters);

    const matrices = {
      preprocessed: verifyOpening(proof.matrices.preprocessed, "preprocessed", schedules.current, rowCount),
      original: verifyOpening(proof.matrices.original, "original", schedules.current, rowCount),
      interaction: verifyOpening(proof.matrices.interaction, "interaction", schedules.current, rowCount),
      interactionGlobal: verifyOpening(
        proof.matrices.interactionGlobal,
        "interactionGlobal",
        schedules.global,
        rowCount,
      ),
      quotientAndFriMask: verifyOpening(
        proof.matrices.quotientAndFriMask,
        "quotientAndFriMask",
        schedules.current,
        rowCount,
      ),
    };
    const layerZero = new Map(proof.fri.layers[0]!.indices.map((index, position) =>
      [index, proof.fri.layers[0]!.values[position]!]));

    for (let queryNumber = 0; queryNumber < queries.length; queryNumber += 1) {
      const query = queries[queryNumber]!;
      const previous = successorTraceOffsetIndex(
        query,
        parameters.relationLog,
        parameters.evalLog,
        -1,
      );
      const interactionCurrent = matrices.interaction.get(query);
      const interactionGlobal = matrices.interactionGlobal.get(query);
      if (!interactionCurrent || !interactionGlobal) throw new Error("local-word interaction opening");
      let interactionCursor = 0;
      const groupRows = [
        ...LOCAL_WORD_INTERACTION_GROUPS.slice(0, -1).map((group) => {
          const end = interactionCursor + group.length * 4;
          const row = interactionCurrent.slice(interactionCursor, end);
          interactionCursor = end;
          return row;
        }),
        interactionGlobal,
      ];
      const interaction = interactionFromPackedRows(interactionCurrent, interactionGlobal);
      const previousGlobal = matrices.interactionGlobal.get(previous);
      if (!previousGlobal) throw new Error("local-word global predecessor");
      const interactionPrevious = Array.from(
        { length: LOCAL_WORD_INTERACTION_QM31_COLUMNS },
        (): QM31El => QM31_ZERO,
      );
      LOCAL_WORD_INTERACTION_GROUPS[3]!.forEach((column, position) => {
        const offset = position * 4;
        interactionPrevious[column] = [
          previousGlobal[offset]!,
          previousGlobal[offset + 1]!,
          previousGlobal[offset + 2]!,
          previousGlobal[offset + 3]!,
        ];
      });
      const original = matrices.original.get(query);
      const preprocessed = matrices.preprocessed.get(query);
      if (!original || !preprocessed) throw new Error("local-word relation opening");
      const frame: LocalWordAirFrame = {
        original,
        preprocessed,
        interaction,
        interactionPrevious,
      };
      const residuals = localWordAirResiduals(frame, challenges, boundary.claimedSum);
      const expectedPartials = localWordAirCompositionPartials(residuals, constraintAlpha);
      const carriedPartials = proof.compositionPartials[queryNumber];
      if (!carriedPartials || carriedPartials.some((value, index) => !qmEq(value, expectedPartials[index]!))) {
        throw new Error("local-word composition partial");
      }
      const composition = combineLocalWordAirCompositionPartials(carriedPartials, constraintAlpha);
      const quotientAndFriMask = matrices.quotientAndFriMask.get(query);
      if (!quotientAndFriMask || quotientAndFriMask.length !== 8) {
        throw new Error("local-word quotient and FRI mask row width");
      }
      const quotient = qFromRow(quotientAndFriMask.slice(0, 4), "local-word quotient");
      const friMask = qFromRow(quotientAndFriMask.slice(4), "local-word FRI mask");
      if (!localWordQuotientIdentity(
        composition,
        localWordRelationZerofierAtBitReversed(query, parameters),
        quotient,
      )) throw new Error("local-word quotient identity");
      const batch = localWordFriBatchValue(
        beta,
        original,
        groupRows as readonly M31El[][],
        quotient,
        friMask,
      );
      const openedBatch = layerZero.get(query);
      if (!openedBatch || !qmEq(batch, openedBatch)) throw new Error("local-word FRI batch link");
    }
    return { ok: true, proof };
  } catch (error) {
    return { ok: false, reason: error instanceof Error ? error.message : "local-word proof exception" };
  }
}

/** Parse canonical bytes, replay omitted transcript data, then verify every check. */
export function verifyLocalWordSealedProofBytes(
  proofBytes: Uint8Array,
  context: LocalWordProofContext,
  parameters: LocalWordProofParameters = LOCAL_WORD_PRODUCTION_PARAMETERS,
): LocalWordVerifyResult {
  try {
    return verifyLocalWordSealedProof(
      decodeLocalWordSealedProof(proofBytes, context, parameters),
      context,
      parameters,
    );
  } catch (error) {
    return { ok: false, reason: error instanceof Error ? error.message : "local-word proof exception" };
  }
}

import { eq32, readU32LE } from "../../pool/bytes.ts";
import { poolLocalBoundaryClaimForWords } from
  "../../chain/pool-relation-local-word-boundary.ts";
import {
  LOCAL_WORD_INTERACTION_QM31_COLUMNS,
  localWordRelationZerofierAtBitReversed,
  LOCAL_WORD_PREPROCESSED_COLUMNS,
} from "./local-word-air.ts";
import { LOCAL_SHA_ORIGINAL_COLUMNS } from
  "../../chain/sha256-local-word-machine.ts";
import { LOCAL_WORD_INTERACTION_GROUPS } from "./local-word-oracle-layout.ts";
import {
  decodeLocalWordSealedProof,
  encodeLocalWordSealedProof,
  LOCAL_WORD_PROOF_VERSION,
  LOCAL_WORD_PROOF_FIXED_PREFIX_BYTES,
  localWordOpeningSchedules,
  localWordProofStaticOffsets,
  localWordV17FriMerkleDescriptor,
  localWordV17MatrixMerkleDescriptor,
  type LocalWordMatrixName,
  type LocalWordMatrixOpening,
  type LocalWordProofContext,
  type LocalWordSealedProof,
} from "./local-word-sealed-proof.ts";
import { v17MerkleOpeningRoot } from "./v17-merkle.ts";
import {
  LOCAL_WORD_PRODUCTION_PARAMETERS,
  validateLocalWordProofParameters,
  type LocalWordProofParameters,
} from "./local-word-successor-params.ts";
import type { M31El } from "./m31.ts";
import {
  QM31_ZERO,
  qmAdd,
  qmEq,
  liftM31,
  qmMul,
  qmMulM31,
  type QM31El,
} from "./qm31.ts";
import {
  successorCirclePointAtBitReversed,
  successorTraceOffsetIndex,
} from "./successor-domain.ts";
import { verifyV17SuccessorFri } from "./successor-fri.ts";
import { V17_PROOF_PROTOCOL_ID } from "./v17-proof-layout.ts";
import {
  flattenV17FriAlphas,
  replayV17ProofTranscript,
} from "./v17-proof-transcript.ts";
import {
  V17_OOD_FUNCTION_COUNT,
  V17_OOD_PREDECESSOR_INTERACTION_COLUMNS,
  v17DegreeCorrectedBatchIdentity,
  v17OodAirQuotientIdentity,
  v17OodFunctionValues,
  type V17OodAirFrame,
} from "./v17-ood-air.ts";
import { liftCirclePoint } from "./v17-oods.ts";

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
  parameters: LocalWordProofParameters,
): Map<number, M31El[]> {
  const descriptor = localWordV17MatrixMerkleDescriptor(name, parameters);
  const root = v17MerkleOpeningRoot({
    descriptor,
    rows: opening.indices.map((index, position) => ({ index, raw: opening.rows[position]! })),
    siblings: opening.siblings,
  });
  if (!sameNumbers(opening.indices, indices) || !eq32(root, opening.root)) {
    throw new Error(`${MATRIX_LABELS[name]} Merkle`);
  }
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
    const productionLayout = localWordProofStaticOffsets(
      context.publicWords.length,
      parameters,
    ).openingBodies === LOCAL_WORD_PROOF_FIXED_PREFIX_BYTES;
    if (proof.version !== LOCAL_WORD_PROOF_VERSION || proof.profile !== context.profile ||
      !productionLayout || context.profile < 0 || context.profile > 2 ||
      !eq32(proof.protocolId, V17_PROOF_PROTOCOL_ID) ||
      !eq32(proof.matrices.preprocessed.root, context.expectedPreprocessedRoot) ||
      proof.proofLength !== encodeLocalWordSealedProof(proof, parameters).length ||
      !proof.oodValues || proof.oodValues.length !== V17_OOD_FUNCTION_COUNT ||
      !proof.roundNonces || proof.roundNonces.length !== 14 ||
      context.publicWords.some((word) => word.row >= 2 ** parameters.relationLog)) {
      throw new Error("local-word verifier key");
    }

    const replay = replayV17ProofTranscript({
      initial: context.transcriptInitial,
      version: 17,
      profile: context.profile as 0 | 1 | 2,
      protocolId: proof.protocolId,
      preprocessedRoot: proof.matrices.preprocessed.root,
      originalRoot: proof.matrices.original.root,
      publicBoundaryInverses: proof.publicBoundaryInverses,
      publicBoundaryClaimedSum: proof.publicBoundaryClaimedSum,
      interactionRoot: proof.matrices.interaction.root,
      interactionGlobalRoot: proof.matrices.interactionGlobal.root,
      quotientAndFriMaskRoot: proof.matrices.quotientAndFriMask.root,
      oodValues: proof.oodValues,
      friRoots: proof.fri.layers.map((layer) => layer.root),
      finalCoefficients: proof.fri.finalCoefficients,
      roundNonces: proof.roundNonces,
    });
    const flatFriAlphas = flattenV17FriAlphas(replay.friAlphas);
    if (proof.transcriptManifest.interactionChallenges.length !==
        replay.interactionChallengeValues.length ||
      proof.transcriptManifest.interactionChallenges.some((value, index) =>
        !qmEq(value, replay.interactionChallengeValues[index]!)) ||
      !eq32(proof.transcriptManifest.interactionDigest, replay.interactionDigest) ||
      !qmEq(proof.transcriptManifest.constraintAlpha, replay.constraintAlpha) ||
      !eq32(proof.transcriptManifest.compositionDigest, replay.compositionDigest) ||
      !qmEq(proof.transcriptManifest.batchBeta, replay.batchBeta) ||
      !eq32(proof.transcriptManifest.batchDigest, replay.batchDigest) ||
      proof.transcriptManifest.friAlphas.length !== flatFriAlphas.length ||
      proof.transcriptManifest.friAlphas.some((alpha, index) =>
        !qmEq(alpha, flatFriAlphas[index]!)) ||
      !eq32(proof.transcriptManifest.friMidDigest, replay.friMidDigest) ||
      !eq32(proof.transcriptManifest.friRootsDigest, replay.friRootsDigest) ||
      !eq32(proof.transcriptManifest.queryDigest, replay.queryDigest)) {
      throw new Error("local-word v17 transcript manifest");
    }

    const boundary = poolLocalBoundaryClaimForWords(
      context.publicWords,
      replay.interactionChallenges.boundary,
    );
    if (proof.publicBoundaryInverses.length !== boundary.publicInverses.length ||
      proof.publicBoundaryInverses.some((value, index) => !qmEq(value, boundary.publicInverses[index]!))) {
      throw new Error("local-word public boundary inverses");
    }
    if (!qmEq(proof.publicBoundaryClaimedSum, boundary.claimedSum)) {
      throw new Error("local-word public boundary claimed sum");
    }

    const oodPreprocessedEnd = LOCAL_WORD_PREPROCESSED_COLUMNS;
    const oodOriginalEnd = oodPreprocessedEnd + LOCAL_SHA_ORIGINAL_COLUMNS;
    const oodInteractionEnd = oodOriginalEnd + LOCAL_WORD_INTERACTION_QM31_COLUMNS;
    const oodPrevious = Array.from(
      { length: LOCAL_WORD_INTERACTION_QM31_COLUMNS },
      (): QM31El => QM31_ZERO,
    );
    V17_OOD_PREDECESSOR_INTERACTION_COLUMNS.forEach((column, index) => {
      oodPrevious[column] = proof.oodValues![oodInteractionEnd + index]!;
    });
    const oodFrame: V17OodAirFrame = {
      preprocessed: proof.oodValues.slice(0, oodPreprocessedEnd),
      original: proof.oodValues.slice(oodPreprocessedEnd, oodOriginalEnd),
      interaction: proof.oodValues.slice(oodOriginalEnd, oodInteractionEnd),
      interactionPrevious: oodPrevious,
    };
    const quotientAtQ = proof.oodValues.at(-1)!;
    if (!v17OodAirQuotientIdentity({
      frame: oodFrame,
      challenges: replay.interactionChallenges,
      boundaryClaimedSum: boundary.claimedSum,
      constraintAlpha: replay.constraintAlpha,
      quotientAtQ,
      oodPoint: replay.oods.point,
      relationLog: parameters.relationLog,
    })) {
      throw new Error("local-word v17 OOD AIR quotient identity");
    }

    const fri = verifyV17SuccessorFri({
      proof: proof.fri,
      inputLog: parameters.evalLog,
      config: parameters.fri,
      challenges: replay.friAlphas,
      queries: replay.queries,
      descriptors: proof.fri.layers.map((_, layer) =>
        localWordV17FriMerkleDescriptor(layer, parameters)),
    });
    if (!fri.ok) throw new Error(fri.reason);
    const queries = replay.queries;
    if (!sameNumbers(proof.queries, queries)) throw new Error("local-word query manifest");
    const schedules = localWordOpeningSchedules(queries, parameters);

    const matrices = {
      preprocessed: verifyOpening(proof.matrices.preprocessed, "preprocessed", schedules.current, parameters),
      original: verifyOpening(proof.matrices.original, "original", schedules.current, parameters),
      interaction: verifyOpening(proof.matrices.interaction, "interaction", schedules.current, parameters),
      interactionGlobal: verifyOpening(
        proof.matrices.interactionGlobal,
        "interactionGlobal",
        schedules.global,
        parameters,
      ),
      quotientAndFriMask: verifyOpening(
        proof.matrices.quotientAndFriMask,
        "quotientAndFriMask",
        schedules.current,
        parameters,
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
      const frame: V17OodAirFrame = {
        original: original.map(liftM31),
        preprocessed: preprocessed.map(liftM31),
        interaction,
        interactionPrevious,
      };
      const quotientAndFriMask = matrices.quotientAndFriMask.get(query);
      if (!quotientAndFriMask || quotientAndFriMask.length !== 8) {
        throw new Error("local-word quotient and FRI mask row width");
      }
      const quotient = qFromRow(quotientAndFriMask.slice(0, 4), "local-word quotient");
      const friMask = qFromRow(quotientAndFriMask.slice(4), "local-word FRI mask");
      const openedBatch = layerZero.get(query);
      if (!openedBatch || !v17DegreeCorrectedBatchIdentity({
        beta: replay.batchBeta,
        functionsAtPoint: v17OodFunctionValues(frame, quotient),
        claimsAtQ: proof.oodValues,
        maskAtPoint: friMask,
        openedBatch,
        oodT: replay.oods.t,
        point: liftCirclePoint(successorCirclePointAtBitReversed(parameters.evalLog, query)),
      })) throw new Error("local-word FRI batch link");
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

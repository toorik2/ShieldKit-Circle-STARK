/** Canonical production transcript replay for the v17 proof. */
import { concatBytes } from "../../pool/bytes.ts";
import {
  type LocalWordInteractionChallenges,
  localWordInteractionChallengeValues,
  localWordQueryIndices,
} from "./local-word-transcript.ts";
import { LOCAL_WORD_PRODUCTION_PARAMETERS } from "./local-word-successor-params.ts";
import { encodeQm31, type QM31El } from "./qm31.ts";
import { V17_PROOF_PROTOCOL_ID } from "./v17-proof-layout.ts";
import {
  V17TheoremRoundCursor,
  V17_THEOREM_ROUND_IDS,
  type V17TheoremRoundId,
} from "./v17-round-transcript.ts";
import { deriveV17OodsChallenge, type V17OodsChallenge } from "./v17-oods.ts";
import { SuccessorTranscript } from "./successor-transcript.ts";

export const V17_PROOF_MAGIC = new TextEncoder().encode("SKLW");

export type V17ProofTranscriptReplay = {
  readonly interactionChallenges: LocalWordInteractionChallenges;
  readonly interactionChallengeValues: readonly QM31El[];
  /** Snapshot after public inverses/sum and both interaction roots. */
  readonly interactionDigest: Uint8Array;
  readonly constraintAlpha: QM31El;
  /** Snapshot after the composition-round PoW and alpha derivation. */
  readonly compositionDigest: Uint8Array;
  readonly oods: V17OodsChallenge;
  readonly batchBeta: QM31El;
  /** Snapshot after the batch-round PoW and beta derivation. */
  readonly batchDigest: Uint8Array;
  /** Nine groups: two independent challenges for rounds 0..7, one for 8. */
  readonly friAlphas: readonly (readonly QM31El[])[];
  readonly friMidDigest: Uint8Array;
  readonly friRootsDigest: Uint8Array;
  /** Snapshot after final coefficients and the query-round PoW. */
  readonly queryDigest: Uint8Array;
  readonly queries: readonly number[];
  readonly finalDigest: Uint8Array;
};

export type V17ProofTranscriptInput = {
  readonly initial: Uint8Array;
  readonly version: 17;
  readonly profile: 0 | 1 | 2;
  readonly protocolId: Uint8Array;
  readonly preprocessedRoot: Uint8Array;
  readonly originalRoot: Uint8Array;
  readonly publicBoundaryInverses: readonly QM31El[];
  readonly publicBoundaryClaimedSum: QM31El;
  readonly interactionRoot: Uint8Array;
  readonly interactionGlobalRoot: Uint8Array;
  readonly quotientAndFriMaskRoot: Uint8Array;
  readonly oodValues: readonly QM31El[];
  readonly friRoots: readonly Uint8Array[];
  readonly finalCoefficients: readonly QM31El[];
  /** Canonical V17_THEOREM_ROUND_IDS order. */
  readonly roundNonces: readonly number[];
};

function width32(value: Uint8Array, label: string): Uint8Array {
  if (value.length !== 32) throw new Error(`v17 transcript ${label} width`);
  return value;
}

function absorbHeader(transcript: SuccessorTranscript, input: V17ProofTranscriptInput): void {
  if (input.initial.length < 1 || input.version !== 17 || input.profile < 0 || input.profile > 2 ||
    input.protocolId.length !== 32 || !input.protocolId.every((byte, index) =>
      byte === V17_PROOF_PROTOCOL_ID[index])) {
    throw new Error("v17 transcript header");
  }
  transcript.absorb("local-word-v17-magic", V17_PROOF_MAGIC);
  transcript.absorb("local-word-v17-proof-version", Uint8Array.of(input.version));
  transcript.absorb("local-word-v17-profile", Uint8Array.of(input.profile));
  transcript.absorb("local-word-v17-protocol-id", input.protocolId);
  transcript.absorb("local-word-v17-preprocessed-root", width32(input.preprocessedRoot, "preprocessed root"));
  transcript.absorb("local-word-v17-original-root", width32(input.originalRoot, "original root"));
}

function deriveInteractionChallenges(transcript: SuccessorTranscript): LocalWordInteractionChallenges {
  return {
    lookup: {
      gamma: transcript.challengeQm31("local-word-v17-lookup-gamma"),
      tuple: Array.from({ length: 6 }, (_, index) =>
        transcript.challengeQm31(`local-word-v17-lookup-tuple-${index}`)) as
        unknown as LocalWordInteractionChallenges["lookup"]["tuple"],
    },
    wordCopy: {
      gamma: transcript.challengeQm31("local-word-v17-copy-gamma"),
      identity: transcript.challengeQm31("local-word-v17-copy-identity"),
      limbs: Array.from({ length: 8 }, (_, index) =>
        transcript.challengeQm31(`local-word-v17-copy-limb-${index}`)) as
        unknown as LocalWordInteractionChallenges["wordCopy"]["limbs"],
    },
    boundary: {
      gamma: transcript.challengeQm31("local-word-v17-boundary-gamma"),
      identity: transcript.challengeQm31("local-word-v17-boundary-identity"),
      limbs: Array.from({ length: 8 }, (_, index) =>
        transcript.challengeQm31(`local-word-v17-boundary-limb-${index}`)) as
        unknown as LocalWordInteractionChallenges["boundary"]["limbs"],
    },
  };
}

function acceptRound(
  cursor: V17TheoremRoundCursor,
  id: V17TheoremRoundId,
  nonces: readonly number[],
): void {
  const index = V17_THEOREM_ROUND_IDS.indexOf(id);
  if (index < 0 || !cursor.accept(id, nonces[index]!)) {
    throw new Error(`v17 transcript PoW ${id}`);
  }
}

/**
 * Replay all challenge-generating phases. Derived-cache frames are checked by
 * the caller against this result; none is reabsorbed. Total length, ranks,
 * directories, and opening bodies are strict-codec data after the last
 * challenge and therefore intentionally absent here.
 */
export function replayV17ProofTranscript(input: V17ProofTranscriptInput): V17ProofTranscriptReplay {
  if (input.publicBoundaryInverses.length !== 8 || input.oodValues.length !== 98 ||
    input.friRoots.length !== 9 || input.finalCoefficients.length !== 8 ||
    input.roundNonces.length !== V17_THEOREM_ROUND_IDS.length) {
    throw new Error("v17 transcript geometry");
  }
  const transcript = new SuccessorTranscript(input.initial);
  const rounds = new V17TheoremRoundCursor(transcript);
  absorbHeader(transcript, input);

  acceptRound(rounds, "air:logup", input.roundNonces);
  const interactionChallenges = deriveInteractionChallenges(transcript);
  const interactionChallengeValues = localWordInteractionChallengeValues(interactionChallenges);

  transcript.absorb(
    "local-word-v17-public-boundary-inverses",
    concatBytes(...input.publicBoundaryInverses.map(encodeQm31)),
  );
  transcript.absorb(
    "local-word-v17-public-boundary-claimed-sum",
    encodeQm31(input.publicBoundaryClaimedSum),
  );
  transcript.absorb("local-word-v17-interaction-root", width32(input.interactionRoot, "interaction root"));
  transcript.absorb(
    "local-word-v17-interaction-global-root",
    width32(input.interactionGlobalRoot, "interaction global root"),
  );
  const interactionDigest = transcript.digest;
  acceptRound(rounds, "air:composition", input.roundNonces);
  const constraintAlpha = transcript.challengeQm31("local-word-v17-constraint-alpha");
  const compositionDigest = transcript.digest;

  transcript.absorb(
    "local-word-v17-quotient-and-fri-mask-root",
    width32(input.quotientAndFriMaskRoot, "quotient root"),
  );
  acceptRound(rounds, "air:ood", input.roundNonces);
  const oods = deriveV17OodsChallenge(transcript.digest);

  transcript.absorb("local-word-v17-ood-values", concatBytes(...input.oodValues.map(encodeQm31)));
  acceptRound(rounds, "fri:batch", input.roundNonces);
  const batchBeta = transcript.challengeQm31("local-word-v17-batch-beta");
  const batchDigest = transcript.digest;

  const friAlphas: QM31El[][] = [];
  let friMidDigest = new Uint8Array();
  input.friRoots.forEach((root, round) => {
    transcript.absorb(`local-word-v17-fri-root-${round}`, width32(root, `FRI root ${round}`));
    acceptRound(rounds, `fri:fold:${round}` as V17TheoremRoundId, input.roundNonces);
    const count = round < 8 ? 2 : 1;
    friAlphas.push(Array.from({ length: count }, (_, subfold) =>
      transcript.challengeQm31(`local-word-v17-fri-alpha-${round}-${subfold}`)));
    if (round === 4) friMidDigest = transcript.digest;
  });
  const friRootsDigest = transcript.digest;
  transcript.absorb(
    "local-word-v17-fri-final",
    concatBytes(...input.finalCoefficients.map(encodeQm31)),
  );
  acceptRound(rounds, "fri:query", input.roundNonces);
  rounds.finish();
  const queryDigest = transcript.digest;
  const queries = localWordQueryIndices(transcript, LOCAL_WORD_PRODUCTION_PARAMETERS);
  return {
    interactionChallenges,
    interactionChallengeValues,
    interactionDigest,
    constraintAlpha,
    compositionDigest,
    oods,
    batchBeta,
    batchDigest,
    friAlphas,
    friMidDigest,
    friRootsDigest,
    queryDigest,
    queries,
    finalDigest: transcript.digest,
  };
}

export function flattenV17FriAlphas(
  groups: readonly (readonly QM31El[])[],
): readonly QM31El[] {
  if (groups.length !== 9 || groups.some((group, round) => group.length !== (round < 8 ? 2 : 1))) {
    throw new Error("v17 FRI challenge groups");
  }
  return groups.flatMap((group) => [...group]);
}

import { encodeQm31, type QM31El } from "./qm31.ts";
import { SuccessorTranscript } from "./successor-transcript.ts";
import { successorTraceOffsetIndex } from "./successor-domain.ts";
import {
  LOCAL_WORD_PRODUCTION_PARAMETERS,
  type LocalWordProofParameters,
} from "./local-word-successor-params.ts";
import type { LocalShaWordCopyChallenges } from "../../chain/sha256-local-word-permutation.ts";

export type LocalWordInteractionChallenges = {
  readonly lookup: {
    readonly gamma: QM31El;
    readonly tuple: readonly [QM31El, QM31El, QM31El, QM31El, QM31El, QM31El];
  };
  readonly wordCopy: LocalShaWordCopyChallenges;
  readonly boundary: {
    readonly gamma: QM31El;
    readonly identity: QM31El;
    readonly limbs: readonly [QM31El, QM31El, QM31El, QM31El, QM31El, QM31El, QM31El, QM31El];
  };
};

export const LOCAL_WORD_INTERACTION_CHALLENGE_COUNT = 27;
export const LOCAL_WORD_BOUNDARY_CHALLENGE_START = 17;
export const LOCAL_WORD_BOUNDARY_CHALLENGE_COUNT = 10;

function fullLocalWordSchedule(
  queries: readonly number[],
  parameters: LocalWordProofParameters,
): boolean {
  const global = new Set(queries.flatMap((query) => [
    query,
    successorTraceOffsetIndex(query, parameters.relationLog, parameters.evalLog, -1),
  ]));
  return global.size === 2 * queries.length;
}

/** One fixed, collision-free schedule for every matrix and FRI opening. */
export function localWordQueryIndices(
  transcript: SuccessorTranscript,
  parameters: LocalWordProofParameters = LOCAL_WORD_PRODUCTION_PARAMETERS,
): number[] {
  const queries = transcript.queryIndices(
    2 ** parameters.evalLog,
    parameters.fri.queries,
    parameters.fri.queryOrbitLog,
  );
  if (!fullLocalWordSchedule(queries, parameters)) {
    throw new Error("local-word global query collision");
  }
  return queries;
}

export function localWordGrindForQueries(
  transcript: SuccessorTranscript,
  parameters: LocalWordProofParameters = LOCAL_WORD_PRODUCTION_PARAMETERS,
): number {
  return transcript.grindForQueries(
    parameters.fri.grindBits,
    2 ** parameters.evalLog,
    parameters.fri.queries,
    parameters.fri.queryOrbitLog,
    (queries) => fullLocalWordSchedule(queries, parameters),
  );
}

/** Canonical manifest order consumed by the independent VM relation roles. */
export function localWordInteractionChallengeValues(
  challenges: LocalWordInteractionChallenges,
): readonly QM31El[] {
  const values = [
    challenges.lookup.gamma,
    ...challenges.lookup.tuple,
    challenges.wordCopy.gamma,
    challenges.wordCopy.identity,
    ...challenges.wordCopy.limbs,
    challenges.boundary.gamma,
    challenges.boundary.identity,
    ...challenges.boundary.limbs,
  ];
  if (values.length !== LOCAL_WORD_INTERACTION_CHALLENGE_COUNT) {
    throw new Error("local-word interaction challenge manifest");
  }
  if (values.slice(LOCAL_WORD_BOUNDARY_CHALLENGE_START).length !==
    LOCAL_WORD_BOUNDARY_CHALLENGE_COUNT) {
    throw new Error("local-word boundary challenge manifest");
  }
  return values;
}

function root(root: Uint8Array, label: string): Uint8Array {
  if (root.length !== 32) throw new Error(`${label} width`);
  return root;
}

/** One versioned path from public construction and sealed roots to challenges. */
export function localWordInteractionTranscript(
  initial: Uint8Array,
  descriptorDigest: Uint8Array,
  preprocessedRoot: Uint8Array,
  originalRoot: Uint8Array,
): { readonly transcript: SuccessorTranscript; readonly challenges: LocalWordInteractionChallenges } {
  const transcript = new SuccessorTranscript(initial);
  transcript.absorb("local-word-v15-descriptor", root(descriptorDigest, "local-word descriptor"));
  transcript.absorb("local-word-v15-preprocessed-root", root(preprocessedRoot, "local-word preprocessed root"));
  transcript.absorb("local-word-v15-original-root", root(originalRoot, "local-word original root"));
  const lookup = {
    gamma: transcript.challengeQm31("local-word-v15-lookup-gamma"),
    tuple: Array.from({ length: 6 }, (_, index) =>
      transcript.challengeQm31(`local-word-v15-lookup-tuple-${index}`)) as unknown as LocalWordInteractionChallenges["lookup"]["tuple"],
  };
  const wordCopy = {
    gamma: transcript.challengeQm31("local-word-v15-copy-gamma"),
    identity: transcript.challengeQm31("local-word-v15-copy-identity"),
    limbs: Array.from({ length: 8 }, (_, limb) =>
      transcript.challengeQm31(`local-word-v15-copy-limb-${limb}`)) as
      unknown as LocalShaWordCopyChallenges["limbs"],
  };
  const boundary = {
    gamma: transcript.challengeQm31("local-word-v15-boundary-gamma"),
    identity: transcript.challengeQm31("local-word-v15-boundary-identity"),
    limbs: Array.from({ length: 8 }, (_, limb) =>
      transcript.challengeQm31(`local-word-v15-boundary-limb-${limb}`)) as unknown as LocalWordInteractionChallenges["boundary"]["limbs"],
  };
  return { transcript, challenges: { lookup, wordCopy, boundary } };
}

export function localWordCompositionTranscript(
  transcript: SuccessorTranscript,
  interactionRoot: Uint8Array,
  interactionGlobalRoot: Uint8Array,
): { readonly constraintAlpha: QM31El; readonly digest: Uint8Array } {
  transcript.absorb(
    "local-word-v15-interaction-root",
    root(interactionRoot, "local-word interaction root"),
  );
  transcript.absorb(
    "local-word-v15-interaction-global-root",
    root(interactionGlobalRoot, "local-word interaction global root"),
  );
  const constraintAlpha = transcript.challengeQm31("local-word-v15-constraint-alpha");
  return { constraintAlpha, digest: transcript.digest };
}

/** Bind the verifier-checked public inverses before any interaction root. */
export function localWordPublicBoundaryTranscript(
  transcript: SuccessorTranscript,
  publicInverses: readonly QM31El[],
): Uint8Array {
  if (publicInverses.length < 1 || publicInverses.length > 1024) {
    throw new Error("local-word public boundary transcript");
  }
  const encoded = new Uint8Array(publicInverses.length * 16);
  publicInverses.forEach((inverse, index) => encoded.set(encodeQm31(inverse), index * 16));
  transcript.absorb("local-word-v15-public-boundary", encoded);
  return transcript.digest;
}

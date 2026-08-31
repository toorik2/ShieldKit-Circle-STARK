import { encodeQm31, type QM31El } from "./qm31.ts";
import { SuccessorTranscript } from "./successor-transcript.ts";
import { successorTraceOffsetIndex } from "./successor-domain.ts";
import {
  LOCAL_WORD_PRODUCTION_PARAMETERS,
  validateLocalWordProofParameters,
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

export type LocalWordQuerySamplerCertificate = {
  readonly rowCount: number;
  readonly orbitSize: number;
  readonly orbitCount: number;
  readonly orbitPrefixLog: number;
  readonly predecessorStep: number;
  readonly maxForbiddenCandidates: number;
  readonly maxScanAttempts: number;
};

export type LocalWordQuerySample = {
  readonly counter: number;
  readonly orbit: number;
  readonly seed: number;
  readonly scan: number;
  readonly query: number;
  readonly predecessor: number;
};

/**
 * Certify the finite scan used after orbit sampling. A query orbit fixes the
 * low natural-index prefix. On each of the two circle halves, predecessor is
 * a translation of that prefix, hence a bijection of query orbits. Distinct
 * selected orbits can therefore place at most two predecessors in the next
 * orbit, while its predecessor can meet at most two prior query orbits. At
 * most four representatives are forbidden, so five distinct scans suffice.
 * The predecessor itself is fixed-point-free because its non-zero step is
 * smaller than a half-domain.
 */
export function validateLocalWordQuerySamplerGeometry(
  parameters: LocalWordProofParameters = LOCAL_WORD_PRODUCTION_PARAMETERS,
): LocalWordQuerySamplerCertificate {
  validateLocalWordProofParameters(parameters);
  const rowCount = 2 ** parameters.evalLog;
  const halfRows = rowCount / 2;
  const orbitSize = 2 ** parameters.fri.queryOrbitLog;
  const orbitCount = rowCount / orbitSize;
  const orbitPrefixLog = parameters.evalLog - parameters.fri.queryOrbitLog;
  const predecessorStep = 2 ** (parameters.evalLog - parameters.relationLog - 1);
  const maxForbiddenCandidates = parameters.fri.queries === 1 ? 0 : 4;
  const maxScanAttempts = maxForbiddenCandidates + 1;
  if (!Number.isSafeInteger(predecessorStep) || predecessorStep < 1 ||
    predecessorStep >= halfRows || orbitPrefixLog < 1 ||
    parameters.fri.queries > orbitCount ||
    orbitSize <= maxForbiddenCandidates) {
    throw new Error("local-word total query sampler geometry");
  }
  return {
    rowCount,
    orbitSize,
    orbitCount,
    orbitPrefixLog,
    predecessorStep,
    maxForbiddenCandidates,
    maxScanAttempts,
  };
}

/** Canonical orbit choices plus the first collision-free representative scan. */
export function localWordQuerySamples(
  transcript: SuccessorTranscript,
  parameters: LocalWordProofParameters = LOCAL_WORD_PRODUCTION_PARAMETERS,
): LocalWordQuerySample[] {
  const geometry = validateLocalWordQuerySamplerGeometry(parameters);
  const selected = transcript.queryOrbits(
    geometry.rowCount,
    parameters.fri.queries,
    parameters.fri.queryOrbitLog,
  );
  const occupied = new Set<number>();
  const samples: LocalWordQuerySample[] = [];
  selected.forEach(({ counter, orbit, seed }, item) => {
    const orbitBase = orbit * geometry.orbitSize;
    const attempts = Math.min(4 * item, 4) + 1;
    for (let scan = 0; scan < attempts; scan += 1) {
      const query = orbitBase + ((seed + scan) & (geometry.orbitSize - 1));
      const predecessor = successorTraceOffsetIndex(
        query,
        parameters.relationLog,
        parameters.evalLog,
        -1,
      );
      if (query === predecessor || occupied.has(query) || occupied.has(predecessor)) continue;
      occupied.add(query);
      occupied.add(predecessor);
      samples.push({ counter, orbit, seed, scan, query, predecessor });
      return;
    }
    throw new Error("local-word total query sampler invariant");
  });
  if (samples.length !== parameters.fri.queries || occupied.size !== 2 * samples.length) {
    throw new Error("local-word total query sampler completion");
  }
  return samples;
}

/** One fixed, collision-free schedule for every matrix and FRI opening. */
export function localWordQueryIndices(
  transcript: SuccessorTranscript,
  parameters: LocalWordProofParameters = LOCAL_WORD_PRODUCTION_PARAMETERS,
): number[] {
  return localWordQuerySamples(transcript, parameters).map(({ query }) => query);
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
  transcript.absorb("local-word-v16-descriptor", root(descriptorDigest, "local-word descriptor"));
  transcript.absorb("local-word-v16-preprocessed-root", root(preprocessedRoot, "local-word preprocessed root"));
  transcript.absorb("local-word-v16-original-root", root(originalRoot, "local-word original root"));
  const lookup = {
    gamma: transcript.challengeQm31("local-word-v16-lookup-gamma"),
    tuple: Array.from({ length: 6 }, (_, index) =>
      transcript.challengeQm31(`local-word-v16-lookup-tuple-${index}`)) as unknown as LocalWordInteractionChallenges["lookup"]["tuple"],
  };
  const wordCopy = {
    gamma: transcript.challengeQm31("local-word-v16-copy-gamma"),
    identity: transcript.challengeQm31("local-word-v16-copy-identity"),
    limbs: Array.from({ length: 8 }, (_, limb) =>
      transcript.challengeQm31(`local-word-v16-copy-limb-${limb}`)) as
      unknown as LocalShaWordCopyChallenges["limbs"],
  };
  const boundary = {
    gamma: transcript.challengeQm31("local-word-v16-boundary-gamma"),
    identity: transcript.challengeQm31("local-word-v16-boundary-identity"),
    limbs: Array.from({ length: 8 }, (_, limb) =>
      transcript.challengeQm31(`local-word-v16-boundary-limb-${limb}`)) as unknown as LocalWordInteractionChallenges["boundary"]["limbs"],
  };
  return { transcript, challenges: { lookup, wordCopy, boundary } };
}

export function localWordCompositionTranscript(
  transcript: SuccessorTranscript,
  interactionRoot: Uint8Array,
  interactionGlobalRoot: Uint8Array,
): { readonly constraintAlpha: QM31El; readonly digest: Uint8Array } {
  transcript.absorb(
    "local-word-v16-interaction-root",
    root(interactionRoot, "local-word interaction root"),
  );
  transcript.absorb(
    "local-word-v16-interaction-global-root",
    root(interactionGlobalRoot, "local-word interaction global root"),
  );
  const constraintAlpha = transcript.challengeQm31("local-word-v16-constraint-alpha");
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
  transcript.absorb("local-word-v16-public-boundary", encoded);
  return transcript.digest;
}

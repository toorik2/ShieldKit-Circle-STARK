import { createHash } from "node:crypto";
import {
  v17BankDigestHexFromRoles,
  type V17BankIdentityRole,
} from "./v17-bank-identity.ts";
import { LOCAL_WORD_RELATION_CONSTRUCTION_VERSION } from
  "../chain/local-word-relation-version.ts";

export const V17_PROOF_VERSION = 17 as const;
export const V17_ELASTIC_PREFIX_SCALE = 4_095 as const;
export const V17_MAXIMUM_CANONICAL_PROOF_BYTES = 457_514 as const;
export const V17_PRODUCTION_QUERY_COUNT = 44 as const;
export const V17_PROFILES = [0, 1, 2] as const;
export type V17Profile = typeof V17_PROFILES[number];

export const V17_NORMATIVE_DOCUMENT_LAYOUT = [
  { id: "constitution", path: "RULES.md" },
  { id: "privacy-membrane", path: "ZK-MEMBRANE.md" },
  { id: "completeness-map", path: "COMPLETENESS.md" },
] as const;
export type V17NormativeDocumentId = typeof V17_NORMATIVE_DOCUMENT_LAYOUT[number]["id"];

export type V17NormativeSpec = {
  /** Files are identity-bound as opaque bytes; Markdown parsing is never consensus-critical. */
  readonly bytePolicy: {
    readonly encoding: "utf-8";
    readonly byteOrderMark: "forbidden";
    readonly lineEndings: "lf";
    readonly terminalNewline: "required";
    readonly interpretation: "opaque-bytes-no-markdown-parsing";
    readonly digest: "sha256-exact-bytes";
  };
  /** Order, IDs, paths, and exact byte digests are all protocol identity. */
  readonly documents: readonly {
    readonly id: V17NormativeDocumentId;
    readonly path: typeof V17_NORMATIVE_DOCUMENT_LAYOUT[number]["path"];
    readonly sha256Hex: string;
  }[];
};

export const V17_TRANSCRIPT_ROLE_PARTS = [
  "interaction", "composition", "batch", "fri-first", "fri-second", "final",
] as const;

export const V17_MATRIX_NAMES = [
  "preprocessed",
  "original",
  "interaction",
  "interactionGlobal",
  "quotientAndFriMask",
] as const;
export type V17MatrixName = typeof V17_MATRIX_NAMES[number];

export const V17_PRODUCTION_ROUND_GRINDING = [
  { id: "air:logup", bits: 9 },
  { id: "air:composition", bits: 0 },
  { id: "air:ood", bits: 3 },
  { id: "fri:batch", bits: 26 },
  { id: "fri:fold:0", bits: 20 },
  { id: "fri:fold:1", bits: 18 },
  { id: "fri:fold:2", bits: 16 },
  { id: "fri:fold:3", bits: 14 },
  { id: "fri:fold:4", bits: 12 },
  { id: "fri:fold:5", bits: 10 },
  { id: "fri:fold:6", bits: 8 },
  { id: "fri:fold:7", bits: 6 },
  { id: "fri:fold:8", bits: 4 },
  { id: "fri:query", bits: 26 },
] as const;
export type V17ProductionRoundId = typeof V17_PRODUCTION_ROUND_GRINDING[number]["id"];

export const V17_COMPLETENESS_IDS = Array.from(
  { length: 33 },
  (_, index) => `C${index + 1}` as `C${number}`,
) as readonly `C${number}`[];
export type V17CompletenessId = typeof V17_COMPLETENESS_IDS[number];

export type V17FoundationSpec = {
  readonly proofFamily: "transparent-circle-fri-stark";
  readonly relationConstructionVersion: typeof LOCAL_WORD_RELATION_CONSTRUCTION_VERSION;
  readonly nativeHash: "sha256";
  readonly traceField: "m31";
  readonly challengeField: "qm31";
  readonly classicalSoundnessFloorBits: 100;
  readonly quantumClaim: "no-known-polynomial-time-quantum-break";
  readonly relationLog: 18;
  /** S-two function degree bound; the trace itself still has 2^18 rows. */
  readonly functionDegreeLog: 19;
  readonly sealedDegreeLog: 19;
  readonly quotientDegreeLog: 20;
  readonly evaluationLog: 24;
  readonly friLogBlowup: 4;
  readonly theta: { readonly numerator: 181; readonly denominator: 256 };
  readonly queries: typeof V17_PRODUCTION_QUERY_COUNT;
  readonly maximumRoundGrindingBits: 26;
  readonly roundGrinding: typeof V17_PRODUCTION_ROUND_GRINDING;
  readonly grindingNonce: {
    readonly serializedBytes: 4;
    readonly proofCodec: "u32be";
    readonly transcriptEncoding: "u32le";
    readonly transcriptDomain: "v17-theorem-round+pow";
    readonly searchSpaceBits: 32;
    readonly expectedHitsAtMaximumBits: 64;
    readonly theoremSaltRestriction: "soundness-monotone-completeness-only";
  };
  readonly oodValueCount: 98;
  readonly degreeCorrectedBatchWidth: 197;
  readonly finalLogDegree: 3;
  readonly friFoldLogs: readonly (1 | 2)[];
  readonly friFoldChallengeCounts: readonly (1 | 2)[];
  readonly friChallengeDerivation: "independent-fiat-shamir";
  readonly virtualIntermediate: "deterministic-uncommitted";
};

export type V17ProofFrameSpec = {
  readonly id: string;
  readonly offsetBytes: number;
  readonly itemBytes: number;
  readonly itemCount: number;
  readonly codec: "bytes" | "u8" | "u32be" | "m31" | "qm31" | "sha256";
};

export type V17ProofSchema = {
  readonly version: 17;
  readonly frames: readonly V17ProofFrameSpec[];
  readonly dynamicTail: {
    readonly id: string;
    readonly offsetBytes: number;
    readonly alignmentBytes: number;
    readonly codec: "canonical-opening-bodies";
  };
};

export type V17TranscriptSectionMode =
  /** The serialized prover message is absorbed before this phase's challenge. */
  | "transcript-absorb"
  /** A serialized cache is checked against an already-derived value and is not reabsorbed. */
  | "derived-snapshot"
  /** A nonce is consumed only by the named-round proof-of-work check. */
  | "named-round-pow"
  /** A post-query field is checked by the strict codec; no challenge follows it. */
  | "terminal-strict-codec";

export type V17TranscriptSectionConsumption = {
  readonly id: string;
  readonly mode: V17TranscriptSectionMode;
};

export type V17TranscriptPhaseSpec = {
  readonly id: string;
  readonly ordinal: number;
  readonly dependsOn: readonly string[];
  /** Every proof section is consumed exactly once, with no ambiguous reabsorption. */
  readonly consumesSections: readonly V17TranscriptSectionConsumption[];
  readonly challenges: readonly string[];
};

export type V17CommitmentSpec = {
  readonly id: string;
  readonly hashLabel: string;
  readonly domainLog: number;
  readonly leafCodec: string;
  readonly rowBytes: number;
  /** Number of fixed leaf-verifier shards; never selected by proof bytes. */
  readonly leafShards: 1 | 2;
  /** Measured internal consumed-bit boundaries; parent stages also start at 0. */
  readonly verifierCuts: readonly number[];
  /** Leaf-to-root arities. A 4 consumes two binary domain bits. */
  readonly arities: readonly (2 | 4)[];
};

export const V17_ROLE_KINDS = [
  "settlement",
  "ood-air",
  "batch-link-query",
  "fri-fold-query",
  "public-boundary",
  "proof-header",
  "edge-append",
  "sparse-nullifier",
  "transcript",
  "query-schedule",
  "opening-schedule",
  "matrix-merkle",
  "fri-merkle",
] as const;
export type V17RoleKind = typeof V17_ROLE_KINDS[number];

/**
 * Exact miner role meaning. These instances live in the construction graph,
 * so their order and parameters are covered by the protocol identifier.
 */
export type V17RoleSemantic =
  | { readonly kind: "settlement" }
  | { readonly kind: "ood-air" }
  | { readonly kind: "batch-link-query"; readonly query: number }
  | { readonly kind: "public-boundary-inverses" }
  | { readonly kind: "proof-header" }
  | { readonly kind: "edge-append" }
  | { readonly kind: "sparse-nullifier"; readonly root: "absence" | "used";
      readonly segment: 0 | 1 }
  | { readonly kind: "public-boundary-sum" }
  | { readonly kind: "transcript";
      readonly part: typeof V17_TRANSCRIPT_ROLE_PARTS[number] }
  | { readonly kind: "query-schedule" }
  | { readonly kind: "opening-current" }
  | { readonly kind: "opening-global"; readonly stage: "current" | "previous" | "shape" }
  | { readonly kind: "opening-fri"; readonly layer: number;
      readonly stage: "current" | "shape"; readonly mappingShard?: 0 | 1 }
  | { readonly kind: "fri-fold-query"; readonly query: number }
  | { readonly kind: "matrix-merkle-leaf"; readonly matrix: V17MatrixName;
      readonly shard: number; readonly shards: number }
  | { readonly kind: "matrix-merkle-parent"; readonly matrix: V17MatrixName;
      readonly stage: number }
  | { readonly kind: "fri-merkle-leaf"; readonly layer: number;
      readonly shard: number; readonly shards: number }
  | { readonly kind: "fri-merkle-parent"; readonly layer: number; readonly stage: number };

export type V17RoleFamilySpec = {
  readonly id: string;
  readonly kind: V17RoleKind;
  /** The sole canonical expansion of this role family. */
  readonly semanticInstances: readonly V17RoleSemantic[];
  readonly ordinalSource: "singleton" | "input-index" | "generated-static";
  readonly proofCarrier: boolean;
  /** Whether literal function bodies may depend on the post-link bank identity. */
  readonly defineBodyIdentity: "construction-independent" | "construction-bound";
  readonly profiles: readonly V17Profile[];
  readonly description: string;
};

export type V17ObligationSpec = {
  readonly id: V17CompletenessId;
  readonly ownerRole: string;
  readonly dependsOn: readonly V17CompletenessId[];
};

export type V17ConstructionGraph = {
  readonly schema: "ShieldKit/V17ConstructionGraph/v1";
  readonly version: 17;
  readonly normativeSpec: V17NormativeSpec;
  readonly foundation: V17FoundationSpec;
  readonly verifierKeyDigests: readonly {
    readonly profile: V17Profile;
    readonly status: "inherited-v16-unqualified" | "derived-v17";
    readonly relationConstructionDigestHex: string;
    readonly preprocessedRootHex: string;
  }[];
  readonly proof: V17ProofSchema;
  readonly transcript: readonly V17TranscriptPhaseSpec[];
  readonly commitments: readonly V17CommitmentSpec[];
  readonly roles: readonly V17RoleFamilySpec[];
  readonly obligations: readonly V17ObligationSpec[];
  readonly allocation: {
    readonly strategy: "base-plus-elastic-prefix";
    readonly proofPartition: "one-contiguous-copy";
    readonly densityCredit: "max-profile-residual-proof-bytes";
    readonly baseEndpoint: "sum-max-profile-residual-proof-bytes";
    readonly closure: "coordinatewise-monotone-profile-envelope";
    readonly closureGenesis: "canonical-bootstrap-affine-allocation";
    readonly closureJoin: "profile-opcost-max-required-max-capacity-min";
    readonly closureTerminal: "explicit-no-change-replay";
    readonly closureTrace: "domain-separated-sha256-chain";
    readonly elasticNormalization: "cumulative-floor-prefix-union";
    readonly elasticScaleUnits: 4_095;
    readonly maximumProofBytes: 457_514;
    readonly minimumProofBytesPerRole: 256;
    readonly capacityLimitBytes: 10_000;
    readonly capacityDerivation: "canonical-proof-push-plus-linked-redeem-push";
    readonly slackDistribution: "capacity-proportional-hamilton-role-order";
    readonly metadataEncoding: "base19-elastic12-disabled-sequence";
  };
  readonly rom: {
    readonly pageFormat: "p2sh32-authenticated-function-page-v1";
    readonly payloadFormat: "skr1-directory-and-exact-bodies-v1";
    readonly bodyAccess: "sibling-input-bytecode-canonical-slice";
    readonly eligibility: "construction-independent-op-define-bodies";
    readonly bankIdentity: "profile-seeded-bch-native-sha256-fold-verifier-workers-and-rom-pages-excluding-settlement-v1";
    readonly deduplication: "exact-byte-equality";
    readonly promotion: "strict-positive-saving-in-every-profile";
    readonly qualificationMeasurement: "post-link-all-profile-independent-bchn";
    readonly functionIdentifiers:
      "minimal-positive-unsigned-be-earliest-static-occurrence-anchor";
    readonly packing: "minimum-pages-then-semantic-anchor";
    readonly placement: "after-proof-workers";
    readonly limits: {
      readonly scriptBytes: 10_000;
      readonly elementBytes: 10_000;
      readonly stackItems: 1_000;
      readonly controlDepth: 100;
      readonly functionIdentifierBytes: 7;
      readonly opcostPerInputByte: 800;
      readonly consensusTransactionBytes: 1_000_000;
    };
  };
};

export type V17ExpandedRole = {
  readonly logicalInputIndex: number;
  readonly id: string;
  readonly familyId: string;
  readonly kind: V17RoleKind;
  readonly semantic: V17RoleSemantic;
  readonly ordinal: number;
  readonly ordinalSource: V17RoleFamilySpec["ordinalSource"];
  readonly proofCarrier: boolean;
  readonly defineBodyIdentity: V17RoleFamilySpec["defineBodyIdentity"];
  readonly profiles: readonly V17Profile[];
  readonly obligations: readonly V17CompletenessId[];
};

export type V17VerifierPlan = {
  readonly schema: "ShieldKit/V17VerifierPlan/v1";
  readonly protocolIdHex: string;
  readonly roleFamilies: readonly V17RoleFamilySpec[];
  readonly roles: readonly V17ExpandedRole[];
  readonly allocation: {
    readonly status: "unmeasured" | "measured";
    readonly strategy: V17ConstructionGraph["allocation"]["strategy"];
    readonly densityCredit: V17ConstructionGraph["allocation"]["densityCredit"];
    readonly baseEndpoint: V17ConstructionGraph["allocation"]["baseEndpoint"];
    readonly closure: V17ConstructionGraph["allocation"]["closure"];
    readonly closureGenesis: V17ConstructionGraph["allocation"]["closureGenesis"];
    readonly closureJoin: V17ConstructionGraph["allocation"]["closureJoin"];
    readonly closureTerminal: V17ConstructionGraph["allocation"]["closureTerminal"];
    readonly closureTrace: V17ConstructionGraph["allocation"]["closureTrace"];
    readonly elasticNormalization: V17ConstructionGraph["allocation"]["elasticNormalization"];
    readonly elasticScaleUnits: 4_095;
    readonly minimumProofBytes: number | null;
    readonly maximumProofBytes: 457_514;
    readonly minimumProofBytesPerRole: 256;
    readonly capacityLimitBytes: 10_000;
    readonly capacityDerivation: V17ConstructionGraph["allocation"]["capacityDerivation"];
    readonly slackDistribution: V17ConstructionGraph["allocation"]["slackDistribution"];
    readonly metadataEncoding: V17ConstructionGraph["allocation"]["metadataEncoding"];
    readonly proofRoleCount: number;
    readonly assignments: readonly {
      readonly roleId: string;
      readonly basePrefixStart: number;
      readonly basePrefixEnd: number;
      readonly elasticPrefixStart: number;
      readonly elasticPrefixEnd: number;
      readonly requiredProofBytes: number;
      readonly capacityProofBytes: number;
      readonly maximumOperationCost: number;
    }[];
  };
  readonly rom: {
    readonly status: "unmeasured" | "measured";
    readonly pageFormat: V17ConstructionGraph["rom"]["pageFormat"];
    readonly payloadFormat: V17ConstructionGraph["rom"]["payloadFormat"];
    readonly bodyAccess: V17ConstructionGraph["rom"]["bodyAccess"];
    readonly eligibility: V17ConstructionGraph["rom"]["eligibility"];
    readonly bankIdentity: V17ConstructionGraph["rom"]["bankIdentity"];
    readonly deduplication: V17ConstructionGraph["rom"]["deduplication"];
    readonly promotion: V17ConstructionGraph["rom"]["promotion"];
    readonly qualificationMeasurement: V17ConstructionGraph["rom"]["qualificationMeasurement"];
    readonly functionIdentifiers: V17ConstructionGraph["rom"]["functionIdentifiers"];
    readonly packing: V17ConstructionGraph["rom"]["packing"];
    readonly placement: V17ConstructionGraph["rom"]["placement"];
    readonly limits: V17ConstructionGraph["rom"]["limits"];
    readonly pages: readonly {
      readonly index: number;
      readonly inputIndex: number;
      readonly outputIndex: number;
      readonly sha256Hex: string;
      readonly bytes: number;
      readonly functionIds: readonly string[];
    }[];
  };
};

export const V17_QUALIFICATION_GATE_IDS = [
  "graph-validation",
  "generated-artifacts",
  "protocol-correspondence",
  "rom-authentication",
  "all-schedule-envelope",
  "profile-0-end-to-end",
  "profile-1-end-to-end",
  "profile-2-end-to-end",
  "privacy-observer",
  "soundness-reduction",
  "source-purity",
  "independent-replay",
] as const;
export type V17QualificationGateId = typeof V17_QUALIFICATION_GATE_IDS[number];

export type V17QualificationGateState =
  | { readonly status: "pending"; readonly reason: string }
  | { readonly status: "blocked"; readonly reason: string }
  | {
    readonly status: "passed";
    readonly evidence: {
      readonly sha256Hex: string;
      readonly summary: string;
    };
  };

export type V17QualificationStatus = {
  readonly schema: "ShieldKit/V17QualificationStatus/v1";
  readonly protocolIdHex: string;
  readonly constructionIdHex: string | null;
  readonly overall: "incomplete" | "blocked" | "qualified";
  readonly gates: Readonly<Record<V17QualificationGateId, V17QualificationGateState>>;
  readonly unresolved: readonly string[];
};

type MutableFrame = Omit<V17ProofFrameSpec, "offsetBytes">;

function contiguousFrames(specs: readonly MutableFrame[]): readonly V17ProofFrameSpec[] {
  let offsetBytes = 0;
  return specs.map((frame) => {
    const placed = { ...frame, offsetBytes };
    offsetBytes += frame.itemBytes * frame.itemCount;
    return placed;
  });
}

const MATRIX_ROOT_IDS = V17_MATRIX_NAMES;

const ROUND_NONCE_FRAMES: readonly MutableFrame[] = V17_PRODUCTION_ROUND_GRINDING.map(({ id }) => ({
  id: `roundNonce:${id}`,
  itemBytes: 4,
  itemCount: 1,
  codec: "u32be" as const,
}));

const FRI_CHALLENGE_FRAME_IDS = [
  ...Array.from({ length: 8 }, (_, group) => [`friAlpha:${group}:0`, `friAlpha:${group}:1`]).flat(),
  "friAlpha:8:0",
] as const;

const DERIVED_SNAPSHOT_FRAME_IDS = [
  "interactionChallenges",
  "interactionDigest",
  "constraintAlpha",
  "compositionDigest",
  "batchBeta",
  "batchDigest",
  ...FRI_CHALLENGE_FRAME_IDS,
  "friMidDigest",
  "friRootsDigest",
  "queryDigest",
  "queries",
  "currentIndices",
  "currentRanks",
  "globalCurrentRanks",
  "globalPreviousRanks",
  "friCosetRanks",
] as const;

const TERMINAL_STRICT_CODEC_FRAME_IDS = [
  "totalLength",
  "openingDirectory",
  "openingBodies",
] as const;

function consumeSections(
  mode: V17TranscriptSectionMode,
  ...ids: readonly string[]
): readonly V17TranscriptSectionConsumption[] {
  return ids.map((id) => ({ id, mode }));
}

const PROOF_FRAMES = contiguousFrames([
  { id: "magic", itemBytes: 4, itemCount: 1, codec: "bytes" },
  { id: "proofVersion", itemBytes: 1, itemCount: 1, codec: "u8" },
  { id: "profile", itemBytes: 1, itemCount: 1, codec: "u8" },
  { id: "protocolId", itemBytes: 32, itemCount: 1, codec: "sha256" },
  { id: "totalLength", itemBytes: 4, itemCount: 1, codec: "u32be" },
  { id: "publicInverses", itemBytes: 16, itemCount: 8, codec: "qm31" },
  { id: "publicClaimedSum", itemBytes: 16, itemCount: 1, codec: "qm31" },
  ...MATRIX_ROOT_IDS.map((id) => ({
    id: `matrixRoot:${id}`, itemBytes: 32, itemCount: 1, codec: "sha256" as const,
  })),
  { id: "interactionChallenges", itemBytes: 16, itemCount: 27, codec: "qm31" },
  { id: "interactionDigest", itemBytes: 32, itemCount: 1, codec: "sha256" },
  { id: "constraintAlpha", itemBytes: 16, itemCount: 1, codec: "qm31" },
  { id: "compositionDigest", itemBytes: 32, itemCount: 1, codec: "sha256" },
  { id: "oodValues", itemBytes: 16, itemCount: 98, codec: "qm31" },
  { id: "batchBeta", itemBytes: 16, itemCount: 1, codec: "qm31" },
  { id: "batchDigest", itemBytes: 32, itemCount: 1, codec: "sha256" },
  ...Array.from({ length: 9 }, (_, index) => ({
    id: `friRoot:${index}`, itemBytes: 32, itemCount: 1, codec: "sha256" as const,
  })),
  ...FRI_CHALLENGE_FRAME_IDS.map((id) => ({
    id, itemBytes: 16, itemCount: 1, codec: "qm31" as const,
  })),
  { id: "finalCoefficients", itemBytes: 16, itemCount: 8, codec: "qm31" },
  { id: "friMidDigest", itemBytes: 32, itemCount: 1, codec: "sha256" },
  { id: "friRootsDigest", itemBytes: 32, itemCount: 1, codec: "sha256" },
  ...ROUND_NONCE_FRAMES,
  { id: "queryDigest", itemBytes: 32, itemCount: 1, codec: "sha256" },
  { id: "queries", itemBytes: 4, itemCount: V17_PRODUCTION_QUERY_COUNT, codec: "u32be" },
  { id: "currentIndices", itemBytes: 4, itemCount: V17_PRODUCTION_QUERY_COUNT, codec: "u32be" },
  { id: "currentRanks", itemBytes: 1, itemCount: V17_PRODUCTION_QUERY_COUNT, codec: "u8" },
  { id: "globalCurrentRanks", itemBytes: 1, itemCount: V17_PRODUCTION_QUERY_COUNT, codec: "u8" },
  { id: "globalPreviousRanks", itemBytes: 1, itemCount: V17_PRODUCTION_QUERY_COUNT, codec: "u8" },
  { id: "friCosetRanks", itemBytes: 1, itemCount: 9 * V17_PRODUCTION_QUERY_COUNT, codec: "u8" },
  { id: "openingDirectory", itemBytes: 20, itemCount: 5 + 9, codec: "bytes" },
]);

const FIXED_PREFIX_BYTES = PROOF_FRAMES.reduce(
  (end, frame) => Math.max(end, frame.offsetBytes + frame.itemBytes * frame.itemCount),
  0,
);

const MATRIX_COMMITMENT_ROWS = {
  preprocessed: [172, "m31-row"],
  original: [136, "m31-row"],
  interaction: [224, "qm31-row"],
  interactionGlobal: [48, "qm31-row"],
  quotientAndFriMask: [32, "qm31-row"],
} as const satisfies Readonly<Record<
  V17MatrixName,
  readonly [number, "m31-row" | "qm31-row"]
>>;

const FRI_LAYER_LOGS = [24, 22, 20, 18, 16, 14, 12, 10, 8] as const;

const MATRIX_MERKLE_CUTS = {
  preprocessed: [6, 12, 18],
  original: [6, 12, 18],
  interaction: [6, 12, 18],
  interactionGlobal: [1, 3, 5, 7, 9, 11, 13, 15, 17],
  quotientAndFriMask: [6, 12, 18],
} as const;

const FRI_MERKLE_CUTS = [
  [2, 7, 13], [2, 5, 11], [2, 8, 14], [2, 7], [2, 5], [2, 8], [2], [2], [],
] as const;

function binaryArities(log: number): readonly 2[] {
  return Array.from({ length: log }, () => 2 as const);
}

const COMMITMENTS: readonly V17CommitmentSpec[] = [
  ...V17_MATRIX_NAMES.map((name) => {
    const [rowBytes, codec] = MATRIX_COMMITMENT_ROWS[name];
    return {
      id: `matrix:${name}`,
      hashLabel: `local-word:${name === "interactionGlobal"
        ? "interaction-global"
        : name === "quotientAndFriMask" ? "quotient-and-fri-mask" : name}`,
      domainLog: 24,
      leafCodec: `${codec}:${rowBytes}-bytes`,
      rowBytes,
      leafShards: 1 as const,
      verifierCuts: MATRIX_MERKLE_CUTS[name],
      arities: binaryArities(24),
    };
  }),
  ...FRI_LAYER_LOGS.map((log, layer) => ({
    id: `fri:${layer}`,
    hashLabel: `fri:layer:${layer}`,
    domainLog: log,
    leafCodec: "qm31-value",
    rowBytes: 16,
    leafShards: layer < 8 ? 2 as const : 1 as const,
    verifierCuts: FRI_MERKLE_CUTS[layer]!,
    arities: layer < 8
      ? [4 as const, ...binaryArities(log - 2)]
      : binaryArities(log),
  })),
];

type V17RoleSemanticSource = {
  readonly queries: number;
  readonly commitments: readonly V17CommitmentSpec[];
};

function orderedCommitmentFamilies(source: V17RoleSemanticSource): {
  readonly matrices: readonly V17CommitmentSpec[];
  readonly fri: readonly V17CommitmentSpec[];
} {
  const matrices = source.commitments.filter(({ id }) => id.startsWith("matrix:"));
  const fri = source.commitments.filter(({ id }) => id.startsWith("fri:"));
  if (matrices.length !== V17_MATRIX_NAMES.length || matrices.some((commitment, index) =>
    commitment.id !== `matrix:${V17_MATRIX_NAMES[index]}`) ||
    fri.some((commitment, layer) => commitment.id !== `fri:${layer}`)) {
    throw new Error("v17 semantic commitment inventory");
  }
  return { matrices, fri };
}

/**
 * Derive the exact ordered semantic instances owned by one graph family.
 * The returned objects are stored in the graph and therefore protocol-bound;
 * this derivation is also reused by validation to reject silent drift.
 */
function deriveV17RoleSemanticInstances(
  familyId: string,
  source: V17RoleSemanticSource,
): readonly V17RoleSemantic[] {
  if (!Number.isSafeInteger(source.queries) || source.queries < 1) {
    throw new Error("v17 semantic query count");
  }
  const { matrices, fri } = orderedCommitmentFamilies(source);
  switch (familyId) {
    case "settlement": return [{ kind: "settlement" }];
    case "ood-air": return [{ kind: "ood-air" }];
    case "batch-link-query": return Array.from(
      { length: source.queries }, (_, query) => ({ kind: "batch-link-query", query }),
    );
    case "public-boundary-inverses": return [{ kind: "public-boundary-inverses" }];
    case "proof-header": return [{ kind: "proof-header" }];
    case "edge-append": return [{ kind: "edge-append" }];
    case "sparse-nullifier": return (["absence", "used"] as const).flatMap((root) =>
      ([0, 1] as const).map((segment) => ({ kind: "sparse-nullifier", root, segment })));
    case "public-boundary-sum": return [{ kind: "public-boundary-sum" }];
    case "transcript": return V17_TRANSCRIPT_ROLE_PARTS.map((part) =>
      ({ kind: "transcript", part }));
    case "query-schedule": return [{ kind: "query-schedule" }];
    case "opening-schedule": return [
      { kind: "opening-current" },
      { kind: "opening-global", stage: "current" },
      { kind: "opening-global", stage: "previous" },
      { kind: "opening-global", stage: "shape" },
      ...fri.flatMap((_, layer): readonly V17RoleSemantic[] => [
        { kind: "opening-fri", layer, stage: "current", mappingShard: 0 },
        { kind: "opening-fri", layer, stage: "current", mappingShard: 1 },
        { kind: "opening-fri", layer, stage: "shape" },
      ]),
    ];
    case "fri-fold-query": return Array.from(
      { length: source.queries }, (_, query) => ({ kind: "fri-fold-query", query }),
    );
    case "matrix-merkle": return matrices.flatMap((commitment, index) => {
      const matrix = V17_MATRIX_NAMES[index]!;
      return [
        ...Array.from({ length: commitment.leafShards }, (_, shard) =>
          ({ kind: "matrix-merkle-leaf" as const, matrix, shard,
            shards: commitment.leafShards })),
        ...Array.from({ length: commitment.verifierCuts.length + 1 }, (_, stage) =>
          ({ kind: "matrix-merkle-parent" as const, matrix, stage })),
      ];
    });
    case "fri-merkle": return fri.flatMap((commitment, layer) => [
      ...Array.from({ length: commitment.leafShards }, (_, shard) =>
        ({ kind: "fri-merkle-leaf" as const, layer, shard, shards: commitment.leafShards })),
      ...Array.from({ length: commitment.verifierCuts.length + 1 }, (_, stage) =>
        ({ kind: "fri-merkle-parent" as const, layer, stage })),
    ]);
    default: throw new Error(`v17 unknown semantic role family ${familyId}`);
  }
}

function familyKindForSemantic(semantic: V17RoleSemantic): V17RoleKind {
  switch (semantic.kind) {
    case "public-boundary-inverses":
    case "public-boundary-sum": return "public-boundary";
    case "opening-current":
    case "opening-global":
    case "opening-fri": return "opening-schedule";
    case "matrix-merkle-leaf":
    case "matrix-merkle-parent": return "matrix-merkle";
    case "fri-merkle-leaf":
    case "fri-merkle-parent": return "fri-merkle";
    default: return semantic.kind;
  }
}

const ROLE_SEMANTIC_SOURCE: V17RoleSemanticSource = {
  queries: V17_PRODUCTION_QUERY_COUNT,
  commitments: COMMITMENTS,
};

const RAW_ROLES = [
  { id: "settlement", kind: "settlement", ordinalSource: "singleton", proofCarrier: true,
    profiles: V17_PROFILES, description: "State, value, token, carrier, and selected-bank covenant." },
  { id: "ood-air", kind: "ood-air", ordinalSource: "singleton",
    proofCarrier: true, profiles: V17_PROFILES,
    description: "All 25 AIR residuals and the one whole quotient identity at the OOD point; no serialized partials." },
  { id: "batch-link-query", kind: "batch-link-query", ordinalSource: "input-index",
    proofCarrier: true, profiles: V17_PROFILES,
    description: "Protocol-4 width-197 degree-corrected batch link to FRI0 for one query." },
  { id: "public-boundary-inverses", kind: "public-boundary",
    ordinalSource: "singleton", proofCarrier: true, profiles: V17_PROFILES,
    description: "Canonical public-boundary inverse checks." },
  { id: "proof-header", kind: "proof-header", ordinalSource: "singleton",
    proofCarrier: true, profiles: V17_PROFILES, description: "Proof version, profile, protocol, and VK header." },
  { id: "edge-append", kind: "edge-append", ordinalSource: "singleton",
    proofCarrier: true, profiles: V17_PROFILES, description: "Public edge-history append." },
  { id: "sparse-nullifier", kind: "sparse-nullifier",
    ordinalSource: "generated-static", proofCarrier: true, profiles: V17_PROFILES,
    description: "Absence/used sparse-nullifier path halves." },
  { id: "public-boundary-sum", kind: "public-boundary",
    ordinalSource: "singleton", proofCarrier: true, profiles: V17_PROFILES,
    description: "Public-boundary claimed-sum closure." },
  { id: "transcript", kind: "transcript", ordinalSource: "generated-static",
    proofCarrier: true, profiles: V17_PROFILES, description: "One ordered Fiat-Shamir transcript." },
  { id: "query-schedule", kind: "query-schedule", ordinalSource: "singleton",
    proofCarrier: true, profiles: V17_PROFILES, description: "Collision-free transcript-derived query schedule." },
  { id: "opening-schedule", kind: "opening-schedule",
    ordinalSource: "generated-static", proofCarrier: true, profiles: V17_PROFILES,
    description: "Current, global, and nine FRI opening directories." },
  { id: "fri-fold-query", kind: "fri-fold-query", ordinalSource: "input-index",
    proofCarrier: true, profiles: V17_PROFILES, description: "All FRI folds and final polynomial for one query." },
  { id: "matrix-merkle", kind: "matrix-merkle",
    ordinalSource: "generated-static", proofCarrier: true, profiles: V17_PROFILES,
    description: "Generated mixed-geometry matrix authentication cuts." },
  { id: "fri-merkle", kind: "fri-merkle",
    ordinalSource: "generated-static", proofCarrier: true, profiles: V17_PROFILES,
    description: "Generated mixed-geometry FRI authentication cuts." },
] as const;

/**
 * The settlement covenant alone embeds the post-link bank digests. Every
 * verifier worker is compiled only from protocol-fixed data, so exact literal
 * function bodies may be moved to authenticated ROM without self-reference.
 */
const ROLES: readonly V17RoleFamilySpec[] = RAW_ROLES.map((role) => ({
  ...role,
  semanticInstances: deriveV17RoleSemanticInstances(role.id, ROLE_SEMANTIC_SOURCE),
  defineBodyIdentity: role.id === "settlement"
    ? "construction-bound" as const
    : "construction-independent" as const,
}));

const OWNER_BY_COMPLETENESS: Readonly<Record<number, string>> = {
  1: "settlement", 2: "settlement", 3: "settlement", 4: "settlement",
  5: "edge-append", 6: "edge-append", 7: "settlement", 8: "settlement",
  9: "sparse-nullifier", 10: "settlement", 11: "settlement",
  12: "ood-air", 13: "ood-air", 14: "ood-air",
  15: "ood-air", 16: "ood-air", 17: "ood-air",
  18: "ood-air", 19: "ood-air", 20: "ood-air",
  21: "ood-air", 22: "ood-air", 23: "proof-header",
  24: "batch-link-query", 25: "transcript", 26: "query-schedule",
  27: "matrix-merkle", 28: "ood-air", 29: "ood-air",
  30: "batch-link-query", 31: "fri-fold-query", 32: "proof-header",
  33: "settlement",
};

const DEPENDENCIES: Readonly<Record<number, readonly number[]>> = {
  1: [], 2: [1], 3: [1], 4: [3], 5: [4], 6: [5], 7: [1], 8: [1], 9: [3],
  10: [2], 11: [10], 12: [], 13: [12], 14: [12], 15: [14], 16: [15],
  17: [15], 18: [17], 19: [17], 20: [17], 21: [17], 22: [16, 19, 20, 21],
  23: [], 24: [23], 25: [23], 26: [25], 27: [26], 28: [13, 22, 25, 27],
  29: [28], 30: [29], 31: [30], 32: [23, 25, 26, 27],
  33: [10, 11, 22, 29, 31, 32],
};

const OBLIGATIONS: readonly V17ObligationSpec[] = V17_COMPLETENESS_IDS.map((id, index) => ({
  id,
  ownerRole: OWNER_BY_COMPLETENESS[index + 1]!,
  dependsOn: (DEPENDENCIES[index + 1] ?? []).map((dependency) =>
    `C${dependency}` as V17CompletenessId),
}));

export const V17_CONSTRUCTION_GRAPH: V17ConstructionGraph = {
  schema: "ShieldKit/V17ConstructionGraph/v1",
  version: V17_PROOF_VERSION,
  normativeSpec: {
    bytePolicy: {
      encoding: "utf-8",
      byteOrderMark: "forbidden",
      lineEndings: "lf",
      terminalNewline: "required",
      interpretation: "opaque-bytes-no-markdown-parsing",
      digest: "sha256-exact-bytes",
    },
    documents: [
      { id: "constitution", path: "RULES.md",
        sha256Hex: "0decee2d6ef156b14c85eeb8b2d4fee3d0074dac6fcebc2184101fbebf45668a" },
      { id: "privacy-membrane", path: "ZK-MEMBRANE.md",
        sha256Hex: "2e11b97f43114a7ab871176c3dc5069819146a5b5a6c85aacca04048c6d8fcad" },
      { id: "completeness-map", path: "COMPLETENESS.md",
        sha256Hex: "064f5d940a62787a3e39a782c41c07583dbbfdc72dd386d18e9ae44f68f20a66" },
    ],
  },
  foundation: {
    proofFamily: "transparent-circle-fri-stark",
    relationConstructionVersion: LOCAL_WORD_RELATION_CONSTRUCTION_VERSION,
    nativeHash: "sha256",
    traceField: "m31",
    challengeField: "qm31",
    classicalSoundnessFloorBits: 100,
    quantumClaim: "no-known-polynomial-time-quantum-break",
    relationLog: 18,
    functionDegreeLog: 19,
    sealedDegreeLog: 19,
    quotientDegreeLog: 20,
    evaluationLog: 24,
    friLogBlowup: 4,
    theta: { numerator: 181, denominator: 256 },
    queries: V17_PRODUCTION_QUERY_COUNT,
    maximumRoundGrindingBits: 26,
    roundGrinding: V17_PRODUCTION_ROUND_GRINDING,
    grindingNonce: {
      serializedBytes: 4,
      proofCodec: "u32be",
      transcriptEncoding: "u32le",
      transcriptDomain: "v17-theorem-round+pow",
      searchSpaceBits: 32,
      expectedHitsAtMaximumBits: 64,
      theoremSaltRestriction: "soundness-monotone-completeness-only",
    },
    oodValueCount: 98,
    degreeCorrectedBatchWidth: 197,
    finalLogDegree: 3,
    friFoldLogs: [2, 2, 2, 2, 2, 2, 2, 2, 1],
    friFoldChallengeCounts: [2, 2, 2, 2, 2, 2, 2, 2, 1],
    friChallengeDerivation: "independent-fiat-shamir",
    virtualIntermediate: "deterministic-uncommitted",
  },
  // Freshly derived from the frozen relation under the v17 mixed-Merkle
  // commitment language. The relation digests remain construction-independent;
  // the preprocessed roots deliberately differ from v16.
  verifierKeyDigests: [
    { profile: 0,
      status: "derived-v17",
      relationConstructionDigestHex: "fed4c84b07b9cd92e518cefcc137e7498110d3ed752716865b25ca8c175c458b",
      preprocessedRootHex: "5a264f2b23e9c88b84bbb3d47141e4f8e92ff2a2e388c6f28101bb6f3d5445ad" },
    { profile: 1,
      status: "derived-v17",
      relationConstructionDigestHex: "a4593456bb0a8dc3ad5df4594b0d0f0362095acd505d9856de658b12f02f7fdb",
      preprocessedRootHex: "85c1861717ec2d6bbe8997bf3f0e848216979f442ff2257ecdab8399d4a6dc66" },
    { profile: 2,
      status: "derived-v17",
      relationConstructionDigestHex: "2efd8a291ed1ddc7189360cf3fb873a58e0fc0eac07b6861eadce9ba1f0aab05",
      preprocessedRootHex: "112a6d31f2fbc8792f01efabc82c44ca5fe3d6c0decedcae5fc17f90e8147304" },
  ],
  proof: {
    version: V17_PROOF_VERSION,
    frames: PROOF_FRAMES,
    // V17 deliberately has no serialized AIR composition-partial bridge.
    dynamicTail: {
      id: "openingBodies",
      offsetBytes: FIXED_PREFIX_BYTES,
      alignmentBytes: 4,
      codec: "canonical-opening-bodies",
    },
  },
  transcript: [
    { id: "header", ordinal: 0, dependsOn: [],
      consumesSections: consumeSections("transcript-absorb",
        "magic", "proofVersion", "profile", "protocolId",
        "matrixRoot:preprocessed", "matrixRoot:original"),
      challenges: [] },
    { id: "air:logup", ordinal: 1, dependsOn: ["header"],
      consumesSections: consumeSections("named-round-pow", "roundNonce:air:logup"),
      challenges: ["interaction-challenges[27]"] },
    { id: "air:composition", ordinal: 2, dependsOn: ["air:logup"],
      consumesSections: [
        ...consumeSections("derived-snapshot", "interactionChallenges"),
        ...consumeSections("transcript-absorb", "publicInverses", "publicClaimedSum",
          "matrixRoot:interaction", "matrixRoot:interactionGlobal"),
        ...consumeSections("derived-snapshot", "interactionDigest"),
        ...consumeSections("named-round-pow", "roundNonce:air:composition"),
      ],
      challenges: ["constraint-alpha"] },
    { id: "air:ood", ordinal: 3, dependsOn: ["air:composition"],
      consumesSections: [
        ...consumeSections("derived-snapshot", "constraintAlpha", "compositionDigest"),
        ...consumeSections("transcript-absorb", "matrixRoot:quotientAndFriMask"),
        ...consumeSections("named-round-pow", "roundNonce:air:ood"),
      ], challenges: ["oods-point"] },
    { id: "fri:batch", ordinal: 4, dependsOn: ["air:ood"],
      consumesSections: [
        ...consumeSections("transcript-absorb", "oodValues"),
        ...consumeSections("named-round-pow", "roundNonce:fri:batch"),
      ], challenges: ["batch-beta"] },
    { id: "fri:fold:0", ordinal: 5, dependsOn: ["fri:batch"],
      consumesSections: [
        ...consumeSections("derived-snapshot", "batchBeta", "batchDigest"),
        ...consumeSections("transcript-absorb", "friRoot:0"),
        ...consumeSections("named-round-pow", "roundNonce:fri:fold:0"),
      ],
      challenges: ["fri-alpha:0:0", "fri-alpha:0:1"] },
    ...Array.from({ length: 8 }, (_, offset): V17TranscriptPhaseSpec => {
      const index = offset + 1;
      return {
        id: `fri:fold:${index}`,
        ordinal: index + 5,
        dependsOn: [`fri:fold:${index - 1}`],
        consumesSections: [
          ...consumeSections("derived-snapshot", `friAlpha:${index - 1}:0`,
            `friAlpha:${index - 1}:1`),
          ...consumeSections("transcript-absorb", `friRoot:${index}`),
          ...consumeSections("named-round-pow", `roundNonce:fri:fold:${index}`),
        ],
        challenges: index < 8
          ? [`fri-alpha:${index}:0`, `fri-alpha:${index}:1`]
          : ["fri-alpha:8:0"],
      };
    }),
    { id: "fri:query", ordinal: 14, dependsOn: ["fri:fold:8"],
      consumesSections: [
        ...consumeSections("derived-snapshot", "friAlpha:8:0", "friMidDigest", "friRootsDigest"),
        ...consumeSections("transcript-absorb", "finalCoefficients"),
        ...consumeSections("named-round-pow", "roundNonce:fri:query"),
      ], challenges: [`query-orbits[${V17_PRODUCTION_QUERY_COUNT}]`] },
    { id: "openings", ordinal: 15, dependsOn: ["fri:query"],
      consumesSections: [
        ...consumeSections("derived-snapshot", "queryDigest", "queries", "currentIndices",
          "currentRanks", "globalCurrentRanks", "globalPreviousRanks", "friCosetRanks"),
        ...consumeSections("terminal-strict-codec", ...TERMINAL_STRICT_CODEC_FRAME_IDS),
      ], challenges: [] },
  ],
  commitments: COMMITMENTS,
  roles: ROLES,
  obligations: OBLIGATIONS,
  allocation: {
    strategy: "base-plus-elastic-prefix",
    proofPartition: "one-contiguous-copy",
    densityCredit: "max-profile-residual-proof-bytes",
    baseEndpoint: "sum-max-profile-residual-proof-bytes",
    closure: "coordinatewise-monotone-profile-envelope",
    closureGenesis: "canonical-bootstrap-affine-allocation",
    closureJoin: "profile-opcost-max-required-max-capacity-min",
    closureTerminal: "explicit-no-change-replay",
    closureTrace: "domain-separated-sha256-chain",
    elasticNormalization: "cumulative-floor-prefix-union",
    elasticScaleUnits: V17_ELASTIC_PREFIX_SCALE,
    maximumProofBytes: V17_MAXIMUM_CANONICAL_PROOF_BYTES,
    minimumProofBytesPerRole: 256,
    capacityLimitBytes: 10_000,
    capacityDerivation: "canonical-proof-push-plus-linked-redeem-push",
    slackDistribution: "capacity-proportional-hamilton-role-order",
    metadataEncoding: "base19-elastic12-disabled-sequence",
  },
  rom: {
    pageFormat: "p2sh32-authenticated-function-page-v1",
    payloadFormat: "skr1-directory-and-exact-bodies-v1",
    bodyAccess: "sibling-input-bytecode-canonical-slice",
    eligibility: "construction-independent-op-define-bodies",
    bankIdentity: "profile-seeded-bch-native-sha256-fold-verifier-workers-and-rom-pages-excluding-settlement-v1",
    deduplication: "exact-byte-equality",
    promotion: "strict-positive-saving-in-every-profile",
    qualificationMeasurement: "post-link-all-profile-independent-bchn",
    functionIdentifiers:
      "minimal-positive-unsigned-be-earliest-static-occurrence-anchor",
    packing: "minimum-pages-then-semantic-anchor",
    placement: "after-proof-workers",
    limits: {
      scriptBytes: 10_000,
      elementBytes: 10_000,
      stackItems: 1_000,
      controlDepth: 100,
      functionIdentifierBytes: 7,
      opcostPerInputByte: 800,
      consensusTransactionBytes: 1_000_000,
    },
  },
};

function assertUnique(label: string, values: readonly string[]): void {
  const seen = new Set<string>();
  for (const value of values) {
    if (seen.has(value)) throw new Error(`v17 duplicate ${label}: ${value}`);
    seen.add(value);
  }
}

function assertHex32(label: string, value: string): void {
  if (!/^[0-9a-f]{64}$/.test(value)) throw new Error(`v17 ${label} must be lowercase hex32`);
}

function assertAcyclic(
  label: string,
  ids: readonly string[],
  dependencies: (id: string) => readonly string[],
): void {
  const known = new Set(ids);
  const visiting = new Set<string>();
  const visited = new Set<string>();
  const visit = (id: string): void => {
    if (visited.has(id)) return;
    if (visiting.has(id)) throw new Error(`v17 ${label} cycle at ${id}`);
    visiting.add(id);
    for (const dependency of dependencies(id)) {
      if (!known.has(dependency)) throw new Error(`v17 unknown ${label} dependency ${id} -> ${dependency}`);
      visit(dependency);
    }
    visiting.delete(id);
    visited.add(id);
  };
  ids.forEach(visit);
}

/** Validate structural completeness only; this is not a soundness theorem. */
export function validateV17ConstructionGraph(graph: V17ConstructionGraph): V17ConstructionGraph {
  const foundation = graph.foundation;
  const bytePolicy = graph.normativeSpec?.bytePolicy;
  if (bytePolicy?.encoding !== "utf-8" || bytePolicy.byteOrderMark !== "forbidden" ||
    bytePolicy.lineEndings !== "lf" || bytePolicy.terminalNewline !== "required" ||
    bytePolicy.interpretation !== "opaque-bytes-no-markdown-parsing" ||
    bytePolicy.digest !== "sha256-exact-bytes") {
    throw new Error("v17 normative document byte policy");
  }
  if (graph.normativeSpec.documents.length !== V17_NORMATIVE_DOCUMENT_LAYOUT.length) {
    throw new Error("v17 normative document inventory");
  }
  assertUnique("normative document id", graph.normativeSpec.documents.map(({ id }) => id));
  assertUnique("normative document path", graph.normativeSpec.documents.map(({ path }) => path));
  for (const [index, expected] of V17_NORMATIVE_DOCUMENT_LAYOUT.entries()) {
    const actual = graph.normativeSpec.documents[index];
    if (actual?.id !== expected.id || actual.path !== expected.path) {
      throw new Error(`v17 normative document order at ${expected.id}`);
    }
    assertHex32(`normative document hash ${expected.id}`, actual.sha256Hex);
  }
  if (graph.schema !== "ShieldKit/V17ConstructionGraph/v1" || graph.version !== 17 ||
    graph.proof.version !== 17 ||
    foundation.proofFamily !== "transparent-circle-fri-stark" ||
    foundation.relationConstructionVersion !== LOCAL_WORD_RELATION_CONSTRUCTION_VERSION ||
    foundation.nativeHash !== "sha256" || foundation.traceField !== "m31" ||
    foundation.challengeField !== "qm31" || foundation.classicalSoundnessFloorBits !== 100 ||
    foundation.quantumClaim !== "no-known-polynomial-time-quantum-break" ||
    foundation.relationLog !== 18 || foundation.functionDegreeLog !== 19 ||
    foundation.sealedDegreeLog !== 19 || foundation.quotientDegreeLog !== 20 ||
    foundation.evaluationLog !== 24 || foundation.friLogBlowup !== 4 ||
    foundation.evaluationLog - foundation.quotientDegreeLog !== foundation.friLogBlowup ||
    foundation.theta.numerator !== 181 || foundation.theta.denominator !== 256 ||
    foundation.queries !== V17_PRODUCTION_QUERY_COUNT ||
    foundation.maximumRoundGrindingBits !== 26 ||
    foundation.finalLogDegree !== 3 || foundation.oodValueCount !== 98 ||
    foundation.degreeCorrectedBatchWidth !== 197 ||
    foundation.friFoldLogs.join(",") !== "2,2,2,2,2,2,2,2,1" ||
    foundation.friFoldChallengeCounts.join(",") !== "2,2,2,2,2,2,2,2,1" ||
    foundation.friChallengeDerivation !== "independent-fiat-shamir" ||
    foundation.virtualIntermediate !== "deterministic-uncommitted" ||
    foundation.friFoldLogs.reduce((sum, value) => sum + value, 0) !==
      foundation.evaluationLog - foundation.friLogBlowup - foundation.finalLogDegree ||
    foundation.roundGrinding.length !== V17_PRODUCTION_ROUND_GRINDING.length ||
    foundation.roundGrinding.some((round, index) =>
      round.id !== V17_PRODUCTION_ROUND_GRINDING[index]?.id ||
      round.bits !== V17_PRODUCTION_ROUND_GRINDING[index]?.bits) ||
    Math.max(...foundation.roundGrinding.map(({ bits }) => bits)) !==
      foundation.maximumRoundGrindingBits ||
    foundation.grindingNonce.serializedBytes !== 4 ||
    foundation.grindingNonce.proofCodec !== "u32be" ||
    foundation.grindingNonce.transcriptEncoding !== "u32le" ||
    foundation.grindingNonce.transcriptDomain !== "v17-theorem-round+pow" ||
    foundation.grindingNonce.searchSpaceBits !== 32 ||
    foundation.grindingNonce.expectedHitsAtMaximumBits !== 64 ||
    foundation.grindingNonce.expectedHitsAtMaximumBits !==
      2 ** (foundation.grindingNonce.searchSpaceBits - foundation.maximumRoundGrindingBits) ||
    foundation.grindingNonce.theoremSaltRestriction !==
      "soundness-monotone-completeness-only" ||
    graph.allocation.strategy !== "base-plus-elastic-prefix" ||
    graph.allocation.proofPartition !== "one-contiguous-copy" ||
    graph.allocation.densityCredit !== "max-profile-residual-proof-bytes" ||
    graph.allocation.baseEndpoint !== "sum-max-profile-residual-proof-bytes" ||
    graph.allocation.closure !== "coordinatewise-monotone-profile-envelope" ||
    graph.allocation.closureGenesis !== "canonical-bootstrap-affine-allocation" ||
    graph.allocation.closureJoin !== "profile-opcost-max-required-max-capacity-min" ||
    graph.allocation.closureTerminal !== "explicit-no-change-replay" ||
    graph.allocation.closureTrace !== "domain-separated-sha256-chain" ||
    graph.allocation.elasticNormalization !== "cumulative-floor-prefix-union" ||
    graph.allocation.elasticScaleUnits !== V17_ELASTIC_PREFIX_SCALE ||
    graph.allocation.maximumProofBytes !== V17_MAXIMUM_CANONICAL_PROOF_BYTES ||
    graph.allocation.minimumProofBytesPerRole !== 256 ||
    graph.allocation.capacityLimitBytes !== 10_000 ||
    graph.allocation.capacityDerivation !==
      "canonical-proof-push-plus-linked-redeem-push" ||
    graph.allocation.slackDistribution !== "capacity-proportional-hamilton-role-order" ||
    graph.allocation.metadataEncoding !== "base19-elastic12-disabled-sequence" ||
    graph.rom.pageFormat !== "p2sh32-authenticated-function-page-v1" ||
    graph.rom.payloadFormat !== "skr1-directory-and-exact-bodies-v1" ||
    graph.rom.bodyAccess !== "sibling-input-bytecode-canonical-slice" ||
    graph.rom.eligibility !== "construction-independent-op-define-bodies" ||
    graph.rom.bankIdentity !==
      "profile-seeded-bch-native-sha256-fold-verifier-workers-and-rom-pages-excluding-settlement-v1" ||
    graph.rom.deduplication !== "exact-byte-equality" ||
    graph.rom.promotion !== "strict-positive-saving-in-every-profile" ||
    graph.rom.qualificationMeasurement !== "post-link-all-profile-independent-bchn" ||
    graph.rom.functionIdentifiers !==
      "minimal-positive-unsigned-be-earliest-static-occurrence-anchor" ||
    graph.rom.packing !== "minimum-pages-then-semantic-anchor" ||
    graph.rom.placement !== "after-proof-workers" ||
    graph.rom.limits.scriptBytes !== 10_000 || graph.rom.limits.elementBytes !== 10_000 ||
    graph.rom.limits.stackItems !== 1_000 || graph.rom.limits.controlDepth !== 100 ||
    graph.rom.limits.functionIdentifierBytes !== 7 ||
    graph.rom.limits.opcostPerInputByte !== 800 ||
    graph.rom.limits.consensusTransactionBytes !== 1_000_000) {
    throw new Error("v17 construction foundation");
  }

  if (graph.verifierKeyDigests.length !== V17_PROFILES.length ||
    graph.verifierKeyDigests.some((key, index) => key.profile !== V17_PROFILES[index])) {
    throw new Error("v17 verifier-key profile order");
  }
  for (const key of graph.verifierKeyDigests) {
    if (key.status !== "inherited-v16-unqualified" && key.status !== "derived-v17") {
      throw new Error("v17 verifier-key status");
    }
    assertHex32("relation construction digest", key.relationConstructionDigestHex);
    assertHex32("preprocessed root", key.preprocessedRootHex);
  }

  assertUnique("proof frame id", graph.proof.frames.map((frame) => frame.id));
  let expectedOffset = 0;
  for (const frame of graph.proof.frames) {
    if (!Number.isSafeInteger(frame.offsetBytes) || frame.offsetBytes !== expectedOffset ||
      !Number.isSafeInteger(frame.itemBytes) || frame.itemBytes < 1 ||
      !Number.isSafeInteger(frame.itemCount) || frame.itemCount < 1) {
      throw new Error(`v17 proof frame gap or width at ${frame.id}`);
    }
    expectedOffset += frame.itemBytes * frame.itemCount;
  }
  if (graph.proof.dynamicTail.id.length === 0 || graph.proof.dynamicTail.offsetBytes !== expectedOffset ||
    !Number.isSafeInteger(graph.proof.dynamicTail.alignmentBytes) ||
    graph.proof.dynamicTail.alignmentBytes < 1) {
    throw new Error("v17 proof dynamic tail");
  }

  const exactFrame = (id: string, itemBytes: number, itemCount: number, codec: V17ProofFrameSpec["codec"]): boolean => {
    const frame = graph.proof.frames.find((candidate) => candidate.id === id);
    return frame?.itemBytes === itemBytes && frame.itemCount === itemCount && frame.codec === codec;
  };
  if (!exactFrame("oodValues", 16, 98, "qm31") ||
    !exactFrame("queries", 4, V17_PRODUCTION_QUERY_COUNT, "u32be") ||
    !exactFrame("currentIndices", 4, V17_PRODUCTION_QUERY_COUNT, "u32be") ||
    !exactFrame("friCosetRanks", 1, 9 * V17_PRODUCTION_QUERY_COUNT, "u8") ||
    FRI_CHALLENGE_FRAME_IDS.some((id) => !exactFrame(id, 16, 1, "qm31")) ||
    foundation.roundGrinding.some(({ id }) =>
      !exactFrame(`roundNonce:${id}`, 4, 1, "u32be"))) {
    throw new Error("v17 production proof frame geometry");
  }

  const sectionIds = [...graph.proof.frames.map((frame) => frame.id), graph.proof.dynamicTail.id];
  assertUnique("proof section id", sectionIds);
  const phaseIds = graph.transcript.map((phase) => phase.id);
  assertUnique("transcript phase id", phaseIds);
  const expectedPhaseIds = [
    "header",
    ...V17_PRODUCTION_ROUND_GRINDING.map(({ id }) => id),
    "openings",
  ];
  if (phaseIds.join("|") !== expectedPhaseIds.join("|") ||
    V17_PRODUCTION_ROUND_GRINDING.some(({ id }) =>
      !graph.transcript.find((phase) => phase.id === id)?.consumesSections.some(
        (section) => section.id === `roundNonce:${id}` && section.mode === "named-round-pow"))) {
    throw new Error("v17 production transcript schedule");
  }
  const headerPhase = graph.transcript.find(({ id }) => id === "header")!;
  const compositionPhase = graph.transcript.find(({ id }) => id === "air:composition")!;
  const openingsPhase = graph.transcript.find(({ id }) => id === "openings")!;
  const compositionOrder = compositionPhase.consumesSections.map(({ id }) => id);
  const openingsOrder = openingsPhase.consumesSections.map(({ id }) => id);
  const strictlyOrdered = (haystack: readonly string[], needles: readonly string[]): boolean =>
    needles.every((needle, index) => index === 0 ||
      haystack.indexOf(needles[index - 1]!) < haystack.indexOf(needle));
  if (["publicInverses", "publicClaimedSum", "totalLength"].some((section) =>
    headerPhase.consumesSections.some(({ id }) => id === section)) ||
    !["publicInverses", "publicClaimedSum"].every((section) =>
      compositionPhase.consumesSections.some(({ id, mode }) =>
        id === section && mode === "transcript-absorb")) ||
    !openingsPhase.consumesSections.some(({ id, mode }) =>
      id === "totalLength" && mode === "terminal-strict-codec") ||
    !strictlyOrdered(compositionOrder, ["interactionChallenges", "publicInverses",
      "publicClaimedSum", "matrixRoot:interaction", "matrixRoot:interactionGlobal",
      "interactionDigest", "roundNonce:air:composition"]) ||
    !strictlyOrdered(openingsOrder, ["queryDigest", "queries", "currentIndices",
      "totalLength"])) {
    throw new Error("v17 transcript causal section placement");
  }
  assertAcyclic("transcript", phaseIds,
    (id) => graph.transcript.find((phase) => phase.id === id)!.dependsOn);
  const consumedSections: string[] = [];
  const challenges: string[] = [];
  for (const [index, phase] of graph.transcript.entries()) {
    if (phase.ordinal !== index) throw new Error(`v17 transcript ordinal ${phase.id}`);
    for (const dependency of phase.dependsOn) {
      const dependencyPhase = graph.transcript.find((candidate) => candidate.id === dependency)!;
      if (dependencyPhase.ordinal >= phase.ordinal) {
        throw new Error(`v17 transcript dependency order ${phase.id} -> ${dependency}`);
      }
    }
    for (const section of phase.consumesSections) {
      if (!sectionIds.includes(section.id)) {
        throw new Error(`v17 transcript unknown section ${section.id}`);
      }
      const expectedMode: V17TranscriptSectionMode =
        section.id.startsWith("roundNonce:") ? "named-round-pow"
          : (DERIVED_SNAPSHOT_FRAME_IDS as readonly string[]).includes(section.id)
            ? "derived-snapshot"
            : (TERMINAL_STRICT_CODEC_FRAME_IDS as readonly string[]).includes(section.id)
              ? "terminal-strict-codec"
              : "transcript-absorb";
      if (section.mode !== expectedMode) {
        throw new Error(`v17 transcript section mode ${section.id}`);
      }
      if (section.mode === "terminal-strict-codec" &&
        graph.transcript.slice(index).some(({ challenges: later }) => later.length > 0)) {
        throw new Error(`v17 transcript terminal section before challenge ${section.id}`);
      }
      consumedSections.push(section.id);
    }
    challenges.push(...phase.challenges);
  }
  assertUnique("transcript-consumed section", consumedSections);
  assertUnique("transcript challenge", challenges);
  if (consumedSections.length !== sectionIds.length ||
    sectionIds.some((section) => !consumedSections.includes(section))) {
    throw new Error("v17 transcript section coverage");
  }

  assertUnique("commitment id", graph.commitments.map((commitment) => commitment.id));
  assertUnique("commitment hash label", graph.commitments.map((commitment) => commitment.hashLabel));
  for (const commitment of graph.commitments) {
    const consumedLog = commitment.arities.reduce((sum, arity) => sum + (arity === 4 ? 2 : 1), 0);
    if (!Number.isInteger(commitment.domainLog) || commitment.domainLog < 1 ||
      consumedLog !== commitment.domainLog || commitment.leafCodec.length === 0 ||
      !Number.isSafeInteger(commitment.rowBytes) || commitment.rowBytes < 1 ||
      !/^[A-Za-z0-9:_-]+$/.test(commitment.hashLabel) ||
      (commitment.leafShards !== 1 && commitment.leafShards !== 2) ||
      (commitment.arities[0] === 4) !== (commitment.leafShards === 2) ||
      commitment.verifierCuts.some((bits, index) => !Number.isInteger(bits) || bits <= 0 ||
        bits >= commitment.domainLog || (index > 0 && commitment.verifierCuts[index - 1]! >= bits))) {
      throw new Error(`v17 commitment geometry ${commitment.id}`);
    }
  }

  const roleIds = graph.roles.map((role) => role.id);
  assertUnique("role family id", roleIds);
  if (graph.roles[0]?.kind !== "settlement" ||
    graph.roles[0].semanticInstances.length !== 1) {
    throw new Error("v17 settlement must be first singleton role");
  }
  if (graph.roles[0].defineBodyIdentity !== "construction-bound" ||
    graph.roles.slice(1).some(({ defineBodyIdentity }) =>
      defineBodyIdentity !== "construction-independent")) {
    throw new Error("v17 role construction-identity boundary");
  }
  const oodAir = graph.roles.find(({ id }) => id === "ood-air");
  const batchLinks = graph.roles.find(({ id }) => id === "batch-link-query");
  const openingSchedules = graph.roles.find(({ id }) => id === "opening-schedule");
  const matrixMerkle = graph.roles.find(({ id }) => id === "matrix-merkle");
  const friMerkle = graph.roles.find(({ id }) => id === "fri-merkle");
  const matrixMerkleCount = graph.commitments.filter(({ id }) => id.startsWith("matrix:"))
    .reduce((sum, commitment) => sum + commitment.leafShards + commitment.verifierCuts.length + 1, 0);
  const friCommitments = graph.commitments.filter(({ id }) => id.startsWith("fri:"));
  const friMerkleCount = friCommitments.reduce((sum, commitment) =>
    sum + commitment.leafShards + commitment.verifierCuts.length + 1, 0);
  if (graph.roles.some(({ id, kind }) => id === "air-algebra-query" ||
    (kind as string) === "air-algebra-query") ||
    oodAir?.kind !== "ood-air" || oodAir.semanticInstances.length !== 1 ||
    oodAir.ordinalSource !== "singleton" ||
    batchLinks?.kind !== "batch-link-query" ||
    batchLinks.semanticInstances.length !== foundation.queries ||
    batchLinks.ordinalSource !== "input-index" ||
    openingSchedules?.semanticInstances.length !== 4 + 3 * friCommitments.length ||
    matrixMerkle?.semanticInstances.length !== matrixMerkleCount ||
    friMerkle?.semanticInstances.length !== friMerkleCount) {
    throw new Error("v17 OOD AIR / batch-link role model");
  }
  for (const role of graph.roles) {
    if (role.semanticInstances.length < 1 || role.description.length === 0 ||
      (role.semanticInstances.length === 1) !== (role.ordinalSource === "singleton") ||
      role.semanticInstances.some((semantic) => familyKindForSemantic(semantic) !== role.kind) ||
      role.profiles.length !== V17_PROFILES.length ||
      role.profiles.some((profile, index) => profile !== V17_PROFILES[index])) {
      throw new Error(`v17 role family ${role.id}`);
    }
    const expectedSemantics = deriveV17RoleSemanticInstances(role.id, {
      queries: foundation.queries,
      commitments: graph.commitments,
    });
    if (canonicalV17Json(role.semanticInstances) !== canonicalV17Json(expectedSemantics)) {
      throw new Error(`v17 role semantic instances ${role.id}`);
    }
  }

  const obligationIds = graph.obligations.map((obligation) => obligation.id);
  assertUnique("completeness id", obligationIds);
  if (obligationIds.length !== V17_COMPLETENESS_IDS.length ||
    V17_COMPLETENESS_IDS.some((id) => !obligationIds.includes(id))) {
    throw new Error("v17 C1-C33 coverage");
  }
  for (const obligation of graph.obligations) {
    if (!roleIds.includes(obligation.ownerRole)) {
      throw new Error(`v17 unknown obligation owner ${obligation.id} -> ${obligation.ownerRole}`);
    }
  }
  assertAcyclic("obligation", obligationIds,
    (id) => graph.obligations.find((obligation) => obligation.id === id)!.dependsOn);
  return graph;
}

type CanonicalJson = null | boolean | number | string | CanonicalJson[] |
  { readonly [key: string]: CanonicalJson };

function canonicalize(value: unknown, ancestors: ReadonlySet<object>): CanonicalJson {
  if (value === null || typeof value === "boolean" || typeof value === "string") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value) || Object.is(value, -0)) throw new Error("v17 noncanonical number");
    return value;
  }
  if (typeof value !== "object") throw new Error(`v17 unsupported canonical value ${typeof value}`);
  if (ancestors.has(value)) throw new Error("v17 canonical serialization cycle");
  const nextAncestors = new Set(ancestors).add(value);
  if (Array.isArray(value)) return value.map((item) => canonicalize(item, nextAncestors));
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new Error("v17 canonical serialization requires plain objects");
  }
  return Object.fromEntries(Object.keys(value as object).sort().map((key) => {
    const item = (value as Record<string, unknown>)[key];
    if (item === undefined) throw new Error(`v17 undefined canonical field ${key}`);
    return [key, canonicalize(item, nextAncestors)];
  }));
}

export function canonicalV17Json(value: unknown): string {
  return JSON.stringify(canonicalize(value, new Set()));
}

function u32be(value: number): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff_ffff) {
    throw new Error("v17 u32");
  }
  const bytes = new Uint8Array(4);
  new DataView(bytes.buffer).setUint32(0, value, false);
  return bytes;
}

function u64be(value: bigint): Uint8Array {
  if (value < 0n || value > 0xffff_ffff_ffff_ffffn) throw new Error("v17 u64");
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigUint64(0, value, false);
  return bytes;
}

function concat(...parts: readonly Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function encodeFramed(parts: readonly Uint8Array[]): Uint8Array {
  return concat(...parts.flatMap((part) => [u32be(part.length), part]));
}

function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function fromHex32(label: string, hex: string): Uint8Array {
  assertHex32(label, hex);
  return new Uint8Array(Buffer.from(hex, "hex"));
}

function domainHash(domain: string, payload: Uint8Array): string {
  return sha256Hex(encodeFramed([new TextEncoder().encode(domain), payload]));
}

export function v17ProtocolIdHex(graph: V17ConstructionGraph = V17_CONSTRUCTION_GRAPH): string {
  validateV17ConstructionGraph(graph);
  return domainHash("ShieldKit/V17ProtocolId/v1", new TextEncoder().encode(canonicalV17Json(graph)));
}

export type V17BankRoleBinding = V17BankIdentityRole;

/** Hash only consensus-observable ordered bank fields; role names are metadata. */
export function v17BankDigestHex(args: {
  readonly protocolIdHex: string;
  readonly profile: V17Profile;
  readonly roles: readonly V17BankRoleBinding[];
}): string {
  fromHex32("protocol id", args.protocolIdHex);
  if (!V17_PROFILES.includes(args.profile) || args.roles.length < 1) {
    throw new Error("v17 bank digest shape");
  }
  // The profile seeds this exact miner-run fold; v17ConstructionIdHex binds
  // the resulting three rows to the protocol. There is no parallel host-only
  // bank commitment language.
  return v17BankDigestHexFromRoles(args.profile, args.roles);
}

export function v17ConstructionIdHex(args: {
  readonly protocolIdHex: string;
  readonly bankDigests: readonly [string, string, string];
}): string {
  const protocolId = fromHex32("protocol id", args.protocolIdHex);
  const banks = args.bankDigests.map((digest, profile) =>
    encodeFramed([Uint8Array.of(profile), fromHex32(`profile ${profile} bank digest`, digest)]));
  return domainHash("ShieldKit/V17ConstructionId/v1", encodeFramed([protocolId, ...banks]));
}

export function buildV17VerifierPlan(
  graph: V17ConstructionGraph = V17_CONSTRUCTION_GRAPH,
): V17VerifierPlan {
  validateV17ConstructionGraph(graph);
  const obligationOwners = new Map<string, V17CompletenessId[]>();
  for (const obligation of graph.obligations) {
    const owned = obligationOwners.get(obligation.ownerRole) ?? [];
    owned.push(obligation.id);
    obligationOwners.set(obligation.ownerRole, owned);
  }
  let logicalInputIndex = 0;
  const roles = graph.roles.flatMap((family): readonly V17ExpandedRole[] =>
    family.semanticInstances.map((semantic, ordinal) => ({
      logicalInputIndex: logicalInputIndex++,
      id: family.semanticInstances.length === 1 ? family.id : `${family.id}:${ordinal}`,
      familyId: family.id,
      kind: family.kind,
      semantic,
      ordinal,
      ordinalSource: family.ordinalSource,
      proofCarrier: family.proofCarrier,
      defineBodyIdentity: family.defineBodyIdentity,
      profiles: family.profiles,
      obligations: obligationOwners.get(family.id) ?? [],
    })));
  return {
    schema: "ShieldKit/V17VerifierPlan/v1",
    protocolIdHex: v17ProtocolIdHex(graph),
    roleFamilies: graph.roles,
    roles,
    allocation: {
      status: "unmeasured",
      strategy: graph.allocation.strategy,
      densityCredit: graph.allocation.densityCredit,
      baseEndpoint: graph.allocation.baseEndpoint,
      closure: graph.allocation.closure,
      closureGenesis: graph.allocation.closureGenesis,
      closureJoin: graph.allocation.closureJoin,
      closureTerminal: graph.allocation.closureTerminal,
      closureTrace: graph.allocation.closureTrace,
      elasticNormalization: graph.allocation.elasticNormalization,
      elasticScaleUnits: graph.allocation.elasticScaleUnits,
      minimumProofBytes: null,
      maximumProofBytes: graph.allocation.maximumProofBytes,
      minimumProofBytesPerRole: graph.allocation.minimumProofBytesPerRole,
      capacityLimitBytes: graph.allocation.capacityLimitBytes,
      capacityDerivation: graph.allocation.capacityDerivation,
      slackDistribution: graph.allocation.slackDistribution,
      metadataEncoding: graph.allocation.metadataEncoding,
      proofRoleCount: roles.filter((role) => role.proofCarrier).length,
      assignments: [],
    },
    rom: {
      status: "unmeasured",
      pageFormat: graph.rom.pageFormat,
      payloadFormat: graph.rom.payloadFormat,
      bodyAccess: graph.rom.bodyAccess,
      eligibility: graph.rom.eligibility,
      bankIdentity: graph.rom.bankIdentity,
      deduplication: graph.rom.deduplication,
      promotion: graph.rom.promotion,
      qualificationMeasurement: graph.rom.qualificationMeasurement,
      functionIdentifiers: graph.rom.functionIdentifiers,
      packing: graph.rom.packing,
      placement: graph.rom.placement,
      limits: graph.rom.limits,
      pages: [],
    },
  };
}

export function createPendingV17Qualification(
  protocolIdHex = v17ProtocolIdHex(),
): V17QualificationStatus {
  assertHex32("protocol id", protocolIdHex);
  const gates = Object.fromEntries(V17_QUALIFICATION_GATE_IDS.map((id) => [id, {
    status: "pending" as const,
    reason: id === "soundness-reduction"
      ? "The exact reduction is fail-closed until OOD, batch-link, grouped-FRI, and mixed-Merkle product correspondences pass."
      : "No identity-bound v17 evidence has been recorded.",
  }])) as Record<V17QualificationGateId, V17QualificationGateState>;
  return {
    schema: "ShieldKit/V17QualificationStatus/v1",
    protocolIdHex,
    constructionIdHex: null,
    overall: "incomplete",
    gates,
    unresolved: [
      "No final identity-bound qualification receipt is embedded in generated source; run the fresh all-profile qualifier for current evidence.",
    ],
  };
}

export function deriveV17QualificationOverall(
  status: Omit<V17QualificationStatus, "overall">,
): V17QualificationStatus["overall"] {
  if (status.constructionIdHex === null ||
    Object.values(status.gates).some((gate) => gate.status === "pending")) return "incomplete";
  if (status.unresolved.length > 0 ||
    Object.values(status.gates).some((gate) => gate.status === "blocked")) return "blocked";
  return "qualified";
}

export function assertV17Qualified(status: V17QualificationStatus): void {
  assertHex32("qualification protocol id", status.protocolIdHex);
  if (status.constructionIdHex !== null) assertHex32("qualification construction id", status.constructionIdHex);
  for (const id of V17_QUALIFICATION_GATE_IDS) {
    const gate = status.gates[id];
    if (gate === undefined) throw new Error(`v17 missing qualification gate ${id}`);
    if (gate.status === "passed") {
      assertHex32(`qualification evidence ${id}`, gate.evidence.sha256Hex);
      if (gate.evidence.summary.length === 0) throw new Error(`v17 empty qualification evidence ${id}`);
    } else if (gate.reason.length === 0) {
      throw new Error(`v17 empty qualification reason ${id}`);
    }
  }
  const { overall: _ignored, ...withoutOverall } = status;
  const derived = deriveV17QualificationOverall(withoutOverall);
  if (status.overall !== derived || derived !== "qualified") {
    throw new Error(`v17 qualification is ${derived}, not qualified`);
  }
}

validateV17ConstructionGraph(V17_CONSTRUCTION_GRAPH);

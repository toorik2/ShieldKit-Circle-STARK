import { createHash } from "node:crypto";
import {
  V17_MAX_FUNCTION_ID_BYTES,
  V17_MAX_SCRIPT_BYTES,
  v17CompactUintBytes,
} from "../chain/v17-code-rom.ts";
import {
  V17_CONSENSUS_TX_BYTES,
  V17_INPUT_FIXED_DENSITY_BYTES,
  V17_OPCOST_PER_DENSITY_BYTE,
} from "./v17-linker.ts";
import {
  V17_PROFILES,
  canonicalV17Json,
  type V17Profile,
} from "./v17-graph.ts";
import { LOCAL_WORD_BATCH_LEADER_ROLE_ID } from
  "../chain/local-word-proof-carriers.ts";
import { V17_BATCH_LEADER_CELL_BYTES } from
  "../backends/circle/v17-batch-leader-cell.ts";

export const V17_ROM_PLACEMENT_INPUT_SCHEMA =
  "ShieldKit/V17RomPlacementOptimizerInput/v1" as const;
export const V17_ROM_PLACEMENT_CERTIFICATE_SCHEMA =
  "ShieldKit/V17RomPlacementCertificate/v1" as const;

const MAX_EXACTLY_ENUMERATED_CANDIDATES = 1_000_000;

type Hex32 = string;

export type V17RomPlacementDecision = "inline" | "rom";

export type V17RomPlacementPage = {
  /** Stable logical identity. Removing another page never silently renames it. */
  readonly pageId: string;
  readonly payloadSha256Hex: Hex32;
  readonly payloadBytes: number;
  readonly bodyClasses: readonly {
    readonly bodySha256Hex: Hex32;
    readonly bodyBytes: number;
  }[];
};

export type V17RomPlacementOccurrence = {
  readonly profile: V17Profile;
  readonly roleId: string;
  /** Static OP_DEFINE census path, e.g. `3` or `3/1`. */
  readonly path: string;
  readonly functionIdHex: string;
  readonly bodySha256Hex: Hex32;
  readonly bodyBytes: number;
  /** The fixed logical page containing this exact body class. */
  readonly pageId: string;
};

export type V17RomPlacement = Pick<
  V17RomPlacementOccurrence,
  "profile" | "roleId" | "path" | "bodySha256Hex"
> & {
  readonly placement: V17RomPlacementDecision;
};

export type V17ExactRoleEnvelope = {
  readonly logicalInputIndex: number;
  readonly roleId: string;
  readonly proofCarrierBytes: number;
  readonly redeemBytes: number;
  readonly unlockingBytes: number;
  readonly redeemSha256Hex: Hex32;
  readonly unlockingSha256Hex: Hex32;
  readonly maximumOperationCost: number;
  readonly operationCostEngine: "bchn-v29.0.0" | "independent-bchn-conformant";
  readonly operationCostEvidenceSha256Hex: Hex32;
};

export type V17ExactRomPageEnvelope = {
  readonly pageId: string;
  readonly pageIndex: number;
  readonly inputIndex: number;
  readonly outputIndex: number;
  readonly payloadBytes: number;
  readonly payloadSha256Hex: Hex32;
  readonly redeemBytes: number;
  readonly lockingBytes: number;
  readonly unlockingBytes: number;
  readonly redeemSha256Hex: Hex32;
  readonly lockingSha256Hex: Hex32;
  readonly unlockingSha256Hex: Hex32;
  readonly maximumOperationCost: number;
  readonly operationCostEngine: "bchn-v29.0.0" | "independent-bchn-conformant";
  readonly operationCostEvidenceSha256Hex: Hex32;
  /** Exact loader width after this topology fixes page/input indices and offsets. */
  readonly bodyLoaders: readonly {
    readonly bodySha256Hex: Hex32;
    readonly loaderBytes: number;
  }[];
};

export type V17ExactRomPlacementProfile = {
  readonly profile: V17Profile;
  readonly transactionBytes: number;
  readonly transactionSha256Hex: Hex32;
  /**
   * Exact serialized transaction bytes after deleting every graph-owned role
   * input. This retains headers, counts, public inputs, all outputs, and ROM
   * inputs, so page removal and CompactSize changes are measured rather than
   * guessed or treated as additive.
   */
  readonly nonRoleTransactionBytes: number;
  readonly envelopeEvidenceSha256Hex: Hex32;
  readonly roles: readonly V17ExactRoleEnvelope[];
  readonly pages: readonly V17ExactRomPageEnvelope[];
};

export type V17MaterializedRomPlacementCandidate = {
  readonly status: "materialized-exact-envelope";
  readonly placements: readonly V17RomPlacement[];
  readonly profiles: readonly [
    V17ExactRomPlacementProfile,
    V17ExactRomPlacementProfile,
    V17ExactRomPlacementProfile,
  ];
};

export type V17ProvenInfeasibleRomPlacementCandidate = {
  readonly status: "proven-infeasible-before-exact-vm-measurement";
  readonly placements: readonly V17RomPlacement[];
  readonly rejection: {
    readonly metric:
      | "redeemBytes"
      | "unlockingBytes"
      | "pushedElementBytes"
      | "transactionBytes";
    readonly actual: number;
    readonly limit: number;
    readonly profile: V17Profile;
    readonly roleId?: string;
    readonly pageId?: string;
    readonly evidenceSha256Hex: Hex32;
  };
};

export type V17ExactRomPlacementCandidate =
  | V17MaterializedRomPlacementCandidate
  | V17ProvenInfeasibleRomPlacementCandidate;

/**
 * A pure planning input. Exactness requires one candidate for every binary
 * body-class placement. All occurrences of one `(pageId, bodySha256Hex)` class
 * move coherently, because the linker either retains that exact body in ROM or
 * inlines every use of it. Every member occurrence remains explicit in each
 * candidate: generic proof reads and transaction introspection make operation
 * cost envelope-dependent, so class deltas are not generally additive.
 */
export type V17RomPlacementOptimizerInput = {
  readonly schema: typeof V17_ROM_PLACEMENT_INPUT_SCHEMA;
  readonly status: "complete-exact-envelope-enumeration";
  readonly protocolIdHex: Hex32;
  readonly constructionGraphSha256Hex: Hex32;
  readonly occurrenceCensusSha256Hex: Hex32;
  readonly minimumProofCarrierBytesPerRole: number;
  readonly roleIds: readonly string[];
  readonly pages: readonly V17RomPlacementPage[];
  readonly occurrences: readonly V17RomPlacementOccurrence[];
  readonly candidates: readonly V17ExactRomPlacementCandidate[];
};

export type V17RomPlacementCertificate = {
  readonly schema: typeof V17_ROM_PLACEMENT_CERTIFICATE_SCHEMA;
  readonly status: "exact-optimum-over-complete-envelope-enumeration";
  readonly qualification: "planning-only-requires-byte-replay-and-independent-bchn";
  readonly protocolIdHex: Hex32;
  readonly constructionGraphSha256Hex: Hex32;
  readonly occurrenceCensusSha256Hex: Hex32;
  readonly modelDigestHex: Hex32;
  readonly selectedCandidateDigestHex: Hex32;
  readonly constraints: {
    readonly maximumScriptBytes: typeof V17_MAX_SCRIPT_BYTES;
    readonly maximumPushedElementBytes: typeof V17_MAX_SCRIPT_BYTES;
    readonly fixedInputDensityBytes: typeof V17_INPUT_FIXED_DENSITY_BYTES;
    readonly operationCostPerDensityByte: typeof V17_OPCOST_PER_DENSITY_BYTE;
    readonly maximumTransactionBytes: typeof V17_CONSENSUS_TX_BYTES;
    readonly evidenceIds: readonly ["LIM-001", "LIM-003", "LIM-006"];
  };
  readonly objective: {
    readonly order: readonly [
      "minimum-maximum-profile-transaction-bytes",
      "minimum-sum-profile-transaction-bytes",
      "minimum-active-rom-pages",
      "lexicographic-inline-before-rom",
    ];
    readonly maximumProfileTransactionBytes: number;
    readonly sumProfileTransactionBytes: number;
  };
  readonly placements: readonly (V17RomPlacement & {
    readonly pageId: string;
    readonly functionIdHex: string;
    readonly bodyBytes: number;
    readonly inlineEncodedBytes: number;
    readonly selectedEncodingBytes: number;
  })[];
  readonly pageEffects: {
    readonly allPageIds: readonly string[];
    readonly activePageIds: readonly string[];
    readonly removedPageIds: readonly string[];
    readonly allRomNonRoleTransactionBytes: readonly [number, number, number];
    readonly selectedNonRoleTransactionBytes: readonly [number, number, number];
    /** Positive means the selected topology removed exact non-role bytes. */
    readonly exactNonRoleBytesRemovedFromAllRom: readonly [number, number, number];
  };
  readonly profiles: readonly {
    readonly profile: V17Profile;
    readonly transactionBytes: number;
    readonly transactionHeadroomBytes: number;
    readonly transactionSha256Hex: Hex32;
    readonly envelopeEvidenceSha256Hex: Hex32;
    readonly roles: readonly (V17ExactRoleEnvelope & {
      readonly serializedInputBytes: number;
      readonly densityControlLength: number;
      readonly operationCostLimit: number;
      readonly operationCostHeadroom: number;
    })[];
    readonly pages: readonly (V17ExactRomPageEnvelope & {
      readonly serializedInputBytes: number;
      readonly serializedOutputBytes: number;
      readonly densityControlLength: number;
      readonly operationCostLimit: number;
      readonly operationCostHeadroom: number;
    })[];
  }[];
  readonly certificateIdHex: Hex32;
};

type NormalizedRole = V17ExactRoleEnvelope & {
  readonly serializedInputBytes: number;
  readonly densityControlLength: number;
  readonly operationCostLimit: number;
  readonly operationCostHeadroom: number;
  readonly feasible: boolean;
};

type NormalizedPageEnvelope = V17ExactRomPageEnvelope & {
  readonly serializedInputBytes: number;
  readonly serializedOutputBytes: number;
  readonly densityControlLength: number;
  readonly operationCostLimit: number;
  readonly operationCostHeadroom: number;
  readonly feasible: boolean;
};

type NormalizedProfile = Omit<V17ExactRomPlacementProfile, "roles" | "pages"> & {
  readonly roles: readonly NormalizedRole[];
  readonly pages: readonly NormalizedPageEnvelope[];
  readonly feasible: boolean;
};

type NormalizedMaterializedCandidate = {
  readonly status: "materialized-exact-envelope";
  readonly placementMask: string;
  readonly placements: readonly V17RomPlacement[];
  readonly activePageIds: readonly string[];
  readonly profiles: readonly [NormalizedProfile, NormalizedProfile, NormalizedProfile];
  readonly feasible: boolean;
  readonly digestHex: Hex32;
};

type NormalizedRejectedCandidate = {
  readonly status: "proven-infeasible-before-exact-vm-measurement";
  readonly placementMask: string;
  readonly placements: readonly V17RomPlacement[];
  readonly rejection: V17ProvenInfeasibleRomPlacementCandidate["rejection"];
};

type NormalizedCandidate = NormalizedMaterializedCandidate | NormalizedRejectedCandidate;

type NormalizedBodyClass = {
  readonly classKey: string;
  readonly pageId: string;
  readonly functionIdHex: string;
  readonly bodySha256Hex: Hex32;
  readonly bodyBytes: number;
  /** Earliest member in canonical semantic occurrence order. */
  readonly semanticAnchorIndex: number;
  /** Indexes into the canonically sorted occurrence census. */
  readonly memberOccurrenceIndexes: readonly number[];
};

function fail(message: string): never {
  throw new Error(`v17 ROM placement optimizer ${message}`);
}

function safeInteger(label: string, value: number, minimum = 0): number {
  if (!Number.isSafeInteger(value) || value < minimum) fail(label);
  return value;
}

function hex32(label: string, value: string): string {
  if (!/^[0-9a-f]{64}$/.test(value)) fail(`${label} must be lowercase hex32`);
  return value;
}

function identifier(label: string, value: string): string {
  if (!/^[a-z0-9][a-z0-9:._-]*$/.test(value)) fail(label);
  return value;
}

function roleIdentifier(value: string): string {
  if (value.length < 1 || /[\u0000-\u001f\u007f]/.test(value)) fail("role id");
  return value;
}

function occurrencePath(value: string): string {
  if (!/^(?:0|[1-9][0-9]*)(?:\/(?:0|[1-9][0-9]*))*$/.test(value)) {
    fail("occurrence path");
  }
  return value;
}

function functionIdHex(value: string): string {
  if (!/^(?:[0-9a-f]{2})+$/.test(value) || value.startsWith("00") ||
    value.length / 2 > V17_MAX_FUNCTION_ID_BYTES) {
    fail("function id");
  }
  return value;
}

/** Locale-independent ordering for canonical ASCII identity strings. */
function compareAscii(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function compareCanonicalDecimal(left: string, right: string): number {
  return left.length - right.length || compareAscii(left, right);
}

function compareOccurrencePath(left: string, right: string): number {
  const leftParts = left.split("/");
  const rightParts = right.split("/");
  const shared = Math.min(leftParts.length, rightParts.length);
  for (let index = 0; index < shared; index += 1) {
    const order = compareCanonicalDecimal(leftParts[index]!, rightParts[index]!);
    if (order !== 0) return order;
  }
  return leftParts.length - rightParts.length;
}

function encodedPushBytes(payloadBytes: number): number {
  safeInteger("push payload bytes", payloadBytes);
  if (payloadBytes === 0) return 1;
  if (payloadBytes <= 75) return 1 + payloadBytes;
  if (payloadBytes <= 0xff) return 2 + payloadBytes;
  if (payloadBytes <= 0xffff) return 3 + payloadBytes;
  return 5 + payloadBytes;
}

function serializedInputBytes(unlockingBytes: number): number {
  return 32 + 4 + v17CompactUintBytes(unlockingBytes) + unlockingBytes + 4;
}

function serializedOutputBytes(lockingBytes: number): number {
  return 8 + v17CompactUintBytes(lockingBytes) + lockingBytes;
}

function framedDomainHash(domain: string, value: unknown): string {
  const domainBytes = new TextEncoder().encode(domain);
  const payload = new TextEncoder().encode(canonicalV17Json(value));
  const frame = new Uint8Array(8 + domainBytes.length + payload.length);
  const view = new DataView(frame.buffer);
  view.setUint32(0, domainBytes.length, false);
  frame.set(domainBytes, 4);
  view.setUint32(4 + domainBytes.length, payload.length, false);
  frame.set(payload, 8 + domainBytes.length);
  return createHash("sha256").update(frame).digest("hex");
}

export function v17RomPlacementOccurrenceKey(
  occurrence: Pick<V17RomPlacementOccurrence,
    "profile" | "roleId" | "path" | "bodySha256Hex">,
): string {
  return canonicalV17Json([
    occurrence.profile,
    occurrence.roleId,
    occurrence.path,
    occurrence.bodySha256Hex,
  ]);
}

/** Canonical construction-level unit controlled by one inline/ROM decision. */
export function v17RomPlacementBodyClassKey(
  occurrence: Pick<V17RomPlacementOccurrence, "pageId" | "bodySha256Hex">,
): string {
  return canonicalV17Json([
    occurrence.pageId,
    occurrence.bodySha256Hex,
  ]);
}

function compareOccurrence(
  left: V17RomPlacementOccurrence,
  right: V17RomPlacementOccurrence,
  roleOrder: ReadonlyMap<string, number>,
): number {
  return left.profile - right.profile ||
    roleOrder.get(left.roleId)! - roleOrder.get(right.roleId)! ||
    compareOccurrencePath(left.path, right.path) ||
    compareAscii(left.bodySha256Hex, right.bodySha256Hex);
}

function normalizePlacements(
  raw: readonly V17RomPlacement[],
  occurrences: readonly V17RomPlacementOccurrence[],
  bodyClasses: readonly NormalizedBodyClass[],
): { readonly placements: readonly V17RomPlacement[]; readonly mask: string } {
  if (raw.length !== occurrences.length) fail("candidate placement count");
  const byKey = new Map<string, V17RomPlacement>();
  for (const placement of raw) {
    if (placement.placement !== "inline" && placement.placement !== "rom") {
      fail("candidate placement decision");
    }
    const key = v17RomPlacementOccurrenceKey(placement);
    if (byKey.has(key)) fail("duplicate candidate placement");
    byKey.set(key, placement);
  }
  const placements = occurrences.map((occurrence): V17RomPlacement => {
    const placement = byKey.get(v17RomPlacementOccurrenceKey(occurrence));
    if (placement === undefined) fail("missing candidate placement");
    return {
      profile: occurrence.profile,
      roleId: occurrence.roleId,
      path: occurrence.path,
      bodySha256Hex: occurrence.bodySha256Hex,
      placement: placement.placement,
    };
  });
  const classDecisions = bodyClasses.map((bodyClass) => {
    const decisions = new Set(bodyClass.memberOccurrenceIndexes.map((index) =>
      placements[index]!.placement));
    if (decisions.size !== 1) {
      fail(`incoherent body-class placement ${bodyClass.pageId}:${bodyClass.bodySha256Hex}`);
    }
    return placements[bodyClass.memberOccurrenceIndexes[0]!]!.placement;
  });
  return {
    placements,
    mask: classDecisions.map((placement) => placement === "inline" ? "0" : "1").join(""),
  };
}

function normalizeRole(
  raw: V17ExactRoleEnvelope,
  profile: V17Profile,
  expectedRoleId: string,
  logicalInputIndex: number,
  minimumProofCarrierBytes: number,
): NormalizedRole {
  if (raw.roleId !== expectedRoleId || raw.logicalInputIndex !== logicalInputIndex) {
    fail(`role layout ${profile}:${expectedRoleId}`);
  }
  const proofCarrierBytes = safeInteger("proof carrier bytes", raw.proofCarrierBytes,
    minimumProofCarrierBytes);
  const redeemBytes = safeInteger("redeem bytes", raw.redeemBytes, 1);
  const unlockingBytes = safeInteger("unlocking bytes", raw.unlockingBytes, 1);
  const expectedUnlockingBytes = encodedPushBytes(proofCarrierBytes) +
    (expectedRoleId === LOCAL_WORD_BATCH_LEADER_ROLE_ID
      ? encodedPushBytes(V17_BATCH_LEADER_CELL_BYTES)
      : 0) +
    encodedPushBytes(redeemBytes);
  if (unlockingBytes !== expectedUnlockingBytes) {
    fail(`noncanonical carrier unlocking ${profile}:${expectedRoleId}`);
  }
  const maximumOperationCost = safeInteger("maximum operation cost", raw.maximumOperationCost, 1);
  if (raw.operationCostEngine !== "bchn-v29.0.0" &&
    raw.operationCostEngine !== "independent-bchn-conformant") {
    fail("operation cost engine");
  }
  const densityControlLength = V17_INPUT_FIXED_DENSITY_BYTES + unlockingBytes;
  const operationCostLimit = densityControlLength * V17_OPCOST_PER_DENSITY_BYTE;
  const feasible = proofCarrierBytes <= V17_MAX_SCRIPT_BYTES &&
    redeemBytes <= V17_MAX_SCRIPT_BYTES && unlockingBytes <= V17_MAX_SCRIPT_BYTES &&
    maximumOperationCost <= operationCostLimit;
  return {
    logicalInputIndex,
    roleId: expectedRoleId,
    proofCarrierBytes,
    redeemBytes,
    unlockingBytes,
    redeemSha256Hex: hex32("redeem digest", raw.redeemSha256Hex),
    unlockingSha256Hex: hex32("unlocking digest", raw.unlockingSha256Hex),
    maximumOperationCost,
    operationCostEngine: raw.operationCostEngine,
    operationCostEvidenceSha256Hex:
      hex32("operation cost evidence", raw.operationCostEvidenceSha256Hex),
    serializedInputBytes: serializedInputBytes(unlockingBytes),
    densityControlLength,
    operationCostLimit,
    operationCostHeadroom: operationCostLimit - maximumOperationCost,
    feasible,
  };
}

function normalizePageEnvelope(
  raw: V17ExactRomPageEnvelope,
  expected: V17RomPlacementPage,
): NormalizedPageEnvelope {
  if (raw.pageId !== expected.pageId || raw.payloadBytes !== expected.payloadBytes ||
    raw.payloadSha256Hex !== expected.payloadSha256Hex) {
    fail(`page identity ${expected.pageId}`);
  }
  const pageIndex = safeInteger("page index", raw.pageIndex);
  const inputIndex = safeInteger("page input index", raw.inputIndex);
  const outputIndex = safeInteger("page output index", raw.outputIndex);
  const redeemBytes = safeInteger("page redeem bytes", raw.redeemBytes, 1);
  const lockingBytes = safeInteger("page locking bytes", raw.lockingBytes, 1);
  const unlockingBytes = safeInteger("page unlocking bytes", raw.unlockingBytes, 1);
  if (unlockingBytes !== encodedPushBytes(expected.payloadBytes) + encodedPushBytes(redeemBytes)) {
    fail(`noncanonical page unlocking ${expected.pageId}`);
  }
  const loaders = [...raw.bodyLoaders].sort((left, right) =>
    compareAscii(left.bodySha256Hex, right.bodySha256Hex));
  const expectedBodies = [...expected.bodyClasses].sort((left, right) =>
    compareAscii(left.bodySha256Hex, right.bodySha256Hex));
  if (loaders.length !== expectedBodies.length || loaders.some((loader, index) =>
    loader.bodySha256Hex !== expectedBodies[index]!.bodySha256Hex)) {
    fail(`page loader census ${expected.pageId}`);
  }
  loaders.forEach((loader) => {
    hex32("loader body digest", loader.bodySha256Hex);
    safeInteger("loader bytes", loader.loaderBytes, 1);
  });
  const maximumOperationCost = safeInteger("page maximum operation cost",
    raw.maximumOperationCost, 1);
  if (raw.operationCostEngine !== "bchn-v29.0.0" &&
    raw.operationCostEngine !== "independent-bchn-conformant") {
    fail("page operation cost engine");
  }
  const densityControlLength = V17_INPUT_FIXED_DENSITY_BYTES + unlockingBytes;
  const operationCostLimit = densityControlLength * V17_OPCOST_PER_DENSITY_BYTE;
  const feasible = expected.payloadBytes <= V17_MAX_SCRIPT_BYTES &&
    redeemBytes <= V17_MAX_SCRIPT_BYTES && lockingBytes <= V17_MAX_SCRIPT_BYTES &&
    unlockingBytes <= V17_MAX_SCRIPT_BYTES && maximumOperationCost <= operationCostLimit;
  return {
    pageId: expected.pageId,
    pageIndex,
    inputIndex,
    outputIndex,
    payloadBytes: expected.payloadBytes,
    payloadSha256Hex: expected.payloadSha256Hex,
    redeemBytes,
    lockingBytes,
    unlockingBytes,
    redeemSha256Hex: hex32("page redeem digest", raw.redeemSha256Hex),
    lockingSha256Hex: hex32("page locking digest", raw.lockingSha256Hex),
    unlockingSha256Hex: hex32("page unlocking digest", raw.unlockingSha256Hex),
    maximumOperationCost,
    operationCostEngine: raw.operationCostEngine,
    operationCostEvidenceSha256Hex:
      hex32("page operation cost evidence", raw.operationCostEvidenceSha256Hex),
    bodyLoaders: loaders,
    serializedInputBytes: serializedInputBytes(unlockingBytes),
    serializedOutputBytes: serializedOutputBytes(lockingBytes),
    densityControlLength,
    operationCostLimit,
    operationCostHeadroom: operationCostLimit - maximumOperationCost,
    feasible,
  };
}

function normalizeProfile(
  raw: V17ExactRomPlacementProfile,
  profile: V17Profile,
  roleIds: readonly string[],
  activePageIds: readonly string[],
  pagesById: ReadonlyMap<string, V17RomPlacementPage>,
  minimumProofCarrierBytes: number,
): NormalizedProfile {
  if (raw.profile !== profile) fail(`profile order ${profile}`);
  const rolesById = new Map(raw.roles.map((role) => [role.roleId, role]));
  if (rolesById.size !== roleIds.length || raw.roles.length !== roleIds.length) {
    fail(`profile role count ${profile}`);
  }
  const roles = roleIds.map((roleId, logicalInputIndex) => {
    const role = rolesById.get(roleId);
    if (role === undefined) fail(`profile missing role ${profile}:${roleId}`);
    return normalizeRole(role, profile, roleId, logicalInputIndex, minimumProofCarrierBytes);
  });
  const rawPagesById = new Map(raw.pages.map((page) => [page.pageId, page]));
  if (rawPagesById.size !== activePageIds.length || raw.pages.length !== activePageIds.length) {
    fail(`profile page count ${profile}`);
  }
  const pages = activePageIds.map((pageId) => {
    const page = rawPagesById.get(pageId);
    const expected = pagesById.get(pageId);
    if (page === undefined || expected === undefined) fail(`profile missing page ${profile}:${pageId}`);
    return normalizePageEnvelope(page, expected);
  }).sort((left, right) => left.pageIndex - right.pageIndex);
  if (pages.some((page, index) => page.pageIndex !== index)) {
    fail(`page index topology ${profile}`);
  }
  if (new Set(pages.map(({ inputIndex }) => inputIndex)).size !== pages.length ||
    new Set(pages.map(({ outputIndex }) => outputIndex)).size !== pages.length) {
    fail(`page transaction index uniqueness ${profile}`);
  }
  const transactionBytes = safeInteger("transaction bytes", raw.transactionBytes, 1);
  const nonRoleTransactionBytes = safeInteger("non-role transaction bytes",
    raw.nonRoleTransactionBytes, 1);
  const workerInputBytes = roles.reduce((sum, role) => sum + role.serializedInputBytes, 0);
  if (transactionBytes !== nonRoleTransactionBytes + workerInputBytes) {
    fail(`transaction byte decomposition ${profile}`);
  }
  const pageBytes = pages.reduce((sum, page) =>
    sum + page.serializedInputBytes + page.serializedOutputBytes, 0);
  if (nonRoleTransactionBytes < pageBytes) fail(`non-role page bytes ${profile}`);
  const feasible = transactionBytes <= V17_CONSENSUS_TX_BYTES &&
    roles.every((role) => role.feasible) && pages.every((page) => page.feasible);
  return {
    profile,
    transactionBytes,
    transactionSha256Hex: hex32("transaction digest", raw.transactionSha256Hex),
    nonRoleTransactionBytes,
    envelopeEvidenceSha256Hex:
      hex32("envelope evidence", raw.envelopeEvidenceSha256Hex),
    roles,
    pages,
    feasible,
  };
}

function topologyFingerprint(profile: NormalizedProfile): string {
  return canonicalV17Json({
    profile: profile.profile,
    nonRoleTransactionBytes: profile.nonRoleTransactionBytes,
    pages: profile.pages.map(({ operationCostEvidenceSha256Hex: ignored, feasible: alsoIgnored,
      ...page }) => {
      void ignored;
      void alsoIgnored;
      return page;
    }),
  });
}

function normalizeRejectedCandidate(
  raw: V17ProvenInfeasibleRomPlacementCandidate,
  placements: readonly V17RomPlacement[],
  mask: string,
  roleIds: readonly string[],
  pageIds: ReadonlySet<string>,
): NormalizedRejectedCandidate {
  const rejection = raw.rejection;
  safeInteger("rejection actual", rejection.actual, 1);
  safeInteger("rejection limit", rejection.limit, 1);
  const expectedLimit = rejection.metric === "transactionBytes"
    ? V17_CONSENSUS_TX_BYTES
    : V17_MAX_SCRIPT_BYTES;
  if (rejection.limit !== expectedLimit || rejection.actual <= rejection.limit ||
    !V17_PROFILES.includes(rejection.profile)) {
    fail("infeasible-candidate proof");
  }
  if (rejection.roleId !== undefined && !roleIds.includes(rejection.roleId)) {
    fail("infeasible-candidate role");
  }
  if (rejection.pageId !== undefined && !pageIds.has(rejection.pageId)) {
    fail("infeasible-candidate page");
  }
  if (rejection.metric === "transactionBytes" &&
    (rejection.roleId !== undefined || rejection.pageId !== undefined)) {
    fail("transaction rejection scope");
  }
  if (rejection.metric !== "transactionBytes" &&
    rejection.roleId === undefined && rejection.pageId === undefined) {
    fail("script rejection scope");
  }
  return {
    status: raw.status,
    placementMask: mask,
    placements,
    rejection: {
      metric: rejection.metric,
      actual: rejection.actual,
      limit: rejection.limit,
      profile: rejection.profile,
      ...(rejection.roleId === undefined ? {} : { roleId: rejection.roleId }),
      ...(rejection.pageId === undefined ? {} : { pageId: rejection.pageId }),
      evidenceSha256Hex: hex32("rejection evidence", rejection.evidenceSha256Hex),
    },
  };
}

function candidateObjective(candidate: NormalizedMaterializedCandidate): readonly [
  number,
  number,
  number,
  string,
] {
  const transactions = candidate.profiles.map(({ transactionBytes }) => transactionBytes);
  return [
    Math.max(...transactions),
    transactions.reduce((sum, bytes) => sum + bytes, 0),
    candidate.activePageIds.length,
    candidate.placementMask,
  ];
}

function compareObjective(
  left: NormalizedMaterializedCandidate,
  right: NormalizedMaterializedCandidate,
): number {
  const a = candidateObjective(left);
  const b = candidateObjective(right);
  return a[0] - b[0] || a[1] - b[1] || a[2] - b[2] || compareAscii(a[3], b[3]);
}

function withoutFeasibility(value: NormalizedCandidate): unknown {
  if (value.status !== "materialized-exact-envelope") return value;
  return {
    status: value.status,
    placementMask: value.placementMask,
    placements: value.placements,
    activePageIds: value.activePageIds,
    profiles: value.profiles.map(({ feasible: ignoredProfile, roles, pages, ...profile }) => {
      void ignoredProfile;
      return {
        ...profile,
        roles: roles.map(({ feasible: ignored, ...role }) => {
          void ignored;
          return role;
        }),
        pages: pages.map(({ feasible: ignored, ...page }) => {
          void ignored;
          return page;
        }),
      };
    }),
  };
}

function prepareModel(
  input: V17RomPlacementOptimizerInput,
  maximumCandidateEvaluations: number,
): {
  readonly roleIds: readonly string[];
  readonly pages: readonly V17RomPlacementPage[];
  readonly occurrences: readonly V17RomPlacementOccurrence[];
  readonly bodyClasses: readonly NormalizedBodyClass[];
  readonly candidates: readonly NormalizedCandidate[];
  readonly modelDigestHex: Hex32;
} {
  if (input.schema !== V17_ROM_PLACEMENT_INPUT_SCHEMA ||
    input.status !== "complete-exact-envelope-enumeration") {
    fail("input schema/status");
  }
  hex32("protocol id", input.protocolIdHex);
  hex32("construction graph", input.constructionGraphSha256Hex);
  hex32("occurrence census", input.occurrenceCensusSha256Hex);
  const minimumProofCarrierBytes = safeInteger("minimum proof carrier bytes",
    input.minimumProofCarrierBytesPerRole, 1);
  if (minimumProofCarrierBytes > V17_MAX_SCRIPT_BYTES) fail("minimum proof carrier limit");
  const roleIds = [...input.roleIds].map(roleIdentifier);
  if (roleIds.length < 1 || new Set(roleIds).size !== roleIds.length) fail("role id census");
  const roleOrder = new Map(roleIds.map((roleId, index) => [roleId, index]));

  const pages = [...input.pages].map((page): V17RomPlacementPage => {
    const pageId = identifier("page id", page.pageId);
    const bodies = [...page.bodyClasses].map((body) => ({
      bodySha256Hex: hex32("page body digest", body.bodySha256Hex),
      bodyBytes: safeInteger("page body bytes", body.bodyBytes, 1),
    })).sort((left, right) => compareAscii(left.bodySha256Hex, right.bodySha256Hex));
    if (bodies.length < 1 || new Set(bodies.map(({ bodySha256Hex }) => bodySha256Hex)).size !==
      bodies.length) fail(`page body census ${pageId}`);
    return {
      pageId,
      payloadSha256Hex: hex32("page payload digest", page.payloadSha256Hex),
      payloadBytes: safeInteger("page payload bytes", page.payloadBytes, 1),
      bodyClasses: bodies,
    };
  }).sort((left, right) => compareAscii(left.pageId, right.pageId));
  const pagesById = new Map(pages.map((page) => [page.pageId, page]));
  if (pagesById.size !== pages.length) fail("page id census");
  const bodyPage = new Map<string, { readonly pageId: string; readonly bodyBytes: number }>();
  pages.forEach((page) => page.bodyClasses.forEach((body) => {
    if (bodyPage.has(body.bodySha256Hex)) fail("body assigned to multiple pages");
    bodyPage.set(body.bodySha256Hex, { pageId: page.pageId, bodyBytes: body.bodyBytes });
  }));

  const occurrences = [...input.occurrences].map((occurrence): V17RomPlacementOccurrence => {
    if (!V17_PROFILES.includes(occurrence.profile) || !roleOrder.has(occurrence.roleId)) {
      fail("occurrence profile/role");
    }
    const bodySha256Hex = hex32("occurrence body digest", occurrence.bodySha256Hex);
    const assigned = bodyPage.get(bodySha256Hex);
    if (assigned === undefined || assigned.pageId !== occurrence.pageId ||
      assigned.bodyBytes !== occurrence.bodyBytes) {
      fail("occurrence page/body identity");
    }
    return {
      profile: occurrence.profile,
      roleId: occurrence.roleId,
      path: occurrencePath(occurrence.path),
      functionIdHex: functionIdHex(occurrence.functionIdHex),
      bodySha256Hex,
      bodyBytes: safeInteger("occurrence body bytes", occurrence.bodyBytes, 1),
      pageId: occurrence.pageId,
    };
  }).sort((left, right) => compareOccurrence(left, right, roleOrder));
  const semanticAnchorKeys = occurrences.map((occurrence) => canonicalV17Json([
    occurrence.profile,
    occurrence.roleId,
    occurrence.path,
  ]));
  if (new Set(semanticAnchorKeys).size !== occurrences.length) {
    fail("duplicate semantic occurrence anchor");
  }
  const occurrenceKeys = occurrences.map(v17RomPlacementOccurrenceKey);
  if (new Set(occurrenceKeys).size !== occurrences.length) fail("occurrence identity census");
  const referencedPages = new Set(occurrences.map(({ pageId }) => pageId));
  if (referencedPages.size !== pages.length) fail("unreferenced ROM page");

  const classMembers = new Map<string, number[]>();
  occurrences.forEach((occurrence, index) => {
    const key = v17RomPlacementBodyClassKey(occurrence);
    const members = classMembers.get(key) ?? [];
    members.push(index);
    classMembers.set(key, members);
  });
  const bodyClasses = [...classMembers.entries()].map(([classKey, memberOccurrenceIndexes]) => {
    const first = occurrences[memberOccurrenceIndexes[0]!]!;
    if (memberOccurrenceIndexes.some((index) =>
      occurrences[index]!.functionIdHex !== first.functionIdHex)) {
      fail(`body-class function id ${first.pageId}:${first.bodySha256Hex}`);
    }
    return {
      classKey,
      pageId: first.pageId,
      functionIdHex: first.functionIdHex,
      bodySha256Hex: first.bodySha256Hex,
      bodyBytes: first.bodyBytes,
      semanticAnchorIndex: memberOccurrenceIndexes[0]!,
      memberOccurrenceIndexes,
    };
  }).sort((left, right) => left.semanticAnchorIndex - right.semanticAnchorIndex);
  const functionIdOwners = new Map<string, string>();
  for (const bodyClass of bodyClasses) {
    const previous = functionIdOwners.get(bodyClass.functionIdHex);
    if (previous !== undefined && previous !== bodyClass.classKey) {
      fail(`function id aliases body classes ${bodyClass.functionIdHex}`);
    }
    functionIdOwners.set(bodyClass.functionIdHex, bodyClass.classKey);
  }

  const expectedCandidates = 1n << BigInt(bodyClasses.length);
  if (BigInt(input.candidates.length) !== expectedCandidates) {
    fail(`under-specified candidate enumeration ${input.candidates.length}/${expectedCandidates}`);
  }
  safeInteger("maximum candidate evaluations", maximumCandidateEvaluations, 1);
  if (input.candidates.length > maximumCandidateEvaluations) {
    fail(`exact search budget ${input.candidates.length}/${maximumCandidateEvaluations}`);
  }

  const topologyFingerprints = new Map<string, string>();
  const candidates = input.candidates.map((candidate): NormalizedCandidate => {
    const normalizedPlacements = normalizePlacements(candidate.placements, occurrences, bodyClasses);
    if (candidate.status === "proven-infeasible-before-exact-vm-measurement") {
      return normalizeRejectedCandidate(candidate, normalizedPlacements.placements,
        normalizedPlacements.mask, roleIds, new Set(pagesById.keys()));
    }
    if (candidate.status !== "materialized-exact-envelope") fail("candidate status");
    const activePageIds = [...new Set(normalizedPlacements.placements.flatMap((placement, index) =>
      placement.placement === "rom" ? [occurrences[index]!.pageId] : []))].sort(compareAscii);
    if (candidate.profiles.length !== V17_PROFILES.length) fail("candidate profile count");
    const profiles = V17_PROFILES.map((profile) => normalizeProfile(
      candidate.profiles[profile]!, profile, roleIds, activePageIds, pagesById,
      minimumProofCarrierBytes,
    )) as unknown as readonly [NormalizedProfile, NormalizedProfile, NormalizedProfile];
    profiles.forEach((profile) => {
      const topologyKey = canonicalV17Json([activePageIds, profile.profile]);
      const fingerprint = topologyFingerprint(profile);
      const previous = topologyFingerprints.get(topologyKey);
      if (previous !== undefined && previous !== fingerprint) {
        fail(`non-deterministic page topology ${profile.profile}:${activePageIds.join(",")}`);
      }
      topologyFingerprints.set(topologyKey, fingerprint);
    });
    const core = {
      status: candidate.status,
      placementMask: normalizedPlacements.mask,
      placements: normalizedPlacements.placements,
      activePageIds,
      profiles: profiles.map(({ feasible: ignoredProfile, roles, pages, ...profile }) => {
        void ignoredProfile;
        return {
          ...profile,
          roles: roles.map(({ feasible: ignored, ...role }) => {
            void ignored;
            return role;
          }),
          pages: pages.map(({ feasible: ignored, ...page }) => {
            void ignored;
            return page;
          }),
        };
      }),
    };
    return {
      status: candidate.status,
      placementMask: normalizedPlacements.mask,
      placements: normalizedPlacements.placements,
      activePageIds,
      profiles,
      feasible: profiles.every((profile) => profile.feasible),
      digestHex: framedDomainHash("ShieldKit/V17RomPlacementCandidate/v1", core),
    };
  }).sort((left, right) => compareAscii(left.placementMask, right.placementMask));
  if (new Set(candidates.map(({ placementMask }) => placementMask)).size !== candidates.length) {
    fail("duplicate placement vector");
  }

  const normalizedModel = {
    schema: input.schema,
    status: input.status,
    protocolIdHex: input.protocolIdHex,
    constructionGraphSha256Hex: input.constructionGraphSha256Hex,
    occurrenceCensusSha256Hex: input.occurrenceCensusSha256Hex,
    minimumProofCarrierBytesPerRole: minimumProofCarrierBytes,
    roleIds,
    pages,
    occurrences,
    bodyClasses: bodyClasses.map((bodyClass) => ({
      classKey: bodyClass.classKey,
      pageId: bodyClass.pageId,
      functionIdHex: bodyClass.functionIdHex,
      bodySha256Hex: bodyClass.bodySha256Hex,
      bodyBytes: bodyClass.bodyBytes,
      semanticAnchorIndex: bodyClass.semanticAnchorIndex,
      memberOccurrenceKeys: bodyClass.memberOccurrenceIndexes.map((index) => occurrenceKeys[index]!),
    })),
    candidates: candidates.map(withoutFeasibility),
  };
  return {
    roleIds,
    pages,
    occurrences,
    bodyClasses,
    candidates,
    modelDigestHex: framedDomainHash("ShieldKit/V17RomPlacementModel/v1", normalizedModel),
  };
}

/**
 * Select the smallest exact, locally feasible construction envelope.
 *
 * The result is intentionally planning-only: hashes and meters are bound, but
 * this pure module neither recompiles the bytecode nor independently replays
 * BCHN. Integration must perform both before construction certification.
 */
export function optimizeV17RomPlacement(
  input: V17RomPlacementOptimizerInput,
  options: { readonly maximumCandidateEvaluations?: number } = {},
): V17RomPlacementCertificate {
  const maximumCandidateEvaluations = options.maximumCandidateEvaluations ??
    MAX_EXACTLY_ENUMERATED_CANDIDATES;
  const model = prepareModel(input, maximumCandidateEvaluations);
  const feasible = model.candidates.filter((candidate): candidate is NormalizedMaterializedCandidate =>
    candidate.status === "materialized-exact-envelope" && candidate.feasible);
  if (feasible.length === 0) fail("no feasible exact candidate");
  const selected = [...feasible].sort(compareObjective)[0]!;
  const allRomMask = "1".repeat(model.bodyClasses.length);
  const allRom = model.candidates.find((candidate): candidate is NormalizedMaterializedCandidate =>
    candidate.placementMask === allRomMask && candidate.status === "materialized-exact-envelope");
  if (allRom === undefined) fail("all-ROM baseline must be an exact materialized envelope");

  const placementRows = selected.placements.map((placement, index) => {
    const occurrence = model.occurrences[index]!;
    const profile = selected.profiles[occurrence.profile];
    const page = profile.pages.find(({ pageId }) => pageId === occurrence.pageId);
    const loader = page?.bodyLoaders.find(({ bodySha256Hex }) =>
      bodySha256Hex === occurrence.bodySha256Hex);
    if (placement.placement === "rom" && loader === undefined) {
      fail("selected placement loader");
    }
    return {
      ...placement,
      pageId: occurrence.pageId,
      functionIdHex: occurrence.functionIdHex,
      bodyBytes: occurrence.bodyBytes,
      inlineEncodedBytes: encodedPushBytes(occurrence.bodyBytes),
      selectedEncodingBytes: placement.placement === "inline"
        ? encodedPushBytes(occurrence.bodyBytes)
        : loader!.loaderBytes,
    };
  });
  const selectedTransactions = selected.profiles.map(({ transactionBytes }) => transactionBytes);
  const allRomNonRole = allRom.profiles.map(({ nonRoleTransactionBytes }) =>
    nonRoleTransactionBytes) as unknown as readonly [number, number, number];
  const selectedNonRole = selected.profiles.map(({ nonRoleTransactionBytes }) =>
    nonRoleTransactionBytes) as unknown as readonly [number, number, number];
  const activePageIds = selected.activePageIds;
  const removedPageIds = model.pages.map(({ pageId }) => pageId)
    .filter((pageId) => !activePageIds.includes(pageId));
  const certificateCore = {
    schema: V17_ROM_PLACEMENT_CERTIFICATE_SCHEMA,
    status: "exact-optimum-over-complete-envelope-enumeration" as const,
    qualification: "planning-only-requires-byte-replay-and-independent-bchn" as const,
    protocolIdHex: input.protocolIdHex,
    constructionGraphSha256Hex: input.constructionGraphSha256Hex,
    occurrenceCensusSha256Hex: input.occurrenceCensusSha256Hex,
    modelDigestHex: model.modelDigestHex,
    selectedCandidateDigestHex: selected.digestHex,
    constraints: {
      maximumScriptBytes: V17_MAX_SCRIPT_BYTES,
      maximumPushedElementBytes: V17_MAX_SCRIPT_BYTES,
      fixedInputDensityBytes: V17_INPUT_FIXED_DENSITY_BYTES,
      operationCostPerDensityByte: V17_OPCOST_PER_DENSITY_BYTE,
      maximumTransactionBytes: V17_CONSENSUS_TX_BYTES,
      evidenceIds: ["LIM-001", "LIM-003", "LIM-006"] as const,
    },
    objective: {
      order: [
        "minimum-maximum-profile-transaction-bytes",
        "minimum-sum-profile-transaction-bytes",
        "minimum-active-rom-pages",
        "lexicographic-inline-before-rom",
      ] as const,
      maximumProfileTransactionBytes: Math.max(...selectedTransactions),
      sumProfileTransactionBytes: selectedTransactions.reduce((sum, bytes) => sum + bytes, 0),
    },
    placements: placementRows,
    pageEffects: {
      allPageIds: model.pages.map(({ pageId }) => pageId),
      activePageIds,
      removedPageIds,
      allRomNonRoleTransactionBytes: allRomNonRole,
      selectedNonRoleTransactionBytes: selectedNonRole,
      exactNonRoleBytesRemovedFromAllRom: V17_PROFILES.map((profile) =>
        allRomNonRole[profile] - selectedNonRole[profile]) as unknown as
        readonly [number, number, number],
    },
    profiles: selected.profiles.map((profile) => ({
      profile: profile.profile,
      transactionBytes: profile.transactionBytes,
      transactionHeadroomBytes: V17_CONSENSUS_TX_BYTES - profile.transactionBytes,
      transactionSha256Hex: profile.transactionSha256Hex,
      envelopeEvidenceSha256Hex: profile.envelopeEvidenceSha256Hex,
      roles: profile.roles.map(({ feasible: ignored, ...role }) => {
        void ignored;
        return role;
      }),
      pages: profile.pages.map(({ feasible: ignored, ...page }) => {
        void ignored;
        return page;
      }),
    })),
  };
  return {
    ...certificateCore,
    certificateIdHex: framedDomainHash(
      "ShieldKit/V17RomPlacementCertificate/v1",
      certificateCore,
    ),
  };
}

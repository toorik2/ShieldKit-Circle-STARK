import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { basename, resolve } from "node:path";
import {
  verifyLocalWordSealedProofBytes,
} from "../src/backends/circle/local-word-verifier.ts";
import {
  V17_PROOF_PROTOCOL_ID,
  V17_PROOF_FIXED_PREFIX_BYTES,
} from "../src/backends/circle/v17-proof-layout.ts";
import {
  measureV17LocalSizingProfiles,
} from "../src/assurance/v17-local-sizing-allocation.ts";
import {
  materializeV17PostLinkCandidateEnvelopes,
} from "../src/assurance/v17-post-link-bchn-measurement.ts";
import {
  V17_BOOTSTRAP_AFFINE_ALLOCATION,
  measuredV17AffineAllocation,
  type V17AffineAllocation,
} from "../src/chain/v17-affine-allocation.ts";
import { V17_PRODUCTION_ROLE_LAYOUT } from "../src/chain/v17-role-layout.ts";
import {
  allocateV17UnqualifiedSizingDensity,
  assessV17UnqualifiedSizingDensity,
} from "../src/construction/v17-linker.ts";
import {
  buildV17LabProductFixture,
} from "../src/construction/v17-lab-product-fixtures.ts";
import {
  materializeV17PostLinkCandidates,
  previewV17ProductRom,
  type V17ProfileProofMaterial,
} from "../src/construction/v17-product-link.ts";
import {
  V17_CONSTRUCTION_GRAPH,
  V17_PROFILES,
  canonicalV17Json,
  v17ProtocolIdHex,
} from "../src/construction/v17-graph.ts";

type DiagnosticMarker = {
  readonly schema: string;
  readonly status: string;
  readonly proofSource: string;
  readonly protocolIdHex: string;
};

function allocationGeometry(allocation: V17AffineAllocation): unknown {
  return {
    status: allocation.status,
    minimumProofBytes: allocation.minimumProofBytes,
    maximumProofBytes: allocation.maximumProofBytes,
    elasticScaleUnits: allocation.elasticScaleUnits,
    assignments: allocation.assignments,
  };
}

const argument = process.argv[2];
if (argument === undefined) {
  throw new Error("usage: npm run diagnose:retained -- .local/v17-fresh-diagnostic-...");
}
const checkpointRoot = resolve(process.cwd(), argument);
if (!basename(checkpointRoot).startsWith("v17-fresh-diagnostic-")) {
  throw new Error("v17 retained sizing requires an explicit diagnostic checkpoint directory");
}
const marker = JSON.parse(readFileSync(resolve(checkpointRoot, "NOT-QUALIFIED.json"), "utf8")) as
  DiagnosticMarker;
assert.deepEqual(marker, {
  schema: "ShieldKit/V17FreshDiagnosticCheckpoint/v1",
  status: "partial-diagnostic-only-not-qualification-evidence",
  proofSource: "fresh-current-process-no-cache",
  protocolIdHex: v17ProtocolIdHex(),
});

const fixtures = V17_PROFILES.map((profile) => buildV17LabProductFixture(profile));
const proofs = V17_PROFILES.map((profile): V17ProfileProofMaterial => {
  const fixture = fixtures[profile]!;
  const proofBytes = new Uint8Array(readFileSync(
    resolve(checkpointRoot, `profile-${profile}.proof`),
  ));
  const verified = verifyLocalWordSealedProofBytes(proofBytes, {
    profile,
    transcriptInitial: fixture.transcriptInitial,
    constructionDescriptor: fixture.constructionDescriptor,
    publicWords: fixture.publicWords,
    expectedPreprocessedRoot: fixture.expectedPreprocessedRoot,
  });
  if (!verified.ok) {
    throw new Error(`v17 retained diagnostic proof ${profile}: ${verified.reason}`);
  }
  return {
    profile,
    proofBytes,
    constructionId: V17_PROOF_PROTOCOL_ID,
    constructionDigest: fixture.constructionDigest,
    expectedPreprocessedRoot: fixture.expectedPreprocessedRoot,
  };
}) as unknown as readonly [
  V17ProfileProofMaterial,
  V17ProfileProofMaterial,
  V17ProfileProofMaterial,
];

const productionLink = previewV17ProductRom(proofs);
const inlineFamilyArgument = process.argv.find((value) => value.startsWith("--inline-families="));
const inlineFamilies = new Set((inlineFamilyArgument?.slice("--inline-families=".length) ?? "")
  .split(",").filter((value) => value.length > 0));
const unknownInlineFamilies = [...inlineFamilies].filter((familyId) =>
  !V17_PRODUCTION_ROLE_LAYOUT.some((role) => role.familyId === familyId));
if (unknownInlineFamilies.length > 0) {
  throw new Error(`v17 retained diagnostic unknown inline families ${unknownInlineFamilies.join(",")}`);
}
const inlineRoleCountsArgument = process.argv.find((value) =>
  value.startsWith("--inline-role-counts="));
const inlineRoleCounts = new Map<string, number>();
for (const entry of (inlineRoleCountsArgument?.slice("--inline-role-counts=".length) ?? "")
  .split(",").filter((value) => value.length > 0)) {
  const separator = entry.lastIndexOf("=");
  const familyId = entry.slice(0, separator);
  const count = Number(entry.slice(separator + 1));
  const familyRoles = V17_PRODUCTION_ROLE_LAYOUT.filter((role) => role.familyId === familyId);
  if (separator < 1 || familyRoles.length < 1 || !Number.isSafeInteger(count) || count < 0 ||
    count > familyRoles.length || inlineRoleCounts.has(familyId)) {
    throw new Error(`v17 retained diagnostic inline role count ${entry}`);
  }
  inlineRoleCounts.set(familyId, count);
}
const inlineRoleIds = new Set<string>();
for (const [familyId, count] of inlineRoleCounts) {
  for (const role of V17_PRODUCTION_ROLE_LAYOUT.filter((candidate) =>
    candidate.familyId === familyId).slice(0, count)) {
    inlineRoleIds.add(role.id);
  }
}
const diagnosticRedeems = V17_PROFILES.map((profile) =>
  productionLink.preview.linkedRedeemsByProfile[profile]!.map((redeem, index) =>
    inlineFamilies.has(V17_PRODUCTION_ROLE_LAYOUT[index]!.familyId) ||
      inlineRoleIds.has(V17_PRODUCTION_ROLE_LAYOUT[index]!.id)
      ? productionLink.profiles[profile]!.workers[index]!.redeemBytecode
      : redeem));
const link = inlineFamilies.size === 0 && inlineRoleIds.size === 0
  ? productionLink
  : {
    ...productionLink,
    preview: {
      ...productionLink.preview,
      linkedRedeemsByProfile: diagnosticRedeems,
      certificate: {
        ...productionLink.preview.certificate,
        profiles: productionLink.preview.certificate.profiles.map((profile) => ({
          ...profile,
          linkedRedeemSha256Hexes: diagnosticRedeems[profile.profile]!.map((redeem) =>
            createHash("sha256").update(redeem).digest("hex")),
        })),
      },
    },
  };
const reserveFixedPrefix = process.argv.includes("--reserve-fixed-prefix");
const fixedPrefixDelta = V17_PROOF_FIXED_PREFIX_BYTES -
  V17_BOOTSTRAP_AFFINE_ALLOCATION.assignments[0]!.basePrefixEnd;
let allocation: V17AffineAllocation = !reserveFixedPrefix
  ? V17_BOOTSTRAP_AFFINE_ALLOCATION
  : {
    ...V17_BOOTSTRAP_AFFINE_ALLOCATION,
    minimumProofBytes: V17_BOOTSTRAP_AFFINE_ALLOCATION.minimumProofBytes + fixedPrefixDelta,
    assignments: V17_BOOTSTRAP_AFFINE_ALLOCATION.assignments.map((assignment, index) => ({
      ...assignment,
      basePrefixStart: index === 0 ? 0 : assignment.basePrefixStart + fixedPrefixDelta,
      basePrefixEnd: assignment.basePrefixEnd + fixedPrefixDelta,
    })),
  };
const visited = new Set<string>();
for (let pass = 1; pass <= 32; pass += 1) {
  const geometry = canonicalV17Json(allocationGeometry(allocation));
  if (visited.has(geometry)) {
    throw new Error(`v17 retained diagnostic allocation cycle at pass ${pass}`);
  }
  visited.add(geometry);
  console.error("v17-retained-sizing-progress", JSON.stringify({
    pass,
    allocation: allocation.status,
    minimumProofBytes: allocation.minimumProofBytes,
    reserveFixedPrefix,
  }));
  const candidates = materializeV17PostLinkCandidates({ link, proofs, allocation });
  const envelopes = materializeV17PostLinkCandidateEnvelopes({
    candidates,
    fixtures: fixtures.map(({ settlementFixture }) => settlementFixture),
  });
  console.error("v17-retained-sizing-progress", JSON.stringify({
    pass,
    inlineFamilies: [...inlineFamilies],
    inlineRoleCounts: Object.fromEntries(inlineRoleCounts),
    transactionBytes: envelopes.map(({ materialized }) => materialized.rawTransactionBytes.length),
    inputCounts: envelopes.map(({ materialized }) => materialized.transaction.inputs.length),
    outputCounts: envelopes.map(({ materialized }) => materialized.transaction.outputs.length),
  }));
  const profiles = measureV17LocalSizingProfiles({
    candidates,
    fixtures: fixtures.map(({ settlementFixture }) => settlementFixture),
  });
  const feasibility = assessV17UnqualifiedSizingDensity(V17_CONSTRUCTION_GRAPH, profiles);
  const familyRows = [...new Set(V17_PRODUCTION_ROLE_LAYOUT.map(({ familyId }) => familyId))]
    .map((familyId) => {
      const rows = feasibility.rows.filter((_, index) =>
        V17_PRODUCTION_ROLE_LAYOUT[index]!.familyId === familyId);
      return {
        familyId,
        roles: rows.length,
        requiredProofBytes: rows.reduce((sum, row) => sum + row.requiredProofBytes, 0),
        maximumOperationCost: rows.reduce((sum, row) => sum + row.maximumOperationCost, 0),
      };
    }).sort((left, right) => right.requiredProofBytes - left.requiredProofBytes);
  const topRoles = [...feasibility.rows]
    .sort((left, right) => right.requiredProofBytes - left.requiredProofBytes)
    .slice(0, 24)
    .map((row) => ({
      roleId: row.roleId,
      requiredProofBytes: row.requiredProofBytes,
      capacityProofBytes: row.capacityProofBytes,
      maximumOperationCost: row.maximumOperationCost,
      profileOperationCosts: row.profileOperationCosts,
    }));
  console.error("v17-retained-sizing-progress", JSON.stringify({
    pass,
    status: feasibility.status,
    currentMinimumProofBytes: allocation.minimumProofBytes,
    measuredMinimumProofBytes: feasibility.minimumProofBytes,
    maximumProofBytes: feasibility.maximumProofBytes,
    infeasibleRoleIds: feasibility.infeasibleRoleIds,
    familyRows,
    topRoles,
  }));
  if (feasibility.status !== "feasible") {
    throw new Error(`v17 retained density infeasible ${feasibility.minimumProofBytes}/${
      feasibility.maximumProofBytes}`);
  }
  const measuredAllocation = measuredV17AffineAllocation(
    allocateV17UnqualifiedSizingDensity(V17_CONSTRUCTION_GRAPH, profiles),
  );
  const status = canonicalV17Json(allocationGeometry(allocation)) ===
    canonicalV17Json(allocationGeometry(measuredAllocation))
    ? "fixed-point"
    : "requires-resizing";
  if (status === "fixed-point") {
    console.log(JSON.stringify({
      schema: "ShieldKit/V17RetainedSizingDiagnostic/v1",
      status: "fixed-point-diagnostic-only-not-qualification-evidence",
      checkpoint: basename(checkpointRoot),
      reserveFixedPrefix,
      inlineFamilies: [...inlineFamilies],
      inlineRoleCounts: Object.fromEntries(inlineRoleCounts),
      protocolIdHex: v17ProtocolIdHex(),
      proofBytes: proofs.map(({ proofBytes }) => proofBytes.length),
      passes: pass,
      minimumProofBytes: measuredAllocation.minimumProofBytes,
      maximumProofBytes: measuredAllocation.maximumProofBytes,
      familyRows,
      topRoles,
    }, null, 2));
    process.exit(0);
  }
  allocation = measuredAllocation;
}
throw new Error("v17 retained diagnostic allocation did not converge in 32 passes");

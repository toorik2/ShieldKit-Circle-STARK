import { createHash } from "node:crypto";
import { binToHex, encodeLockingBytecodeP2sh32, hash256 } from "@bitauth/libauth";
import {
  compileLocalWordPoolCarrierRedeem,
  encodeLocalWordP2shBatchLeaderUnlocking,
  encodeLocalWordP2shCarrierUnlocking,
  LOCAL_WORD_BATCH_LEADER_ROLE_ID,
  localWordPoolCarrierSequence,
  localWordVerifierBankDigestFromInputs,
  localWordVerifierCarrierSequence,
  localWordVerifierCarrierValue,
  reassembleLocalWordProofBytes,
} from "../chain/local-word-proof-carriers.ts";
import { encodeV17BatchLeaderCell } from
  "../backends/circle/v17-batch-leader-cell.ts";
import { compileLocalWordValueSettlementGate } from "../chain/local-word-balanced-vm.ts";
import {
  measuredV17AffineAllocation,
  validateV17AffineAllocation,
} from "../chain/v17-affine-allocation.ts";
import { validateV17AffineReaderConstruction } from
  "../chain/v17-affine-reader-vm.ts";
import { validateV17RomPage, type V17RomPage } from "../chain/v17-code-rom.ts";
import { V17_PRODUCTION_ROLE_LAYOUT } from "../chain/v17-role-layout.ts";
import {
  V17_PROFILES,
  canonicalV17Json,
  v17ConstructionIdHex,
  v17ProtocolIdHex,
  type V17Profile,
} from "../construction/v17-graph.ts";
import type {
  V17FinalInfrastructureSet,
  V17FinalProfileInfrastructure,
} from "../construction/v17-product-link.ts";
import {
  allocateV17DensityClosure,
  validateV17DensityClosure,
  validateV17DensityRows,
  v17DensityClosureDominates,
} from "../construction/v17-density-closure.ts";

export const V17_FINAL_INFRASTRUCTURE_IDENTITY_SCHEMA =
  "ShieldKit/V17FinalInfrastructureIdentity/v1" as const;

export type V17FinalInfrastructureProfileIdentity = {
  readonly profile: V17Profile;
  readonly bankDigestHex: string;
  readonly proofBytes: number;
  readonly proofSha256Hex: string;
  readonly infrastructureInputs: number;
  readonly romPages: number;
  /** Hash of every exact lock, unlock, value, sequence, kind, index, and role id. */
  readonly infrastructureInventorySha256Hex: string;
};

export type V17FinalInfrastructureIdentityBody = {
  readonly schema: typeof V17_FINAL_INFRASTRUCTURE_IDENTITY_SCHEMA;
  readonly status: "identity-replayed-not-qualified";
  readonly protocolIdHex: string;
  readonly constructionIdHex: string;
  readonly linkerCertificateIdHex: string;
  readonly romPreviewIdHex: string;
  readonly profiles: readonly [
    V17FinalInfrastructureProfileIdentity,
    V17FinalInfrastructureProfileIdentity,
    V17FinalInfrastructureProfileIdentity,
  ];
};

export type V17FinalInfrastructureIdentity = V17FinalInfrastructureIdentityBody & {
  readonly identitySha256Hex: string;
};

function equal(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((byte, index) => byte === right[index]);
}

function sha256Hex(bytes: Uint8Array | string): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function hex32(label: string, value: string): void {
  if (!/^[0-9a-f]{64}$/.test(value)) throw new Error(`v17 final identity ${label}`);
}

function u32be(value: number): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff_ffff) {
    throw new Error("v17 final identity u32");
  }
  return Uint8Array.of(value >>> 24, value >>> 16, value >>> 8, value);
}

function concat(...parts: readonly Uint8Array[]): Uint8Array {
  const result = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

/** The linker's certificate hash language, repeated here as an assurance replay. */
function linkerDomainHash(domain: string, value: unknown): string {
  const domainBytes = new TextEncoder().encode(domain);
  const payload = new TextEncoder().encode(canonicalV17Json(value));
  return sha256Hex(concat(u32be(domainBytes.length), domainBytes, u32be(payload.length), payload));
}

function romDescription(page: V17RomPage) {
  validateV17RomPage(page);
  return {
    pageIndex: page.pageIndex,
    inputIndex: page.inputIndex,
    outputIndex: page.outputIndex,
    valueSatoshis: page.valueSatoshis.toString(),
    sequenceNumber: page.sequenceNumber,
    payloadSha256Hex: page.payloadSha256Hex,
    redeemSha256Hex: sha256Hex(page.redeemBytecode),
    lockingBytecodeHex: binToHex(page.lockingBytecode),
    payloadBytes: page.payload.length,
    redeemBytes: page.redeemBytecode.length,
    unlockingBytes: page.unlockingBytecode.length,
    functionIds: page.entries.map((entry) => entry.functionIdHex),
    bodySha256Hexes: page.entries.map((entry) => entry.bodySha256Hex),
  };
}

function sameCanonical(left: unknown, right: unknown): boolean {
  return canonicalV17Json(left) === canonicalV17Json(right);
}

function allocationGeometry(allocation: ReturnType<typeof validateV17AffineAllocation>) {
  return {
    status: allocation.status,
    minimumProofBytes: allocation.minimumProofBytes,
    maximumProofBytes: allocation.maximumProofBytes,
    elasticScaleUnits: allocation.elasticScaleUnits,
    assignments: allocation.assignments.map((assignment) => ({
      roleId: assignment.roleId,
      basePrefixStart: assignment.basePrefixStart,
      basePrefixEnd: assignment.basePrefixEnd,
      elasticPrefixStart: assignment.elasticPrefixStart,
      elasticPrefixEnd: assignment.elasticPrefixEnd,
    })),
  };
}

function assertPageCopies(
  profile: V17Profile,
  expected: readonly V17RomPage[],
  actual: readonly V17RomPage[],
): void {
  if (actual.length !== expected.length || actual.some((page, index) =>
    !sameCanonical(romDescription(page), romDescription(expected[index]!)))) {
    throw new Error(`v17 final identity ROM copy ${profile}`);
  }
}

function inventoryDigest(profile: V17FinalProfileInfrastructure): string {
  return sha256Hex(canonicalV17Json({
    profile: profile.profile,
    rows: profile.infrastructure.map((row) => ({
      kind: row.kind,
      index: row.index,
      roleId: row.roleId,
      lockingBytecodeHex: binToHex(row.lockingBytecode),
      unlockingBytecodeHex: binToHex(row.unlockingBytecode),
      valueSatoshis: row.valueSatoshis === null ? null : row.valueSatoshis.toString(),
      sequenceNumber: row.sequenceNumber,
    })),
  }));
}

function replayProfile(args: {
  readonly finalSet: V17FinalInfrastructureSet;
  readonly profile: V17Profile;
  readonly settlementRedeem: Uint8Array;
}): V17FinalInfrastructureProfileIdentity {
  const { finalSet, profile, settlementRedeem } = args;
  const row = finalSet.profiles[profile]!;
  const certificate = finalSet.construction.certificate;
  const allocation = measuredV17AffineAllocation(certificate.allocation);
  const pages = finalSet.construction.pages;
  if (row.schema !== "ShieldKit/V17FinalProfileInfrastructure/v1" ||
    row.status !== "materialized-requires-final-bchn-qualification" ||
    row.profile !== profile || row.constructionIdHex !== certificate.constructionIdHex ||
    row.bankDigestHex !== certificate.profiles[profile]!.bankDigestHex ||
    !sameCanonical(
      allocationGeometry(validateV17AffineAllocation(row.allocation)),
      allocationGeometry(validateV17AffineAllocation(allocation)),
    ) ||
    row.roles.length !== V17_PRODUCTION_ROLE_LAYOUT.length ||
    row.infrastructure.length !== V17_PRODUCTION_ROLE_LAYOUT.length + pages.length) {
    throw new Error(`v17 final identity profile envelope ${profile}`);
  }
  assertPageCopies(profile, pages, row.pages);

  const proofBytes = reassembleLocalWordProofBytes(
    row.roles.map((role) => role.carrier),
    allocation,
  );
  const protocolId = new Uint8Array(Buffer.from(certificate.protocolIdHex, "hex"));
  if (proofBytes[5] !== profile || !equal(proofBytes.subarray(6, 38), protocolId)) {
    throw new Error(`v17 final identity proof header ${profile}`);
  }
  const batchLeaderCell = encodeV17BatchLeaderCell(proofBytes);

  row.roles.forEach((role, index) => {
    const layout = V17_PRODUCTION_ROLE_LAYOUT[index]!;
    const expectedRedeem = index === 0
      ? settlementRedeem
      : finalSet.construction.workersByProfile[profile]![index]!.redeemBytecode;
    const expectedUnlocking = role.name === LOCAL_WORD_BATCH_LEADER_ROLE_ID
      ? encodeLocalWordP2shBatchLeaderUnlocking(
        role.carrier.chunk,
        batchLeaderCell,
        expectedRedeem,
      )
      : encodeLocalWordP2shCarrierUnlocking(role.carrier.chunk, expectedRedeem);
    if (role.index !== index || role.name !== layout.id ||
      !equal(role.redeem, expectedRedeem) ||
      !equal(role.unlockingBytecode, expectedUnlocking)) {
      throw new Error(`v17 final identity role ${profile}:${layout.id}`);
    }
  });

  row.infrastructure.forEach((infrastructure, index) => {
    if (infrastructure.index !== index) {
      throw new Error(`v17 final identity infrastructure order ${profile}:${index}`);
    }
    if (index < row.roles.length) {
      const role = row.roles[index]!;
      const expectedValue = index === 0 ? null : localWordVerifierCarrierValue(index, allocation);
      const expectedSequence = index === 0
        ? localWordPoolCarrierSequence(proofBytes.length, allocation)
        : localWordVerifierCarrierSequence(index, allocation);
      if (infrastructure.kind !== (index === 0 ? "pool" : "proof-worker") ||
        infrastructure.roleId !== role.name || infrastructure.valueSatoshis !== expectedValue ||
        infrastructure.sequenceNumber !== expectedSequence ||
        !equal(infrastructure.lockingBytecode,
          encodeLockingBytecodeP2sh32(hash256(role.redeem))) ||
        !equal(infrastructure.unlockingBytecode, role.unlockingBytecode)) {
        throw new Error(`v17 final identity infrastructure role ${profile}:${index}`);
      }
      if (index > 0) {
        const linked = finalSet.construction.workersByProfile[profile]![index]!;
        if (linked.profile !== profile || linked.logicalInputIndex !== index ||
          linked.roleId !== role.name || linked.linkedRedeemSha256Hex !== sha256Hex(role.redeem) ||
          !equal(linked.redeemBytecode, role.redeem) ||
          !equal(linked.lockingBytecode, infrastructure.lockingBytecode) ||
          !equal(linked.unlockingBytecode, role.unlockingBytecode) ||
          linked.valueSatoshis !== expectedValue || linked.sequenceNumber !== expectedSequence) {
          throw new Error(`v17 final identity linked worker ${profile}:${index}`);
        }
      }
      return;
    }
    const page = pages[index - row.roles.length]!;
    if (infrastructure.kind !== "rom-page" ||
      infrastructure.roleId !== `rom-page:${page.pageIndex}` ||
      infrastructure.valueSatoshis !== page.valueSatoshis ||
      infrastructure.sequenceNumber !== page.sequenceNumber ||
      infrastructure.index !== page.inputIndex || page.outputIndex !== page.inputIndex ||
      !equal(infrastructure.lockingBytecode, page.lockingBytecode) ||
      !equal(infrastructure.unlockingBytecode, page.unlockingBytecode)) {
      throw new Error(`v17 final identity ROM infrastructure ${profile}:${page.pageIndex}`);
    }
  });

  const bankDigest = localWordVerifierBankDigestFromInputs(profile,
    row.infrastructure.slice(1).map((role) => {
      if (role.valueSatoshis === null) {
        throw new Error(`v17 final identity bank value ${profile}:${role.index}`);
      }
      return {
        lockingBytecode: role.lockingBytecode,
        valueSatoshis: role.valueSatoshis,
        sequenceNumber: role.sequenceNumber,
      };
    }));
  const bankDigestHex = binToHex(bankDigest);
  if (bankDigestHex !== row.bankDigestHex ||
    !equal(bankDigest, finalSet.authorizedBankDigests[profile]!)) {
    throw new Error(`v17 final identity bank digest ${profile}`);
  }
  return {
    profile,
    bankDigestHex,
    proofBytes: proofBytes.length,
    proofSha256Hex: sha256Hex(proofBytes),
    infrastructureInputs: row.infrastructure.length,
    romPages: pages.length,
    infrastructureInventorySha256Hex: inventoryDigest(row),
  };
}

/**
 * Replay the complete construction-to-infrastructure identity boundary.
 * This certifies identity only: BCHN execution and transaction validity remain
 * separate mandatory gates.
 */
export function replayV17FinalInfrastructureIdentity(
  finalSet: V17FinalInfrastructureSet,
): V17FinalInfrastructureIdentity {
  if (finalSet.schema !== "ShieldKit/V17FinalInfrastructureSet/v1" ||
    finalSet.status !== "materialized-requires-final-bchn-qualification" ||
    finalSet.qualification !== "not-qualified-until-final-transactions-pass") {
    throw new Error("v17 final identity set envelope");
  }
  const construction = finalSet.construction;
  const certificate = construction.certificate;
  const protocolIdHex = v17ProtocolIdHex();
  if (certificate.schema !== "ShieldKit/V17LinkerCertificate/v3" ||
    certificate.status !== "post-link-measured" ||
    certificate.qualification !== "construction-only-not-qualified" ||
    certificate.protocolIdHex !== protocolIdHex ||
    construction.verifierPlan.protocolIdHex !== protocolIdHex ||
    construction.verifierPlan.allocation.status !== "measured" ||
    construction.verifierPlan.rom.status !== "measured" ||
    certificate.profiles.length !== V17_PROFILES.length ||
    certificate.profiles.some((profile, index) => profile.profile !== V17_PROFILES[index]) ||
    finalSet.profiles.length !== V17_PROFILES.length ||
    finalSet.profiles.some((profile, index) => profile.profile !== V17_PROFILES[index]) ||
    construction.workersByProfile.length !== V17_PROFILES.length ||
    construction.workersByProfile.some((workers) =>
      workers.length !== V17_PRODUCTION_ROLE_LAYOUT.length)) {
    throw new Error("v17 final identity construction envelope");
  }
  [
    certificate.protocolIdHex,
    certificate.romPreviewIdHex,
    certificate.measurementEvidenceDigestHex,
    certificate.terminalMeasurementRowsSha256Hex,
    certificate.densityClosureSha256Hex,
    certificate.densityTraceRootSha256Hex,
    certificate.allocationDigestHex,
    certificate.constructionIdHex,
    certificate.certificateIdHex,
  ].forEach((hex, index) => hex32(`certificate hex ${index}`, hex));
  const closure = validateV17DensityClosure(certificate.densityClosure);
  validateV17DensityRows(certificate.terminalMeasurementRows);
  if (certificate.densityClosureSha256Hex !== closure.closureSha256Hex ||
    !v17DensityClosureDominates(closure, certificate.terminalMeasurementRows) ||
    !sameCanonical(certificate.allocation, allocateV17DensityClosure(closure))) {
    throw new Error("v17 final identity density closure");
  }
  validateV17AffineAllocation(measuredV17AffineAllocation(certificate.allocation));
  if (certificate.allocationDigestHex !== linkerDomainHash(
    "ShieldKit/V17DensityAllocation/v3",
    certificate.allocation,
  )) {
    throw new Error("v17 final identity allocation digest");
  }
  if (certificate.terminalMeasurementRowsSha256Hex !== linkerDomainHash(
    "ShieldKit/V17TerminalDensityMeasurementRows/v1",
    certificate.terminalMeasurementRows,
  )) {
    throw new Error("v17 final identity terminal measurement rows");
  }
  const describedPages = construction.pages.map(romDescription);
  if (!sameCanonical(describedPages, certificate.romPages) ||
    construction.pages.some((page, index) =>
      page.pageIndex !== index || page.inputIndex !== V17_PRODUCTION_ROLE_LAYOUT.length + index ||
      page.outputIndex !== page.inputIndex)) {
    throw new Error("v17 final identity certificate ROM");
  }
  const { certificateIdHex, ...certificateCore } = certificate;
  if (certificateIdHex !== linkerDomainHash(
    "ShieldKit/V17LinkerCertificateId/v3",
    certificateCore,
  )) {
    throw new Error("v17 final identity certificate digest");
  }
  const bankDigestHexes = certificate.profiles.map(({ bankDigestHex }) => bankDigestHex) as
    unknown as readonly [string, string, string];
  bankDigestHexes.forEach((hex, profile) => hex32(`bank digest ${profile}`, hex));
  if (certificate.constructionIdHex !== v17ConstructionIdHex({
    protocolIdHex,
    bankDigests: bankDigestHexes,
  })) {
    throw new Error("v17 final identity construction digest");
  }
  const affineReader = construction.affineReader;
  if (affineReader === null) {
    throw new Error("v17 final identity missing affine reader construction");
  }
  const reader = validateV17AffineReaderConstruction(affineReader);
  if (!sameCanonical(reader.allocation, measuredV17AffineAllocation(certificate.allocation)) ||
    !sameCanonical(reader.evidence, certificate.affineReader)) {
    throw new Error("v17 final identity affine reader");
  }
  const settlementRedeem = compileLocalWordPoolCarrierRedeem(
    compileLocalWordValueSettlementGate(finalSet.authorizedBankDigests, reader.vm),
  );
  const profiles = V17_PROFILES.map((profile) => replayProfile({
    finalSet,
    profile,
    settlementRedeem,
  })) as unknown as V17FinalInfrastructureIdentityBody["profiles"];
  const body: V17FinalInfrastructureIdentityBody = {
    schema: V17_FINAL_INFRASTRUCTURE_IDENTITY_SCHEMA,
    status: "identity-replayed-not-qualified",
    protocolIdHex,
    constructionIdHex: certificate.constructionIdHex,
    linkerCertificateIdHex: certificate.certificateIdHex,
    romPreviewIdHex: certificate.romPreviewIdHex,
    profiles,
  };
  return { ...body, identitySha256Hex: sha256Hex(canonicalV17Json(body)) };
}

export function assertV17FinalInfrastructureIdentity(
  identity: V17FinalInfrastructureIdentity,
): void {
  const { identitySha256Hex, ...body } = identity;
  if (!/^[0-9a-f]{64}$/.test(identitySha256Hex) ||
    identitySha256Hex !== sha256Hex(canonicalV17Json(body)) ||
    body.schema !== V17_FINAL_INFRASTRUCTURE_IDENTITY_SCHEMA ||
    body.status !== "identity-replayed-not-qualified" ||
    body.protocolIdHex !== v17ProtocolIdHex() ||
    body.profiles.length !== V17_PROFILES.length ||
    body.profiles.some((profile, index) => profile.profile !== V17_PROFILES[index])) {
    throw new Error("v17 final infrastructure identity integrity");
  }
  [body.constructionIdHex, body.linkerCertificateIdHex, body.romPreviewIdHex,
    ...body.profiles.flatMap((profile) => [
      profile.bankDigestHex,
      profile.proofSha256Hex,
      profile.infrastructureInventorySha256Hex,
    ])].forEach((hex) => hex32("identity digest", hex));
}

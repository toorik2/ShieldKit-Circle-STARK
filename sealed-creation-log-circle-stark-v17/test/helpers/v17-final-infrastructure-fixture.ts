import { createHash } from "node:crypto";
import { binToHex, encodeLockingBytecodeP2sh32, hash256 } from "@bitauth/libauth";
import { compileLocalWordValueSettlementGate } from
  "../../src/chain/local-word-balanced-vm.ts";
import {
  compileLocalWordBatchLeaderCarrierRedeem,
  compileLocalWordPoolCarrierRedeem,
  encodeLocalWordP2shBatchLeaderUnlocking,
  encodeLocalWordP2shCarrierUnlocking,
  LOCAL_WORD_BATCH_LEADER_ROLE_ID,
  localWordPoolCarrierSequence,
  localWordVerifierBankDigestFromInputs,
  localWordVerifierCarrierSequence,
  localWordVerifierCarrierValue,
  partitionLocalWordProofBytes,
  type LocalWordVerifierBankDigests,
} from "../../src/chain/local-word-proof-carriers.ts";
import { encodeV17BatchLeaderCell } from
  "../../src/backends/circle/v17-batch-leader-cell.ts";
import { v17ProofFrameOffset } from
  "../../src/backends/circle/v17-proof-layout.ts";
import {
  measuredV17AffineAllocation,
} from "../../src/chain/v17-affine-allocation.ts";
import { compileV17AffineReaderConstruction } from
  "../../src/chain/v17-affine-reader-vm.ts";
import { createV17RomPage } from "../../src/chain/v17-code-rom.ts";
import { V17_PRODUCTION_ROLE_LAYOUT } from "../../src/chain/v17-role-layout.ts";
import {
  V17_PROFILES,
  buildV17VerifierPlan,
  canonicalV17Json,
  v17ConstructionIdHex,
  v17ProtocolIdHex,
  type V17Profile,
} from "../../src/construction/v17-graph.ts";
import type {
  V17FinalInfrastructureSet,
  V17FinalProfileInfrastructure,
} from "../../src/construction/v17-product-link.ts";
import {
  allocateV17DensityClosure,
  createV17DensityClosure,
} from "../../src/construction/v17-density-closure.ts";
import {
  LOCAL_WORD_PROOF_LENGTH_OFFSET,
  LOCAL_WORD_PROOF_VERSION,
} from "../../src/backends/circle/local-word-sealed-proof.ts";
import { writeU32BE } from "../../src/pool/bytes.ts";

// Consume the canonical proof-slice stack item, then succeed under P2SH
// clean-stack rules. A bare OP_TRUE is not an executable carrier verifier.
const TRUE_REDEEM = Uint8Array.of(0x75, 0x51);
const ROM_PAGES = 2;

function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function u32be(value: number): Uint8Array {
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

// The specialized wrapper leaves cell, chunk for query zero's verifier. The
// retained inert push keeps this fake linked redeem in the production size class.
const BATCH_LEADER_TRUE_VERIFIER = concat(
  Uint8Array.of(0x6d, 0x4d, 0x2c, 0x01), // OP_2DROP PUSHDATA2(300)
  new Uint8Array(300),
  Uint8Array.of(0x75, 0x51), // OP_DROP OP_TRUE
);

function linkerDomainHash(domain: string, value: unknown): string {
  const domainBytes = new TextEncoder().encode(domain);
  const payload = new TextEncoder().encode(canonicalV17Json(value));
  return sha256Hex(concat(u32be(domainBytes.length), domainBytes, u32be(payload.length), payload));
}

const terminalMeasurementRows = V17_PRODUCTION_ROLE_LAYOUT.map((role, index) => ({
  roleId: role.id,
  requiredProofBytes: 256,
  capacityProofBytes: 9_000,
  maximumOperationCost: 1_000 + index,
  profileOperationCosts: [1_000 + index, 1_000 + index, 1_000 + index] as const,
  profileRequiredProofBytes: [256, 256, 256] as const,
  profileCapacityProofBytes: [9_000, 9_000, 9_000] as const,
}));
const densityClosure = createV17DensityClosure(terminalMeasurementRows);
const certificateAllocation = allocateV17DensityClosure(densityClosure);
const allocation = measuredV17AffineAllocation(certificateAllocation);
const protocolIdHex = v17ProtocolIdHex();
const pages = Array.from({ length: ROM_PAGES }, (_, pageIndex) => createV17RomPage({
  pageIndex,
  inputIndex: V17_PRODUCTION_ROLE_LAYOUT.length + pageIndex,
  outputIndex: V17_PRODUCTION_ROLE_LAYOUT.length + pageIndex,
  entries: [{
    functionId: Uint8Array.of(pageIndex + 1),
    body: Uint8Array.of(0x51, pageIndex),
  }],
}));

function proof(profile: V17Profile): Uint8Array {
  const bytes = new Uint8Array(allocation.minimumProofBytes);
  bytes.set(new TextEncoder().encode("SKLW"), 0);
  bytes[4] = LOCAL_WORD_PROOF_VERSION;
  bytes[5] = profile;
  bytes.set(Buffer.from(protocolIdHex, "hex"), 6);
  bytes.set(writeU32BE(bytes.length), LOCAL_WORD_PROOF_LENGTH_OFFSET);
  const nonceOffset = v17ProofFrameOffset("roundNonce:air:ood");
  for (let nonce = 0; nonce < 256; nonce += 1) {
    bytes.set(writeU32BE(nonce), nonceOffset);
    try {
      encodeV17BatchLeaderCell(bytes);
      return bytes;
    } catch (error) {
      if (!String(error).includes("OODS nonce")) throw error;
    }
  }
  throw new Error("v17 final infrastructure fixture OODS nonce");
}

function provisionalProfile(profile: V17Profile) {
  const proofBytes = proof(profile);
  const carriers = partitionLocalWordProofBytes(proofBytes, allocation);
  const leaderCell = encodeV17BatchLeaderCell(proofBytes);
  const roles = carriers.map((carrier, index) => {
    const name = V17_PRODUCTION_ROLE_LAYOUT[index]!.id;
    const leader = name === LOCAL_WORD_BATCH_LEADER_ROLE_ID;
    const verifier = leader ? BATCH_LEADER_TRUE_VERIFIER : TRUE_REDEEM;
    const redeem = leader
      ? compileLocalWordBatchLeaderCarrierRedeem({ index, verifier })
      : TRUE_REDEEM;
    return {
      index,
      name,
      carrier,
      verifier,
      redeem,
      unlockingBytecode: leader
        ? encodeLocalWordP2shBatchLeaderUnlocking(carrier.chunk, leaderCell, redeem)
        : encodeLocalWordP2shCarrierUnlocking(carrier.chunk, redeem),
    };
  });
  const infrastructure = [
    ...roles.map((role, index) => ({
      kind: (index === 0 ? "pool" : "proof-worker") as "pool" | "proof-worker",
      index,
      roleId: role.name,
      lockingBytecode: encodeLockingBytecodeP2sh32(hash256(role.redeem)),
      unlockingBytecode: role.unlockingBytecode,
      valueSatoshis: index === 0 ? null : localWordVerifierCarrierValue(index, allocation),
      sequenceNumber: index === 0
        ? localWordPoolCarrierSequence(proofBytes.length, allocation)
        : localWordVerifierCarrierSequence(index, allocation),
    })),
    ...pages.map((page) => ({
      kind: "rom-page" as const,
      index: page.inputIndex,
      roleId: `rom-page:${page.pageIndex}`,
      lockingBytecode: page.lockingBytecode,
      unlockingBytecode: page.unlockingBytecode,
      valueSatoshis: page.valueSatoshis,
      sequenceNumber: page.sequenceNumber,
    })),
  ];
  const bankDigest = localWordVerifierBankDigestFromInputs(profile,
    infrastructure.slice(1).map((role) => ({
      lockingBytecode: role.lockingBytecode,
      valueSatoshis: role.valueSatoshis!,
      sequenceNumber: role.sequenceNumber,
    })));
  return { profile, proofBytes, roles, infrastructure, bankDigest };
}

function describePage(page: typeof pages[number]) {
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

/** A structurally exact, semantically trivial construction used only by assurance tests. */
export function fakeV17FinalInfrastructureSet(): V17FinalInfrastructureSet {
  const provisional = V17_PROFILES.map(provisionalProfile);
  const authorizedBankDigests = provisional.map(({ bankDigest }) => bankDigest) as unknown as
    LocalWordVerifierBankDigests;
  const bankDigestHexes = authorizedBankDigests.map(binToHex) as unknown as
    readonly [string, string, string];
  const constructionIdHex = v17ConstructionIdHex({ protocolIdHex, bankDigests: bankDigestHexes });
  const certifiedAllocation = measuredV17AffineAllocation(certificateAllocation);
  const affineReader = compileV17AffineReaderConstruction(certifiedAllocation);
  const settlementVerifier = compileLocalWordValueSettlementGate(
    authorizedBankDigests,
    affineReader.vm,
  );
  const settlementRedeem = compileLocalWordPoolCarrierRedeem(settlementVerifier);
  const settlementLock = encodeLockingBytecodeP2sh32(hash256(settlementRedeem));
  const finalProfiles = provisional.map((candidate): V17FinalProfileInfrastructure => {
    const settlementRole = {
      ...candidate.roles[0]!,
      verifier: settlementVerifier,
      redeem: settlementRedeem,
      unlockingBytecode: encodeLocalWordP2shCarrierUnlocking(
        candidate.roles[0]!.carrier.chunk,
        settlementRedeem,
      ),
    };
    const roles = [settlementRole, ...candidate.roles.slice(1)];
    return {
      schema: "ShieldKit/V17FinalProfileInfrastructure/v1",
      status: "materialized-requires-final-bchn-qualification",
      profile: candidate.profile,
      constructionIdHex,
      bankDigestHex: binToHex(candidate.bankDigest),
      allocation: certifiedAllocation,
      roles,
      pages,
      infrastructure: [{
        ...candidate.infrastructure[0]!,
        lockingBytecode: settlementLock,
        unlockingBytecode: settlementRole.unlockingBytecode,
      }, ...candidate.infrastructure.slice(1)],
    };
  }) as unknown as V17FinalInfrastructureSet["profiles"];
  const certificateProfiles = V17_PROFILES.map((profile) => ({
    profile,
    baselineRelevantBytes: 900_000,
    linkedRelevantBytes: 800_000,
    strictSavingBytes: 100_000,
    bankDigestHex: bankDigestHexes[profile]!,
  }));
  const certificateCore = {
    schema: "ShieldKit/V17LinkerCertificate/v3" as const,
    status: "post-link-measured" as const,
    qualification: "construction-only-not-qualified" as const,
    protocolIdHex,
    affineReader: affineReader.evidence,
    romPreviewIdHex: "72".repeat(32),
    measurementEvidenceDigestHex: "73".repeat(32),
    terminalMeasurementRowsSha256Hex: linkerDomainHash(
      "ShieldKit/V17TerminalDensityMeasurementRows/v1",
      terminalMeasurementRows,
    ),
    terminalMeasurementRows,
    densityClosureSha256Hex: densityClosure.closureSha256Hex,
    densityClosure,
    densityTraceRootSha256Hex: "74".repeat(32),
    allocationDigestHex: linkerDomainHash(
      "ShieldKit/V17DensityAllocation/v3",
      certificateAllocation,
    ),
    allocation: certificateAllocation,
    census: {
      staticDefinitionOccurrences: 0,
      exactBodyClasses: 0,
      promotedBodySha256Hexes: pages.flatMap((page) =>
        page.entries.map((entry) => entry.bodySha256Hex)),
    },
    romPages: pages.map(describePage),
    profiles: certificateProfiles,
    constructionIdHex,
  };
  const certificate = {
    ...certificateCore,
    certificateIdHex: linkerDomainHash(
      "ShieldKit/V17LinkerCertificateId/v3",
      certificateCore,
    ),
  };
  const plan = buildV17VerifierPlan();
  const workersByProfile = finalProfiles.map((profile) => profile.roles.map((role, index) => ({
    profile: profile.profile,
    logicalInputIndex: index,
    roleId: role.name,
    baselineRedeemSha256Hex: sha256Hex(role.redeem),
    linkedRedeemSha256Hex: sha256Hex(role.redeem),
    redeemBytecode: role.redeem,
    lockingBytecode: encodeLockingBytecodeP2sh32(hash256(role.redeem)),
    unlockingBytecode: role.unlockingBytecode,
    valueSatoshis: index === 0 ? 0n : localWordVerifierCarrierValue(index, allocation),
    sequenceNumber: index === 0
      ? localWordPoolCarrierSequence(role.carrier.proofLength, allocation)
      : localWordVerifierCarrierSequence(index, allocation),
  })));
  return {
    schema: "ShieldKit/V17FinalInfrastructureSet/v1",
    status: "materialized-requires-final-bchn-qualification",
    qualification: "not-qualified-until-final-transactions-pass",
    construction: {
      certificate,
      affineReader,
      verifierPlan: {
        ...plan,
        allocation: {
          ...plan.allocation,
          status: "measured",
          minimumProofBytes: allocation.minimumProofBytes,
          assignments: certificateAllocation.map((assignment) => ({
            roleId: assignment.roleId,
            basePrefixStart: assignment.basePrefixStart,
            basePrefixEnd: assignment.basePrefixEnd,
            elasticPrefixStart: assignment.elasticPrefixStart,
            elasticPrefixEnd: assignment.elasticPrefixEnd,
            requiredProofBytes: assignment.requiredProofBytes,
            capacityProofBytes: assignment.capacityProofBytes,
            maximumOperationCost: assignment.maximumOperationCost,
          })),
        },
        rom: {
          ...plan.rom,
          status: "measured",
          pages: pages.map((page) => ({
            index: page.pageIndex,
            inputIndex: page.inputIndex,
            outputIndex: page.outputIndex,
            sha256Hex: page.payloadSha256Hex,
            bytes: page.payload.length,
            functionIds: page.entries.map((entry) => entry.functionIdHex),
          })),
        },
      },
      pages,
      workersByProfile,
    },
    authorizedBankDigests,
    profiles: finalProfiles,
  } as V17FinalInfrastructureSet;
}

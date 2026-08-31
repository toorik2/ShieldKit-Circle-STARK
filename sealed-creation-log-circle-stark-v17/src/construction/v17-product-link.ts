import { createHash } from "node:crypto";
import { binToHex, encodeLockingBytecodeP2sh32, hash256 } from "@bitauth/libauth";
import {
  compileLocalWordValueSettlementGate,
} from "../chain/local-word-balanced-vm.ts";
import {
  compileLocalWordVerifierPrograms,
  type LocalWordVerifierProgram,
  type LocalWordVerifierRole,
} from "../chain/local-word-role-manifest.ts";
import {
  compileLocalWordPoolCarrierRedeem,
  encodeLocalWordBatchLeaderUnlockingPrefix,
  encodeLocalWordP2shBatchLeaderUnlocking,
  encodeLocalWordP2shCarrierUnlocking,
  LOCAL_WORD_BATCH_LEADER_ROLE_ID,
  localWordPoolCarrierSequence,
  localWordVerifierBankDigestFromInputs,
  localWordVerifierBankDigestFromRedeems,
  localWordVerifierCarrierSequence,
  localWordVerifierCarrierValue,
  partitionLocalWordProofBytes,
  type LocalWordVerifierBankDigests,
} from "../chain/local-word-proof-carriers.ts";
import {
  encodeV17BatchLeaderCell,
  V17_BATCH_LEADER_CELL_BYTES,
} from "../backends/circle/v17-batch-leader-cell.ts";
import {
  V17_BOOTSTRAP_AFFINE_ALLOCATION,
  measuredV17AffineAllocation,
  type V17AffineAllocation,
} from "../chain/v17-affine-allocation.ts";
import {
  compileV17AffineReaderConstruction,
  validateV17AffineReaderConstruction,
  type V17AffineReaderConstruction,
} from "../chain/v17-affine-reader-vm.ts";
import {
  encodeV17CanonicalPush,
  type V17RomPage,
} from "../chain/v17-code-rom.ts";
import { V17_PRODUCTION_ROLE_LAYOUT } from "../chain/v17-role-layout.ts";
import {
  V17_CONSTRUCTION_GRAPH,
  V17_PROFILES,
  canonicalV17Json,
  v17ConstructionIdHex,
  v17ProtocolIdHex,
  type V17Profile,
} from "./v17-graph.ts";
import {
  V17_INPUT_FIXED_DENSITY_BYTES,
  assessV17Density,
  certifyV17LinkedConstruction,
  previewV17Rom,
  v17PostLinkMeasurementEvidenceDigestHex,
  v17DefinePoliciesForRole,
  type V17LinkedConstruction,
  type V17PostLinkMeasuredProfile,
  type V17PreLinkProgramProfile,
  type V17RomPreview,
} from "./v17-linker.ts";
import {
  appendV17DensityClosureTrace,
  replayV17DensityClosureTrace,
  validateV17DensityClosure,
  v17DensityClosureDominates,
  type V17DensityClosure,
  type V17DensityClosureTrace,
  type V17DensityFeasibilityRow,
} from "./v17-density-closure.ts";

export type V17VerifierKeyMaterial = {
  readonly profile: V17Profile;
  /** The transcript/proof protocol identifier; retained under the compiler's historical name. */
  readonly constructionId: Uint8Array;
  readonly constructionDigest: Uint8Array;
  readonly expectedPreprocessedRoot: Uint8Array;
};

export type V17ProfileProofMaterial = V17VerifierKeyMaterial & {
  readonly proofBytes: Uint8Array;
};

type V17ProgramRole = LocalWordVerifierProgram;

export type V17PreLinkProduct = {
  readonly schema: "ShieldKit/V17PreLinkProduct/v1";
  readonly status: "program-census-only";
  readonly qualification: "non-executable-non-measurement";
  readonly protocolIdHex: string;
  /** Allocation-bound construction code; deliberately absent from the proof protocol graph. */
  readonly affineReader: V17AffineReaderConstruction;
  readonly provisionalBankDigests: LocalWordVerifierBankDigests;
  readonly profiles: readonly [
    V17PreLinkProgramProfile,
    V17PreLinkProgramProfile,
    V17PreLinkProgramProfile,
  ];
  readonly programsByProfile: readonly [
    readonly V17ProgramRole[],
    readonly V17ProgramRole[],
    readonly V17ProgramRole[],
  ];
};

export type V17RomLinkStage = V17PreLinkProduct & {
  readonly preview: V17RomPreview;
};

export type V17PostLinkCandidateProfile = {
  readonly schema: "ShieldKit/V17PostLinkCandidateProfile/v1";
  readonly status: "candidate-envelope-requires-independent-bchn-measurement";
  readonly romPreviewIdHex: string;
  /** Exact linked identity used by candidate and final synthetic outpoints. */
  readonly constructionIdHex: string;
  readonly profile: V17Profile;
  readonly allocationStatus: V17AffineAllocation["status"];
  readonly allocation: V17AffineAllocation;
  readonly projectedInputCount: number;
  readonly projectedOutputCount: number;
  readonly proofBytes: Uint8Array;
  readonly roles: readonly LocalWordVerifierRole[];
  readonly pages: readonly V17RomPage[];
};

export type V17PostLinkCandidateSet = {
  readonly schema: "ShieldKit/V17PostLinkCandidateSet/v1";
  readonly status: "candidate-envelope-requires-independent-bchn-measurement";
  readonly constructionIdHex: string;
  readonly preview: V17RomPreview;
  readonly profiles: readonly [
    V17PostLinkCandidateProfile,
    V17PostLinkCandidateProfile,
    V17PostLinkCandidateProfile,
  ];
};

export type V17IndependentRoleEvidence = {
  readonly accepted: true;
  readonly fixtureInputCount: number;
  readonly fixtureOutputCount: number;
  readonly logicalInputIndex: number;
  readonly roleId: string;
  readonly redeemSha256Hex: string;
  readonly unlockingSha256Hex: string;
  readonly maximumOperationCost: number;
  readonly densityControlLength: number;
  readonly maximumMemorySlots: number;
  readonly maximumControlDepth: number;
  readonly valueSatoshis: bigint;
  readonly sequenceNumber: number;
  readonly operationCostEngine: "bchn-v29.0.0" | "independent-bchn-conformant";
  readonly operationCostEvidenceSha256Hex: string;
};

export type V17IndependentPostLinkEvidence = {
  readonly schema: "ShieldKit/V17IndependentPostLinkEvidence/v1";
  readonly status: "accepted-byte-exact-candidate-envelope";
  readonly qualification: "candidate-resource-only-not-final-qualification";
  readonly romPreviewIdHex: string;
  readonly profile: V17Profile;
  readonly projectedInputCount: number;
  readonly projectedOutputCount: number;
  readonly candidateEnvelopeEvidenceSha256Hex: string;
  readonly workers: readonly V17IndependentRoleEvidence[];
};

export type V17AllocationIteration = {
  readonly schema: "ShieldKit/V17AllocationIteration/v2";
  readonly status: "stable" | "requires-remeasurement";
  readonly qualification: "construction-resource-loop-only";
  readonly romPreviewIdHex: string;
  readonly currentReaderPlanSha256Hex: string;
  readonly measuredReaderPlanSha256Hex: string;
  readonly currentAllocation: V17AffineAllocation;
  readonly measuredAllocation: V17AffineAllocation;
  readonly densityClosure: V17DensityClosure;
  readonly densityTraceRootSha256Hex: string;
  readonly measuredRows: readonly V17DensityFeasibilityRow[];
  readonly trace: V17DensityClosureTrace;
  readonly postLinkProfiles: readonly [
    V17PostLinkMeasuredProfile,
    V17PostLinkMeasuredProfile,
    V17PostLinkMeasuredProfile,
  ];
};

export type V17FinalAllocationAssessment = {
  readonly schema: "ShieldKit/V17FinalAllocationAssessment/v2";
  readonly status: "stable" | "restart-post-link-loop";
  readonly qualification: "allocation-check-only-not-final-qualification";
  readonly constructionIdHex: string;
  readonly certifiedReaderPlanSha256Hex: string;
  readonly finalMeasuredReaderPlanSha256Hex: string;
  readonly certifiedAllocation: V17AffineAllocation;
  readonly finalMeasuredAllocation: V17AffineAllocation;
  readonly densityClosure: V17DensityClosure;
  readonly densityTraceRootSha256Hex: string;
  readonly finalMeasuredRows: readonly V17DensityFeasibilityRow[];
  readonly trace: V17DensityClosureTrace;
};

export type V17FinalInfrastructureRole = {
  readonly kind: "pool" | "proof-worker" | "rom-page";
  readonly index: number;
  readonly roleId: string;
  readonly lockingBytecode: Uint8Array;
  readonly unlockingBytecode: Uint8Array;
  readonly valueSatoshis: bigint | null;
  readonly sequenceNumber: number;
};

export type V17FinalProfileInfrastructure = {
  readonly schema: "ShieldKit/V17FinalProfileInfrastructure/v1";
  readonly status: "materialized-requires-final-bchn-qualification";
  readonly profile: V17Profile;
  readonly constructionIdHex: string;
  readonly bankDigestHex: string;
  readonly allocation: V17AffineAllocation;
  readonly roles: readonly LocalWordVerifierRole[];
  readonly pages: readonly V17RomPage[];
  readonly infrastructure: readonly V17FinalInfrastructureRole[];
};

export type V17FinalInfrastructureSet = {
  readonly schema: "ShieldKit/V17FinalInfrastructureSet/v1";
  readonly status: "materialized-requires-final-bchn-qualification";
  readonly qualification: "not-qualified-until-final-transactions-pass";
  readonly construction: V17LinkedConstruction;
  readonly authorizedBankDigests: LocalWordVerifierBankDigests;
  readonly profiles: readonly [
    V17FinalProfileInfrastructure,
    V17FinalProfileInfrastructure,
    V17FinalProfileInfrastructure,
  ];
};

function hex32(label: string, bytes: Uint8Array): string {
  if (bytes.length !== 32) throw new Error(`v17 product-link ${label}`);
  return binToHex(bytes);
}

function bytes32(label: string, hex: string): Uint8Array {
  if (!/^[0-9a-f]{64}$/.test(hex)) throw new Error(`v17 product-link ${label}`);
  return Uint8Array.from(Buffer.from(hex, "hex"));
}

function encodeRoleUnlocking(args: {
  readonly roleId: string;
  readonly proofBytes: Uint8Array;
  readonly chunk: Uint8Array;
  readonly redeem: Uint8Array;
}): Uint8Array {
  return args.roleId === LOCAL_WORD_BATCH_LEADER_ROLE_ID
    ? encodeLocalWordP2shBatchLeaderUnlocking(
      args.chunk,
      encodeV17BatchLeaderCell(args.proofBytes),
      args.redeem,
    )
    : encodeLocalWordP2shCarrierUnlocking(args.chunk, args.redeem);
}

function encodeRoleUnlockingPrefix(args: {
  readonly roleId: string;
  readonly proofBytes: Uint8Array;
  readonly chunk: Uint8Array;
  readonly ordinaryPrefix: Uint8Array;
}): Uint8Array {
  return args.roleId === LOCAL_WORD_BATCH_LEADER_ROLE_ID
    ? encodeLocalWordBatchLeaderUnlockingPrefix(
      args.chunk,
      encodeV17BatchLeaderCell(args.proofBytes),
    )
    : args.ordinaryPrefix;
}

function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function canonicalDigest(value: unknown): string {
  return createHash("sha256").update(canonicalV17Json(value)).digest("hex");
}

function preLinkProgramCensusDigest(args: {
  readonly profile: V17Profile;
  readonly baselineInputCount: number;
  readonly baselineOutputCount: number;
  readonly workers: readonly V17PreLinkProgramProfile["workers"][number][];
  readonly affineReader: V17AffineReaderConstruction;
}): string {
  return canonicalDigest({
    phase: "pre-link-program-census",
    profile: args.profile,
    baselineInputCount: args.baselineInputCount,
    baselineOutputCount: args.baselineOutputCount,
    workers: args.workers.map((worker) => ({
      logicalInputIndex: worker.logicalInputIndex,
      roleId: worker.roleId,
      redeemSha256Hex: sha256Hex(worker.redeemBytecode),
      redeemBytes: worker.redeemBytecode.length,
      unlockingPrefixSha256Hex: sha256Hex(worker.unlockingPrefixBytecode),
      proofCarrierBytes: worker.proofCarrierBytes,
      definePolicies: worker.definePolicies,
    })),
    affineReader: args.affineReader.evidence,
  });
}

function equal(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((byte, index) => byte === right[index]);
}

function orderedKeys(
  keys: readonly V17VerifierKeyMaterial[],
): readonly [V17VerifierKeyMaterial, V17VerifierKeyMaterial, V17VerifierKeyMaterial] {
  if (keys.length !== V17_PROFILES.length ||
    keys.some((key, index) => key.profile !== V17_PROFILES[index])) {
    throw new Error("v17 product-link verifier-key order");
  }
  const protocolIdHex = v17ProtocolIdHex();
  keys.forEach((key) => {
    const expected = V17_CONSTRUCTION_GRAPH.verifierKeyDigests[key.profile];
    if (hex32("protocol id", key.constructionId) !== protocolIdHex ||
      key.constructionDigest.length !== 32 || key.expectedPreprocessedRoot.length !== 32 ||
      expected?.profile !== key.profile ||
      hex32("relation construction", key.constructionDigest) !==
        expected.relationConstructionDigestHex ||
      hex32("preprocessed root", key.expectedPreprocessedRoot) !== expected.preprocessedRootHex) {
      throw new Error(`v17 product-link verifier key ${key.profile}`);
    }
  });
  return keys as unknown as readonly [
    V17VerifierKeyMaterial,
    V17VerifierKeyMaterial,
    V17VerifierKeyMaterial,
  ];
}

function baselineEnvelopeCounts(profile: V17Profile, roleCount: number): {
  readonly inputCount: number;
  readonly outputCount: number;
} {
  if (profile === 0) return { inputCount: roleCount + 1, outputCount: roleCount + 1 };
  if (profile === 1) return { inputCount: roleCount, outputCount: roleCount + 2 };
  return { inputCount: roleCount, outputCount: roleCount + 3 };
}

function compileBankPrograms(
  key: V17VerifierKeyMaterial,
  affineReader: V17AffineReaderConstruction,
): readonly LocalWordVerifierProgram[] {
  return compileLocalWordVerifierPrograms({
    profile: key.profile,
    constructionId: key.constructionId,
    constructionDigest: key.constructionDigest,
    expectedPreprocessedRoot: key.expectedPreprocessedRoot,
    affineReader,
  });
}

/**
 * Compile every unlinked verifier program and bind its byte census to the
 * exact proof partition used by the current allocation. This remains a
 * non-executable, non-resource-evidentiary baseline: its sole purpose is an
 * apples-to-apples byte comparison with the later linked carrier layout.
 */
export function compileV17PreLinkProduct(
  rawProofs: readonly V17ProfileProofMaterial[],
  allocation: V17AffineAllocation = V17_BOOTSTRAP_AFFINE_ALLOCATION,
): V17PreLinkProduct {
  const proofs = orderedProofs(rawProofs);
  const keys = orderedKeys(proofs);
  const protocolIdHex = v17ProtocolIdHex();
  const affineReader = compileV17AffineReaderConstruction(allocation);
  const banks = keys.map((key) => compileBankPrograms(key, affineReader));
  const provisionalBankDigests = V17_PROFILES.map((profile) =>
    localWordVerifierBankDigestFromRedeems(
      profile,
      banks[profile]!.map((role) => role.redeem),
      allocation,
    )) as unknown as LocalWordVerifierBankDigests;
  const settlementVerifier = compileLocalWordValueSettlementGate(
    provisionalBankDigests,
    affineReader.vm,
  );
  const settlementRedeem = compileLocalWordPoolCarrierRedeem(settlementVerifier);
  const programsByProfile = banks.map((bank): readonly V17ProgramRole[] => [
    { index: 0, name: "settlement", verifier: settlementVerifier, redeem: settlementRedeem },
    ...bank,
  ]) as unknown as V17PreLinkProduct["programsByProfile"];
  const profiles = programsByProfile.map((programs, profileIndex): V17PreLinkProgramProfile => {
    const profile = V17_PROFILES[profileIndex]!;
    if (programs.length !== V17_PRODUCTION_ROLE_LAYOUT.length || programs.some((program, index) =>
      program.index !== index || program.name !== V17_PRODUCTION_ROLE_LAYOUT[index]!.id)) {
      throw new Error(`v17 product-link program layout ${profile}`);
    }
    const envelopeCounts = baselineEnvelopeCounts(profile, programs.length);
    const counts = {
      baselineInputCount: envelopeCounts.inputCount,
      baselineOutputCount: envelopeCounts.outputCount,
    } as const;
    const proofBytes = proofs[profile]!.proofBytes;
    const carriers = partitionLocalWordProofBytes(proofBytes, allocation);
    const workers = programs.map((program) => {
      const carrier = carriers[program.index]!;
      // ROM placement depends on exact serialized widths, never on witness or
      // transcript bytes. A canonical zero carrier of the real partition
      // length has the same push width; the leader's fixed cell is likewise
      // represented by its canonical zero value.
      const canonicalChunk = new Uint8Array(carrier.chunk.length);
      const canonicalPrefix = program.name === LOCAL_WORD_BATCH_LEADER_ROLE_ID
        ? encodeLocalWordBatchLeaderUnlockingPrefix(
          canonicalChunk,
          new Uint8Array(V17_BATCH_LEADER_CELL_BYTES),
        )
        : encodeV17CanonicalPush(canonicalChunk);
      return {
        profile,
        logicalInputIndex: program.index,
        roleId: program.name,
        redeemBytecode: program.redeem,
        unlockingPrefixBytecode: canonicalPrefix,
        proofCarrierBytes: carrier.chunk.length,
        valueSatoshis: program.index === 0
          ? 0n
          : localWordVerifierCarrierValue(program.index, allocation),
        sequenceNumber: program.index === 0
          ? localWordPoolCarrierSequence(proofBytes.length, allocation)
          : localWordVerifierCarrierSequence(program.index, allocation),
        definePolicies: v17DefinePoliciesForRole({
          roleId: program.name,
          redeemBytecode: program.redeem,
        }),
      };
    });
    const programCensusSha256Hex = preLinkProgramCensusDigest({
      profile,
      ...counts,
      workers,
      affineReader,
    });
    return {
      baselinePhase: "pre-link-program-census",
      qualification: "non-executable-non-measurement",
      profile,
      workers,
      ...counts,
      programCensusSha256Hex,
    };
  }) as unknown as V17PreLinkProduct["profiles"];
  return {
    schema: "ShieldKit/V17PreLinkProduct/v1",
    status: "program-census-only",
    qualification: "non-executable-non-measurement",
    protocolIdHex,
    affineReader,
    provisionalBankDigests,
    profiles,
    programsByProfile,
  };
}

/** Deterministic program census followed by the graph-governed ROM preview. */
export function previewV17ProductRom(
  proofs: readonly V17ProfileProofMaterial[],
  allocation: V17AffineAllocation = V17_BOOTSTRAP_AFFINE_ALLOCATION,
): V17RomLinkStage {
  const preLink = compileV17PreLinkProduct(proofs, allocation);
  const preview = previewV17Rom({
    profiles: preLink.profiles,
    affineReader: preLink.affineReader,
  });
  return { ...preLink, preview };
}

function orderedProofs(
  proofs: readonly V17ProfileProofMaterial[],
): readonly [V17ProfileProofMaterial, V17ProfileProofMaterial, V17ProfileProofMaterial] {
  orderedKeys(proofs);
  if (proofs.some((proof) => proof.proofBytes[5] !== proof.profile)) {
    throw new Error("v17 product-link proof profile");
  }
  return proofs as unknown as readonly [
    V17ProfileProofMaterial,
    V17ProfileProofMaterial,
    V17ProfileProofMaterial,
  ];
}

function carrierizeProfile(args: {
  readonly profile: V17Profile;
  readonly proofBytes: Uint8Array;
  readonly programs: readonly V17ProgramRole[];
  readonly redeems: readonly Uint8Array[];
  readonly allocation: V17AffineAllocation;
}): readonly LocalWordVerifierRole[] {
  const carriers = partitionLocalWordProofBytes(args.proofBytes, args.allocation);
  if (args.programs.length !== carriers.length || args.redeems.length !== carriers.length) {
    throw new Error(`v17 product-link carrier shape ${args.profile}`);
  }
  return args.programs.map((program, index): LocalWordVerifierRole => {
    const carrier = carriers[index]!;
    const redeem = args.redeems[index]!;
    return {
      index,
      name: program.name,
      carrier,
      verifier: program.verifier,
      redeem,
      unlockingBytecode: encodeRoleUnlocking({
        roleId: program.name,
        proofBytes: args.proofBytes,
        chunk: carrier.chunk,
        redeem,
      }),
    };
  });
}

/**
 * Build exact post-link candidate inputs under a chosen affine allocation.
 * The default bootstrap allocation is only a measurement scaffold; this stage
 * is never final evidence and its type says so.
 */
export function materializeV17PostLinkCandidates(args: {
  readonly link: V17RomLinkStage;
  readonly proofs: readonly V17ProfileProofMaterial[];
  readonly allocation?: V17AffineAllocation;
}): V17PostLinkCandidateSet {
  const proofs = orderedProofs(args.proofs);
  const allocation = args.allocation ?? V17_BOOTSTRAP_AFFINE_ALLOCATION;
  const affineReader = validateV17AffineReaderConstruction(args.link.affineReader);
  const expectedReader = compileV17AffineReaderConstruction(allocation);
  if (canonicalV17Json(affineReader.evidence) !==
    canonicalV17Json(expectedReader.evidence)) {
    throw new Error("v17 product-link stale affine reader; recompile link for allocation");
  }
  const provisionalProfiles = V17_PROFILES.map((profile) => {
    const counts = baselineEnvelopeCounts(profile, V17_PRODUCTION_ROLE_LAYOUT.length);
    return {
      profile,
      projectedInputCount: counts.inputCount + args.link.preview.pages.length,
      projectedOutputCount: counts.outputCount + args.link.preview.pages.length,
      proofBytes: proofs[profile]!.proofBytes,
      roles: carrierizeProfile({
        profile,
        proofBytes: proofs[profile]!.proofBytes,
        programs: args.link.programsByProfile[profile]!,
        redeems: args.link.preview.linkedRedeemsByProfile[profile]!,
        allocation,
      }),
      pages: args.link.preview.pages,
    };
  });
  const candidateBankDigests = V17_PROFILES.map((profile) =>
    localWordVerifierBankDigestFromInputs(profile, [
      ...provisionalProfiles[profile]!.roles.slice(1).map((role) => ({
        lockingBytecode: encodeLockingBytecodeP2sh32(hash256(role.redeem)),
        valueSatoshis: localWordVerifierCarrierValue(role.index, allocation),
        sequenceNumber: localWordVerifierCarrierSequence(role.index, allocation),
      })),
      ...args.link.preview.pages.map((page) => ({
        lockingBytecode: page.lockingBytecode,
        valueSatoshis: page.valueSatoshis,
        sequenceNumber: page.sequenceNumber,
      })),
    ])) as unknown as LocalWordVerifierBankDigests;
  const constructionIdHex = v17ConstructionIdHex({
    protocolIdHex: args.link.protocolIdHex,
    bankDigests: candidateBankDigests.map(binToHex) as unknown as
      readonly [string, string, string],
  });
  const settlementVerifier = compileLocalWordValueSettlementGate(
    candidateBankDigests,
    affineReader.vm,
  );
  const settlementRedeem = compileLocalWordPoolCarrierRedeem(settlementVerifier);
  const profiles = V17_PROFILES.map((profile): V17PostLinkCandidateProfile => {
    const provisional = provisionalProfiles[profile]!;
    const carrier = provisional.roles[0]!.carrier;
    const settlement: LocalWordVerifierRole = {
      index: 0,
      name: "settlement",
      carrier,
      verifier: settlementVerifier,
      redeem: settlementRedeem,
      unlockingBytecode: encodeLocalWordP2shCarrierUnlocking(carrier.chunk, settlementRedeem),
    };
    return {
      schema: "ShieldKit/V17PostLinkCandidateProfile/v1",
      status: "candidate-envelope-requires-independent-bchn-measurement",
      romPreviewIdHex: args.link.preview.certificate.previewIdHex,
      constructionIdHex,
      profile,
      allocationStatus: allocation.status,
      allocation,
      projectedInputCount: provisional.projectedInputCount,
      projectedOutputCount: provisional.projectedOutputCount,
      proofBytes: provisional.proofBytes,
      roles: [settlement, ...provisional.roles.slice(1)],
      pages: provisional.pages,
    };
  }) as unknown as V17PostLinkCandidateSet["profiles"];
  return {
    schema: "ShieldKit/V17PostLinkCandidateSet/v1",
    status: "candidate-envelope-requires-independent-bchn-measurement",
    constructionIdHex,
    preview: args.link.preview,
    profiles,
  };
}

/**
 * Bind external BCHN results to one exact, accepting candidate envelope per
 * profile. The candidate has its allocation-specific settlement, linked
 * workers, and authenticated ROM, but remains construction-resource input only;
 * the fixed-point certificate and final exact transactions are later gates.
 */
export function bindV17PostLinkEvidence(args: {
  readonly candidates: V17PostLinkCandidateSet;
  readonly evidence: readonly V17IndependentPostLinkEvidence[];
}): readonly [
  V17PostLinkMeasuredProfile,
  V17PostLinkMeasuredProfile,
  V17PostLinkMeasuredProfile,
] {
  if (args.candidates.schema !== "ShieldKit/V17PostLinkCandidateSet/v1" ||
    args.candidates.status !== "candidate-envelope-requires-independent-bchn-measurement" ||
    !/^[0-9a-f]{64}$/.test(args.candidates.constructionIdHex) ||
    args.evidence.length !== V17_PROFILES.length) {
    throw new Error("v17 product-link post-link evidence count");
  }
  return V17_PROFILES.map((profile): V17PostLinkMeasuredProfile => {
    const candidate = args.candidates.profiles[profile]!;
    const evidence = args.evidence[profile]!;
    if (evidence.schema !== "ShieldKit/V17IndependentPostLinkEvidence/v1" ||
      evidence.status !== "accepted-byte-exact-candidate-envelope" ||
      evidence.qualification !== "candidate-resource-only-not-final-qualification" ||
      evidence.profile !== profile ||
      evidence.romPreviewIdHex !== candidate.romPreviewIdHex ||
      candidate.constructionIdHex !== args.candidates.constructionIdHex ||
      evidence.projectedInputCount !== candidate.projectedInputCount ||
      evidence.projectedOutputCount !== candidate.projectedOutputCount ||
      !/^[0-9a-f]{64}$/.test(evidence.candidateEnvelopeEvidenceSha256Hex) ||
      evidence.workers.length !== candidate.roles.length) {
      throw new Error(`v17 product-link post-link evidence ${profile}`);
    }
    const workers = candidate.roles.map((role, index) => {
      const measured = evidence.workers[index]!;
      const redeemSha256Hex = sha256Hex(role.redeem);
      const unlockingSha256Hex = sha256Hex(role.unlockingBytecode);
      const unlockingPrefixBytecode = encodeRoleUnlockingPrefix({
        roleId: role.name,
        proofBytes: candidate.proofBytes,
        chunk: role.carrier.chunk,
        ordinaryPrefix: role.carrier.unlockingBytecode,
      });
      const expectedValue = index === 0
        ? measured.valueSatoshis
        : localWordVerifierCarrierValue(index, candidate.allocation);
      const expectedSequence = index === 0
        ? localWordPoolCarrierSequence(candidate.proofBytes.length, candidate.allocation)
        : localWordVerifierCarrierSequence(index, candidate.allocation);
      if (measured.logicalInputIndex !== index || measured.roleId !== role.name ||
        measured.accepted !== true ||
        measured.fixtureInputCount !== candidate.projectedInputCount ||
        measured.fixtureOutputCount !== candidate.projectedOutputCount ||
        measured.redeemSha256Hex !== redeemSha256Hex ||
        measured.unlockingSha256Hex !== unlockingSha256Hex ||
        measured.densityControlLength !==
          V17_INPUT_FIXED_DENSITY_BYTES + role.unlockingBytecode.length ||
        measured.valueSatoshis !== expectedValue || measured.valueSatoshis < 0n ||
        measured.sequenceNumber !== expectedSequence ||
        !Number.isSafeInteger(measured.maximumOperationCost) || measured.maximumOperationCost < 1 ||
        !Number.isSafeInteger(measured.maximumMemorySlots) || measured.maximumMemorySlots < 1 ||
        !Number.isSafeInteger(measured.maximumControlDepth) || measured.maximumControlDepth < 0 ||
        !/^[0-9a-f]{64}$/.test(measured.operationCostEvidenceSha256Hex)) {
        throw new Error(`v17 product-link post-link worker evidence ${profile}:${role.name}`);
      }
      return {
        profile,
        logicalInputIndex: index,
        roleId: role.name,
        redeemBytecode: role.redeem,
        unlockingPrefixBytecode,
        maximumOperationCost: measured.maximumOperationCost,
        densityControlLength: measured.densityControlLength,
        proofCarrierBytes: role.carrier.chunk.length,
        maximumMemorySlots: measured.maximumMemorySlots,
        maximumControlDepth: measured.maximumControlDepth,
        valueSatoshis: measured.valueSatoshis,
        sequenceNumber: measured.sequenceNumber,
        operationCostEngine: measured.operationCostEngine,
        operationCostEvidenceSha256Hex: measured.operationCostEvidenceSha256Hex,
      };
    });
    return {
      measurementPhase: "post-link",
      romPreviewIdHex: candidate.romPreviewIdHex,
      profile,
      workers,
      inputCount: candidate.projectedInputCount,
      outputCount: candidate.projectedOutputCount,
      envelopeEvidenceSha256Hex: evidence.candidateEnvelopeEvidenceSha256Hex,
    };
  }) as unknown as readonly [
    V17PostLinkMeasuredProfile,
    V17PostLinkMeasuredProfile,
    V17PostLinkMeasuredProfile,
  ];
}

function allocationGeometry(allocation: V17AffineAllocation): unknown {
  return {
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

/**
 * One explicit measurement/allocation iteration. If the returned status is
 * `requires-remeasurement`, rebuild candidates with `measuredAllocation` and
 * run the independent BCHN fixtures again. Reader branches and opcost are not
 * assumed invariant under changed affine metadata.
 */
export function assessV17AllocationIteration(args: {
  readonly candidates: V17PostLinkCandidateSet;
  readonly evidence: readonly V17IndependentPostLinkEvidence[];
  readonly trace: V17DensityClosureTrace;
}): V17AllocationIteration {
  const postLinkProfiles = bindV17PostLinkEvidence(args);
  const currentAllocation = args.candidates.profiles[0].allocation;
  if (args.candidates.profiles.some((profile) =>
    canonicalV17Json(allocationGeometry(profile.allocation)) !==
      canonicalV17Json(allocationGeometry(currentAllocation)))) {
    throw new Error("v17 product-link mixed candidate allocations");
  }
  const feasibility = assessV17Density(V17_CONSTRUCTION_GRAPH, postLinkProfiles);
  if (feasibility.status !== "feasible") {
    throw new Error(`v17 product-link density infeasible ${feasibility.infeasibleRoleIds.join(",")}`);
  }
  const currentReaderPlanSha256Hex = args.candidates.preview.certificate
    .affineReader?.planSha256Hex;
  if (currentReaderPlanSha256Hex === undefined) {
    throw new Error("v17 product-link missing affine reader evidence");
  }
  const retainedReader = args.candidates.preview.affineReader;
  if (retainedReader === null) throw new Error("v17 product-link missing affine reader");
  const trace = appendV17DensityClosureTrace({
    trace: args.trace,
    phase: "post-link-bchn",
    currentAllocation,
    currentReader: retainedReader.evidence,
    romPreviewIdHex: args.candidates.preview.certificate.previewIdHex,
    measurementEvidenceSha256Hex: v17PostLinkMeasurementEvidenceDigestHex(
      args.candidates.preview.certificate.previewIdHex,
      postLinkProfiles,
    ),
    measuredRows: feasibility.rows,
  });
  const head = replayV17DensityClosureTrace(trace);
  const measuredAllocation = head.allocation;
  const densityClosure = head.closure;
  if (densityClosure === null) throw new Error("v17 product-link missing density closure");
  const measuredReader = compileV17AffineReaderConstruction(measuredAllocation);
  const measuredReaderPlanSha256Hex = measuredReader.evidence.planSha256Hex;
  const terminal = trace.entries.at(-1)!;
  const stable = terminal.noChange && terminal.phase === "post-link-bchn" &&
    v17DensityClosureDominates(densityClosure, feasibility.rows);
  return {
    schema: "ShieldKit/V17AllocationIteration/v2",
    status: stable ? "stable" : "requires-remeasurement",
    qualification: "construction-resource-loop-only",
    romPreviewIdHex: args.candidates.preview.certificate.previewIdHex,
    currentReaderPlanSha256Hex,
    measuredReaderPlanSha256Hex,
    currentAllocation,
    measuredAllocation,
    densityClosure,
    densityTraceRootSha256Hex: head.traceRootSha256Hex,
    measuredRows: feasibility.rows,
    trace,
    postLinkProfiles,
  };
}

/** Certify only a measured allocation fixed point; the claim remains construction-only. */
export function certifyV17ProductLink(args: {
  readonly candidates: V17PostLinkCandidateSet;
  readonly evidence: readonly V17IndependentPostLinkEvidence[];
  readonly trace: V17DensityClosureTrace;
}): V17LinkedConstruction {
  if (args.trace.entries.length < 1) throw new Error("v17 product-link missing terminal trace");
  const priorTrace: V17DensityClosureTrace = {
    ...args.trace,
    entries: args.trace.entries.slice(0, -1),
  };
  const iteration = assessV17AllocationIteration({
    candidates: args.candidates,
    evidence: args.evidence,
    trace: priorTrace,
  });
  if (canonicalV17Json(iteration.trace) !== canonicalV17Json(args.trace)) {
    throw new Error("v17 product-link terminal trace replay");
  }
  if (iteration.status !== "stable") {
    throw new Error("v17 product-link allocation requires post-link remeasurement");
  }
  const construction = certifyV17LinkedConstruction({
    preview: args.candidates.preview,
    postLinkProfiles: iteration.postLinkProfiles,
    densityTrace: iteration.trace,
  });
  if (construction.certificate.constructionIdHex !== args.candidates.constructionIdHex) {
    throw new Error("v17 product-link candidate construction identity");
  }
  return construction;
}

/**
 * Reconcile exact final-transaction BCHN worker measurements with the
 * construction certificate. Callers must build `finalProfiles` from the
 * materialized transactions (including the exact bank digests, settlement,
 * affine metadata, and ROM placement), not reuse the role-resource fixtures.
 * A mismatch invalidates the certificate and restarts the post-link loop with
 * `finalMeasuredAllocation`.
 */
export function assessV17FinalAllocationStability(args: {
  readonly construction: V17LinkedConstruction;
  readonly finalProfiles: readonly [
    V17PostLinkMeasuredProfile,
    V17PostLinkMeasuredProfile,
    V17PostLinkMeasuredProfile,
  ];
  readonly trace: V17DensityClosureTrace;
}): V17FinalAllocationAssessment {
  const certifiedAllocation = measuredV17AffineAllocation(
    args.construction.certificate.allocation,
  );
  const finalFeasibility = assessV17Density(V17_CONSTRUCTION_GRAPH, args.finalProfiles);
  if (finalFeasibility.status !== "feasible") {
    throw new Error(`v17 product-link final density infeasible ${
      finalFeasibility.infeasibleRoleIds.join(",")}`);
  }
  const retainedReader = args.construction.affineReader;
  if (retainedReader === null) {
    throw new Error("v17 product-link final missing affine reader");
  }
  const certifiedReader = validateV17AffineReaderConstruction(retainedReader);
  const retainedClosure = validateV17DensityClosure(
    args.construction.certificate.densityClosure,
  );
  const priorHead = replayV17DensityClosureTrace(args.trace);
  if (priorHead.traceRootSha256Hex !==
      args.construction.certificate.densityTraceRootSha256Hex ||
    priorHead.closure === null || priorHead.closure.closureSha256Hex !==
      retainedClosure.closureSha256Hex ||
    canonicalV17Json(allocationGeometry(priorHead.allocation)) !==
      canonicalV17Json(allocationGeometry(certifiedAllocation))) {
    throw new Error("v17 product-link final density trace");
  }
  const trace = appendV17DensityClosureTrace({
    trace: args.trace,
    phase: "final-bchn",
    currentAllocation: certifiedAllocation,
    currentReader: certifiedReader.evidence,
    romPreviewIdHex: args.construction.certificate.romPreviewIdHex,
    measurementEvidenceSha256Hex: v17PostLinkMeasurementEvidenceDigestHex(
      args.construction.certificate.romPreviewIdHex,
      args.finalProfiles,
    ),
    measuredRows: finalFeasibility.rows,
  });
  const finalHead = replayV17DensityClosureTrace(trace);
  const finalMeasuredAllocation = finalHead.allocation;
  const finalMeasuredReader = compileV17AffineReaderConstruction(finalMeasuredAllocation);
  const certifiedReaderPlanSha256Hex = certifiedReader.evidence.planSha256Hex;
  const finalMeasuredReaderPlanSha256Hex = finalMeasuredReader.evidence.planSha256Hex;
  if (certifiedReaderPlanSha256Hex !==
    args.construction.certificate.affineReader?.planSha256Hex) {
    throw new Error("v17 product-link final affine reader certificate");
  }
  const terminal = trace.entries.at(-1)!;
  const finalClosure = finalHead.closure;
  if (finalClosure === null) throw new Error("v17 product-link final density closure");
  const stable = terminal.noChange && terminal.phase === "final-bchn" &&
    certifiedReaderPlanSha256Hex === finalMeasuredReaderPlanSha256Hex &&
    v17DensityClosureDominates(finalClosure, finalFeasibility.rows);
  return {
    schema: "ShieldKit/V17FinalAllocationAssessment/v2",
    status: stable ? "stable" : "restart-post-link-loop",
    qualification: "allocation-check-only-not-final-qualification",
    constructionIdHex: args.construction.certificate.constructionIdHex,
    certifiedReaderPlanSha256Hex,
    finalMeasuredReaderPlanSha256Hex,
    certifiedAllocation,
    finalMeasuredAllocation,
    densityClosure: finalClosure,
    densityTraceRootSha256Hex: finalHead.traceRootSha256Hex,
    finalMeasuredRows: finalFeasibility.rows,
    trace,
  };
}

/**
 * Repartition each real proof under the measured affine allocation, rebuild
 * every linked unlocking script, derive the exact banks including ROM pages,
 * and only then compile the settlement role with those three bank digests.
 */
export function materializeV17FinalInfrastructure(args: {
  readonly construction: V17LinkedConstruction;
  readonly proofs: readonly V17ProfileProofMaterial[];
}): V17FinalInfrastructureSet {
  const proofs = orderedProofs(args.proofs);
  if (args.construction.certificate.protocolIdHex !== v17ProtocolIdHex() ||
    args.construction.certificate.qualification !== "construction-only-not-qualified") {
    throw new Error("v17 product-link construction identity");
  }
  const allocation = measuredV17AffineAllocation(args.construction.certificate.allocation);
  const affineReader = validateV17AffineReaderConstruction(
    args.construction.affineReader ?? compileV17AffineReaderConstruction(allocation),
  );
  if (affineReader.evidence.planSha256Hex !==
    args.construction.certificate.affineReader?.planSha256Hex) {
    throw new Error("v17 product-link final affine reader identity");
  }
  const banks = V17_PROFILES.map((profile) => {
    const programs = compileBankPrograms(proofs[profile]!, affineReader);
    const carriers = partitionLocalWordProofBytes(proofs[profile]!.proofBytes, allocation);
    const linkedWorkers = args.construction.workersByProfile[profile]!;
    if (linkedWorkers.length !== V17_PRODUCTION_ROLE_LAYOUT.length ||
      programs.length !== linkedWorkers.length - 1) {
      throw new Error(`v17 product-link final worker shape ${profile}`);
    }
    return programs.map((program, local): LocalWordVerifierRole => {
      const index = local + 1;
      const linked = linkedWorkers[index]!;
      const carrier = carriers[index]!;
      const lockingBytecode = encodeLockingBytecodeP2sh32(hash256(linked.redeemBytecode));
      if (linked.profile !== profile || linked.logicalInputIndex !== index ||
        linked.roleId !== program.name || !equal(linked.lockingBytecode, lockingBytecode) ||
        linked.valueSatoshis !== localWordVerifierCarrierValue(index, allocation) ||
        linked.sequenceNumber !== localWordVerifierCarrierSequence(index, allocation)) {
        throw new Error(`v17 product-link final worker identity ${profile}:${program.name}`);
      }
      return {
        index,
        name: program.name,
        carrier,
        verifier: program.verifier,
        redeem: linked.redeemBytecode,
        unlockingBytecode: encodeRoleUnlocking({
          roleId: program.name,
          proofBytes: proofs[profile]!.proofBytes,
          chunk: carrier.chunk,
          redeem: linked.redeemBytecode,
        }),
      };
    });
  });
  const bankDigests = V17_PROFILES.map((profile) => {
    const roleInputs = [
      ...banks[profile]!.map((role) => ({
        lockingBytecode: encodeLockingBytecodeP2sh32(hash256(role.redeem)),
        valueSatoshis: localWordVerifierCarrierValue(role.index, allocation),
        sequenceNumber: localWordVerifierCarrierSequence(role.index, allocation),
      })),
      ...args.construction.pages.map((page) => ({
        lockingBytecode: page.lockingBytecode,
        valueSatoshis: page.valueSatoshis,
        sequenceNumber: page.sequenceNumber,
      })),
    ];
    const digest = localWordVerifierBankDigestFromInputs(profile, roleInputs);
    const expected = args.construction.certificate.profiles[profile]!.bankDigestHex;
    if (binToHex(digest) !== expected) {
      throw new Error(`v17 product-link final bank digest ${profile}`);
    }
    return digest;
  }) as unknown as LocalWordVerifierBankDigests;
  const replayedConstructionIdHex = v17ConstructionIdHex({
    protocolIdHex: args.construction.certificate.protocolIdHex,
    bankDigests: bankDigests.map(binToHex) as unknown as readonly [string, string, string],
  });
  if (replayedConstructionIdHex !== args.construction.certificate.constructionIdHex) {
    throw new Error("v17 product-link final construction id");
  }
  const settlementVerifier = compileLocalWordValueSettlementGate(bankDigests, affineReader.vm);
  const settlementRedeem = compileLocalWordPoolCarrierRedeem(settlementVerifier);
  const profiles = V17_PROFILES.map((profile): V17FinalProfileInfrastructure => {
    const carriers = partitionLocalWordProofBytes(proofs[profile]!.proofBytes, allocation);
    const settlement: LocalWordVerifierRole = {
      index: 0,
      name: "settlement",
      carrier: carriers[0]!,
      verifier: settlementVerifier,
      redeem: settlementRedeem,
      unlockingBytecode: encodeLocalWordP2shCarrierUnlocking(
        carriers[0]!.chunk,
        settlementRedeem,
      ),
    };
    const roles = [settlement, ...banks[profile]!];
    const infrastructure: V17FinalInfrastructureRole[] = [
      ...roles.map((role): V17FinalInfrastructureRole => ({
        kind: role.index === 0 ? "pool" : "proof-worker",
        index: role.index,
        roleId: role.name,
        lockingBytecode: encodeLockingBytecodeP2sh32(hash256(role.redeem)),
        unlockingBytecode: role.unlockingBytecode,
        valueSatoshis: role.index === 0
          ? null
          : localWordVerifierCarrierValue(role.index, allocation),
        sequenceNumber: role.index === 0
          ? localWordPoolCarrierSequence(proofs[profile]!.proofBytes.length, allocation)
          : localWordVerifierCarrierSequence(role.index, allocation),
      })),
      ...args.construction.pages.map((page): V17FinalInfrastructureRole => ({
        kind: "rom-page",
        index: page.inputIndex,
        roleId: `rom-page:${page.pageIndex}`,
        lockingBytecode: page.lockingBytecode,
        unlockingBytecode: page.unlockingBytecode,
        valueSatoshis: page.valueSatoshis,
        sequenceNumber: page.sequenceNumber,
      })),
    ];
    if (infrastructure.some((role, index) => role.index !== index)) {
      throw new Error(`v17 product-link final infrastructure order ${profile}`);
    }
    return {
      schema: "ShieldKit/V17FinalProfileInfrastructure/v1",
      status: "materialized-requires-final-bchn-qualification",
      profile,
      constructionIdHex: args.construction.certificate.constructionIdHex,
      bankDigestHex: binToHex(bankDigests[profile]!),
      allocation,
      roles,
      pages: args.construction.pages,
      infrastructure,
    };
  }) as unknown as V17FinalInfrastructureSet["profiles"];
  bytes32("construction id", args.construction.certificate.constructionIdHex);
  if (profiles.some((profile) => !equal(
    bytes32("bank digest", profile.bankDigestHex),
    bankDigests[profile.profile]!,
  ))) {
    throw new Error("v17 product-link final bank replay");
  }
  return {
    schema: "ShieldKit/V17FinalInfrastructureSet/v1",
    status: "materialized-requires-final-bchn-qualification",
    qualification: "not-qualified-until-final-transactions-pass",
    construction: args.construction,
    authorizedBankDigests: bankDigests,
    profiles,
  };
}

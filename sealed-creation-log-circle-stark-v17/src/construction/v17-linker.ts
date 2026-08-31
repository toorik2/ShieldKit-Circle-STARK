import { createHash } from "node:crypto";
import { binToHex, encodeLockingBytecodeP2sh32, hash256 } from "@bitauth/libauth";
import {
  V17_CONSTRUCTION_GRAPH,
  V17_ELASTIC_PREFIX_SCALE,
  V17_MAXIMUM_CANONICAL_PROOF_BYTES,
  V17_PROFILES,
  buildV17VerifierPlan,
  canonicalV17Json,
  type V17ConstructionGraph,
  type V17Profile,
  type V17VerifierPlan,
  v17BankDigestHex,
  v17ConstructionIdHex,
  v17ProtocolIdHex,
  validateV17ConstructionGraph,
} from "./v17-graph.ts";
import {
  V17_MAX_CONTROL_DEPTH,
  V17_MAX_FUNCTION_ID_BYTES,
  V17_MAX_SCRIPT_BYTES,
  V17_MAX_STACK_ITEMS,
  V17_ROM_VALUE_BASE_SATOSHIS,
  compileV17RomBodyLoader,
  createV17RomPage,
  encodeV17CanonicalPush,
  validateV17RomPage,
  type V17RomEntryInput,
  type V17RomPage,
  v17CompactUintBytes,
  v17SerializedInputBytes,
} from "../chain/v17-code-rom.ts";
import {
  measuredV17AffineAllocation,
  v17AffineBoundarySequence,
  v17AffineVerifierValue,
  type V17AffineAllocation,
} from "../chain/v17-affine-allocation.ts";
import {
  validateV17AffineReaderConstruction,
  type V17AffineReaderConstruction,
  type V17AffineReaderConstructionEvidence,
} from "../chain/v17-affine-reader-vm.ts";
import { compileLocalWordValueSettlementGate } from
  "../chain/local-word-balanced-vm.ts";
import {
  compileLocalWordPoolCarrierRedeem,
  LOCAL_WORD_BATCH_LEADER_ROLE_ID,
  type LocalWordVerifierBankDigests,
} from "../chain/local-word-proof-carriers.ts";
import { V17_BATCH_LEADER_CELL_BYTES } from
  "../backends/circle/v17-batch-leader-cell.ts";
import {
  allocateV17DensityClosure,
  allocateV17DensityRows,
  replayV17DensityClosureTrace,
  validateV17DensityClosure,
  v17DensityClosureDominates,
  type V17DensityAssignment,
  type V17DensityClosure,
  type V17DensityFeasibility,
  type V17DensityFeasibilityRow,
  type V17DensityClosureTrace,
} from "./v17-density-closure.ts";

export type {
  V17DensityAssignment,
  V17DensityClosure,
  V17DensityFeasibility,
  V17DensityFeasibilityRow,
} from "./v17-density-closure.ts";

export const V17_OPCOST_PER_DENSITY_BYTE = 800 as const;
export const V17_CONSENSUS_TX_BYTES = 1_000_000 as const;
export const V17_INPUT_FIXED_DENSITY_BYTES = 41 as const;

export type V17DefinePolicy = {
  readonly path: string;
  readonly classification:
    | "construction-independent"
    | "construction-independent-execution-local"
    | "construction-bound";
};

type V17LinkableWorker = {
  readonly profile: V17Profile;
  readonly logicalInputIndex: number;
  readonly roleId: string;
  readonly redeemBytecode: Uint8Array;
  /** Exact bytes preceding the final canonical P2SH redeem push. */
  readonly unlockingPrefixBytecode: Uint8Array;
  /** Proof bytes inside that density-control length; all other bytes are fixed. */
  readonly proofCarrierBytes: number;
  readonly valueSatoshis: bigint;
  readonly sequenceNumber: number;
};

type V17ResourceMeasuredWorker = V17LinkableWorker & {
  readonly maximumOperationCost: number;
  /** Exact BCH density-control length at measurement time. */
  readonly densityControlLength: number;
  /** BCH combines stack, altstack, and defined-function slots under this cap. */
  readonly maximumMemorySlots: number;
  readonly maximumControlDepth: number;
  /** Libauth next.8 is deliberately not an opcost evidence source for OP_DEFINE. */
  readonly operationCostEngine: "bchn-v29.0.0" | "independent-bchn-conformant";
  readonly operationCostEvidenceSha256Hex: string;
};

/** Exact pre-link measurement. Static definitions must follow the graph policy. */
export type V17MeasuredWorker = V17ResourceMeasuredWorker & {
  /** Exact, exhaustive policy for every recursively static OP_DEFINE site. */
  readonly definePolicies: readonly V17DefinePolicy[];
};

export type V17MeasuredProfile = {
  readonly profile: V17Profile;
  readonly workers: readonly V17MeasuredWorker[];
  readonly baselineInputCount: number;
  readonly baselineOutputCount: number;
  readonly envelopeEvidenceSha256Hex: string;
};

/** Phase-explicit names for new callers; legacy names above remain source-compatible. */
export type V17BaselineMeasuredWorker = V17MeasuredWorker;
export type V17BaselineMeasuredProfile = V17MeasuredProfile;

/**
 * Carrier-independent pre-link input. The canonical probe prefix exists only
 * to price serialized bytes and prove the linked script-size envelope; it is
 * not an executable transaction or an operation-cost measurement.
 */
export type V17PreLinkProgramWorker = V17LinkableWorker & {
  readonly definePolicies: readonly V17DefinePolicy[];
};

export type V17PreLinkProgramProfile = {
  readonly baselinePhase: "pre-link-program-census";
  readonly qualification: "non-executable-non-measurement";
  readonly profile: V17Profile;
  readonly workers: readonly V17PreLinkProgramWorker[];
  readonly baselineInputCount: number;
  readonly baselineOutputCount: number;
  readonly programCensusSha256Hex: string;
};

export type V17RomBaselineProfile = V17MeasuredProfile | V17PreLinkProgramProfile;

/**
 * Exact measurement of the bytecode emitted by a particular ROM preview.
 * The preview binding makes a baseline profile impossible to pass accidentally.
 */
export type V17PostLinkMeasuredWorker = V17ResourceMeasuredWorker;

export type V17PostLinkMeasuredProfile = {
  readonly measurementPhase: "post-link";
  readonly romPreviewIdHex: string;
  readonly profile: V17Profile;
  readonly workers: readonly V17PostLinkMeasuredWorker[];
  readonly inputCount: number;
  readonly outputCount: number;
  readonly envelopeEvidenceSha256Hex: string;
};

type V17DensityMeasuredProfile = V17MeasuredProfile | V17PostLinkMeasuredProfile;

/**
 * Exact local VM geometry used only to find an executable allocation seed.
 * It is deliberately incompatible with post-link resource evidence and can
 * never enter construction certification.
 */
export type V17UnqualifiedSizingWorker = V17LinkableWorker & {
  readonly maximumOperationCost: number;
  readonly densityControlLength: number;
};

export type V17UnqualifiedSizingProfile = {
  readonly qualification: "local-sizing-only-not-resource-evidence";
  readonly profile: V17Profile;
  readonly workers: readonly V17UnqualifiedSizingWorker[];
};

type DecodedInstruction = {
  readonly opcode: number;
  readonly start: number;
  readonly end: number;
  readonly pushedData?: Uint8Array;
};

export type V17DefineOccurrence = {
  readonly path: string;
  readonly depth: number;
  readonly bodyPushStart: number;
  readonly bodyPushEnd: number;
  readonly definitionEnd: number;
  readonly functionIdHex: string;
  readonly bodyHex: string;
  readonly bodySha256Hex: string;
  readonly body: Uint8Array;
};

export type V17LinkedWorker = {
  readonly profile: V17Profile;
  readonly logicalInputIndex: number;
  readonly roleId: string;
  readonly baselineRedeemSha256Hex: string;
  readonly linkedRedeemSha256Hex: string;
  readonly redeemBytecode: Uint8Array;
  readonly lockingBytecode: Uint8Array;
  readonly unlockingBytecode: Uint8Array;
  readonly valueSatoshis: bigint;
  readonly sequenceNumber: number;
};

export type V17RomPreviewCertificate = {
  readonly schema: "ShieldKit/V17RomPreview/v1";
  readonly status: "preview-only";
  readonly qualification: "requires-post-link-all-profile-measurement";
  readonly protocolIdHex: string;
  /** Null only for synthetic legacy linker tests, never for the V17 product path. */
  readonly affineReader: V17AffineReaderConstructionEvidence | null;
  readonly baselineEvidenceDigestHex: string;
  readonly census: {
    readonly staticDefinitionOccurrences: number;
    readonly exactBodyClasses: number;
    readonly promotedBodySha256Hexes: readonly string[];
  };
  readonly romPages: readonly {
    readonly pageIndex: number;
    readonly inputIndex: number;
    readonly outputIndex: number;
    readonly valueSatoshis: string;
    readonly sequenceNumber: number;
    readonly payloadSha256Hex: string;
    readonly redeemSha256Hex: string;
    readonly lockingBytecodeHex: string;
    readonly payloadBytes: number;
    readonly redeemBytes: number;
    readonly unlockingBytes: number;
    readonly functionIds: readonly string[];
    readonly bodySha256Hexes: readonly string[];
  }[];
  readonly profiles: readonly {
    readonly profile: V17Profile;
    readonly baselineInputCount: number;
    readonly baselineOutputCount: number;
    readonly baselineRelevantBytes: number;
    readonly projectedLinkedRelevantBytes: number;
    readonly projectedSavingBytes: number;
    readonly baselineRedeemSha256Hexes: readonly string[];
    readonly linkedRedeemSha256Hexes: readonly string[];
  }[];
  readonly previewIdHex: string;
};

export type V17RomPreview = {
  readonly certificate: V17RomPreviewCertificate;
  readonly affineReader: V17AffineReaderConstruction | null;
  /** Retained so certification can replay the graph-governed selection exactly. */
  readonly baselineProfiles: readonly [
    V17RomBaselineProfile,
    V17RomBaselineProfile,
    V17RomBaselineProfile,
  ];
  /** Deliberately remains unmeasured until post-link certification. */
  readonly verifierPlan: V17VerifierPlan;
  readonly pages: readonly V17RomPage[];
  readonly linkedRedeemsByProfile: readonly (readonly Uint8Array[])[];
  /** Executable projections, never resource or qualification evidence. */
  readonly workersByProfile: readonly (readonly V17LinkedWorker[])[];
};

export type V17LinkerCertificate = {
  readonly schema: "ShieldKit/V17LinkerCertificate/v3";
  readonly status: "post-link-measured";
  readonly qualification: "construction-only-not-qualified";
  readonly protocolIdHex: string;
  readonly affineReader: V17AffineReaderConstructionEvidence | null;
  readonly romPreviewIdHex: string;
  readonly measurementEvidenceDigestHex: string;
  /** Exact terminal BCHN rows; never relabelled as the conservative envelope. */
  readonly terminalMeasurementRowsSha256Hex: string;
  readonly terminalMeasurementRows: readonly V17DensityFeasibilityRow[];
  /** Monotone construction geometry selected by the canonical replay chain. */
  readonly densityClosureSha256Hex: string;
  readonly densityClosure: V17DensityClosure;
  readonly densityTraceRootSha256Hex: string;
  readonly allocationDigestHex: string;
  readonly allocation: readonly V17DensityAssignment[];
  readonly census: {
    readonly staticDefinitionOccurrences: number;
    readonly exactBodyClasses: number;
    readonly promotedBodySha256Hexes: readonly string[];
  };
  readonly romPages: readonly {
    readonly pageIndex: number;
    readonly inputIndex: number;
    readonly outputIndex: number;
    readonly valueSatoshis: string;
    readonly sequenceNumber: number;
    readonly payloadSha256Hex: string;
    readonly redeemSha256Hex: string;
    readonly lockingBytecodeHex: string;
    readonly payloadBytes: number;
    readonly redeemBytes: number;
    readonly unlockingBytes: number;
    readonly functionIds: readonly string[];
    readonly bodySha256Hexes: readonly string[];
  }[];
  readonly profiles: readonly {
    readonly profile: V17Profile;
    readonly baselineRelevantBytes: number;
    readonly linkedRelevantBytes: number;
    readonly strictSavingBytes: number;
    readonly bankDigestHex: string;
  }[];
  readonly constructionIdHex: string;
  readonly certificateIdHex: string;
};

export type V17LinkedConstruction = {
  readonly certificate: V17LinkerCertificate;
  readonly affineReader: V17AffineReaderConstruction | null;
  readonly verifierPlan: V17VerifierPlan;
  readonly pages: readonly V17RomPage[];
  readonly workersByProfile: readonly (readonly V17LinkedWorker[])[];
};

function concat(...parts: readonly Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((byte, index) => byte === right[index]);
}

function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function assertHex32(label: string, value: string): void {
  if (!/^[0-9a-f]{64}$/.test(value)) throw new Error(`v17 linker ${label} must be lowercase hex32`);
}

function domainHash(domain: string, value: unknown): string {
  const domainBytes = new TextEncoder().encode(domain);
  const payload = new TextEncoder().encode(canonicalV17Json(value));
  const framed = concat(
    Uint8Array.of(domainBytes.length >>> 24, domainBytes.length >>> 16,
      domainBytes.length >>> 8, domainBytes.length),
    domainBytes,
    Uint8Array.of(payload.length >>> 24, payload.length >>> 16, payload.length >>> 8, payload.length),
    payload,
  );
  return sha256Hex(framed);
}

function decodeInstructions(bytecode: Uint8Array): readonly DecodedInstruction[] {
  const instructions: DecodedInstruction[] = [];
  let cursor = 0;
  while (cursor < bytecode.length) {
    const start = cursor;
    const opcode = bytecode[cursor++]!;
    let dataLength: number | undefined;
    if (opcode === 0x00) dataLength = 0;
    else if (opcode >= 0x01 && opcode <= 0x4b) dataLength = opcode;
    else if (opcode === 0x4c) {
      if (cursor >= bytecode.length) throw new Error("v17 malformed OP_PUSHDATA1");
      dataLength = bytecode[cursor++]!;
    } else if (opcode === 0x4d) {
      if (cursor + 2 > bytecode.length) throw new Error("v17 malformed OP_PUSHDATA2");
      dataLength = bytecode[cursor]! | (bytecode[cursor + 1]! << 8);
      cursor += 2;
    } else if (opcode === 0x4e) {
      if (cursor + 4 > bytecode.length) throw new Error("v17 malformed OP_PUSHDATA4");
      dataLength = new DataView(bytecode.buffer, bytecode.byteOffset + cursor, 4).getUint32(0, true);
      cursor += 4;
    }
    if (dataLength !== undefined) {
      if (cursor + dataLength > bytecode.length) throw new Error("v17 malformed push length");
      const pushedData = bytecode.slice(cursor, cursor + dataLength);
      cursor += dataLength;
      instructions.push({ opcode, start, end: cursor, pushedData });
    } else if (opcode === 0x4f) {
      instructions.push({ opcode, start, end: cursor, pushedData: Uint8Array.of(0x81) });
    } else if (opcode >= 0x51 && opcode <= 0x60) {
      instructions.push({ opcode, start, end: cursor, pushedData: Uint8Array.of(opcode - 0x50) });
    } else {
      instructions.push({ opcode, start, end: cursor });
    }
  }
  return instructions;
}

function hasCanonicalWorkerPrefix(worker: V17LinkableWorker): boolean {
  const instructions = decodeInstructions(worker.unlockingPrefixBytecode);
  const proofPush = instructions[0];
  if (proofPush?.opcode !== 0x4d ||
    proofPush.pushedData?.length !== worker.proofCarrierBytes) {
    return false;
  }
  if (worker.roleId !== LOCAL_WORD_BATCH_LEADER_ROLE_ID) {
    return instructions.length === 1 &&
      proofPush.end === worker.unlockingPrefixBytecode.length;
  }
  const cellPush = instructions[1];
  return instructions.length === 2 &&
    cellPush?.opcode === 0x4c &&
    cellPush.pushedData?.length === V17_BATCH_LEADER_CELL_BYTES &&
    cellPush.end === worker.unlockingPrefixBytecode.length;
}

/** Recursively census every statically literal OP_DEFINE body exactly once. */
export function censusV17OpDefineBodies(bytecode: Uint8Array): readonly V17DefineOccurrence[] {
  const occurrences: V17DefineOccurrence[] = [];
  const walk = (scope: Uint8Array, parentPath: string, depth: number): void => {
    if (depth > V17_MAX_CONTROL_DEPTH) throw new Error("v17 OP_DEFINE static nesting exceeds 100");
    const instructions = decodeInstructions(scope);
    let localOrdinal = 0;
    for (let index = 0; index < instructions.length; index += 1) {
      const instruction = instructions[index]!;
      if (instruction.opcode !== 0x89) continue; // OP_DEFINE
      const bodyPush = instructions[index - 2];
      const identifierPush = instructions[index - 1];
      if (bodyPush?.pushedData === undefined || identifierPush?.pushedData === undefined) {
        throw new Error("v17 dynamic OP_DEFINE is not linkable");
      }
      if (identifierPush.pushedData.length > V17_MAX_FUNCTION_ID_BYTES) {
        throw new Error("v17 OP_DEFINE function identifier width");
      }
      if (bodyPush.pushedData.length > V17_MAX_SCRIPT_BYTES) {
        throw new Error("v17 OP_DEFINE body width");
      }
      const path = parentPath.length === 0 ? `${localOrdinal}` : `${parentPath}/${localOrdinal}`;
      localOrdinal += 1;
      const body = bodyPush.pushedData.slice();
      occurrences.push({
        path,
        depth,
        bodyPushStart: bodyPush.start,
        bodyPushEnd: bodyPush.end,
        definitionEnd: instruction.end,
        functionIdHex: binToHex(identifierPush.pushedData),
        bodyHex: binToHex(body),
        bodySha256Hex: sha256Hex(body),
        body,
      });
      if (body.length > 0) walk(body, path, depth + 1);
    }
  };
  walk(bytecode, "", 0);
  return occurrences;
}

/**
 * Derive the exhaustive policy from the typed construction boundary. The
 * settlement role is the only compiler that receives post-link bank digests;
 * all later roles receive protocol-fixed data only.
 */
export function v17DefinePoliciesForRole(args: {
  readonly graph?: V17ConstructionGraph;
  readonly roleId: string;
  readonly redeemBytecode: Uint8Array;
}): readonly V17DefinePolicy[] {
  const graph = args.graph ?? V17_CONSTRUCTION_GRAPH;
  const role = buildV17VerifierPlan(graph).roles.find(({ id }) => id === args.roleId);
  if (role === undefined) throw new Error(`v17 define-policy role ${args.roleId}`);
  const classification = role.defineBodyIdentity;
  const occurrences = censusV17OpDefineBodies(args.redeemBytecode);
  const executionLocalAlgebraRole =
    (role.kind === "batch-link-query" && role.semantic.kind === "batch-link-query" &&
      role.semantic.query > 0) || role.kind === "fri-fold-query";
  let executionLocalPath: string | undefined;
  if (executionLocalAlgebraRole) {
    const topLevel = occurrences.filter(({ depth }) => depth === 0);
    const expectedFunctionIds = role.kind === "batch-link-query"
      ? ["1d", "22"] as const
      : ["1e", "23"] as const;
    const exactExecutionLocalAbi = topLevel.length === 2 &&
      topLevel.every(({ functionIdHex }, index) => functionIdHex === expectedFunctionIds[index]);
    const resemblesExecutionLocalAbi = topLevel.some(({ functionIdHex }) =>
      expectedFunctionIds.some((expected) => expected === functionIdHex));
    if (classification !== "construction-independent" ||
      (!exactExecutionLocalAbi && resemblesExecutionLocalAbi)) {
      throw new Error(`v17 algebra define-placement ABI ${args.roleId}`);
    }
    // Synthetic linker fixtures and future construction-independent compilers
    // may reuse the same semantic role without this optional two-wrapper ABI.
    // Only the exact, identity-bound initializer/orchestrator pair opts in.
    if (exactExecutionLocalAbi) executionLocalPath = topLevel[1]!.path;
  }
  return occurrences.map(({ path }) => ({
    path,
    // Placement is attached to the local wrapper occurrence only. Its nested
    // definitions remain honestly construction-independent: they stay literal
    // because the linker rewrites depth-zero occurrences only, while identical
    // top-level helpers in other roles remain eligible for purification.
    classification: path === executionLocalPath
      ? "construction-independent-execution-local" as const
      : classification,
  }));
}

function workerUnlocking(
  worker: V17LinkableWorker,
  redeemBytecode: Uint8Array,
  enforceLimit = true,
): Uint8Array {
  const unlocking = concat(worker.unlockingPrefixBytecode, encodeV17CanonicalPush(redeemBytecode));
  if (redeemBytecode.length > V17_MAX_SCRIPT_BYTES ||
    (enforceLimit && unlocking.length > V17_MAX_SCRIPT_BYTES)) {
    throw new Error(`v17 worker script limit ${worker.profile}:${worker.roleId}`);
  }
  return unlocking;
}

function isPreLinkProgramProfile(
  profile: V17RomBaselineProfile | V17PostLinkMeasuredProfile,
): profile is V17PreLinkProgramProfile {
  return "baselinePhase" in profile;
}

function validatePreLinkProgramProfiles(
  graph: V17ConstructionGraph,
  profiles: readonly V17PreLinkProgramProfile[],
): V17VerifierPlan {
  const plan = buildV17VerifierPlan(graph);
  if (profiles.length !== V17_PROFILES.length ||
    profiles.some((profile, index) => profile.profile !== V17_PROFILES[index])) {
    throw new Error("v17 pre-link program profile order");
  }
  for (const profile of profiles) {
    assertHex32("program census", profile.programCensusSha256Hex);
    if (profile.baselinePhase !== "pre-link-program-census" ||
      profile.qualification !== "non-executable-non-measurement" ||
      !Number.isSafeInteger(profile.baselineInputCount) ||
      profile.baselineInputCount < plan.roles.length ||
      !Number.isSafeInteger(profile.baselineOutputCount) ||
      profile.baselineOutputCount < plan.roles.length ||
      profile.workers.length !== plan.roles.length) {
      throw new Error(`v17 pre-link program profile shape ${profile.profile}`);
    }
    profile.workers.forEach((worker, index) => {
      const role = plan.roles[index]!;
      if (worker.profile !== profile.profile || worker.logicalInputIndex !== index ||
        worker.roleId !== role.id || worker.redeemBytecode.length < 1 ||
        worker.redeemBytecode.length > V17_MAX_SCRIPT_BYTES ||
        !Number.isSafeInteger(worker.proofCarrierBytes) ||
        worker.proofCarrierBytes < graph.allocation.minimumProofBytesPerRole ||
        !hasCanonicalWorkerPrefix(worker) ||
        worker.valueSatoshis < 0n || !Number.isSafeInteger(worker.sequenceNumber) ||
        worker.sequenceNumber < 0 || worker.sequenceNumber > 0xffff_ffff) {
        throw new Error(`v17 pre-link program worker shape ${profile.profile}:${role.id}`);
      }
      // The pre-link census is explicitly non-executable. A raw unlocking may
      // exceed 10KB only so the linker can price and remove a repeated static
      // body; every linked and measured unlocking remains hard-limited.
      workerUnlocking(worker, worker.redeemBytecode, false);
    });
  }
  return plan;
}

function measurementCounts(profile: V17DensityMeasuredProfile): {
  readonly inputCount: number;
  readonly outputCount: number;
} {
  return "measurementPhase" in profile
    ? { inputCount: profile.inputCount, outputCount: profile.outputCount }
    : { inputCount: profile.baselineInputCount, outputCount: profile.baselineOutputCount };
}

function validateResourceMeasurements(
  graph: V17ConstructionGraph,
  measuredProfiles: readonly V17DensityMeasuredProfile[],
): V17VerifierPlan {
  const plan = buildV17VerifierPlan(graph);
  if (measuredProfiles.length !== V17_PROFILES.length ||
    measuredProfiles.some((profile, index) => profile.profile !== V17_PROFILES[index])) {
    throw new Error("v17 linker profile order");
  }
  for (const profile of measuredProfiles) {
    assertHex32("envelope evidence", profile.envelopeEvidenceSha256Hex);
    const counts = measurementCounts(profile);
    if (!Number.isSafeInteger(counts.inputCount) || counts.inputCount < plan.roles.length ||
      !Number.isSafeInteger(counts.outputCount) || counts.outputCount < plan.roles.length ||
      profile.workers.length !== plan.roles.length) {
      throw new Error(`v17 linker profile shape ${profile.profile}`);
    }
    for (const [index, worker] of profile.workers.entries()) {
      const role = plan.roles[index]!;
      if (worker.profile !== profile.profile || worker.logicalInputIndex !== index ||
        worker.roleId !== role.id || worker.redeemBytecode.length < 1 ||
        !Number.isSafeInteger(worker.maximumOperationCost) || worker.maximumOperationCost < 1 ||
        !Number.isSafeInteger(worker.densityControlLength) || worker.densityControlLength < 1 ||
        !Number.isSafeInteger(worker.proofCarrierBytes) ||
        worker.proofCarrierBytes < graph.allocation.minimumProofBytesPerRole ||
        worker.proofCarrierBytes > worker.unlockingPrefixBytecode.length ||
        !hasCanonicalWorkerPrefix(worker) ||
        !Number.isSafeInteger(worker.maximumMemorySlots) || worker.maximumMemorySlots < 1 ||
        worker.maximumMemorySlots > V17_MAX_STACK_ITEMS ||
        !Number.isSafeInteger(worker.maximumControlDepth) || worker.maximumControlDepth < 0 ||
        worker.maximumControlDepth > V17_MAX_CONTROL_DEPTH || worker.valueSatoshis < 0n ||
        !Number.isSafeInteger(worker.sequenceNumber) || worker.sequenceNumber < 0 ||
        worker.sequenceNumber > 0xffff_ffff ||
        (worker.operationCostEngine !== "bchn-v29.0.0" &&
          worker.operationCostEngine !== "independent-bchn-conformant")) {
        throw new Error(`v17 linker worker shape ${profile.profile}:${role.id}`);
      }
      assertHex32("operation-cost evidence", worker.operationCostEvidenceSha256Hex);
      const unlocking = workerUnlocking(worker, worker.redeemBytecode);
      if (worker.densityControlLength !== V17_INPUT_FIXED_DENSITY_BYTES + unlocking.length) {
        throw new Error(`v17 linker density evidence ${profile.profile}:${role.id}`);
      }
    }
  }
  return plan;
}

function validateUnqualifiedSizingProfiles(
  graph: V17ConstructionGraph,
  profiles: readonly V17UnqualifiedSizingProfile[],
): V17VerifierPlan {
  const plan = buildV17VerifierPlan(graph);
  if (profiles.length !== V17_PROFILES.length || profiles.some((profile, index) =>
    profile.qualification !== "local-sizing-only-not-resource-evidence" ||
    profile.profile !== V17_PROFILES[index] || profile.workers.length !== plan.roles.length)) {
    throw new Error("v17 local sizing profile order");
  }
  for (const profile of profiles) {
    profile.workers.forEach((worker, index) => {
      const role = plan.roles[index]!;
      if (worker.profile !== profile.profile || worker.logicalInputIndex !== index ||
        worker.roleId !== role.id || worker.redeemBytecode.length < 1 ||
        !Number.isSafeInteger(worker.maximumOperationCost) || worker.maximumOperationCost < 1 ||
        !Number.isSafeInteger(worker.densityControlLength) || worker.densityControlLength < 1 ||
        !Number.isSafeInteger(worker.proofCarrierBytes) ||
        worker.proofCarrierBytes < graph.allocation.minimumProofBytesPerRole ||
        worker.proofCarrierBytes > worker.unlockingPrefixBytecode.length ||
        !hasCanonicalWorkerPrefix(worker) ||
        worker.valueSatoshis < 0n || !Number.isSafeInteger(worker.sequenceNumber) ||
        worker.sequenceNumber < 0 || worker.sequenceNumber > 0xffff_ffff) {
        throw new Error(`v17 local sizing worker ${profile.profile}:${role.id}`);
      }
      const unlocking = workerUnlocking(worker, worker.redeemBytecode);
      if (worker.densityControlLength !== V17_INPUT_FIXED_DENSITY_BYTES + unlocking.length) {
        throw new Error(`v17 local sizing density ${profile.profile}:${role.id}`);
      }
    });
  }
  return plan;
}

function validateBaselineProfiles(
  graph: V17ConstructionGraph,
  baselineProfiles: readonly V17RomBaselineProfile[],
): {
  readonly plan: V17VerifierPlan;
  readonly census: ReadonlyMap<V17PreLinkProgramWorker, readonly V17DefineOccurrence[]>;
  readonly policies: ReadonlyMap<V17PreLinkProgramWorker, ReadonlyMap<string, V17DefinePolicy["classification"]>>;
} {
  const phases = baselineProfiles.map(isPreLinkProgramProfile);
  if (phases.some(Boolean) && !phases.every(Boolean)) {
    throw new Error("v17 mixed pre-link baseline phases");
  }
  const plan = phases.every(Boolean)
    ? validatePreLinkProgramProfiles(graph, baselineProfiles as readonly V17PreLinkProgramProfile[])
    : validateResourceMeasurements(graph, baselineProfiles as readonly V17MeasuredProfile[]);
  const census = new Map<V17PreLinkProgramWorker, readonly V17DefineOccurrence[]>();
  const policies = new Map<V17PreLinkProgramWorker,
    ReadonlyMap<string, V17DefinePolicy["classification"]>>();
  for (const profile of baselineProfiles) {
    for (const worker of profile.workers) {
      const expectedPolicies = v17DefinePoliciesForRole({
        graph,
        roleId: worker.roleId,
        redeemBytecode: worker.redeemBytecode,
      });
      if (worker.definePolicies.length !== expectedPolicies.length ||
        worker.definePolicies.some((policy, index) =>
          policy.path !== expectedPolicies[index]?.path ||
          policy.classification !== expectedPolicies[index]?.classification)) {
        throw new Error(`v17 linker graph OP_DEFINE policy ${profile.profile}:${worker.roleId}`);
      }
      const workerCensus = censusV17OpDefineBodies(worker.redeemBytecode);
      census.set(worker, workerCensus);
      policies.set(worker, new Map(expectedPolicies.map((policy) =>
        [policy.path, policy.classification])));
    }
  }
  return { plan, census, policies };
}

function proofCarrierCapacity(worker: V17LinkableWorker): number {
  const fixedUnlockingBytes = worker.unlockingPrefixBytecode.length - worker.proofCarrierBytes;
  const capacity = V17_MAX_SCRIPT_BYTES - fixedUnlockingBytes -
    encodeV17CanonicalPush(worker.redeemBytecode).length;
  if (!Number.isSafeInteger(capacity) || capacity < 1) {
    throw new Error(`v17 density carrier capacity ${worker.profile}:${worker.roleId}`);
  }
  return capacity;
}

function v17DensityFeasibility(
  graph: V17ConstructionGraph,
  plan: V17VerifierPlan,
  measuredProfiles: readonly { readonly workers: readonly V17UnqualifiedSizingWorker[] }[],
): V17DensityFeasibility {
  const rows = plan.roles.map((role, index): V17DensityFeasibilityRow => {
    const costs = V17_PROFILES.map((profile) =>
      measuredProfiles[profile]!.workers[index]!.maximumOperationCost) as unknown as
      readonly [number, number, number];
    const required = V17_PROFILES.map((profile) => {
      const worker = measuredProfiles[profile]!.workers[index]!;
      const nonProofDensityBytes = worker.densityControlLength - worker.proofCarrierBytes;
      return Math.max(
        graph.allocation.minimumProofBytesPerRole,
        Math.ceil(worker.maximumOperationCost / V17_OPCOST_PER_DENSITY_BYTE) -
          nonProofDensityBytes,
      );
    }) as unknown as readonly [number, number, number];
    const capacities = V17_PROFILES.map((profile) =>
      proofCarrierCapacity(measuredProfiles[profile]!.workers[index]!)) as unknown as
      readonly [number, number, number];
    const maximumOperationCost = Math.max(...costs);
    const requiredProofBytes = Math.max(...required);
    const capacityProofBytes = Math.min(...capacities);
    return {
      roleId: role.id,
      maximumOperationCost,
      profileOperationCosts: costs,
      profileRequiredProofBytes: required,
      profileCapacityProofBytes: capacities,
      requiredProofBytes,
      capacityProofBytes,
    };
  });
  const minimumProofBytes = rows.reduce((sum, row) => sum + row.requiredProofBytes, 0);
  const maximumProofBytes = graph.allocation.maximumProofBytes;
  const infeasibleRoleIds = rows.filter(({ requiredProofBytes, capacityProofBytes }) =>
    requiredProofBytes > capacityProofBytes).map(({ roleId }) => roleId);
  return {
    status: infeasibleRoleIds.length === 0 && minimumProofBytes < maximumProofBytes
      ? "feasible"
      : "infeasible",
    rows,
    minimumProofBytes,
    maximumProofBytes,
    infeasibleRoleIds,
  };
}

/** Measure every density row without hiding later failures behind the first one. */
export function assessV17UnqualifiedSizingDensity(
  graph: V17ConstructionGraph,
  profiles: readonly V17UnqualifiedSizingProfile[],
): V17DensityFeasibility {
  const plan = validateUnqualifiedSizingProfiles(graph, profiles);
  return v17DensityFeasibility(graph, plan, profiles);
}

function allocateV17DensityGeometry(
  graph: V17ConstructionGraph,
  plan: V17VerifierPlan,
  measuredProfiles: readonly { readonly workers: readonly V17UnqualifiedSizingWorker[] }[],
): readonly V17DensityAssignment[] {
  return allocateV17DensityRows(graph, v17DensityFeasibility(graph, plan, measuredProfiles).rows);
}

/**
 * Give every role its exact post-link density floor at the base endpoint, then
 * route only the variable proof tail through roles with measured unlocking
 * headroom. For x in [0, U-R], each extra chunk is a difference of cumulative
 * floors at scale 4095, so it is never negative and never exceeds the role's
 * certified headroom. A tight role may own zero elastic units.
 */
export function allocateV17Density(
  graph: V17ConstructionGraph,
  measuredProfiles: readonly V17DensityMeasuredProfile[],
): readonly V17DensityAssignment[] {
  const plan = validateResourceMeasurements(graph, measuredProfiles);
  return allocateV17DensityGeometry(graph, plan, measuredProfiles);
}

/** Expose the exact resource rows without selecting a fresh allocation. */
export function assessV17Density(
  graph: V17ConstructionGraph,
  measuredProfiles: readonly V17DensityMeasuredProfile[],
): V17DensityFeasibility {
  const plan = validateResourceMeasurements(graph, measuredProfiles);
  return v17DensityFeasibility(graph, plan, measuredProfiles);
}

/**
 * Run the same one allocator law over explicitly non-evidentiary local sizing
 * rows. The result can seed an independently measured candidate, but cannot be
 * passed to construction certification as resource evidence.
 */
export function allocateV17UnqualifiedSizingDensity(
  graph: V17ConstructionGraph,
  profiles: readonly V17UnqualifiedSizingProfile[],
): readonly V17DensityAssignment[] {
  const plan = validateUnqualifiedSizingProfiles(graph, profiles);
  return allocateV17DensityGeometry(graph, plan, profiles);
}

/** Materialize the one-copy allocation; no bytes are inserted, removed, or padded. */
export function partitionV17ProofByDensity(
  proofBytes: Uint8Array,
  assignments: readonly V17DensityAssignment[],
): readonly { readonly roleId: string; readonly start: number; readonly end: number; readonly bytes: Uint8Array }[] {
  const minimumProofBytes = assignments.at(-1)?.basePrefixEnd;
  if (assignments.length < 1 || assignments[0]?.basePrefixStart !== 0 ||
    assignments[0]?.elasticPrefixStart !== 0 || minimumProofBytes === undefined ||
    assignments.at(-1)?.elasticPrefixEnd !== V17_ELASTIC_PREFIX_SCALE) {
    throw new Error("v17 density partition shape");
  }
  if (proofBytes.length < minimumProofBytes ||
    proofBytes.length > V17_MAXIMUM_CANONICAL_PROOF_BYTES) {
    throw new Error("v17 density proof envelope");
  }
  const elasticBytes = proofBytes.length - minimumProofBytes;
  const parts = assignments.map((assignment, index) => {
    if (assignment.basePrefixStart < 0 ||
      assignment.basePrefixEnd <= assignment.basePrefixStart ||
      assignment.elasticPrefixStart < 0 ||
      assignment.elasticPrefixEnd < assignment.elasticPrefixStart ||
      (index > 0 && (assignment.basePrefixStart !== assignments[index - 1]!.basePrefixEnd ||
        assignment.elasticPrefixStart !== assignments[index - 1]!.elasticPrefixEnd))) {
      throw new Error("v17 density partition gap or overlap");
    }
    const start = assignment.basePrefixStart + Math.floor(
      elasticBytes * assignment.elasticPrefixStart / V17_ELASTIC_PREFIX_SCALE,
    );
    const end = index === assignments.length - 1
      ? proofBytes.length
      : assignment.basePrefixEnd + Math.floor(
        elasticBytes * assignment.elasticPrefixEnd / V17_ELASTIC_PREFIX_SCALE,
      );
    if (end - start < assignment.requiredProofBytes) {
      throw new Error(`v17 density proof too short at ${assignment.roleId}`);
    }
    if (end - start > assignment.capacityProofBytes) {
      throw new Error(`v17 density proof too long at ${assignment.roleId}`);
    }
    return { roleId: assignment.roleId, start, end, bytes: proofBytes.slice(start, end) };
  });
  const joined = concat(...parts.map((part) => part.bytes));
  if (joined.length !== proofBytes.length || !joined.every((byte, index) => byte === proofBytes[index])) {
    throw new Error("v17 density partition changed proof bytes");
  }
  return parts;
}

type Candidate = {
  readonly bodyHex: string;
  readonly bodySha256Hex: string;
  readonly body: Uint8Array;
  readonly functionId: Uint8Array;
  readonly anchor: {
    readonly profile: V17Profile;
    readonly logicalInputIndex: number;
    readonly path: string;
  };
};

function compareDefinePaths(left: string, right: string): number {
  const leftParts = left.split("/").map(Number);
  const rightParts = right.split("/").map(Number);
  const shared = Math.min(leftParts.length, rightParts.length);
  for (let index = 0; index < shared; index += 1) {
    const order = leftParts[index]! - rightParts[index]!;
    if (order !== 0) return order;
  }
  return leftParts.length - rightParts.length;
}

function compareCandidateAnchors(
  left: Candidate["anchor"],
  right: Candidate["anchor"],
): number {
  return left.profile - right.profile ||
    left.logicalInputIndex - right.logicalInputIndex ||
    compareDefinePaths(left.path, right.path);
}

function occurrenceAnchorKey(args: {
  readonly profile: V17Profile;
  readonly logicalInputIndex: number;
  readonly path: string;
}): string {
  return `${args.profile}:${args.logicalInputIndex}:${args.path}`;
}

function identifierForOrdinal(ordinal: number): Uint8Array {
  if (!Number.isSafeInteger(ordinal) || ordinal < 0) throw new Error("v17 ROM identifier ordinal");
  let value = BigInt(ordinal + 1);
  const bytes: number[] = [];
  while (value > 0n) {
    bytes.unshift(Number(value & 0xffn));
    value >>= 8n;
  }
  if (bytes.length > V17_MAX_FUNCTION_ID_BYTES) throw new Error("v17 ROM identifier space");
  return Uint8Array.from(bytes);
}

function replacePromotedBodies(
  worker: V17PreLinkProgramWorker,
  occurrences: readonly V17DefineOccurrence[],
  placements: ReadonlyMap<string, { readonly loader: Uint8Array }>,
): Uint8Array {
  const replacements = occurrences.filter((occurrence) => occurrence.depth === 0 &&
    placements.has(occurrence.bodyHex)).map((occurrence) => {
      const placement = placements.get(occurrence.bodyHex)!;
      return {
        start: occurrence.bodyPushStart,
        end: occurrence.bodyPushEnd,
        bytes: placement.loader,
      };
    }).filter((replacement) =>
      // A ROM page may be beneficial for the body class as a whole while its
      // authenticated loader is no smaller than one inline occurrence. Keep
      // that occurrence inline: linking is a purification pass and must never
      // make an individual verifier script larger.
      replacement.bytes.length < replacement.end - replacement.start
    ).sort((left, right) => right.start - left.start);
  let linked = worker.redeemBytecode.slice();
  for (const replacement of replacements) {
    linked = concat(linked.slice(0, replacement.start), replacement.bytes, linked.slice(replacement.end));
  }
  if (linked.length > V17_MAX_SCRIPT_BYTES) {
    throw new Error(`v17 linked worker script limit ${worker.profile}:${worker.roleId}`);
  }
  return linked;
}

function relevantProfileBytes(args: {
  readonly profile: V17DensityMeasuredProfile | V17PreLinkProgramProfile;
  readonly redeems: readonly Uint8Array[];
  readonly pages: readonly V17RomPage[];
  readonly inputCount: number;
  readonly outputCount: number;
}): number {
  const workerInputs = args.profile.workers.reduce((sum, worker, index) =>
    sum + v17SerializedInputBytes(workerUnlocking(
      worker,
      args.redeems[index]!,
      !isPreLinkProgramProfile(args.profile),
    )), 0);
  return v17CompactUintBytes(args.inputCount) + v17CompactUintBytes(args.outputCount) +
    workerInputs + args.pages.reduce((sum, page) =>
      sum + page.serializedInputBytes + page.serializedOutputBytes, 0);
}

function createPageForEntries(
  pageIndex: number,
  entries: readonly Candidate[],
  romStartIndex: number,
): V17RomPage {
  return createV17RomPage({
    pageIndex,
    inputIndex: romStartIndex + pageIndex,
    outputIndex: romStartIndex + pageIndex,
    valueSatoshis: V17_ROM_VALUE_BASE_SATOSHIS + BigInt(pageIndex),
    entries: entries.map((entry): V17RomEntryInput => ({
      functionId: entry.functionId,
      body: entry.body,
    })),
  });
}

/** Exact minimum page count, then earliest stable semantic-anchor assignment. */
function packCandidates(candidates: readonly Candidate[], romStartIndex: number): readonly V17RomPage[] {
  if (candidates.length === 0) return [];
  const sorted = [...candidates].sort((left, right) =>
    compareCandidateAnchors(left.anchor, right.anchor));
  for (const candidate of sorted) createPageForEntries(0, [candidate], romStartIndex);

  const fits = (bin: readonly Candidate[], pageIndex: number): boolean => {
    try {
      createPageForEntries(pageIndex, bin, romStartIndex);
      return true;
    } catch (error) {
      if (error instanceof Error && /(?:payload|unlocking|element|limit)/.test(error.message)) return false;
      throw error;
    }
  };
  let greedy: Candidate[][] = [];
  for (const candidate of sorted) {
    const existing = greedy.findIndex((bin, page) => fits([...bin, candidate], page));
    if (existing === -1) greedy.push([candidate]);
    else greedy[existing] = [...greedy[existing]!, candidate];
  }
  const totalBodyBytes = sorted.reduce((sum, candidate) => sum + candidate.body.length, 0);
  const lowerBound = Math.max(1, Math.ceil(totalBodyBytes / V17_MAX_SCRIPT_BYTES));
  for (let target = lowerBound; target <= greedy.length; target += 1) {
    const bins: Candidate[][] = [];
    const search = (at: number): Candidate[][] | undefined => {
      if (at === sorted.length) return bins.length === target ? bins.map((bin) => [...bin]) : undefined;
      if (bins.length > target || bins.length + (sorted.length - at) < target) return undefined;
      const candidate = sorted[at]!;
      for (let page = 0; page <= Math.min(bins.length, target - 1); page += 1) {
        const isNew = page === bins.length;
        const next = isNew ? [candidate] : [...bins[page]!, candidate];
        if (!fits(next, page)) continue;
        if (isNew) bins.push(next);
        else bins[page] = next;
        const found = search(at + 1);
        if (found !== undefined) return found;
        if (isNew) bins.pop();
        else bins[page] = next.slice(0, -1);
      }
      return undefined;
    };
    const packed = search(0);
    if (packed !== undefined) return packed.map((entries, page) =>
      createPageForEntries(page, entries, romStartIndex));
  }
  throw new Error("v17 ROM exact packing failed");
}

function baselineRedeems(profile: V17RomBaselineProfile): readonly Uint8Array[] {
  return profile.workers.map((worker) => worker.redeemBytecode);
}

function linkedRedeemsFor(
  profile: V17RomBaselineProfile,
  census: ReadonlyMap<V17PreLinkProgramWorker, readonly V17DefineOccurrence[]>,
  pages: readonly V17RomPage[],
): readonly Uint8Array[] {
  const placements = new Map<string, { loader: Uint8Array }>();
  for (const page of pages) {
    for (const entry of page.entries) placements.set(binToHex(entry.body), {
      loader: compileV17RomBodyLoader(page, entry.functionIdHex),
    });
  }
  return profile.workers.map((worker) =>
    replacePromotedBodies(worker, census.get(worker)!, placements));
}

function describeRomPages(pages: readonly V17RomPage[]): V17RomPreviewCertificate["romPages"] {
  return pages.map((page) => ({
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
  }));
}

function measurementEvidenceRow(profile: V17Profile, worker: V17ResourceMeasuredWorker) {
  return {
    profile,
    logicalInputIndex: worker.logicalInputIndex,
    roleId: worker.roleId,
    redeemSha256Hex: sha256Hex(worker.redeemBytecode),
    unlockingPrefixSha256Hex: sha256Hex(worker.unlockingPrefixBytecode),
    maximumOperationCost: worker.maximumOperationCost,
    densityControlLength: worker.densityControlLength,
    proofCarrierBytes: worker.proofCarrierBytes,
    maximumMemorySlots: worker.maximumMemorySlots,
    maximumControlDepth: worker.maximumControlDepth,
    valueSatoshis: worker.valueSatoshis.toString(),
    sequenceNumber: worker.sequenceNumber,
    operationCostEngine: worker.operationCostEngine,
    operationCostEvidenceSha256Hex: worker.operationCostEvidenceSha256Hex,
  } as const;
}

function measurementEvidenceRows(profiles: readonly V17DensityMeasuredProfile[]) {
  return profiles.flatMap((profile) => profile.workers.map((worker) =>
    measurementEvidenceRow(profile.profile, worker)));
}

/** Canonical digest of the exact current post-link resource evidence. */
export function v17PostLinkMeasurementEvidenceDigestHex(
  romPreviewIdHex: string,
  profiles: readonly V17PostLinkMeasuredProfile[],
): string {
  return domainHash("ShieldKit/V17PostLinkEvidence/v2", {
    romPreviewIdHex,
    profiles: profiles.map((profile) => ({
      profile: profile.profile,
      measurementPhase: profile.measurementPhase,
      romPreviewIdHex: profile.romPreviewIdHex,
      inputCount: profile.inputCount,
      outputCount: profile.outputCount,
      envelopeEvidenceSha256Hex: profile.envelopeEvidenceSha256Hex,
    })),
    workers: measurementEvidenceRows(profiles),
  });
}

function baselineProfileEvidence(profile: V17RomBaselineProfile) {
  return isPreLinkProgramProfile(profile)
    ? {
      phase: profile.baselinePhase,
      qualification: profile.qualification,
      profile: profile.profile,
      baselineInputCount: profile.baselineInputCount,
      baselineOutputCount: profile.baselineOutputCount,
      programCensusSha256Hex: profile.programCensusSha256Hex,
    }
    : {
      phase: "pre-link-measured" as const,
      qualification: "independently-measured" as const,
      profile: profile.profile,
      baselineInputCount: profile.baselineInputCount,
      baselineOutputCount: profile.baselineOutputCount,
      envelopeEvidenceSha256Hex: profile.envelopeEvidenceSha256Hex,
    };
}

function baselineWorkerEvidence(profile: V17RomBaselineProfile, worker: V17PreLinkProgramWorker) {
  const common = {
    profile: profile.profile,
    logicalInputIndex: worker.logicalInputIndex,
    roleId: worker.roleId,
    redeemSha256Hex: sha256Hex(worker.redeemBytecode),
    unlockingPrefixSha256Hex: sha256Hex(worker.unlockingPrefixBytecode),
    proofCarrierBytes: worker.proofCarrierBytes,
    valueSatoshis: worker.valueSatoshis.toString(),
    sequenceNumber: worker.sequenceNumber,
    definePolicies: worker.definePolicies,
  } as const;
  return isPreLinkProgramProfile(profile)
    ? common
    : { ...common, ...measurementEvidenceRow(profile.profile, worker as V17MeasuredWorker) };
}

function linkedWorkers(
  profile: V17DensityMeasuredProfile | V17PreLinkProgramProfile,
  redeems: readonly Uint8Array[],
  baselineRedeemSha256Hexes: readonly string[],
  allocation?: V17AffineAllocation,
): readonly V17LinkedWorker[] {
  return profile.workers.map((worker, index): V17LinkedWorker => {
    const redeemBytecode = redeems[index]!;
    return {
      profile: profile.profile,
      logicalInputIndex: worker.logicalInputIndex,
      roleId: worker.roleId,
      baselineRedeemSha256Hex: baselineRedeemSha256Hexes[index]!,
      linkedRedeemSha256Hex: sha256Hex(redeemBytecode),
      redeemBytecode,
      lockingBytecode: encodeLockingBytecodeP2sh32(hash256(redeemBytecode)),
      unlockingBytecode: workerUnlocking(worker, redeemBytecode),
      valueSatoshis: allocation === undefined || index === 0
        ? worker.valueSatoshis
        : v17AffineVerifierValue(allocation, index),
      sequenceNumber: allocation === undefined || index === 0
        ? worker.sequenceNumber
        : v17AffineBoundarySequence(allocation, index),
    };
  });
}

/**
 * Phase one: choose ROM bodies and produce the exact linked redeem scripts.
 * Every byte count and saving here is a projection from baseline evidence; no
 * allocation, bank digest, construction id, or post-link cost claim is made.
 */
export function previewV17Rom(args: {
  readonly graph?: V17ConstructionGraph;
  readonly affineReader?: V17AffineReaderConstruction;
  readonly profiles: readonly [
    V17RomBaselineProfile,
    V17RomBaselineProfile,
    V17RomBaselineProfile,
  ];
}): V17RomPreview {
  const graph = args.graph ?? V17_CONSTRUCTION_GRAPH;
  validateV17ConstructionGraph(graph);
  const protocolIdHex = v17ProtocolIdHex(graph);
  const affineReader = args.affineReader === undefined
    ? null
    : validateV17AffineReaderConstruction(args.affineReader);
  const checked = validateBaselineProfiles(graph, args.profiles);
  const romStartIndex = checked.plan.roles.length;
  const allOccurrences = args.profiles.flatMap((profile) => profile.workers.flatMap((worker) =>
    checked.census.get(worker)!.map((occurrence) => ({ worker, occurrence }))));
  // Function identifiers belong to semantic occurrence anchors, not to the
  // accidental number of exact-body classes. Assign every static occurrence
  // its ordinal before body equality can split or merge classes; the earliest
  // occurrence of a class owns that ordinal and later classes retain their IDs.
  const staticOccurrences = [...allOccurrences].sort((left, right) =>
    compareCandidateAnchors({
      profile: left.worker.profile,
      logicalInputIndex: left.worker.logicalInputIndex,
      path: left.occurrence.path,
    }, {
      profile: right.worker.profile,
      logicalInputIndex: right.worker.logicalInputIndex,
      path: right.occurrence.path,
    }));
  const occurrenceOrdinals = new Map<string, number>();
  staticOccurrences.forEach(({ worker, occurrence }, ordinal) => {
    const key = occurrenceAnchorKey({
      profile: worker.profile,
      logicalInputIndex: worker.logicalInputIndex,
      path: occurrence.path,
    });
    if (occurrenceOrdinals.has(key)) throw new Error("v17 ROM duplicate occurrence anchor");
    occurrenceOrdinals.set(key, ordinal);
  });
  const classes = new Map<string, typeof allOccurrences>();
  for (const row of allOccurrences) {
    const bodyClass = classes.get(row.occurrence.bodyHex) ?? [];
    bodyClass.push(row);
    classes.set(row.occurrence.bodyHex, bodyClass);
  }
  const bodyClasses = [...classes.entries()].map(([bodyHex, rows]) => {
    const first = [...rows].sort((left, right) => compareCandidateAnchors({
      profile: left.worker.profile,
      logicalInputIndex: left.worker.logicalInputIndex,
      path: left.occurrence.path,
    }, {
      profile: right.worker.profile,
      logicalInputIndex: right.worker.logicalInputIndex,
      path: right.occurrence.path,
    }))[0]!;
    return {
      bodyHex,
      rows,
      anchorOrdinal: Math.min(...rows.map(({ worker, occurrence }) => {
        const ordinal = occurrenceOrdinals.get(occurrenceAnchorKey({
          profile: worker.profile,
          logicalInputIndex: worker.logicalInputIndex,
          path: occurrence.path,
        }));
        if (ordinal === undefined) throw new Error("v17 ROM occurrence ordinal");
        return ordinal;
      })),
      anchor: {
        profile: first.worker.profile,
        logicalInputIndex: first.worker.logicalInputIndex,
        path: first.occurrence.path,
      },
    };
  }).sort((left, right) => compareCandidateAnchors(left.anchor, right.anchor));
  const eligibleBodyHexes = new Set(bodyClasses.filter(({ rows }) => {
    const topLevel = rows.filter((row) => row.occurrence.depth === 0);
    if (topLevel.length < 2 || rows.some((row) =>
      checked.policies.get(row.worker)!.get(row.occurrence.path) !==
        "construction-independent")) return false;
    return topLevel.every((row) => {
      const policy = checked.policies.get(row.worker)!;
      return policy.get(row.occurrence.path) === "construction-independent" &&
        [...policy].every(([path, classification]) =>
          !path.startsWith(`${row.occurrence.path}/`) ||
            classification === "construction-independent");
    });
  }).map(({ bodyHex }) => bodyHex));
  // Assign ordinals before eligibility filtering. A body therefore retains
  // its semantic identifier when an earlier class changes placement policy;
  // gaps are harmless and avoid another source of cross-class movement.
  const candidates = bodyClasses.map(({ bodyHex, rows, anchor, anchorOrdinal }): Candidate => ({
    bodyHex,
    bodySha256Hex: rows[0]!.occurrence.bodySha256Hex,
    body: rows[0]!.occurrence.body,
    functionId: identifierForOrdinal(anchorOrdinal),
    anchor,
  })).filter(({ bodyHex }) => eligibleBodyHexes.has(bodyHex));

  // Preview eligibility is byte-exact but deliberately not an opcost claim.
  // A body must pay for an authenticated page by itself in every profile;
  // packing may then improve the already-positive saving, never create it.
  const promoted = candidates.filter((candidate) => {
    const page = createPageForEntries(0, [candidate], romStartIndex);
    return args.profiles.every((profile) => {
      const baseline = relevantProfileBytes({
        profile,
        redeems: baselineRedeems(profile),
        pages: [],
        inputCount: profile.baselineInputCount,
        outputCount: profile.baselineOutputCount,
      });
      const linked = relevantProfileBytes({
        profile,
        redeems: linkedRedeemsFor(profile, checked.census, [page]),
        pages: [page],
        inputCount: profile.baselineInputCount + 1,
        outputCount: profile.baselineOutputCount + 1,
      });
      return baseline - linked > 0;
    });
  });
  const pages = packCandidates(promoted, romStartIndex);
  const linkedRedeemsByProfile = args.profiles.map((profile) =>
    linkedRedeemsFor(profile, checked.census, pages));
  const profileRows = args.profiles.map((profile, profileIndex) => {
    const baselineRelevantBytes = relevantProfileBytes({
      profile,
      redeems: baselineRedeems(profile),
      pages: [],
      inputCount: profile.baselineInputCount,
      outputCount: profile.baselineOutputCount,
    });
    const projectedLinkedRelevantBytes = relevantProfileBytes({
      profile,
      redeems: linkedRedeemsByProfile[profileIndex]!,
      pages,
      inputCount: profile.baselineInputCount + pages.length,
      outputCount: profile.baselineOutputCount + pages.length,
    });
    const projectedSavingBytes = baselineRelevantBytes - projectedLinkedRelevantBytes;
    if (pages.length > 0 && projectedSavingBytes <= 0) {
      throw new Error(`v17 ROM non-positive projected profile saving ${profile.profile}`);
    }
    return {
      profile: profile.profile,
      baselineInputCount: profile.baselineInputCount,
      baselineOutputCount: profile.baselineOutputCount,
      baselineRelevantBytes,
      projectedLinkedRelevantBytes,
      projectedSavingBytes,
      baselineRedeemSha256Hexes: profile.workers.map((worker) => sha256Hex(worker.redeemBytecode)),
      linkedRedeemSha256Hexes: linkedRedeemsByProfile[profileIndex]!.map(sha256Hex),
    } as const;
  });
  const baselineEvidenceDigestHex = domainHash("ShieldKit/V17RomBaselineEvidence/v2", {
    profiles: args.profiles.map(baselineProfileEvidence),
    workers: args.profiles.flatMap((profile) => profile.workers.map((worker) =>
      baselineWorkerEvidence(profile, worker))),
  });
  const certificateCore = {
    schema: "ShieldKit/V17RomPreview/v1" as const,
    status: "preview-only" as const,
    qualification: "requires-post-link-all-profile-measurement" as const,
    protocolIdHex,
    affineReader: affineReader?.evidence ?? null,
    baselineEvidenceDigestHex,
    census: {
      staticDefinitionOccurrences: allOccurrences.length,
      exactBodyClasses: classes.size,
      promotedBodySha256Hexes: promoted.map((candidate) => candidate.bodySha256Hex),
    },
    romPages: describeRomPages(pages),
    profiles: profileRows,
  };
  const certificate: V17RomPreviewCertificate = {
    ...certificateCore,
    previewIdHex: domainHash("ShieldKit/V17RomPreviewId/v1", certificateCore),
  };
  const workersByProfile = args.profiles.map((profile, profileIndex) => linkedWorkers(
    profile,
    linkedRedeemsByProfile[profileIndex]!,
    profileRows[profileIndex]!.baselineRedeemSha256Hexes,
  ));
  return {
    certificate,
    affineReader,
    baselineProfiles: args.profiles,
    verifierPlan: checked.plan,
    pages,
    linkedRedeemsByProfile,
    workersByProfile,
  };
}

/** Compatibility name retained for callers; the result is explicitly preview-only. */
export function linkV17Construction(args: {
  readonly graph?: V17ConstructionGraph;
  readonly affineReader?: V17AffineReaderConstruction;
  readonly profiles: readonly [
    V17RomBaselineProfile,
    V17RomBaselineProfile,
    V17RomBaselineProfile,
  ];
}): V17RomPreview {
  return previewV17Rom(args);
}

function validateRomPreview(graph: V17ConstructionGraph, preview: V17RomPreview): V17VerifierPlan {
  const plan = buildV17VerifierPlan(graph);
  const certificate = preview.certificate;
  if (certificate.schema !== "ShieldKit/V17RomPreview/v1" || certificate.status !== "preview-only" ||
    certificate.qualification !== "requires-post-link-all-profile-measurement" ||
    certificate.protocolIdHex !== plan.protocolIdHex ||
    canonicalV17Json(preview.verifierPlan) !== canonicalV17Json(plan)) {
    throw new Error("v17 ROM preview identity");
  }
  if ((certificate.affineReader === null) !== (preview.affineReader === null) ||
    (preview.affineReader !== null && canonicalV17Json(
      validateV17AffineReaderConstruction(preview.affineReader).evidence,
    ) !== canonicalV17Json(certificate.affineReader))) {
    throw new Error("v17 ROM preview affine reader");
  }
  assertHex32("ROM preview id", certificate.previewIdHex);
  assertHex32("ROM baseline evidence", certificate.baselineEvidenceDigestHex);
  if (preview.pages.length !== certificate.romPages.length || preview.pages.some((page, index) => {
    validateV17RomPage(page);
    return page.pageIndex !== index || page.inputIndex !== plan.roles.length + index ||
      page.outputIndex !== page.inputIndex;
  }) || canonicalV17Json(describeRomPages(preview.pages)) !== canonicalV17Json(certificate.romPages)) {
    throw new Error("v17 ROM preview pages");
  }
  if (certificate.profiles.length !== V17_PROFILES.length ||
    preview.linkedRedeemsByProfile.length !== V17_PROFILES.length ||
    certificate.profiles.some((row, profileIndex) => {
      const redeems = preview.linkedRedeemsByProfile[profileIndex];
      return row.profile !== V17_PROFILES[profileIndex] || redeems?.length !== plan.roles.length ||
        row.baselineRedeemSha256Hexes.length !== plan.roles.length ||
        row.linkedRedeemSha256Hexes.length !== plan.roles.length ||
        redeems.some((redeem, index) => sha256Hex(redeem) !== row.linkedRedeemSha256Hexes[index]) ||
        row.baselineInputCount < plan.roles.length || row.baselineOutputCount < plan.roles.length ||
        (preview.pages.length > 0 && row.projectedSavingBytes <= 0);
    })) {
    throw new Error("v17 ROM preview profile shape");
  }
  const { previewIdHex: ignored, ...certificateCore } = certificate;
  void ignored;
  if (domainHash("ShieldKit/V17RomPreviewId/v1", certificateCore) !== certificate.previewIdHex) {
    throw new Error("v17 ROM preview digest");
  }
  const replay = previewV17Rom({
    graph,
    profiles: preview.baselineProfiles,
    ...(preview.affineReader === null ? {} : { affineReader: preview.affineReader }),
  });
  if (replay.certificate.previewIdHex !== certificate.previewIdHex) {
    throw new Error("v17 ROM preview deterministic replay");
  }
  return plan;
}

function validatePostLinkMeasurements(
  graph: V17ConstructionGraph,
  preview: V17RomPreview,
  profiles: readonly V17PostLinkMeasuredProfile[],
): V17VerifierPlan {
  const previewPlan = validateRomPreview(graph, preview);
  const plan = validateResourceMeasurements(graph, profiles);
  if (profiles.some((profile, profileIndex) => {
    const previewProfile = preview.certificate.profiles[profileIndex]!;
    const previewRedeems = preview.linkedRedeemsByProfile[profileIndex]!;
    const baselineWorkers = preview.baselineProfiles[profileIndex]!.workers;
    return profile.measurementPhase !== "post-link" ||
      profile.romPreviewIdHex !== preview.certificate.previewIdHex ||
      profile.inputCount !== previewProfile.baselineInputCount + preview.pages.length ||
      profile.outputCount !== previewProfile.baselineOutputCount + preview.pages.length ||
      profile.workers.some((worker, index) => {
        const baseline = baselineWorkers[index]!;
        return worker.proofCarrierBytes !== baseline.proofCarrierBytes ||
          worker.unlockingPrefixBytecode.length !== baseline.unlockingPrefixBytecode.length ||
          (index > 0 && !equalBytes(worker.redeemBytecode, previewRedeems[index]!));
      }) || relevantProfileBytes({
        profile,
        redeems: profile.workers.map((worker) => worker.redeemBytecode),
        pages: preview.pages,
        inputCount: profile.inputCount,
        outputCount: profile.outputCount,
      }) !== previewProfile.projectedLinkedRelevantBytes;
  })) {
    throw new Error("v17 stale or unmeasured post-link profile");
  }
  if (canonicalV17Json(plan) !== canonicalV17Json(previewPlan)) {
    throw new Error("v17 post-link plan drift");
  }
  return plan;
}

/**
 * Phase two: certify only exact, preview-bound post-link measurements. This is
 * a construction certificate, not a proof-system qualification certificate.
 */
export function certifyV17LinkedConstruction(args: {
  readonly graph?: V17ConstructionGraph;
  readonly preview: V17RomPreview;
  readonly postLinkProfiles: readonly [
    V17PostLinkMeasuredProfile,
    V17PostLinkMeasuredProfile,
    V17PostLinkMeasuredProfile,
  ];
  readonly densityTrace: V17DensityClosureTrace;
}): V17LinkedConstruction {
  const graph = args.graph ?? V17_CONSTRUCTION_GRAPH;
  validateV17ConstructionGraph(graph);
  const plan = validatePostLinkMeasurements(graph, args.preview, args.postLinkProfiles);
  const protocolIdHex = v17ProtocolIdHex(graph);
  const terminalFeasibility = v17DensityFeasibility(graph, plan, args.postLinkProfiles);
  if (terminalFeasibility.status !== "feasible") {
    throw new Error(`v17 terminal density infeasible ${terminalFeasibility.infeasibleRoleIds.join(",")}`);
  }
  const traceHead = replayV17DensityClosureTrace(args.densityTrace);
  const terminalTrace = args.densityTrace.entries.at(-1);
  if (terminalTrace === undefined || !traceHead.terminalNoChange ||
    traceHead.terminalPhase !== "post-link-bchn" || terminalTrace.phase !== "post-link-bchn" ||
    terminalTrace.romPreviewIdHex !== args.preview.certificate.previewIdHex ||
    canonicalV17Json(terminalTrace.measuredRows) !== canonicalV17Json(terminalFeasibility.rows)) {
    throw new Error("v17 terminal density trace gate");
  }
  const measurementEvidenceDigestHex = v17PostLinkMeasurementEvidenceDigestHex(
    args.preview.certificate.previewIdHex,
    args.postLinkProfiles,
  );
  if (terminalTrace.measurementEvidenceSha256Hex !== measurementEvidenceDigestHex) {
    throw new Error("v17 terminal density trace measurement");
  }
  const densityClosure = validateV17DensityClosure(traceHead.closure!, graph);
  if (!v17DensityClosureDominates(densityClosure, terminalFeasibility.rows, graph)) {
    throw new Error("v17 terminal density closure does not dominate BCHN rows");
  }
  const densityTraceRootSha256Hex = traceHead.traceRootSha256Hex;
  assertHex32("density trace root", densityTraceRootSha256Hex);
  const assignments = allocateV17DensityClosure(densityClosure, graph);
  const affineAllocation = measuredV17AffineAllocation(assignments);
  if (canonicalV17Json(traceHead.allocation) !== canonicalV17Json(affineAllocation)) {
    throw new Error("v17 terminal density trace allocation");
  }
  if (args.preview.affineReader !== null && canonicalV17Json(
    args.preview.affineReader.allocation,
  ) !== canonicalV17Json(affineAllocation)) {
    throw new Error("v17 terminal density closure preview allocation");
  }
  const pages = args.preview.pages;
  const romPages = describeRomPages(pages);
  const profileRows = args.postLinkProfiles.map((profile, profileIndex) => {
    const previewProfile = args.preview.certificate.profiles[profileIndex]!;
    const linkedRelevantBytes = relevantProfileBytes({
      profile,
      redeems: profile.workers.map((worker) => worker.redeemBytecode),
      pages,
      inputCount: profile.inputCount,
      outputCount: profile.outputCount,
    });
    const strictSavingBytes = previewProfile.baselineRelevantBytes - linkedRelevantBytes;
    if (pages.length > 0 && strictSavingBytes <= 0) {
      throw new Error(`v17 ROM non-positive post-link profile saving ${profile.profile}`);
    }
    const verifierRoles = profile.workers.slice(1).map((worker) => ({
      index: worker.logicalInputIndex,
      lockingBytecode: encodeLockingBytecodeP2sh32(hash256(worker.redeemBytecode)),
      valueSatoshis: v17AffineVerifierValue(affineAllocation, worker.logicalInputIndex),
      sequenceNumber: v17AffineBoundarySequence(affineAllocation, worker.logicalInputIndex),
    }));
    const roles = [
      ...verifierRoles,
      ...pages.map((page) => ({
        index: page.inputIndex,
        lockingBytecode: page.lockingBytecode,
        valueSatoshis: page.valueSatoshis,
        sequenceNumber: page.sequenceNumber,
      })),
    ];
    if (verifierRoles.length !== plan.roles.length - 1 || verifierRoles[0]?.index !== 1 ||
      verifierRoles.at(-1)?.index !== plan.roles.length - 1 ||
      roles.length !== plan.roles.length - 1 + pages.length) {
      throw new Error(`v17 verifier bank role range ${profile.profile}`);
    }
    return {
      profile: profile.profile,
      baselineRelevantBytes: previewProfile.baselineRelevantBytes,
      linkedRelevantBytes,
      strictSavingBytes,
      bankDigestHex: v17BankDigestHex({ protocolIdHex, profile: profile.profile, roles }),
    } as const;
  });
  const bankDigests = profileRows.map((row) => row.bankDigestHex) as unknown as
    readonly [string, string, string];
  const bankDigestBytes = bankDigests.map((digest) =>
    Uint8Array.from(Buffer.from(digest, "hex"))) as unknown as LocalWordVerifierBankDigests;
  const exactSettlementRedeem = compileLocalWordPoolCarrierRedeem(
    compileLocalWordValueSettlementGate(
      bankDigestBytes,
      args.preview.affineReader?.vm,
    ),
  );
  if (args.postLinkProfiles.some((profile) => {
    const settlement = profile.workers[0];
    return settlement === undefined || settlement.logicalInputIndex !== 0 ||
      settlement.roleId !== plan.roles[0]!.id ||
      !equalBytes(settlement.redeemBytecode, exactSettlementRedeem);
  })) {
    throw new Error("v17 post-link settlement bank identity");
  }
  const constructionIdHex = v17ConstructionIdHex({ protocolIdHex, bankDigests });
  const terminalMeasurementRowsSha256Hex = domainHash(
    "ShieldKit/V17TerminalDensityMeasurementRows/v1",
    terminalFeasibility.rows,
  );
  const allocationDigestHex = domainHash("ShieldKit/V17DensityAllocation/v3", assignments);
  const certificateCore = {
    schema: "ShieldKit/V17LinkerCertificate/v3" as const,
    status: "post-link-measured" as const,
    qualification: "construction-only-not-qualified" as const,
    protocolIdHex,
    affineReader: args.preview.certificate.affineReader,
    romPreviewIdHex: args.preview.certificate.previewIdHex,
    measurementEvidenceDigestHex,
    terminalMeasurementRowsSha256Hex,
    terminalMeasurementRows: terminalFeasibility.rows,
    densityClosureSha256Hex: densityClosure.closureSha256Hex,
    densityClosure,
    densityTraceRootSha256Hex,
    allocationDigestHex,
    allocation: assignments,
    census: args.preview.certificate.census,
    romPages,
    profiles: profileRows,
    constructionIdHex,
  };
  const certificate: V17LinkerCertificate = {
    ...certificateCore,
    certificateIdHex: domainHash("ShieldKit/V17LinkerCertificateId/v3", certificateCore),
  };
  const workersByProfile = args.postLinkProfiles.map((profile, profileIndex) => linkedWorkers(
    profile,
    profile.workers.map((worker) => worker.redeemBytecode),
    args.preview.certificate.profiles[profileIndex]!.baselineRedeemSha256Hexes,
    affineAllocation,
  ));
  const verifierPlan: V17VerifierPlan = {
    ...plan,
    allocation: {
      ...plan.allocation,
      status: "measured",
      minimumProofBytes: assignments.at(-1)!.basePrefixEnd,
      assignments: assignments.map((assignment) => ({
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
      pages: romPages.map((page) => ({
        index: page.pageIndex,
        inputIndex: page.inputIndex,
        outputIndex: page.outputIndex,
        sha256Hex: page.payloadSha256Hex,
        bytes: page.payloadBytes,
        functionIds: page.functionIds,
      })),
    },
  };
  return {
    certificate,
    affineReader: args.preview.affineReader,
    verifierPlan,
    pages,
    workersByProfile,
  };
}

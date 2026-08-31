import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  binToHex,
  createInstructionSetBch2026,
  createVirtualMachine,
  encodeLockingBytecodeP2sh32,
  hash256,
  type Output,
  type Transaction,
} from "@bitauth/libauth";
import {
  compileLocalWordValueSettlementGate,
} from "../chain/local-word-balanced-vm.ts";
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
  type LocalWordVerifierBankDigests,
} from "../chain/local-word-proof-carriers.ts";
import { encodeV17BatchLeaderCell } from
  "../backends/circle/v17-batch-leader-cell.ts";
import {
  V17_MAX_CONTROL_DEPTH,
  V17_MAX_STACK_ITEMS,
  validateV17RomPage,
} from "../chain/v17-code-rom.ts";
import { V17_PRODUCTION_ROLE_LAYOUT } from "../chain/v17-role-layout.ts";
import { validateV17AffineReaderConstruction } from
  "../chain/v17-affine-reader-vm.ts";
import {
  V17_PROFILES,
  canonicalV17Json,
  v17ConstructionIdHex,
  type V17Profile,
} from "../construction/v17-graph.ts";
import {
  V17_INPUT_FIXED_DENSITY_BYTES,
} from "../construction/v17-linker.ts";
import {
  materializeV17ProfileSettlementTransaction,
  type V17PublicSettlementFixture,
  type V17SettlementTransaction,
} from "../construction/v17-settlement-transaction.ts";
import type {
  V17FinalProfileInfrastructure,
  V17IndependentPostLinkEvidence,
  V17PostLinkCandidateProfile,
  V17PostLinkCandidateSet,
} from "../construction/v17-product-link.ts";
import {
  V17_BCHN_ASSAY_ENGINE_VERSION,
  V17_BCHN_ASSAY_SOURCE_TAG_COMMIT,
  V17_BCHN_MAY_2026_CONSENSUS_FLAGS,
  V17_BCHN_TRANSACTION_SIGCHECKS,
} from "./v17-bchn-product-gate.ts";

export const V17_POST_LINK_BCHN_MEASUREMENT_SCHEMA =
  "ShieldKit/V17PostLinkBchnMeasurement/v1" as const;

export type V17PostLinkCandidateEnvelope = {
  readonly schema: "ShieldKit/V17PostLinkCandidateEnvelope/v1";
  readonly status: "materialized-candidate-resource-envelope";
  readonly qualification: "not-final-product-qualification";
  readonly profile: V17Profile;
  readonly bankDigestHex: string;
  readonly candidate: V17PostLinkCandidateProfile;
  readonly materialized: V17SettlementTransaction;
};

export type V17PostLinkAssayRequest = {
  readonly profile: V17Profile;
  readonly inputIndex: number;
  readonly transaction: Transaction;
  readonly sourceOutputs: readonly Output[];
  readonly transactionBytes: Uint8Array;
  readonly sourceOutputsBytes: Uint8Array;
  readonly transactionHexPath: string;
  readonly sourceOutputsHexPath: string;
};

export type V17PostLinkAssayExecution = {
  readonly status: number | null;
  readonly stdout: string;
  readonly stderr: string;
  readonly error?: Error;
};

/** Dependency-injection seam used by fast tests and independent conformant runners. */
export type V17PostLinkAssayRunner = (
  request: V17PostLinkAssayRequest,
) => V17PostLinkAssayExecution;

export type V17PostLinkMemoryControlResult = {
  readonly maximumMemorySlots: number;
  readonly maximumControlDepth: number;
};

export type V17PostLinkAssayProvenance =
  | {
    readonly mode: "byte-exact-executable";
    readonly executableSha256Hex: string;
  }
  | {
    readonly mode: "injected-runner-test-only";
    readonly qualification: "test-only-nonqualifying";
  };

/** The linker consumes the base fields; these remain visible assurance evidence. */
export type V17BchnPostLinkEvidence = V17IndependentPostLinkEvidence & {
  readonly assayProvenance: V17PostLinkAssayProvenance;
  readonly checkedEnvelopeInputs: number;
  readonly transactionSha256Hex: string;
  readonly sourceOutputsSha256Hex: string;
};

/**
 * This diagnostic never supplies operation cost. BCHN remains the sole source
 * of accepted execution and operation-cost evidence.
 */
export type V17PostLinkMemoryControlRunner = (args: {
  readonly profile: V17Profile;
  readonly inputIndex: number;
  readonly transaction: Transaction;
  readonly sourceOutputs: readonly Output[];
}) => V17PostLinkMemoryControlResult;

export type V17PostLinkBchnMeasurementArguments = {
  readonly candidates: V17PostLinkCandidateSet;
  readonly fixtures: readonly V17PublicSettlementFixture[];
  readonly assayExecutablePath?: string;
  readonly assayEnvironment?: Readonly<Record<string, string>>;
  readonly assayRunner?: V17PostLinkAssayRunner;
  /** Required whenever the injectable seam is used; such evidence is test-only. */
  readonly injectedRunnerQualification?: "test-only-nonqualifying";
  readonly memoryControlRunner?: V17PostLinkMemoryControlRunner;
};

type AssayResult = {
  readonly engine: unknown;
  readonly engineVersion: unknown;
  readonly sourceTagCommit: unknown;
  readonly scope: unknown;
  readonly mode: unknown;
  readonly flags: unknown;
  readonly inputIndex: unknown;
  readonly inputCount: unknown;
  readonly sourceOutputCount: unknown;
  readonly transactionBytes: unknown;
  readonly sourceOutputsBytes: unknown;
  readonly unlockingBytecodeBytes: unknown;
  readonly lockingBytecodeBytes: unknown;
  readonly valid: unknown;
  readonly scriptErrorCode: unknown;
  readonly scriptError: unknown;
  readonly metricsReliable: unknown;
  readonly metrics: unknown;
};

type AssayMetrics = {
  readonly baseOpCost: unknown;
  readonly compositeOpCost: unknown;
  readonly opCostLimit: unknown;
  readonly hashDigestIterations: unknown;
  readonly hashDigestIterationsLimit: unknown;
  readonly sigChecks: unknown;
  readonly sigChecksInputLimit: unknown;
  readonly sigChecksTransactionLimit: unknown;
};

type CheckedAssayResult = {
  readonly baseOpCost: number;
  readonly compositeOpCost: number;
  readonly opCostLimit: number;
  readonly hashDigestIterations: number;
  readonly hashDigestIterationsLimit: number;
  readonly sigChecks: number;
};

function equal(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((byte, index) => byte === right[index]);
}

function sha256Hex(bytes: Uint8Array | string): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function canonicalDigest(value: unknown): string {
  return sha256Hex(canonicalV17Json(value));
}

function exactInteger(value: unknown, label: string, minimum = 0): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum) {
    throw new Error(`v17 post-link BCHN ${label}`);
  }
  return value as number;
}

function assertCandidateSet(candidates: V17PostLinkCandidateSet): void {
  if (candidates.schema !== "ShieldKit/V17PostLinkCandidateSet/v1" ||
    candidates.status !== "candidate-envelope-requires-independent-bchn-measurement" ||
    !/^[0-9a-f]{64}$/.test(candidates.constructionIdHex) ||
    candidates.profiles.length !== V17_PROFILES.length ||
    candidates.preview.certificate.previewIdHex !== candidates.profiles[0]?.romPreviewIdHex) {
    throw new Error("v17 post-link BCHN candidate set");
  }
  candidates.profiles.forEach((candidate, profile) => {
    const previewRedeems = candidates.preview.linkedRedeemsByProfile[profile];
    const previewProfile = candidates.preview.certificate.profiles[profile];
    if (candidate.schema !== "ShieldKit/V17PostLinkCandidateProfile/v1" ||
      candidate.status !== "candidate-envelope-requires-independent-bchn-measurement" ||
      candidate.profile !== profile ||
      candidate.romPreviewIdHex !== candidates.preview.certificate.previewIdHex ||
      candidate.constructionIdHex !== candidates.constructionIdHex ||
      candidate.roles.length !== V17_PRODUCTION_ROLE_LAYOUT.length ||
      candidate.pages.length !== candidates.preview.pages.length ||
      previewRedeems === undefined || previewRedeems.length !== candidate.roles.length ||
      previewProfile?.profile !== profile ||
      previewProfile.linkedRedeemSha256Hexes.length !== candidate.roles.length ||
      candidate.proofBytes[5] !== profile ||
      candidate.projectedInputCount !== candidate.roles.length + candidate.pages.length +
        (profile === 0 ? 1 : 0) ||
      candidate.projectedOutputCount !== candidate.roles.length + candidate.pages.length +
        (profile === 0 ? 1 : profile === 1 ? 2 : 3)) {
      throw new Error(`v17 post-link BCHN candidate profile ${profile}`);
    }
    const proof = reassembleLocalWordProofBytes(
      candidate.roles.map((role) => role.carrier),
      candidate.allocation,
    );
    if (!equal(proof, candidate.proofBytes)) {
      throw new Error(`v17 post-link BCHN candidate proof ${profile}`);
    }
    const batchLeaderCell = encodeV17BatchLeaderCell(proof);
    candidate.roles.forEach((role, index) => {
      const layout = V17_PRODUCTION_ROLE_LAYOUT[index];
      const expectedUnlocking = role.name === LOCAL_WORD_BATCH_LEADER_ROLE_ID
        ? encodeLocalWordP2shBatchLeaderUnlocking(
          role.carrier.chunk,
          batchLeaderCell,
          role.redeem,
        )
        : encodeLocalWordP2shCarrierUnlocking(role.carrier.chunk, role.redeem);
      if (layout === undefined || role.index !== index || role.name !== layout.id ||
        role.carrier.index !== index || role.carrier.proofLength !== candidate.proofBytes.length ||
        !equal(role.unlockingBytecode, expectedUnlocking) ||
        (index > 0 && (!equal(role.redeem, previewRedeems[index]!) ||
          sha256Hex(role.redeem) !== previewProfile.linkedRedeemSha256Hexes[index]))) {
        throw new Error(`v17 post-link BCHN candidate role ${profile}:${index}`);
      }
    });
    candidate.pages.forEach((page, local) => {
      validateV17RomPage(page);
      const index = candidate.roles.length + local;
      const previewPage = candidates.preview.pages[local];
      if (page.pageIndex !== local || page.inputIndex !== index || page.outputIndex !== index ||
        previewPage === undefined || page.pageIndex !== previewPage.pageIndex ||
        page.inputIndex !== previewPage.inputIndex || page.outputIndex !== previewPage.outputIndex ||
        page.valueSatoshis !== previewPage.valueSatoshis ||
        page.sequenceNumber !== previewPage.sequenceNumber ||
        page.payloadSha256Hex !== previewPage.payloadSha256Hex ||
        !equal(page.payload, previewPage.payload) ||
        !equal(page.redeemBytecode, previewPage.redeemBytecode) ||
        !equal(page.lockingBytecode, previewPage.lockingBytecode) ||
        !equal(page.unlockingBytecode, previewPage.unlockingBytecode)) {
        throw new Error(`v17 post-link BCHN candidate ROM ${profile}:${local}`);
      }
    });
  });
}

function candidateBankDigests(
  candidates: V17PostLinkCandidateSet,
): LocalWordVerifierBankDigests {
  return candidates.profiles.map((candidate) => localWordVerifierBankDigestFromInputs(
    candidate.profile,
    [
      ...candidate.roles.slice(1).map((role) => ({
        lockingBytecode: encodeLockingBytecodeP2sh32(hash256(role.redeem)),
        valueSatoshis: localWordVerifierCarrierValue(role.index, candidate.allocation),
        sequenceNumber: localWordVerifierCarrierSequence(role.index, candidate.allocation),
      })),
      ...candidate.pages.map((page) => ({
        lockingBytecode: page.lockingBytecode,
        valueSatoshis: page.valueSatoshis,
        sequenceNumber: page.sequenceNumber,
      })),
    ],
  )) as unknown as LocalWordVerifierBankDigests;
}

function candidateInfrastructure(
  candidate: V17PostLinkCandidateProfile,
  bankDigestHex: string,
  constructionIdHex: string,
): V17FinalProfileInfrastructure {
  return {
    schema: "ShieldKit/V17FinalProfileInfrastructure/v1",
    status: "materialized-requires-final-bchn-qualification",
    profile: candidate.profile,
    constructionIdHex,
    bankDigestHex,
    allocation: candidate.allocation,
    roles: candidate.roles,
    pages: candidate.pages,
    infrastructure: [
      ...candidate.roles.map((role) => ({
        kind: (role.index === 0 ? "pool" : "proof-worker") as "pool" | "proof-worker",
        index: role.index,
        roleId: role.name,
        lockingBytecode: encodeLockingBytecodeP2sh32(hash256(role.redeem)),
        unlockingBytecode: role.unlockingBytecode,
        valueSatoshis: role.index === 0
          ? null
          : localWordVerifierCarrierValue(role.index, candidate.allocation),
        sequenceNumber: role.index === 0
          ? localWordPoolCarrierSequence(candidate.proofBytes.length, candidate.allocation)
          : localWordVerifierCarrierSequence(role.index, candidate.allocation),
      })),
      ...candidate.pages.map((page) => ({
        kind: "rom-page" as const,
        index: page.inputIndex,
        roleId: `rom-page:${page.pageIndex}`,
        lockingBytecode: page.lockingBytecode,
        unlockingBytecode: page.unlockingBytecode,
        valueSatoshis: page.valueSatoshis,
        sequenceNumber: page.sequenceNumber,
      })),
    ],
  };
}

/**
 * Build exactly one allocation-specific, bank-bound candidate envelope for
 * each profile. This is resource-loop input, never the final product envelope.
 */
export function materializeV17PostLinkCandidateEnvelopes(args: {
  readonly candidates: V17PostLinkCandidateSet;
  readonly fixtures: readonly V17PublicSettlementFixture[];
}): readonly [
  V17PostLinkCandidateEnvelope,
  V17PostLinkCandidateEnvelope,
  V17PostLinkCandidateEnvelope,
] {
  assertCandidateSet(args.candidates);
  if (args.fixtures.length !== V17_PROFILES.length ||
    args.fixtures.some((fixture, profile) => fixture.profile !== profile)) {
    throw new Error("v17 post-link BCHN public fixture order");
  }
  const bankDigests = candidateBankDigests(args.candidates);
  const constructionIdHex = v17ConstructionIdHex({
    protocolIdHex: args.candidates.preview.certificate.protocolIdHex,
    bankDigests: bankDigests.map(binToHex) as unknown as readonly [string, string, string],
  });
  if (constructionIdHex !== args.candidates.constructionIdHex) {
    throw new Error("v17 post-link BCHN candidate construction identity");
  }
  const affineReader = args.candidates.preview.affineReader;
  if (affineReader === null) {
    throw new Error("v17 post-link BCHN missing affine reader construction");
  }
  const reader = validateV17AffineReaderConstruction(affineReader);
  const expectedSettlementVerifier = compileLocalWordValueSettlementGate(
    bankDigests,
    reader.vm,
  );
  const expectedSettlementRedeem = compileLocalWordPoolCarrierRedeem(expectedSettlementVerifier);
  const envelopes = V17_PROFILES.map((profile): V17PostLinkCandidateEnvelope => {
    const candidate = args.candidates.profiles[profile]!;
    const settlement = candidate.roles[0]!;
    if (!equal(settlement.verifier, expectedSettlementVerifier) ||
      !equal(settlement.redeem, expectedSettlementRedeem)) {
      throw new Error(`v17 post-link BCHN candidate settlement bank ${profile}`);
    }
    const bankDigestHex = binToHex(bankDigests[profile]!);
    const materialized = materializeV17ProfileSettlementTransaction({
      profileInfrastructure: candidateInfrastructure(
        candidate,
        bankDigestHex,
        constructionIdHex,
      ),
      authorizedBankDigests: bankDigests,
      affineReader: reader,
      fixture: args.fixtures[profile]!,
    });
    if (materialized.transaction.inputs.length !== candidate.projectedInputCount ||
      materialized.transaction.outputs.length !== candidate.projectedOutputCount ||
      materialized.sourceOutputs.length !== candidate.projectedInputCount) {
      throw new Error(`v17 post-link BCHN candidate envelope counts ${profile}`);
    }
    return {
      schema: "ShieldKit/V17PostLinkCandidateEnvelope/v1",
      status: "materialized-candidate-resource-envelope",
      qualification: "not-final-product-qualification",
      profile,
      bankDigestHex,
      candidate,
      materialized,
    };
  });
  return envelopes as unknown as readonly [
    V17PostLinkCandidateEnvelope,
    V17PostLinkCandidateEnvelope,
    V17PostLinkCandidateEnvelope,
  ];
}

function spawnAssayRunner(args: {
  readonly executablePath: string;
  readonly environment?: Readonly<Record<string, string>>;
}): V17PostLinkAssayRunner {
  return (request) => {
    const execution = spawnSync(
      args.executablePath,
      [
        "--transaction-file", request.transactionHexPath,
        "--source-outputs-file", request.sourceOutputsHexPath,
        "--input-index", String(request.inputIndex),
        "--mode", "consensus",
      ],
      {
        encoding: "utf8",
        maxBuffer: 4 * 1024 * 1024,
        env: { ...process.env, ...args.environment },
      },
    );
    return {
      status: execution.status,
      stdout: execution.stdout,
      stderr: execution.stderr,
      ...(execution.error === undefined ? {} : { error: execution.error }),
    };
  };
}

function parseAssayResult(stdout: string, profile: V17Profile, inputIndex: number): AssayResult {
  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout.trim());
  } catch {
    throw new Error(`v17 post-link BCHN non-JSON ${profile}:${inputIndex}`);
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(`v17 post-link BCHN result shape ${profile}:${inputIndex}`);
  }
  return parsed as AssayResult;
}

function validateAssayResult(args: {
  readonly result: AssayResult;
  readonly request: V17PostLinkAssayRequest;
}): CheckedAssayResult {
  const { result, request } = args;
  const input = request.transaction.inputs[request.inputIndex];
  const sourceOutput = request.sourceOutputs[request.inputIndex];
  if (input === undefined || sourceOutput === undefined ||
    result.engine !== "bchn" || result.engineVersion !== V17_BCHN_ASSAY_ENGINE_VERSION ||
    result.sourceTagCommit !== V17_BCHN_ASSAY_SOURCE_TAG_COMMIT ||
    result.scope !== "script-input-only" || result.mode !== "consensus" ||
    result.flags !== V17_BCHN_MAY_2026_CONSENSUS_FLAGS ||
    result.inputIndex !== request.inputIndex ||
    result.inputCount !== request.transaction.inputs.length ||
    result.sourceOutputCount !== request.sourceOutputs.length ||
    result.transactionBytes !== request.transactionBytes.length ||
    result.sourceOutputsBytes !== request.sourceOutputsBytes.length ||
    result.unlockingBytecodeBytes !== input.unlockingBytecode.length ||
    result.lockingBytecodeBytes !== sourceOutput.lockingBytecode.length ||
    result.valid !== true || result.scriptErrorCode !== 0 || result.scriptError !== "No error" ||
    result.metricsReliable !== true || result.metrics === null ||
    typeof result.metrics !== "object" || Array.isArray(result.metrics)) {
    throw new Error(`v17 post-link BCHN identity or acceptance ${request.profile}:${request.inputIndex}`);
  }
  const metrics = result.metrics as AssayMetrics;
  const checked = {
    baseOpCost: exactInteger(metrics.baseOpCost, "base operation cost"),
    compositeOpCost: exactInteger(metrics.compositeOpCost, "composite operation cost", 1),
    opCostLimit: exactInteger(metrics.opCostLimit, "operation cost limit", 1),
    hashDigestIterations: exactInteger(metrics.hashDigestIterations, "hash iterations"),
    hashDigestIterationsLimit: exactInteger(
      metrics.hashDigestIterationsLimit,
      "hash iteration limit",
      1,
    ),
    sigChecks: exactInteger(metrics.sigChecks, "signature checks"),
  };
  if (metrics.sigChecksInputLimit !== null ||
    metrics.sigChecksTransactionLimit !== V17_BCHN_TRANSACTION_SIGCHECKS ||
    checked.compositeOpCost > checked.opCostLimit ||
    checked.hashDigestIterations > checked.hashDigestIterationsLimit) {
    throw new Error(`v17 post-link BCHN resource limit ${request.profile}:${request.inputIndex}`);
  }
  return checked;
}

function defaultMemoryControlRunner(args: {
  readonly profile: V17Profile;
  readonly inputIndex: number;
  readonly transaction: Transaction;
  readonly sourceOutputs: readonly Output[];
}): V17PostLinkMemoryControlResult {
  const instructionSet = createInstructionSetBch2026(false);
  const every = instructionSet.every!;
  let maximumMemorySlots = 1;
  let maximumControlDepth = 0;
  const observe = (state: Parameters<typeof every>[0]): void => {
    maximumMemorySlots = Math.max(
      maximumMemorySlots,
      state.stack.length + state.alternateStack.length + state.functionCount,
    );
    maximumControlDepth = Math.max(maximumControlDepth, state.controlStack.length);
  };
  const vm = createVirtualMachine({
    ...instructionSet,
    every: (state) => {
      // Libauth is diagnostic-only here. Disable its opcost stop so its known
      // OP_DEFINE accounting defect cannot decide acceptance or operation cost.
      state.metrics.maximumOperationCost = 1_000_000_000;
      observe(state);
      const next = every(state);
      observe(next);
      return next;
    },
  });
  const state = vm.evaluate({
    inputIndex: args.inputIndex,
    sourceOutputs: args.sourceOutputs,
    transaction: args.transaction,
  } as never);
  observe(state);
  if (vm.stateSuccess(state) !== true) {
    throw new Error(
      `v17 post-link libauth memory/control diagnostic ${args.profile}:${args.inputIndex}: ${String(state.error)}`,
    );
  }
  return { maximumMemorySlots, maximumControlDepth };
}

function checkedMemoryControl(
  result: V17PostLinkMemoryControlResult,
  profile: V17Profile,
  inputIndex: number,
): V17PostLinkMemoryControlResult {
  if (!Number.isSafeInteger(result.maximumMemorySlots) || result.maximumMemorySlots < 1 ||
    result.maximumMemorySlots > V17_MAX_STACK_ITEMS ||
    !Number.isSafeInteger(result.maximumControlDepth) || result.maximumControlDepth < 0 ||
    result.maximumControlDepth > V17_MAX_CONTROL_DEPTH) {
    throw new Error(`v17 post-link memory/control limit ${profile}:${inputIndex}`);
  }
  return result;
}

/**
 * Run BCHN against every input of each exact candidate envelope. Allocation
 * rows include only the semantic verifier roles; ROM and transparent funding
 * acceptance remain bound into the candidate-envelope evidence digest.
 */
export function measureV17PostLinkCandidatesWithBchn(
  args: V17PostLinkBchnMeasurementArguments,
): readonly [
  V17BchnPostLinkEvidence,
  V17BchnPostLinkEvidence,
  V17BchnPostLinkEvidence,
] {
  if ((args.assayExecutablePath === undefined) === (args.assayRunner === undefined)) {
    throw new Error("v17 post-link BCHN requires exactly one assay runner");
  }
  if ((args.assayRunner === undefined) !==
    (args.injectedRunnerQualification === undefined) ||
    (args.assayRunner !== undefined &&
      args.injectedRunnerQualification !== "test-only-nonqualifying")) {
    throw new Error("v17 post-link BCHN injected runner is test-only");
  }
  const envelopes = materializeV17PostLinkCandidateEnvelopes(args);
  const assayRunner = args.assayRunner ?? spawnAssayRunner({
    executablePath: args.assayExecutablePath!,
    environment: args.assayEnvironment,
  });
  const memoryControlRunner = args.memoryControlRunner ?? defaultMemoryControlRunner;
  const assayProvenance: V17PostLinkAssayProvenance = args.assayExecutablePath === undefined
    ? {
      mode: "injected-runner-test-only" as const,
      qualification: "test-only-nonqualifying" as const,
    }
    : {
      mode: "byte-exact-executable" as const,
      executableSha256Hex: sha256Hex(new Uint8Array(readFileSync(args.assayExecutablePath))),
    };
  const temporaryRoot = mkdtempSync(join(tmpdir(), "shieldkit-v17-post-link-bchn-"));
  try {
    const evidence = envelopes.map((envelope): V17BchnPostLinkEvidence => {
      const { candidate, materialized, profile } = envelope;
      const transactionHexPath = join(temporaryRoot, `profile-${profile}.tx.hex`);
      const sourceOutputsHexPath = join(temporaryRoot, `profile-${profile}.source-outputs.hex`);
      writeFileSync(
        transactionHexPath,
        `${Buffer.from(materialized.rawTransactionBytes).toString("hex")}\n`,
        { mode: 0o600 },
      );
      writeFileSync(
        sourceOutputsHexPath,
        `${Buffer.from(materialized.encodedSourceOutputsBytes).toString("hex")}\n`,
        { mode: 0o600 },
      );

      const allInputEvidence: {
        readonly inputIndex: number;
        readonly operationCostEvidenceSha256Hex: string;
        readonly sigChecks: number;
      }[] = [];
      const workers = [] as Array<V17IndependentPostLinkEvidence["workers"][number]>;
      let profileSigChecks = 0;
      for (let inputIndex = 0; inputIndex < materialized.transaction.inputs.length; inputIndex += 1) {
        const request: V17PostLinkAssayRequest = {
          profile,
          inputIndex,
          transaction: materialized.transaction,
          sourceOutputs: materialized.sourceOutputs,
          transactionBytes: materialized.rawTransactionBytes,
          sourceOutputsBytes: materialized.encodedSourceOutputsBytes,
          transactionHexPath,
          sourceOutputsHexPath,
        };
        const execution = assayRunner(request);
        if (execution.error !== undefined || execution.status !== 0) {
          throw new Error(
            `v17 post-link BCHN execution ${profile}:${inputIndex}: ${execution.error?.message ?? execution.stderr.trim()}`,
          );
        }
        const parsed = parseAssayResult(execution.stdout, profile, inputIndex);
        const checked = validateAssayResult({ result: parsed, request });
        profileSigChecks += checked.sigChecks;
        const input = materialized.transaction.inputs[inputIndex]!;
        const sourceOutput = materialized.sourceOutputs[inputIndex]!;
        const role = candidate.roles[inputIndex];
        const diagnostic = role === undefined
          ? undefined
          : checkedMemoryControl(memoryControlRunner({
            profile,
            inputIndex,
            transaction: materialized.transaction,
            sourceOutputs: materialized.sourceOutputs,
          }), profile, inputIndex);
        const operationCostEvidenceSha256Hex = canonicalDigest({
          schema: V17_POST_LINK_BCHN_MEASUREMENT_SCHEMA,
          scope: "one-byte-exact-candidate-envelope-input",
          profile,
          inputIndex,
          romPreviewIdHex: candidate.romPreviewIdHex,
          transactionSha256Hex: materialized.transactionSha256Hex,
          sourceOutputsSha256Hex: materialized.sourceOutputsSha256Hex,
          assayProvenance,
          unlockingSha256Hex: sha256Hex(input.unlockingBytecode),
          lockingSha256Hex: sha256Hex(sourceOutput.lockingBytecode),
          valueSatoshis: sourceOutput.valueSatoshis.toString(),
          sequenceNumber: input.sequenceNumber,
          assay: checked,
          ...(diagnostic === undefined ? {} : {
            memoryControlDiagnostic: {
              engine: "libauth-3.1.0-next.8-bch2026-diagnostic-only",
              operationCostAuthority: "none",
              ...diagnostic,
            },
          }),
        });
        allInputEvidence.push({
          inputIndex,
          operationCostEvidenceSha256Hex,
          sigChecks: checked.sigChecks,
        });
        if (role !== undefined) {
          workers.push({
            accepted: true,
            fixtureInputCount: materialized.transaction.inputs.length,
            fixtureOutputCount: materialized.transaction.outputs.length,
            logicalInputIndex: inputIndex,
            roleId: role.name,
            redeemSha256Hex: sha256Hex(role.redeem),
            unlockingSha256Hex: sha256Hex(role.unlockingBytecode),
            maximumOperationCost: checked.compositeOpCost,
            densityControlLength: V17_INPUT_FIXED_DENSITY_BYTES + role.unlockingBytecode.length,
            maximumMemorySlots: diagnostic!.maximumMemorySlots,
            maximumControlDepth: diagnostic!.maximumControlDepth,
            valueSatoshis: sourceOutput.valueSatoshis,
            sequenceNumber: input.sequenceNumber,
            operationCostEngine: "bchn-v29.0.0",
            operationCostEvidenceSha256Hex,
          });
        }
      }
      if (profileSigChecks > V17_BCHN_TRANSACTION_SIGCHECKS ||
        workers.length !== candidate.roles.length) {
        throw new Error(`v17 post-link BCHN candidate aggregate ${profile}`);
      }
      const candidateEnvelopeEvidenceSha256Hex = canonicalDigest({
        schema: V17_POST_LINK_BCHN_MEASUREMENT_SCHEMA,
        status: "accepted-byte-exact-candidate-envelope",
        qualification: "candidate-resource-only-not-final-qualification",
        profile,
        romPreviewIdHex: candidate.romPreviewIdHex,
        bankDigestHex: envelope.bankDigestHex,
        proofSha256Hex: sha256Hex(candidate.proofBytes),
        transactionBytes: materialized.rawTransactionBytes.length,
        transactionSha256Hex: materialized.transactionSha256Hex,
        sourceOutputsBytes: materialized.encodedSourceOutputsBytes.length,
        sourceOutputsSha256Hex: materialized.sourceOutputsSha256Hex,
        projectedInputCount: candidate.projectedInputCount,
        projectedOutputCount: candidate.projectedOutputCount,
        checkedInputs: allInputEvidence.length,
        profileSigChecks,
        assayProvenance,
        allInputEvidence,
        workers: workers.map((worker) => ({
          logicalInputIndex: worker.logicalInputIndex,
          roleId: worker.roleId,
          redeemSha256Hex: worker.redeemSha256Hex,
          unlockingSha256Hex: worker.unlockingSha256Hex,
          valueSatoshis: worker.valueSatoshis.toString(),
          sequenceNumber: worker.sequenceNumber,
          maximumOperationCost: worker.maximumOperationCost,
          maximumMemorySlots: worker.maximumMemorySlots,
          maximumControlDepth: worker.maximumControlDepth,
          operationCostEvidenceSha256Hex: worker.operationCostEvidenceSha256Hex,
        })),
      });
      return {
        schema: "ShieldKit/V17IndependentPostLinkEvidence/v1",
        status: "accepted-byte-exact-candidate-envelope",
        qualification: "candidate-resource-only-not-final-qualification",
        romPreviewIdHex: candidate.romPreviewIdHex,
        profile,
        projectedInputCount: candidate.projectedInputCount,
        projectedOutputCount: candidate.projectedOutputCount,
        candidateEnvelopeEvidenceSha256Hex,
        assayProvenance,
        checkedEnvelopeInputs: allInputEvidence.length,
        transactionSha256Hex: materialized.transactionSha256Hex,
        sourceOutputsSha256Hex: materialized.sourceOutputsSha256Hex,
        workers,
      };
    });
    return evidence as unknown as readonly [
      V17BchnPostLinkEvidence,
      V17BchnPostLinkEvidence,
      V17BchnPostLinkEvidence,
    ];
  } finally {
    rmSync(temporaryRoot, { recursive: true, force: true });
  }
}

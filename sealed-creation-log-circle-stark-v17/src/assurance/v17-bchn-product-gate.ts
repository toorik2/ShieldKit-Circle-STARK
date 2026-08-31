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
  decodeTransaction,
  decodeTransactionOutputs,
  encodeTransaction,
  encodeTransactionOutputs,
  verifyTransactionTokens,
  type Output,
  type Transaction,
} from "@bitauth/libauth";
import {
  V17_PROFILES,
  canonicalV17Json,
  v17ProtocolIdHex,
  type V17Profile,
} from "../construction/v17-graph.ts";
import {
  assessV17FinalAllocationStability,
  bindV17PostLinkEvidence,
  certifyV17ProductLink,
  materializeV17FinalInfrastructure,
  materializeV17PostLinkCandidates,
  previewV17ProductRom,
  type V17FinalInfrastructureSet,
  type V17IndependentPostLinkEvidence,
  type V17ProfileProofMaterial,
} from "../construction/v17-product-link.ts";
import type { V17AffineAllocation } from "../chain/v17-affine-allocation.ts";
import {
  replayV17DensityClosureTrace,
  type V17DensityClosureTrace,
} from
  "../construction/v17-density-closure.ts";
import {
  V17_INPUT_FIXED_DENSITY_BYTES,
  type V17PostLinkMeasuredProfile,
} from "../construction/v17-linker.ts";
import { encodeV17CanonicalPush } from "../chain/v17-code-rom.ts";
import { V17_PRODUCTION_ROLE_LAYOUT } from "../chain/v17-role-layout.ts";
import {
  assertV17FinalInfrastructureIdentity,
  replayV17FinalInfrastructureIdentity,
  type V17FinalInfrastructureIdentity,
  type V17FinalInfrastructureProfileIdentity,
} from "./v17-final-infrastructure-identity.ts";
import {
  decodeState,
  STATE_BASE_SATS,
} from "../pool/state.ts";

/**
 * Exact constants used by this qualification gate.
 *
 * BCHN v29.0.0 reports MAX_TX_SIGCHECKS itself, and its pinned amount.h supplies
 * MAX_MONEY. The transaction/script/token limits were separately checked
 * against bch-constants source commit
 * 864c53ee34924cca6c6b6d96607ff2cedcdccf02. CashToken commitment and authority
 * behavior is documented by cashscript-next evidence TOK-003, TOK-008,
 * TOK-009, and TOK-012.
 */
export const V17_BCHN_CONSENSUS_TRANSACTION_BYTES = 1_000_000;
export const V17_BCHN_CONSENSUS_SCRIPT_BYTES = 10_000;
export const V17_BCHN_TRANSACTION_SIGCHECKS = 3_000;
export const V17_BCHN_MAX_TOKEN_COMMITMENT_BYTES = 128;
export const V17_BCHN_MAX_MONEY_SATOSHIS = 2_100_000_000_000_000n;
export const V17_BCHN_ASSAY_ENGINE_VERSION = "29.0.0";
export const V17_BCHN_ASSAY_SOURCE_TAG_COMMIT =
  "89a591f7c5b1fd110c0819377ad8f2647d656800";
export const V17_BCHN_MAY_2026_CONSENSUS_FLAGS = 1_604_405_103;

export const V17_BCHN_PRODUCT_EVIDENCE_SCHEMA =
  "ShieldKit/V17BchnProductQualification/v4" as const;

export type V17BchnProductArtifact = {
  readonly profile: V17Profile;
  /** Exact raw network serialization, not hex text. */
  readonly transactionPath: string;
  /** Exact CompactSize-prefixed vector<CTxOut> serialization, not hex text. */
  readonly sourceOutputsPath: string;
};

export type V17BchnInputEvidence = {
  readonly inputIndex: number;
  readonly unlockingBytecodeBytes: number;
  readonly lockingBytecodeBytes: number;
  readonly baseOpCost: number;
  readonly compositeOpCost: number;
  readonly opCostLimit: number;
  readonly hashDigestIterations: number;
  readonly hashDigestIterationsLimit: number;
  readonly sigChecks: number;
};

export type V17BchnProfileEvidence = {
  readonly profile: V17Profile;
  readonly transactionBytes: number;
  readonly transactionSha256Hex: string;
  readonly sourceOutputsBytes: number;
  readonly sourceOutputsSha256Hex: string;
  readonly inputCount: number;
  readonly outputCount: number;
  readonly inputSatoshis: string;
  readonly outputSatoshis: string;
  readonly minerFeeSatoshis: string;
  readonly infrastructureInputs: number;
  readonly bankDigestHex: string;
  readonly proofBytes: number;
  readonly proofSha256Hex: string;
  readonly infrastructureInventorySha256Hex: string;
  readonly infrastructureIdentityCheck: "passed-byte-exact";
  readonly tokenRuleCheck: "passed-libauth-may-2026";
  readonly v17TopologyCheck: "passed";
  readonly sigChecks: number;
  readonly inputs: readonly V17BchnInputEvidence[];
};

export type V17BchnProductEvidenceBody = {
  readonly schema: typeof V17_BCHN_PRODUCT_EVIDENCE_SCHEMA;
  readonly status: "passed";
  readonly protocolIdHex: string;
  readonly constructionIdHex: string;
  readonly linkerCertificateIdHex: string;
  readonly finalInfrastructureIdentitySha256Hex: string;
  readonly finalDensityTraceRootSha256Hex: string;
  readonly finalDensityRowsSha256Hex: string;
  readonly scope: {
    readonly bchn: "every-input-VerifyScript-only";
    readonly localEnvelope:
      "canonical-serialization-value-token-v17-topology-and-byte-exact-infrastructure";
    readonly protocolIdentity: "linker-certificate-and-final-infrastructure-replayed";
    readonly excluded: readonly [
      "BCHN transaction-level CheckTransaction and CheckTxInputs",
      "UTXO existence maturity and relative-locktime context",
      "standardness mempool block acceptance mining and broadcast",
    ];
  };
  readonly engine: {
    readonly name: "bchn";
    readonly version: typeof V17_BCHN_ASSAY_ENGINE_VERSION;
    readonly sourceTagCommit: typeof V17_BCHN_ASSAY_SOURCE_TAG_COMMIT;
    readonly executableSha256Hex: string;
    readonly mode: "consensus";
    readonly flags: typeof V17_BCHN_MAY_2026_CONSENSUS_FLAGS;
  };
  readonly limits: {
    readonly transactionBytes: typeof V17_BCHN_CONSENSUS_TRANSACTION_BYTES;
    readonly scriptBytes: typeof V17_BCHN_CONSENSUS_SCRIPT_BYTES;
    readonly sigChecksPerTransaction: typeof V17_BCHN_TRANSACTION_SIGCHECKS;
    readonly tokenCommitmentBytes: typeof V17_BCHN_MAX_TOKEN_COMMITMENT_BYTES;
    readonly bchConstantsSourceCommit:
      "864c53ee34924cca6c6b6d96607ff2cedcdccf02";
  };
  readonly profiles: readonly V17BchnProfileEvidence[];
  readonly aggregate: {
    readonly profileCount: 3;
    readonly checkedInputs: number;
    readonly maximumProfileSigChecks: number;
    readonly maximumCompositeOpCost: number;
    readonly maximumHashDigestIterations: number;
  };
};

export type V17BchnProductEvidence = V17BchnProductEvidenceBody & {
  /** SHA-256 of canonical JSON for every other field in this evidence object. */
  readonly evidenceSha256Hex: string;
};

/**
 * Qualification artifacts kept outside the compact, hash-bound receipt. The
 * trace remains independently replayable; its root and terminal rows digest
 * are the commitments carried by `evidence`.
 */
export type V17BchnProductGateResult = {
  readonly evidence: V17BchnProductEvidence;
  readonly finalDensityTrace: V17DensityClosureTrace;
};

export type V17BchnProductGateArguments = {
  readonly assayExecutablePath: string;
  readonly artifacts: readonly V17BchnProductArtifact[];
  /** Inputs from which this gate independently recompiles and replays the product. */
  readonly canonicalProduct: {
    readonly proofs: readonly V17ProfileProofMaterial[];
    readonly allocation: V17AffineAllocation;
    readonly postLinkEvidence: readonly V17IndependentPostLinkEvidence[];
    readonly densityTrace: V17DensityClosureTrace;
  };
  /** Test-only/integration environment additions; never enter evidence. */
  readonly assayEnvironment?: Readonly<Record<string, string>>;
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

function canonicalJson(value: unknown): string {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("v17 evidence contains a non-finite number");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map((key) =>
      `${JSON.stringify(key)}:${canonicalJson(record[key])}`).join(",")}}`;
  }
  throw new Error(`v17 evidence contains unsupported ${typeof value}`);
}

function sha256Hex(bytes: Uint8Array | string): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function domainDigest(domain: string, value: unknown): string {
  return sha256Hex(`${domain}\u0000${canonicalV17Json(value)}`);
}

function concat(...parts: readonly Uint8Array[]): Uint8Array {
  const result = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  parts.forEach((part) => {
    result.set(part, offset);
    offset += part.length;
  });
  return result;
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((byte, index) => byte === right[index]);
}

function exactInteger(value: unknown, label: string, minimum = 0): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum) {
    throw new Error(`v17 BCHN assay ${label}`);
  }
  return value as number;
}

function tokenless(output: Output | undefined): output is Output {
  return output !== undefined && output.token === undefined;
}

function outputEqual(left: Output, right: Output): boolean {
  return left.valueSatoshis === right.valueSatoshis &&
    equalBytes(left.lockingBytecode, right.lockingBytecode) &&
    left.token === undefined && right.token === undefined;
}

function decodeExactArtifacts(
  artifact: V17BchnProductArtifact,
): {
  readonly transactionBytes: Uint8Array;
  readonly sourceOutputBytes: Uint8Array;
  readonly transaction: Transaction;
  readonly sourceOutputs: Output[];
} {
  const transactionBytes = new Uint8Array(readFileSync(artifact.transactionPath));
  const sourceOutputBytes = new Uint8Array(readFileSync(artifact.sourceOutputsPath));
  if (transactionBytes.length > V17_BCHN_CONSENSUS_TRANSACTION_BYTES) {
    throw new Error(`v17 profile ${artifact.profile} transaction exceeds 1000000 bytes`);
  }
  const decodedTransaction = decodeTransaction(transactionBytes);
  if (typeof decodedTransaction === "string") {
    throw new Error(`v17 profile ${artifact.profile} transaction decode: ${decodedTransaction}`);
  }
  const decodedSourceOutputs = decodeTransactionOutputs(sourceOutputBytes);
  if (typeof decodedSourceOutputs === "string") {
    throw new Error(`v17 profile ${artifact.profile} source outputs decode: ${decodedSourceOutputs}`);
  }
  if (!equalBytes(encodeTransaction(decodedTransaction), transactionBytes)) {
    throw new Error(`v17 profile ${artifact.profile} non-canonical transaction serialization`);
  }
  if (!equalBytes(encodeTransactionOutputs(decodedSourceOutputs), sourceOutputBytes)) {
    throw new Error(`v17 profile ${artifact.profile} non-canonical source-output serialization`);
  }
  return {
    transactionBytes,
    sourceOutputBytes,
    transaction: decodedTransaction,
    sourceOutputs: decodedSourceOutputs,
  };
}

function assertScriptWidths(
  profile: V17Profile,
  transaction: Transaction,
  sourceOutputs: readonly Output[],
): void {
  transaction.inputs.forEach((input, index) => {
    if (input.unlockingBytecode.length > V17_BCHN_CONSENSUS_SCRIPT_BYTES) {
      throw new Error(`v17 profile ${profile} input ${index} unlocking bytecode exceeds 10000 bytes`);
    }
  });
  [...sourceOutputs, ...transaction.outputs].forEach((output, index) => {
    if (output.lockingBytecode.length > V17_BCHN_CONSENSUS_SCRIPT_BYTES) {
      throw new Error(`v17 profile ${profile} output ${index} locking bytecode exceeds 10000 bytes`);
    }
  });
}

function assertUniqueNonCoinbaseOutpoints(profile: V17Profile, transaction: Transaction): void {
  const seen = new Set<string>();
  transaction.inputs.forEach((input, index) => {
    const hash = Buffer.from(input.outpointTransactionHash).toString("hex");
    if (hash === "00".repeat(32) && input.outpointIndex === 0xffff_ffff) {
      throw new Error(`v17 profile ${profile} input ${index} uses a coinbase outpoint`);
    }
    const id = `${hash}:${input.outpointIndex}`;
    if (seen.has(id)) throw new Error(`v17 profile ${profile} duplicate outpoint ${index}`);
    seen.add(id);
  });
}

function checkedSatoshiSum(profile: V17Profile, label: string, outputs: readonly Output[]): bigint {
  let total = 0n;
  outputs.forEach((output, index) => {
    if (output.valueSatoshis < 0n ||
      output.valueSatoshis > V17_BCHN_MAX_MONEY_SATOSHIS) {
      throw new Error(`v17 profile ${profile} ${label} ${index} money range`);
    }
    total += output.valueSatoshis;
    if (total > V17_BCHN_MAX_MONEY_SATOSHIS) {
      throw new Error(`v17 profile ${profile} ${label} sum money range`);
    }
  });
  return total;
}

function assertV17TokenAndTopology(
  profile: V17Profile,
  transaction: Transaction,
  sourceOutputs: readonly Output[],
): number {
  const poolSource = sourceOutputs[0];
  const poolOutput = transaction.outputs[0];
  if (poolSource === undefined || poolOutput === undefined ||
    poolSource.token === undefined || poolOutput.token === undefined ||
    poolSource.token.amount !== 0n || poolOutput.token.amount !== 0n ||
    poolSource.token.nft?.capability !== "mutable" ||
    poolOutput.token.nft?.capability !== "mutable" ||
    poolSource.token.category.length !== 32 ||
    !equalBytes(poolSource.token.category, poolOutput.token.category) ||
    !equalBytes(poolSource.lockingBytecode, poolOutput.lockingBytecode) ||
    poolSource.valueSatoshis < STATE_BASE_SATS || poolOutput.valueSatoshis < STATE_BASE_SATS) {
    throw new Error(`v17 profile ${profile} mutable pool continuation`);
  }
  const oldState = decodeState(
    poolSource.token.nft.commitment,
    poolSource.valueSatoshis - STATE_BASE_SATS,
  );
  const newState = decodeState(
    poolOutput.token.nft.commitment,
    poolOutput.valueSatoshis - STATE_BASE_SATS,
  );
  if (newState.sequence !== oldState.sequence + 1n ||
    (profile === 0 && newState.reserveSats <= oldState.reserveSats) ||
    (profile !== 0 && newState.reserveSats >= oldState.reserveSats)) {
    throw new Error(`v17 profile ${profile} public state progression`);
  }
  if (sourceOutputs.slice(1).some((output) => output.token !== undefined) ||
    transaction.outputs.slice(1).some((output) => output.token !== undefined)) {
    throw new Error(`v17 profile ${profile} non-pool token`);
  }

  const infrastructureInputs = profile === 0
    ? sourceOutputs.length - 1
    : sourceOutputs.length;
  if (infrastructureInputs < 2) {
    throw new Error(`v17 profile ${profile} infrastructure input count`);
  }
  for (let index = 1; index < infrastructureInputs; index += 1) {
    const source = sourceOutputs[index];
    const output = transaction.outputs[index];
    if (source === undefined || output === undefined || !outputEqual(source, output)) {
      throw new Error(`v17 profile ${profile} infrastructure roll-forward ${index}`);
    }
  }

  const expectedOutputs = infrastructureInputs + (profile === 0 ? 1 : profile === 1 ? 2 : 3);
  if (transaction.outputs.length !== expectedOutputs) {
    throw new Error(`v17 profile ${profile} public suffix count`);
  }
  if (profile === 0) {
    const funding = sourceOutputs[infrastructureInputs];
    const edge = transaction.outputs[infrastructureInputs];
    if (!tokenless(funding) || !tokenless(edge) || edge.valueSatoshis !== 0n ||
      poolOutput.valueSatoshis <= poolSource.valueSatoshis) {
      throw new Error("v17 profile 0 deposit suffix");
    }
  } else {
    const payout = transaction.outputs[infrastructureInputs];
    const nullifier = transaction.outputs[infrastructureInputs + 1];
    const edge = profile === 2 ? transaction.outputs[infrastructureInputs + 2] : undefined;
    if (!tokenless(payout) || payout.valueSatoshis <= 0n ||
      !tokenless(nullifier) || nullifier.valueSatoshis !== 0n ||
      (profile === 2 && (!tokenless(edge) || edge.valueSatoshis !== 0n)) ||
      poolOutput.valueSatoshis >= poolSource.valueSatoshis) {
      throw new Error(`v17 profile ${profile} withdrawal suffix`);
    }
  }
  return infrastructureInputs;
}

function assertLocalEnvelope(
  profile: V17Profile,
  transaction: Transaction,
  sourceOutputs: readonly Output[],
): {
  readonly inputSatoshis: bigint;
  readonly outputSatoshis: bigint;
  readonly minerFeeSatoshis: bigint;
  readonly infrastructureInputs: number;
} {
  if (transaction.version !== 2 || transaction.locktime !== 0 ||
    transaction.inputs.length === 0 || transaction.outputs.length === 0 ||
    sourceOutputs.length !== transaction.inputs.length) {
    throw new Error(`v17 profile ${profile} transaction envelope`);
  }
  assertScriptWidths(profile, transaction, sourceOutputs);
  assertUniqueNonCoinbaseOutpoints(profile, transaction);
  const inputSatoshis = checkedSatoshiSum(profile, "source output", sourceOutputs);
  const outputSatoshis = checkedSatoshiSum(profile, "transaction output", transaction.outputs);
  if (outputSatoshis > inputSatoshis) {
    throw new Error(`v17 profile ${profile} creates satoshis`);
  }
  const tokenResult = verifyTransactionTokens(
    transaction,
    [...sourceOutputs],
    { maximumTokenCommitmentLength: V17_BCHN_MAX_TOKEN_COMMITMENT_BYTES },
  );
  if (tokenResult !== true) {
    throw new Error(`v17 profile ${profile} CashToken rules: ${tokenResult}`);
  }
  return {
    inputSatoshis,
    outputSatoshis,
    minerFeeSatoshis: inputSatoshis - outputSatoshis,
    infrastructureInputs: assertV17TokenAndTopology(profile, transaction, sourceOutputs),
  };
}

function assertExactFinalInfrastructure(args: {
  readonly profile: V17Profile;
  readonly transaction: Transaction;
  readonly sourceOutputs: readonly Output[];
  readonly finalInfrastructure: V17FinalInfrastructureSet;
  readonly identity: V17FinalInfrastructureProfileIdentity;
}): void {
  const { profile, transaction, sourceOutputs, finalInfrastructure, identity } = args;
  const expected = finalInfrastructure.profiles[profile]!;
  const infrastructureCount = expected.infrastructure.length;
  const expectedInputs = infrastructureCount + (profile === 0 ? 1 : 0);
  if (identity.profile !== profile || identity.infrastructureInputs !== infrastructureCount ||
    identity.romPages !== expected.pages.length || identity.bankDigestHex !== expected.bankDigestHex ||
    transaction.inputs.length !== expectedInputs || sourceOutputs.length !== expectedInputs) {
    throw new Error(`v17 profile ${profile} final infrastructure envelope`);
  }
  expected.infrastructure.forEach((role, index) => {
    const input = transaction.inputs[index];
    const sourceOutput = sourceOutputs[index];
    const rolledOutput = transaction.outputs[index];
    if (input === undefined || sourceOutput === undefined || rolledOutput === undefined ||
      input.sequenceNumber !== role.sequenceNumber ||
      !equalBytes(input.unlockingBytecode, role.unlockingBytecode) ||
      !equalBytes(sourceOutput.lockingBytecode, role.lockingBytecode) ||
      !equalBytes(rolledOutput.lockingBytecode, role.lockingBytecode)) {
      throw new Error(`v17 profile ${profile} final infrastructure bytes ${index}`);
    }
    if (index === 0) {
      if (role.kind !== "pool" || role.valueSatoshis !== null) {
        throw new Error(`v17 profile ${profile} final pool identity`);
      }
      return;
    }
    if (role.valueSatoshis === null || sourceOutput.token !== undefined ||
      rolledOutput.token !== undefined || sourceOutput.valueSatoshis !== role.valueSatoshis ||
      rolledOutput.valueSatoshis !== role.valueSatoshis) {
      throw new Error(`v17 profile ${profile} final infrastructure value ${index}`);
    }
  });
}

function parseAssayResult(
  stdout: string,
  profile: V17Profile,
  inputIndex: number,
): AssayResult {
  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout.trim());
  } catch {
    throw new Error(`v17 profile ${profile} input ${inputIndex} BCHN assay non-JSON output`);
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(`v17 profile ${profile} input ${inputIndex} BCHN assay result shape`);
  }
  return parsed as AssayResult;
}

function validateAssayResult(args: {
  readonly result: AssayResult;
  readonly profile: V17Profile;
  readonly inputIndex: number;
  readonly transaction: Transaction;
  readonly sourceOutputs: readonly Output[];
  readonly transactionBytes: number;
  readonly sourceOutputsBytes: number;
}): V17BchnInputEvidence {
  const { result, profile, inputIndex, transaction, sourceOutputs } = args;
  if (result.engine !== "bchn" ||
    result.engineVersion !== V17_BCHN_ASSAY_ENGINE_VERSION ||
    result.sourceTagCommit !== V17_BCHN_ASSAY_SOURCE_TAG_COMMIT ||
    result.scope !== "script-input-only" || result.mode !== "consensus" ||
    result.flags !== V17_BCHN_MAY_2026_CONSENSUS_FLAGS ||
    result.inputIndex !== inputIndex || result.inputCount !== transaction.inputs.length ||
    result.sourceOutputCount !== sourceOutputs.length ||
    result.transactionBytes !== args.transactionBytes ||
    result.sourceOutputsBytes !== args.sourceOutputsBytes ||
    result.unlockingBytecodeBytes !== transaction.inputs[inputIndex]!.unlockingBytecode.length ||
    result.lockingBytecodeBytes !== sourceOutputs[inputIndex]!.lockingBytecode.length ||
    result.valid !== true || result.metricsReliable !== true ||
    result.scriptErrorCode !== 0 || result.scriptError !== "No error" ||
    result.metrics === null || typeof result.metrics !== "object" || Array.isArray(result.metrics)) {
    throw new Error(`v17 profile ${profile} input ${inputIndex} BCHN assay identity or validity`);
  }
  const metrics = result.metrics as AssayMetrics;
  const baseOpCost = exactInteger(metrics.baseOpCost, "base operation cost");
  const compositeOpCost = exactInteger(metrics.compositeOpCost, "composite operation cost");
  const opCostLimit = exactInteger(metrics.opCostLimit, "operation cost limit", 1);
  const hashDigestIterations = exactInteger(
    metrics.hashDigestIterations,
    "hash digest iterations",
  );
  const hashDigestIterationsLimit = exactInteger(
    metrics.hashDigestIterationsLimit,
    "hash digest iteration limit",
    1,
  );
  const sigChecks = exactInteger(metrics.sigChecks, "signature checks");
  if (metrics.sigChecksInputLimit !== null ||
    metrics.sigChecksTransactionLimit !== V17_BCHN_TRANSACTION_SIGCHECKS ||
    compositeOpCost > opCostLimit || hashDigestIterations > hashDigestIterationsLimit) {
    throw new Error(`v17 profile ${profile} input ${inputIndex} BCHN assay limits`);
  }
  return {
    inputIndex,
    unlockingBytecodeBytes: result.unlockingBytecodeBytes as number,
    lockingBytecodeBytes: result.lockingBytecodeBytes as number,
    baseOpCost,
    compositeOpCost,
    opCostLimit,
    hashDigestIterations,
    hashDigestIterationsLimit,
    sigChecks,
  };
}

type V17ExactAssayedProfile = {
  readonly profile: V17Profile;
  readonly transactionSha256Hex: string;
  readonly sourceOutputsSha256Hex: string;
  readonly transaction: Transaction;
  readonly sourceOutputs: readonly Output[];
  readonly inputs: readonly V17BchnInputEvidence[];
};

/**
 * Rebuild the 210 density-bearing semantic workers from the final serialized
 * transactions and the assay results just returned for those exact inputs.
 * ROM pages and profile-0 funding follow the semantic roles and remain final
 * product evidence, but they never enter the proof-carrier allocation law.
 */
function deriveV17FinalAssayedProfiles(args: {
  readonly assayExecutableSha256Hex: string;
  readonly candidates: ReturnType<typeof materializeV17PostLinkCandidates>;
  readonly postLinkProfiles: readonly [
    V17PostLinkMeasuredProfile,
    V17PostLinkMeasuredProfile,
    V17PostLinkMeasuredProfile,
  ];
  readonly finalInfrastructure: V17FinalInfrastructureSet;
  readonly exactProfiles: readonly V17ExactAssayedProfile[];
}): readonly [
  V17PostLinkMeasuredProfile,
  V17PostLinkMeasuredProfile,
  V17PostLinkMeasuredProfile,
] {
  if (args.exactProfiles.length !== V17_PROFILES.length ||
    args.exactProfiles.some((profile, index) => profile.profile !== V17_PROFILES[index])) {
    throw new Error("v17 BCHN final density profile order");
  }
  return V17_PROFILES.map((profile): V17PostLinkMeasuredProfile => {
    const exact = args.exactProfiles[profile]!;
    const prior = args.postLinkProfiles[profile]!;
    const candidate = args.candidates.profiles[profile]!;
    const infrastructure = args.finalInfrastructure.profiles[profile]!;
    if (prior.profile !== profile || candidate.profile !== profile ||
      infrastructure.profile !== profile ||
      prior.inputCount !== exact.transaction.inputs.length ||
      prior.outputCount !== exact.transaction.outputs.length ||
      prior.workers.length !== V17_PRODUCTION_ROLE_LAYOUT.length ||
      candidate.roles.length !== V17_PRODUCTION_ROLE_LAYOUT.length ||
      infrastructure.roles.length !== V17_PRODUCTION_ROLE_LAYOUT.length ||
      exact.inputs.length !== exact.transaction.inputs.length) {
      throw new Error(`v17 BCHN final density envelope ${profile}`);
    }
    const workers = prior.workers.map((retained, inputIndex) => {
      const layout = V17_PRODUCTION_ROLE_LAYOUT[inputIndex]!;
      const candidateRole = candidate.roles[inputIndex]!;
      const finalRole = infrastructure.roles[inputIndex]!;
      const input = exact.transaction.inputs[inputIndex]!;
      const sourceOutput = exact.sourceOutputs[inputIndex]!;
      const assay = exact.inputs[inputIndex]!;
      const redeemPush = encodeV17CanonicalPush(finalRole.redeem);
      if (input.unlockingBytecode.length < redeemPush.length) {
        throw new Error(`v17 BCHN final density unlocking ${profile}:${layout.id}`);
      }
      const unlockingPrefixBytecode = input.unlockingBytecode.slice(
        0,
        input.unlockingBytecode.length - redeemPush.length,
      );
      const retainedUnlocking = concat(
        retained.unlockingPrefixBytecode,
        encodeV17CanonicalPush(retained.redeemBytecode),
      );
      if (retained.profile !== profile || retained.logicalInputIndex !== inputIndex ||
        retained.roleId !== layout.id || candidateRole.index !== inputIndex ||
        candidateRole.name !== layout.id || finalRole.index !== inputIndex ||
        finalRole.name !== layout.id || assay.inputIndex !== inputIndex ||
        !equalBytes(candidateRole.redeem, finalRole.redeem) ||
        !equalBytes(retained.redeemBytecode, finalRole.redeem) ||
        !equalBytes(input.unlockingBytecode, finalRole.unlockingBytecode) ||
        !equalBytes(input.unlockingBytecode, candidateRole.unlockingBytecode) ||
        !equalBytes(input.unlockingBytecode, retainedUnlocking) ||
        !equalBytes(input.unlockingBytecode.subarray(unlockingPrefixBytecode.length), redeemPush) ||
        retained.proofCarrierBytes !== finalRole.carrier.chunk.length ||
        candidateRole.carrier.chunk.length !== finalRole.carrier.chunk.length ||
        assay.unlockingBytecodeBytes !== input.unlockingBytecode.length ||
        assay.lockingBytecodeBytes !== sourceOutput.lockingBytecode.length) {
        throw new Error(`v17 BCHN final density byte identity ${profile}:${layout.id}`);
      }
      const operationCostEvidenceSha256Hex = domainDigest(
        "ShieldKit/V17FinalBchnInputDensityEvidence/v1",
        {
          assayExecutableSha256Hex: args.assayExecutableSha256Hex,
          transactionSha256Hex: exact.transactionSha256Hex,
          sourceOutputsSha256Hex: exact.sourceOutputsSha256Hex,
          profile,
          inputIndex,
          roleId: layout.id,
          redeemSha256Hex: sha256Hex(finalRole.redeem),
          unlockingSha256Hex: sha256Hex(input.unlockingBytecode),
          lockingSha256Hex: sha256Hex(sourceOutput.lockingBytecode),
          valueSatoshis: sourceOutput.valueSatoshis.toString(),
          sequenceNumber: input.sequenceNumber,
          proofCarrierBytes: finalRole.carrier.chunk.length,
          assay,
        },
      );
      return {
        profile,
        logicalInputIndex: inputIndex,
        roleId: layout.id,
        redeemBytecode: finalRole.redeem,
        unlockingPrefixBytecode,
        maximumOperationCost: assay.compositeOpCost,
        densityControlLength: V17_INPUT_FIXED_DENSITY_BYTES + input.unlockingBytecode.length,
        proofCarrierBytes: finalRole.carrier.chunk.length,
        valueSatoshis: sourceOutput.valueSatoshis,
        sequenceNumber: input.sequenceNumber,
        // BCHN's current assay does not expose these two non-density diagnostics.
        // The retained post-link values are admissible only after the byte-exact
        // identity proof above ties them to this same worker program.
        maximumMemorySlots: retained.maximumMemorySlots,
        maximumControlDepth: retained.maximumControlDepth,
        operationCostEngine: "bchn-v29.0.0" as const,
        operationCostEvidenceSha256Hex,
      };
    });
    const envelopeEvidenceSha256Hex = domainDigest(
      "ShieldKit/V17FinalBchnDensityEnvelope/v1",
      {
        assayExecutableSha256Hex: args.assayExecutableSha256Hex,
        profile,
        romPreviewIdHex: prior.romPreviewIdHex,
        transactionSha256Hex: exact.transactionSha256Hex,
        sourceOutputsSha256Hex: exact.sourceOutputsSha256Hex,
        inputCount: exact.transaction.inputs.length,
        outputCount: exact.transaction.outputs.length,
        semanticRoles: workers.map((worker) => ({
          logicalInputIndex: worker.logicalInputIndex,
          roleId: worker.roleId,
          maximumOperationCost: worker.maximumOperationCost,
          densityControlLength: worker.densityControlLength,
          proofCarrierBytes: worker.proofCarrierBytes,
          operationCostEvidenceSha256Hex: worker.operationCostEvidenceSha256Hex,
        })),
      },
    );
    return {
      measurementPhase: "post-link",
      romPreviewIdHex: prior.romPreviewIdHex,
      profile,
      workers,
      inputCount: exact.transaction.inputs.length,
      outputCount: exact.transaction.outputs.length,
      envelopeEvidenceSha256Hex,
    };
  }) as unknown as readonly [
    V17PostLinkMeasuredProfile,
    V17PostLinkMeasuredProfile,
    V17PostLinkMeasuredProfile,
  ];
}

function orderedArtifacts(
  artifacts: readonly V17BchnProductArtifact[],
): readonly V17BchnProductArtifact[] {
  if (artifacts.length !== V17_PROFILES.length) {
    throw new Error("v17 BCHN qualification requires profiles 0, 1, and 2");
  }
  const sorted = [...artifacts].sort((left, right) => left.profile - right.profile);
  sorted.forEach((artifact, index) => {
    if (artifact.profile !== V17_PROFILES[index]) {
      throw new Error("v17 BCHN qualification requires each profile exactly once");
    }
  });
  return sorted;
}

/**
 * Qualify the exact three serialized v17 envelopes with BCHN's per-input
 * VerifyScript oracle. This deliberately does not claim BCHN transaction-level
 * validation; the locally checked envelope and supply invariants are labeled
 * separately in the returned evidence.
 */
export function qualifyV17BchnProductWithTrace(
  args: V17BchnProductGateArguments,
): V17BchnProductGateResult {
  const link = previewV17ProductRom(
    args.canonicalProduct.proofs,
    args.canonicalProduct.allocation,
  );
  const candidates = materializeV17PostLinkCandidates({
    link,
    proofs: args.canonicalProduct.proofs,
    allocation: args.canonicalProduct.allocation,
  });
  const postLinkProfiles = bindV17PostLinkEvidence({
    candidates,
    evidence: args.canonicalProduct.postLinkEvidence,
  });
  const construction = certifyV17ProductLink({
    candidates,
    evidence: args.canonicalProduct.postLinkEvidence,
    trace: args.canonicalProduct.densityTrace,
  });
  const certificationTraceHead = replayV17DensityClosureTrace(
    args.canonicalProduct.densityTrace,
  );
  if (certificationTraceHead.traceRootSha256Hex !==
      construction.certificate.densityTraceRootSha256Hex) {
    throw new Error("v17 BCHN certification density trace");
  }
  const finalInfrastructure = materializeV17FinalInfrastructure({
    construction,
    proofs: args.canonicalProduct.proofs,
  });
  const finalIdentity = replayV17FinalInfrastructureIdentity(finalInfrastructure);
  assertV17FinalInfrastructureIdentity(finalIdentity);
  const assayExecutableSha256Hex = sha256Hex(
    new Uint8Array(readFileSync(args.assayExecutablePath)),
  );
  const profiles: V17BchnProfileEvidence[] = [];
  const exactProfiles: V17ExactAssayedProfile[] = [];
  const temporaryRoot = mkdtempSync(join(tmpdir(), "shieldkit-v17-bchn-"));
  try {
    for (const artifact of orderedArtifacts(args.artifacts)) {
      const decoded = decodeExactArtifacts(artifact);
      const envelope = assertLocalEnvelope(
        artifact.profile,
        decoded.transaction,
        decoded.sourceOutputs,
      );
      const profileIdentity = finalIdentity.profiles[artifact.profile]!;
      assertExactFinalInfrastructure({
        profile: artifact.profile,
        transaction: decoded.transaction,
        sourceOutputs: decoded.sourceOutputs,
        finalInfrastructure,
        identity: profileIdentity,
      });
      const transactionHexPath = join(temporaryRoot, `profile-${artifact.profile}.tx.hex`);
      const sourceOutputsHexPath = join(
        temporaryRoot,
        `profile-${artifact.profile}.source-outputs.hex`,
      );
      writeFileSync(transactionHexPath, `${Buffer.from(decoded.transactionBytes).toString("hex")}\n`,
        { mode: 0o600 });
      writeFileSync(sourceOutputsHexPath,
        `${Buffer.from(decoded.sourceOutputBytes).toString("hex")}\n`, { mode: 0o600 });

      const inputs: V17BchnInputEvidence[] = [];
      for (let inputIndex = 0; inputIndex < decoded.transaction.inputs.length; inputIndex += 1) {
        const execution = spawnSync(
          args.assayExecutablePath,
          [
            "--transaction-file", transactionHexPath,
            "--source-outputs-file", sourceOutputsHexPath,
            "--input-index", String(inputIndex),
            "--mode", "consensus",
          ],
          {
            encoding: "utf8",
            maxBuffer: 4 * 1024 * 1024,
            env: { ...process.env, ...args.assayEnvironment },
          },
        );
        if (execution.error !== undefined) {
          throw new Error(
            `v17 profile ${artifact.profile} input ${inputIndex} BCHN assay: ${execution.error.message}`,
          );
        }
        const result = parseAssayResult(
          execution.stdout,
          artifact.profile,
          inputIndex,
        );
        if (execution.status !== 0) {
          throw new Error(
            `v17 profile ${artifact.profile} input ${inputIndex} BCHN assay rejected: ` +
            `${execution.stderr.trim() || JSON.stringify(result)}`,
          );
        }
        inputs.push(validateAssayResult({
          result,
          profile: artifact.profile,
          inputIndex,
          transaction: decoded.transaction,
          sourceOutputs: decoded.sourceOutputs,
          transactionBytes: decoded.transactionBytes.length,
          sourceOutputsBytes: decoded.sourceOutputBytes.length,
        }));
      }
      const sigChecks = inputs.reduce((sum, input) => sum + input.sigChecks, 0);
      if (sigChecks > V17_BCHN_TRANSACTION_SIGCHECKS) {
        throw new Error(
          `v17 profile ${artifact.profile} aggregate sigchecks ${sigChecks} exceed 3000`,
        );
      }
      const transactionSha256Hex = sha256Hex(decoded.transactionBytes);
      const sourceOutputsSha256Hex = sha256Hex(decoded.sourceOutputBytes);
      exactProfiles.push({
        profile: artifact.profile,
        transactionSha256Hex,
        sourceOutputsSha256Hex,
        transaction: decoded.transaction,
        sourceOutputs: decoded.sourceOutputs,
        inputs,
      });
      profiles.push({
        profile: artifact.profile,
        transactionBytes: decoded.transactionBytes.length,
        transactionSha256Hex,
        sourceOutputsBytes: decoded.sourceOutputBytes.length,
        sourceOutputsSha256Hex,
        inputCount: decoded.transaction.inputs.length,
        outputCount: decoded.transaction.outputs.length,
        inputSatoshis: envelope.inputSatoshis.toString(),
        outputSatoshis: envelope.outputSatoshis.toString(),
        minerFeeSatoshis: envelope.minerFeeSatoshis.toString(),
        infrastructureInputs: envelope.infrastructureInputs,
        bankDigestHex: profileIdentity.bankDigestHex,
        proofBytes: profileIdentity.proofBytes,
        proofSha256Hex: profileIdentity.proofSha256Hex,
        infrastructureInventorySha256Hex:
          profileIdentity.infrastructureInventorySha256Hex,
        infrastructureIdentityCheck: "passed-byte-exact",
        tokenRuleCheck: "passed-libauth-may-2026",
        v17TopologyCheck: "passed",
        sigChecks,
        inputs,
      });
    }
  } finally {
    rmSync(temporaryRoot, { recursive: true, force: true });
  }

  const finalProfiles = deriveV17FinalAssayedProfiles({
    assayExecutableSha256Hex,
    candidates,
    postLinkProfiles,
    finalInfrastructure,
    exactProfiles,
  });
  const finalAllocation = assessV17FinalAllocationStability({
    construction,
    finalProfiles,
    trace: args.canonicalProduct.densityTrace,
  });
  const finalDensityEntry = finalAllocation.trace.entries.at(-1);
  if (finalAllocation.status !== "stable" || finalDensityEntry === undefined ||
    finalDensityEntry.phase !== "final-bchn" || !finalDensityEntry.noChange ||
    finalDensityEntry.entrySha256Hex !== finalAllocation.densityTraceRootSha256Hex ||
    finalAllocation.densityClosure.closureSha256Hex !==
      construction.certificate.densityClosureSha256Hex ||
    finalAllocation.certifiedReaderPlanSha256Hex !==
      finalAllocation.finalMeasuredReaderPlanSha256Hex ||
    canonicalV17Json(finalAllocation.certifiedAllocation) !==
      canonicalV17Json(args.canonicalProduct.allocation) ||
    canonicalV17Json(finalAllocation.finalMeasuredAllocation) !==
      canonicalV17Json(args.canonicalProduct.allocation)) {
    throw new Error("v17 BCHN final density requires post-link restart");
  }
  const finalDensityRowsSha256Hex = domainDigest(
    "ShieldKit/V17FinalBchnDensityRows/v1",
    finalAllocation.finalMeasuredRows,
  );
  const allInputs = profiles.flatMap((profile) => profile.inputs);
  const body: V17BchnProductEvidenceBody = {
    schema: V17_BCHN_PRODUCT_EVIDENCE_SCHEMA,
    status: "passed",
    protocolIdHex: finalIdentity.protocolIdHex,
    constructionIdHex: finalIdentity.constructionIdHex,
    linkerCertificateIdHex: finalIdentity.linkerCertificateIdHex,
    finalInfrastructureIdentitySha256Hex: finalIdentity.identitySha256Hex,
    finalDensityTraceRootSha256Hex: finalAllocation.densityTraceRootSha256Hex,
    finalDensityRowsSha256Hex,
    scope: {
      bchn: "every-input-VerifyScript-only",
      localEnvelope:
        "canonical-serialization-value-token-v17-topology-and-byte-exact-infrastructure",
      protocolIdentity: "linker-certificate-and-final-infrastructure-replayed",
      excluded: [
        "BCHN transaction-level CheckTransaction and CheckTxInputs",
        "UTXO existence maturity and relative-locktime context",
        "standardness mempool block acceptance mining and broadcast",
      ],
    },
    engine: {
      name: "bchn",
      version: V17_BCHN_ASSAY_ENGINE_VERSION,
      sourceTagCommit: V17_BCHN_ASSAY_SOURCE_TAG_COMMIT,
      executableSha256Hex: assayExecutableSha256Hex,
      mode: "consensus",
      flags: V17_BCHN_MAY_2026_CONSENSUS_FLAGS,
    },
    limits: {
      transactionBytes: V17_BCHN_CONSENSUS_TRANSACTION_BYTES,
      scriptBytes: V17_BCHN_CONSENSUS_SCRIPT_BYTES,
      sigChecksPerTransaction: V17_BCHN_TRANSACTION_SIGCHECKS,
      tokenCommitmentBytes: V17_BCHN_MAX_TOKEN_COMMITMENT_BYTES,
      bchConstantsSourceCommit: "864c53ee34924cca6c6b6d96607ff2cedcdccf02",
    },
    profiles,
    aggregate: {
      profileCount: 3,
      checkedInputs: allInputs.length,
      maximumProfileSigChecks: Math.max(...profiles.map(({ sigChecks }) => sigChecks)),
      maximumCompositeOpCost: Math.max(...allInputs.map(({ compositeOpCost }) => compositeOpCost)),
      maximumHashDigestIterations: Math.max(
        ...allInputs.map(({ hashDigestIterations }) => hashDigestIterations),
      ),
    },
  };
  const evidence: V17BchnProductEvidence = {
    ...body,
    evidenceSha256Hex: sha256Hex(canonicalJson(body)),
  };
  const result = {
    evidence,
    finalDensityTrace: finalAllocation.trace,
  };
  assertV17BchnProductGateResult(result);
  return result;
}

/** Compatibility wrapper for callers that only need the compact receipt. */
export function qualifyV17BchnProduct(
  args: V17BchnProductGateArguments,
): V17BchnProductEvidence {
  return qualifyV17BchnProductWithTrace(args).evidence;
}

export function assertV17BchnProductEvidence(evidence: V17BchnProductEvidence): void {
  const { evidenceSha256Hex, ...body } = evidence;
  if (!/^[0-9a-f]{64}$/.test(evidenceSha256Hex) ||
    evidenceSha256Hex !== sha256Hex(canonicalJson(body)) ||
    body.schema !== V17_BCHN_PRODUCT_EVIDENCE_SCHEMA || body.status !== "passed" ||
    body.protocolIdHex !== v17ProtocolIdHex() ||
    !/^[0-9a-f]{64}$/.test(body.constructionIdHex) ||
    !/^[0-9a-f]{64}$/.test(body.linkerCertificateIdHex) ||
    !/^[0-9a-f]{64}$/.test(body.finalInfrastructureIdentitySha256Hex) ||
    !/^[0-9a-f]{64}$/.test(body.finalDensityTraceRootSha256Hex) ||
    !/^[0-9a-f]{64}$/.test(body.finalDensityRowsSha256Hex) ||
    body.scope.bchn !== "every-input-VerifyScript-only" ||
    body.scope.localEnvelope !==
      "canonical-serialization-value-token-v17-topology-and-byte-exact-infrastructure" ||
    body.scope.protocolIdentity !== "linker-certificate-and-final-infrastructure-replayed" ||
    body.engine.name !== "bchn" || body.engine.version !== V17_BCHN_ASSAY_ENGINE_VERSION ||
    body.engine.sourceTagCommit !== V17_BCHN_ASSAY_SOURCE_TAG_COMMIT ||
    !/^[0-9a-f]{64}$/.test(body.engine.executableSha256Hex) ||
    body.engine.mode !== "consensus" || body.engine.flags !== V17_BCHN_MAY_2026_CONSENSUS_FLAGS ||
    body.limits.transactionBytes !== V17_BCHN_CONSENSUS_TRANSACTION_BYTES ||
    body.limits.scriptBytes !== V17_BCHN_CONSENSUS_SCRIPT_BYTES ||
    body.limits.sigChecksPerTransaction !== V17_BCHN_TRANSACTION_SIGCHECKS ||
    body.limits.tokenCommitmentBytes !== V17_BCHN_MAX_TOKEN_COMMITMENT_BYTES ||
    body.limits.bchConstantsSourceCommit !==
      "864c53ee34924cca6c6b6d96607ff2cedcdccf02" ||
    body.profiles.length !== 3 || body.profiles.some((profile, index) => profile.profile !== index)) {
    throw new Error("v17 BCHN product evidence integrity");
  }
  let checkedInputs = 0;
  let maximumProfileSigChecks = 0;
  let maximumCompositeOpCost = 0;
  let maximumHashDigestIterations = 0;
  for (const profile of body.profiles) {
    let inputSatoshis: bigint;
    let outputSatoshis: bigint;
    let minerFeeSatoshis: bigint;
    try {
      inputSatoshis = BigInt(profile.inputSatoshis);
      outputSatoshis = BigInt(profile.outputSatoshis);
      minerFeeSatoshis = BigInt(profile.minerFeeSatoshis);
    } catch {
      throw new Error("v17 BCHN product evidence integrity");
    }
    const expectedInfrastructure = profile.profile === 0
      ? profile.inputCount - 1
      : profile.inputCount;
    const expectedOutputs = expectedInfrastructure +
      (profile.profile === 0 ? 1 : profile.profile === 1 ? 2 : 3);
    if (!Number.isSafeInteger(profile.transactionBytes) || profile.transactionBytes < 1 ||
      profile.transactionBytes > V17_BCHN_CONSENSUS_TRANSACTION_BYTES ||
      !Number.isSafeInteger(profile.sourceOutputsBytes) || profile.sourceOutputsBytes < 1 ||
      !/^[0-9a-f]{64}$/.test(profile.transactionSha256Hex) ||
      !/^[0-9a-f]{64}$/.test(profile.sourceOutputsSha256Hex) ||
      !/^[0-9a-f]{64}$/.test(profile.bankDigestHex) ||
      !/^[0-9a-f]{64}$/.test(profile.proofSha256Hex) ||
      !/^[0-9a-f]{64}$/.test(profile.infrastructureInventorySha256Hex) ||
      !Number.isSafeInteger(profile.proofBytes) || profile.proofBytes < 1 ||
      !Number.isSafeInteger(profile.inputCount) || profile.inputCount < 2 ||
      profile.inputs.length !== profile.inputCount ||
      profile.infrastructureInputs !== expectedInfrastructure ||
      profile.outputCount !== expectedOutputs ||
      inputSatoshis < 0n || inputSatoshis > V17_BCHN_MAX_MONEY_SATOSHIS ||
      outputSatoshis < 0n || outputSatoshis > inputSatoshis ||
      minerFeeSatoshis !== inputSatoshis - outputSatoshis ||
      profile.infrastructureIdentityCheck !== "passed-byte-exact" ||
      profile.tokenRuleCheck !== "passed-libauth-may-2026" ||
      profile.v17TopologyCheck !== "passed") {
      throw new Error("v17 BCHN product evidence integrity");
    }
    let sigChecks = 0;
    profile.inputs.forEach((input, inputIndex) => {
      if (input.inputIndex !== inputIndex ||
        !Number.isSafeInteger(input.unlockingBytecodeBytes) || input.unlockingBytecodeBytes < 0 ||
        input.unlockingBytecodeBytes > V17_BCHN_CONSENSUS_SCRIPT_BYTES ||
        !Number.isSafeInteger(input.lockingBytecodeBytes) || input.lockingBytecodeBytes < 0 ||
        input.lockingBytecodeBytes > V17_BCHN_CONSENSUS_SCRIPT_BYTES ||
        !Number.isSafeInteger(input.baseOpCost) || input.baseOpCost < 0 ||
        !Number.isSafeInteger(input.compositeOpCost) || input.compositeOpCost < 0 ||
        !Number.isSafeInteger(input.opCostLimit) || input.opCostLimit < 1 ||
        input.compositeOpCost > input.opCostLimit ||
        !Number.isSafeInteger(input.hashDigestIterations) || input.hashDigestIterations < 0 ||
        !Number.isSafeInteger(input.hashDigestIterationsLimit) ||
        input.hashDigestIterationsLimit < 1 ||
        input.hashDigestIterations > input.hashDigestIterationsLimit ||
        !Number.isSafeInteger(input.sigChecks) || input.sigChecks < 0) {
        throw new Error("v17 BCHN product evidence integrity");
      }
      sigChecks += input.sigChecks;
      maximumCompositeOpCost = Math.max(maximumCompositeOpCost, input.compositeOpCost);
      maximumHashDigestIterations = Math.max(
        maximumHashDigestIterations,
        input.hashDigestIterations,
      );
    });
    if (sigChecks !== profile.sigChecks || sigChecks > V17_BCHN_TRANSACTION_SIGCHECKS) {
      throw new Error("v17 BCHN product evidence integrity");
    }
    checkedInputs += profile.inputCount;
    maximumProfileSigChecks = Math.max(maximumProfileSigChecks, sigChecks);
  }
  if (body.aggregate.profileCount !== 3 ||
    body.aggregate.checkedInputs !== checkedInputs ||
    body.aggregate.maximumProfileSigChecks !== maximumProfileSigChecks ||
    body.aggregate.maximumCompositeOpCost !== maximumCompositeOpCost ||
    body.aggregate.maximumHashDigestIterations !== maximumHashDigestIterations) {
    throw new Error("v17 BCHN product evidence integrity");
  }
}

export function assertV17BchnProductGateResult(
  result: V17BchnProductGateResult,
): void {
  const head = replayV17DensityClosureTrace(result.finalDensityTrace);
  const terminal = result.finalDensityTrace.entries.at(-1);
  if (terminal === undefined || terminal.phase !== "final-bchn" || !terminal.noChange ||
    terminal.entrySha256Hex !== head.traceRootSha256Hex ||
    head.traceRootSha256Hex !== result.evidence.finalDensityTraceRootSha256Hex ||
    domainDigest("ShieldKit/V17FinalBchnDensityRows/v1", terminal.measuredRows) !==
      result.evidence.finalDensityRowsSha256Hex) {
    throw new Error("v17 BCHN gate result final density trace");
  }
  assertV17BchnProductEvidence(result.evidence);
}

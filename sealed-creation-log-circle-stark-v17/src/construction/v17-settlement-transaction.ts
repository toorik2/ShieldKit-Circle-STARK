import { createHash } from "node:crypto";
import { writeFileSync } from "node:fs";
import {
  binToHex,
  encodeLockingBytecodeP2sh32,
  encodeTransaction,
  encodeTransactionOutputs,
  hash256,
  type Output,
  type Transaction,
} from "@bitauth/libauth";
import {
  deriveLocalWordPublicSettlement,
  type LocalWordPublicSettlement,
} from "../chain/local-word-envelope.ts";
import { compileLocalWordValueSettlementGate } from "../chain/local-word-balanced-vm.ts";
import {
  LOCAL_WORD_CARRIER_INPUTS,
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
  V17_MAX_SCRIPT_BYTES,
  validateV17RomPage,
} from "../chain/v17-code-rom.ts";
import { V17_PRODUCTION_ROLE_LAYOUT } from "../chain/v17-role-layout.ts";
import {
  validateV17AffineReaderConstruction,
  type V17AffineReaderConstruction,
} from "../chain/v17-affine-reader-vm.ts";
import { checkPublicTransition } from "../pool/transition.ts";
import { encodeStatement, type PoolStatement } from "../pool/statement.ts";
import { encodePublicPaa2, STATE_BASE_SATS } from "../pool/state.ts";
import { canonicalV17Json, type V17Profile } from "./v17-graph.ts";
import type {
  V17FinalInfrastructureSet,
  V17FinalProfileInfrastructure,
} from "./v17-product-link.ts";

export const V17_SETTLEMENT_TRANSACTION_SCHEMA =
  "ShieldKit/V17SettlementTransaction/v1" as const;
export const V17_SETTLEMENT_FUNDING_SEQUENCE = 0xffff_fffe;
const V17_CONSENSUS_TRANSACTION_BYTES = 1_000_000;
const OUTPOINT_DOMAIN = "ShieldKit/V17SettlementSyntheticOutpoint/v1";

type TransparentFunding = {
  readonly lockingBytecode: Uint8Array;
  readonly unlockingBytecode: Uint8Array;
};

type CommonSettlementFixture = {
  readonly statement: PoolStatement;
  readonly minerFeeSatoshis: bigint;
};

export type V17DepositSettlementFixture = CommonSettlementFixture & {
  readonly profile: 0;
  readonly edgeDataLockingBytecode: Uint8Array;
  readonly funding: TransparentFunding;
};

export type V17FullWithdrawalSettlementFixture = CommonSettlementFixture & {
  readonly profile: 1;
  readonly nullifierDataLockingBytecode: Uint8Array;
  readonly payoutLockingBytecode: Uint8Array;
};

export type V17ChangeWithdrawalSettlementFixture = CommonSettlementFixture & {
  readonly profile: 2;
  readonly edgeDataLockingBytecode: Uint8Array;
  readonly nullifierDataLockingBytecode: Uint8Array;
  readonly payoutLockingBytecode: Uint8Array;
};

export type V17PublicSettlementFixture =
  | V17DepositSettlementFixture
  | V17FullWithdrawalSettlementFixture
  | V17ChangeWithdrawalSettlementFixture;

export type V17SettlementTransaction = {
  readonly schema: typeof V17_SETTLEMENT_TRANSACTION_SCHEMA;
  readonly status: "materialized-requires-final-bchn-qualification";
  readonly profile: V17Profile;
  readonly constructionIdHex: string;
  readonly bankDigestHex: string;
  readonly infrastructureInputCount: number;
  readonly publicInputCount: 0 | 1;
  readonly publicOutputCount: 1 | 2 | 3;
  readonly transaction: Transaction;
  readonly sourceOutputs: readonly Output[];
  readonly rawTransactionBytes: Uint8Array;
  readonly encodedSourceOutputsBytes: Uint8Array;
  readonly transactionSha256Hex: string;
  readonly sourceOutputsSha256Hex: string;
  readonly replay: LocalWordPublicSettlement;
};

export type V17SettlementTransactionFiles = {
  readonly profile: V17Profile;
  readonly transactionPath: string;
  readonly sourceOutputsPath: string;
  readonly transactionBytes: number;
  readonly sourceOutputsBytes: number;
  readonly transactionSha256Hex: string;
  readonly sourceOutputsSha256Hex: string;
};

function equal(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((byte, index) => byte === right[index]);
}

function sha256(bytes: Uint8Array | string): Uint8Array {
  return new Uint8Array(createHash("sha256").update(bytes).digest());
}

function sha256Hex(bytes: Uint8Array): string {
  return binToHex(sha256(bytes));
}

function hex32(value: string, label: string): Uint8Array {
  if (!/^[0-9a-f]{64}$/.test(value)) throw new Error(`v17 settlement ${label}`);
  return Uint8Array.from(Buffer.from(value, "hex"));
}

function zero32(value: Uint8Array): boolean {
  return value.length === 32 && value.every((byte) => byte === 0);
}

function assertScript(bytecode: Uint8Array, label: string): void {
  if (bytecode.length > V17_MAX_SCRIPT_BYTES) {
    throw new Error(`v17 settlement ${label} exceeds 10000 bytes`);
  }
}

function assertOutputValue(value: bigint, label: string): void {
  if (value < 0n || value > 0xffff_ffff_ffff_ffffn) {
    throw new Error(`v17 settlement ${label} value`);
  }
}

function syntheticOutpoint(
  constructionIdHex: string,
  profile: V17Profile,
  inputIndex: number,
): { readonly outpointTransactionHash: Uint8Array; readonly outpointIndex: number } {
  const hash = sha256(`${OUTPOINT_DOMAIN}\u0000${constructionIdHex}\u0000${profile}\u0000${inputIndex}`);
  return { outpointTransactionHash: hash, outpointIndex: inputIndex };
}

function assertUniqueNonCoinbaseOutpoints(transaction: Transaction): void {
  const seen = new Set<string>();
  transaction.inputs.forEach((input, index) => {
    const hash = binToHex(input.outpointTransactionHash);
    if (hash === "00".repeat(32) && input.outpointIndex === 0xffff_ffff) {
      throw new Error(`v17 settlement coinbase outpoint ${index}`);
    }
    const key = `${hash}:${input.outpointIndex}`;
    if (seen.has(key)) throw new Error(`v17 settlement duplicate outpoint ${index}`);
    seen.add(key);
  });
}

function sameStatement(left: PoolStatement, right: PoolStatement): boolean {
  return equal(encodeStatement(left), encodeStatement(right)) &&
    left.oldState.reserveSats === right.oldState.reserveSats &&
    left.newState.reserveSats === right.newState.reserveSats;
}

function expectedProfile(statement: PoolStatement): V17Profile {
  if (statement.action === "DEPOSIT") return 0;
  return zero32(statement.createdEdge) ? 1 : 2;
}

function poolOutput(
  lockingBytecode: Uint8Array,
  statement: PoolStatement,
  which: "old" | "new",
): Output {
  const state = which === "old" ? statement.oldState : statement.newState;
  return {
    lockingBytecode: lockingBytecode.slice(),
    valueSatoshis: STATE_BASE_SATS + state.reserveSats,
    token: {
      category: statement.poolCategory.slice(),
      amount: 0n,
      nft: {
        capability: "mutable",
        commitment: encodePublicPaa2(state),
      },
    },
  };
}

function assertProfileInfrastructure(
  profile: V17FinalProfileInfrastructure,
  authorizedBankDigests: LocalWordVerifierBankDigests,
  readerConstruction: V17AffineReaderConstruction,
): number {
  const reader = validateV17AffineReaderConstruction(readerConstruction);
  const authorizedBankDigest = authorizedBankDigests[profile.profile];
  if (profile.schema !== "ShieldKit/V17FinalProfileInfrastructure/v1" ||
    profile.status !== "materialized-requires-final-bchn-qualification" ||
    profile.roles.length !== LOCAL_WORD_CARRIER_INPUTS ||
    profile.roles.length !== V17_PRODUCTION_ROLE_LAYOUT.length ||
    profile.infrastructure.length !== profile.roles.length + profile.pages.length ||
    authorizedBankDigest === undefined || authorizedBankDigest.length !== 32 ||
    canonicalV17Json(reader.allocation) !== canonicalV17Json(profile.allocation) ||
    !equal(hex32(profile.bankDigestHex, "profile bank digest"), authorizedBankDigest)) {
    throw new Error(`v17 settlement infrastructure shape ${profile.profile}`);
  }
  hex32(profile.constructionIdHex, "construction id");

  const proofBytes = reassembleLocalWordProofBytes(
    profile.roles.map((role) => role.carrier),
    profile.allocation,
  );
  const batchLeaderCell = encodeV17BatchLeaderCell(proofBytes);
  const expectedSettlementVerifier = compileLocalWordValueSettlementGate(
    authorizedBankDigests,
    reader.vm,
  );
  const expectedSettlementRedeem = compileLocalWordPoolCarrierRedeem(expectedSettlementVerifier);
  if (!equal(profile.roles[0]!.verifier, expectedSettlementVerifier) ||
    !equal(profile.roles[0]!.redeem, expectedSettlementRedeem)) {
    throw new Error(`v17 settlement authorized bank set ${profile.profile}`);
  }
  profile.roles.forEach((role, index) => {
    const infrastructure = profile.infrastructure[index];
    const layout = V17_PRODUCTION_ROLE_LAYOUT[index];
    const expectedLock = encodeLockingBytecodeP2sh32(hash256(role.redeem));
    const expectedUnlocking = role.name === LOCAL_WORD_BATCH_LEADER_ROLE_ID
      ? encodeLocalWordP2shBatchLeaderUnlocking(
        role.carrier.chunk,
        batchLeaderCell,
        role.redeem,
      )
      : encodeLocalWordP2shCarrierUnlocking(role.carrier.chunk, role.redeem);
    const expectedSequence = index === 0
      ? localWordPoolCarrierSequence(proofBytes.length, profile.allocation)
      : localWordVerifierCarrierSequence(index, profile.allocation);
    const expectedValue = index === 0
      ? null
      : localWordVerifierCarrierValue(index, profile.allocation);
    if (infrastructure === undefined || layout === undefined || role.index !== index ||
      role.name !== layout.id || role.carrier.index !== index ||
      infrastructure.index !== index || infrastructure.roleId !== role.name ||
      infrastructure.kind !== (index === 0 ? "pool" : "proof-worker") ||
      infrastructure.valueSatoshis !== expectedValue ||
      infrastructure.sequenceNumber !== expectedSequence ||
      !equal(infrastructure.lockingBytecode, expectedLock) ||
      !equal(infrastructure.unlockingBytecode, role.unlockingBytecode) ||
      !equal(infrastructure.unlockingBytecode, expectedUnlocking)) {
      throw new Error(`v17 settlement proof infrastructure ${profile.profile}:${index}`);
    }
    assertScript(role.redeem, `profile ${profile.profile} redeem ${index}`);
    assertScript(infrastructure.lockingBytecode, `profile ${profile.profile} lock ${index}`);
    assertScript(infrastructure.unlockingBytecode, `profile ${profile.profile} unlock ${index}`);
  });

  profile.pages.forEach((page, local) => {
    validateV17RomPage(page);
    const index = profile.roles.length + local;
    const infrastructure = profile.infrastructure[index];
    if (page.pageIndex !== local || page.inputIndex !== index || page.outputIndex !== index ||
      infrastructure === undefined || infrastructure.kind !== "rom-page" ||
      infrastructure.index !== index || infrastructure.roleId !== `rom-page:${local}` ||
      infrastructure.valueSatoshis !== page.valueSatoshis ||
      infrastructure.sequenceNumber !== page.sequenceNumber ||
      !equal(infrastructure.lockingBytecode, page.lockingBytecode) ||
      !equal(infrastructure.unlockingBytecode, page.unlockingBytecode)) {
      throw new Error(`v17 settlement ROM infrastructure ${profile.profile}:${local}`);
    }
    assertScript(infrastructure.lockingBytecode, `profile ${profile.profile} ROM lock ${local}`);
    assertScript(infrastructure.unlockingBytecode, `profile ${profile.profile} ROM unlock ${local}`);
  });

  const computedBankDigest = localWordVerifierBankDigestFromInputs(
    profile.profile,
    profile.infrastructure.slice(1).map((role) => {
      if (role.valueSatoshis === null) {
        throw new Error(`v17 settlement null infrastructure value ${role.index}`);
      }
      return {
        lockingBytecode: role.lockingBytecode,
        valueSatoshis: role.valueSatoshis,
        sequenceNumber: role.sequenceNumber,
      };
    }),
  );
  if (!equal(computedBankDigest, authorizedBankDigest)) {
    throw new Error(`v17 settlement bank digest ${profile.profile}`);
  }
  return profile.infrastructure.length;
}

function validateFixture(fixture: V17PublicSettlementFixture): void {
  checkPublicTransition(fixture.statement);
  if (fixture.minerFeeSatoshis < 0n || expectedProfile(fixture.statement) !== fixture.profile) {
    throw new Error(`v17 settlement public fixture profile ${fixture.profile}`);
  }
  if (fixture.profile === 0) {
    assertScript(fixture.edgeDataLockingBytecode, "deposit edge data");
    assertScript(fixture.funding.lockingBytecode, "deposit funding lock");
    assertScript(fixture.funding.unlockingBytecode, "deposit funding unlock");
  } else {
    assertScript(fixture.payoutLockingBytecode, `profile ${fixture.profile} payout lock`);
    assertScript(fixture.nullifierDataLockingBytecode, `profile ${fixture.profile} nullifier data`);
    if (fixture.profile === 2) {
      assertScript(fixture.edgeDataLockingBytecode, "change edge data");
    }
  }
}

/**
 * Purely materialize one byte-exact v17 transaction from a linked profile.
 * This performs host replay but does not claim BCHN execution or chain validity.
 */
export function materializeV17ProfileSettlementTransaction(args: {
  readonly profileInfrastructure: V17FinalProfileInfrastructure;
  readonly authorizedBankDigests: LocalWordVerifierBankDigests;
  readonly affineReader: V17AffineReaderConstruction;
  readonly fixture: V17PublicSettlementFixture;
}): V17SettlementTransaction {
  const { profileInfrastructure, authorizedBankDigests, affineReader, fixture } = args;
  if (profileInfrastructure.profile !== fixture.profile ||
    authorizedBankDigests.length !== 3 ||
    authorizedBankDigests.some((digest) => digest.length !== 32)) {
    throw new Error("v17 settlement selected profile");
  }
  validateFixture(fixture);
  const infrastructureInputCount = assertProfileInfrastructure(
    profileInfrastructure,
    authorizedBankDigests,
    affineReader,
  );
  const poolInfrastructure = profileInfrastructure.infrastructure[0]!;
  const sourceOutputs: Output[] = [
    poolOutput(poolInfrastructure.lockingBytecode, fixture.statement, "old"),
    ...profileInfrastructure.infrastructure.slice(1).map((role): Output => {
      if (role.valueSatoshis === null) {
        throw new Error(`v17 settlement infrastructure value ${role.index}`);
      }
      assertOutputValue(role.valueSatoshis, `infrastructure ${role.index}`);
      return {
        lockingBytecode: role.lockingBytecode.slice(),
        valueSatoshis: role.valueSatoshis,
      };
    }),
  ];
  const outputs: Output[] = [
    poolOutput(poolInfrastructure.lockingBytecode, fixture.statement, "new"),
    ...sourceOutputs.slice(1).map((source): Output => ({
      lockingBytecode: source.lockingBytecode.slice(),
      valueSatoshis: source.valueSatoshis,
    })),
  ];
  const inputs: Transaction["inputs"] = profileInfrastructure.infrastructure.map((role, index) => ({
    ...syntheticOutpoint(profileInfrastructure.constructionIdHex, fixture.profile, index),
    sequenceNumber: role.sequenceNumber,
    unlockingBytecode: role.unlockingBytecode.slice(),
  }));

  let publicInputCount: 0 | 1;
  let publicOutputCount: 1 | 2 | 3;
  if (fixture.profile === 0) {
    const fundingValue = fixture.statement.publicAmountSats + fixture.minerFeeSatoshis;
    assertOutputValue(fundingValue, "deposit funding");
    sourceOutputs.push({
      lockingBytecode: fixture.funding.lockingBytecode.slice(),
      valueSatoshis: fundingValue,
    });
    inputs.push({
      ...syntheticOutpoint(
        profileInfrastructure.constructionIdHex,
        fixture.profile,
        infrastructureInputCount,
      ),
      sequenceNumber: V17_SETTLEMENT_FUNDING_SEQUENCE,
      unlockingBytecode: fixture.funding.unlockingBytecode.slice(),
    });
    outputs.push({
      lockingBytecode: fixture.edgeDataLockingBytecode.slice(),
      valueSatoshis: 0n,
    });
    publicInputCount = 1;
    publicOutputCount = 1;
  } else {
    const payoutValue = -fixture.statement.publicAmountSats - fixture.minerFeeSatoshis;
    if (payoutValue <= 0n) throw new Error(`v17 settlement profile ${fixture.profile} payout value`);
    outputs.push({
      lockingBytecode: fixture.payoutLockingBytecode.slice(),
      valueSatoshis: payoutValue,
    }, {
      lockingBytecode: fixture.nullifierDataLockingBytecode.slice(),
      valueSatoshis: 0n,
    });
    if (fixture.profile === 2) {
      outputs.push({
        lockingBytecode: fixture.edgeDataLockingBytecode.slice(),
        valueSatoshis: 0n,
      });
      publicOutputCount = 3;
    } else {
      publicOutputCount = 2;
    }
    publicInputCount = 0;
  }

  const transaction: Transaction = { version: 2, locktime: 0, inputs, outputs };
  assertUniqueNonCoinbaseOutpoints(transaction);
  transaction.inputs.forEach((input, index) =>
    assertScript(input.unlockingBytecode, `input ${index} unlock`));
  [...sourceOutputs, ...outputs].forEach((output, index) => {
    assertScript(output.lockingBytecode, `output ${index} lock`);
    assertOutputValue(output.valueSatoshis, `output ${index}`);
  });

  const replay = deriveLocalWordPublicSettlement({
    sourceOutputs,
    inputSequenceNumbers: inputs.map((input) => input.sequenceNumber),
    outputs,
  }, authorizedBankDigests);
  if (replay.profile !== (fixture.profile === 0
    ? "deposit"
    : fixture.profile === 1
      ? "withdraw-full"
      : "withdraw-change") ||
    replay.minerFeeSats !== fixture.minerFeeSatoshis ||
    !sameStatement(replay.statement, fixture.statement)) {
    throw new Error(`v17 settlement exact public replay ${fixture.profile}`);
  }

  const rawTransactionBytes = encodeTransaction(transaction);
  const encodedSourceOutputsBytes = encodeTransactionOutputs(sourceOutputs);
  if (rawTransactionBytes.length > V17_CONSENSUS_TRANSACTION_BYTES) {
    throw new Error(`v17 settlement transaction exceeds 1000000 bytes: ${rawTransactionBytes.length}`);
  }
  return {
    schema: V17_SETTLEMENT_TRANSACTION_SCHEMA,
    status: "materialized-requires-final-bchn-qualification",
    profile: fixture.profile,
    constructionIdHex: profileInfrastructure.constructionIdHex,
    bankDigestHex: profileInfrastructure.bankDigestHex,
    infrastructureInputCount,
    publicInputCount,
    publicOutputCount,
    transaction,
    sourceOutputs,
    rawTransactionBytes,
    encodedSourceOutputsBytes,
    transactionSha256Hex: sha256Hex(rawTransactionBytes),
    sourceOutputsSha256Hex: sha256Hex(encodedSourceOutputsBytes),
    replay,
  };
}

/** Bind selection and construction identity to the complete final infrastructure set. */
export function materializeV17SettlementTransaction(args: {
  readonly infrastructureSet: V17FinalInfrastructureSet;
  readonly fixture: V17PublicSettlementFixture;
}): V17SettlementTransaction {
  const { infrastructureSet, fixture } = args;
  const profile = infrastructureSet.profiles[fixture.profile];
  if (infrastructureSet.schema !== "ShieldKit/V17FinalInfrastructureSet/v1" ||
    infrastructureSet.status !== "materialized-requires-final-bchn-qualification" ||
    infrastructureSet.qualification !== "not-qualified-until-final-transactions-pass" ||
    infrastructureSet.profiles.length !== 3 ||
    infrastructureSet.profiles.some((candidate, index) =>
      candidate.profile !== index ||
      candidate.constructionIdHex !== infrastructureSet.construction.certificate.constructionIdHex ||
      candidate.bankDigestHex !== binToHex(infrastructureSet.authorizedBankDigests[index]!)) ||
    profile === undefined ||
    infrastructureSet.authorizedBankDigests.some((digest) => digest.length !== 32)) {
    throw new Error("v17 settlement infrastructure set");
  }
  const affineReader = infrastructureSet.construction.affineReader;
  if (affineReader === null) {
    throw new Error("v17 settlement missing affine reader construction");
  }
  return materializeV17ProfileSettlementTransaction({
    profileInfrastructure: profile,
    authorizedBankDigests: infrastructureSet.authorizedBankDigests,
    affineReader,
    fixture,
  });
}

/** Write only the two exact binary payloads consumed by the offline BCHN gate. */
export function writeV17SettlementTransactionFiles(
  materialized: V17SettlementTransaction,
  paths: {
    readonly transactionPath: string;
    readonly sourceOutputsPath: string;
  },
): V17SettlementTransactionFiles {
  writeFileSync(paths.transactionPath, materialized.rawTransactionBytes);
  writeFileSync(paths.sourceOutputsPath, materialized.encodedSourceOutputsBytes);
  return {
    profile: materialized.profile,
    transactionPath: paths.transactionPath,
    sourceOutputsPath: paths.sourceOutputsPath,
    transactionBytes: materialized.rawTransactionBytes.length,
    sourceOutputsBytes: materialized.encodedSourceOutputsBytes.length,
    transactionSha256Hex: materialized.transactionSha256Hex,
    sourceOutputsSha256Hex: materialized.sourceOutputsSha256Hex,
  };
}

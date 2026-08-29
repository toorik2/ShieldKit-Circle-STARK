import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  createVirtualMachineBch2026,
  encodeLockingBytecodeP2sh32,
  hash256,
} from "@bitauth/libauth";
import {
  compileLocalWordInteractionTranscriptKatGate,
  compileLocalWordPublicBoundaryInverseBatchGate,
  compileLocalWordPublicBoundaryInverseGate,
  compileLocalWordPublicBoundarySumGate,
  compileLocalWordQueryScheduleGate,
  compileLocalWordSparseNullifierGate,
  compileLocalWordTranscriptInitialKatGate,
  compileLocalWordTranscriptManifestGate,
  compileLocalWordValueSettlementGate,
  localWordPublicWordCount,
  localWordProofTranscriptOffsets,
} from "../src/chain/local-word-balanced-vm.ts";
import {
  deriveLocalWordPublicSettlement,
  encodeLocalWordNullifierData,
  LOCAL_WORD_NULLIFIER_DATA_OUTPUT,
  LOCAL_WORD_NULLIFIER_PATH_OFFSET,
  LOCAL_WORD_PAYOUT_OUTPUT,
} from "../src/chain/local-word-envelope.ts";
import {
  compileLocalWordCarrierRedeem,
  compileLocalWordPoolCarrierRedeem,
  encodeLocalWordP2shCarrierUnlocking,
  LOCAL_WORD_CARRIER_INPUTS,
  localWordVerifierCarrierValue,
  localWordVerifierCarrierSequence,
  localWordPoolCarrierSequence,
  locateLocalWordProofByte,
  localWordP2sh32Lock,
  localWordVerifierBankDigestFromLockingBytecodes,
  partitionLocalWordProofBytes,
} from
  "../src/chain/local-word-proof-carriers.ts";
import { LAB_PAYOUT_LOCKING } from "../src/chain/payout.ts";
import {
  LOCAL_WORD_PROOF_FIXED_PREFIX_BYTES,
  LOCAL_WORD_PROOF_LENGTH_OFFSET,
  LOCAL_WORD_PROOF_VERSION,
  localWordMaximumCanonicalProofBytes,
  localWordProofStaticOffsets,
} from "../src/backends/circle/local-word-sealed-proof.ts";
import { LOCAL_WORD_V15_CONSTRUCTION_ID } from
  "../src/backends/circle/local-word-construction-v15.ts";
import {
  encodeLocalWordScriptI64,
  localWordTranscriptInitial,
} from "../src/backends/circle/local-word-public-statement.ts";
import { SuccessorTranscript } from "../src/backends/circle/successor-transcript.ts";
import {
  localWordCompositionTranscript,
  localWordInteractionChallengeValues,
  localWordInteractionTranscript,
  localWordGrindForQueries,
  localWordPublicBoundaryTranscript,
  localWordQueryIndices,
} from "../src/backends/circle/local-word-transcript.ts";
import { decodeQm31, encodeQm31 } from "../src/backends/circle/qm31.ts";
import {
  LOCAL_WORD_PRODUCTION_PARAMETERS,
  type LocalWordProofParameters,
} from "../src/backends/circle/local-word-successor-params.ts";
import { poolLocalBoundaryClaimForWords } from "../src/chain/pool-relation-local-word-boundary.ts";
import { localShaWordsFromBytes } from "../src/chain/sha256-local-word-machine.ts";
import { writeU32BE } from "../src/pool/bytes.ts";
import { SparseNullifierTree, emptySparseNullifierRoot } from "../src/pool/sparse-nullifiers.ts";
import { emptyState, encodePublicPaa1, STATE_BASE_SATS, type AnyAmountState } from "../src/pool/state.ts";

const CATEGORY = new Uint8Array(32).fill(0x42);
const CONSTRUCTION_ID = LOCAL_WORD_V15_CONSTRUCTION_ID;
const carrierLocks = (profile: 0 | 1 | 2) =>
  Array.from({ length: LOCAL_WORD_CARRIER_INPUTS - 1 }, (_, index) =>
    localWordP2sh32Lock(Uint8Array.of(0x51, profile, index & 0xff, index >>> 8)));
const CARRIER_LOCKS = [carrierLocks(0), carrierLocks(1), carrierLocks(2)] as const;
const BANK_DIGESTS = [
  localWordVerifierBankDigestFromLockingBytecodes(CARRIER_LOCKS[0]),
  localWordVerifierBankDigestFromLockingBytecodes(CARRIER_LOCKS[1]),
  localWordVerifierBankDigestFromLockingBytecodes(CARRIER_LOCKS[2]),
] as const;
const NULLIFIER_ROLE_START = 33;

function proofBytes(profile: 0 | 1 | 2): Uint8Array {
  const bytes = Uint8Array.from(
    { length: localWordMaximumCanonicalProofBytes(localWordPublicWordCount(profile)) },
    (_, index) => (index * 73 + 9) & 0xff,
  );
  bytes.set(new TextEncoder().encode("SKLW"), 0);
  bytes[4] = LOCAL_WORD_PROOF_VERSION;
  bytes[5] = profile;
  bytes.set(writeU32BE(bytes.length), LOCAL_WORD_PROOF_LENGTH_OFFSET);
  return bytes;
}

function poolToken(state: AnyAmountState) {
  return {
    amount: 0n,
    category: CATEGORY,
    nft: { capability: "mutable" as const, commitment: encodePublicPaa1(state) },
  };
}

function input(index: number, unlockingBytecode: Uint8Array) {
  return {
    outpointTransactionHash: new Uint8Array(32).fill((index + 1) & 0xff),
    outpointIndex: index,
    sequenceNumber: index > 0 && index < LOCAL_WORD_CARRIER_INPUTS
      ? localWordVerifierCarrierSequence(index)
      : 0xffff_ffff,
    unlockingBytecode,
  };
}

function oldState(reserveSats: bigint): AnyAmountState {
  return {
    ...emptyState(new Uint8Array(32).fill(0x31)),
    reserveSats,
    nullifierRoot: emptySparseNullifierRoot(),
  };
}

function evaluate(args: {
  readonly profile: 0 | 1 | 2;
  readonly old: AnyAmountState;
  readonly next: AnyAmountState;
  readonly fee: bigint;
  readonly payout?: bigint;
  readonly nullifierData?: Uint8Array;
  readonly proof?: Uint8Array;
  /** Select the standing bank independently when testing a wrong proof profile. */
  readonly bankProfile?: 0 | 1 | 2;
}) {
  const verifier = compileLocalWordValueSettlementGate(BANK_DIGESTS);
  const redeem = compileLocalWordPoolCarrierRedeem(verifier);
  const poolLock = encodeLockingBytecodeP2sh32(hash256(redeem));
  const proof = args.proof ?? proofBytes(args.profile);
  const carriers = partitionLocalWordProofBytes(proof);
  const selectedLocks = CARRIER_LOCKS[args.bankProfile ?? args.profile];
  const sourceOutputs = [
    { lockingBytecode: poolLock, valueSatoshis: STATE_BASE_SATS + args.old.reserveSats, token: poolToken(args.old) },
    ...selectedLocks.map((lockingBytecode, local) => ({
      lockingBytecode,
      valueSatoshis: localWordVerifierCarrierValue(local + 1),
    })),
  ];
  const outputs = [
    { lockingBytecode: poolLock, valueSatoshis: STATE_BASE_SATS + args.next.reserveSats, token: poolToken(args.next) },
    ...selectedLocks.map((lockingBytecode, local) => ({
      lockingBytecode,
      valueSatoshis: localWordVerifierCarrierValue(local + 1),
    })),
  ];
  const inputs = carriers.map((carrier) => input(carrier.index, carrier.unlockingBytecode));
  inputs[0]!.sequenceNumber = localWordPoolCarrierSequence(proof.length);
  inputs[0]!.unlockingBytecode = encodeLocalWordP2shCarrierUnlocking(
    carriers[0]!.chunk,
    redeem,
  );
  if (args.payout === undefined) {
    const deposit = args.next.reserveSats - args.old.reserveSats;
    sourceOutputs.push({ lockingBytecode: Uint8Array.of(0x51), valueSatoshis: deposit + args.fee });
    inputs.push(input(inputs.length, new Uint8Array()));
  } else {
    outputs.push({ lockingBytecode: LAB_PAYOUT_LOCKING, valueSatoshis: args.payout });
    outputs.push({ lockingBytecode: args.nullifierData!, valueSatoshis: 0n });
  }
  const transaction = { version: 2, locktime: 0, inputs, outputs };
  const vm = createVirtualMachineBch2026(false);
  const state = vm.evaluate({ inputIndex: 0, sourceOutputs, transaction } as never);
  return { lock: redeem, vm, state, sourceOutputs, transaction, proof };
}

function mutateProofByte(
  transaction: ReturnType<typeof evaluate>["transaction"],
  proofLength: number,
  proofOffset: number,
): void {
  const location = locateLocalWordProofByte(proofLength, proofOffset);
  transaction.inputs[location.carrierIndex]!.unlockingBytecode[3 + location.chunkOffset] ^= 1;
}

function evaluateRole(
  fixture: ReturnType<typeof evaluate>,
  verifier: Uint8Array,
  inputIndex = 2,
) {
  const carrier = partitionLocalWordProofBytes(fixture.proof)[inputIndex]!;
  const redeem = compileLocalWordCarrierRedeem({
    index: inputIndex,
    verifier,
  });
  const lockingBytecode = encodeLockingBytecodeP2sh32(hash256(redeem));
  const sourceOutputs = structuredClone(fixture.sourceOutputs);
  const transaction = structuredClone(fixture.transaction);
  sourceOutputs[inputIndex]!.lockingBytecode = lockingBytecode;
  transaction.outputs[inputIndex]!.lockingBytecode = lockingBytecode;
  transaction.inputs[inputIndex]!.unlockingBytecode = encodeLocalWordP2shCarrierUnlocking(
    carrier.chunk,
    redeem,
  );
  const state = fixture.vm.evaluate({ inputIndex, sourceOutputs, transaction } as never);
  return { sourceOutputs, transaction, state };
}

function evaluateP2shRole(
  fixture: ReturnType<typeof evaluate>,
  proof: Uint8Array,
  verifier: Uint8Array,
  inputIndex: number,
) {
  const carrier = partitionLocalWordProofBytes(proof)[inputIndex]!;
  const redeem = compileLocalWordCarrierRedeem({
    index: inputIndex,
    verifier,
  });
  const lockingBytecode = encodeLockingBytecodeP2sh32(hash256(redeem));
  const sourceOutputs = structuredClone(fixture.sourceOutputs);
  const transaction = structuredClone(fixture.transaction);
  sourceOutputs[inputIndex]!.lockingBytecode = lockingBytecode;
  transaction.outputs[inputIndex]!.lockingBytecode = lockingBytecode;
  transaction.inputs[inputIndex]!.unlockingBytecode = encodeLocalWordP2shCarrierUnlocking(
    carrier.chunk,
    redeem,
  );
  const state = fixture.vm.evaluate({ inputIndex, sourceOutputs, transaction } as never);
  return { sourceOutputs, transaction, state };
}

function transactionTranscriptDigest(fixture: ReturnType<typeof evaluate>): Uint8Array {
  const settlement = deriveLocalWordPublicSettlement({
    sourceOutputs: fixture.sourceOutputs,
    outputs: fixture.transaction.outputs,
  }, BANK_DIGESTS);
  return new SuccessorTranscript(localWordTranscriptInitial(
    settlement.statement,
    CONSTRUCTION_ID,
    settlement.minerFeeSats,
  )).digest;
}

function transactionInteraction(
  fixture: ReturnType<typeof evaluate>,
  publicWordCount: number,
  proof?: Uint8Array,
) {
  const settlement = deriveLocalWordPublicSettlement({
    sourceOutputs: fixture.sourceOutputs,
    outputs: fixture.transaction.outputs,
  }, BANK_DIGESTS);
  const initial = localWordTranscriptInitial(
    settlement.statement,
    CONSTRUCTION_ID,
    settlement.minerFeeSats,
  );
  const bytes = proof ?? proofBytes(fixture.transaction.inputs.length === LOCAL_WORD_CARRIER_INPUTS + 1 ? 0 :
    settlement.profile === "withdraw-full" ? 1 : 2);
  const rootOffset = localWordProofStaticOffsets(publicWordCount).matrixRoots;
  const replay = localWordInteractionTranscript(
    initial,
    bytes.slice(6, 38),
    bytes.slice(rootOffset, rootOffset + 32),
    bytes.slice(rootOffset + 32, rootOffset + 64),
  );
  return { ...replay, proof: bytes };
}

function publicBoundaryValues(fixture: ReturnType<typeof evaluate>): readonly number[] {
  const settlement = deriveLocalWordPublicSettlement({
    sourceOutputs: fixture.sourceOutputs,
    outputs: fixture.transaction.outputs,
  }, BANK_DIGESTS);
  const { statement, profile } = settlement;
  if (profile === "deposit") {
    return [
      ...localShaWordsFromBytes(encodeLocalWordScriptI64(statement.publicAmountSats)),
      ...localShaWordsFromBytes(statement.oldState.noteRoot),
      ...localShaWordsFromBytes(statement.newState.noteRoot),
    ];
  }
  const shared = [
    ...localShaWordsFromBytes(statement.oldState.poolInstanceId),
    ...localShaWordsFromBytes(statement.nullifier),
    ...localShaWordsFromBytes(statement.oldState.noteRoot),
  ];
  const withdrawal = -statement.publicAmountSats;
  return profile === "withdraw-full"
    ? [...shared, ...localShaWordsFromBytes(encodeLocalWordScriptI64(withdrawal))]
    : [
      ...shared,
      ...localShaWordsFromBytes(statement.newState.noteRoot),
      ...localShaWordsFromBytes(encodeLocalWordScriptI64(withdrawal)),
    ];
}

function proofWithPublicInverses(fixture: ReturnType<typeof evaluate>): Uint8Array {
  const values = publicBoundaryValues(fixture);
  const base = proofBytes(values.length === 18 ? 0 : values.length === 26 ? 1 : 2);
  const replay = transactionInteraction(fixture, values.length, base);
  const claim = poolLocalBoundaryClaimForWords(
    values.map((expected, index) => ({ id: BigInt(index + 1), row: index, expected })),
    replay.challenges.boundary,
  );
  const offsets = localWordProofTranscriptOffsets(values.length);
  claim.publicInverses.forEach((inverse, index) =>
    base.set(encodeQm31(inverse), offsets.publicInverses + index * 16));
  base.set(encodeQm31(claim.claimedSum), offsets.publicClaimedSum);
  localWordInteractionChallengeValues(replay.challenges).forEach((challenge, index) =>
    base.set(encodeQm31(challenge), offsets.interactionChallenges + index * 16));
  return base;
}

function fillTranscriptManifest(
  fixture: ReturnType<typeof evaluate>,
  proof: Uint8Array,
  publicWordCount: number,
  parameters: LocalWordProofParameters,
): readonly number[] {
  const replay = transactionInteraction(fixture, publicWordCount, proof);
  const offsets = localWordProofTranscriptOffsets(publicWordCount, parameters);
  const inverses = Array.from({ length: publicWordCount }, (_, index) =>
    decodeQm31(proof.slice(offsets.publicInverses + index * 16, offsets.publicInverses + (index + 1) * 16)));
  localWordInteractionChallengeValues(replay.challenges).forEach((challenge, index) =>
    proof.set(encodeQm31(challenge), offsets.interactionChallenges + index * 16));
  localWordPublicBoundaryTranscript(replay.transcript, inverses);
  proof.set(replay.transcript.digest, offsets.interactionDigest);
  const roots = Array.from({ length: 5 }, (_, index) =>
    proof.slice(offsets.matrixRoots + index * 32, offsets.matrixRoots + (index + 1) * 32));
  const composition = localWordCompositionTranscript(
    replay.transcript,
    roots[2]!,
    roots[3]!,
  );
  proof.set(encodeQm31(composition.constraintAlpha), offsets.constraintAlpha);
  proof.set(composition.digest, offsets.compositionDigest);
  replay.transcript.absorb("local-word-quotient-and-fri-mask-root", roots[4]!);
  const batchBeta = replay.transcript.challengeQm31("local-word-batch-beta");
  proof.set(encodeQm31(batchBeta), offsets.batchBeta);
  proof.set(replay.transcript.digest, offsets.batchDigest);
  const friSplit = Math.ceil(offsets.friLayerCount / 2);
  for (let round = 0; round < offsets.friLayerCount; round += 1) {
    replay.transcript.absorb(
      `fri-root:${round}`,
      proof.slice(offsets.friRoots + round * 32, offsets.friRoots + (round + 1) * 32),
    );
    const alpha = replay.transcript.challengeQm31(`fri-alpha:${round}`);
    proof.set(encodeQm31(alpha), offsets.friAlphas + round * 16);
    if (round + 1 === friSplit) proof.set(replay.transcript.digest, offsets.friMidDigest);
  }
  proof.set(replay.transcript.digest, offsets.friRootsDigest);
  replay.transcript.absorb(
    "fri-final",
    proof.slice(offsets.finalCoefficients, offsets.grindNonce),
  );
  const nonce = localWordGrindForQueries(replay.transcript, parameters);
  proof.set(writeU32BE(nonce), offsets.grindNonce);
  proof.set(replay.transcript.digest, offsets.queryDigest);
  const queries = localWordQueryIndices(replay.transcript, parameters);
  queries.forEach((query, index) => proof.set(writeU32BE(query), offsets.queries + index * 4));
  return queries;
}

describe("local-word public settlement on the May-2026 VM", () => {
  it("accepts a deposit and rejects a wrong proof profile or carrier rollover", () => {
    const old = oldState(0n);
    const next = {
      ...old,
      sequence: 1n,
      reserveSats: 20_000n,
      depositCount: 1n,
      noteRoot: new Uint8Array(32).fill(0x52),
    };
    const accepted = evaluate({ profile: 0, old, next, fee: 1_000n });
    assert.equal(accepted.vm.stateSuccess(accepted.state), true, JSON.stringify({
      error: accepted.state.error,
      stack: accepted.state.stack.map((item) => Buffer.from(item).toString("hex")),
      metrics: accepted.state.metrics,
    }));
    assert.ok(accepted.lock.length < 10_000);
    console.log("local-word-deposit-settlement-gate", JSON.stringify({
      lockingBytes: accepted.lock.length,
      operationCost: accepted.state.metrics.operationCost,
    }));

    const wrongProfile = evaluate({ profile: 2, bankProfile: 0, old, next, fee: 1_000n });
    assert.notEqual(wrongProfile.vm.stateSuccess(wrongProfile.state), true);

    const altered = structuredClone(accepted.transaction);
    altered.outputs[5]!.valueSatoshis += 1n;
    const rejected = accepted.vm.evaluate({
      inputIndex: 0,
      sourceOutputs: accepted.sourceOutputs,
      transaction: altered,
    } as never);
    assert.notEqual(accepted.vm.stateSuccess(rejected), true);

    const substitutedSources = structuredClone(accepted.sourceOutputs);
    const substitutedTransaction = structuredClone(accepted.transaction);
    const attackerLock = localWordP2sh32Lock(Uint8Array.of(0x51));
    substitutedSources[5]!.lockingBytecode = attackerLock;
    substitutedTransaction.outputs[5]!.lockingBytecode = attackerLock;
    const substituted = accepted.vm.evaluate({
      inputIndex: 0,
      sourceOutputs: substitutedSources,
      transaction: substitutedTransaction,
    } as never);
    assert.notEqual(accepted.vm.stateSuccess(substituted), true);

    const wrongProofLength = structuredClone(accepted.transaction);
    wrongProofLength.inputs[0]!.sequenceNumber += 1;
    const wrongProofLengthState = accepted.vm.evaluate({
      inputIndex: 0,
      sourceOutputs: accepted.sourceOutputs,
      transaction: wrongProofLength,
    } as never);
    assert.notEqual(accepted.vm.stateSuccess(wrongProofLengthState), true);

    const wrongJumpIndex = structuredClone(accepted.transaction);
    wrongJumpIndex.inputs[5]!.sequenceNumber += 1;
    const wrongJumpIndexState = accepted.vm.evaluate({
      inputIndex: 0,
      sourceOutputs: accepted.sourceOutputs,
      transaction: wrongJumpIndex,
    } as never);
    assert.notEqual(accepted.vm.stateSuccess(wrongJumpIndexState), true);
  });

  it("accepts a change withdrawal and binds payout plus transaction fee to the pool drop", () => {
    const old = oldState(20_000n);
    const nullifier = new Uint8Array(32).fill(0x77);
    const sparse = new SparseNullifierTree();
    const inserted = sparse.insert(nullifier);
    const payout = 8_000n;
    const fee = 1_000n;
    const next = {
      ...old,
      sequence: 1n,
      reserveSats: old.reserveSats - payout - fee,
      withdrawalCount: 1n,
      noteRoot: new Uint8Array(32).fill(0x53),
      nullifierRoot: inserted.newRoot,
    };
    const accepted = evaluate({
      profile: 2,
      old,
      next,
      fee,
      payout,
      nullifierData: encodeLocalWordNullifierData({ nullifier, path: inserted.path }),
    });
    assert.equal(accepted.vm.stateSuccess(accepted.state), true, String(accepted.vm.stateSuccess(accepted.state)));
    console.log("local-word-withdraw-change-settlement-gate", JSON.stringify({
      lockingBytes: accepted.lock.length,
      operationCost: accepted.state.metrics.operationCost,
    }));

    const wrongProfile = evaluate({
      profile: 1,
      bankProfile: 2,
      old,
      next,
      fee,
      payout,
      nullifierData: encodeLocalWordNullifierData({ nullifier, path: inserted.path }),
    });
    assert.notEqual(wrongProfile.vm.stateSuccess(wrongProfile.state), true);
  });

  it("accepts a full withdrawal with the unchanged note root and profile-1 bank", () => {
    const old = oldState(20_000n);
    const nullifier = new Uint8Array(32).fill(0x78);
    const inserted = new SparseNullifierTree().insert(nullifier);
    const payout = 19_000n;
    const fee = 1_000n;
    const next = {
      ...old,
      sequence: 1n,
      reserveSats: 0n,
      withdrawalCount: 1n,
      nullifierRoot: inserted.newRoot,
    };
    const accepted = evaluate({
      profile: 1,
      old,
      next,
      fee,
      payout,
      nullifierData: encodeLocalWordNullifierData({ nullifier, path: inserted.path }),
    });
    assert.equal(accepted.vm.stateSuccess(accepted.state), true, String(accepted.state.error));

    const wrongBank = evaluate({
      profile: 1,
      bankProfile: 2,
      old,
      next,
      fee,
      payout,
      nullifierData: encodeLocalWordNullifierData({ nullifier, path: inserted.path }),
    });
    assert.notEqual(wrongBank.vm.stateSuccess(wrongBank.state), true);
  });

  it("accepts only an exact public sparse-nullifier absence-to-used update", () => {
    const roles = [
      { inputIndex: NULLIFIER_ROLE_START, root: "absence", segment: 0 },
      { inputIndex: NULLIFIER_ROLE_START + 1, root: "absence", segment: 1 },
      { inputIndex: NULLIFIER_ROLE_START + 2, root: "used", segment: 0 },
      { inputIndex: NULLIFIER_ROLE_START + 3, root: "used", segment: 1 },
    ] as const;
    const gates = roles.map((role) => ({
      ...role,
      gate: compileLocalWordSparseNullifierGate(role.root, role.segment),
    }));
    assert.equal(gates.every(({ gate }) => gate.length < 10_000), true);

    const depositOld = oldState(0n);
    const depositNext = {
      ...depositOld,
      sequence: 1n,
      reserveSats: 20_000n,
      depositCount: 1n,
      noteRoot: new Uint8Array(32).fill(0x52),
    };
    const deposit = evaluate({ profile: 0, old: depositOld, next: depositNext, fee: 1_000n });
    for (const { inputIndex, gate } of gates) {
      const depositRole = evaluateRole(deposit, gate, inputIndex);
      assert.equal(deposit.vm.stateSuccess(depositRole.state), true);
    }

    const old = oldState(20_000n);
    const nullifier = new Uint8Array(32).fill(0x77);
    const inserted = new SparseNullifierTree().insert(nullifier);
    const payout = 8_000n;
    const fee = 1_000n;
    const next = {
      ...old,
      sequence: 1n,
      reserveSats: old.reserveSats - payout - fee,
      withdrawalCount: 1n,
      noteRoot: new Uint8Array(32).fill(0x53),
      nullifierRoot: inserted.newRoot,
    };
    const withdrawal = evaluate({
      profile: 2,
      old,
      next,
      fee,
      payout,
      nullifierData: encodeLocalWordNullifierData({ nullifier, path: inserted.path }),
    });
    const accepted = gates.map(({ inputIndex, root, segment, gate }) => ({
      inputIndex,
      root,
      segment,
      ...evaluateRole(withdrawal, gate, inputIndex),
    }));
    for (const role of accepted) {
      assert.equal(
        withdrawal.vm.stateSuccess(role.state),
        true,
        JSON.stringify({
          inputIndex: role.inputIndex,
          root: role.root,
          segment: role.segment,
          error: role.state.error,
          ip: role.state.ip,
          metrics: role.state.metrics,
        }),
      );
    }
    console.log("local-word-sparse-nullifier-gates", JSON.stringify(accepted.map((role) => ({
      root: role.root,
      segment: role.segment,
      lockingBytes: gates.find((gate) => gate.root === role.root && gate.segment === role.segment)!.gate.length,
      operationCost: role.state.metrics.operationCost,
    }))));

    const changedPath = structuredClone(accepted[0]!.transaction);
    changedPath.outputs[LOCAL_WORD_NULLIFIER_DATA_OUTPUT]!
      .lockingBytecode[LOCAL_WORD_NULLIFIER_PATH_OFFSET + 17] ^= 1;
    const pathRejected = withdrawal.vm.evaluate({
      inputIndex: accepted[0]!.inputIndex,
      sourceOutputs: accepted[0]!.sourceOutputs,
      transaction: changedPath,
    } as never);
    assert.notEqual(withdrawal.vm.stateSuccess(pathRejected), true);

    const changedUpperPath = structuredClone(accepted[1]!.transaction);
    changedUpperPath.outputs[LOCAL_WORD_NULLIFIER_DATA_OUTPUT]!
      .lockingBytecode[LOCAL_WORD_NULLIFIER_PATH_OFFSET + 4_096 + 17] ^= 1;
    const upperPathRejected = withdrawal.vm.evaluate({
      inputIndex: accepted[1]!.inputIndex,
      sourceOutputs: accepted[1]!.sourceOutputs,
      transaction: changedUpperPath,
    } as never);
    assert.notEqual(withdrawal.vm.stateSuccess(upperPathRejected), true);

    const changedRoot = structuredClone(accepted[3]!.transaction);
    const changedRootOutput = changedRoot.outputs[0]!;
    if (!("token" in changedRootOutput)) throw new Error("pool token fixture");
    changedRootOutput.token.nft.commitment[96] ^= 1;
    const rootRejected = withdrawal.vm.evaluate({
      inputIndex: accepted[3]!.inputIndex,
      sourceOutputs: accepted[3]!.sourceOutputs,
      transaction: changedRoot,
    } as never);
    assert.notEqual(withdrawal.vm.stateSuccess(rootRejected), true);

    const changedOldRoot = structuredClone(accepted[1]!.sourceOutputs);
    const changedOldRootOutput = changedOldRoot[0]!;
    if (!("token" in changedOldRootOutput)) throw new Error("pool token fixture");
    changedOldRootOutput.token.nft.commitment[96] ^= 1;
    const oldRootRejected = withdrawal.vm.evaluate({
      inputIndex: accepted[1]!.inputIndex,
      sourceOutputs: changedOldRoot,
      transaction: accepted[1]!.transaction,
    } as never);
    assert.notEqual(withdrawal.vm.stateSuccess(oldRootRejected), true);
  });

  it("derives the prover transcript start from the exact transaction bytes", () => {
    const depositOld = oldState(0n);
    const depositNext = {
      ...depositOld,
      sequence: 1n,
      reserveSats: 20_000n,
      depositCount: 1n,
      noteRoot: new Uint8Array(32).fill(0x52),
    };
    const deposit = evaluate({ profile: 0, old: depositOld, next: depositNext, fee: 1_000n });
    const depositGate = compileLocalWordTranscriptInitialKatGate({
      constructionId: CONSTRUCTION_ID,
      expectedDigest: transactionTranscriptDigest(deposit),
    });
    const depositRole = evaluateRole(deposit, depositGate, 38);
    assert.equal(deposit.vm.stateSuccess(depositRole.state), true, depositRole.state.error);

    const changedReserve = structuredClone(depositRole.transaction);
    changedReserve.outputs[0]!.valueSatoshis += 1n;
    const reserveRejected = deposit.vm.evaluate({
      inputIndex: 38,
      sourceOutputs: depositRole.sourceOutputs,
      transaction: changedReserve,
    } as never);
    assert.notEqual(deposit.vm.stateSuccess(reserveRejected), true);

    const old = oldState(20_000n);
    const nullifier = new Uint8Array(32).fill(0x77);
    const inserted = new SparseNullifierTree().insert(nullifier);
    const payout = 8_000n;
    const fee = 1_000n;
    const next = {
      ...old,
      sequence: 1n,
      reserveSats: old.reserveSats - payout - fee,
      withdrawalCount: 1n,
      noteRoot: new Uint8Array(32).fill(0x53),
      nullifierRoot: inserted.newRoot,
    };
    const withdrawal = evaluate({
      profile: 2,
      old,
      next,
      fee,
      payout,
      nullifierData: encodeLocalWordNullifierData({ nullifier, path: inserted.path }),
    });
    const withdrawalGate = compileLocalWordTranscriptInitialKatGate({
      constructionId: CONSTRUCTION_ID,
      expectedDigest: transactionTranscriptDigest(withdrawal),
    });
    const withdrawalRole = evaluateRole(withdrawal, withdrawalGate, 38);
    assert.equal(withdrawal.vm.stateSuccess(withdrawalRole.state), true, withdrawalRole.state.error);
    console.log("local-word-transcript-initial-gates", JSON.stringify([
      { profile: 0, lockingBytes: depositGate.length, operationCost: depositRole.state.metrics.operationCost },
      { profile: 2, lockingBytes: withdrawalGate.length, operationCost: withdrawalRole.state.metrics.operationCost },
    ]));

    const changedPayout = structuredClone(withdrawalRole.transaction);
    changedPayout.outputs[LOCAL_WORD_PAYOUT_OUTPUT]!.lockingBytecode[0] ^= 1;
    const payoutRejected = withdrawal.vm.evaluate({
      inputIndex: 38,
      sourceOutputs: withdrawalRole.sourceOutputs,
      transaction: changedPayout,
    } as never);
    assert.notEqual(withdrawal.vm.stateSuccess(payoutRejected), true);

    const changedNullifier = structuredClone(withdrawalRole.transaction);
    changedNullifier.outputs[LOCAL_WORD_NULLIFIER_DATA_OUTPUT]!.lockingBytecode[9] ^= 1;
    const nullifierRejected = withdrawal.vm.evaluate({
      inputIndex: 38,
      sourceOutputs: withdrawalRole.sourceOutputs,
      transaction: changedNullifier,
    } as never);
    assert.notEqual(withdrawal.vm.stateSuccess(nullifierRejected), true);
  });

  it("replays every interaction challenge from transaction data and canonical proof roots", () => {
    const old = oldState(0n);
    const next = {
      ...old,
      sequence: 1n,
      reserveSats: 20_000n,
      depositCount: 1n,
      noteRoot: new Uint8Array(32).fill(0x52),
    };
    const deposit = evaluate({ profile: 0, old, next, fee: 1_000n });
    const replay = transactionInteraction(deposit, 18);
    const gate = compileLocalWordInteractionTranscriptKatGate({
      constructionId: CONSTRUCTION_ID,
      publicWordCount: 18,
      expectedDigest: replay.transcript.digest,
      boundaryChallenges: replay.challenges.boundary,
    });
    assert.ok(gate.length < 10_000);
    const accepted = evaluateRole(deposit, gate, NULLIFIER_ROLE_START);
    assert.equal(
      deposit.vm.stateSuccess(accepted.state),
      true,
      JSON.stringify({ error: accepted.state.error, ip: accepted.state.ip, metrics: accepted.state.metrics }),
    );
    console.log("local-word-interaction-transcript-gate", JSON.stringify({
      lockingBytes: gate.length,
      operationCost: accepted.state.metrics.operationCost,
    }));

    const changedOriginalRoot = structuredClone(accepted.transaction);
    const originalRootOffset = localWordProofStaticOffsets(18).matrixRoots + 32;
    mutateProofByte(changedOriginalRoot, deposit.proof.length, originalRootOffset);
    const rootRejected = deposit.vm.evaluate({
      inputIndex: NULLIFIER_ROLE_START,
      sourceOutputs: accepted.sourceOutputs,
      transaction: changedOriginalRoot,
    } as never);
    assert.notEqual(deposit.vm.stateSuccess(rootRejected), true);

    const changedStatement = structuredClone(accepted.transaction);
    changedStatement.outputs[0]!.valueSatoshis += 1n;
    const statementRejected = deposit.vm.evaluate({
      inputIndex: 8,
      sourceOutputs: accepted.sourceOutputs,
      transaction: changedStatement,
    } as never);
    assert.notEqual(deposit.vm.stateSuccess(statementRejected), true);
  });

  it("binds ordered transaction words to their serialized QM31 public inverses", () => {
    const depositOld = oldState(0n);
    const depositNext = {
      ...depositOld,
      sequence: 1n,
      reserveSats: 20_000n,
      depositCount: 1n,
      noteRoot: new Uint8Array(32).fill(0x52),
    };
    const depositBase = evaluate({ profile: 0, old: depositOld, next: depositNext, fee: 1_000n });
    const depositProof = proofWithPublicInverses(depositBase);
    const deposit = evaluate({
      profile: 0,
      old: depositOld,
      next: depositNext,
      fee: 1_000n,
      proof: depositProof,
    });
    const depositInverseCosts: number[] = [];
    for (const [role, publicWordIndex] of Array.from({ length: 18 }, (_, index) => index).entries()) {
      const gate = compileLocalWordPublicBoundaryInverseGate({
        profile: 0,
        publicWordIndex,
      });
      assert.ok(gate.length < 10_000);
      const checked = evaluateRole(deposit, gate, 9 + role);
      assert.equal(
        deposit.vm.stateSuccess(checked.state),
        true,
        JSON.stringify({ index: publicWordIndex, error: checked.state.error, metrics: checked.state.metrics }),
      );
      depositInverseCosts.push(Number(checked.state.metrics.operationCost));
    }
    const depositSumGate = compileLocalWordPublicBoundarySumGate(0);
    const depositSum = evaluateRole(deposit, depositSumGate, 12);
    assert.equal(deposit.vm.stateSuccess(depositSum.state), true, String(depositSum.state.error));

    const inverseGate = compileLocalWordPublicBoundaryInverseGate({
      profile: 0,
      publicWordIndex: 0,
    });
    const inverseRole = evaluateRole(deposit, inverseGate, 9);
    const changedInverse = structuredClone(inverseRole.transaction);
    mutateProofByte(changedInverse, deposit.proof.length, LOCAL_WORD_PROOF_FIXED_PREFIX_BYTES);
    const inverseRejected = deposit.vm.evaluate({
      inputIndex: 9,
      sourceOutputs: inverseRole.sourceOutputs,
      transaction: changedInverse,
    } as never);
    assert.notEqual(deposit.vm.stateSuccess(inverseRejected), true);
    const changedSum = structuredClone(depositSum.transaction);
    mutateProofByte(
      changedSum,
      deposit.proof.length,
      localWordProofStaticOffsets(18).publicClaimedSum,
    );
    const sumRejected = deposit.vm.evaluate({
      inputIndex: 12,
      sourceOutputs: depositSum.sourceOutputs,
      transaction: changedSum,
    } as never);
    assert.notEqual(deposit.vm.stateSuccess(sumRejected), true);

    const old = oldState(20_000n);
    const nullifier = new Uint8Array(32).fill(0x77);
    const inserted = new SparseNullifierTree().insert(nullifier);
    const payout = 8_000n;
    const fee = 1_000n;
    const next = {
      ...old,
      sequence: 1n,
      reserveSats: old.reserveSats - payout - fee,
      withdrawalCount: 1n,
      noteRoot: new Uint8Array(32).fill(0x53),
      nullifierRoot: inserted.newRoot,
    };
    const withdrawalBase = evaluate({
      profile: 2,
      old,
      next,
      fee,
      payout,
      nullifierData: encodeLocalWordNullifierData({ nullifier, path: inserted.path }),
    });
    const withdrawalProof = proofWithPublicInverses(withdrawalBase);
    const withdrawal = evaluate({
      profile: 2,
      old,
      next,
      fee,
      payout,
      nullifierData: encodeLocalWordNullifierData({ nullifier, path: inserted.path }),
      proof: withdrawalProof,
    });
    const withdrawalInverseCosts: number[] = [];
    for (const [role, publicWordIndex] of Array.from({ length: 34 }, (_, index) => index).entries()) {
      const gate = compileLocalWordPublicBoundaryInverseGate({
        profile: 2,
        publicWordIndex,
      });
      const checked = evaluateRole(withdrawal, gate, 12 + role);
      assert.equal(
        withdrawal.vm.stateSuccess(checked.state),
        true,
        JSON.stringify({ index: publicWordIndex, error: checked.state.error, metrics: checked.state.metrics }),
      );
      withdrawalInverseCosts.push(Number(checked.state.metrics.operationCost));
    }
    const withdrawalSum = evaluateRole(withdrawal, compileLocalWordPublicBoundarySumGate(2), 17);
    assert.equal(withdrawal.vm.stateSuccess(withdrawalSum.state), true, String(withdrawalSum.state.error));
    const boundaryBatches = [
      { start: 0, count: 12 },
      { start: 12, count: 12 },
      { start: 24, count: 10 },
    ] as const;
    const batchMeasurements = boundaryBatches.map((batch, role) => {
      const gate = compileLocalWordPublicBoundaryInverseBatchGate({ profile: 2, ...batch });
      const inputIndex = 29 + role;
      const checked = evaluateP2shRole(withdrawal, withdrawalProof, gate, inputIndex);
      assert.equal(withdrawal.vm.stateSuccess(checked.state), true, JSON.stringify({ batch, error: checked.state.error }));
      const changed = structuredClone(checked.transaction);
      mutateProofByte(
        changed,
        withdrawalProof.length,
        LOCAL_WORD_PROOF_FIXED_PREFIX_BYTES + batch.start * 16,
      );
      const rejected = withdrawal.vm.evaluate({
        inputIndex,
        sourceOutputs: checked.sourceOutputs,
        transaction: changed,
      } as never);
      assert.notEqual(withdrawal.vm.stateSuccess(rejected), true);
      return {
        ...batch,
        lockingBytes: gate.length,
        operationCost: checked.state.metrics.operationCost,
      };
    });
    console.log("local-word-public-boundary-gates", JSON.stringify({
      depositInverse: { min: Math.min(...depositInverseCosts), max: Math.max(...depositInverseCosts) },
      depositSum: depositSum.state.metrics.operationCost,
      withdrawalInverse: { min: Math.min(...withdrawalInverseCosts), max: Math.max(...withdrawalInverseCosts) },
      withdrawalSum: withdrawalSum.state.metrics.operationCost,
      withdrawalBatches: batchMeasurements,
    }));
  });

  it("derives the unique query schedule from the complete proof transcript", () => {
    const parameters: LocalWordProofParameters = {
      ...LOCAL_WORD_PRODUCTION_PARAMETERS,
      // Pin the exact production PoW branch; zero-bit fixtures missed a mask
      // truncation that rejected valid candidates with a nonzero low nibble.
      fri: { ...LOCAL_WORD_PRODUCTION_PARAMETERS.fri, grindBits: 20 },
    };
    const old = oldState(0n);
    const next = {
      ...old,
      sequence: 1n,
      reserveSats: 20_000n,
      depositCount: 1n,
      noteRoot: new Uint8Array(32).fill(0x52),
    };
    const base = evaluate({ profile: 0, old, next, fee: 1_000n });
    const proof = proofWithPublicInverses(base);
    const offsets = localWordProofTranscriptOffsets(18, parameters);
    const expectedQueries = fillTranscriptManifest(base, proof, 18, parameters);
    const depositWithManifest = evaluate({ profile: 0, old, next, fee: 1_000n, proof });

    const manifestParts = [
      "interaction",
      "composition",
      "batch",
      "fri-first",
      "fri-second",
      "final",
    ] as const;
    const manifestMeasurements: { part: string; lockingBytes: number; operationCost: number | bigint }[] = [];
    let friFirstRole: ReturnType<typeof evaluateRole> | undefined;
    for (const [index, part] of manifestParts.entries()) {
      const gate = compileLocalWordTranscriptManifestGate({
        constructionId: CONSTRUCTION_ID,
        publicWordCount: 18,
        part,
        parameters,
      });
      assert.ok(gate.length < 10_000);
      const role = evaluateRole(depositWithManifest, gate, 38 + index);
      assert.equal(
        depositWithManifest.vm.stateSuccess(role.state),
        true,
        JSON.stringify({
          part,
          lockingBytes: gate.length,
          error: role.state.error,
          ip: role.state.ip,
          stack: role.state.stack.map((item) => Buffer.from(item).toString("hex")),
          metrics: role.state.metrics,
        }),
      );
      manifestMeasurements.push({ part, lockingBytes: gate.length, operationCost: role.state.metrics.operationCost });
      if (part === "fri-first") friFirstRole = role;
    }
    console.log("local-word-transcript-manifest-gates", JSON.stringify(manifestMeasurements));
    assert.ok(friFirstRole);
    const changedFriRoot = structuredClone(friFirstRole.transaction);
    mutateProofByte(changedFriRoot, depositWithManifest.proof.length, offsets.friRoots);
    const friRejected = depositWithManifest.vm.evaluate({
      inputIndex: 41,
      sourceOutputs: friFirstRole.sourceOutputs,
      transaction: changedFriRoot,
    } as never);
    assert.notEqual(depositWithManifest.vm.stateSuccess(friRejected), true);

    const actualGate = compileLocalWordQueryScheduleGate({
      publicWordCount: 18,
      parameters,
    });
    assert.ok(actualGate.length < 10_000);
    const actual = evaluateRole(depositWithManifest, actualGate, 44);
    assert.equal(
      depositWithManifest.vm.stateSuccess(actual.state),
      true,
      JSON.stringify({
        lockingBytes: actualGate.length,
        error: actual.state.error,
        ip: actual.state.ip,
        metrics: actual.state.metrics,
      }),
    );
    console.log("local-word-query-schedule-gate", JSON.stringify({
      lockingBytes: actualGate.length,
      operationCost: actual.state.metrics.operationCost,
      maximumOperationCost: actual.state.metrics.maximumOperationCost,
    }));

    const katGate = compileLocalWordQueryScheduleGate({
      publicWordCount: 18,
      parameters,
      expectedQueries,
    });
    const kat = evaluateRole(depositWithManifest, katGate, 44);
    assert.equal(
      depositWithManifest.vm.stateSuccess(kat.state),
      true,
      JSON.stringify({ error: kat.state.error, ip: kat.state.ip, metrics: kat.state.metrics }),
    );

    const changedTranscript = structuredClone(kat.transaction);
    mutateProofByte(changedTranscript, depositWithManifest.proof.length, offsets.queryDigest);
    const rejected = depositWithManifest.vm.evaluate({
      inputIndex: 44,
      sourceOutputs: kat.sourceOutputs,
      transaction: changedTranscript,
    } as never);
    assert.notEqual(depositWithManifest.vm.stateSuccess(rejected), true);
  });
});

import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  createVirtualMachine,
  createVirtualMachineBch2026,
  encodeLockingBytecodeP2sh32,
  hash256,
} from "@bitauth/libauth";
import { createV17LibauthBchnOpDefineDiagnosticInstructionSet } from
  "../src/assurance/v17-libauth-opdefine-diagnostic.ts";
import {
  compileLocalWordInteractionTranscriptKatGate,
  compileLocalWordEdgeAppendGate,
  compileLocalWordPublicBoundaryInverseBatchGate,
  compileLocalWordPublicBoundaryInverseGate,
  compileLocalWordPublicBoundarySumGate,
  compileLocalWordQueryScheduleGate,
  compileLocalWordSparseNullifierGate,
  compileLocalWordTranscriptInitialKatGate,
  compileLocalWordTranscriptManifestGate,
  compileV17LocalWordTranscriptManifestKatGate,
  compileLocalWordValueSettlementGate,
  localWordPublicWordCount,
  localWordProofTranscriptOffsets,
} from "../src/chain/local-word-balanced-vm.ts";
import {
  deriveLocalWordPublicSettlement,
  encodeLocalWordEdgeData,
  encodeLocalWordNullifierData,
  LOCAL_WORD_CHANGE_EDGE_DATA_OUTPUT,
  LOCAL_WORD_DEPOSIT_EDGE_DATA_OUTPUT,
  LOCAL_WORD_EDGE_PATH_OFFSET,
  LOCAL_WORD_NULLIFIER_DATA_OUTPUT,
  LOCAL_WORD_NULLIFIER_PATH_OFFSET,
  LOCAL_WORD_PAYOUT_OUTPUT,
} from "../src/chain/local-word-envelope.ts";
import {
  compileLocalWordCarrierRedeem,
  compileLocalWordPoolCarrierRedeem,
  encodeLocalWordP2shCarrierUnlocking,
  LOCAL_WORD_CARRIER_INPUTS,
  LOCAL_WORD_CARRIER_MIN_PROOF_BYTES,
  localWordVerifierCarrierValue,
  localWordVerifierCarrierSequence,
  localWordPoolCarrierSequence,
  locateLocalWordProofByte,
  localWordP2sh32Lock,
  localWordVerifierBankDigestFromInputs,
  localWordVerifierBankDigestFromLockingBytecodes,
  partitionLocalWordProofBytes,
} from
  "../src/chain/local-word-proof-carriers.ts";
import { createV17RomPage } from "../src/chain/v17-code-rom.ts";
import { LAB_PAYOUT_LOCKING } from "../src/chain/payout.ts";
import {
  LOCAL_WORD_PROOF_LENGTH_OFFSET,
  LOCAL_WORD_PROOF_VERSION,
  localWordMaximumCanonicalProofBytes,
  localWordProofStaticOffsets,
} from "../src/backends/circle/local-word-sealed-proof.ts";
import { LOCAL_WORD_V16_CONSTRUCTION_ID } from
  "../src/backends/circle/local-word-construction-v16.ts";
import {
  localWordRelationStatementDigest,
  localWordTranscriptInitial,
} from "../src/backends/circle/local-word-public-statement.ts";
import { SuccessorTranscript } from "../src/backends/circle/successor-transcript.ts";
import {
  V17_PROOF_PROTOCOL_ID,
  v17ProofFrame,
  v17ProofFrameOffset,
  type V17GeneratedProofFrameId,
} from "../src/backends/circle/v17-proof-layout.ts";
import {
  grindV17TheoremRound,
  V17_THEOREM_ROUND_IDS,
  type V17RoundGrinding,
  type V17TheoremRoundId,
} from "../src/backends/circle/v17-round-transcript.ts";
import { deriveV17OodsChallenge } from "../src/backends/circle/v17-oods.ts";
import {
  localWordCompositionTranscript,
  localWordInteractionChallengeValues,
  localWordInteractionTranscript,
  localWordPublicBoundaryTranscript,
  localWordQueryIndices,
  localWordQuerySamples,
} from "../src/backends/circle/local-word-transcript.ts";
import { decodeQm31, encodeQm31 } from "../src/backends/circle/qm31.ts";
import {
  LOCAL_WORD_PRODUCTION_PARAMETERS,
  type LocalWordProofParameters,
} from "../src/backends/circle/local-word-successor-params.ts";
import { poolLocalBoundaryClaimForWords } from "../src/chain/pool-relation-local-word-boundary.ts";
import { localShaWordsFromBytes } from "../src/chain/sha256-local-word-machine.ts";
import { writeU32BE, writeU32LE } from "../src/pool/bytes.ts";
import { EdgeHistory } from "../src/pool/edge-history.ts";
import { SparseNullifierTree, emptySparseNullifierRoot } from "../src/pool/sparse-nullifiers.ts";
import { emptyState, encodePublicPaa2, STATE_BASE_SATS, type AnyAmountState } from "../src/pool/state.ts";

const CATEGORY = Uint8Array.from({ length: 32 }, (_, index) => index + 1);
const CONSTRUCTION_ID = LOCAL_WORD_V16_CONSTRUCTION_ID;
const carrierLocks = (profile: 0 | 1 | 2) =>
  Array.from({ length: LOCAL_WORD_CARRIER_INPUTS - 1 }, (_, index) =>
    localWordP2sh32Lock(Uint8Array.of(0x51, profile, index & 0xff, index >>> 8)));
const CARRIER_LOCKS = [carrierLocks(0), carrierLocks(1), carrierLocks(2)] as const;
const BANK_DIGESTS = [
  localWordVerifierBankDigestFromLockingBytecodes(0, CARRIER_LOCKS[0]),
  localWordVerifierBankDigestFromLockingBytecodes(1, CARRIER_LOCKS[1]),
  localWordVerifierBankDigestFromLockingBytecodes(2, CARRIER_LOCKS[2]),
] as const;
const EDGE_ROLE_INPUT = 32;
const NULLIFIER_ROLE_INPUTS = [33, 34, 35, 36] as const;
const BOUNDARY_ROLE_START = 30;
const BOUNDARY_SUM_ROLE_INPUT = 37;
const TRANSCRIPT_ROLE_START = 38;
const QUERY_SCHEDULE_ROLE_INPUT = 44;
const V17_TRANSCRIPT_KAT_GRINDING = V17_THEOREM_ROUND_IDS.map((id, index): V17RoundGrinding => ({
  id,
  bits: [2, 0, 3, 4, 3, 2, 4, 1, 3, 2, 4, 1, 3, 4][index]!,
}));
const V17_TRANSCRIPT_KATS = [
  {
    nonces: [2, 0, 9, 19, 0, 2, 18, 0, 11, 0, 10, 0, 21, 4],
    queryDigest: "1c0cd7178a9a50ee00e784c6f03f3a202b2db12bbfbe22decddb60dba5e0cd04",
  },
  {
    nonces: [5, 0, 9, 12, 5, 5, 21, 3, 0, 2, 29, 1, 3, 49],
    queryDigest: "4014919e7c24f4246343cceaa8ffac5b0a9bc434dfce102c9511500f148f2cee",
  },
  {
    nonces: [8, 0, 1, 17, 8, 4, 6, 3, 1, 8, 27, 0, 16, 0],
    queryDigest: "51cc9916bb8290bbfd6169ad88788c201a344c70e910423828d8600550a30e0c",
  },
] as const;

function proofBytes(
  profile: 0 | 1 | 2,
  length = localWordMaximumCanonicalProofBytes(localWordPublicWordCount(profile)),
): Uint8Array {
  const bytes = Uint8Array.from(
    { length },
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
    nft: { capability: "mutable" as const, commitment: encodePublicPaa2(state) },
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
    ...emptyState(),
    reserveSats,
    nullifierRoot: emptySparseNullifierRoot(),
  };
}

function appendCreation(old: AnyAmountState, edgeByte: number, headByte: number) {
  const history = new EdgeHistory();
  assert.deepEqual(history.root, old.edgeHistoryRoot);
  assert.equal(old.creationCount, 0n);
  const edge = new Uint8Array(32).fill(edgeByte);
  const appended = history.append(edge);
  return {
    state: {
      creationCount: old.creationCount + 1n,
      creationHead: new Uint8Array(32).fill(headByte),
      edgeHistoryRoot: appended.newRoot,
    },
    data: encodeLocalWordEdgeData({
      creationIndex: appended.index,
      edge,
      path: appended.path,
    }),
  };
}

function evaluate(args: {
  readonly profile: 0 | 1 | 2;
  readonly old: AnyAmountState;
  readonly next: AnyAmountState;
  readonly fee: bigint;
  readonly payout?: bigint;
  readonly nullifierData?: Uint8Array;
  readonly edgeData?: Uint8Array;
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
    outputs.push({ lockingBytecode: args.edgeData!, valueSatoshis: 0n });
  } else {
    outputs.push({ lockingBytecode: LAB_PAYOUT_LOCKING, valueSatoshis: args.payout });
    outputs.push({ lockingBytecode: args.nullifierData!, valueSatoshis: 0n });
    if (args.profile === 2) outputs.push({ lockingBytecode: args.edgeData!, valueSatoshis: 0n });
  }
  const transaction = { version: 2, locktime: 0, inputs, outputs };
  const vm = createVirtualMachineBch2026(false);
  const state = vm.evaluate({ inputIndex: 0, sourceOutputs, transaction } as never);
  return { verifier, lock: redeem, vm, state, sourceOutputs, transaction, proof };
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
  vm = fixture.vm,
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
  const state = vm.evaluate({ inputIndex, sourceOutputs, transaction } as never);
  return { sourceOutputs, transaction, state, vm };
}

function unboundedV17DiagnosticVm() {
  const instructionSet = createV17LibauthBchnOpDefineDiagnosticInstructionSet(false);
  const every = instructionSet.every!;
  return createVirtualMachine({
    ...instructionSet,
    every: (state) => {
      state.metrics.maximumOperationCost = 1_000_000_000;
      return every(state);
    },
  });
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
    inputSequenceNumbers: fixture.transaction.inputs.map((input) => input.sequenceNumber),
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
    inputSequenceNumbers: fixture.transaction.inputs.map((input) => input.sequenceNumber),
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
    inputSequenceNumbers: fixture.transaction.inputs.map((input) => input.sequenceNumber),
    outputs: fixture.transaction.outputs,
  }, BANK_DIGESTS);
  return localShaWordsFromBytes(localWordRelationStatementDigest(
    settlement.statement,
    settlement.minerFeeSats,
  ));
}

function proofWithPublicInverses(fixture: ReturnType<typeof evaluate>): Uint8Array {
  const values = publicBoundaryValues(fixture);
  const settlement = deriveLocalWordPublicSettlement({
    sourceOutputs: fixture.sourceOutputs,
    inputSequenceNumbers: fixture.transaction.inputs.map((input) => input.sequenceNumber),
    outputs: fixture.transaction.outputs,
  }, BANK_DIGESTS);
  const profile = settlement.profile === "deposit" ? 0 : settlement.profile === "withdraw-full" ? 1 : 2;
  const base = fixture.proof.slice();
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
    proof.slice(
      offsets.finalCoefficients,
      offsets.finalCoefficients + offsets.finalCoefficientCount * 16,
    ),
  );
  const nonce = replay.transcript.grind(parameters.fri.grindBits);
  proof.set(writeU32BE(nonce), offsets.grindNonce);
  proof.set(replay.transcript.digest, offsets.queryDigest);
  const queries = localWordQueryIndices(replay.transcript, parameters);
  queries.forEach((query, index) => proof.set(writeU32BE(query), offsets.queries + index * 4));
  return queries;
}

function fillV17TranscriptKat(
  fixture: ReturnType<typeof evaluate>,
  proof: Uint8Array,
): { readonly nonces: readonly number[]; readonly queryDigest: Uint8Array } {
  const settlement = deriveLocalWordPublicSettlement({
    sourceOutputs: fixture.sourceOutputs,
    inputSequenceNumbers: fixture.transaction.inputs.map((input) => input.sequenceNumber),
    outputs: fixture.transaction.outputs,
  }, BANK_DIGESTS);
  const transcript = new SuccessorTranscript(localWordTranscriptInitial(
    settlement.statement,
    V17_PROOF_PROTOCOL_ID,
    settlement.minerFeeSats,
  ));
  const frame = (id: V17GeneratedProofFrameId): Uint8Array => {
    const spec = v17ProofFrame(id);
    return proof.slice(spec.offsetBytes, spec.offsetBytes + spec.totalBytes);
  };
  const setFrame = (id: V17GeneratedProofFrameId, value: Uint8Array): void => {
    const spec = v17ProofFrame(id);
    assert.equal(value.length, spec.totalBytes, `v17 KAT frame ${id}`);
    proof.set(value, spec.offsetBytes);
  };
  const setQm31Item = (id: V17GeneratedProofFrameId, item: number, value: ReturnType<SuccessorTranscript["challengeQm31"]>): void => {
    const spec = v17ProofFrame(id);
    assert.equal(spec.itemBytes, 16);
    proof.set(encodeQm31(value), spec.offsetBytes + item * 16);
  };
  proof.set(V17_PROOF_PROTOCOL_ID, v17ProofFrameOffset("protocolId"));
  proof.fill(0, v17ProofFrameOffset("publicInverses"),
    v17ProofFrameOffset("publicInverses") + v17ProofFrame("publicInverses").totalBytes);
  proof.fill(0, v17ProofFrameOffset("publicClaimedSum"),
    v17ProofFrameOffset("publicClaimedSum") + v17ProofFrame("publicClaimedSum").totalBytes);
  proof.fill(0, v17ProofFrameOffset("oodValues"),
    v17ProofFrameOffset("oodValues") + v17ProofFrame("oodValues").totalBytes);
  proof.fill(0, v17ProofFrameOffset("finalCoefficients"),
    v17ProofFrameOffset("finalCoefficients") + v17ProofFrame("finalCoefficients").totalBytes);

  transcript.absorb("local-word-v17-magic", frame("magic"));
  transcript.absorb("local-word-v17-proof-version", frame("proofVersion"));
  transcript.absorb("local-word-v17-profile", frame("profile"));
  transcript.absorb("local-word-v17-protocol-id", frame("protocolId"));
  transcript.absorb("local-word-v17-preprocessed-root", frame("matrixRoot:preprocessed"));
  transcript.absorb("local-word-v17-original-root", frame("matrixRoot:original"));

  let round = 0;
  const nonces: number[] = [];
  const grind = (id: V17TheoremRoundId): void => {
    const expected = V17_TRANSCRIPT_KAT_GRINDING[round]!;
    assert.equal(expected.id, id);
    const result = grindV17TheoremRound(transcript, expected);
    proof.set(writeU32BE(result.nonce), v17ProofFrameOffset(`roundNonce:${id}`));
    nonces.push(result.nonce);
    round += 1;
  };
  grind("air:logup");
  const interactionChallenges = [
    transcript.challengeQm31("local-word-v17-lookup-gamma"),
    ...Array.from({ length: 6 }, (_, index) =>
      transcript.challengeQm31(`local-word-v17-lookup-tuple-${index}`)),
    transcript.challengeQm31("local-word-v17-copy-gamma"),
    transcript.challengeQm31("local-word-v17-copy-identity"),
    ...Array.from({ length: 8 }, (_, index) =>
      transcript.challengeQm31(`local-word-v17-copy-limb-${index}`)),
    transcript.challengeQm31("local-word-v17-boundary-gamma"),
    transcript.challengeQm31("local-word-v17-boundary-identity"),
    ...Array.from({ length: 8 }, (_, index) =>
      transcript.challengeQm31(`local-word-v17-boundary-limb-${index}`)),
  ];
  assert.equal(interactionChallenges.length, 27);
  interactionChallenges.forEach((challenge, item) =>
    setQm31Item("interactionChallenges", item, challenge));
  transcript.absorb("local-word-v17-public-boundary-inverses", frame("publicInverses"));
  transcript.absorb("local-word-v17-public-boundary-claimed-sum", frame("publicClaimedSum"));
  transcript.absorb("local-word-v17-interaction-root", frame("matrixRoot:interaction"));
  transcript.absorb("local-word-v17-interaction-global-root", frame("matrixRoot:interactionGlobal"));
  setFrame("interactionDigest", transcript.digest);

  grind("air:composition");
  setFrame("constraintAlpha", encodeQm31(
    transcript.challengeQm31("local-word-v17-constraint-alpha"),
  ));
  setFrame("compositionDigest", transcript.digest);
  transcript.absorb(
    "local-word-v17-quotient-and-fri-mask-root",
    frame("matrixRoot:quotientAndFriMask"),
  );
  grind("air:ood");
  deriveV17OodsChallenge(transcript.digest);
  transcript.absorb("local-word-v17-ood-values", frame("oodValues"));
  grind("fri:batch");
  setFrame("batchBeta", encodeQm31(transcript.challengeQm31("local-word-v17-batch-beta")));
  setFrame("batchDigest", transcript.digest);

  for (let friRound = 0; friRound < 9; friRound += 1) {
    transcript.absorb(`local-word-v17-fri-root-${friRound}`,
      frame(`friRoot:${friRound}` as V17GeneratedProofFrameId));
    grind(`fri:fold:${friRound}` as V17TheoremRoundId);
    const count = friRound < 8 ? 2 : 1;
    for (let subfold = 0; subfold < count; subfold += 1) {
      setFrame(
        `friAlpha:${friRound}:${subfold}` as V17GeneratedProofFrameId,
        encodeQm31(transcript.challengeQm31(
          `local-word-v17-fri-alpha-${friRound}-${subfold}`,
        )),
      );
    }
    if (friRound === 4) setFrame("friMidDigest", transcript.digest);
  }
  setFrame("friRootsDigest", transcript.digest);
  transcript.absorb("local-word-v17-fri-final", frame("finalCoefficients"));
  grind("fri:query");
  assert.equal(round, V17_THEOREM_ROUND_IDS.length);
  setFrame("queryDigest", transcript.digest);
  localWordQueryIndices(transcript).forEach((query, item) =>
    proof.set(writeU32BE(query), v17ProofFrameOffset("queries") + item * 4));
  return { nonces, queryDigest: transcript.digest };
}

describe("local-word public settlement on the May-2026 VM", () => {
  it("accepts a deposit and rejects a wrong proof profile or carrier rollover", () => {
    const old = oldState(0n);
    const creation = appendCreation(old, 0x5e, 0x52);
    const next = {
      ...old,
      sequence: 1n,
      reserveSats: 20_000n,
      ...creation.state,
    };
    const accepted = evaluate({ profile: 0, old, next, fee: 1_000n, edgeData: creation.data });
    assert.equal(accepted.vm.stateSuccess(accepted.state), true, JSON.stringify({
      error: accepted.state.error,
      stack: accepted.state.stack.map((item) => Buffer.from(item).toString("hex")),
      metrics: accepted.state.metrics,
    }));
    assert.ok(accepted.lock.length < 10_000);
    console.log("local-word-deposit-settlement-gate", JSON.stringify({
      verifierBytes: accepted.verifier.length,
      redeemBytes: accepted.lock.length,
      unlockingBytes: accepted.transaction.inputs[0]!.unlockingBytecode.length,
      operationCost: accepted.state.metrics.operationCost,
      maximumOperationCost: accepted.state.metrics.maximumOperationCost,
    }));

    const wrongProfile = evaluate({
      profile: 2,
      bankProfile: 0,
      old,
      next,
      fee: 1_000n,
      edgeData: creation.data,
    });
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

    const mintingSources = structuredClone(accepted.sourceOutputs);
    const mintingTransaction = structuredClone(accepted.transaction);
    const mintingInput = mintingSources[0]!;
    const mintingOutput = mintingTransaction.outputs[0]!;
    if (!("token" in mintingInput) || !("token" in mintingOutput)) {
      throw new Error("pool token fixture");
    }
    (mintingInput.token.nft as { capability: string }).capability = "minting";
    (mintingOutput.token.nft as { capability: string }).capability = "minting";
    const mintingRejected = accepted.vm.evaluate({
      inputIndex: 0,
      sourceOutputs: mintingSources,
      transaction: mintingTransaction,
    } as never);
    assert.notEqual(accepted.vm.stateSuccess(mintingRejected), true);

    const tokenFunding = structuredClone(accepted.sourceOutputs);
    Object.assign(tokenFunding[LOCAL_WORD_CARRIER_INPUTS]!, {
      token: {
        category: new Uint8Array(32).fill(0x99),
        amount: 1n,
      },
    });
    const tokenFundingRejected = accepted.vm.evaluate({
      inputIndex: 0,
      sourceOutputs: tokenFunding,
      transaction: accepted.transaction,
    } as never);
    assert.notEqual(accepted.vm.stateSuccess(tokenFundingRejected), true);

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

    const wrongBankValueSources = structuredClone(accepted.sourceOutputs);
    const wrongBankValueTransaction = structuredClone(accepted.transaction);
    wrongBankValueSources[5]!.valueSatoshis += 1n;
    wrongBankValueTransaction.outputs[5]!.valueSatoshis += 1n;
    const wrongBankValueState = accepted.vm.evaluate({
      inputIndex: 0,
      sourceOutputs: wrongBankValueSources,
      transaction: wrongBankValueTransaction,
    } as never);
    assert.notEqual(accepted.vm.stateSuccess(wrongBankValueState), true);
  });

  it("extends the same ordered value-neutral bank over authenticated ROM pages", () => {
    const old = oldState(0n);
    const creation = appendCreation(old, 0x5e, 0x52);
    const next = {
      ...old,
      sequence: 1n,
      reserveSats: 20_000n,
      ...creation.state,
    };
    const base = evaluate({
      profile: 0,
      old,
      next,
      fee: 1_000n,
      edgeData: creation.data,
      proof: proofBytes(0, LOCAL_WORD_CARRIER_MIN_PROOF_BYTES + 256),
    });
    const page = createV17RomPage({
      pageIndex: 0,
      inputIndex: LOCAL_WORD_CARRIER_INPUTS,
      outputIndex: LOCAL_WORD_CARRIER_INPUTS,
      entries: [{ functionId: Uint8Array.of(1), body: Uint8Array.of(0x51) }],
    });
    const bankDigests = CARRIER_LOCKS.map((locks, profile) =>
      localWordVerifierBankDigestFromInputs(profile as 0 | 1 | 2, [
        ...locks.map((lockingBytecode, local) => ({
          lockingBytecode,
          valueSatoshis: localWordVerifierCarrierValue(local + 1),
          sequenceNumber: localWordVerifierCarrierSequence(local + 1),
        })),
        {
          lockingBytecode: page.lockingBytecode,
          valueSatoshis: page.valueSatoshis,
          sequenceNumber: page.sequenceNumber,
        },
      ])) as unknown as typeof BANK_DIGESTS;
    const verifier = compileLocalWordValueSettlementGate(bankDigests);
    const redeem = compileLocalWordPoolCarrierRedeem(verifier);
    const poolLock = encodeLockingBytecodeP2sh32(hash256(redeem));
    const sourceOutputs = structuredClone(base.sourceOutputs);
    const transaction = structuredClone(base.transaction);
    sourceOutputs.splice(LOCAL_WORD_CARRIER_INPUTS, 0, {
      lockingBytecode: page.lockingBytecode,
      valueSatoshis: page.valueSatoshis,
    });
    transaction.inputs.splice(LOCAL_WORD_CARRIER_INPUTS, 0, {
      outpointTransactionHash: new Uint8Array(32).fill(0xa5),
      outpointIndex: LOCAL_WORD_CARRIER_INPUTS,
      sequenceNumber: page.sequenceNumber,
      unlockingBytecode: page.unlockingBytecode,
    });
    transaction.outputs.splice(LOCAL_WORD_CARRIER_INPUTS, 0, {
      lockingBytecode: page.lockingBytecode,
      valueSatoshis: page.valueSatoshis,
    });
    sourceOutputs[0]!.lockingBytecode = poolLock;
    transaction.outputs[0]!.lockingBytecode = poolLock;
    transaction.inputs[0]!.unlockingBytecode = encodeLocalWordP2shCarrierUnlocking(
      partitionLocalWordProofBytes(base.proof)[0]!.chunk,
      redeem,
    );

    const state = base.vm.evaluate({ inputIndex: 0, sourceOutputs, transaction } as never);
    assert.equal(base.vm.stateSuccess(state), true, JSON.stringify({
      error: state.error,
      metrics: state.metrics,
    }));
    const pageState = base.vm.evaluate({
      inputIndex: page.inputIndex,
      sourceOutputs,
      transaction,
    } as never);
    assert.equal(base.vm.stateSuccess(pageState), true, String(pageState.error));
    const settlement = deriveLocalWordPublicSettlement({
      sourceOutputs,
      inputSequenceNumbers: transaction.inputs.map((candidate) => candidate.sequenceNumber),
      outputs: transaction.outputs,
    }, bankDigests);
    assert.equal(settlement.profile, "deposit");

    const romFixture = { ...base, verifier, lock: redeem, sourceOutputs, transaction, state };
    const edge = evaluateRole(romFixture, compileLocalWordEdgeAppendGate(), EDGE_ROLE_INPUT);
    assert.equal(base.vm.stateSuccess(edge.state), true, String(edge.state.error));

    const changedValueSources = structuredClone(sourceOutputs);
    const changedValueTransaction = structuredClone(transaction);
    changedValueSources[page.inputIndex]!.valueSatoshis += 1n;
    changedValueTransaction.outputs[page.outputIndex]!.valueSatoshis += 1n;
    const changedValueState = base.vm.evaluate({
      inputIndex: 0,
      sourceOutputs: changedValueSources,
      transaction: changedValueTransaction,
    } as never);
    assert.notEqual(base.vm.stateSuccess(changedValueState), true);

    const tokenSources = structuredClone(sourceOutputs) as Array<
      (typeof sourceOutputs)[number] & { token?: unknown }
    >;
    const tokenTransaction = structuredClone(transaction) as typeof transaction & {
      outputs: Array<(typeof transaction.outputs)[number] & { token?: unknown }>;
    };
    const forbiddenToken = {
      category: new Uint8Array(32).fill(0x99),
      amount: 0n,
      nft: { capability: "minting", commitment: new Uint8Array() },
    };
    tokenSources[page.inputIndex]!.token = forbiddenToken;
    tokenTransaction.outputs[page.outputIndex]!.token = forbiddenToken;
    const tokenState = base.vm.evaluate({
      inputIndex: 0,
      sourceOutputs: tokenSources,
      transaction: tokenTransaction,
    } as never);
    assert.notEqual(base.vm.stateSuccess(tokenState), true);
    assert.throws(() => deriveLocalWordPublicSettlement({
      sourceOutputs: tokenSources as never,
      inputSequenceNumbers: tokenTransaction.inputs.map((candidate) => candidate.sequenceNumber),
      outputs: tokenTransaction.outputs as never,
    }, bankDigests), /value neutrality/);
  });

  it("accepts a change withdrawal and binds payout plus transaction fee to the pool drop", () => {
    const old = oldState(20_000n);
    const nullifier = new Uint8Array(32).fill(0x77);
    const sparse = new SparseNullifierTree();
    const inserted = sparse.insert(nullifier);
    const payout = 8_000n;
    const fee = 1_000n;
    const creation = appendCreation(old, 0x5f, 0x53);
    const next = {
      ...old,
      sequence: 1n,
      reserveSats: old.reserveSats - payout - fee,
      ...creation.state,
      nullifierRoot: inserted.newRoot,
    };
    const accepted = evaluate({
      profile: 2,
      old,
      next,
      fee,
      payout,
      nullifierData: encodeLocalWordNullifierData({ nullifier, path: inserted.path }),
      edgeData: creation.data,
    });
    assert.equal(accepted.vm.stateSuccess(accepted.state), true, String(accepted.vm.stateSuccess(accepted.state)));
    console.log("local-word-withdraw-change-settlement-gate", JSON.stringify({
      verifierBytes: accepted.verifier.length,
      redeemBytes: accepted.lock.length,
      unlockingBytes: accepted.transaction.inputs[0]!.unlockingBytecode.length,
      operationCost: accepted.state.metrics.operationCost,
      maximumOperationCost: accepted.state.metrics.maximumOperationCost,
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

  it("accepts a full withdrawal with unchanged creation state and profile-1 bank", () => {
    const old = oldState(20_000n);
    const nullifier = new Uint8Array(32).fill(0x78);
    const inserted = new SparseNullifierTree().insert(nullifier);
    const payout = 19_000n;
    const fee = 1_000n;
    const next = {
      ...old,
      sequence: 1n,
      reserveSats: 0n,
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

  it("verifies the canonical public depth-32 creation-edge append", () => {
    const gate = compileLocalWordEdgeAppendGate();
    assert.ok(gate.length < 10_000);

    const old = oldState(0n);
    const creation = appendCreation(old, 0x5e, 0x52);
    const next = {
      ...old,
      sequence: 1n,
      reserveSats: 20_000n,
      ...creation.state,
    };
    const deposit = evaluate({
      profile: 0,
      old,
      next,
      fee: 1_000n,
      edgeData: creation.data,
    });
    const accepted = evaluateRole(deposit, gate, EDGE_ROLE_INPUT);
    assert.equal(deposit.vm.stateSuccess(accepted.state), true, JSON.stringify({
      error: accepted.state.error,
      ip: accepted.state.ip,
      metrics: accepted.state.metrics,
    }));
    console.log("local-word-edge-append-gate", JSON.stringify({
      verifierBytes: gate.length,
      redeemBytes: compileLocalWordCarrierRedeem({ index: EDGE_ROLE_INPUT, verifier: gate }).length,
      unlockingBytes: accepted.transaction.inputs[EDGE_ROLE_INPUT]!.unlockingBytecode.length,
      operationCost: accepted.state.metrics.operationCost,
      maximumOperationCost: accepted.state.metrics.maximumOperationCost,
    }));

    const changedPath = structuredClone(accepted.transaction);
    changedPath.outputs[LOCAL_WORD_DEPOSIT_EDGE_DATA_OUTPUT]!
      .lockingBytecode[LOCAL_WORD_EDGE_PATH_OFFSET + 17] ^= 1;
    const pathRejected = deposit.vm.evaluate({
      inputIndex: EDGE_ROLE_INPUT,
      sourceOutputs: accepted.sourceOutputs,
      transaction: changedPath,
    } as never);
    assert.notEqual(deposit.vm.stateSuccess(pathRejected), true);

    const changedRoot = structuredClone(accepted.transaction);
    const pool = changedRoot.outputs[0]!;
    if (!("token" in pool)) throw new Error("pool token fixture");
    pool.token.nft.commitment[64] ^= 1;
    const rootRejected = deposit.vm.evaluate({
      inputIndex: EDGE_ROLE_INPUT,
      sourceOutputs: accepted.sourceOutputs,
      transaction: changedRoot,
    } as never);
    assert.notEqual(deposit.vm.stateSuccess(rootRejected), true);
  });

  it("accepts only an exact public sparse-nullifier absence-to-used update", () => {
    const roles = [
      { inputIndex: NULLIFIER_ROLE_INPUTS[0], root: "absence", segment: 0 },
      { inputIndex: NULLIFIER_ROLE_INPUTS[1], root: "absence", segment: 1 },
      { inputIndex: NULLIFIER_ROLE_INPUTS[2], root: "used", segment: 0 },
      { inputIndex: NULLIFIER_ROLE_INPUTS[3], root: "used", segment: 1 },
    ] as const;
    const gates = roles.map((role) => ({
      ...role,
      gate: compileLocalWordSparseNullifierGate(role.root, role.segment),
    }));
    assert.equal(gates.every(({ gate }) => gate.length < 10_000), true);

    const depositOld = oldState(0n);
    const depositCreation = appendCreation(depositOld, 0x5e, 0x52);
    const depositNext = {
      ...depositOld,
      sequence: 1n,
      reserveSats: 20_000n,
      ...depositCreation.state,
    };
    const deposit = evaluate({
      profile: 0,
      old: depositOld,
      next: depositNext,
      fee: 1_000n,
      edgeData: depositCreation.data,
    });
    for (const { inputIndex, gate } of gates) {
      const depositRole = evaluateRole(deposit, gate, inputIndex);
      assert.equal(deposit.vm.stateSuccess(depositRole.state), true);
    }

    const old = oldState(20_000n);
    const nullifier = new Uint8Array(32).fill(0x77);
    const inserted = new SparseNullifierTree().insert(nullifier);
    const payout = 8_000n;
    const fee = 1_000n;
    const creation = appendCreation(old, 0x5f, 0x53);
    const next = {
      ...old,
      sequence: 1n,
      reserveSats: old.reserveSats - payout - fee,
      ...creation.state,
      nullifierRoot: inserted.newRoot,
    };
    const withdrawal = evaluate({
      profile: 2,
      old,
      next,
      fee,
      payout,
      nullifierData: encodeLocalWordNullifierData({ nullifier, path: inserted.path }),
      edgeData: creation.data,
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
    const depositCreation = appendCreation(depositOld, 0x5e, 0x52);
    const depositNext = {
      ...depositOld,
      sequence: 1n,
      reserveSats: 20_000n,
      ...depositCreation.state,
    };
    const deposit = evaluate({
      profile: 0,
      old: depositOld,
      next: depositNext,
      fee: 1_000n,
      edgeData: depositCreation.data,
    });
    const depositGate = compileLocalWordTranscriptInitialKatGate({
      constructionId: CONSTRUCTION_ID,
      expectedDigest: transactionTranscriptDigest(deposit),
    });
    const depositRole = evaluateRole(deposit, depositGate, TRANSCRIPT_ROLE_START);
    assert.equal(deposit.vm.stateSuccess(depositRole.state), true, depositRole.state.error);

    const changedReserve = structuredClone(depositRole.transaction);
    changedReserve.outputs[0]!.valueSatoshis += 1n;
    const reserveRejected = deposit.vm.evaluate({
      inputIndex: TRANSCRIPT_ROLE_START,
      sourceOutputs: depositRole.sourceOutputs,
      transaction: changedReserve,
    } as never);
    assert.notEqual(deposit.vm.stateSuccess(reserveRejected), true);

    const old = oldState(20_000n);
    const nullifier = new Uint8Array(32).fill(0x77);
    const inserted = new SparseNullifierTree().insert(nullifier);
    const payout = 8_000n;
    const fee = 1_000n;
    const creation = appendCreation(old, 0x5f, 0x53);
    const next = {
      ...old,
      sequence: 1n,
      reserveSats: old.reserveSats - payout - fee,
      ...creation.state,
      nullifierRoot: inserted.newRoot,
    };
    const withdrawal = evaluate({
      profile: 2,
      old,
      next,
      fee,
      payout,
      nullifierData: encodeLocalWordNullifierData({ nullifier, path: inserted.path }),
      edgeData: creation.data,
    });
    const withdrawalGate = compileLocalWordTranscriptInitialKatGate({
      constructionId: CONSTRUCTION_ID,
      expectedDigest: transactionTranscriptDigest(withdrawal),
    });
    const withdrawalRole = evaluateRole(withdrawal, withdrawalGate, TRANSCRIPT_ROLE_START);
    assert.equal(withdrawal.vm.stateSuccess(withdrawalRole.state), true, withdrawalRole.state.error);
    console.log("local-word-transcript-initial-gates", JSON.stringify([
      { profile: 0, lockingBytes: depositGate.length, operationCost: depositRole.state.metrics.operationCost },
      { profile: 2, lockingBytes: withdrawalGate.length, operationCost: withdrawalRole.state.metrics.operationCost },
    ]));

    const changedPayout = structuredClone(withdrawalRole.transaction);
    changedPayout.outputs[LOCAL_WORD_PAYOUT_OUTPUT]!.lockingBytecode[0] ^= 1;
    const payoutRejected = withdrawal.vm.evaluate({
      inputIndex: TRANSCRIPT_ROLE_START,
      sourceOutputs: withdrawalRole.sourceOutputs,
      transaction: changedPayout,
    } as never);
    assert.notEqual(withdrawal.vm.stateSuccess(payoutRejected), true);

    const changedNullifier = structuredClone(withdrawalRole.transaction);
    changedNullifier.outputs[LOCAL_WORD_NULLIFIER_DATA_OUTPUT]!.lockingBytecode[9] ^= 1;
    const nullifierRejected = withdrawal.vm.evaluate({
      inputIndex: TRANSCRIPT_ROLE_START,
      sourceOutputs: withdrawalRole.sourceOutputs,
      transaction: changedNullifier,
    } as never);
    assert.notEqual(withdrawal.vm.stateSuccess(nullifierRejected), true);
  });

  it("replays every interaction challenge from transaction data and canonical proof roots", () => {
    const old = oldState(0n);
    const creation = appendCreation(old, 0x5e, 0x52);
    const next = {
      ...old,
      sequence: 1n,
      reserveSats: 20_000n,
      ...creation.state,
    };
    const deposit = evaluate({ profile: 0, old, next, fee: 1_000n, edgeData: creation.data });
    const replay = transactionInteraction(deposit, 8);
    const gate = compileLocalWordInteractionTranscriptKatGate({
      constructionId: CONSTRUCTION_ID,
      publicWordCount: 8,
      expectedDigest: replay.transcript.digest,
      boundaryChallenges: replay.challenges.boundary,
    });
    assert.ok(gate.length < 10_000);
    // This standalone KAT gate is larger than the production partitioned
    // transcript role, so use one deliberately wider synthetic carrier.
    const transcriptRole = 45;
    const accepted = evaluateRole(deposit, gate, transcriptRole);
    assert.equal(
      deposit.vm.stateSuccess(accepted.state),
      true,
      JSON.stringify({
        error: accepted.state.error,
        ip: accepted.state.ip,
        stack: accepted.state.stack.map((item) => Buffer.from(item).toString("hex")),
        metrics: accepted.state.metrics,
      }),
    );
    console.log("local-word-interaction-transcript-gate", JSON.stringify({
      lockingBytes: gate.length,
      operationCost: accepted.state.metrics.operationCost,
    }));

    const changedOriginalRoot = structuredClone(accepted.transaction);
    const originalRootOffset = localWordProofStaticOffsets(8).matrixRoots + 32;
    mutateProofByte(changedOriginalRoot, deposit.proof.length, originalRootOffset);
    const rootRejected = deposit.vm.evaluate({
      inputIndex: transcriptRole,
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
    const depositCreation = appendCreation(depositOld, 0x5e, 0x52);
    const depositNext = {
      ...depositOld,
      sequence: 1n,
      reserveSats: 20_000n,
      ...depositCreation.state,
    };
    const depositBase = evaluate({
      profile: 0,
      old: depositOld,
      next: depositNext,
      fee: 1_000n,
      edgeData: depositCreation.data,
    });
    const depositProof = proofWithPublicInverses(depositBase);
    const deposit = evaluate({
      profile: 0,
      old: depositOld,
      next: depositNext,
      fee: 1_000n,
      edgeData: depositCreation.data,
      proof: depositProof,
    });
    const depositInverseCosts: number[] = [];
    for (const [role, publicWordIndex] of Array.from({ length: 8 }, (_, index) => index).entries()) {
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
    const depositSum = evaluateRole(deposit, depositSumGate, BOUNDARY_SUM_ROLE_INPUT);
    assert.equal(deposit.vm.stateSuccess(depositSum.state), true, String(depositSum.state.error));

    const inverseGate = compileLocalWordPublicBoundaryInverseGate({
      profile: 0,
      publicWordIndex: 0,
    });
    const inverseRole = evaluateRole(deposit, inverseGate, 9);
    const changedInverse = structuredClone(inverseRole.transaction);
    mutateProofByte(
      changedInverse,
      deposit.proof.length,
      localWordProofStaticOffsets(8).publicInverses,
    );
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
      localWordProofStaticOffsets(8).publicClaimedSum,
    );
    const sumRejected = deposit.vm.evaluate({
      inputIndex: BOUNDARY_SUM_ROLE_INPUT,
      sourceOutputs: depositSum.sourceOutputs,
      transaction: changedSum,
    } as never);
    assert.notEqual(deposit.vm.stateSuccess(sumRejected), true);

    const old = oldState(20_000n);
    const nullifier = new Uint8Array(32).fill(0x77);
    const inserted = new SparseNullifierTree().insert(nullifier);
    const payout = 8_000n;
    const fee = 1_000n;
    const creation = appendCreation(old, 0x5f, 0x53);
    const next = {
      ...old,
      sequence: 1n,
      reserveSats: old.reserveSats - payout - fee,
      ...creation.state,
      nullifierRoot: inserted.newRoot,
    };
    const withdrawalBase = evaluate({
      profile: 2,
      old,
      next,
      fee,
      payout,
      nullifierData: encodeLocalWordNullifierData({ nullifier, path: inserted.path }),
      edgeData: creation.data,
    });
    const withdrawalProof = proofWithPublicInverses(withdrawalBase);
    const withdrawal = evaluate({
      profile: 2,
      old,
      next,
      fee,
      payout,
      nullifierData: encodeLocalWordNullifierData({ nullifier, path: inserted.path }),
      edgeData: creation.data,
      proof: withdrawalProof,
    });
    const withdrawalInverseCosts: number[] = [];
    for (const [role, publicWordIndex] of Array.from({ length: 8 }, (_, index) => index).entries()) {
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
    const withdrawalSum = evaluateRole(
      withdrawal,
      compileLocalWordPublicBoundarySumGate(2),
      BOUNDARY_SUM_ROLE_INPUT,
    );
    assert.equal(withdrawal.vm.stateSuccess(withdrawalSum.state), true, String(withdrawalSum.state.error));
    const boundaryBatches = [{ start: 0, count: 8 }] as const;
    const batchMeasurements = boundaryBatches.map((batch, role) => {
      const gate = compileLocalWordPublicBoundaryInverseBatchGate({ profile: 2, ...batch });
      const inputIndex = BOUNDARY_ROLE_START + role;
      const checked = evaluateP2shRole(withdrawal, withdrawalProof, gate, inputIndex);
      assert.equal(withdrawal.vm.stateSuccess(checked.state), true, JSON.stringify({ batch, error: checked.state.error }));
      const changed = structuredClone(checked.transaction);
      mutateProofByte(
        changed,
        withdrawalProof.length,
        localWordProofStaticOffsets(8).publicInverses + batch.start * 16,
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
    // This test owns semantic equivalence and adversarial rejection. Exact
    // density acceptance is owned by the final byte-identical BCHN gate.
    const semanticVm = unboundedV17DiagnosticVm();
    const parameters: LocalWordProofParameters = {
      ...LOCAL_WORD_PRODUCTION_PARAMETERS,
      // Pin the exact production PoW branch; zero-bit fixtures missed a mask
      // truncation that rejected valid candidates with a nonzero low nibble.
      fri: { ...LOCAL_WORD_PRODUCTION_PARAMETERS.fri, grindBits: 20 },
    };
    const old = oldState(0n);
    const creation = appendCreation(old, 0x5e, 0x52);
    const next = {
      ...old,
      sequence: 1n,
      reserveSats: 20_000n,
      ...creation.state,
    };
    const base = evaluate({
      profile: 0,
      old,
      next,
      fee: 1_000n,
      edgeData: creation.data,
      proof: proofBytes(0, LOCAL_WORD_CARRIER_MIN_PROOF_BYTES + 256),
    });
    const proof = proofWithPublicInverses(base);
    const offsets = localWordProofTranscriptOffsets(8, parameters);
    const expectedQueries = fillTranscriptManifest(base, proof, 8, parameters);
    const depositWithManifest = evaluate({
      profile: 0,
      old,
      next,
      fee: 1_000n,
      edgeData: creation.data,
      proof,
    });

    const manifestParts = [
      "interaction",
      "composition",
      "batch",
      "fri-first",
      "fri-second",
      "final",
    ] as const;
    const manifestRoleInputs = [38, 39, 40, 41, 42, 43] as const;
    const manifestMeasurements: { part: string; lockingBytes: number; operationCost: number | bigint }[] = [];
    let friFirstRole: ReturnType<typeof evaluateRole> | undefined;
    let friFirstInput = -1;
    for (const [index, part] of manifestParts.entries()) {
      const gate = compileLocalWordTranscriptManifestGate({
        constructionId: CONSTRUCTION_ID,
        publicWordCount: 8,
        part,
        parameters,
      });
      assert.ok(gate.length < 10_000);
      const role = evaluateRole(depositWithManifest, gate, manifestRoleInputs[index]!, semanticVm);
      assert.equal(
        semanticVm.stateSuccess(role.state),
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
      if (part === "fri-first") {
        friFirstRole = role;
        friFirstInput = manifestRoleInputs[index]!;
      }
    }
    console.log("local-word-transcript-manifest-gates", JSON.stringify(manifestMeasurements));
    assert.ok(friFirstRole);
    const changedFriRoot = structuredClone(friFirstRole.transaction);
    mutateProofByte(changedFriRoot, depositWithManifest.proof.length, offsets.friRoots);
    const friRejected = semanticVm.evaluate({
      inputIndex: friFirstInput,
      sourceOutputs: friFirstRole.sourceOutputs,
      transaction: changedFriRoot,
    } as never);
    assert.notEqual(semanticVm.stateSuccess(friRejected), true);

    const actualGate = compileLocalWordQueryScheduleGate({
      publicWordCount: 8,
      parameters,
    });
    assert.ok(actualGate.length < 10_000);
    const queryRole = QUERY_SCHEDULE_ROLE_INPUT;
    const actual = evaluateRole(depositWithManifest, actualGate, queryRole, semanticVm);
    assert.equal(
      semanticVm.stateSuccess(actual.state),
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
      publicWordCount: 8,
      parameters,
      expectedQueries,
    });
    const kat = evaluateRole(depositWithManifest, katGate, queryRole, semanticVm);
    assert.equal(
      semanticVm.stateSuccess(kat.state),
      true,
      JSON.stringify({ error: kat.state.error, ip: kat.state.ip, metrics: kat.state.metrics }),
    );

    const changedTranscript = structuredClone(kat.transaction);
    mutateProofByte(changedTranscript, depositWithManifest.proof.length, offsets.queryDigest);
    const rejected = semanticVm.evaluate({
      inputIndex: queryRole,
      sourceOutputs: kat.sourceOutputs,
      transaction: changedTranscript,
    } as never);
    assert.notEqual(semanticVm.stateSuccess(rejected), true);

    for (const queryIndex of [0, 22, 43]) {
      const changedQuery = structuredClone(kat.transaction);
      mutateProofByte(
        changedQuery,
        depositWithManifest.proof.length,
        offsets.queries + queryIndex * 4 + 2,
      );
      const queryRejected = semanticVm.evaluate({
        inputIndex: queryRole,
        sourceOutputs: kat.sourceOutputs,
        transaction: changedQuery,
      } as never);
      assert.notEqual(
        semanticVm.stateSuccess(queryRejected),
        true,
        `query ${queryIndex} mutation must be rejected`,
      );
    }

    // Cross-language KAT whose 23rd representative must advance one place
    // inside its already-selected orbit to avoid a predecessor collision.
    const scanTranscript = new SuccessorTranscript(writeU32LE(12_701));
    const scanSamples = localWordQuerySamples(scanTranscript, parameters);
    assert.equal(scanSamples[22]!.scan, 1);
    const scanProof = new Uint8Array(proof);
    scanProof.set(scanTranscript.digest, offsets.queryDigest);
    scanSamples.forEach(({ query }, index) =>
      scanProof.set(writeU32BE(query), offsets.queries + index * 4));
    const scanFixture = evaluate({
      profile: 0,
      old,
      next,
      fee: 1_000n,
      edgeData: creation.data,
      proof: scanProof,
    });
    const scanRole = evaluateRole(scanFixture, actualGate, queryRole, semanticVm);
    assert.equal(
      semanticVm.stateSuccess(scanRole.state),
      true,
      JSON.stringify({ error: scanRole.state.error, ip: scanRole.state.ip, metrics: scanRole.state.metrics }),
    );

    const changedScannedQuery = structuredClone(scanRole.transaction);
    mutateProofByte(
      changedScannedQuery,
      scanFixture.proof.length,
      offsets.queries + 22 * 4 + 3,
    );
    const scanRejected = semanticVm.evaluate({
      inputIndex: queryRole,
      sourceOutputs: scanRole.sourceOutputs,
      transaction: changedScannedQuery,
    } as never);
    assert.notEqual(semanticVm.stateSuccess(scanRejected), true);
  });

  it("replays the generated v17 transcript in six CashVM roles for all profiles", () => {
    const parts = [
      "interaction", "composition", "batch", "fri-first", "fri-second", "final",
    ] as const;
    const roleInputs = [38, 39, 40, 41, 42, 43] as const;
    const mutationOffsets = [
      v17ProofFrameOffset("interactionChallenges"),
      v17ProofFrameOffset("roundNonce:air:composition"),
      v17ProofFrameOffset("batchBeta"),
      v17ProofFrameOffset("friAlpha:2:1"),
      v17ProofFrameOffset("friRoot:7"),
      v17ProofFrameOffset("finalCoefficients"),
    ] as const;
    const measurements: {
      readonly profile: number;
      readonly part: string;
      readonly lockingBytes: number;
      readonly redeemBytes: number;
      readonly unlockingBytes: number;
      readonly operationCost: number;
      readonly maximumOperationCost: number;
      readonly maximumStackDepth: number;
      readonly maximumStackItemBytes: number;
    }[] = [];
    const fixtureArgs = (profile: 0 | 1 | 2): Parameters<typeof evaluate>[0] => {
      if (profile === 0) {
        const old = oldState(0n);
        const creation = appendCreation(old, 0x5e, 0x52);
        return {
          profile,
          old,
          next: { ...old, sequence: 1n, reserveSats: 20_000n, ...creation.state },
          fee: 1_000n,
          edgeData: creation.data,
        };
      }
      const old = oldState(20_000n);
      const nullifier = new Uint8Array(32).fill(0x70 + profile);
      const inserted = new SparseNullifierTree().insert(nullifier);
      if (profile === 1) {
        return {
          profile,
          old,
          next: { ...old, sequence: 1n, reserveSats: 0n, nullifierRoot: inserted.newRoot },
          fee: 1_000n,
          payout: 19_000n,
          nullifierData: encodeLocalWordNullifierData({ nullifier, path: inserted.path }),
        };
      }
      const creation = appendCreation(old, 0x5f, 0x53);
      return {
        profile,
        old,
        next: {
          ...old,
          sequence: 1n,
          reserveSats: 11_000n,
          nullifierRoot: inserted.newRoot,
          ...creation.state,
        },
        fee: 1_000n,
        payout: 8_000n,
        nullifierData: encodeLocalWordNullifierData({ nullifier, path: inserted.path }),
        edgeData: creation.data,
      };
    };

    for (const profile of [0, 1, 2] as const) {
      const args = fixtureArgs(profile);
      const base = evaluate(args);
      const proof = proofBytes(profile);
      const kat = fillV17TranscriptKat(base, proof);
      const fixture = evaluate({ ...args, proof });
      assert.deepEqual(kat.nonces, V17_TRANSCRIPT_KATS[profile].nonces);
      assert.equal(Buffer.from(kat.queryDigest).toString("hex"),
        V17_TRANSCRIPT_KATS[profile].queryDigest);
      assert.deepEqual(kat.queryDigest, proof.slice(
        v17ProofFrameOffset("queryDigest"),
        v17ProofFrameOffset("queryDigest") + 32,
      ));

      for (const [index, part] of parts.entries()) {
        const productionGate = compileLocalWordTranscriptManifestGate({
          constructionId: V17_PROOF_PROTOCOL_ID,
          publicWordCount: 8,
          part,
        });
        const gate = compileV17LocalWordTranscriptManifestKatGate({
          part,
          roundGrinding: V17_TRANSCRIPT_KAT_GRINDING,
        });
        const inputIndex = roleInputs[index]!;
        const redeem = compileLocalWordCarrierRedeem({ index: inputIndex, verifier: gate });
        const role = evaluateRole(fixture, gate, inputIndex);
        assert.equal(fixture.vm.stateSuccess(role.state), true, JSON.stringify({
          profile,
          part,
          error: role.state.error,
          ip: role.state.ip,
          metrics: role.state.metrics,
          stack: role.state.stack.map((item) => Buffer.from(item).toString("hex")),
        }));
        assert.ok(productionGate.length <= 10_000);
        assert.ok(gate.length <= 10_000);
        assert.ok(redeem.length <= 10_000);
        assert.ok(role.transaction.inputs[inputIndex]!.unlockingBytecode.length <= 10_000);
        assert.ok(Number(role.state.metrics.operationCost) <=
          Number(role.state.metrics.maximumOperationCost));

        const trace = fixture.vm.debug({
          inputIndex,
          sourceOutputs: role.sourceOutputs,
          transaction: role.transaction,
        } as never, { maskProgramState: true });
        const maximumStackDepth = trace.reduce((maximum, state) =>
          Math.max(maximum, state.stack.length + state.alternateStack.length), 0);
        const maximumStackItemBytes = trace.reduce((maximum, state) =>
          [...state.stack, ...state.alternateStack].reduce(
            (itemMaximum, item) => Math.max(itemMaximum, item.length),
            maximum,
          ), 0);
        assert.ok(maximumStackDepth <= 1_000);
        assert.ok(maximumStackItemBytes <= 10_000);
        measurements.push({
          profile,
          part,
          lockingBytes: gate.length,
          redeemBytes: redeem.length,
          unlockingBytes: role.transaction.inputs[inputIndex]!.unlockingBytecode.length,
          operationCost: Number(role.state.metrics.operationCost),
          maximumOperationCost: Number(role.state.metrics.maximumOperationCost),
          maximumStackDepth,
          maximumStackItemBytes,
        });

        const changed = structuredClone(role.transaction);
        mutateProofByte(changed, proof.length, mutationOffsets[index]!);
        const rejected = fixture.vm.evaluate({
          inputIndex,
          sourceOutputs: role.sourceOutputs,
          transaction: changed,
        } as never);
        assert.notEqual(fixture.vm.stateSuccess(rejected), true,
          `v17 transcript mutation ${profile}:${part}`);
      }

      // No transcript role consumes terminal codec-only bytes, and no
      // challenge follows them. Their strict validation belongs to framing.
      const finalGate = compileV17LocalWordTranscriptManifestKatGate({
        part: "final",
        roundGrinding: V17_TRANSCRIPT_KAT_GRINDING,
      });
      const finalRole = evaluateRole(fixture, finalGate, roleInputs[5]);
      for (const terminalOffset of [
        v17ProofFrameOffset("totalLength"),
        v17ProofFrameOffset("openingDirectory"),
        localWordProofStaticOffsets(8).openingBodies,
      ]) {
        const changed = structuredClone(finalRole.transaction);
        mutateProofByte(changed, proof.length, terminalOffset);
        const accepted = fixture.vm.evaluate({
          inputIndex: roleInputs[5],
          sourceOutputs: finalRole.sourceOutputs,
          transaction: changed,
        } as never);
        assert.equal(fixture.vm.stateSuccess(accepted), true,
          `v17 terminal codec separation ${profile}:${terminalOffset}`);
      }
      console.log("v17-cashvm-transcript-kat", JSON.stringify({
        profile,
        nonces: kat.nonces,
        queryDigest: Buffer.from(kat.queryDigest).toString("hex"),
      }));
    }
    console.log("v17-cashvm-transcript-gates", JSON.stringify(measurements));
  });
});

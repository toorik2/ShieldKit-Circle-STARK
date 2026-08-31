import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  LOCAL_WORD_CARRIER_INPUTS,
  localWordP2sh32Lock,
  localWordVerifierBankDigestFromInputs,
  localWordVerifierCarrierSequence,
  localWordVerifierCarrierValue,
  type LocalWordVerifierBankDigests,
} from "../src/chain/local-word-proof-carriers.ts";
import {
  LOCAL_WORD_CHANGE_EDGE_DATA_OUTPUT,
  LOCAL_WORD_EDGE_PATH_OFFSET,
  LOCAL_WORD_NULLIFIER_DATA_OUTPUT,
  LOCAL_WORD_NULLIFIER_PATH_OFFSET,
  deriveLocalWordPublicSettlement,
  encodeLocalWordEdgeData,
  encodeLocalWordNullifierData,
  type LocalWordEnvelopeView,
  type LocalWordSourceOutput,
} from "../src/chain/local-word-envelope.ts";
import { LAB_PAYOUT_LOCKING } from "../src/chain/payout.ts";
import { EdgeHistory } from "../src/pool/edge-history.ts";
import { SparseNullifierTree, emptySparseNullifierRoot } from "../src/pool/sparse-nullifiers.ts";
import { emptyState, encodePublicPaa2, STATE_BASE_SATS, type AnyAmountState } from "../src/pool/state.ts";

const POOL_LOCK = Uint8Array.of(0x51);
const CATEGORY = new Uint8Array(32).fill(0x42);

function poolOutput(state: AnyAmountState): LocalWordSourceOutput {
  return {
    lockingBytecode: POOL_LOCK,
    valueSatoshis: STATE_BASE_SATS + state.reserveSats,
    token: {
      category: CATEGORY,
      amount: 0n,
      nft: { capability: "mutable", commitment: encodePublicPaa2(state) },
    },
  };
}

function carrier(index: number): LocalWordSourceOutput {
  return {
    lockingBytecode: localWordP2sh32Lock(Uint8Array.of(0x51, index & 0xff, index >>> 8)),
    valueSatoshis: localWordVerifierCarrierValue(index),
  };
}

function bankDigests(view: LocalWordEnvelopeView): LocalWordVerifierBankDigests {
  const inputs = view.sourceOutputs.slice(1, LOCAL_WORD_CARRIER_INPUTS).map((output, local) => ({
      lockingBytecode: output.lockingBytecode,
      valueSatoshis: output.valueSatoshis,
      sequenceNumber: view.inputSequenceNumbers[local + 1]!,
    }));
  return [0, 1, 2].map((profile) => localWordVerifierBankDigestFromInputs(
    profile as 0 | 1 | 2, inputs,
  )) as unknown as LocalWordVerifierBankDigests;
}

function inputSequenceNumbers(inputCount: number): number[] {
  return Array.from({ length: inputCount }, (_, index) =>
    index > 0 && index < LOCAL_WORD_CARRIER_INPUTS
      ? localWordVerifierCarrierSequence(index)
      : 0xffff_ffff);
}

function carrierSources(pool: AnyAmountState): LocalWordSourceOutput[] {
  return [poolOutput(pool), ...Array.from({ length: LOCAL_WORD_CARRIER_INPUTS - 1 }, (_, index) => carrier(index + 1))];
}

function carrierOutputs(pool: AnyAmountState): LocalWordSourceOutput[] {
  return [poolOutput(pool), ...Array.from({ length: LOCAL_WORD_CARRIER_INPUTS - 1 }, (_, index) => carrier(index + 1))];
}

function oldState(reserveSats: bigint): AnyAmountState {
  return {
    ...emptyState(),
    reserveSats,
    nullifierRoot: emptySparseNullifierRoot(),
  };
}

describe("local-word one-transaction envelope reference", () => {
  it("derives a deposit whose transparent funding input pays deposit plus fee", () => {
    const old = oldState(0n);
    const deposited = 20_000n;
    const fee = 1_000n;
    const edge = new Uint8Array(32).fill(0x5e);
    const edgeHistory = new EdgeHistory();
    const appended = edgeHistory.append(edge);
    const next: AnyAmountState = {
      ...old,
      sequence: 1n,
      reserveSats: deposited,
      creationCount: 1n,
      creationHead: new Uint8Array(32).fill(0x52),
      edgeHistoryRoot: appended.newRoot,
    };
    const view: LocalWordEnvelopeView = {
      sourceOutputs: [
        ...carrierSources(old),
        { lockingBytecode: Uint8Array.of(0x76), valueSatoshis: deposited + fee },
      ],
      inputSequenceNumbers: inputSequenceNumbers(LOCAL_WORD_CARRIER_INPUTS + 1),
      outputs: [
        ...carrierOutputs(next),
        {
          lockingBytecode: encodeLocalWordEdgeData({
            creationIndex: appended.index,
            edge,
            path: appended.path,
          }),
          valueSatoshis: 0n,
        },
      ],
    };
    const settlement = deriveLocalWordPublicSettlement(view, bankDigests(view));
    assert.equal(settlement.profile, "deposit");
    assert.equal(settlement.statement.publicAmountSats, deposited);
    assert.equal(settlement.minerFeeSats, fee);
    assert.deepEqual(settlement.statement.createdEdge, edge);
    assert.deepEqual(settlement.statement.poolCategory, CATEGORY);
  });

  it("derives one withdrawal whose note funds payout plus miner fee", () => {
    const old = oldState(20_000n);
    const nullifier = new Uint8Array(32).fill(0x77);
    const sparse = new SparseNullifierTree();
    assert.deepEqual(sparse.root, old.nullifierRoot);
    const inserted = sparse.insert(nullifier);
    const payout = 8_000n;
    const fee = 1_000n;
    const edge = new Uint8Array(32).fill(0x5f);
    const edgeHistory = new EdgeHistory();
    const appended = edgeHistory.append(edge);
    const next: AnyAmountState = {
      ...old,
      sequence: 1n,
      reserveSats: old.reserveSats - payout - fee,
      creationCount: 1n,
      creationHead: new Uint8Array(32).fill(0x53),
      edgeHistoryRoot: appended.newRoot,
      nullifierRoot: inserted.newRoot,
    };
    const view: LocalWordEnvelopeView = {
      sourceOutputs: carrierSources(old),
      inputSequenceNumbers: inputSequenceNumbers(LOCAL_WORD_CARRIER_INPUTS),
      outputs: [
        ...carrierOutputs(next),
        { lockingBytecode: LAB_PAYOUT_LOCKING, valueSatoshis: payout },
        { lockingBytecode: encodeLocalWordNullifierData({ nullifier, path: inserted.path }), valueSatoshis: 0n },
        {
          lockingBytecode: encodeLocalWordEdgeData({
            creationIndex: appended.index,
            edge,
            path: appended.path,
          }),
          valueSatoshis: 0n,
        },
      ],
    };
    const authorized = bankDigests(view);
    const settlement = deriveLocalWordPublicSettlement(view, authorized);
    assert.equal(settlement.profile, "withdraw-change");
    assert.equal(settlement.statement.publicAmountSats, -(payout + fee));
    assert.equal(settlement.minerFeeSats, fee);
    assert.deepEqual(settlement.statement.nullifier, nullifier);

    const changedCarrier: LocalWordEnvelopeView = {
      ...view,
      outputs: view.outputs.map((output, index) => index === 5
        ? { ...output, valueSatoshis: output.valueSatoshis + 1n }
        : output),
    };
    assert.throws(() => deriveLocalWordPublicSettlement(changedCarrier, authorized), /value neutrality/);

    const changedPath = structuredClone(view);
    changedPath.outputs[LOCAL_WORD_NULLIFIER_DATA_OUTPUT]!.lockingBytecode[LOCAL_WORD_NULLIFIER_PATH_OFFSET + 17] ^= 1;
    assert.throws(() => deriveLocalWordPublicSettlement(changedPath, authorized), /nullifier/);

    const changedEdgePath = structuredClone(view);
    changedEdgePath.outputs[LOCAL_WORD_CHANGE_EDGE_DATA_OUTPUT]!
      .lockingBytecode[LOCAL_WORD_EDGE_PATH_OFFSET + 17] ^= 1;
    assert.throws(() => deriveLocalWordPublicSettlement(changedEdgePath, authorized), /edge append/);

    const changedPayout: LocalWordEnvelopeView = {
      ...view,
      outputs: view.outputs.map((output, index) => index === LOCAL_WORD_CARRIER_INPUTS
        ? { ...output, valueSatoshis: output.valueSatoshis + 1n }
        : output),
    };
    const changedSettlement = deriveLocalWordPublicSettlement(changedPayout, authorized);
    assert.equal(changedSettlement.minerFeeSats, fee - 1n);
    assert.equal(changedSettlement.statement.publicAmountSats, settlement.statement.publicAmountSats);

    const attackerLock = localWordP2sh32Lock(Uint8Array.of(0x51));
    const substituted: LocalWordEnvelopeView = {
      ...view,
      sourceOutputs: view.sourceOutputs.map((output, index) =>
        index === 5 ? { ...output, lockingBytecode: attackerLock } : output),
      outputs: view.outputs.map((output, index) =>
        index === 5 ? { ...output, lockingBytecode: attackerLock } : output),
    };
    assert.throws(() => deriveLocalWordPublicSettlement(substituted, authorized), /unauthorized verifier bank/);

    const changedValue: LocalWordEnvelopeView = {
      ...view,
      sourceOutputs: view.sourceOutputs.map((output, index) => index === 5
        ? { ...output, valueSatoshis: output.valueSatoshis + 1n }
        : output),
      outputs: view.outputs.map((output, index) => index === 5
        ? { ...output, valueSatoshis: output.valueSatoshis + 1n }
        : output),
    };
    assert.throws(() => deriveLocalWordPublicSettlement(changedValue, authorized),
      /unauthorized verifier bank/);

    const changedSequence: LocalWordEnvelopeView = {
      ...view,
      inputSequenceNumbers: view.inputSequenceNumbers.map((sequence, index) =>
        index === 5 ? sequence + 1 : sequence),
    };
    assert.throws(() => deriveLocalWordPublicSettlement(changedSequence, authorized),
      /unauthorized verifier bank/);
  });

  it("keeps the creation log exactly unchanged on a full withdrawal", () => {
    const old = oldState(20_000n);
    const nullifier = new Uint8Array(32).fill(0x78);
    const inserted = new SparseNullifierTree().insert(nullifier);
    const payout = 19_000n;
    const fee = 1_000n;
    const next: AnyAmountState = {
      ...old,
      sequence: 1n,
      reserveSats: 0n,
      nullifierRoot: inserted.newRoot,
    };
    const view: LocalWordEnvelopeView = {
      sourceOutputs: carrierSources(old),
      inputSequenceNumbers: inputSequenceNumbers(LOCAL_WORD_CARRIER_INPUTS),
      outputs: [
        ...carrierOutputs(next),
        { lockingBytecode: LAB_PAYOUT_LOCKING, valueSatoshis: payout },
        {
          lockingBytecode: encodeLocalWordNullifierData({ nullifier, path: inserted.path }),
          valueSatoshis: 0n,
        },
      ],
    };
    const settlement = deriveLocalWordPublicSettlement(view, bankDigests(view));
    assert.equal(settlement.profile, "withdraw-full");
    assert.deepEqual(settlement.statement.createdEdge, new Uint8Array(32));
    assert.deepEqual(settlement.edgePath, []);
    assert.equal(settlement.minerFeeSats, fee);
  });
});

import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  LOCAL_WORD_CARRIER_INPUTS,
  localWordP2sh32Lock,
  localWordVerifierBankDigestFromLockingBytecodes,
  type LocalWordVerifierBankDigests,
} from "../src/chain/local-word-proof-carriers.ts";
import {
  LOCAL_WORD_NULLIFIER_DATA_OUTPUT,
  LOCAL_WORD_NULLIFIER_PATH_OFFSET,
  deriveLocalWordPublicSettlement,
  encodeLocalWordNullifierData,
  type LocalWordEnvelopeView,
  type LocalWordSourceOutput,
} from "../src/chain/local-word-envelope.ts";
import { LAB_PAYOUT_LOCKING } from "../src/chain/payout.ts";
import { SparseNullifierTree, emptySparseNullifierRoot } from "../src/pool/sparse-nullifiers.ts";
import { emptyState, encodePublicPaa1, STATE_BASE_SATS, type AnyAmountState } from "../src/pool/state.ts";

const POOL_LOCK = Uint8Array.of(0x51);
const CATEGORY = new Uint8Array(32).fill(0x42);

function poolOutput(state: AnyAmountState): LocalWordSourceOutput {
  return {
    lockingBytecode: POOL_LOCK,
    valueSatoshis: STATE_BASE_SATS + state.reserveSats,
    token: {
      category: CATEGORY,
      amount: 0n,
      nft: { capability: "mutable", commitment: encodePublicPaa1(state) },
    },
  };
}

function carrier(index: number): LocalWordSourceOutput {
  return {
    lockingBytecode: localWordP2sh32Lock(Uint8Array.of(0x51, index & 0xff, index >>> 8)),
    valueSatoshis: 1_000n,
  };
}

function bankDigests(view: LocalWordEnvelopeView): LocalWordVerifierBankDigests {
  const digest = localWordVerifierBankDigestFromLockingBytecodes(
    view.sourceOutputs.slice(1, LOCAL_WORD_CARRIER_INPUTS).map((output) => output.lockingBytecode),
  );
  return [digest, digest, digest];
}

function carrierSources(pool: AnyAmountState): LocalWordSourceOutput[] {
  return [poolOutput(pool), ...Array.from({ length: LOCAL_WORD_CARRIER_INPUTS - 1 }, (_, index) => carrier(index + 1))];
}

function carrierOutputs(pool: AnyAmountState): LocalWordSourceOutput[] {
  return [poolOutput(pool), ...Array.from({ length: LOCAL_WORD_CARRIER_INPUTS - 1 }, (_, index) => carrier(index + 1))];
}

function oldState(reserveSats: bigint): AnyAmountState {
  return {
    ...emptyState(new Uint8Array(32).fill(0x31)),
    reserveSats,
    nullifierRoot: emptySparseNullifierRoot(),
  };
}

describe("local-word one-transaction envelope reference", () => {
  it("derives a deposit whose transparent funding input pays deposit plus fee", () => {
    const old = oldState(0n);
    const deposited = 20_000n;
    const fee = 1_000n;
    const next: AnyAmountState = {
      ...old,
      sequence: 1n,
      reserveSats: deposited,
      depositCount: 1n,
      noteRoot: new Uint8Array(32).fill(0x52),
    };
    const view: LocalWordEnvelopeView = {
      sourceOutputs: [
        ...carrierSources(old),
        { lockingBytecode: Uint8Array.of(0x76), valueSatoshis: deposited + fee },
      ],
      outputs: carrierOutputs(next),
    };
    const settlement = deriveLocalWordPublicSettlement(view, bankDigests(view));
    assert.equal(settlement.profile, "deposit");
    assert.equal(settlement.statement.publicAmountSats, deposited);
    assert.equal(settlement.minerFeeSats, fee);
    assert.deepEqual(settlement.statement.noteCommitment, new Uint8Array(32));
  });

  it("derives one withdrawal whose note funds payout plus miner fee", () => {
    const old = oldState(20_000n);
    const nullifier = new Uint8Array(32).fill(0x77);
    const sparse = new SparseNullifierTree();
    assert.deepEqual(sparse.root, old.nullifierRoot);
    const inserted = sparse.insert(nullifier);
    const payout = 8_000n;
    const fee = 1_000n;
    const next: AnyAmountState = {
      ...old,
      sequence: 1n,
      reserveSats: old.reserveSats - payout - fee,
      withdrawalCount: 1n,
      noteRoot: new Uint8Array(32).fill(0x53),
      nullifierRoot: inserted.newRoot,
    };
    const view: LocalWordEnvelopeView = {
      sourceOutputs: carrierSources(old),
      outputs: [
        ...carrierOutputs(next),
        { lockingBytecode: LAB_PAYOUT_LOCKING, valueSatoshis: payout },
        { lockingBytecode: encodeLocalWordNullifierData({ nullifier, path: inserted.path }), valueSatoshis: 0n },
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
  });
});

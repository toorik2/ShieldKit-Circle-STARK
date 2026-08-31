import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import {
  binToHex,
  decodeTransaction,
  decodeTransactionOutputs,
  type Output,
} from "@bitauth/libauth";
import {
  encodeLocalWordEdgeData,
  encodeLocalWordNullifierData,
  deriveLocalWordPublicSettlement,
} from "../src/chain/local-word-envelope.ts";
import {
  LOCAL_WORD_CARRIER_INPUTS,
} from "../src/chain/local-word-proof-carriers.ts";
import {
  V17_SETTLEMENT_FUNDING_SEQUENCE,
  materializeV17SettlementTransaction,
  writeV17SettlementTransactionFiles,
  type V17PublicSettlementFixture,
} from "../src/construction/v17-settlement-transaction.ts";
import type {
  V17FinalInfrastructureSet,
  V17FinalProfileInfrastructure,
} from "../src/construction/v17-product-link.ts";
import type { V17Profile } from "../src/construction/v17-graph.ts";
import { EdgeHistory } from "../src/pool/edge-history.ts";
import { hashPayoutLocking } from "../src/chain/payout.ts";
import { emptyState, type AnyAmountState } from "../src/pool/state.ts";
import { SparseNullifierTree } from "../src/pool/sparse-nullifiers.ts";
import { fakeV17FinalInfrastructureSet } from
  "./helpers/v17-final-infrastructure-fixture.ts";

const CATEGORY = Uint8Array.from({ length: 32 }, (_, index) => index + 1);
const PAYOUT_LOCK = Uint8Array.of(0x51);
const ROM_PAGES = 2;

function fakeInfrastructureSet(): V17FinalInfrastructureSet {
  return fakeV17FinalInfrastructureSet();
}

function oldState(sequence: bigint, reserveSats = 100_000n): AnyAmountState {
  return { ...emptyState(), sequence, reserveSats };
}

function fixture(profile: V17Profile): V17PublicSettlementFixture {
  const old = oldState(20n + BigInt(profile));
  if (profile === 0) {
    const edge = new Uint8Array(32).fill(0x41);
    const append = new EdgeHistory().append(edge);
    const next: AnyAmountState = {
      ...old,
      sequence: old.sequence + 1n,
      reserveSats: old.reserveSats + 8_000n,
      creationCount: 1n,
      creationHead: new Uint8Array(32).fill(0x42),
      edgeHistoryRoot: append.newRoot,
    };
    return {
      profile,
      minerFeeSatoshis: 300n,
      statement: {
        profile: "sealed-creation-log-v1",
        action: "DEPOSIT",
        publicAmountSats: 8_000n,
        poolCategory: CATEGORY,
        oldState: old,
        newState: next,
        createdEdge: edge,
        nullifier: new Uint8Array(32),
        payoutLockingDigest: new Uint8Array(32),
      },
      edgeDataLockingBytecode: encodeLocalWordEdgeData({
        creationIndex: append.index,
        edge,
        path: append.path,
      }),
      funding: {
        lockingBytecode: Uint8Array.of(0x51),
        unlockingBytecode: new Uint8Array(),
      },
    };
  }

  const nullifier = new Uint8Array(32).fill(0x50 + profile);
  const insertion = new SparseNullifierTree().insert(nullifier);
  const withdrawSats = profile === 1 ? 7_000n : 9_000n;
  const common = {
    profile,
    minerFeeSatoshis: 250n,
    nullifierDataLockingBytecode: encodeLocalWordNullifierData({
      nullifier,
      path: insertion.path,
    }),
    payoutLockingBytecode: PAYOUT_LOCK,
  } as const;
  if (profile === 1) {
    return {
      ...common,
      profile,
      statement: {
        profile: "sealed-creation-log-v1",
        action: "WITHDRAW",
        publicAmountSats: -withdrawSats,
        poolCategory: CATEGORY,
        oldState: old,
        newState: {
          ...old,
          sequence: old.sequence + 1n,
          reserveSats: old.reserveSats - withdrawSats,
          nullifierRoot: insertion.newRoot,
        },
        createdEdge: new Uint8Array(32),
        nullifier,
        payoutLockingDigest: hashPayoutLocking(PAYOUT_LOCK),
      },
    };
  }

  const edge = new Uint8Array(32).fill(0x61);
  const append = new EdgeHistory().append(edge);
  return {
    ...common,
    profile,
    statement: {
      profile: "sealed-creation-log-v1",
      action: "WITHDRAW",
      publicAmountSats: -withdrawSats,
      poolCategory: CATEGORY,
      oldState: old,
      newState: {
        ...old,
        sequence: old.sequence + 1n,
        reserveSats: old.reserveSats - withdrawSats,
        creationCount: 1n,
        creationHead: new Uint8Array(32).fill(0x62),
        edgeHistoryRoot: append.newRoot,
        nullifierRoot: insertion.newRoot,
      },
      createdEdge: edge,
      nullifier,
      payoutLockingDigest: hashPayoutLocking(PAYOUT_LOCK),
    },
    edgeDataLockingBytecode: encodeLocalWordEdgeData({
      creationIndex: append.index,
      edge,
      path: append.path,
    }),
  };
}

function outputSame(left: Output, right: Output): boolean {
  return left.valueSatoshis === right.valueSatoshis &&
    left.lockingBytecode.length === right.lockingBytecode.length &&
    left.lockingBytecode.every((byte, index) => byte === right.lockingBytecode[index]) &&
    left.token === undefined && right.token === undefined;
}

describe("v17 exact settlement transaction materializer", () => {
  it("materializes all profiles with proof roles and dynamic ROM pages before the public suffix", () => {
    const set = fakeInfrastructureSet();
    for (const profile of [0, 1, 2] as const) {
      const product = materializeV17SettlementTransaction({
        infrastructureSet: set,
        fixture: fixture(profile),
      });
      const infrastructureInputs = LOCAL_WORD_CARRIER_INPUTS + ROM_PAGES;
      assert.equal(product.profile, profile);
      assert.equal(product.infrastructureInputCount, infrastructureInputs);
      assert.equal(product.transaction.inputs.length, infrastructureInputs + (profile === 0 ? 1 : 0));
      assert.equal(product.transaction.outputs.length, infrastructureInputs + (profile === 0 ? 1 : profile === 1 ? 2 : 3));
      assert.equal(product.sourceOutputs.length, product.transaction.inputs.length);
      assert.equal(product.rawTransactionBytes.length <= 1_000_000, true);
      assert.equal(product.transaction.inputs.every((input) => input.unlockingBytecode.length <= 10_000), true);
      assert.equal([...product.sourceOutputs, ...product.transaction.outputs]
        .every((output) => output.lockingBytecode.length <= 10_000), true);
      assert.equal(typeof decodeTransaction(product.rawTransactionBytes), "object");
      assert.equal(typeof decodeTransactionOutputs(product.encodedSourceOutputsBytes), "object");
      assert.equal(product.replay.minerFeeSats, fixture(profile).minerFeeSatoshis);
      assert.equal(product.sourceOutputs[0]!.token?.nft?.capability, "mutable");
      assert.equal(product.transaction.outputs[0]!.token?.nft?.capability, "mutable");
      assert.equal(product.sourceOutputs.slice(1, infrastructureInputs)
        .every((output) => output.token === undefined), true);
      assert.equal(product.transaction.outputs.slice(1, infrastructureInputs)
        .every((output) => output.token === undefined), true);

      for (let index = 1; index < infrastructureInputs; index += 1) {
        assert.equal(outputSame(product.sourceOutputs[index]!, product.transaction.outputs[index]!), true);
      }
      set.profiles[profile].pages.forEach((page) => {
        assert.equal(page.inputIndex >= LOCAL_WORD_CARRIER_INPUTS, true);
        assert.deepEqual(product.sourceOutputs[page.inputIndex]!.lockingBytecode, page.lockingBytecode);
        assert.deepEqual(product.transaction.outputs[page.outputIndex]!.lockingBytecode, page.lockingBytecode);
      });
      assert.equal(product.transaction.inputs[0]!.sequenceNumber,
        set.profiles[profile].infrastructure[0]!.sequenceNumber);
      if (profile === 0) {
        assert.equal(product.transaction.inputs.at(-1)!.sequenceNumber, V17_SETTLEMENT_FUNDING_SEQUENCE);
      }

      const duplicate = materializeV17SettlementTransaction({
        infrastructureSet: set,
        fixture: fixture(profile),
      });
      assert.deepEqual(duplicate.rawTransactionBytes, product.rawTransactionBytes);
      assert.equal(new Set(product.transaction.inputs.map((input) =>
        `${binToHex(input.outpointTransactionHash)}:${input.outpointIndex}`)).size,
      product.transaction.inputs.length);
    }
  });

  it("writes exactly the already-materialized transaction and source-output bytes", () => {
    const product = materializeV17SettlementTransaction({
      infrastructureSet: fakeInfrastructureSet(),
      fixture: fixture(0),
    });
    const directory = mkdtempSync(join(tmpdir(), "shieldkit-v17-settlement-"));
    try {
      const transactionPath = join(directory, "transaction.bin");
      const sourceOutputsPath = join(directory, "source-outputs.bin");
      const files = writeV17SettlementTransactionFiles(product, {
        transactionPath,
        sourceOutputsPath,
      });
      assert.deepEqual(new Uint8Array(readFileSync(transactionPath)), product.rawTransactionBytes);
      assert.deepEqual(new Uint8Array(readFileSync(sourceOutputsPath)), product.encodedSourceOutputsBytes);
      assert.equal(files.transactionSha256Hex, product.transactionSha256Hex);
      assert.equal(files.sourceOutputsSha256Hex, product.sourceOutputsSha256Hex);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it("rejects infrastructure, ROM, public-data, and post-materialization sequence mutations", () => {
    const set = fakeInfrastructureSet();
    const changedSequence = structuredClone(set) as V17FinalInfrastructureSet;
    const profileZero = changedSequence.profiles[0];
    const mutatedInfrastructure = [...profileZero.infrastructure];
    mutatedInfrastructure[1] = {
      ...mutatedInfrastructure[1]!,
      sequenceNumber: mutatedInfrastructure[1]!.sequenceNumber + 1,
    };
    (changedSequence.profiles as unknown as V17FinalProfileInfrastructure[])[0] = {
      ...profileZero,
      infrastructure: mutatedInfrastructure,
    };
    assert.throws(() => materializeV17SettlementTransaction({
      infrastructureSet: changedSequence,
      fixture: fixture(0),
    }), /proof infrastructure/);

    const changedRom = structuredClone(set) as V17FinalInfrastructureSet;
    const romProfile = changedRom.profiles[1];
    const changedPages = [...romProfile.pages];
    changedPages[0] = { ...changedPages[0]!, pageIndex: 9 };
    (changedRom.profiles as unknown as V17FinalProfileInfrastructure[])[1] = {
      ...romProfile,
      pages: changedPages,
    };
    assert.throws(() => materializeV17SettlementTransaction({
      infrastructureSet: changedRom,
      fixture: fixture(1),
    }), /ROM page|ROM infrastructure/);

    const deposit = fixture(0);
    assert.equal(deposit.profile, 0);
    const changedEdge = deposit.edgeDataLockingBytecode.slice();
    changedEdge[changedEdge.length - 1] ^= 1;
    assert.throws(() => materializeV17SettlementTransaction({
      infrastructureSet: set,
      fixture: { ...deposit, edgeDataLockingBytecode: changedEdge },
    }), /edge append/);
    assert.throws(() => materializeV17SettlementTransaction({
      infrastructureSet: set,
      fixture: {
        ...deposit,
        funding: {
          ...deposit.funding,
          lockingBytecode: new Uint8Array(10_001),
        },
      },
    }), /exceeds 10000 bytes/);

    const product = materializeV17SettlementTransaction({
      infrastructureSet: set,
      fixture: fixture(2),
    });
    const inputSequenceNumbers = product.transaction.inputs.map((input) => input.sequenceNumber);
    inputSequenceNumbers[1]! += 1;
    assert.throws(() => deriveLocalWordPublicSettlement({
      sourceOutputs: product.sourceOutputs,
      inputSequenceNumbers,
      outputs: product.transaction.outputs,
    }, set.authorizedBankDigests), /unauthorized verifier bank/);
  });
});

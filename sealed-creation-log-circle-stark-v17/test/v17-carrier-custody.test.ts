import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { createVirtualMachineBch2026 } from "@bitauth/libauth";
import {
  LOCAL_WORD_PROOF_LENGTH_OFFSET,
  LOCAL_WORD_PROOF_VERSION,
} from "../src/backends/circle/local-word-sealed-proof.ts";
import { V17_BATCH_LEADER_CELL_BYTES } from
  "../src/backends/circle/v17-batch-leader-cell.ts";
import {
  compileLocalWordBatchLeaderCarrierRedeem,
  compileLocalWordCarrierRedeem,
  encodeLocalWordP2shBatchLeaderUnlocking,
  encodeLocalWordP2shCarrierUnlocking,
  LOCAL_WORD_BATCH_LEADER_INPUT_INDEX,
  LOCAL_WORD_CARRIER_MIN_PROOF_BYTES,
  localWordP2sh32Lock,
  localWordPoolCarrierSequence,
  localWordVerifierCarrierSequence,
  localWordVerifierCarrierValue,
  partitionLocalWordProofBytes,
} from "../src/chain/local-word-proof-carriers.ts";
import { concatBytes, writeU32BE } from "../src/pool/bytes.ts";

const ORDINARY_INPUT_INDEX = 3;
const ORDINARY_VERIFIER = Uint8Array.of(0x75, 0x51); // OP_DROP OP_TRUE
const LEADER_VERIFIER = concatBytes(
  Uint8Array.of(0x6d, 0x4d, 0x2c, 0x01), // OP_2DROP PUSHDATA2(300)
  new Uint8Array(300),
  Uint8Array.of(0x75, 0x51), // OP_DROP OP_TRUE
);

function canonicalProof(): Uint8Array {
  const proof = new Uint8Array(LOCAL_WORD_CARRIER_MIN_PROOF_BYTES);
  proof.set(new TextEncoder().encode("SKLW"), 0);
  proof[4] = LOCAL_WORD_PROOF_VERSION;
  proof.set(writeU32BE(proof.length), LOCAL_WORD_PROOF_LENGTH_OFFSET);
  return proof;
}

function standaloneCarrierFixture(leader: boolean) {
  const proof = canonicalProof();
  const carriers = partitionLocalWordProofBytes(proof);
  const inputIndex = leader ? LOCAL_WORD_BATCH_LEADER_INPUT_INDEX : ORDINARY_INPUT_INDEX;
  const redeem = leader
    ? compileLocalWordBatchLeaderCarrierRedeem({
      index: inputIndex,
      verifier: LEADER_VERIFIER,
    })
    : compileLocalWordCarrierRedeem({ index: inputIndex, verifier: ORDINARY_VERIFIER });
  const lockingBytecode = localWordP2sh32Lock(redeem);
  const sourceOutputs = carriers.map((_, index) => ({
    lockingBytecode: index === inputIndex ? lockingBytecode : Uint8Array.of(0x51),
    valueSatoshis: index === 0 ? 1_000n : localWordVerifierCarrierValue(index),
  }));
  const transaction = {
    version: 2,
    locktime: 0,
    inputs: carriers.map((carrier, index) => ({
      outpointTransactionHash: new Uint8Array(32).fill((index + 1) & 0xff),
      outpointIndex: index,
      sequenceNumber: index === 0
        ? localWordPoolCarrierSequence(proof.length)
        : localWordVerifierCarrierSequence(index),
      unlockingBytecode: index === inputIndex
        ? leader
          ? encodeLocalWordP2shBatchLeaderUnlocking(
            carrier.chunk,
            new Uint8Array(V17_BATCH_LEADER_CELL_BYTES),
            redeem,
          )
          : encodeLocalWordP2shCarrierUnlocking(carrier.chunk, redeem)
        : carrier.unlockingBytecode,
    })),
    outputs: sourceOutputs.map((output) => ({ ...output })),
  };
  return { inputIndex, sourceOutputs, transaction };
}

function assertLocalCustody(leader: boolean): void {
  const fixture = standaloneCarrierFixture(leader);
  const vm = createVirtualMachineBch2026(false);
  const evaluate = (candidate: typeof fixture) => vm.evaluate({
    inputIndex: candidate.inputIndex,
    sourceOutputs: candidate.sourceOutputs,
    transaction: candidate.transaction,
  } as never);

  const rolled = evaluate(fixture);
  assert.equal(vm.stateSuccess(rolled), true, String(rolled.error));
  assert.deepEqual(
    fixture.transaction.outputs[fixture.inputIndex],
    fixture.sourceOutputs[fixture.inputIndex],
  );

  const destroyed = structuredClone(fixture);
  destroyed.transaction.outputs.splice(fixture.inputIndex);
  assert.notEqual(vm.stateSuccess(evaluate(destroyed)), true, "carrier cannot be destroyed");

  const changedLock = structuredClone(fixture);
  changedLock.transaction.outputs[fixture.inputIndex]!.lockingBytecode = Uint8Array.of(0x51);
  assert.notEqual(vm.stateSuccess(evaluate(changedLock)), true, "carrier lock cannot change");

  const changedValue = structuredClone(fixture);
  changedValue.transaction.outputs[fixture.inputIndex]!.valueSatoshis += 1n;
  assert.notEqual(vm.stateSuccess(evaluate(changedValue)), true, "carrier value cannot change");

  const inputToken = structuredClone(fixture) as typeof fixture & {
    sourceOutputs: Array<(typeof fixture.sourceOutputs)[number] & { token?: unknown }>;
  };
  inputToken.sourceOutputs[fixture.inputIndex]!.token = {
    category: new Uint8Array(32).fill(0x77),
    amount: 1n,
  };
  assert.notEqual(
    vm.stateSuccess(evaluate(inputToken as typeof fixture)),
    true,
    "carrier input must remain tokenless",
  );

  const outputToken = structuredClone(fixture) as typeof fixture & {
    transaction: typeof fixture.transaction & {
      outputs: Array<(typeof fixture.transaction.outputs)[number] & { token?: unknown }>;
    };
  };
  outputToken.transaction.outputs[fixture.inputIndex]!.token = {
    category: new Uint8Array(32).fill(0x88),
    amount: 1n,
  };
  assert.notEqual(
    vm.stateSuccess(evaluate(outputToken as typeof fixture)),
    true,
    "carrier output must remain tokenless",
  );
}

describe("v17 persistent verifier-carrier custody", () => {
  it("allows an ordinary standalone carrier only to roll forward identically", () => {
    assertLocalCustody(false);
  });

  it("preserves q0 framing while requiring the same local rollover", () => {
    assertLocalCustody(true);
  });
});

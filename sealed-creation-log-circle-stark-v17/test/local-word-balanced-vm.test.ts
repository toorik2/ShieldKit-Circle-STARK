import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  createVirtualMachineBch2026,
  encodeLockingBytecodeP2sh32,
  hash256,
} from "@bitauth/libauth";
import {
  compileLocalWordHeaderGate,
  compileLocalWordReadGate,
} from "../src/chain/local-word-balanced-vm.ts";
import {
  compileLocalWordCarrierRedeem,
  compileLocalWordPoolCarrierRedeem,
  encodeLocalWordP2shCarrierUnlocking,
  localWordVerifierCarrierValue,
  localWordVerifierCarrierSequence,
  localWordPoolCarrierSequence,
  LOCAL_WORD_CARRIER_MIN_PROOF_BYTES,
  LOCAL_WORD_PRIMARY_CARRIER_INPUTS,
  partitionLocalWordProofBytes,
} from "../src/chain/local-word-proof-carriers.ts";
import {
  LOCAL_WORD_PROOF_LENGTH_OFFSET,
  LOCAL_WORD_PROOF_VERSION,
  localWordProofStaticOffsets,
} from "../src/backends/circle/local-word-sealed-proof.ts";
import { writeU32BE } from "../src/pool/bytes.ts";

function proofBytes(length = LOCAL_WORD_CARRIER_MIN_PROOF_BYTES + 1_000): Uint8Array {
  const bytes = Uint8Array.from({ length }, (_, index) => (index * 73 + 9) & 0xff);
  bytes.set(new TextEncoder().encode("SKLW"), 0);
  bytes[4] = LOCAL_WORD_PROOF_VERSION;
  bytes[5] = 2;
  bytes.set(writeU32BE(bytes.length), LOCAL_WORD_PROOF_LENGTH_OFFSET);
  return bytes;
}

function transactionFor(carriers: ReturnType<typeof partitionLocalWordProofBytes>) {
  return {
    version: 2,
    locktime: 0,
    inputs: carriers.map((carrier, input) => ({
      outpointTransactionHash: new Uint8Array(32).fill((input + 1) & 0xff),
      outpointIndex: input,
      sequenceNumber: input === 0
        ? localWordPoolCarrierSequence(carriers[0]!.proofLength)
        : localWordVerifierCarrierSequence(input),
      unlockingBytecode: carrier.unlockingBytecode,
    })),
    outputs: [{ lockingBytecode: Uint8Array.of(0x51), valueSatoshis: 128_000n }],
  };
}

function p2shFixture(
  carriers: ReturnType<typeof partitionLocalWordProofBytes>,
  redeems: readonly Uint8Array[],
) {
  const transaction = transactionFor(carriers);
  const sourceOutputs = redeems.map((redeem, index) => ({
    lockingBytecode: encodeLockingBytecodeP2sh32(hash256(redeem)),
    valueSatoshis: index === 0 ? 1_000n : localWordVerifierCarrierValue(index),
  }));
  return {
    transaction: {
      ...transaction,
      inputs: transaction.inputs.map((transactionInput, index) => ({
        ...transactionInput,
        unlockingBytecode: encodeLocalWordP2shCarrierUnlocking(
          carriers[index]!.chunk,
          redeems[index]!,
        ),
      })),
      outputs: sourceOutputs.map((output) => ({ ...output })),
    },
    sourceOutputs,
  };
}

describe("local-word canonical carrier VM", () => {
  it("binds the proof header to verifier-key constants", () => {
    const proof = proofBytes();
    const carriers = partitionLocalWordProofBytes(proof);
    const lock = compileLocalWordHeaderGate({
      profile: 2,
      protocolId: proof.slice(6, 38),
      expectedPreprocessedRoot: proof.slice(
        localWordProofStaticOffsets(1).matrixRoots,
        localWordProofStaticOffsets(1).matrixRoots + 32,
      ),
      publicWordCount: 1,
    });
    const inputIndex = LOCAL_WORD_PRIMARY_CARRIER_INPUTS;
    const redeems = carriers.map(() => new Uint8Array(256));
    redeems[0] = compileLocalWordPoolCarrierRedeem(Uint8Array.of(0x75, 0x51));
    redeems[inputIndex] = compileLocalWordCarrierRedeem({
      index: inputIndex,
      verifier: lock,
    });
    const honest = p2shFixture(carriers, redeems);
    const vm = createVirtualMachineBch2026(false);
    const state = vm.evaluate({ inputIndex, ...honest } as never);
    assert.equal(vm.stateSuccess(state), true, String(vm.stateSuccess(state)));

    const wrong = compileLocalWordHeaderGate({
      profile: 2,
      protocolId: Uint8Array.of(...proof.slice(6, 37), proof[37]! ^ 1),
      expectedPreprocessedRoot: proof.slice(
        localWordProofStaticOffsets(1).matrixRoots,
        localWordProofStaticOffsets(1).matrixRoots + 32,
      ),
      publicWordCount: 1,
    });
    const wrongRedeems = [...redeems];
    wrongRedeems[inputIndex] = compileLocalWordCarrierRedeem({
      index: inputIndex,
      verifier: wrong,
    });
    const rejected = vm.evaluate({ inputIndex, ...p2shFixture(carriers, wrongRedeems) } as never);
    assert.notEqual(vm.stateSuccess(rejected), true);
  });

  it("reads within and across every per-role budget boundary", () => {
    const proof = proofBytes();
    const carriers = partitionLocalWordProofBytes(proof);
    const cases = [
      { offset: LOCAL_WORD_PROOF_LENGTH_OFFSET, width: 4 },
      { offset: 42, width: 16 },
      { offset: carriers[17]!.end - 11, width: 64 },
      { offset: carriers[7]!.end - 11, width: 1_000 },
      { offset: carriers[90]!.end - 7, width: 96 },
      { offset: proof.length - 64, width: 64 },
    ];
    const vm = createVirtualMachineBch2026(false);
    for (const [caseIndex, read] of cases.entries()) {
      const lock = compileLocalWordReadGate({
        proofOffset: read.offset,
        expected: proof.slice(read.offset, read.offset + read.width),
      });
      const inputIndex = 1;
      const redeems = carriers.map(() => new Uint8Array(256));
      redeems[0] = compileLocalWordPoolCarrierRedeem(Uint8Array.of(0x75, 0x51));
      redeems[inputIndex] = compileLocalWordCarrierRedeem({
        index: inputIndex,
        verifier: lock,
      });
      const fixture = p2shFixture(carriers, redeems);
      const state = vm.evaluate({ inputIndex, ...fixture } as never);
      assert.equal(vm.stateSuccess(state), true, `local-word reader ${caseIndex}: ${String(vm.stateSuccess(state))}`);
      const changed = structuredClone(fixture.transaction);
      const changedCarrier = carriers.find((carrier) =>
        read.offset >= carrier.start && read.offset < carrier.end)!;
      changed.inputs[changedCarrier.index]!.unlockingBytecode[
        3 + read.offset - changedCarrier.start
      ] ^= 1;
      const rejected = vm.evaluate({
        inputIndex,
        sourceOutputs: fixture.sourceOutputs,
        transaction: changed,
      } as never);
      assert.notEqual(vm.stateSuccess(rejected), true, `local-word reader mutation ${caseIndex}`);
    }
  });

  it("binds each carrier locally to one proof slice and its transaction index", () => {
    const proof = proofBytes();
    const carriers = partitionLocalWordProofBytes(proof);
    const vm = createVirtualMachineBch2026(false);
    for (const input of [0, LOCAL_WORD_PRIMARY_CARRIER_INPUTS]) {
      const redeem = input === 0
        ? compileLocalWordPoolCarrierRedeem(Uint8Array.of(0x75, 0x51))
        : compileLocalWordCarrierRedeem({
          index: input,
          verifier: Uint8Array.of(0x75, 0x51),
        });
      const redeems = carriers.map(() => new Uint8Array(256));
      redeems[input] = redeem;
      const state = vm.evaluate({ inputIndex: input, ...p2shFixture(carriers, redeems) } as never);
      assert.equal(vm.stateSuccess(state), true, `local-word placement ${input}: ${String(state.error)}`);

      const shorter = partitionLocalWordProofBytes(proofBytes(LOCAL_WORD_CARRIER_MIN_PROOF_BYTES + 500));
      const shorterRedeems = shorter.map(() => new Uint8Array(256));
      shorterRedeems[input] = redeem;
      const shorterState = vm.evaluate({
        inputIndex: input,
        ...p2shFixture(shorter, shorterRedeems),
      } as never);
      assert.equal(vm.stateSuccess(shorterState), true,
        `local-word dynamic placement ${input}: ${String(shorterState.error)}`);
    }

    const input = 0;
    const redeem = compileLocalWordPoolCarrierRedeem(Uint8Array.of(0x75, 0x51));
    const redeems = carriers.map(() => new Uint8Array(256));
    redeems[input] = redeem;
    const fixture = p2shFixture(carriers, redeems);
    const short = structuredClone(fixture.transaction);
    short.inputs[input]!.unlockingBytecode = encodeLocalWordP2shCarrierUnlocking(
      carriers[input]!.chunk.slice(0, -1),
      redeem,
    );
    const shortRejected = vm.evaluate({ inputIndex: input, sourceOutputs: fixture.sourceOutputs,
      transaction: short } as never);
    assert.notEqual(vm.stateSuccess(shortRejected), true);

    const extra = structuredClone(fixture.transaction);
    extra.inputs[input]!.unlockingBytecode = Uint8Array.of(
      0,
      ...extra.inputs[input]!.unlockingBytecode,
    );
    const extraRejected = vm.evaluate({ inputIndex: input, sourceOutputs: fixture.sourceOutputs,
      transaction: extra } as never);
    assert.notEqual(vm.stateSuccess(extraRejected), true);

    const wrongIndex = 1;
    const movedRedeems = carriers.map(() => new Uint8Array(256));
    movedRedeems[wrongIndex] = redeem;
    const moved = p2shFixture(carriers, movedRedeems);
    const movedRejected = vm.evaluate({ inputIndex: wrongIndex, ...moved } as never);
    assert.notEqual(vm.stateSuccess(movedRejected), true);
  });
});

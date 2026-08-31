import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  createInstructionSetBch2026,
  createVirtualMachine,
  decodeAuthenticationInstructions,
  OpcodesBch,
} from "@bitauth/libauth";
import { inv as mInv } from "../src/backends/circle/m31.ts";
import {
  LOCAL_WORD_MATRIX_NAMES,
  LOCAL_WORD_PROOF_LENGTH_OFFSET,
  LOCAL_WORD_PROOF_VERSION,
  localWordProofStaticOffsets,
} from "../src/backends/circle/local-word-sealed-proof.ts";
import {
  encodeQm31,
  qm31,
  qmAdd,
  qmMul,
  qmMulM31,
  qmSub,
  QM31_ZERO,
  type QM31El,
} from "../src/backends/circle/qm31.ts";
import {
  successorCirclePointAtBitReversed,
  successorLineXAtBitReversed,
} from "../src/backends/circle/successor-domain.ts";
import {
  compileLocalWordFriBatchGate,
  compileLocalWordFriDomainKatGate,
  compileLocalWordFriFoldGate,
} from
  "../src/chain/local-word-algebra-vm.ts";
import {
  localWordVerifierCarrierValue,
  localWordVerifierCarrierSequence,
  localWordPoolCarrierSequence,
  partitionLocalWordProofBytes,
} from "../src/chain/local-word-proof-carriers.ts";
import { localWordRequiredChunkBytes } from "../src/chain/local-word-role-budget.ts";
import { concatBytes, writeU32BE, writeU32LE } from "../src/pool/bytes.ts";

const PROOF_BYTES = 340_382;
// After sixteen folds this lands in the second pair of a four-point block,
// exercising the distinct binary-tail normalization.
const QUERY = 777_710;
const FRI_MASK = qm31(67n, 71n, 73n, 79n);

function unboundedVm() {
  const instructionSet = createInstructionSetBch2026(false);
  const every = instructionSet.every!;
  return createVirtualMachine({
    ...instructionSet,
    every: (state) => {
      state.metrics.maximumOperationCost = 1_000_000_000;
      return every(state);
    },
  });
}

function evaluate(proof: Uint8Array, lock: Uint8Array) {
  const carriers = partitionLocalWordProofBytes(proof);
  const transaction = {
    version: 2,
    locktime: 0,
    inputs: carriers.map((carrier, input) => ({
      outpointTransactionHash: new Uint8Array(32).fill((input + 1) & 0xff),
      outpointIndex: input,
      sequenceNumber: input === 0
        ? localWordPoolCarrierSequence(proof.length)
        : localWordVerifierCarrierSequence(input),
      unlockingBytecode: carrier.unlockingBytecode,
    })),
    outputs: [{ lockingBytecode: Uint8Array.of(0x51), valueSatoshis: 128_000n }],
  };
  const vm = unboundedVm();
  const sourceOutputs = carriers.map((_, index) => ({
    lockingBytecode: lock,
    valueSatoshis: index === 0 ? 1_000n : localWordVerifierCarrierValue(index),
  }));
  const state = vm.evaluate({ inputIndex: 8, sourceOutputs, transaction } as never);
  return { vm, state };
}

function changed(proof: Uint8Array, offset: number): Uint8Array {
  const result = proof.slice();
  result[offset] ^= 1;
  return result;
}

function batchFixture(): {
  readonly proof: Uint8Array;
  readonly mutations: readonly [string, number][];
} {
  const offsets = localWordProofStaticOffsets(8);
  const proof = new Uint8Array(PROOF_BYTES);
  proof.set(new TextEncoder().encode("SKLW"), 0);
  proof[4] = LOCAL_WORD_PROOF_VERSION;
  proof[5] = 0;
  proof.set(writeU32BE(proof.length), LOCAL_WORD_PROOF_LENGTH_OFFSET);
  const beta = qm31(83n, 89n, 97n, 101n);
  proof.set(encodeQm31(beta), offsets.batchBeta);
  proof.set(writeU32BE(QUERY), offsets.queries);
  proof[offsets.currentRanks] = 0;
  proof[offsets.globalCurrentRanks] = 0;
  proof[offsets.friCosetRanks] = 0;

  const rows = {
    original: 80_000,
    interaction: 90_000,
    interactionGlobal: 100_000,
    quotientAndFriMask: 110_000,
    fri: 120_000,
  } as const;
  for (const name of LOCAL_WORD_MATRIX_NAMES) {
    if (name === "preprocessed") continue;
    const start = rows[name as keyof typeof rows];
    proof.set(writeU32BE(start), offsets.openingDirectory + LOCAL_WORD_MATRIX_NAMES.indexOf(name) * 20 + 4);
  }
  proof.set(writeU32BE(rows.fri), offsets.openingDirectory + LOCAL_WORD_MATRIX_NAMES.length * 20 + 4);

  const original = Array.from({ length: 34 }, (_, index) => BigInt(index + 1));
  const interaction = Array.from({ length: 14 }, (_, index) =>
    qm31(BigInt(107 + index), BigInt(223 + index), BigInt(347 + index), BigInt(463 + index)));
  const global = [
    qm31(587n, 593n, 599n, 601n),
    qm31(607n, 613n, 617n, 619n),
    qm31(631n, 641n, 643n, 647n),
  ] as const;
  const quotient = qm31(653n, 659n, 661n, 673n);
  proof.set(concatBytes(...original.map((value) => writeU32LE(Number(value)))), rows.original);
  proof.set(concatBytes(...interaction.map(encodeQm31)), rows.interaction);
  proof.set(concatBytes(...global.map(encodeQm31)), rows.interactionGlobal);
  proof.set(concatBytes(
    encodeQm31(quotient),
    encodeQm31(FRI_MASK),
  ), rows.quotientAndFriMask);

  const packedOriginal = Array.from({ length: 9 }, (_, chunk) =>
    qm31(...Array.from({ length: 4 }, (_, coordinate) =>
      original[chunk * 4 + coordinate] ?? 0n) as [bigint, bigint, bigint, bigint]));
  const values: QM31El[] = [...packedOriginal, ...interaction, ...global, quotient];
  assert.equal(values.length, 27);
  const expected = qmAdd(values.slice(1).reduce((accumulator, value) =>
    qmAdd(qmMul(accumulator, beta), value), values[0]!), FRI_MASK);
  proof.set(encodeQm31(expected), rows.fri + (QUERY & 3) * 16);
  return {
    proof,
    mutations: [
      ["beta", offsets.batchBeta],
      ["original", rows.original],
      ["interaction", rows.interaction],
      ["global interaction", rows.interactionGlobal],
      ["FRI mask", rows.quotientAndFriMask + 16],
      ["quotient", rows.quotientAndFriMask],
      ["FRI layer zero", rows.fri + (QUERY & 3) * 16],
    ],
  };
}

describe("local-word oracle batching on the May-2026 VM", () => {
  it("binds all 28 opened values to the first FRI layer", () => {
    const built = batchFixture();
    const lock = compileLocalWordFriBatchGate({ profile: 0, query: 0 });
    const honest = evaluate(built.proof, lock);
    assert.equal(honest.vm.stateSuccess(honest.state), true, String(honest.state.error));
    for (const [label, offset] of built.mutations) {
      const rejected = evaluate(changed(built.proof, offset), lock);
      assert.notEqual(rejected.vm.stateSuccess(rejected.state), true, label);
    }
    const operationCost = Number(honest.state.metrics.operationCost);
    console.log("local-word-fri-batch-gate", JSON.stringify({
      values: 28,
      lockingBytes: lock.length,
      operationCost,
      requiredChunkBytes: localWordRequiredChunkBytes(operationCost),
    }));
    assert.ok(lock.length < 10_000);
  });
});

function friFold(left: QM31El, right: QM31El, twiddle: bigint, alpha: QM31El): QM31El {
  return qmAdd(
    qmAdd(left, right),
    qmMul(alpha, qmMulM31(qmSub(left, right), mInv(twiddle))),
  );
}

function friFoldFixture(): {
  readonly proof: Uint8Array;
  readonly mutations: readonly [string, number][];
  readonly twiddles: Uint8Array;
  readonly finalX: number;
} {
  const offsets = localWordProofStaticOffsets(8);
  const proof = new Uint8Array(PROOF_BYTES);
  proof.set(new TextEncoder().encode("SKLW"), 0);
  proof[4] = LOCAL_WORD_PROOF_VERSION;
  proof[5] = 0;
  proof.set(writeU32BE(proof.length), LOCAL_WORD_PROOF_LENGTH_OFFSET);
  proof.set(writeU32BE(QUERY), offsets.queries);
  const alphas = Array.from({ length: 9 }, (_, round) =>
    qm31(BigInt(701 + round), BigInt(733 + round), BigInt(761 + round), BigInt(797 + round)));
  alphas.forEach((alpha, round) => proof.set(encodeQm31(alpha), offsets.friAlphas + round * 16));

  const rows = Array.from({ length: 9 }, (_, layer) => 130_000 + layer * 1_000);
  let position = QUERY;
  let completedFolds = 0;
  let expected: QM31El | undefined;
  let firstExpectedOffset = 0;
  const twiddles: bigint[] = [];
  for (let layer = 0; layer < 9; layer += 1) {
    const folds = layer === 8 ? 1 : 2;
    const arity = 2 ** folds;
    const base = position & ~(arity - 1);
    const values = Array.from({ length: arity }, (_, value) =>
      qm31(
        BigInt(809 + layer * 37 + value),
        BigInt(911 + layer * 41 + value),
        BigInt(1_009 + layer * 43 + value),
        BigInt(1_103 + layer * 47 + value),
      ));
    if (expected) {
      const exact = position % arity;
      values[exact] = expected;
      if (layer === 1) firstExpectedOffset = rows[layer]! + exact * 16;
    }
    proof.set(concatBytes(...values.map(encodeQm31)), rows[layer]);
    proof[offsets.friCosetRanks + layer * 28] = 0;
    proof.set(
      writeU32BE(rows[layer]!),
      offsets.openingDirectory + (LOCAL_WORD_MATRIX_NAMES.length + layer) * 20 + 4,
    );

    let folded = values;
    for (let subfold = 0; subfold < folds; subfold += 1) {
      const challenge = subfold === 0 ? alphas[layer]! : qmMul(alphas[layer]!, alphas[layer]!);
      folded = Array.from({ length: folded.length / 2 }, (_, pair) => {
        const pairBase = (base >> subfold) + pair * 2;
        const totalFold = completedFolds + subfold;
        const twiddle = totalFold === 0
          ? successorCirclePointAtBitReversed(24, pairBase).y
          : successorLineXAtBitReversed(24 - totalFold, pairBase);
        twiddles.push(twiddle);
        return friFold(folded[pair * 2]!, folded[pair * 2 + 1]!, twiddle, challenge);
      });
    }
    expected = folded[0]!;
    position >>= folds;
    completedFolds += folds;
  }
  assert.equal(completedFolds, 17);
  assert.equal(twiddles.length, 25);
  proof.set(encodeQm31(expected!), offsets.finalCoefficients);
  for (let coefficient = 1; coefficient < 8; coefficient += 1) {
    proof.set(encodeQm31(QM31_ZERO), offsets.finalCoefficients + coefficient * 16);
  }
  return {
    proof,
    twiddles: concatBytes(...twiddles.map((twiddle) => writeU32LE(Number(twiddle)))),
    finalX: Number(successorLineXAtBitReversed(7, position)),
    mutations: [
      ["first layer", rows[0]!],
      ["fold challenge", offsets.friAlphas],
      ["fold link", firstExpectedOffset],
      ["final polynomial", offsets.finalCoefficients],
    ],
  };
}

describe("local-word FRI algebra on the May-2026 VM", () => {
  it("checks all 17 folds and the final degree-7 polynomial for one query", () => {
    const built = friFoldFixture();
    const domainLock = compileLocalWordFriDomainKatGate({
      query: QUERY,
      expectedTwiddles: built.twiddles,
      expectedFinalX: built.finalX,
    });
    const domain = evaluate(built.proof, domainLock);
    if (domain.vm.stateSuccess(domain.state) !== true) {
      const instructions = decodeAuthenticationInstructions(domainLock);
      const names = new Map(Object.entries(OpcodesBch).map(([name, opcode]) => [opcode, name]));
      console.log("local-word-domain-debug", JSON.stringify({
        error: domain.state.error,
        ip: domain.state.ip,
        depth: domain.state.stack.length,
        alt: domain.state.alternateStack.length,
        stack: domain.state.stack.map((item) => Buffer.from(item).toString("hex")),
        instructions: instructions.slice(Math.max(0, domain.state.ip - 8), domain.state.ip + 4)
          .map((instruction, offset) => ({
            at: Math.max(0, domain.state.ip - 8) + offset,
            op: "data" in instruction ? `push:${instruction.data.length}` : names.get(instruction.opcode),
          })),
      }));
    }
    assert.equal(domain.vm.stateSuccess(domain.state), true, `domain: ${String(domain.state.error)}`);
    const lock = compileLocalWordFriFoldGate({ profile: 0, query: 0 });
    const honest = evaluate(built.proof, lock);
    if (honest.vm.stateSuccess(honest.state) !== true) {
      const instructions = decodeAuthenticationInstructions(lock);
      const names = new Map(Object.entries(OpcodesBch).map(([name, opcode]) => [opcode, name]));
      console.log("local-word-fri-debug", JSON.stringify({
        error: honest.state.error,
        ip: honest.state.ip,
        depth: honest.state.stack.length,
        alt: honest.state.alternateStack.length,
        stack: honest.state.stack.slice(-12).map((item) => Buffer.from(item).toString("hex")),
        instructions: instructions.slice(Math.max(0, honest.state.ip - 5), honest.state.ip + 3)
          .map((instruction, offset) => ({
            at: Math.max(0, honest.state.ip - 5) + offset,
            op: "data" in instruction ? `push:${instruction.data.length}` : names.get(instruction.opcode),
          })),
        depthOps: instructions.flatMap((instruction, at) =>
          !("data" in instruction) && names.get(instruction.opcode) === "OP_DEPTH" ? [at] : []),
      }));
    }
    assert.equal(honest.vm.stateSuccess(honest.state), true, String(honest.state.error));
    for (const [label, offset] of built.mutations) {
      const rejected = evaluate(changed(built.proof, offset), lock);
      assert.notEqual(rejected.vm.stateSuccess(rejected.state), true, label);
    }
    const noncanonical = built.proof.slice();
    noncanonical.set(writeU32LE(2_147_483_647), localWordProofStaticOffsets(8).finalCoefficients);
    const noncanonicalResult = evaluate(noncanonical, lock);
    assert.notEqual(noncanonicalResult.vm.stateSuccess(noncanonicalResult.state), true);
    const operationCost = Number(honest.state.metrics.operationCost);
    console.log("local-word-fri-fold-gate", JSON.stringify({
      folds: 17,
      lockingBytes: lock.length,
      operationCost,
      requiredChunkBytes: localWordRequiredChunkBytes(operationCost),
    }));
    assert.ok(lock.length < 10_000);
  });
});

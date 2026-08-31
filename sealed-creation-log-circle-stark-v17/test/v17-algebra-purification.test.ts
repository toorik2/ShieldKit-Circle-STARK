import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  binToHex,
  cashAssemblyToBin,
  createInstructionSetBch2026,
  createVirtualMachine,
} from "@bitauth/libauth";
import { M31 } from "../src/backends/circle/m31.ts";
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
  compileLocalWordFriBatchGate,
  compileV17FriFoldPurificationKatGate,
  compileV17LocalWordFriFoldGate,
  compileV17PackedBetaDotPurificationKatGate,
} from "../src/chain/local-word-algebra-vm.ts";
import { censusV17OpDefineBodies } from "../src/construction/v17-linker.ts";
import { concatBytes, encodeVmNumber } from "../src/pool/bytes.ts";

function compile(assembly: string): Uint8Array {
  const bytecode = cashAssemblyToBin(assembly);
  if (typeof bytecode === "string") throw new Error(bytecode);
  return bytecode;
}

const instructionSet = createInstructionSetBch2026(false);
const every = instructionSet.every!;
const vm = createVirtualMachine({
  ...instructionSet,
  every: (state) => {
    state.metrics.maximumOperationCost = 1_000_000_000;
    return every(state);
  },
});

function evaluate(lockingBytecode: Uint8Array, items: readonly Uint8Array[]) {
  const unlockingBytecode = compile(items.map((item) => `<0x${binToHex(item)}>`).join("\n"));
  const state = vm.evaluate({
    inputIndex: 0,
    sourceOutputs: [{ lockingBytecode, valueSatoshis: 1n }],
    transaction: {
      version: 2,
      locktime: 0,
      inputs: [{
        outpointTransactionHash: new Uint8Array(32),
        outpointIndex: 0,
        sequenceNumber: 0,
        unlockingBytecode,
      }],
      outputs: [{ lockingBytecode: Uint8Array.of(0x51), valueSatoshis: 1n }],
    },
  } as never);
  return { ok: vm.stateSuccess(state) === true, state };
}

function foldFromInverse(
  left: QM31El,
  right: QM31El,
  inverse: bigint,
  alpha: QM31El,
): QM31El {
  return qmAdd(
    qmAdd(left, right),
    qmMul(alpha, qmMulM31(qmSub(left, right), inverse)),
  );
}

function dot(values: readonly QM31El[], weights: readonly QM31El[]): QM31El {
  return values.reduce(
    (sum, value, index) => qmAdd(sum, qmMul(value, weights[index]!)),
    QM31_ZERO,
  );
}

function deterministicElements(count: number): readonly QM31El[] {
  let state = 0x6d2b79f5;
  const next = (): bigint => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return BigInt(state >>> 0) % M31;
  };
  return Array.from({ length: count }, () => qm31(next(), next(), next(), next()));
}

describe("v17 limb-local algebra purifications", () => {
  it("matches the prior FRI fold lowering at field edges and deterministic random points", () => {
    const zero = qm31(0n, 0n, 0n, 0n);
    const one = qm31(1n, 1n, 1n, 1n);
    const maximum = qm31(M31 - 1n, M31 - 1n, M31 - 1n, M31 - 1n);
    const alternating = qm31(0n, M31 - 1n, 1n, M31 - 2n);
    const edgeCases = [
      { left: zero, right: zero, inverse: 1n, alpha: zero },
      { left: maximum, right: zero, inverse: 1n, alpha: one },
      { left: zero, right: maximum, inverse: M31 - 1n, alpha: alternating },
      { left: alternating, right: one, inverse: M31 - 2n, alpha: maximum },
    ];
    const random = deterministicElements(64 * 3);
    const cases = [
      ...edgeCases,
      ...Array.from({ length: 64 }, (_, index) => ({
        left: random[index * 3]!,
        right: random[index * 3 + 1]!,
        inverse: BigInt(index * 104_729 + 1) % M31,
        alpha: random[index * 3 + 2]!,
      })),
    ];
    for (const [index, item] of cases.entries()) {
      const expected = encodeQm31(foldFromInverse(
        item.left,
        item.right,
        item.inverse,
        item.alpha,
      ));
      const gate = compileV17FriFoldPurificationKatGate(expected);
      const result = evaluate(gate, [
        encodeQm31(item.left),
        encodeQm31(item.right),
        encodeVmNumber(item.inverse),
        encodeQm31(item.alpha),
      ]);
      assert.equal(result.ok, true, `${index}:${String(result.state.error)}`);
      assert.equal(result.state.stack.length, 1, `${index}: clean stack`);
      assert.equal(result.state.alternateStack.length, 0, `${index}: clean alternate stack`);
    }
  });

  it("matches the prior fused dot at field edges and deterministic random vectors", () => {
    const zero = qm31(0n, 0n, 0n, 0n);
    const maximum = qm31(M31 - 1n, M31 - 1n, M31 - 1n, M31 - 1n);
    const elements = deterministicElements(32 * 20);
    const cases = [
      {
        values: Array.from({ length: 10 }, () => zero),
        weights: Array.from({ length: 10 }, () => maximum),
      },
      {
        values: Array.from({ length: 10 }, (_, index) => index % 2 === 0 ? maximum : zero),
        weights: Array.from({ length: 10 }, (_, index) => index % 2 === 0 ? zero : maximum),
      },
      ...Array.from({ length: 32 }, (_, vector) => ({
        values: elements.slice(vector * 20, vector * 20 + 10),
        weights: elements.slice(vector * 20 + 10, vector * 20 + 20),
      })),
    ];
    for (const [index, item] of cases.entries()) {
      const values = concatBytes(...item.values.map(encodeQm31));
      const weights = concatBytes(...item.weights.map(encodeQm31));
      const expected = encodeQm31(dot(item.values, item.weights));
      const gate = compileV17PackedBetaDotPurificationKatGate(expected);
      const result = evaluate(gate, [values, weights]);
      assert.equal(result.ok, true, `${index}:${String(result.state.error)}`);
      assert.equal(result.state.stack.length, 1, `${index}: clean stack`);
      assert.equal(result.state.alternateStack.length, 0, `${index}: clean alternate stack`);
    }
  });

  it("keeps the two purifications inside the existing shared outer kernels", () => {
    const batch = compileLocalWordFriBatchGate({ profile: 0, query: 1 });
    const fri = compileV17LocalWordFriFoldGate({ profile: 0, query: 0 });
    const batchCensus = censusV17OpDefineBodies(batch);
    const friCensus = censusV17OpDefineBodies(fri);
    assert.equal(batchCensus.filter(({ depth, functionIdHex }) =>
      depth === 0 && functionIdHex === "1d").length, 1);
    assert.equal(friCensus.filter(({ depth, functionIdHex }) =>
      depth === 0 && functionIdHex === "1e").length, 1);
    assert.equal(batchCensus.filter(({ depth, functionIdHex }) =>
      depth === 1 && functionIdHex === "20").length, 1);
    assert.equal(batchCensus.filter(({ depth, functionIdHex }) =>
      depth === 1 && functionIdHex === "21").length, 1);
    assert.equal(friCensus.filter(({ depth, functionIdHex }) =>
      depth === 1 && functionIdHex === "1f").length, 1);
    assert.equal(friCensus.filter(({ depth, functionIdHex }) =>
      depth === 1 && (functionIdHex === "0b" || functionIdHex === "0e")).length, 0);
    assert.ok(batch.length < 10_000);
    assert.ok(fri.length < 10_000);
    console.log("v17-algebra-purification-bodies", JSON.stringify({
      batchOuterBytes: batchCensus.find(({ depth }) => depth === 0)!.body.length,
      friOuterBytes: friCensus.find(({ depth }) => depth === 0)!.body.length,
      batchGateBytes: batch.length,
      friGateBytes: fri.length,
      fusedFoldBytes: friCensus.find(({ functionIdHex }) => functionIdHex === "1f")!.body.length,
      packWeightsBytes: batchCensus.find(({ functionIdHex }) => functionIdHex === "20")!.body.length,
      packedDotBytes: batchCensus.find(({ functionIdHex }) => functionIdHex === "21")!.body.length,
    }));
  });
});

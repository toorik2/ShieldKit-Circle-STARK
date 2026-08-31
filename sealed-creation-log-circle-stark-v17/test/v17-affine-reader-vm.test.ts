import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { describe, it } from "node:test";
import {
  cashAssemblyToBin,
  createInstructionSetBch2026,
  createVirtualMachine,
} from "@bitauth/libauth";
import {
  LOCAL_WORD_MATRIX_ROW_WIDTHS,
  LOCAL_WORD_PROOF_LENGTH_OFFSET,
  LOCAL_WORD_PROOF_VERSION,
} from "../src/backends/circle/local-word-sealed-proof.ts";
import { localWordReadDynamicAssembly } from
  "../src/chain/local-word-balanced-vm.ts";
import {
  compileV17AffineReaderVm,
  v17AffineReaderIntervalTable,
} from "../src/chain/v17-affine-reader-vm.ts";
import {
  V17_BOOTSTRAP_AFFINE_ALLOCATION,
  v17AffineBoundary,
} from "../src/chain/v17-affine-allocation.ts";
import {
  localWordPoolCarrierSequence,
  localWordVerifierCarrierSequence,
  localWordVerifierCarrierValue,
  partitionLocalWordProofBytes,
} from "../src/chain/local-word-proof-carriers.ts";
import {
  buildV17AffineReaderPlan,
  locateV17AffineReaderCarrier,
  type V17AffineReaderPlan,
  v17AffineReaderPlanDigestHex,
  v17AffineReaderPlanInterval,
} from "../src/construction/v17-affine-reader-plan.ts";
import { concatBytes, writeU32BE } from "../src/pool/bytes.ts";

const allocation = V17_BOOTSTRAP_AFFINE_ALLOCATION;
const plan = buildV17AffineReaderPlan(allocation);
const specialized = compileV17AffineReaderVm(plan);

function compile(assembly: string): Uint8Array {
  const bytecode = cashAssemblyToBin(assembly);
  if (typeof bytecode === "string") throw new Error(bytecode);
  return bytecode;
}

const specializedGate = compile(`OP_TOALTSTACK <3> OP_ROLL OP_DROP
${specialized.assembly}
OP_NIP OP_SHA256 OP_FROMALTSTACK OP_EQUAL`);
const genericAssembly = localWordReadDynamicAssembly();
const genericGate = compile(`OP_TOALTSTACK <3> OP_ROLL OP_DROP
${genericAssembly}
OP_NIP OP_SHA256 OP_FROMALTSTACK OP_EQUAL`);

function proofBytes(length: number): Uint8Array {
  const bytes = Uint8Array.from({ length }, (_, index) =>
    (index * 73 + Math.floor(index / 251) * 19 + 9) & 0xff);
  bytes.set(new TextEncoder().encode("SKLW"), 0);
  bytes[4] = LOCAL_WORD_PROOF_VERSION;
  bytes[5] = 0;
  bytes.set(writeU32BE(length), LOCAL_WORD_PROOF_LENGTH_OFFSET);
  return bytes;
}

type ReaderFixture = ReturnType<typeof readerFixture>;

function readerFixture(proofLength: number) {
  const proof = proofBytes(proofLength);
  const carriers = partitionLocalWordProofBytes(proof, allocation);
  const inputs = carriers.map((carrier, index) => ({
    outpointTransactionHash: new Uint8Array(32).fill((index + 1) & 0xff),
    outpointIndex: index,
    sequenceNumber: index === 0
      ? localWordPoolCarrierSequence(proofLength, allocation)
      : localWordVerifierCarrierSequence(index, allocation),
    unlockingBytecode: carrier.unlockingBytecode,
  }));
  const sourceOutputs = carriers.map((_, index) => ({
    lockingBytecode: Uint8Array.of(0x51),
    valueSatoshis: index === 0 ? 1_000n : localWordVerifierCarrierValue(index, allocation),
  }));
  return {
    proof,
    carriers,
    transaction: {
      version: 2,
      locktime: 0,
      inputs,
      outputs: [{ lockingBytecode: Uint8Array.of(0x51), valueSatoshis: 1_000n }],
    },
    sourceOutputs,
  };
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

function readArguments(
  fixture: ReaderFixture,
  proofOffset: number,
  width: number,
): Uint8Array {
  const expected = fixture.proof.slice(proofOffset, proofOffset + width);
  const digest = new Uint8Array(createHash("sha256").update(expected).digest());
  return compile(`<${fixture.proof.length}> <${proofOffset}> <${width}> <0x${
    Buffer.from(digest).toString("hex")
  }>`);
}

function evaluateRead(args: {
  readonly fixture: ReaderFixture;
  readonly gate: Uint8Array;
  readonly proofOffset: number;
  readonly width: number;
  readonly mutate?: (fixture: ReaderFixture) => ReaderFixture;
}) {
  const fixture = args.mutate === undefined ? args.fixture : args.mutate(args.fixture);
  const inputIndex = 1;
  const transaction = structuredClone(fixture.transaction);
  transaction.inputs[inputIndex]!.unlockingBytecode = concatBytes(
    fixture.carriers[inputIndex]!.unlockingBytecode,
    readArguments(args.fixture, args.proofOffset, args.width),
  );
  const sourceOutputs = fixture.sourceOutputs.map((output) => ({ ...output }));
  sourceOutputs[inputIndex]!.lockingBytecode = args.gate;
  const state = vm.evaluate({ inputIndex, transaction, sourceOutputs } as never);
  return {
    ok: vm.stateSuccess(state) === true,
    operationCost: Number(state.metrics.operationCost),
    error: state.error,
  };
}

function ceilRatio(numerator: number, denominator: number): number {
  return Math.floor((numerator + denominator - 1) / denominator);
}

function lengthCellBounds(cell: number): readonly [number, number] {
  const count = plan.maximumProofBytes - plan.minimumProofBytes + 1;
  return [
    plan.minimumProofBytes + ceilRatio(cell * count, plan.lengthCells),
    plan.minimumProofBytes + ceilRatio((cell + 1) * count, plan.lengthCells) - 1,
  ];
}

function offsetCellBounds(proofLength: number, cell: number): readonly [number, number] {
  return [
    ceilRatio(cell * proofLength, plan.normalizedOffsetCells),
    ceilRatio((cell + 1) * proofLength, plan.normalizedOffsetCells) - 1,
  ];
}

type ReadCase = { readonly proofLength: number; readonly proofOffset: number; readonly width: number };

function canonicalCases(): readonly ReadCase[] {
  const cases = new Map<string, ReadCase>();
  const add = (proofLength: number, proofOffset: number, width = 1): void => {
    if (proofLength < plan.minimumProofBytes || proofLength > plan.maximumProofBytes ||
      proofOffset < 0 || width < 1 || proofOffset + width > proofLength) return;
    cases.set(`${proofLength}:${proofOffset}:${width}`, { proofLength, proofOffset, width });
  };

  // Exercise every certified table cell at an interior integer address.
  for (let lengthCell = 0; lengthCell < plan.lengthCells; lengthCell += 1) {
    const [lengthLow, lengthHigh] = lengthCellBounds(lengthCell);
    const proofLength = Math.floor((lengthLow + lengthHigh) / 2);
    for (let offsetCell = 0; offsetCell < plan.normalizedOffsetCells; offsetCell += 1) {
      const [offsetLow, offsetHigh] = offsetCellBounds(proofLength, offsetCell);
      add(proofLength, Math.floor((offsetLow + offsetHigh) / 2));
    }
  }

  // Cross every length-cell boundary at -1/0/+1 for every offset cell.
  const proofLengthCount = plan.maximumProofBytes - plan.minimumProofBytes + 1;
  for (let cell = 1; cell < plan.lengthCells; cell += 1) {
    const boundary = plan.minimumProofBytes + ceilRatio(
      cell * proofLengthCount,
      plan.lengthCells,
    );
    for (const proofLength of [boundary - 1, boundary, boundary + 1]) {
      for (let offsetCell = 0;
        offsetCell < plan.normalizedOffsetCells;
        offsetCell += 1) {
        const [low, high] = offsetCellBounds(proofLength, offsetCell);
        add(proofLength, Math.floor((low + high) / 2));
      }
    }
  }

  // Cross every normalized-offset-cell boundary at -1/0/+1 in every length cell.
  for (let lengthCell = 0; lengthCell < plan.lengthCells; lengthCell += 1) {
    const [lengthLow, lengthHigh] = lengthCellBounds(lengthCell);
    const proofLength = Math.floor((lengthLow + lengthHigh) / 2);
    for (let cell = 0; cell <= plan.normalizedOffsetCells; cell += 1) {
      const boundary = ceilRatio(cell * proofLength, plan.normalizedOffsetCells);
      for (const offset of [boundary - 1, boundary, boundary + 1]) add(proofLength, offset);
    }
  }

  // Recheck every authenticated carrier boundary at -1/0/+1 at the midpoint.
  const middleLength = Math.floor((plan.minimumProofBytes + plan.maximumProofBytes) / 2);
  for (let boundaryIndex = 0; boundaryIndex <= plan.carrierCount; boundaryIndex += 1) {
    const boundary = v17AffineBoundary(allocation, middleLength, boundaryIndex);
    for (const offset of [boundary - 1, boundary, boundary + 1]) add(middleLength, offset);
  }

  // Explicit minimum/middle/maximum lengths and all production read widths.
  const widths = [...new Set([
    1, 4, 16, 32, 36, 4_474, ...LOCAL_WORD_MATRIX_ROW_WIDTHS,
  ])];
  for (const proofLength of [
    plan.minimumProofBytes,
    middleLength,
    plan.maximumProofBytes,
  ]) {
    add(proofLength, 0);
    add(proofLength, Math.floor(proofLength / 2));
    add(proofLength, proofLength - 1);
    const crossingBoundary = v17AffineBoundary(allocation, proofLength, 100);
    for (const width of widths) {
      add(proofLength, Math.max(0, crossingBoundary - Math.floor(width / 3)), width);
    }
  }
  return [...cases.values()];
}

function recomputeMaximumInterval(planCandidate: V17AffineReaderPlan): number {
  return Math.max(...planCandidate.intervals.map((interval) =>
    interval.highCarrier - interval.lowCarrier + 1));
}

describe("v17 allocation-specialized affine reader VM", () => {
  it("matches the generic VM reader across every plan cell and critical boundary", () => {
    const cases = canonicalCases();
    const fixtures = new Map<number, ReaderFixture>();
    let specializedCost = 0;
    let genericCost = 0;
    let maximumSpecializedCost = 0;
    let maximumGenericCost = 0;
    let minimumOperationCostSaved = Number.POSITIVE_INFINITY;
    let maximumOperationCostSaved = Number.NEGATIVE_INFINITY;
    for (const testCase of cases) {
      let fixture = fixtures.get(testCase.proofLength);
      if (fixture === undefined) {
        fixture = readerFixture(testCase.proofLength);
        fixtures.set(testCase.proofLength, fixture);
      }
      const fast = evaluateRead({ fixture, gate: specializedGate, ...testCase });
      const generic = evaluateRead({ fixture, gate: genericGate, ...testCase });
      assert.equal(fast.ok, true,
        `specialized ${testCase.proofLength}:${testCase.proofOffset}:${testCase.width} ${String(fast.error)}`);
      assert.equal(generic.ok, true,
        `generic ${testCase.proofLength}:${testCase.proofOffset}:${testCase.width} ${String(generic.error)}`);
      specializedCost += fast.operationCost;
      genericCost += generic.operationCost;
      maximumSpecializedCost = Math.max(maximumSpecializedCost, fast.operationCost);
      maximumGenericCost = Math.max(maximumGenericCost, generic.operationCost);
      minimumOperationCostSaved = Math.min(
        minimumOperationCostSaved,
        generic.operationCost - fast.operationCost,
      );
      maximumOperationCostSaved = Math.max(
        maximumOperationCostSaved,
        generic.operationCost - fast.operationCost,
      );
    }
    assert.ok(cases.length > 1_000);
    assert.ok(genericCost > specializedCost);
    console.log(JSON.stringify({
      affineReaderVm: {
        cases: cases.length,
        tableBytes: specialized.intervalTableBytes.length,
        specializedBytecode: specialized.bytecode.length,
        genericBytecode: compile(genericAssembly).length,
        averageSpecializedOperationCost: Math.round(specializedCost / cases.length),
        averageGenericOperationCost: Math.round(genericCost / cases.length),
        averageOperationCostSaved: Math.round((genericCost - specializedCost) / cases.length),
        minimumOperationCostSaved,
        maximumOperationCostSaved,
        maximumSpecializedOperationCost: maximumSpecializedCost,
        maximumGenericOperationCost: maximumGenericCost,
      },
    }));
  });

  it("extracts one and many consecutive carriers at every production width", () => {
    const fixture = readerFixture(plan.maximumProofBytes);
    const widths = [...new Set([1, 4, 16, 32, 36, 4_474, ...LOCAL_WORD_MATRIX_ROW_WIDTHS])];
    const boundary = v17AffineBoundary(allocation, fixture.proof.length, 100);
    for (const width of widths) {
      for (const offset of [boundary + 7, boundary - Math.floor(width / 2)]) {
        const result = evaluateRead({
          fixture,
          gate: specializedGate,
          proofOffset: offset,
          width,
        });
        assert.equal(result.ok, true, `${offset}:${width}:${String(result.error)}`);
      }
    }
  });

  it("rejects invalid bounds and authenticated allocation/rank mutations", () => {
    const fixture = readerFixture(plan.maximumProofBytes);
    const boundaryIndex = 100;
    const boundary = v17AffineBoundary(allocation, fixture.proof.length, boundaryIndex);
    const valid = evaluateRead({
      fixture,
      gate: specializedGate,
      proofOffset: boundary + 1,
      width: 36,
    });
    assert.equal(valid.ok, true, String(valid.error));

    const wrongOrigin = evaluateRead({
      fixture,
      gate: specializedGate,
      proofOffset: boundary + 1,
      width: 36,
      mutate: (base) => {
        const changed = structuredClone(base);
        changed.sourceOutputs[1]!.valueSatoshis += 1n;
        return changed;
      },
    });
    assert.equal(wrongOrigin.ok, false);

    const wrongBoundary = evaluateRead({
      fixture,
      gate: specializedGate,
      proofOffset: boundary + 1,
      width: 36,
      mutate: (base) => {
        const changed = structuredClone(base);
        changed.transaction.inputs[boundaryIndex]!.sequenceNumber += 1;
        return changed;
      },
    });
    assert.equal(wrongBoundary.ok, false);

    const wrongRank = evaluateRead({
      fixture,
      gate: specializedGate,
      proofOffset: boundary - 8,
      width: 36,
      mutate: (base) => {
        const changed = structuredClone(base);
        const left = changed.transaction.inputs[boundaryIndex - 1]!.unlockingBytecode;
        changed.transaction.inputs[boundaryIndex - 1]!.unlockingBytecode =
          changed.transaction.inputs[boundaryIndex]!.unlockingBytecode;
        changed.transaction.inputs[boundaryIndex]!.unlockingBytecode = left;
        return changed;
      },
    });
    assert.equal(wrongRank.ok, false);

    for (const [proofOffset, width] of [
      [-1, 1],
      [0, 0],
      [fixture.proof.length - 3, 4],
      [0, 10_001],
    ] as const) {
      const result = evaluateRead({ fixture, gate: specializedGate, proofOffset, width });
      assert.equal(result.ok, false, `bounds ${proofOffset}:${width}`);
    }
  });

  it("binds a mutated plan to different code and rechecks its false bracket", () => {
    const fixture = readerFixture(Math.floor(
      (plan.minimumProofBytes + plan.maximumProofBytes) / 2,
    ));
    const proofOffset = Math.floor(fixture.proof.length * 7 / 13);
    const interval = v17AffineReaderPlanInterval(plan, fixture.proof.length, proofOffset);
    const exact = locateV17AffineReaderCarrier(allocation, fixture.proof.length, proofOffset);
    const wrong = exact === 0 ? 1 : exact - 1;
    const intervalIndex = interval.lengthCell * plan.normalizedOffsetCells +
      interval.normalizedOffsetCell;
    const changedIntervals = plan.intervals.map((candidate, index) => index === intervalIndex
      ? Object.freeze({ ...candidate, lowCarrier: wrong, highCarrier: wrong })
      : candidate);
    const candidate = {
      ...plan,
      intervals: Object.freeze(changedIntervals),
      maximumIntervalCarriers: 0,
    } satisfies V17AffineReaderPlan;
    const mutatedPlan = Object.freeze({
      ...candidate,
      maximumIntervalCarriers: recomputeMaximumInterval(candidate),
    });
    const mutated = compileV17AffineReaderVm(mutatedPlan);
    assert.notEqual(v17AffineReaderPlanDigestHex(mutatedPlan), specialized.planDigestHex);
    assert.notDeepEqual(v17AffineReaderIntervalTable(mutatedPlan), specialized.intervalTableBytes);
    assert.notDeepEqual(mutated.bytecode, specialized.bytecode);

    const mutatedGate = compile(`OP_TOALTSTACK <3> OP_ROLL OP_DROP
${mutated.assembly}
OP_NIP OP_SHA256 OP_FROMALTSTACK OP_EQUAL`);
    const result = evaluateRead({ fixture, gate: mutatedGate, proofOffset, width: 32 });
    assert.equal(result.ok, false);
  });
});

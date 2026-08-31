import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  binToHex,
  cashAssemblyToBin,
  createInstructionSetBch2026,
  createVirtualMachine,
} from "@bitauth/libauth";
import { M31, add as mAdd } from "../src/backends/circle/m31.ts";
import {
  LOCAL_WORD_PRODUCTION_PARAMETERS,
} from "../src/backends/circle/local-word-successor-params.ts";
import {
  successorCirclePointAtBitReversed,
  successorLineXAtBitReversed,
} from "../src/backends/circle/successor-domain.ts";
import {
  QM31_ONE,
  qm31,
  qmAdd,
  qmEq,
  qmInv,
  qmMul,
  type QM31El,
} from "../src/backends/circle/qm31.ts";
import {
  V17_FRI_CURRENT_DENOMINATOR_COUNT,
  foldFriFourWayFused,
  foldFriQueryBatched,
  foldFriQueryLegacy,
  invertQm31Batch,
  v17Qm31BatchInversionCounts,
  type V17FriFoldLayer,
} from "../src/backends/circle/v17-fri-arithmetic.ts";
import { M31_INV } from "../src/chain/m31-asm.ts";
import {
  compileV17FriInversionMeterLock,
  createV17FriArithmeticVmCertificate,
  v17M31BatchInverseAssembly,
} from "../src/chain/v17-fri-arithmetic-vm.ts";

const PROFILES = [0, 1, 2] as const;
const DOMAIN_MASK = 2 ** LOCAL_WORD_PRODUCTION_PARAMETERS.evalLog - 1;

function deterministicFelt(...coordinates: readonly number[]): bigint {
  let state = 0x9e3779b97f4a7c15n;
  for (const coordinate of coordinates) {
    state ^= BigInt(coordinate + 1) * 0xbf58476d1ce4e5b9n;
    state = (state ^ (state >> 30n)) * 0x94d049bb133111ebn;
    state ^= state >> 31n;
  }
  return ((state % (M31 - 1n)) + (M31 - 1n)) % (M31 - 1n) + 1n;
}

function deterministicQm31(...coordinates: readonly number[]): QM31El {
  return qm31(
    deterministicFelt(...coordinates, 0),
    deterministicFelt(...coordinates, 1),
    deterministicFelt(...coordinates, 2),
    deterministicFelt(...coordinates, 3),
  );
}

function queryLayers(profile: 0 | 1 | 2, queryOrdinal: number): readonly V17FriFoldLayer[] {
  let position = (0x51f15 + profile * 0x1f123 + queryOrdinal * 0x2c927) & DOMAIN_MASK;
  let completedFolds = 0;
  return Array.from({ length: 9 }, (_, layer): V17FriFoldLayer => {
    const folds = layer === 8 ? 1 : 2;
    const arity = 2 ** folds;
    const base = position & ~(arity - 1);
    const twiddleAt = (totalFold: number, pairBase: number): bigint => totalFold === 0
      ? successorCirclePointAtBitReversed(24, pairBase).y
      : successorLineXAtBitReversed(24 - totalFold, pairBase);
    const alphas = Array.from({ length: folds }, (_, subfold) =>
      deterministicQm31(profile, queryOrdinal, layer, subfold, 97));
    const values = Array.from({ length: arity }, (_, value) =>
      deterministicQm31(profile, queryOrdinal, layer, value, 193));
    if (folds === 2) {
      const twiddles = [
        twiddleAt(completedFolds, base),
        twiddleAt(completedFolds, base + 2),
        twiddleAt(completedFolds + 1, base >> 1),
      ] as const;
      position >>= folds;
      completedFolds += folds;
      return {
        folds: 2,
        values: values as [QM31El, QM31El, QM31El, QM31El],
        twiddles,
        alphas: alphas as [QM31El, QM31El],
      };
    }
    const twiddles = [twiddleAt(completedFolds, base)] as const;
    position >>= folds;
    completedFolds += folds;
    return { folds: 1, values: values as [QM31El, QM31El], twiddles, alphas: alphas as [QM31El] };
  });
}

function allEqual(left: readonly QM31El[], right: readonly QM31El[]): boolean {
  return left.length === right.length && left.every((value, index) => qmEq(value, right[index]!));
}

function mutateLayerValue(layers: readonly V17FriFoldLayer[]): readonly V17FriFoldLayer[] {
  return layers.map((layer, index) => index === 0
    ? {
      ...layer,
      values: layer.values.map((value, valueIndex) => valueIndex === 0
        ? qm31(mAdd(value[0], 1n), value[1], value[2], value[3])
        : value) as unknown as V17FriFoldLayer["values"],
    } as V17FriFoldLayer
    : layer);
}

function mutateLayerTwiddle(
  layers: readonly V17FriFoldLayer[],
  flatIndex: number,
  replacement?: bigint,
): readonly V17FriFoldLayer[] {
  let cursor = 0;
  return layers.map((layer) => {
    const next = cursor + layer.twiddles.length;
    if (flatIndex < cursor || flatIndex >= next) {
      cursor = next;
      return layer;
    }
    const local = flatIndex - cursor;
    cursor = next;
    const twiddles = layer.twiddles.map((twiddle, index) => index === local
      ? replacement ?? (twiddle === M31 - 1n ? 1n : twiddle + 1n)
      : twiddle);
    return (layer.twiddles.length === 3
      ? { ...layer, twiddles: twiddles as [bigint, bigint, bigint] }
      : { ...layer, twiddles: twiddles as [bigint] }) as V17FriFoldLayer;
  });
}

function mutateLayerAlpha(layers: readonly V17FriFoldLayer[]): readonly V17FriFoldLayer[] {
  return layers.map((layer, index) => index === 4
    ? {
      ...layer,
      alphas: layer.alphas.map((alpha, subfold) =>
        subfold === layer.alphas.length - 1 ? qmAdd(alpha, QM31_ONE) : alpha) as
        unknown as V17FriFoldLayer["alphas"],
    } as V17FriFoldLayer
    : layer);
}

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

function evaluateLock(lockingBytecode: Uint8Array) {
  const vm = unboundedVm();
  const sourceOutputs = [{ lockingBytecode, valueSatoshis: 1_000n }];
  const transaction = {
    version: 2,
    locktime: 0,
    inputs: [{
      outpointTransactionHash: new Uint8Array(32).fill(1),
      outpointIndex: 0,
      sequenceNumber: 0xffff_fffen,
      unlockingBytecode: new Uint8Array(),
    }],
    outputs: [{ lockingBytecode: Uint8Array.of(0x51), valueSatoshis: 1_000n }],
  };
  const state = vm.evaluate({ inputIndex: 0, sourceOutputs, transaction } as never);
  return { vm, state };
}

function compileRaw(assembly: string): Uint8Array {
  const result = cashAssemblyToBin(assembly);
  if (typeof result === "string") throw new Error(result);
  return result;
}

describe("v17 pure verifier-derived FRI arithmetic", () => {
  it("batch-inverts 25+ QM31 denominators with the exact prefix/suffix schedule", () => {
    for (const count of [25, 29, 41]) {
      const denominators = Array.from({ length: count }, (_, index) =>
        deterministicQm31(count, index, 313));
      const batched = invertQm31Batch(denominators);
      const legacy = denominators.map(qmInv);
      assert.equal(allEqual(batched, legacy), true, `count ${count}`);
      batched.forEach((inverse, index) =>
        assert.equal(qmEq(qmMul(denominators[index]!, inverse), QM31_ONE), true));
      assert.deepEqual(v17Qm31BatchInversionCounts(count), {
        denominators: count,
        qm31Inversions: 1,
        qm31Multiplications: 3 * (count - 1),
      });
    }

    assert.throws(() => invertQm31Batch([]), /at least one denominator/);
    for (const zeroAt of [0, 12, 24]) {
      const denominators = Array.from({ length: 25 }, (_, index) =>
        index === zeroAt ? qm31(0n, 0n, 0n, 0n) : deterministicQm31(index, 419));
      assert.throws(() => invertQm31Batch(denominators), new RegExp(`zero QM31 denominator at ${zeroAt}`));
    }
  });

  it("matches every legacy fold under 17 independent challenges for all queries and profiles", () => {
    let checked = 0;
    for (const profile of PROFILES) {
      for (let query = 0; query < LOCAL_WORD_PRODUCTION_PARAMETERS.fri.queries; query += 1) {
        const layers = queryLayers(profile, query);
        const denominatorCount = layers.reduce((total, layer) => total + layer.twiddles.length, 0);
        assert.equal(denominatorCount, V17_FRI_CURRENT_DENOMINATOR_COUNT);
        const legacy = foldFriQueryLegacy(layers);
        const batched = foldFriQueryBatched(layers);
        assert.equal(allEqual(batched, legacy), true, `profile ${profile}, query ${query}`);
        const first = layers[0]!;
        assert.equal(first.values.length, 4);
        if (first.folds === 2) {
          assert.equal(qmEq(
            foldFriFourWayFused(first.values, first.twiddles, first.alphas),
            legacy[0]!,
          ), true);
        }
        checked += 1;
      }
    }
    assert.equal(checked, LOCAL_WORD_PRODUCTION_PARAMETERS.fri.queries * PROFILES.length);
  });

  it("rejects zero twiddles and reacts to values, twiddles, and challenges", () => {
    const layers = queryLayers(2, 17);
    const honest = foldFriQueryBatched(layers);
    assert.equal(allEqual(foldFriQueryBatched(mutateLayerValue(layers)), honest), false);
    assert.equal(allEqual(foldFriQueryBatched(mutateLayerTwiddle(layers, 8)), honest), false);
    assert.equal(allEqual(foldFriQueryBatched(mutateLayerAlpha(layers)), honest), false);
    for (const zeroAt of [0, 12, 24]) {
      assert.throws(
        () => foldFriQueryBatched(mutateLayerTwiddle(layers, zeroAt, 0n)),
        new RegExp(`zero QM31 denominator at ${zeroAt}`),
      );
    }
  });

  it("executes and meters the legacy and one-inversion BCH lowerings", () => {
    const denominators = queryLayers(0, 0).flatMap((layer) => [...layer.twiddles]);
    const legacyLock = compileV17FriInversionMeterLock(denominators, "legacy");
    const batchLock = compileV17FriInversionMeterLock(denominators, "batch");
    const legacy = evaluateLock(legacyLock);
    const batch = evaluateLock(batchLock);
    assert.equal(legacy.vm.stateSuccess(legacy.state), true, String(legacy.state.error));
    assert.equal(batch.vm.stateSuccess(batch.state), true, String(batch.state.error));

    const legacyCost = Number(legacy.state.metrics.operationCost);
    const batchCost = Number(batch.state.metrics.operationCost);
    const certificate = createV17FriArithmeticVmCertificate();
    assert.equal(certificate.denominators, 25);
    assert.equal(certificate.legacy.m31Inversions, 25);
    assert.equal(certificate.batched.m31Inversions, 1);
    assert.equal(certificate.batched.batchProductMultiplications, 72);
    assert.equal(certificate.proofSuppliedInverseBytes, 0);
    assert.equal(certificate.commonFoldCore.independentChallenges, 17);
    assert.deepEqual(certificate.productionRoleTarget, {
      bch2026Roles: LOCAL_WORD_PRODUCTION_PARAMETERS.fri.queries * PROFILES.length,
      profiles: 3,
      queriesPerProfile: LOCAL_WORD_PRODUCTION_PARAMETERS.fri.queries,
      differentialLegacyOracle: true,
    });
    assert.ok(batchCost < legacyCost);
    console.log("v17-fri-inversion-meter", JSON.stringify({
      denominators: denominators.length,
      legacyLockingBytes: legacyLock.length,
      batchLockingBytes: batchLock.length,
      legacyOperationCost: legacyCost,
      batchOperationCost: batchCost,
      operationCostSaved: legacyCost - batchCost,
      proofSuppliedInverseBytes: certificate.proofSuppliedInverseBytes,
      productionRoleTarget: certificate.productionRoleTarget,
    }));
  });

  it("rejects a zero inside the emitted BCH batch before inversion", () => {
    const denominators = Array.from({ length: 25 }, (_, index) => index === 7 ? 0n : BigInt(index + 2));
    const inverseBytecode = compileRaw(M31_INV);
    const lock = compileRaw(`<0x${binToHex(inverseBytecode)}> <0> OP_DEFINE
${denominators.map((value) => `<${value}>`).join("\n")}
${v17M31BatchInverseAssembly(25, "<0> OP_INVOKE")}
OP_1`);
    const rejected = evaluateLock(lock);
    assert.notEqual(rejected.vm.stateSuccess(rejected.state), true);
  });
});

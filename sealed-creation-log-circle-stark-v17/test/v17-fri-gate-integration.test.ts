import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  createInstructionSetBch2026,
  createVirtualMachine,
} from "@bitauth/libauth";
import { inv as mInv } from "../src/backends/circle/m31.ts";
import {
  LOCAL_WORD_MATRIX_NAMES,
  LOCAL_WORD_PROOF_LENGTH_OFFSET,
  LOCAL_WORD_PROOF_VERSION,
  localWordProofStaticOffsets,
} from "../src/backends/circle/local-word-sealed-proof.ts";
import { LOCAL_WORD_PRODUCTION_PARAMETERS } from
  "../src/backends/circle/local-word-successor-params.ts";
import { V17_MAXIMUM_CANONICAL_PROOF_BYTES } from "../src/construction/v17-graph.ts";
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
  compileLocalWordFriFoldGate,
} from "../src/chain/local-word-algebra-vm.ts";
import {
  compileLocalWordCarrierRedeem,
  encodeLocalWordP2shCarrierUnlocking,
  localWordP2sh32Lock,
  localWordPoolCarrierSequence,
  localWordVerifierCarrierSequence,
  localWordVerifierCarrierValue,
  partitionLocalWordProofBytes,
} from "../src/chain/local-word-proof-carriers.ts";
import { LOCAL_WORD_CANONICAL_ROLE_NAMES } from
  "../src/chain/local-word-carrier-allocation.ts";
import { compileLocalWordProductionFriFoldGate } from
  "../src/chain/local-word-role-manifest.ts";
import { createV17FriArithmeticVmCertificate } from
  "../src/chain/v17-fri-arithmetic-vm.ts";
import { concatBytes, writeU32BE } from "../src/pool/bytes.ts";
import { censusV17OpDefineBodies } from "../src/construction/v17-linker.ts";

const PROOF_BYTES = V17_MAXIMUM_CANONICAL_PROOF_BYTES;
const PROFILES = [0, 1, 2] as const;

type Fixture = {
  readonly proof: Uint8Array;
  readonly mutations: readonly number[];
};

function foldPair(left: QM31El, right: QM31El, twiddle: bigint, alpha: QM31El): QM31El {
  return qmAdd(
    qmAdd(left, right),
    qmMul(alpha, qmMulM31(qmSub(left, right), mInv(twiddle))),
  );
}

function fixture(profile: 0 | 1 | 2, queryOrdinal: number): Fixture {
  const parameters = LOCAL_WORD_PRODUCTION_PARAMETERS;
  const offsets = localWordProofStaticOffsets(8, parameters);
  const proof = new Uint8Array(PROOF_BYTES);
  proof.set(new TextEncoder().encode("SKLW"), 0);
  proof[4] = LOCAL_WORD_PROOF_VERSION;
  proof[5] = profile;
  proof.set(writeU32BE(proof.length), LOCAL_WORD_PROOF_LENGTH_OFFSET);

  const queryPosition = (777_710 + profile * 131_071 + queryOrdinal * 524_287) &
    (2 ** parameters.evalLog - 1);
  proof.set(writeU32BE(queryPosition), offsets.queries + queryOrdinal * 4);
  const alphas = Array.from({ length: 9 }, (_, layer) =>
    Array.from({ length: layer === 8 ? 1 : 2 }, (_, subfold) => qm31(
      BigInt(701 + profile * 31 + queryOrdinal * 11 + layer * 3 + subfold),
      BigInt(733 + profile * 37 + queryOrdinal * 13 + layer * 5 + subfold),
      BigInt(761 + profile * 41 + queryOrdinal * 17 + layer * 7 + subfold),
      BigInt(797 + profile * 43 + queryOrdinal * 19 + layer * 11 + subfold),
    )));
  alphas.flat().forEach((alpha, challenge) =>
    proof.set(encodeQm31(alpha), offsets.friAlphas + challenge * 16));

  const rows = Array.from({ length: 9 }, (_, layer) => 130_000 + layer * 1_000);
  let position = queryPosition;
  let completedFolds = 0;
  let expected: QM31El | undefined;
  let firstLinkOffset = 0;
  for (let layer = 0; layer < 9; layer += 1) {
    const folds = layer === 8 ? 1 : 2;
    const arity = 2 ** folds;
    const base = position & ~(arity - 1);
    const values = Array.from({ length: arity }, (_, value) => qm31(
      BigInt(809 + profile * 47 + queryOrdinal * 23 + layer * 37 + value),
      BigInt(911 + profile * 53 + queryOrdinal * 29 + layer * 41 + value),
      BigInt(1_009 + profile * 59 + queryOrdinal * 31 + layer * 43 + value),
      BigInt(1_103 + profile * 61 + queryOrdinal * 37 + layer * 47 + value),
    ));
    if (expected) {
      const exact = position % arity;
      values[exact] = expected;
      if (layer === 1) firstLinkOffset = rows[layer]! + exact * 16;
    }
    proof.set(concatBytes(...values.map(encodeQm31)), rows[layer]);
    proof[offsets.friCosetRanks + layer * parameters.fri.queries + queryOrdinal] = 0;
    proof.set(
      writeU32BE(rows[layer]!),
      offsets.openingDirectory + (LOCAL_WORD_MATRIX_NAMES.length + layer) * 20 + 4,
    );

    let folded = values;
    for (let subfold = 0; subfold < folds; subfold += 1) {
      const challenge = alphas[layer]![subfold]!;
      folded = Array.from({ length: folded.length / 2 }, (_, pair) => {
        const pairBase = (base >> subfold) + pair * 2;
        const totalFold = completedFolds + subfold;
        const twiddle = totalFold === 0
          ? successorCirclePointAtBitReversed(parameters.evalLog, pairBase).y
          : successorLineXAtBitReversed(parameters.evalLog - totalFold, pairBase);
        return foldPair(folded[pair * 2]!, folded[pair * 2 + 1]!, twiddle, challenge);
      });
    }
    expected = folded[0]!;
    position >>= folds;
    completedFolds += folds;
  }
  assert.equal(completedFolds, parameters.fri.queryOrbitLog);
  proof.set(encodeQm31(expected!), offsets.finalCoefficients);
  for (let coefficient = 1; coefficient < offsets.finalCoefficientCount; coefficient += 1) {
    proof.set(encodeQm31(QM31_ZERO), offsets.finalCoefficients + coefficient * 16);
  }
  return {
    proof,
    mutations: [
      rows[0]!,
      offsets.friAlphas + (queryOrdinal % 17) * 16,
      firstLinkOffset,
      offsets.finalCoefficients,
    ],
  };
}

function evaluateProduction(proof: Uint8Array, verifier: Uint8Array, query: number) {
  const carriers = partitionLocalWordProofBytes(proof);
  const local = LOCAL_WORD_CANONICAL_ROLE_NAMES.indexOf(`fri-fold-query:${query}`);
  assert.notEqual(local, -1);
  const inputIndex = local + 1;
  const redeem = compileLocalWordCarrierRedeem({ index: inputIndex, verifier });
  const lockingBytecode = localWordP2sh32Lock(redeem);
  const transaction = {
    version: 2,
    locktime: 0,
    inputs: carriers.map((carrier, input) => ({
      outpointTransactionHash: new Uint8Array(32).fill((input + 1) & 0xff),
      outpointIndex: input,
      sequenceNumber: input === 0
        ? localWordPoolCarrierSequence(proof.length)
        : localWordVerifierCarrierSequence(input),
      unlockingBytecode: input === inputIndex
        ? encodeLocalWordP2shCarrierUnlocking(carrier.chunk, redeem)
        : carrier.unlockingBytecode,
    })),
    outputs: [{ lockingBytecode: Uint8Array.of(0x51), valueSatoshis: 128_000n }],
  };
  // This differential test owns semantic equivalence and exact metering. The
  // retained-proof fixed-point and BCHN gates separately own density limits.
  const instructionSet = createInstructionSetBch2026(false);
  const every = instructionSet.every!;
  const vm = createVirtualMachine({
    ...instructionSet,
    every: (state) => {
      state.metrics.maximumOperationCost = 1_000_000_000;
      return every(state);
    },
  });
  const sourceOutputs = carriers.map((_, index) => ({
    lockingBytecode,
    valueSatoshis: index === 0 ? 1_000n : localWordVerifierCarrierValue(index),
  }));
  transaction.outputs = sourceOutputs.map((output) => ({ ...output }));
  const state = vm.evaluate({ inputIndex, sourceOutputs, transaction } as never);
  return {
    vm,
    state,
    redeemBytes: redeem.length,
    unlockingBytes: transaction.inputs[inputIndex]!.unlockingBytecode.length,
  };
}

function changed(proof: Uint8Array, offset: number): Uint8Array {
  const mutation = proof.slice();
  mutation[offset] ^= 1;
  return mutation;
}

describe("v17 production FRI role integration", () => {
  it("owns one shared initializer and one execution-local orchestrator for all roles", () => {
    const initializers = PROFILES.flatMap((profile) =>
      Array.from({ length: LOCAL_WORD_PRODUCTION_PARAMETERS.fri.queries }, (_, query) => {
        const gate = compileLocalWordProductionFriFoldGate({ profile, query });
        const census = censusV17OpDefineBodies(gate);
        const topLevel = census.filter(({ depth }) => depth === 0);
        assert.equal(topLevel.length, 2, `${profile}:${query} top-level definitions`);
        assert.equal(topLevel[0]!.functionIdHex, "1e", `${profile}:${query} outer id`);
        assert.equal(topLevel[0]!.body.length, 2_619, `${profile}:${query} shared bytes`);
        assert.equal(topLevel[1]!.functionIdHex, "23", `${profile}:${query} local id`);
        assert.equal(topLevel[1]!.body.length, 4_107, `${profile}:${query} local bytes`);
        assert.ok(census.filter(({ depth }) => depth === 1).length > 1,
          `${profile}:${query} nested helpers`);
        assert.ok(census.every(({ depth }) => depth <= 1), `${profile}:${query} control depth`);
        assert.ok(gate.length < 10_000, `${profile}:${query} gate bytes`);
        return topLevel[0]!;
      }));
    assert.equal(initializers.length, 3 * 44);
    assert.equal(new Set(initializers.map(({ bodySha256Hex }) => bodySha256Hex)).size, 1);
    assert.equal(new Set(initializers.map(({ body }) => body.length)).size, 1);
  });

  it("differentially accepts and rejects, then meters every profile/query role", () => {
    const parameters = LOCAL_WORD_PRODUCTION_PARAMETERS;
    const legacyLocks = Array.from({ length: parameters.fri.queries }, (_, query) =>
      compileLocalWordFriFoldGate({ profile: 0, query }));
    const v17Locks = Array.from({ length: parameters.fri.queries }, (_, query) =>
      compileLocalWordProductionFriFoldGate({ profile: 0, query }));
    const measurements: {
      profile: number;
      query: number;
      legacyOperationCost: number;
      v17OperationCost: number;
      savedOperationCost: number;
      v17RedeemBytes: number;
      v17UnlockingBytes: number;
    }[] = [];

    for (const profile of PROFILES) {
      for (let query = 0; query < parameters.fri.queries; query += 1) {
        const built = fixture(profile, query);
        const legacy = evaluateProduction(built.proof, legacyLocks[query]!, query);
        const v17 = evaluateProduction(built.proof, v17Locks[query]!, query);
        assert.equal(legacy.vm.stateSuccess(legacy.state), true,
          `legacy profile ${profile}, query ${query}: ${String(legacy.state.error)} ` +
          `ip=${legacy.state.ip} stack=${JSON.stringify(legacy.state.stack.slice(-8)
            .map((item) => Buffer.from(item).toString("hex")))}`);
        assert.equal(v17.vm.stateSuccess(v17.state), true,
          `v17 profile ${profile}, query ${query}: ${String(v17.state.error)}`);

        const mutation = changed(built.proof, built.mutations[(profile * parameters.fri.queries + query) % 4]!);
        const legacyRejected = evaluateProduction(mutation, legacyLocks[query]!, query);
        const v17Rejected = evaluateProduction(mutation, v17Locks[query]!, query);
        assert.notEqual(legacyRejected.vm.stateSuccess(legacyRejected.state), true,
          `legacy mutation profile ${profile}, query ${query}`);
        assert.notEqual(v17Rejected.vm.stateSuccess(v17Rejected.state), true,
          `v17 mutation profile ${profile}, query ${query}`);

        const legacyOperationCost = Number(legacy.state.metrics.operationCost);
        const v17OperationCost = Number(v17.state.metrics.operationCost);
        assert.ok(v17OperationCost < legacyOperationCost, `opcost profile ${profile}, query ${query}`);
        measurements.push({
          profile,
          query,
          legacyOperationCost,
          v17OperationCost,
          savedOperationCost: legacyOperationCost - v17OperationCost,
          v17RedeemBytes: v17.redeemBytes,
          v17UnlockingBytes: v17.unlockingBytes,
        });
      }
    }

    assert.equal(measurements.length, parameters.fri.queries * PROFILES.length);
    assert.equal(
      measurements.length,
      createV17FriArithmeticVmCertificate().productionRoleTarget.bch2026Roles,
    );
    const saved = measurements.map((measurement) => measurement.savedOperationCost);
    const legacyCosts = measurements.map((measurement) => measurement.legacyOperationCost);
    const v17Costs = measurements.map((measurement) => measurement.v17OperationCost);
    console.log("v17-fri-production-role-meter", JSON.stringify({
      roles: measurements.length,
      legacyLockingBytes: {
        minimum: Math.min(...legacyLocks.map((lock) => lock.length)),
        maximum: Math.max(...legacyLocks.map((lock) => lock.length)),
      },
      v17LockingBytes: {
        minimum: Math.min(...v17Locks.map((lock) => lock.length)),
        maximum: Math.max(...v17Locks.map((lock) => lock.length)),
      },
      minimumSavedOperationCost: Math.min(...saved),
      maximumSavedOperationCost: Math.max(...saved),
      totalSavedOperationCost: saved.reduce((total, value) => total + value, 0),
      legacyOperationCost: {
        minimum: Math.min(...legacyCosts),
        maximum: Math.max(...legacyCosts),
        total: legacyCosts.reduce((total, value) => total + value, 0),
      },
      v17OperationCost: {
        minimum: Math.min(...v17Costs),
        maximum: Math.max(...v17Costs),
        total: v17Costs.reduce((total, value) => total + value, 0),
      },
      maximumV17RedeemBytes: Math.max(...measurements.map((measurement) => measurement.v17RedeemBytes)),
      maximumV17UnlockingBytes: Math.max(...measurements.map((measurement) => measurement.v17UnlockingBytes)),
    }));
  });
});

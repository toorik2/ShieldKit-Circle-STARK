import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  createVirtualMachineBch2026,
  createInstructionSetBch2026,
  createVirtualMachine,
  decodeAuthenticationInstructions,
  OpcodesBch,
} from "@bitauth/libauth";
import {
  encodeV17MerkleCutFrontiers,
  v17MerkleCutFrontiers,
  v17MerkleOpeningRoot,
  v17MerkleSchedule,
  type V17MerkleDescriptor,
} from "../src/backends/circle/v17-merkle.ts";
import {
  LOCAL_WORD_MATRIX_NAMES,
  LOCAL_WORD_MATRIX_ROW_WIDTHS,
  LOCAL_WORD_PROOF_LENGTH_OFFSET,
  LOCAL_WORD_PROOF_VERSION,
  localWordOpeningSchedules,
  localWordProofStaticOffsets,
  localWordV17FriMerkleDescriptor,
  localWordV17MerkleCuts,
  localWordV17MatrixMerkleDescriptor,
  type LocalWordMatrixName,
} from "../src/backends/circle/local-word-sealed-proof.ts";
import type { LocalWordProofParameters } from
  "../src/backends/circle/local-word-successor-params.ts";
import { LOCAL_WORD_PRODUCTION_PARAMETERS } from
  "../src/backends/circle/local-word-successor-params.ts";
import { localWordFriLayerLogs } from
  "../src/backends/circle/local-word-successor-params.ts";
import { localWordFriFoldCounts } from
  "../src/backends/circle/local-word-successor-params.ts";
import { successorTraceOffsetIndex } from
  "../src/backends/circle/successor-domain.ts";
import { compileLocalWordOpeningScheduleGate } from
  "../src/chain/local-word-balanced-vm.ts";
import { compileLocalWordCurrentMatrixMerkleGate } from
  "../src/chain/local-word-merkle-vm.ts";
import {
  compileLocalWordInteractionLeafGate,
  compileLocalWordMerkleLeafGate,
  LOCAL_WORD_INTERACTION_LEAF_SHARDS,
} from "../src/chain/local-word-merkle-vm.ts";
import { compileLocalWordFriMerkleGate } from
  "../src/chain/local-word-merkle-vm.ts";
import {
  compileLocalWordCarrierRedeem,
  encodeLocalWordP2shCarrierUnlocking,
  localWordVerifierCarrierValue,
  localWordVerifierCarrierSequence,
  localWordPoolCarrierSequence,
  localWordP2sh32Lock,
  partitionLocalWordProofBytes,
} from "../src/chain/local-word-proof-carriers.ts";
import { writeU32BE } from "../src/pool/bytes.ts";

const PARAMETERS: LocalWordProofParameters = {
  relationLog: 6,
  evalLog: 10,
  quotientDegreeRows: 1 << 6,
  fri: {
    logBlowup: 4,
    finalLogDegree: 3,
    foldLog: 2,
    queryOrbitLog: 3,
    queries: 8,
    grindBits: 0,
  },
};

const PRODUCTION_PUBLIC_WORDS = 8;

function rootForOpening(
  descriptor: V17MerkleDescriptor,
  indices: readonly number[],
  rows: readonly Uint8Array[],
  siblings: readonly Uint8Array[],
  cutBits: readonly number[],
): {
  readonly root: Uint8Array;
  readonly frontiers: readonly { readonly bytes: Uint8Array; readonly siblingCount: number }[];
} {
  const openingRows = indices.map((index, position) => ({ index, raw: rows[position]! }));
  const schedule = v17MerkleSchedule(descriptor, indices);
  assert.equal(schedule.siblingCount, siblings.length);
  const siblingCountByBits = new Map<number, number>([[0, 0]]);
  let siblingCount = 0;
  schedule.levels.forEach((level) => {
    siblingCount += level.siblingIndices.length;
    siblingCountByBits.set(level.nextConsumedBits, siblingCount);
  });
  const frontiers = v17MerkleCutFrontiers({
    descriptor,
    rows: openingRows,
    siblings,
    cutBits,
  });
  return {
    root: v17MerkleOpeningRoot({ descriptor, rows: openingRows, siblings }),
    frontiers: frontiers.map((frontier) => ({
      bytes: encodeV17MerkleCutFrontiers([frontier]),
      siblingCount: siblingCountByBits.get(frontier.consumedBits)!,
    })),
  };
}

function fixtureQueries(parameters: LocalWordProofParameters): readonly number[] {
  const rowCount = 2 ** parameters.evalLog;
  const orbitSize = 2 ** parameters.fri.queryOrbitLog;
  const orbitCount = rowCount / orbitSize;
  const queries: number[] = [];
  const global = new Set<number>();
  const usedOrbits = new Set<number>();
  for (let item = 0; item < parameters.fri.queries; item += 1) {
    let found = false;
    for (let jitter = 0; jitter < orbitCount; jitter += 1) {
      const orbit = (Math.floor(item * orbitCount / parameters.fri.queries) + jitter) % orbitCount;
      if (usedOrbits.has(orbit)) continue;
      const candidate = orbit * orbitSize + ((orbit * 37 + 3) % orbitSize);
      const previous = successorTraceOffsetIndex(
        candidate,
        parameters.relationLog,
        parameters.evalLog,
        -1,
      );
      if (candidate === previous || global.has(candidate) || global.has(previous)) continue;
      queries.push(candidate);
      global.add(candidate);
      global.add(previous);
      usedOrbits.add(orbit);
      found = true;
      break;
    }
    if (!found) throw new Error("local-word fixture spread schedule");
  }
  if (queries.length !== parameters.fri.queries) throw new Error("local-word fixture schedule");
  // Keep transcript order visibly distinct from canonical sorted opening order.
  // A permutation multiplier must be coprime to the query count. In
  // particular, 11 aliases q44 into four repeated positions rather than a
  // transcript-order permutation.
  const gcd = (left: number, right: number): number =>
    right === 0 ? left : gcd(right, left % right);
  const multiplier = Array.from(
    { length: parameters.fri.queries - 2 },
    (_, item) => item + 2,
  ).find((candidate) => gcd(candidate, parameters.fri.queries) === 1)!;
  const permuted = Array.from(
    { length: queries.length },
    (_, item) => queries[(item * multiplier) % queries.length]!,
  );
  localWordOpeningSchedules(permuted, parameters);
  return permuted;
}

function fixture(
  parameters: LocalWordProofParameters,
  matrixName: LocalWordMatrixName = "quotientAndFriMask",
  invalidField?: "p" | "negative",
): {
  readonly proof: Uint8Array;
  readonly indicesStart: number;
  readonly rowsStart: number;
  readonly siblingsStart: number;
  readonly frontiers: readonly { readonly siblingCut: number; readonly start: number; readonly end: number }[];
  readonly siblingCount: number;
} {
  const matrix = LOCAL_WORD_MATRIX_NAMES.indexOf(matrixName);
  const descriptor = localWordV17MatrixMerkleDescriptor(matrixName, parameters);
  const rowWidth = descriptor.rowWidth;
  const global = matrixName === "interactionGlobal";
  const queries = fixtureQueries(parameters);
  const schedules = localWordOpeningSchedules(queries, parameters);
  const sorted = global ? schedules.global : schedules.current;
  const manifestIndices = schedules.current;
  const ranks = new Map(manifestIndices.map((query, rank) => [query, rank]));
  // Maximal canonical M31 limbs exercise the worst numeric-width cost path.
  const maximumM31 = Uint8Array.of(0xfe, 0xff, 0xff, 0x7f);
  const rows = sorted.map(() => Uint8Array.from(
    { length: rowWidth }, (_, byte) => maximumM31[byte % 4]!,
  ));
  if (invalidField !== undefined) {
    rows[0]!.set(invalidField === "p"
      ? Uint8Array.of(0xff, 0xff, 0xff, 0x7f)
      : Uint8Array.of(0, 0, 0, 0x80));
  }
  const siblingCount = v17MerkleSchedule(descriptor, sorted).siblingCount;
  const siblings = Array.from({ length: siblingCount }, (_, item) =>
    Uint8Array.from({ length: 32 }, (__, byte) => (item * 37 + byte * 11 + 5) & 0xff));
  const rowsStart = 50_000;
  const indicesStart = rowsStart;
  const siblingsStart = rowsStart + rows.length * rowWidth;
  const stageDirectoryStart = siblingsStart + siblings.length * 32;
  const opening = rootForOpening(
    descriptor,
    sorted,
    rows,
    siblings,
    localWordV17MerkleCuts({ matrix: matrixName, parameters }),
  );
  let frontierCursor = stageDirectoryStart + opening.frontiers.length * 12;
  const frontiers = opening.frontiers.map((frontier) => {
    const start = frontierCursor;
    frontierCursor += frontier.bytes.length;
    return {
      siblingCut: siblingsStart + frontier.siblingCount * 32,
      start,
      end: frontierCursor,
    };
  });
  const end = frontierCursor;
  // Production-sized carrier density gives this complete role its real BCH
  // operation-cost envelope; the unused bytes are test-only fixture space.
  const proof = new Uint8Array(Math.max(340_382, end));
  proof.set(new TextEncoder().encode("SKLW"), 0);
  proof[4] = LOCAL_WORD_PROOF_VERSION;
  proof.set(writeU32BE(proof.length), LOCAL_WORD_PROOF_LENGTH_OFFSET);
  const offsets = localWordProofStaticOffsets(PRODUCTION_PUBLIC_WORDS, parameters);
  proof.set(opening.root, offsets.matrixRoots + matrix * 32);
  queries.forEach((query, item) => {
    proof.set(writeU32BE(query), offsets.queries + item * 4);
    proof[offsets.currentRanks + item] = ranks.get(query)!;
  });
  manifestIndices.forEach((index, rank) => proof.set(writeU32BE(index), offsets.currentIndices + rank * 4));
  if (global) {
    const globalRanks = new Map(sorted.map((index, rank) => [index, rank]));
    queries.forEach((query, item) => {
      const previous = successorTraceOffsetIndex(
        query,
        parameters.relationLog,
        parameters.evalLog,
        -1,
      );
      proof[offsets.globalCurrentRanks + item] = globalRanks.get(query)!;
      proof[offsets.globalPreviousRanks + item] = globalRanks.get(previous)!;
    });
  }
  const directory = offsets.openingDirectory + matrix * 20;
  [indicesStart, rowsStart, siblingsStart, stageDirectoryStart, end].forEach((value, word) =>
    proof.set(writeU32BE(value), directory + word * 4));
  rows.forEach((row, rank) => proof.set(row, rowsStart + rank * rowWidth));
  siblings.forEach((sibling, item) => proof.set(sibling, siblingsStart + item * 32));
  frontiers.forEach((frontier, item) => {
    [frontier.siblingCut, frontier.start, frontier.end].forEach((value, word) =>
      proof.set(writeU32BE(value), stageDirectoryStart + item * 12 + word * 4));
    proof.set(opening.frontiers[item]!.bytes, frontier.start);
  });
  return { proof, indicesStart, rowsStart, siblingsStart, frontiers, siblingCount };
}

function friFixture(
  parameters: LocalWordProofParameters,
  round: number,
  invalidField?: "p" | "negative",
) {
  const queryCount = parameters.fri.queries;
  const queries = fixtureQueries(parameters);
  const indices = localWordOpeningSchedules(queries, parameters).fri[round]!;
  const descriptor = localWordV17FriMerkleDescriptor(round, parameters);
  const rowWidth = descriptor.rowWidth;
  // Maximal canonical M31 limbs exercise the worst numeric-width cost path.
  const maximumM31 = Uint8Array.of(0xfe, 0xff, 0xff, 0x7f);
  const rows = indices.map(() => Uint8Array.from(
    { length: rowWidth }, (_, byte) => maximumM31[byte % 4]!,
  ));
  if (invalidField !== undefined) {
    rows[0]!.set(invalidField === "p"
      ? Uint8Array.of(0xff, 0xff, 0xff, 0x7f)
      : Uint8Array.of(0, 0, 0, 0x80));
  }
  const siblingCount = v17MerkleSchedule(descriptor, indices).siblingCount;
  const siblings = Array.from({ length: siblingCount }, (_, item) =>
    Uint8Array.from({ length: 32 }, (__, byte) => (item * 31 + byte * 17 + round + 3) & 0xff));
  const rowsStart = 50_000;
  const indicesStart = rowsStart;
  const siblingsStart = rowsStart + rows.length * rowWidth;
  const stageDirectoryStart = siblingsStart + siblings.length * 32;
  const opening = rootForOpening(
    descriptor,
    indices,
    rows,
    siblings,
    localWordV17MerkleCuts({ friLayer: round, parameters }),
  );
  let frontierCursor = stageDirectoryStart + opening.frontiers.length * 12;
  const frontiers = opening.frontiers.map((frontier) => {
    const start = frontierCursor;
    frontierCursor += frontier.bytes.length;
    return {
      siblingCut: siblingsStart + frontier.siblingCount * 32,
      start,
      end: frontierCursor,
    };
  });
  const proof = new Uint8Array(Math.max(340_382, frontierCursor));
  proof.set(new TextEncoder().encode("SKLW"), 0);
  proof[4] = LOCAL_WORD_PROOF_VERSION;
  proof.set(writeU32BE(proof.length), LOCAL_WORD_PROOF_LENGTH_OFFSET);
  const offsets = localWordProofStaticOffsets(PRODUCTION_PUBLIC_WORDS, parameters);
  proof.set(opening.root, offsets.friRoots + round * 32);
  queries.forEach((query, item) => proof.set(writeU32BE(query), offsets.queries + item * 4));
  const foldCounts = localWordFriFoldCounts(parameters);
  const completedFolds = foldCounts.slice(0, round).reduce((sum, folds) => sum + folds, 0);
  const arity = 2 ** foldCounts[round]!;
  const ranks = new Map(indices.map((index, rank) => [index, rank]));
  queries.forEach((query, item) => {
    const base = (query >>> completedFolds) & ~(arity - 1);
    proof[offsets.friCosetRanks + round * queryCount + item] = ranks.get(base)!;
  });
  const directory = offsets.openingDirectory + (LOCAL_WORD_MATRIX_NAMES.length + round) * 20;
  [indicesStart, rowsStart, siblingsStart, stageDirectoryStart, frontierCursor]
    .forEach((value, word) => proof.set(writeU32BE(value), directory + word * 4));
  rows.forEach((row, item) => proof.set(row, rowsStart + item * rowWidth));
  siblings.forEach((sibling, item) => proof.set(sibling, siblingsStart + item * 32));
  frontiers.forEach((frontier, item) => {
    [frontier.siblingCut, frontier.start, frontier.end].forEach((value, word) =>
      proof.set(writeU32BE(value), stageDirectoryStart + item * 12 + word * 4));
    proof.set(opening.frontiers[item]!.bytes, frontier.start);
  });
  return { proof, indicesStart, rowsStart, siblingsStart, frontiers };
}

function evaluate(proof: Uint8Array, lock: Uint8Array, unbounded = false) {
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
  const vm = unbounded
    ? (() => {
      const instructionSet = createInstructionSetBch2026(false);
      const every = instructionSet.every!;
      return createVirtualMachine({
        ...instructionSet,
        every: (state) => {
          state.metrics.maximumOperationCost = 1_000_000_000;
          return every(state);
        },
      });
    })()
    : createVirtualMachineBch2026(false);
  const sourceOutputs = carriers.map((_, index) => ({
    lockingBytecode: lock,
    valueSatoshis: index === 0 ? 1_000n : localWordVerifierCarrierValue(index),
  }));
  transaction.outputs = sourceOutputs.map((output) => ({ ...output }));
  const state = vm.evaluate({ inputIndex: 8, sourceOutputs, transaction } as never);
  return { vm, state };
}

/** Measure the exact P2SH32 density credit used by one product carrier. */
function evaluateCarrier(proof: Uint8Array, verifier: Uint8Array) {
  const carriers = partitionLocalWordProofBytes(proof);
  const inputIndex = 8;
  const carrier = carriers[inputIndex]!;
  const redeem = compileLocalWordCarrierRedeem({
    index: inputIndex,
    verifier,
  });
  const lockingBytecode = localWordP2sh32Lock(redeem);
  const transaction = {
    version: 2,
    locktime: 0,
    inputs: carriers.map((member, index) => ({
      outpointTransactionHash: new Uint8Array(32).fill((index + 1) & 0xff),
      outpointIndex: index,
      sequenceNumber: index === 0
        ? localWordPoolCarrierSequence(proof.length)
        : localWordVerifierCarrierSequence(index),
      unlockingBytecode: index === inputIndex
        ? encodeLocalWordP2shCarrierUnlocking(member.chunk, redeem)
        : member.unlockingBytecode,
    })),
    outputs: [{ lockingBytecode: Uint8Array.of(0x51), valueSatoshis: 128_000n }],
  };
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
  assert.equal(vm.stateSuccess(state), true);
  const operationCost = Number(state.metrics.operationCost);
  const densityControlLength = Number(state.metrics.densityControlLength);
  return {
    operationCost,
    densityControlLength,
    requiredChunkBytes: Math.max(
      256,
      Math.ceil(operationCost / 800) - (densityControlLength - carrier.chunk.length),
    ),
  };
}

describe("local-word canonical Merkle VM", () => {
  it("binds first, middle, and last current openings to one preloaded schedule", () => {
    const built = fixture(LOCAL_WORD_PRODUCTION_PARAMETERS);
    const offsets = localWordProofStaticOffsets(PRODUCTION_PUBLIC_WORDS);
    const lock = compileLocalWordOpeningScheduleGate({
      publicWordCount: PRODUCTION_PUBLIC_WORDS,
      opening: "current",
    });
    const honest = evaluate(built.proof, lock, true);
    assert.equal(honest.vm.stateSuccess(honest.state), true, String(honest.state.error));
    assert.ok(lock.length < 10_000);

    for (const item of [0, 22, 43]) {
      for (const offset of [
        offsets.currentRanks + item,
        offsets.queries + item * 4 + 3,
        offsets.currentIndices + item * 4 + 3,
      ]) {
        const changed = built.proof.slice();
        changed[offset] ^= 1;
        const rejected = evaluate(changed, lock, true);
        assert.notEqual(rejected.vm.stateSuccess(rejected.state), true,
          `current item ${item} mutation ${offset}`);
      }
    }
    console.log("local-word-current-opening-schedule-gate", JSON.stringify({
      lockBytes: lock.length,
      operationCost: Number(honest.state.metrics.operationCost),
    }));
    assert.ok(Number(honest.state.metrics.operationCost) < 8_025_600);
  });

  it("rejects p and negative field encodings even under recomputed honest roots", () => {
    const interactionLock = compileLocalWordInteractionLeafGate({
      shard: 0,
      publicWordCount: PRODUCTION_PUBLIC_WORDS,
    });
    const currentLock = compileLocalWordMerkleLeafGate({
      matrix: "quotientAndFriMask",
      shard: 0,
      shards: 1,
      publicWordCount: PRODUCTION_PUBLIC_WORDS,
    });
    const friLock = compileLocalWordMerkleLeafGate({
      friLayer: 0,
      shard: 0,
      shards: 2,
      publicWordCount: PRODUCTION_PUBLIC_WORDS,
    });
    for (const [name, built, lock] of [
      ["interaction", fixture(LOCAL_WORD_PRODUCTION_PARAMETERS, "interaction"), interactionLock],
      ["quotientAndFriMask", fixture(LOCAL_WORD_PRODUCTION_PARAMETERS), currentLock],
      ["fri:0", friFixture(LOCAL_WORD_PRODUCTION_PARAMETERS, 0), friLock],
    ] as const) {
      const honest = evaluate(built.proof, lock, true);
      assert.equal(honest.vm.stateSuccess(honest.state), true,
        `${name} positive control: ${String(honest.state.error)}`);
    }

    for (const invalidField of ["p", "negative"] as const) {
      const interaction = fixture(LOCAL_WORD_PRODUCTION_PARAMETERS, "interaction", invalidField);
      const interactionResult = evaluate(interaction.proof, interactionLock, true);
      assert.notEqual(interactionResult.vm.stateSuccess(interactionResult.state), true);

      const current = fixture(LOCAL_WORD_PRODUCTION_PARAMETERS, "quotientAndFriMask", invalidField);
      const currentResult = evaluate(current.proof, currentLock, true);
      assert.notEqual(currentResult.vm.stateSuccess(currentResult.state), true);

      const fri = friFixture(LOCAL_WORD_PRODUCTION_PARAMETERS, 0, invalidField);
      const friResult = evaluate(fri.proof, friLock, true);
      assert.notEqual(friResult.vm.stateSuccess(friResult.state), true);
    }
  });

  it("verifies one complete current-row opening and rejects every owned stream", () => {
    const built = fixture(PARAMETERS);
    const lock = compileLocalWordCurrentMatrixMerkleGate({
      matrix: "quotientAndFriMask",
      publicWordCount: PRODUCTION_PUBLIC_WORDS,
      parameters: PARAMETERS,
    });
    const leafLock = compileLocalWordMerkleLeafGate({
      matrix: "quotientAndFriMask",
      shard: 0,
      shards: 1,
      publicWordCount: PRODUCTION_PUBLIC_WORDS,
      parameters: PARAMETERS,
    });
    const honest = evaluate(built.proof, lock, true);
    if (honest.vm.stateSuccess(honest.state) !== true) {
      const instructions = decodeAuthenticationInstructions(lock);
      const names = new Map(Object.entries(OpcodesBch).map(([name, opcode]) => [opcode, name]));
      console.log("local-word-merkle-debug", JSON.stringify({
        error: honest.state.error,
        ip: honest.state.ip,
        depth: honest.state.stack.length,
        stack: honest.state.stack.slice(-12).map((item) => Buffer.from(item).toString("hex")),
        instructions: instructions.slice(Math.max(0, honest.state.ip - 4), honest.state.ip + 3)
          .map((instruction, offset) => ({
            at: Math.max(0, honest.state.ip - 4) + offset,
            op: "data" in instruction ? `push:${instruction.data.length}:${Buffer.from(instruction.data).toString("hex")}`
              : names.get(instruction.opcode),
          })),
      }));
    }
    assert.equal(honest.vm.stateSuccess(honest.state), true);
    const metrics = (honest.state as {
      metrics?: {
        arithmeticCost?: number | bigint;
        evaluatedInstructionCount?: number | bigint;
        hashDigestIterations?: number | bigint;
        operationCost?: number | bigint;
        maximumOperationCost?: number | bigint;
        stackPushedBytes?: number | bigint;
      };
    }).metrics;
    console.log("local-word-merkle-measurement", JSON.stringify({
      lockBytes: lock.length,
      operationCost: Number(metrics?.operationCost ?? 0),
      maximumOperationCost: Number(metrics?.maximumOperationCost ?? 0),
    }));

    const honestLeaf = evaluate(built.proof, leafLock, true);
    assert.equal(honestLeaf.vm.stateSuccess(honestLeaf.state), true,
      String(honestLeaf.state.error));
    for (const [ownedLock, offset] of [
      [leafLock, built.rowsStart + 7],
      [leafLock, built.frontiers[0]!.start + 9],
      [lock, built.siblingsStart + 9],
      [lock, built.frontiers[0]!.start + 9],
    ] as const) {
      const changed = built.proof.slice();
      changed[offset] ^= 1;
      const rejected = evaluate(changed, ownedLock, true);
      assert.notEqual(rejected.vm.stateSuccess(rejected.state), true);
    }
  });

  it("splits canonical frontiers into fixed verifier stages", () => {
    const built = fixture(LOCAL_WORD_PRODUCTION_PARAMETERS);
    const stageCount = localWordV17MerkleCuts({
      matrix: "quotientAndFriMask",
    }).length;
    const locks = Array.from({ length: stageCount }, (_, stage) => compileLocalWordCurrentMatrixMerkleGate({
      matrix: "quotientAndFriMask", publicWordCount: PRODUCTION_PUBLIC_WORDS, stage,
    }));
    const costs = locks.map((lock) => {
      const honest = evaluate(built.proof, lock, true);
      assert.equal(honest.vm.stateSuccess(honest.state), true);
      return Number(honest.state.metrics.operationCost);
    });
    console.log("local-word-merkle-stages", JSON.stringify({
      frontierBytes: built.frontiers.reduce((sum, frontier) => sum + frontier.end - frontier.start, 0),
      stages: locks.map((lock, stage) => ({ stage, lockBytes: lock.length, operationCost: costs[stage] })),
    }));
    assert.ok(costs.every((cost) => cost < 8_025_600));

    const leafLock = compileLocalWordMerkleLeafGate({
      matrix: "quotientAndFriMask",
      shard: 0,
      shards: 1,
      publicWordCount: PRODUCTION_PUBLIC_WORDS,
    });
    const honestLeaf = evaluate(built.proof, leafLock, true);
    assert.equal(honestLeaf.vm.stateSuccess(honestLeaf.state), true,
      String(honestLeaf.state.error));
    const mutations = [
      [leafLock, built.rowsStart + 7],
      [leafLock, built.frontiers[0]!.start + 9],
      [locks[0]!, built.siblingsStart + 9],
      [locks[0]!, built.frontiers[0]!.start + 9],
      [locks[0]!, built.frontiers[1]!.start + 9],
      [locks[1]!, built.frontiers[1]!.siblingCut + 9],
      [locks[1]!, built.frontiers[1]!.start + 9],
      [locks[1]!, built.frontiers[2]!.start + 9],
      [locks.at(-1)!, built.frontiers.at(-1)!.start + 9],
      [locks.at(-1)!, built.frontiers.at(-1)!.siblingCut + 9],
    ] as const;
    for (const [lock, offset] of mutations) {
      const changed = built.proof.slice();
      changed[offset] ^= 1;
      const rejected = evaluate(changed, lock, true);
      assert.notEqual(rejected.vm.stateSuccess(rejected.state), true);
    }
  });

  it("keeps every current-row matrix stage within one maximum useful-byte input", () => {
    const measurements: { readonly matrix: string; readonly costs: readonly number[] }[] = [];
    for (const matrix of ["preprocessed", "original", "interaction", "quotientAndFriMask"] as const) {
      const built = fixture(LOCAL_WORD_PRODUCTION_PARAMETERS, matrix);
      const stages = Array.from(
        { length: localWordV17MerkleCuts({ matrix }).length },
        (_, stage) => stage,
      );
      const leafCosts = matrix === "interaction"
        ? Array.from({ length: LOCAL_WORD_INTERACTION_LEAF_SHARDS }, (_, shard) => {
          const lock = compileLocalWordInteractionLeafGate({
            shard, publicWordCount: PRODUCTION_PUBLIC_WORDS,
          });
          const honest = evaluate(built.proof, lock, true);
          assert.equal(honest.vm.stateSuccess(honest.state), true);
          return Number(honest.state.metrics.operationCost);
        })
        : [];
      const costs = stages.map((stage) => {
        const lock = compileLocalWordCurrentMatrixMerkleGate({
          matrix,
          publicWordCount: PRODUCTION_PUBLIC_WORDS,
          stage,
        });
        const honest = evaluate(built.proof, lock, true);
        assert.equal(honest.vm.stateSuccess(honest.state), true);
        return Number(honest.state.metrics.operationCost);
      });
      const carrierRequirements = stages.map((stage) => evaluateCarrier(
        built.proof,
        compileLocalWordCurrentMatrixMerkleGate({
          matrix, publicWordCount: PRODUCTION_PUBLIC_WORDS, stage,
        }),
      ).requiredChunkBytes);
      const leafCarrierRequirements = matrix === "interaction"
        ? Array.from({ length: LOCAL_WORD_INTERACTION_LEAF_SHARDS }, (_, shard) => evaluateCarrier(
          built.proof,
          compileLocalWordInteractionLeafGate({
            shard, publicWordCount: PRODUCTION_PUBLIC_WORDS,
          }),
        ).requiredChunkBytes)
        : [];
      console.log("local-word-current-matrix-stages", JSON.stringify({
        matrix,
        leafCosts,
        costs,
        leafCarrierRequirements,
        carrierRequirements,
      }));
      measurements.push({ matrix, costs: [...leafCosts, ...costs] });
      if (matrix === "interaction") {
        for (const [shard, offset] of [
          [0, built.rowsStart + 7],
          [0, built.frontiers[0]!.start + 9],
          [1, built.rowsStart + (LOCAL_WORD_PRODUCTION_PARAMETERS.fri.queries - 1) *
            LOCAL_WORD_MATRIX_ROW_WIDTHS[2] + 7],
        ] as const) {
          const changed = built.proof.slice();
          changed[offset] ^= 1;
          const rejected = evaluate(changed, compileLocalWordInteractionLeafGate({
            shard, publicWordCount: PRODUCTION_PUBLIC_WORDS,
          }), true);
          assert.notEqual(rejected.vm.stateSuccess(rejected.state), true);
        }
      }
    }
    assert.ok(measurements.every(({ costs }) => costs.every((cost) => cost < 8_025_600)));
  });

  it("keeps the global matrix's fixed two-level stages within the same envelope", () => {
    const built = fixture(LOCAL_WORD_PRODUCTION_PARAMETERS, "interactionGlobal");
    const stageCount = localWordV17MerkleCuts({ matrix: "interactionGlobal" }).length;
    const costs = Array.from({ length: stageCount }, (_, stage) => {
      const lock = compileLocalWordCurrentMatrixMerkleGate({
        matrix: "interactionGlobal",
        publicWordCount: PRODUCTION_PUBLIC_WORDS,
        stage,
      });
      const honest = evaluate(built.proof, lock, true);
      assert.equal(honest.vm.stateSuccess(honest.state), true);
      return Number(honest.state.metrics.operationCost);
    });
    const carrierRequirements = Array.from({ length: stageCount }, (_, stage) => evaluateCarrier(
      built.proof,
      compileLocalWordCurrentMatrixMerkleGate({
        matrix: "interactionGlobal", publicWordCount: PRODUCTION_PUBLIC_WORDS, stage,
      }),
    ).requiredChunkBytes);
    console.log("local-word-global-matrix-stages", JSON.stringify({ costs, carrierRequirements }));
    assert.ok(costs.every((cost) => cost < 8_025_600));
    const stage = (index: number) => compileLocalWordCurrentMatrixMerkleGate({
      matrix: "interactionGlobal", publicWordCount: PRODUCTION_PUBLIC_WORDS, stage: index,
    });
    const leafLock = compileLocalWordMerkleLeafGate({
      matrix: "interactionGlobal",
      shard: 0,
      shards: 1,
      publicWordCount: PRODUCTION_PUBLIC_WORDS,
    });
    const honestLeaf = evaluate(built.proof, leafLock, true);
    assert.equal(honestLeaf.vm.stateSuccess(honestLeaf.state), true,
      String(honestLeaf.state.error));
    for (const [lock, offset] of [
      [leafLock, built.rowsStart + 7],
      [leafLock, built.frontiers[0]!.start + 9],
      [stage(0), built.frontiers[0]!.start + 9],
      [stage(0), built.frontiers[0]!.siblingCut + 9],
      [stage(0), built.frontiers[1]!.start + 9],
      [stage(1), built.frontiers[1]!.siblingCut + 9],
      [stage(1), built.frontiers[1]!.start + 9],
      [stage(stageCount - 1), built.frontiers.at(-1)!.start + 9],
    ] as const) {
      const changed = built.proof.slice();
      changed[offset] ^= 1;
      const rejected = evaluate(changed, lock, true);
      assert.notEqual(rejected.vm.stateSuccess(rejected.state), true);
    }
  });

  it("keeps every FRI authentication stage within the useful-byte envelope", () => {
    const logs = localWordFriLayerLogs(LOCAL_WORD_PRODUCTION_PARAMETERS);
    const measurements: { readonly layer: number; readonly costs: readonly number[] }[] = [];
    logs.forEach((_, layer) => {
      const built = friFixture(LOCAL_WORD_PRODUCTION_PARAMETERS, layer);
      const stages = localWordV17MerkleCuts({ friLayer: layer }).length;
      const costs = Array.from({ length: stages }, (_, stage) => {
        const lock = compileLocalWordFriMerkleGate({
          layer, publicWordCount: PRODUCTION_PUBLIC_WORDS, stage,
        });
        const honest = evaluate(built.proof, lock, true);
        assert.equal(honest.vm.stateSuccess(honest.state), true);
        return Number(honest.state.metrics.operationCost);
      });
      const carrierRequirements = Array.from({ length: stages }, (_, stage) => evaluateCarrier(
        built.proof,
        compileLocalWordFriMerkleGate({
          layer, publicWordCount: PRODUCTION_PUBLIC_WORDS, stage,
        }),
      ).requiredChunkBytes);
      console.log("local-word-fri-merkle-stages", JSON.stringify({
        layer,
        costs,
        carrierRequirements,
      }));
      measurements.push({ layer, costs });
      if (layer === 0) {
        const lock = (stage: number) => compileLocalWordFriMerkleGate({
          layer, publicWordCount: PRODUCTION_PUBLIC_WORDS, stage,
        });
        const leafLock = compileLocalWordMerkleLeafGate({
          friLayer: layer,
          shard: 0,
          shards: 2,
          publicWordCount: PRODUCTION_PUBLIC_WORDS,
        });
        const honestLeaf = evaluate(built.proof, leafLock, true);
        assert.equal(honestLeaf.vm.stateSuccess(honestLeaf.state), true,
          String(honestLeaf.state.error));
        for (const [gate, offset] of [
          [leafLock, built.rowsStart + 7],
          [leafLock, built.frontiers[0]!.start + 9],
          // The quartet-first stage consumes complete four-leaf groups, so its
          // sibling slice is empty; the first binary stage owns this byte.
          [lock(1), built.siblingsStart + 9],
          [lock(0), built.frontiers[0]!.start + 9],
          [lock(0), built.frontiers[1]!.start + 9],
          [lock(1), built.frontiers[1]!.siblingCut + 9],
          [lock(1), built.frontiers[1]!.start + 9],
          [lock(1), built.frontiers[2]!.start + 9],
          [lock(2), built.frontiers[2]!.siblingCut + 9],
        ] as const) {
          const changed = built.proof.slice();
          changed[offset] ^= 1;
          const rejected = evaluate(changed, gate, true);
          assert.notEqual(rejected.vm.stateSuccess(rejected.state), true);
        }
      }
    });
    assert.ok(measurements.every(({ costs }) => costs.every((cost) => cost < 8_025_600)));
  });
});

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
  canonicalMerkleFrontier4,
  canonicalMerkleLeaf,
  canonicalMerkleParent4,
  encodeCanonicalMerkleFrontier4,
} from "../src/backends/circle/canonical-merkle.ts";
import {
  LOCAL_WORD_MATRIX_NAMES,
  LOCAL_WORD_MATRIX_ROW_WIDTHS,
  LOCAL_WORD_FRI_MERKLE_STAGE_GEOMETRY,
  localWordMatrixMerkleStageGeometry,
  localWordMerkleFrontierLevels,
  LOCAL_WORD_PROOF_LENGTH_OFFSET,
  LOCAL_WORD_PROOF_VERSION,
  localWordCanonicalSiblingCount,
  localWordMerkleFrontierSchedules,
  localWordOpeningSchedules,
  localWordProofStaticOffsets,
  type LocalWordMerkleStageGeometry,
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

function rootForOpening(
  label: string,
  indices: readonly number[],
  rows: readonly Uint8Array[],
  siblings: readonly Uint8Array[],
  rowCount: number,
  geometry: number | LocalWordMerkleStageGeometry = 3,
): {
  readonly root: Uint8Array;
  readonly frontiers: readonly { readonly bytes: Uint8Array; readonly siblingCount: number }[];
} {
  const schedules = localWordMerkleFrontierSchedules(indices, rowCount, geometry);
  const staged = schedules.map((schedule) => {
    const frontier = canonicalMerkleFrontier4(
      label,
      indices.map((index, position) => ({ index, raw: rows[position]! })),
      siblings,
      rowCount,
      schedule.level,
    );
    return { bytes: encodeCanonicalMerkleFrontier4(frontier), siblingCount: frontier.siblingCount };
  });
  let frontier = new Map(indices.map((index, position) => [
    index,
    canonicalMerkleLeaf(label, index, rows[position]!),
  ]));
  let sibling = 0;
  for (let level = 0; level < Math.log2(rowCount) / 2; level += 1) {
    const next = new Map<number, Uint8Array>();
    const parents = [...new Set([...frontier.keys()].map((index) => index >>> 2))]
      .sort((left, right) => left - right);
    for (const parent of parents) {
      const children = Array.from({ length: 4 }, (_, child) =>
        frontier.get(parent * 4 + child) ?? siblings[sibling++]!);
      next.set(parent, canonicalMerkleParent4(label, level, children));
    }
    frontier = next;
  }
  assert.equal(sibling, siblings.length);
  return {
    root: frontier.get(0)!,
    frontiers: staged,
  };
}

const MATRIX_LABELS = {
  preprocessed: "local-word:preprocessed",
  original: "local-word:original",
  interaction: "local-word:interaction",
  interactionGlobal: "local-word:interaction-global",
  quotientAndFriMask: "local-word:quotient-and-fri-mask",
} as const;

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
  const multiplier = parameters.fri.queries === 8 ? 5 : 11;
  const permuted = Array.from(
    { length: queries.length },
    (_, item) => queries[(item * multiplier) % queries.length]!,
  );
  localWordOpeningSchedules(permuted, parameters);
  return permuted;
}

function fixture(
  parameters: LocalWordProofParameters,
  matrixName: keyof typeof MATRIX_LABELS = "quotientAndFriMask",
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
  const rowWidth = LOCAL_WORD_MATRIX_ROW_WIDTHS[matrix]!;
  const rowCount = 2 ** parameters.evalLog;
  const queryCount = parameters.fri.queries;
  const global = matrixName === "interactionGlobal";
  const queries = fixtureQueries(parameters);
  const schedules = localWordOpeningSchedules(queries, parameters);
  const sorted = global ? schedules.global : schedules.current;
  const manifestIndices = schedules.current;
  const ranks = new Map(manifestIndices.map((query, rank) => [query, rank]));
  const rows = sorted.map((index) => Uint8Array.from(
    { length: rowWidth },
    (_, byte) => ((index * 17 + byte * 29 + 3) & 0xff) & (byte % 4 === 3 ? 0x3f : 0xff),
  ));
  if (invalidField !== undefined) {
    rows[0]!.set(invalidField === "p"
      ? Uint8Array.of(0xff, 0xff, 0xff, 0x7f)
      : Uint8Array.of(0, 0, 0, 0x80));
  }
  const siblingCount = localWordCanonicalSiblingCount(sorted, rowCount);
  const siblings = Array.from({ length: siblingCount }, (_, item) =>
    Uint8Array.from({ length: 32 }, (__, byte) => (item * 37 + byte * 11 + 5) & 0xff));
  const indicesStart = 50_000;
  const rowsStart = indicesStart + (global ? sorted.length * 4 : 0);
  const siblingsStart = rowsStart + rows.length * rowWidth;
  const stageDirectoryStart = siblingsStart + siblings.length * 32;
  const opening = rootForOpening(
    MATRIX_LABELS[matrixName],
    sorted,
    rows,
    siblings,
    rowCount,
    localWordMatrixMerkleStageGeometry(matrixName),
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
  const offsets = localWordProofStaticOffsets(1, parameters);
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
  if (global) sorted.forEach((index, item) => proof.set(writeU32BE(index), indicesStart + item * 4));
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
  const rowCount = 2 ** localWordFriLayerLogs(parameters)[round]!;
  const rows = indices.map((index) => Uint8Array.from(
    { length: 16 }, (_, byte) =>
      ((index * 13 + byte * 23 + round * 7 + 1) & 0xff) & (byte % 4 === 3 ? 0x3f : 0xff),
  ));
  if (invalidField !== undefined) {
    rows[0]!.set(invalidField === "p"
      ? Uint8Array.of(0xff, 0xff, 0xff, 0x7f)
      : Uint8Array.of(0, 0, 0, 0x80));
  }
  const siblingCount = localWordCanonicalSiblingCount(indices, rowCount);
  const siblings = Array.from({ length: siblingCount }, (_, item) =>
    Uint8Array.from({ length: 32 }, (__, byte) => (item * 31 + byte * 17 + round + 3) & 0xff));
  const indicesStart = 50_000;
  const rowsStart = indicesStart + indices.length * 4;
  const siblingsStart = rowsStart + rows.length * 16;
  const stageDirectoryStart = siblingsStart + siblings.length * 32;
  const opening = rootForOpening(
    `fri:layer:${round}`,
    indices,
    rows,
    siblings,
    rowCount,
    LOCAL_WORD_FRI_MERKLE_STAGE_GEOMETRY,
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
  const offsets = localWordProofStaticOffsets(1, parameters);
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
  indices.forEach((index, item) => proof.set(writeU32BE(index), indicesStart + item * 4));
  rows.forEach((row, item) => proof.set(row, rowsStart + item * 16));
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
  it("binds current, global, and every FRI index to one fixed query schedule", () => {
    const globalBuilt = fixture(LOCAL_WORD_PRODUCTION_PARAMETERS, "interactionGlobal");
    const scheduleOffsets = localWordProofStaticOffsets(1);
    const globalCurrentRow = globalBuilt.indicesStart +
      globalBuilt.proof[scheduleOffsets.globalCurrentRanks]! * 4;
    const globalPreviousRow = globalBuilt.indicesStart +
      globalBuilt.proof[scheduleOffsets.globalPreviousRanks]! * 4;
    const cases = [
      {
        label: "current",
        built: fixture(LOCAL_WORD_PRODUCTION_PARAMETERS),
        lock: compileLocalWordOpeningScheduleGate({ publicWordCount: 1, opening: "current" }),
        mutationOffsets: [
          localWordProofStaticOffsets(1).currentRanks,
          localWordProofStaticOffsets(1).currentIndices + 3,
        ],
      },
      {
        label: "global-current",
        built: globalBuilt,
        lock: compileLocalWordOpeningScheduleGate({
          publicWordCount: 1, opening: "global", stage: "current",
        }),
        mutationOffsets: [scheduleOffsets.globalCurrentRanks, globalCurrentRow + 3],
      },
      {
        label: "global-previous",
        built: globalBuilt,
        lock: compileLocalWordOpeningScheduleGate({
          publicWordCount: 1, opening: "global", stage: "previous",
        }),
        mutationOffsets: [scheduleOffsets.globalPreviousRanks, globalPreviousRow + 3],
      },
      {
        label: "global-shape",
        built: globalBuilt,
        lock: compileLocalWordOpeningScheduleGate({
          publicWordCount: 1, opening: "global", stage: "shape",
        }),
        mutationOffsets: [scheduleOffsets.globalPreviousRanks, globalBuilt.indicesStart],
      },
      ...localWordFriLayerLogs(LOCAL_WORD_PRODUCTION_PARAMETERS).map((_, layer) => ({
        label: `fri-${layer}`,
        built: friFixture(LOCAL_WORD_PRODUCTION_PARAMETERS, layer),
        lock: compileLocalWordOpeningScheduleGate({ publicWordCount: 1, opening: "fri", friLayer: layer }),
        mutationOffsets: [
          localWordProofStaticOffsets(1).friCosetRanks +
            layer * LOCAL_WORD_PRODUCTION_PARAMETERS.fri.queries,
          50_003,
        ],
      })),
    ];
    const measurements = cases.map(({ label, built, lock, mutationOffsets }) => {
      const honest = evaluate(built.proof, lock, true);
      assert.equal(honest.vm.stateSuccess(honest.state), true, `${label}: ${honest.state.error}`);
      assert.ok(lock.length < 10_000);

      for (const offset of mutationOffsets) {
        const changed = built.proof.slice();
        changed[offset] ^= 1;
        const rejected = evaluate(changed, lock, true);
        assert.notEqual(rejected.vm.stateSuccess(rejected.state), true, `${label} mutation ${offset}`);
      }
      return {
        label,
        lockBytes: lock.length,
        operationCost: Number(honest.state.metrics.operationCost),
      };
    });
    console.log("local-word-opening-schedule-gates", JSON.stringify(measurements));
    assert.ok(measurements.every(({ operationCost }) => operationCost < 8_025_600));
  });

  it("rejects p and negative field encodings even under recomputed honest roots", () => {
    for (const invalidField of ["p", "negative"] as const) {
      const interaction = fixture(LOCAL_WORD_PRODUCTION_PARAMETERS, "interaction", invalidField);
      const interactionResult = evaluate(interaction.proof, compileLocalWordInteractionLeafGate({
        shard: 0,
        publicWordCount: 1,
      }), true);
      assert.notEqual(interactionResult.vm.stateSuccess(interactionResult.state), true);

      const current = fixture(LOCAL_WORD_PRODUCTION_PARAMETERS, "quotientAndFriMask", invalidField);
      const currentResult = evaluate(current.proof, compileLocalWordCurrentMatrixMerkleGate({
        matrix: "quotientAndFriMask",
        publicWordCount: 1,
        stage: 0,
      }), true);
      assert.notEqual(currentResult.vm.stateSuccess(currentResult.state), true);

      const fri = friFixture(LOCAL_WORD_PRODUCTION_PARAMETERS, 0, invalidField);
      const friResult = evaluate(fri.proof, compileLocalWordFriMerkleGate({
        layer: 0,
        publicWordCount: 1,
        stage: 0,
      }), true);
      assert.notEqual(friResult.vm.stateSuccess(friResult.state), true);
    }
  });

  it("verifies one complete current-row opening and rejects every owned stream", () => {
    const built = fixture(PARAMETERS);
    const lock = compileLocalWordCurrentMatrixMerkleGate({
      matrix: "quotientAndFriMask",
      publicWordCount: 1,
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

    for (const offset of [built.rowsStart + 7, built.siblingsStart + 9]) {
      const changed = built.proof.slice();
      changed[offset] ^= 1;
      const rejected = evaluate(changed, lock, true);
      assert.notEqual(rejected.vm.stateSuccess(rejected.state), true);
    }
  });

  it("splits canonical frontiers into fixed verifier stages", () => {
    const built = fixture(LOCAL_WORD_PRODUCTION_PARAMETERS);
    const treeLevels = LOCAL_WORD_PRODUCTION_PARAMETERS.evalLog / 2;
    const frontierLevels = localWordMerkleFrontierLevels(
      treeLevels,
      localWordMatrixMerkleStageGeometry("quotientAndFriMask"),
    );
    const stageCount = frontierLevels.length + 1;
    const locks = Array.from({ length: stageCount }, (_, stage) => compileLocalWordCurrentMatrixMerkleGate({
      matrix: "quotientAndFriMask", publicWordCount: 1, stage,
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

    const mutations = [
      [locks[0]!, built.rowsStart + 7],
      [locks[0]!, built.siblingsStart + 9],
      [locks[0]!, built.frontiers[0]!.start + 9],
      [locks[1]!, built.frontiers[0]!.start + 9],
      [locks[1]!, built.frontiers[0]!.siblingCut + 9],
      [locks[1]!, built.frontiers[1]!.start + 9],
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
      const treeLevels = LOCAL_WORD_PRODUCTION_PARAMETERS.evalLog / 2;
      const frontierLevels = localWordMerkleFrontierLevels(
        treeLevels,
        localWordMatrixMerkleStageGeometry(matrix),
      );
      const stages = matrix === "interaction"
        ? Array.from({ length: frontierLevels.length }, (_, stage) => stage + 1)
        : Array.from({ length: frontierLevels.length + 1 }, (_, stage) => stage);
      const leafCosts = matrix === "interaction"
        ? Array.from({ length: LOCAL_WORD_INTERACTION_LEAF_SHARDS }, (_, shard) => {
          const lock = compileLocalWordInteractionLeafGate({ shard, publicWordCount: 1 });
          const honest = evaluate(built.proof, lock, true);
          assert.equal(honest.vm.stateSuccess(honest.state), true);
          return Number(honest.state.metrics.operationCost);
        })
        : [];
      const costs = stages.map((stage) => {
        const lock = compileLocalWordCurrentMatrixMerkleGate({
          matrix,
          publicWordCount: 1,
          stage,
        });
        const honest = evaluate(built.proof, lock, true);
        assert.equal(honest.vm.stateSuccess(honest.state), true);
        return Number(honest.state.metrics.operationCost);
      });
      const carrierRequirements = stages.map((stage) => evaluateCarrier(
        built.proof,
        compileLocalWordCurrentMatrixMerkleGate({ matrix, publicWordCount: 1, stage }),
      ).requiredChunkBytes);
      const leafCarrierRequirements = matrix === "interaction"
        ? Array.from({ length: LOCAL_WORD_INTERACTION_LEAF_SHARDS }, (_, shard) => evaluateCarrier(
          built.proof,
          compileLocalWordInteractionLeafGate({ shard, publicWordCount: 1 }),
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
            shard, publicWordCount: 1,
          }), true);
          assert.notEqual(rejected.vm.stateSuccess(rejected.state), true);
        }
      }
    }
    assert.ok(measurements.every(({ costs }) => costs.every((cost) => cost < 8_025_600)));
  });

  it("keeps the global matrix's fixed two-level stages within the same envelope", () => {
    const built = fixture(LOCAL_WORD_PRODUCTION_PARAMETERS, "interactionGlobal");
    const treeLevels = LOCAL_WORD_PRODUCTION_PARAMETERS.evalLog / 2;
    const stageCount = localWordMerkleFrontierLevels(
      treeLevels,
      localWordMatrixMerkleStageGeometry("interactionGlobal"),
    ).length + 1;
    const costs = Array.from({ length: stageCount }, (_, stage) => {
      const lock = compileLocalWordCurrentMatrixMerkleGate({
        matrix: "interactionGlobal",
        publicWordCount: 1,
        stage,
      });
      const honest = evaluate(built.proof, lock, true);
      assert.equal(honest.vm.stateSuccess(honest.state), true);
      return Number(honest.state.metrics.operationCost);
    });
    const carrierRequirements = Array.from({ length: stageCount }, (_, stage) => evaluateCarrier(
      built.proof,
      compileLocalWordCurrentMatrixMerkleGate({
        matrix: "interactionGlobal", publicWordCount: 1, stage,
      }),
    ).requiredChunkBytes);
    console.log("local-word-global-matrix-stages", JSON.stringify({ costs, carrierRequirements }));
    assert.ok(costs.every((cost) => cost < 8_025_600));
    const stage = (index: number) => compileLocalWordCurrentMatrixMerkleGate({
      matrix: "interactionGlobal", publicWordCount: 1, stage: index,
    });
    for (const [lock, offset] of [
      [stage(0), built.indicesStart + 3],
      [stage(0), built.rowsStart + 7],
      [stage(0), built.frontiers[0]!.start + 9],
      [stage(1), built.frontiers[0]!.siblingCut + 9],
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
    logs.forEach((logRows, layer) => {
      const built = friFixture(LOCAL_WORD_PRODUCTION_PARAMETERS, layer);
      const stages = localWordMerkleFrontierLevels(
        logRows / 2,
        LOCAL_WORD_FRI_MERKLE_STAGE_GEOMETRY,
      ).length + 1;
      const costs = Array.from({ length: stages }, (_, stage) => {
        const lock = compileLocalWordFriMerkleGate({ layer, publicWordCount: 1, stage });
        const honest = evaluate(built.proof, lock, true);
        assert.equal(honest.vm.stateSuccess(honest.state), true);
        return Number(honest.state.metrics.operationCost);
      });
      const carrierRequirements = Array.from({ length: stages }, (_, stage) => evaluateCarrier(
        built.proof,
        compileLocalWordFriMerkleGate({ layer, publicWordCount: 1, stage }),
      ).requiredChunkBytes);
      console.log("local-word-fri-merkle-stages", JSON.stringify({
        layer,
        costs,
        carrierRequirements,
      }));
      measurements.push({ layer, costs });
      if (layer === 0) {
        const lock = (stage: number) => compileLocalWordFriMerkleGate({
          layer, publicWordCount: 1, stage,
        });
        for (const [gate, offset] of [
          [lock(0), built.indicesStart + 3],
          [lock(0), built.rowsStart + 7],
          [lock(1), built.siblingsStart + 9],
          [lock(0), built.frontiers[0]!.start + 9],
          [lock(1), built.frontiers[0]!.start + 9],
          [lock(1), built.frontiers[1]!.start + 9],
          [lock(2), built.frontiers[1]!.siblingCut + 9],
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

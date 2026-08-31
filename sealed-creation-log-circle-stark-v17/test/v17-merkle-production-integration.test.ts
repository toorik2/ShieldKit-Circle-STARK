import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  LOCAL_WORD_CARRIER_BUDGETS,
  LOCAL_WORD_CANONICAL_ROLE_NAMES,
  localWordCanonicalCarrierBudgets,
} from "../src/chain/local-word-carrier-allocation.ts";
import {
  binToHex,
  cashAssemblyToBin,
  createInstructionSetBch2026,
  createVirtualMachine,
  createVirtualMachineBch2026,
} from "@bitauth/libauth";
import {
  V17MerkleTree,
  encodeV17MerkleCutFrontiers,
  encodeV17MerkleOpening,
  v17MerkleCutFrontiers,
  v17MerkleDescriptorsFromCommitments,
  v17MerkleLevels,
  v17MerkleOpeningRoot,
  v17MerkleSchedule,
  v17ProductionMerkleDescriptors,
  type V17MerkleDescriptor,
} from "../src/backends/circle/v17-merkle.ts";
import {
  LOCAL_WORD_PROOF_VERSION,
  LOCAL_WORD_MATRIX_NAMES,
  decodeLocalWordSealedProof,
  encodeLocalWordSealedProof,
  frameLocalWordSealedProof,
  localWordMaximumCanonicalProofBytes,
  localWordOpeningSchedules,
  localWordProofDirectory,
  localWordProofStaticOffsets,
  localWordV17FriMerkleDescriptor,
  localWordV17MerkleCuts,
  localWordV17MatrixMerkleDescriptor,
  localWordV17MerklePlan,
  type LocalWordMatrixName,
} from "../src/backends/circle/local-word-sealed-proof.ts";
import {
  LOCAL_WORD_PRODUCTION_PARAMETERS,
  localWordFriLayerLogs,
  type LocalWordProofParameters,
} from
  "../src/backends/circle/local-word-successor-params.ts";
import {
  localWordCompositionTranscript,
  localWordInteractionChallengeValues,
  localWordInteractionTranscript,
  localWordPublicBoundaryTranscript,
  localWordQueryIndices,
} from "../src/backends/circle/local-word-transcript.ts";
import { encodeQm31, QM31_ZERO, type QM31El } from
  "../src/backends/circle/qm31.ts";
import { V17_PROOF_PROTOCOL_ID } from "../src/backends/circle/v17-proof-layout.ts";
import { poolLocalBoundaryClaimForWords } from
  "../src/chain/pool-relation-local-word-boundary.ts";
import {
  planV17MerkleStagesFromMeasurements,
  planV17ProductionMerkleStages,
  verifyV17MeasuredMerklePlanCertificate,
  verifyV17MerklePlanCertificate,
} from "../src/chain/v17-merkle-planner.ts";
import {
  compileLocalWordCurrentMatrixMerkleGate,
  compileLocalWordFriMerkleGate,
  compileLocalWordMerkleLeafGate,
  compileV17MerkleOpeningFixtureGate,
} from
  "../src/chain/local-word-merkle-vm.ts";
import { compileLocalWordOpeningScheduleGate } from
  "../src/chain/local-word-balanced-vm.ts";
import {
  compileLocalWordCarrierRedeem,
  encodeLocalWordP2shCarrierUnlocking,
  LOCAL_WORD_CARRIER_MIN_PROOF_BYTES,
  localWordP2sh32Lock,
  localWordPoolCarrierSequence,
  localWordVerifierCarrierSequence,
  localWordVerifierCarrierValue,
  partitionLocalWordProofBytes,
} from "../src/chain/local-word-proof-carriers.ts";
import { V17_PRODUCTION_ROLE_LAYOUT } from "../src/chain/v17-role-layout.ts";
import { V17_CONSTRUCTION_GRAPH } from "../src/construction/v17-graph.ts";
import { concatBytes, sha256, writeU32BE } from "../src/pool/bytes.ts";
import { successorTraceOffsetIndex } from "../src/backends/circle/successor-domain.ts";

function rows(count: number, width: number): Uint8Array[] {
  return Array.from({ length: count }, (_, row) =>
    Uint8Array.from({ length: width }, (__, byte) => (row * 37 + byte * 19 + 11) & 0xff));
}

function compilePush(bytes: Uint8Array): Uint8Array {
  const result = cashAssemblyToBin(`<0x${binToHex(bytes)}>`);
  if (typeof result === "string") throw new Error(result);
  return result;
}

function evaluate(opening: Uint8Array, lockingBytecode: Uint8Array) {
  const transaction = {
    version: 2,
    locktime: 0,
    inputs: [{
      outpointTransactionHash: new Uint8Array(32),
      outpointIndex: 0,
      sequenceNumber: 0,
      unlockingBytecode: compilePush(opening),
    }],
    outputs: [{ lockingBytecode: Uint8Array.of(0x51), valueSatoshis: 999n }],
  };
  const sourceOutputs = [{ lockingBytecode, valueSatoshis: 1_000n }];
  const instructionSet = createInstructionSetBch2026(false);
  const every = instructionSet.every!;
  const vm = createVirtualMachine({
    ...instructionSet,
    every: (state) => {
      state.metrics.maximumOperationCost = 1_000_000_000;
      return every(state);
    },
  });
  const state = vm.evaluate({ inputIndex: 0, sourceOutputs, transaction } as never);
  return { ok: vm.stateSuccess(state) === true, state };
}

function mutate(bytes: Uint8Array, offset: number): Uint8Array {
  const result = bytes.slice();
  result[offset]! ^= 1;
  return result;
}

function swapFixed(bytes: Uint8Array, left: number, right: number, width: number): Uint8Array {
  const result = bytes.slice();
  const first = result.slice(left, left + width);
  result.copyWithin(left, right, right + width);
  result.set(first, right);
  return result;
}

function fixtureQueries(parameters: LocalWordProofParameters): readonly number[] {
  const rowCount = 2 ** parameters.evalLog;
  const orbitSize = 2 ** parameters.fri.queryOrbitLog;
  const orbitCount = rowCount / orbitSize;
  const queries: number[] = [];
  const global = new Set<number>();
  const usedOrbits = new Set<number>();
  for (let item = 0; item < parameters.fri.queries; item += 1) {
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
      break;
    }
  }
  const gcd = (left: number, right: number): number => right === 0 ? left : gcd(right, left % right);
  const multiplier = Array.from({ length: parameters.fri.queries - 2 }, (_, item) => item + 2)
    .find((candidate) => gcd(candidate, parameters.fri.queries) === 1)!;
  const permuted = Array.from(
    { length: queries.length },
    (_, item) => queries[(item * multiplier) % queries.length]!,
  );
  localWordOpeningSchedules(permuted, parameters);
  return permuted;
}

function installCompactV17Opening(args: {
  readonly proof: Uint8Array;
  readonly publicWordCount: number;
  readonly parameters: LocalWordProofParameters;
  readonly descriptor: V17MerkleDescriptor;
  readonly openingIndex: number;
  readonly rootOffset: number;
  readonly indices: readonly number[];
  readonly cutBits: readonly number[];
}): {
  readonly rowsStart: number;
  readonly siblingsStart: number;
  readonly stageDirectoryStart: number;
  readonly end: number;
  readonly root: Uint8Array;
  readonly frontierStarts: readonly number[];
} {
  const offsets = localWordProofStaticOffsets(args.publicWordCount, args.parameters);
  const schedule = v17MerkleSchedule(args.descriptor, args.indices);
  const rows = args.indices.map(() => new Uint8Array(args.descriptor.rowWidth));
  const siblings = Array.from({ length: schedule.siblingCount }, (_, item) =>
    sha256(concatBytes(new TextEncoder().encode("v17-compact-sibling"), writeU32BE(item))));
  const root = v17MerkleOpeningRoot({
    descriptor: args.descriptor,
    rows: args.indices.map((index, item) => ({ index, raw: rows[item]! })),
    siblings,
  });
  const frontiers = v17MerkleCutFrontiers({
    descriptor: args.descriptor,
    rows: args.indices.map((index, item) => ({ index, raw: rows[item]! })),
    siblings,
    cutBits: args.cutBits,
  });
  const siblingCountByBits = new Map<number, number>([[0, 0]]);
  let siblingCount = 0;
  schedule.levels.forEach((level) => {
    siblingCount += level.siblingIndices.length;
    siblingCountByBits.set(level.nextConsumedBits, siblingCount);
  });
  const rowsStart = Math.max(offsets.openingBodies + 512, 16_384);
  const siblingsStart = rowsStart + rows.length * args.descriptor.rowWidth;
  const stageDirectoryStart = siblingsStart + siblings.length * 32;
  let frontierCursor = stageDirectoryStart + args.cutBits.length * 12;
  const records = frontiers.map((frontier) => {
    const bytes = encodeV17MerkleCutFrontiers([frontier]);
    const start = frontierCursor;
    frontierCursor += bytes.length;
    return {
      bytes,
      siblingCut: siblingsStart + siblingCountByBits.get(frontier.consumedBits)! * 32,
      start,
      end: frontierCursor,
    };
  });
  const end = frontierCursor;
  if (end > args.proof.length) throw new Error(`compact v17 opening exceeds proof ${end}`);
  args.proof.set(concatBytes(...rows), rowsStart);
  args.proof.set(concatBytes(...siblings), siblingsStart);
  records.forEach((record, item) => {
    args.proof.set(concatBytes(
      writeU32BE(record.siblingCut), writeU32BE(record.start), writeU32BE(record.end),
    ), stageDirectoryStart + item * 12);
    args.proof.set(record.bytes, record.start);
  });
  args.proof.set(concatBytes(
    writeU32BE(rowsStart),
    writeU32BE(rowsStart),
    writeU32BE(siblingsStart),
    writeU32BE(stageDirectoryStart),
    writeU32BE(end),
  ), offsets.openingDirectory + args.openingIndex * 20);
  args.proof.set(root, args.rootOffset);
  return {
    rowsStart,
    siblingsStart,
    stageDirectoryStart,
    end,
    root,
    frontierStarts: records.map(({ start }) => start),
  };
}

function evaluateProofGate(
  proof: Uint8Array,
  lockingBytecode: Uint8Array,
  inputIndex = 8,
) {
  const carriers = partitionLocalWordProofBytes(proof);
  const transaction = {
    version: 2,
    locktime: 0,
    inputs: carriers.map((carrier, input) => ({
      outpointTransactionHash: new Uint8Array(32).fill(input + 1),
      outpointIndex: input,
      sequenceNumber: input === 0
        ? localWordPoolCarrierSequence(proof.length)
        : localWordVerifierCarrierSequence(input),
      unlockingBytecode: carrier.unlockingBytecode,
    })),
    outputs: [{ lockingBytecode: Uint8Array.of(0x51), valueSatoshis: 128_000n }],
  };
  const sourceOutputs = carriers.map((_, input) => ({
    lockingBytecode,
    valueSatoshis: input === 0 ? 1_000n : localWordVerifierCarrierValue(input),
  }));
  transaction.outputs = sourceOutputs.map((output) => ({ ...output }));
  const instructionSet = createInstructionSetBch2026(false);
  const every = instructionSet.every!;
  const vm = createVirtualMachine({
    ...instructionSet,
    every: (state) => {
      state.metrics.maximumOperationCost = 1_000_000_000;
      return every(state);
    },
  });
  const state = vm.evaluate({ inputIndex, sourceOutputs, transaction } as never);
  return { ok: vm.stateSuccess(state) === true, state };
}

function evaluateP2shProofGate(
  proof: Uint8Array,
  verifier: Uint8Array,
  inputIndex: number,
) {
  const carriers = partitionLocalWordProofBytes(proof);
  const carrier = carriers[inputIndex]!;
  const redeem = compileLocalWordCarrierRedeem({ index: inputIndex, verifier });
  const lockingBytecode = localWordP2sh32Lock(redeem);
  const unlockingBytecode = encodeLocalWordP2shCarrierUnlocking(carrier.chunk, redeem);
  const transaction = {
    version: 2,
    locktime: 0,
    inputs: carriers.map((member, input) => ({
      outpointTransactionHash: new Uint8Array(32).fill(input + 1),
      outpointIndex: input,
      sequenceNumber: input === 0
        ? localWordPoolCarrierSequence(proof.length)
        : localWordVerifierCarrierSequence(input),
      unlockingBytecode: input === inputIndex ? unlockingBytecode : member.unlockingBytecode,
    })),
    outputs: [{ lockingBytecode: Uint8Array.of(0x51), valueSatoshis: 128_000n }],
  };
  const sourceOutputs = carriers.map((_, input) => ({
    lockingBytecode,
    valueSatoshis: input === 0 ? 1_000n : localWordVerifierCarrierValue(input),
  }));
  transaction.outputs = sourceOutputs.map((output) => ({ ...output }));
  const instructionSet = createInstructionSetBch2026(false);
  const every = instructionSet.every!;
  const vm = createVirtualMachine({
    ...instructionSet,
    every: (state) => {
      state.metrics.maximumOperationCost = 1_000_000_000;
      return every(state);
    },
  });
  const state = vm.evaluate({ inputIndex, sourceOutputs, transaction } as never);
  const operationCost = Number(state.metrics.operationCost);
  const densityControlLength = Number(state.metrics.densityControlLength);
  return {
    ok: vm.stateSuccess(state) === true,
    state,
    redeemBytes: redeem.length,
    unlockingBytes: unlockingBytecode.length,
    operationCost,
    densityControlLength,
    carrierBytes: carrier.chunk.length,
    requiredProofBytes: Math.max(256,
      Math.ceil(operationCost / 800) - (densityControlLength - carrier.chunk.length)),
  };
}

describe("v17 mixed Merkle production integration", () => {
  it("generates one atomic carrier role inventory", () => {
    assert.equal(LOCAL_WORD_CARRIER_BUDGETS.length,
      LOCAL_WORD_CANONICAL_ROLE_NAMES.length + 1);
    assert.equal(new Set(LOCAL_WORD_CANONICAL_ROLE_NAMES).size,
      LOCAL_WORD_CANONICAL_ROLE_NAMES.length);
    assert.equal(V17_PRODUCTION_ROLE_LAYOUT.filter(({ kind }) =>
      kind === "matrix-merkle-leaf").length, LOCAL_WORD_MATRIX_NAMES.length);
    assert.equal(V17_PRODUCTION_ROLE_LAYOUT.filter(({ kind }) =>
      kind === "fri-merkle-leaf").length, 17);
    assert.equal(V17_PRODUCTION_ROLE_LAYOUT.filter(({ kind }) =>
      kind === "matrix-merkle-parent" || kind === "fri-merkle-parent").length, 52);
    assert.throws(() => localWordCanonicalCarrierBudgets(
      LOCAL_WORD_CANONICAL_ROLE_NAMES.slice(1),
    ), /carrier roles/);
    const substituted = [...LOCAL_WORD_CANONICAL_ROLE_NAMES];
    substituted[0] = "query:0:substituted";
    assert.throws(() => localWordCanonicalCarrierBudgets(substituted), /carrier roles/);
    const reordered = [...LOCAL_WORD_CANONICAL_ROLE_NAMES];
    [reordered[0], reordered[1]] = [reordered[1]!, reordered[0]!];
    assert.throws(() => localWordCanonicalCarrierBudgets(reordered), /carrier roles/);
  });

  it("derives provisional cuts without treating any role count as an input", () => {
    assert.equal(LOCAL_WORD_PROOF_VERSION, 17);
    assert.equal(localWordProofStaticOffsets(8).openingBodies, 4_474);
    assert.deepEqual(
      v17MerkleDescriptorsFromCommitments(V17_CONSTRUCTION_GRAPH.commitments),
      v17ProductionMerkleDescriptors(),
    );
    const generated = planV17ProductionMerkleStages();
    const all = [...Object.values(generated.matrices), ...generated.fri];
    assert.equal(all.length, V17_CONSTRUCTION_GRAPH.commitments.length);
    assert.equal(generated.matrixRoleCount,
      Object.values(generated.matrices).reduce((sum, item) => sum + item.plan.stages.length, 0));
    assert.equal(generated.friRoleCount,
      generated.fri.reduce((sum, item) => sum + item.plan.stages.length, 0));
    assert.ok(all.every(({ plan }) => verifyV17MerklePlanCertificate(plan.certificate)));
  });

  it("exposes exactly graph-derived production descriptors to the sealed codec", () => {
    const descriptors = v17ProductionMerkleDescriptors();
    for (const name of Object.keys(descriptors.matrices) as (keyof typeof descriptors.matrices)[]) {
      assert.deepEqual(localWordV17MatrixMerkleDescriptor(name), descriptors.matrices[name]);
      assert.deepEqual(localWordV17MerklePlan({ matrix: name }).certificate.input.descriptor,
        descriptors.matrices[name]);
    }
    descriptors.fri.forEach((descriptor, layer) => {
      assert.deepEqual(localWordV17FriMerkleDescriptor(layer), descriptor);
      assert.deepEqual(localWordV17MerklePlan({ friLayer: layer }).certificate.input.descriptor,
        descriptor);
    });
    assert.deepEqual(LOCAL_WORD_PRODUCTION_PARAMETERS.fri.foldLog, 2);
  });

  it("round-trips one self-contained sealed proof with index-free v17 bodies", () => {
    const parameters: LocalWordProofParameters = {
      relationLog: 6,
      evalLog: 10,
      quotientDegreeRows: 64,
      fri: {
        logBlowup: 4,
        finalLogDegree: 3,
        foldLog: 2,
        queryOrbitLog: 3,
        queries: 8,
        grindBits: 0,
      },
    };
    const transcriptInitial = new TextEncoder().encode("v17-index-free-opening-kat");
    const constructionDescriptor = new TextEncoder().encode("v17-index-free-construction-kat");
    const constructionDigest = sha256(constructionDescriptor);
    const publicWords = [{ id: 1n, row: 0, expected: 0 }];
    const matrixTrees = Object.fromEntries(LOCAL_WORD_MATRIX_NAMES.map((matrix) => {
      const descriptor = localWordV17MatrixMerkleDescriptor(matrix, parameters);
      return [matrix, new V17MerkleTree(
        descriptor,
        Array.from({ length: 2 ** descriptor.logRows }, () => new Uint8Array(descriptor.rowWidth)),
      )];
    })) as Record<typeof LOCAL_WORD_MATRIX_NAMES[number], V17MerkleTree>;
    const friTrees = localWordFriLayerLogs(parameters).map((_, layer) => {
      const descriptor = localWordV17FriMerkleDescriptor(layer, parameters);
      return new V17MerkleTree(
        descriptor,
        Array.from({ length: 2 ** descriptor.logRows }, () => encodeQm31(QM31_ZERO)),
      );
    });
    const { transcript, challenges } = localWordInteractionTranscript(
      transcriptInitial,
      V17_PROOF_PROTOCOL_ID,
      matrixTrees.preprocessed.root,
      matrixTrees.original.root,
    );
    const boundary = poolLocalBoundaryClaimForWords(publicWords, challenges.boundary);
    localWordPublicBoundaryTranscript(transcript, boundary.publicInverses);
    const interactionDigest = transcript.digest;
    const composition = localWordCompositionTranscript(
      transcript,
      matrixTrees.interaction.root,
      matrixTrees.interactionGlobal.root,
    );
    transcript.absorb("local-word-quotient-and-fri-mask-root", matrixTrees.quotientAndFriMask.root);
    const batchBeta = transcript.challengeQm31("local-word-batch-beta");
    const batchDigest = transcript.digest;
    const friAlphas: QM31El[] = [];
    let friMidDigest = new Uint8Array();
    friTrees.forEach((tree, layer) => {
      transcript.absorb(`fri-root:${layer}`, tree.root);
      friAlphas.push(transcript.challengeQm31(`fri-alpha:${layer}`));
      if (layer + 1 === Math.ceil(friTrees.length / 2)) friMidDigest = transcript.digest;
    });
    const friRootsDigest = transcript.digest;
    const finalCoefficients = Array.from(
      { length: 2 ** parameters.fri.finalLogDegree },
      (): QM31El => QM31_ZERO,
    );
    transcript.absorb("fri-final", concatBytes(...finalCoefficients.map(encodeQm31)));
    assert.equal(transcript.acceptGrind(0, 0), true);
    const queries = localWordQueryIndices(transcript, parameters);
    const schedules = localWordOpeningSchedules(queries, parameters);
    const matrices = Object.fromEntries(LOCAL_WORD_MATRIX_NAMES.map((matrix) => {
      const tree = matrixTrees[matrix];
      const indices = matrix === "interactionGlobal" ? schedules.global : schedules.current;
      const opening = tree.opening(indices);
      return [matrix, {
        root: tree.root,
        rowWidth: tree.descriptor.rowWidth,
        indices,
        rows: opening.rows.map(({ raw }) => raw),
        siblings: opening.siblings,
      }];
    })) as unknown as Parameters<typeof encodeLocalWordSealedProof>[0]["matrices"];
    const proof: Parameters<typeof encodeLocalWordSealedProof>[0] = {
      version: 17,
      profile: 0,
      protocolId: V17_PROOF_PROTOCOL_ID,
      proofLength: 0,
      publicBoundaryInverses: boundary.publicInverses,
      publicBoundaryClaimedSum: boundary.claimedSum,
      matrices,
      fri: {
        layers: friTrees.map((tree, layer) => {
          const opening = tree.opening(schedules.fri[layer]!);
          return {
            root: tree.root,
            indices: schedules.fri[layer]!,
            values: opening.rows.map((): QM31El => QM31_ZERO),
            siblings: opening.siblings,
          };
        }),
        finalCoefficients,
        grindNonce: 0,
      },
      transcriptManifest: {
        interactionChallenges: localWordInteractionChallengeValues(challenges),
        interactionDigest,
        constraintAlpha: composition.constraintAlpha,
        compositionDigest: composition.digest,
        batchBeta,
        batchDigest,
        friAlphas,
        friMidDigest,
        friRootsDigest,
        queryDigest: transcript.digest,
      },
      queries,
    };
    const context = {
      profile: 0,
      transcriptInitial,
      constructionDescriptor,
      publicWords,
      expectedPreprocessedRoot: matrixTrees.preprocessed.root,
    };
    const encoded = encodeLocalWordSealedProof(proof, parameters);
    const directory = localWordProofDirectory(queries, publicWords.length, parameters);
    assert.ok(directory.openings.every(({ indicesStart, rowsStart }) => indicesStart === rowsStart));
    assert.ok(encoded.length <= localWordMaximumCanonicalProofBytes(1, parameters));
    const decoded = decodeLocalWordSealedProof(encoded, context, parameters);
    assert.deepEqual(encodeLocalWordSealedProof(decoded, parameters), encoded);
    const frames = frameLocalWordSealedProof(decoded, parameters);
    assert.equal(frames.at(-1)!.end, encoded.length);
    assert.equal(frames.some(({ kind }) => kind === "opening-index"), false);
    const firstBody = directory.openings[0]!;
    assert.equal(firstBody.rowsStart, localWordProofStaticOffsets(1, parameters).openingBodies);
    assert.equal(decoded.version, 17);
  });

  it("reconstructs global and FRI sorted indices from query/rank manifests in BCH", () => {
    const parameters: LocalWordProofParameters = {
      relationLog: 6,
      evalLog: 10,
      quotientDegreeRows: 64,
      fri: {
        logBlowup: 4,
        finalLogDegree: 3,
        foldLog: 2,
        queryOrbitLog: 3,
        queries: 8,
        grindBits: 0,
      },
    };
    const queries = fixtureQueries(parameters);
    const offsets = localWordProofStaticOffsets(1, parameters);
    const directory = localWordProofDirectory(queries, 1, parameters);
    const proof = new Uint8Array(LOCAL_WORD_CARRIER_MIN_PROOF_BYTES);
    proof.set(new TextEncoder().encode("SKLW"), 0);
    proof[4] = 17;
    proof.set(writeU32BE(proof.length), 38);
    queries.forEach((query, item) => proof.set(writeU32BE(query), offsets.queries + item * 4));
    directory.currentIndices.forEach((index, item) =>
      proof.set(writeU32BE(index), offsets.currentIndices + item * 4));
    proof.set(directory.bytes, offsets.currentRanks);
    const schedules = localWordOpeningSchedules(queries, parameters);

    for (const opening of [
      { opening: "global" as const },
      { opening: "fri" as const, friLayer: 0 },
      { opening: "fri" as const, friLayer: 1 },
    ]) {
      const friLayer = "friLayer" in opening ? opening.friLayer : undefined;
      const openingIndex = friLayer === undefined
        ? LOCAL_WORD_MATRIX_NAMES.indexOf("interactionGlobal")
        : LOCAL_WORD_MATRIX_NAMES.length + friLayer;
      installCompactV17Opening({
        proof,
        publicWordCount: 1,
        parameters,
        descriptor: friLayer === undefined
          ? localWordV17MatrixMerkleDescriptor("interactionGlobal", parameters)
          : localWordV17FriMerkleDescriptor(friLayer, parameters),
        openingIndex,
        rootOffset: friLayer === undefined
          ? offsets.matrixRoots + openingIndex * 32
          : offsets.friRoots + friLayer * 32,
        indices: friLayer === undefined ? schedules.global : schedules.fri[friLayer]!,
        cutBits: friLayer === undefined
          ? localWordV17MerkleCuts({ matrix: "interactionGlobal", parameters })
          : localWordV17MerkleCuts({ friLayer, parameters }),
      });
      const roles = opening.opening === "global"
        ? ([
          { ...opening, stage: "current" as const },
          { ...opening, stage: "previous" as const },
          { ...opening, stage: "shape" as const },
        ])
        : ([
          { ...opening, stage: "current" as const, mappingShard: 0, mappingShards: 2 },
          { ...opening, stage: "current" as const, mappingShard: 1, mappingShards: 2 },
          { ...opening, stage: "shape" as const },
        ]);
      for (const role of roles) {
        const gate = compileLocalWordOpeningScheduleGate({
          ...role,
          publicWordCount: 1,
          parameters,
        });
        const honest = evaluateProofGate(proof, gate);
        assert.equal(honest.ok, true,
          `${opening.opening}:${"friLayer" in opening ? opening.friLayer : "-"}:` +
          `${role.stage} ${String(honest.state.error)}`);
        assert.ok(gate.length < 10_000);
      }
    }
    const changedRank = proof.slice();
    changedRank[offsets.globalCurrentRanks]! ^= 1;
    assert.equal(evaluateProofGate(changedRank, compileLocalWordOpeningScheduleGate({
      opening: "global",
      stage: "current",
      publicWordCount: 1,
      parameters,
    })).ok, false);
    const changedQuery = proof.slice();
    changedQuery[offsets.queries + 2]! ^= 1;
    assert.equal(evaluateProofGate(changedQuery, compileLocalWordOpeningScheduleGate({
      opening: "fri",
      friLayer: 0,
      stage: "current",
      mappingShard: 0,
      mappingShards: 2,
      publicWordCount: 1,
      parameters,
    })).ok, false);
  });

  it("measures every production index-reconstruction gate", () => {
    const parameters = LOCAL_WORD_PRODUCTION_PARAMETERS;
    const queries = fixtureQueries(parameters);
    const offsets = localWordProofStaticOffsets(8, parameters);
    const directory = localWordProofDirectory(queries, 8, parameters);
    const proof = new Uint8Array(localWordMaximumCanonicalProofBytes(8));
    proof.set(new TextEncoder().encode("SKLW"), 0);
    proof[4] = 17;
    proof.set(writeU32BE(proof.length), 38);
    queries.forEach((query, item) => proof.set(writeU32BE(query), offsets.queries + item * 4));
    directory.currentIndices.forEach((index, item) =>
      proof.set(writeU32BE(index), offsets.currentIndices + item * 4));
    proof.set(directory.bytes, offsets.currentRanks);
    const schedules = localWordOpeningSchedules(queries, parameters);
    const openings = [
      ...(["current", "previous", "shape"] as const).map((stage) =>
        ({ opening: "global" as const, stage })),
      ...Array.from({ length: 9 }, (_, friLayer) =>
        [
          { opening: "fri" as const, friLayer, stage: "current" as const,
            mappingShard: 0, mappingShards: 2 },
          { opening: "fri" as const, friLayer, stage: "current" as const,
            mappingShard: 1, mappingShards: 2 },
          { opening: "fri" as const, friLayer, stage: "shape" as const },
        ]).flat(),
    ];
    const measurements = openings.map((opening) => {
      const friLayer = "friLayer" in opening ? opening.friLayer : undefined;
      const openingIndex = friLayer === undefined
        ? LOCAL_WORD_MATRIX_NAMES.indexOf("interactionGlobal")
        : LOCAL_WORD_MATRIX_NAMES.length + friLayer;
      const descriptor = friLayer === undefined
        ? localWordV17MatrixMerkleDescriptor("interactionGlobal", parameters)
        : localWordV17FriMerkleDescriptor(friLayer, parameters);
      installCompactV17Opening({
        proof,
        publicWordCount: 8,
        parameters,
        descriptor,
        openingIndex,
        rootOffset: friLayer === undefined
          ? offsets.matrixRoots + openingIndex * 32
          : offsets.friRoots + friLayer * 32,
        indices: friLayer === undefined ? schedules.global : schedules.fri[friLayer]!,
        cutBits: friLayer === undefined
          ? localWordV17MerkleCuts({ matrix: "interactionGlobal", parameters })
          : localWordV17MerkleCuts({ friLayer, parameters }),
      });
      const gate = compileLocalWordOpeningScheduleGate({
        ...opening,
        publicWordCount: 8,
        parameters,
      });
      const result = evaluateProofGate(proof, gate);
      assert.equal(result.ok, true,
        `${opening.opening}:${"friLayer" in opening ? opening.friLayer : "-"} ${String(result.state.error)}`);
      return {
        opening: opening.opening,
        layer: "friLayer" in opening ? opening.friLayer : undefined,
        stage: opening.stage,
        shard: "mappingShard" in opening ? opening.mappingShard : undefined,
        lockingBytes: gate.length,
        operationCost: Number(result.state.metrics.operationCost),
      };
    });
    console.log("v17-index-reconstruction-measurements", JSON.stringify(measurements));
    assert.ok(measurements.every(({ lockingBytes, operationCost }) =>
      lockingBytes < 10_000 && operationCost < 8_025_600));
  });

  it("binds rows, indices, and hashes at the mandatory level-zero frontier", () => {
    const parameters: LocalWordProofParameters = {
      relationLog: 6,
      evalLog: 10,
      quotientDegreeRows: 64,
      fri: {
        logBlowup: 4,
        finalLogDegree: 3,
        foldLog: 2,
        queryOrbitLog: 3,
        queries: 8,
        grindBits: 0,
      },
    };
    const queries = fixtureQueries(parameters);
    const schedules = localWordOpeningSchedules(queries, parameters);
    const offsets = localWordProofStaticOffsets(1, parameters);
    const directory = localWordProofDirectory(queries, 1, parameters);
    const baseProof = new Uint8Array(LOCAL_WORD_CARRIER_MIN_PROOF_BYTES);
    baseProof.set(new TextEncoder().encode("SKLW"), 0);
    baseProof[4] = 17;
    baseProof.set(writeU32BE(baseProof.length), 38);
    schedules.current.forEach((index, item) =>
      baseProof.set(writeU32BE(index), offsets.currentIndices + item * 4));
    baseProof.set(directory.bytes, offsets.currentRanks);
    for (const target of [
      { friLayer: 0 },
      { matrix: "original" as const },
    ]) {
      const proof = baseProof.slice();
      const friLayer = "friLayer" in target ? target.friLayer : undefined;
      const matrix = friLayer === undefined ? target.matrix! : undefined;
      const openingIndex = friLayer === undefined
        ? LOCAL_WORD_MATRIX_NAMES.indexOf(matrix!)
        : LOCAL_WORD_MATRIX_NAMES.length + friLayer;
      const descriptor = friLayer === undefined
        ? localWordV17MatrixMerkleDescriptor(matrix!, parameters)
        : localWordV17FriMerkleDescriptor(friLayer, parameters);
      const installed = installCompactV17Opening({
        proof,
        publicWordCount: 1,
        parameters,
        descriptor,
        openingIndex,
        rootOffset: friLayer === undefined
          ? offsets.matrixRoots + openingIndex * 32
          : offsets.friRoots + friLayer * 32,
        indices: friLayer === undefined ? schedules.current : schedules.fri[friLayer]!,
        cutBits: friLayer === undefined
          ? localWordV17MerkleCuts({ matrix: matrix!, parameters })
          : localWordV17MerkleCuts({ friLayer, parameters }),
      });
      const gate = compileLocalWordMerkleLeafGate({
        ...(friLayer === undefined ? { matrix: matrix! } : { friLayer }),
        shard: 0,
        shards: 1,
        publicWordCount: 1,
        parameters,
      });
      const honest = evaluateProofGate(proof, gate);
      assert.equal(honest.ok, true, `${descriptor.label}: ${String(honest.state.error)}`);
      for (const byteOffset of [
        installed.rowsStart,
        installed.frontierStarts[0]!,
        installed.frontierStarts[0]! + 4,
        offsets.openingDirectory + openingIndex * 20 + 4,
        offsets.openingDirectory + openingIndex * 20 + 12,
      ]) {
        assert.equal(evaluateProofGate(mutate(proof, byteOffset), gate).ok, false,
          `${descriptor.label}:${byteOffset}`);
      }
      const orderGate = friLayer === undefined ? gate : compileLocalWordOpeningScheduleGate({
        publicWordCount: 1,
        parameters,
        opening: "fri",
        friLayer,
        stage: "shape",
      });
      assert.equal(evaluateProofGate(proof, orderGate).ok, true,
        `${descriptor.label}:frontier-order-honest`);
      assert.equal(evaluateProofGate(swapFixed(
        proof,
        installed.frontierStarts[0]!,
        installed.frontierStarts[0]! + 36,
        36,
      ), orderGate).ok, false, `${descriptor.label}:frontier-order`);
    }
  });

  it("derives the minimum q44 level-zero leaf shards from exact BCH measurements", () => {
    const parameters = LOCAL_WORD_PRODUCTION_PARAMETERS;
    const queries = fixtureQueries(parameters);
    const schedules = localWordOpeningSchedules(queries, parameters);
    const offsets = localWordProofStaticOffsets(8, parameters);
    const directory = localWordProofDirectory(queries, 8, parameters);
    const baseProof = new Uint8Array(localWordMaximumCanonicalProofBytes(8));
    baseProof.set(new TextEncoder().encode("SKLW"), 0);
    baseProof[4] = 17;
    baseProof.set(writeU32BE(baseProof.length), 38);
    schedules.current.forEach((index, item) =>
      baseProof.set(writeU32BE(index), offsets.currentIndices + item * 4));
    baseProof.set(directory.bytes, offsets.currentRanks);
    const targets: readonly (
      { readonly matrix: LocalWordMatrixName } | { readonly friLayer: number }
    )[] = [
      ...LOCAL_WORD_MATRIX_NAMES.map((matrix) => ({ matrix })),
      ...Array.from({ length: 9 }, (_, friLayer) => ({ friLayer })),
    ];
    const selectedMeasurements: {
      readonly name: string;
      readonly inputIndex: number;
      readonly lockingBytes: number;
      readonly operationCost: number;
      readonly requiredProofBytes: number;
      readonly capacity: number;
      readonly ok: boolean;
    }[] = [];
    const measurements = targets.map((target) => {
      const proof = baseProof.slice();
      const matrix = "matrix" in target ? target.matrix : undefined;
      const friLayer = "friLayer" in target ? target.friLayer : undefined;
      const openingIndex = friLayer === undefined
        ? LOCAL_WORD_MATRIX_NAMES.indexOf(matrix!)
        : LOCAL_WORD_MATRIX_NAMES.length + friLayer;
      const descriptor = friLayer === undefined
        ? localWordV17MatrixMerkleDescriptor(matrix!, parameters)
        : localWordV17FriMerkleDescriptor(friLayer, parameters);
      installCompactV17Opening({
        proof,
        publicWordCount: 8,
        parameters,
        descriptor,
        openingIndex,
        rootOffset: friLayer === undefined
          ? offsets.matrixRoots + openingIndex * 32
          : offsets.friRoots + friLayer * 32,
        indices: friLayer === undefined
          ? matrix === "interactionGlobal" ? schedules.global : schedules.current
          : schedules.fri[friLayer]!,
        cutBits: friLayer === undefined
          ? localWordV17MerkleCuts({ matrix: matrix!, parameters })
          : localWordV17MerkleCuts({ friLayer, parameters }),
      });
      const selected = V17_PRODUCTION_ROLE_LAYOUT.filter((role) =>
        friLayer === undefined
          ? role.kind === "matrix-merkle-leaf" && role.matrix === matrix
          : role.kind === "fri-merkle-leaf" && role.layer === friLayer);
      selected.forEach((role) => {
        if (role.kind !== "matrix-merkle-leaf" && role.kind !== "fri-merkle-leaf") {
          throw new Error("v17 selected Merkle leaf role");
        }
        const inputIndex = LOCAL_WORD_CANONICAL_ROLE_NAMES.indexOf(role.id) + 1;
        assert.ok(inputIndex > 0, role.id);
        const gate = compileLocalWordMerkleLeafGate({
          ...(role.kind === "matrix-merkle-leaf"
            ? { matrix: role.matrix }
            : { friLayer: role.layer }),
          shard: role.shard,
          shards: role.shards,
          publicWordCount: 8,
          parameters,
        });
        const result = evaluateProofGate(proof, gate, inputIndex);
        const packaged = evaluateP2shProofGate(proof, gate, inputIndex);
        selectedMeasurements.push({
          name: role.id,
          inputIndex,
          lockingBytes: gate.length,
          operationCost: packaged.operationCost,
          requiredProofBytes: packaged.requiredProofBytes,
          capacity: 10_000 - (packaged.unlockingBytes - packaged.carrierBytes),
          ok: result.ok && packaged.ok,
        });
      });
      for (let shards = 1; shards <= 16; shards += 1) {
        try {
          const measured = Array.from({ length: shards }, (_, shard) => {
            const gate = compileLocalWordMerkleLeafGate({
              ...(friLayer === undefined ? { matrix: matrix! } : { friLayer }),
              shard,
              shards,
              publicWordCount: 8,
              parameters,
            });
            const result = evaluateProofGate(proof, gate);
            assert.equal(result.ok, true,
              `${descriptor.label}:${shard}/${shards}:${String(result.state.error)}`);
            return {
              lockingBytes: gate.length,
              operationCost: Number(result.state.metrics.operationCost),
            };
          });
          if (measured.every(({ lockingBytes, operationCost }) =>
            lockingBytes < 10_000 && operationCost < 8_025_600)) {
            return { id: descriptor.label, shards, measured };
          }
        } catch (error) {
          if (!(error instanceof Error) || !/locking limit/.test(error.message)) throw error;
        }
      }
      throw new Error(`no q44 leaf shard plan ${descriptor.label}`);
    });
    console.log("v17-leaf-shard-measurements", JSON.stringify(measurements));
    console.log("v17-selected-leaf-production-measurements", JSON.stringify(selectedMeasurements));
    assert.equal(measurements.length, 14);
    assert.equal(selectedMeasurements.length, 22);
    assert.deepEqual(selectedMeasurements.filter(({ ok, lockingBytes, operationCost,
      requiredProofBytes, capacity }) => !ok || lockingBytes >= 10_000 ||
      operationCost >= 8_032_800 || requiredProofBytes > capacity), []);
  });

  it("certifies provisional q44 parent plans from pre-link BCH measurements", () => {
    const parameters = LOCAL_WORD_PRODUCTION_PARAMETERS;
    const queries = fixtureQueries(parameters);
    const schedules = localWordOpeningSchedules(queries, parameters);
    const offsets = localWordProofStaticOffsets(8, parameters);
    const directory = localWordProofDirectory(queries, 8, parameters);
    const baseProof = new Uint8Array(localWordMaximumCanonicalProofBytes(8));
    baseProof.set(new TextEncoder().encode("SKLW"), 0);
    baseProof[4] = 17;
    baseProof.set(writeU32BE(baseProof.length), 38);
    schedules.current.forEach((index, item) =>
      baseProof.set(writeU32BE(index), offsets.currentIndices + item * 4));
    baseProof.set(directory.bytes, offsets.currentRanks);
    const targets: readonly (
      { readonly matrix: LocalWordMatrixName } | { readonly friLayer: number }
    )[] = [
      ...LOCAL_WORD_MATRIX_NAMES.map((matrix) => ({ matrix })),
      ...Array.from({ length: localWordFriLayerLogs(parameters).length }, (_, friLayer) =>
        ({ friLayer })),
    ];
    const plans = targets.map((target) => {
      const proof = baseProof.slice();
      const matrix = "matrix" in target ? target.matrix : undefined;
      const friLayer = "friLayer" in target ? target.friLayer : undefined;
      const openingIndex = friLayer === undefined
        ? LOCAL_WORD_MATRIX_NAMES.indexOf(matrix!)
        : LOCAL_WORD_MATRIX_NAMES.length + friLayer;
      const descriptor = friLayer === undefined
        ? localWordV17MatrixMerkleDescriptor(matrix!, parameters)
        : localWordV17FriMerkleDescriptor(friLayer, parameters);
      const levels = v17MerkleLevels(descriptor);
      const cutBits = [
        0,
        ...levels.map(({ nextConsumedBits }) => nextConsumedBits)
          .filter((bits) => bits < descriptor.logRows),
      ];
      installCompactV17Opening({
        proof,
        publicWordCount: 8,
        parameters,
        descriptor,
        openingIndex,
        rootOffset: friLayer === undefined
          ? offsets.matrixRoots + openingIndex * 32
          : offsets.friRoots + friLayer * 32,
        indices: friLayer === undefined
          ? matrix === "interactionGlobal" ? schedules.global : schedules.current
          : schedules.fri[friLayer]!,
        cutBits,
      });
      const measurementRole = V17_PRODUCTION_ROLE_LAYOUT.find((role) =>
        friLayer === undefined
          ? role.kind === "matrix-merkle-parent" && role.matrix === matrix && role.stage === 0
          : role.kind === "fri-merkle-parent" && role.layer === friLayer && role.stage === 0)?.id;
      assert.ok(measurementRole, "v17 Merkle measurement role");
      const measurementInputIndex = LOCAL_WORD_CANONICAL_ROLE_NAMES.indexOf(measurementRole) + 1;
      assert.ok(measurementInputIndex > 0, measurementRole);
      const measurementInputIndices = matrix === "interactionGlobal"
        ? Array.from(
          { length: localWordV17MerkleCuts({ matrix, parameters }).length },
          (_, item) => measurementInputIndex + item,
        )
        : [measurementInputIndex];
      const measurements = levels.flatMap((_, startLevel) =>
        Array.from({ length: levels.length - startLevel }, (__, item) => {
          const endLevel = startLevel + item + 1;
          if (new Set(levels.slice(startLevel, endLevel).map(({ arity }) => arity)).size > 1) {
            return undefined;
          }
          const gate = friLayer === undefined
            ? compileLocalWordCurrentMatrixMerkleGate({
              matrix: matrix!,
              publicWordCount: 8,
              parameters,
              measurementSpan: { startLevel, endLevel },
              measurementCutBits: cutBits,
            })
            : compileLocalWordFriMerkleGate({
              layer: friLayer,
              publicWordCount: 8,
              parameters,
              measurementSpan: { startLevel, endLevel },
              measurementCutBits: cutBits,
            });
          const results = measurementInputIndices.map((inputIndex) =>
            evaluateProofGate(proof, gate, inputIndex));
          return {
            startLevel,
            endLevel,
            lockingBytes: gate.length,
            operationCost: Math.max(...results.map(({ state }) =>
              Number(state.metrics.operationCost))),
            consensusValid: results.every(({ ok }) => ok),
          };
        }).filter((measurement) => measurement !== undefined));
      const plan = planV17MerkleStagesFromMeasurements({
        descriptor,
        opening: friLayer === undefined
          ? { openedLeaves: parameters.fri.queries *
            (matrix === "interactionGlobal" ? 2 : 1) }
          : { completeFirstGroups: parameters.fri.queries },
        measurements,
        limits: {
          maxLockingBytes: 10_000,
          maxOperationCost: 8_025_600,
          maxHandoffBytes: 64_000,
        },
      });
      assert.equal(verifyV17MeasuredMerklePlanCertificate(plan.certificate), true);
      assert.ok(plan.stages.every(({ consensusValid }) => consensusValid !== false));
      // This planner intentionally sees only the unpackaged verifier body.
      // Production cuts are graph-owned and are qualified below against their
      // exact carrier, P2SH wrapper, affine density, linked ROM, and BCHN.
      return {
        id: descriptor.label,
        cuts: plan.cuts,
        serializedCutBytes: plan.serializedCutBytes,
        selected: plan.stages.map(({ startLevel, endLevel, lockingBytes, operationCost }) =>
          ({ startLevel, endLevel, lockingBytes, operationCost })),
        candidateCount: measurements.length,
      };
    });
    console.log("v17-parent-plan-measurements", JSON.stringify(plans));
    assert.equal(plans.length, 14);
  });

  it("executes every selected q44 parent at its generated production carrier", () => {
    const parameters = LOCAL_WORD_PRODUCTION_PARAMETERS;
    const queries = fixtureQueries(parameters);
    const schedules = localWordOpeningSchedules(queries, parameters);
    const offsets = localWordProofStaticOffsets(8, parameters);
    const directory = localWordProofDirectory(queries, 8, parameters);
    const baseProof = new Uint8Array(localWordMaximumCanonicalProofBytes(8));
    baseProof.set(new TextEncoder().encode("SKLW"), 0);
    baseProof[4] = 17;
    baseProof.set(writeU32BE(baseProof.length), 38);
    schedules.current.forEach((index, item) =>
      baseProof.set(writeU32BE(index), offsets.currentIndices + item * 4));
    baseProof.set(directory.bytes, offsets.currentRanks);
    const targets: readonly (
      { readonly matrix: LocalWordMatrixName } | { readonly friLayer: number }
    )[] = [
      ...LOCAL_WORD_MATRIX_NAMES.map((matrix) => ({ matrix })),
      ...Array.from({ length: localWordFriLayerLogs(parameters).length }, (_, friLayer) =>
        ({ friLayer })),
    ];
    const measurements = targets.flatMap((target) => {
      const proof = baseProof.slice();
      const matrix = "matrix" in target ? target.matrix : undefined;
      const friLayer = "friLayer" in target ? target.friLayer : undefined;
      const openingIndex = friLayer === undefined
        ? LOCAL_WORD_MATRIX_NAMES.indexOf(matrix!)
        : LOCAL_WORD_MATRIX_NAMES.length + friLayer;
      const descriptor = friLayer === undefined
        ? localWordV17MatrixMerkleDescriptor(matrix!, parameters)
        : localWordV17FriMerkleDescriptor(friLayer, parameters);
      const cutBits = friLayer === undefined
        ? localWordV17MerkleCuts({ matrix: matrix!, parameters })
        : localWordV17MerkleCuts({ friLayer, parameters });
      installCompactV17Opening({
        proof,
        publicWordCount: 8,
        parameters,
        descriptor,
        openingIndex,
        rootOffset: friLayer === undefined
          ? offsets.matrixRoots + openingIndex * 32
          : offsets.friRoots + friLayer * 32,
        indices: friLayer === undefined
          ? matrix === "interactionGlobal" ? schedules.global : schedules.current
          : schedules.fri[friLayer]!,
        cutBits,
      });
      return cutBits.map((_, stage) => {
        const name = V17_PRODUCTION_ROLE_LAYOUT.find((role) =>
          friLayer === undefined
            ? role.kind === "matrix-merkle-parent" && role.matrix === matrix && role.stage === stage
            : role.kind === "fri-merkle-parent" && role.layer === friLayer && role.stage === stage)?.id;
        assert.ok(name, "v17 Merkle selected role");
        const inputIndex = LOCAL_WORD_CANONICAL_ROLE_NAMES.indexOf(name) + 1;
        assert.ok(inputIndex > 0, name);
        const gate = friLayer === undefined
          ? compileLocalWordCurrentMatrixMerkleGate({
            matrix: matrix!, publicWordCount: 8, parameters, stage,
          })
          : compileLocalWordFriMerkleGate({
            layer: friLayer, publicWordCount: 8, parameters, stage,
          });
        const result = evaluateProofGate(proof, gate, inputIndex);
        const packaged = evaluateP2shProofGate(proof, gate, inputIndex);
        return {
          name,
          inputIndex,
          lockingBytes: gate.length,
          operationCost: Number(result.state.metrics.operationCost),
          p2shOperationCost: packaged.operationCost,
          redeemBytes: packaged.redeemBytes,
          unlockingBytes: packaged.unlockingBytes,
          carrierBytes: packaged.carrierBytes,
          requiredProofBytes: packaged.requiredProofBytes,
          ok: result.ok && packaged.ok,
          error: result.state.error ?? packaged.state.error,
        };
      });
    });
    console.log("v17-selected-parent-production-measurements", JSON.stringify(measurements));
    console.log("v17-selected-parent-production-totals", JSON.stringify({
      roles: measurements.length,
      operationCost: measurements.reduce((total, row) => total + row.operationCost, 0),
      p2shOperationCost: measurements.reduce((total, row) => total + row.p2shOperationCost, 0),
      requiredProofBytes: measurements.reduce((total, row) => total + row.requiredProofBytes, 0),
    }));
    assert.equal(measurements.length, 52);
    assert.ok(Math.max(...measurements.map(({ p2shOperationCost }) => p2shOperationCost)) < 7_000_000,
      "the generic parent kernel keeps sibling-buffer refill outside the hot branch");
    assert.deepEqual(measurements.filter(({
      ok, lockingBytes, p2shOperationCost, requiredProofBytes, unlockingBytes, carrierBytes,
    }) => !ok || lockingBytes >= 10_000 || p2shOperationCost >= 8_032_800 ||
      requiredProofBytes > 10_000 - (unlockingBytes - carrierBytes)), []);
  });

  it("executes every generated binary and quartet-first parent stage in BCH", () => {
    const parameters: LocalWordProofParameters = {
      relationLog: 6,
      evalLog: 10,
      quotientDegreeRows: 64,
      fri: {
        logBlowup: 4,
        finalLogDegree: 3,
        foldLog: 2,
        queryOrbitLog: 3,
        queries: 8,
        grindBits: 0,
      },
    };
    const queries = fixtureQueries(parameters);
    const schedules = localWordOpeningSchedules(queries, parameters);
    const offsets = localWordProofStaticOffsets(1, parameters);
    const directory = localWordProofDirectory(queries, 1, parameters);
    const baseProof = new Uint8Array(LOCAL_WORD_CARRIER_MIN_PROOF_BYTES);
    baseProof.set(new TextEncoder().encode("SKLW"), 0);
    baseProof[4] = 17;
    baseProof.set(writeU32BE(baseProof.length), 38);
    baseProof.set(directory.bytes, offsets.currentRanks);
    for (const target of [{ matrix: "original" as const }, { friLayer: 0 }]) {
      const proof = baseProof.slice();
      const friLayer = "friLayer" in target ? target.friLayer : undefined;
      const matrix = friLayer === undefined ? target.matrix! : undefined;
      const openingIndex = friLayer === undefined
        ? LOCAL_WORD_MATRIX_NAMES.indexOf(matrix!)
        : LOCAL_WORD_MATRIX_NAMES.length + friLayer;
      const descriptor = friLayer === undefined
        ? localWordV17MatrixMerkleDescriptor(matrix!, parameters)
        : localWordV17FriMerkleDescriptor(friLayer, parameters);
      const plan = friLayer === undefined
        ? localWordV17MerklePlan({ matrix: matrix!, parameters })
        : localWordV17MerklePlan({ friLayer, parameters });
      const installed = installCompactV17Opening({
        proof,
        publicWordCount: 1,
        parameters,
        descriptor,
        openingIndex,
        rootOffset: friLayer === undefined
          ? offsets.matrixRoots + openingIndex * 32
          : offsets.friRoots + friLayer * 32,
        indices: friLayer === undefined ? schedules.current : schedules.fri[friLayer]!,
        cutBits: [0, ...plan.cuts],
      });
      const gates = plan.stages.map((_, stage) => friLayer === undefined
        ? compileLocalWordCurrentMatrixMerkleGate({
          matrix: matrix!, publicWordCount: 1, parameters, stage,
        })
        : compileLocalWordFriMerkleGate({
          layer: friLayer, publicWordCount: 1, parameters, stage,
        }));
      gates.forEach((gate, stage) => {
        const result = evaluateProofGate(proof, gate);
        assert.equal(result.ok, true,
          `${descriptor.label}:${stage}:${String(result.state.error)}`);
        assert.ok(gate.length < 10_000);
        assert.ok(Number(result.state.metrics.operationCost) < 8_025_600);
      });
      assert.equal(gates.some((gate) => !evaluateProofGate(
        mutate(proof, installed.siblingsStart), gate,
      ).ok), true);
      const finalGate = gates.at(-1)!;
      const rootOffset = friLayer === undefined
        ? offsets.matrixRoots + openingIndex * 32
        : offsets.friRoots + friLayer * 32;
      assert.equal(evaluateProofGate(mutate(proof, rootOffset), finalGate).ok, false);
      if (gates.length > 1) {
        assert.equal(evaluateProofGate(
          mutate(proof, installed.frontierStarts[1]! + 4), gates[0]!,
        ).ok, false);
        assert.equal(evaluateProofGate(
          mutate(proof, installed.frontierStarts[1]! + 4), gates[1]!,
        ).ok, false);
      }
    }
  });

  for (const shape of ["binary", "quartet-first"] as const) {
    it(`executes and adversarially binds the strict ${shape} codec in BCH`, () => {
      const descriptor: V17MerkleDescriptor = {
        shape,
        label: `bch-kat:${shape}`,
        logRows: 3,
        rowWidth: 4,
      };
      const tree = new V17MerkleTree(descriptor, rows(8, 4));
      const indices = shape === "binary" ? [0, 3, 5, 7] : [0, 1, 2, 7];
      const cutBits = shape === "binary" ? [1, 2] : [2];
      const opening = tree.opening(indices);
      const encoded = encodeV17MerkleOpening({
        descriptor,
        rows: opening.rows,
        siblings: opening.siblings,
        cutBits,
      });
      const gate = compileV17MerkleOpeningFixtureGate({
        descriptor,
        indices,
        cutBits,
        expectedRoot: tree.root,
      });
      const honest = evaluate(encoded, gate);
      assert.equal(honest.ok, true, String(honest.state.error));
      assert.ok(gate.length < 10_000);
      assert.ok(Number(honest.state.metrics.operationCost) <
        Number(honest.state.metrics.maximumOperationCost));
      for (const offset of [0, indices.length * descriptor.rowWidth, encoded.length - 1]) {
        assert.equal(evaluate(mutate(encoded, offset), gate).ok, false, `offset=${offset}`);
      }
      assert.equal(evaluate(encoded.slice(0, -1), gate).ok, false);
      assert.equal(evaluate(new Uint8Array([...encoded, 0]), gate).ok, false);
    });
  }

  it("selects cuts only after every candidate has exact BCH measurements", () => {
    const descriptor: V17MerkleDescriptor = {
      shape: "binary",
      label: "bch-measured-planner",
      logRows: 3,
      rowWidth: 4,
    };
    const indices = [0, 3, 5, 7];
    const cutBits = [1, 2];
    const tree = new V17MerkleTree(descriptor, rows(8, 4));
    const opening = tree.opening(indices);
    const encoded = encodeV17MerkleOpening({
      descriptor,
      rows: opening.rows,
      siblings: opening.siblings,
      cutBits,
    });
    const measurements = [];
    for (let startLevel = 0; startLevel < 3; startLevel += 1) {
      for (let endLevel = startLevel + 1; endLevel <= 3; endLevel += 1) {
        const gate = compileV17MerkleOpeningFixtureGate({
          descriptor,
          indices,
          cutBits,
          expectedRoot: tree.root,
          stage: { startLevel, endLevel },
        });
        const result = evaluate(encoded, gate);
        assert.equal(result.ok, true, `${startLevel}:${endLevel} ${String(result.state.error)}`);
        measurements.push({
          startLevel,
          endLevel,
          lockingBytes: gate.length,
          operationCost: Number(result.state.metrics.operationCost),
        });
      }
    }
    const full = measurements.find(({ startLevel, endLevel }) => startLevel === 0 && endLevel === 3)!;
    const twoStageLockingCeiling = Math.max(
      measurements.find(({ startLevel, endLevel }) => startLevel === 0 && endLevel === 1)!.lockingBytes,
      measurements.find(({ startLevel, endLevel }) => startLevel === 1 && endLevel === 3)!.lockingBytes,
    );
    assert.ok(twoStageLockingCeiling < full.lockingBytes);
    const plan = planV17MerkleStagesFromMeasurements({
      descriptor,
      opening: { openedLeaves: indices.length },
      measurements,
      limits: {
        maxLockingBytes: twoStageLockingCeiling,
        maxOperationCost: Math.max(...measurements.map(({ operationCost }) => operationCost), 1),
        maxHandoffBytes: 4_096,
      },
    });
    assert.equal(plan.stages.length, 2);
    assert.equal(verifyV17MeasuredMerklePlanCertificate(plan.certificate), true);
    const incomplete = measurements.slice(1);
    assert.throws(() => planV17MerkleStagesFromMeasurements({
      ...plan.certificate.input,
      measurements: incomplete,
    }), /incomplete/);
    const changed = structuredClone(plan.certificate);
    (changed.input.measurements[0] as { operationCost: number }).operationCost += 1;
    assert.equal(verifyV17MeasuredMerklePlanCertificate(changed), false);
  });
});

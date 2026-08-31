import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  createInstructionSetBch2026,
  createVirtualMachine,
} from "@bitauth/libauth";
import {
  localWordAirResiduals,
  localWordRelationZerofierAtBitReversed,
  mixLocalWordAirResiduals,
  type LocalWordAirFrame,
} from "../src/backends/circle/local-word-air.ts";
import { inv as mInv } from "../src/backends/circle/m31.ts";
import type { LocalWordInteractionChallenges } from
  "../src/backends/circle/local-word-transcript.ts";
import {
  LOCAL_WORD_MATRIX_NAMES,
  LOCAL_WORD_PROOF_LENGTH_OFFSET,
  LOCAL_WORD_PROOF_VERSION,
  localWordProofStaticOffsets,
} from "../src/backends/circle/local-word-sealed-proof.ts";
import { encodeQm31, qm31, qmMulM31, type QM31El } from "../src/backends/circle/qm31.ts";
import {
  buildPoolLocalBoundaryTrace,
  poolLocalBoundaryPreprocessedAt,
} from "../src/chain/pool-relation-local-word-boundary.ts";
import type { PoolLocalShaGraph } from "../src/chain/pool-relation-local-word-machine.ts";
import {
  buildLocalShaTrace,
  executeLocalShaProgram,
  localShaGeometry,
  localShaTableMultiplicitiesForExecution,
  LocalShaCircuitBuilder,
} from "../src/chain/sha256-local-word-machine.ts";
import { buildLocalShaInteractionTrace } from
  "../src/chain/sha256-local-word-interaction.ts";
import {
  compileLocalShaWordCopyPermutation,
  localShaWordRelationFrameAt,
} from "../src/chain/sha256-local-word-permutation.ts";
import {
  compileV17LocalWordAirQuotientGate,
} from "../src/chain/sha256-local-word-vm.ts";
import { localWordRequiredChunkBytes } from "../src/chain/local-word-role-budget.ts";
import {
  localWordVerifierCarrierValue,
  localWordVerifierCarrierSequence,
  localWordPoolCarrierSequence,
  partitionLocalWordProofBytes,
} from "../src/chain/local-word-proof-carriers.ts";
import { concatBytes, writeU32BE, writeU32LE } from "../src/pool/bytes.ts";

const CHALLENGES: LocalWordInteractionChallenges = {
  lookup: {
    gamma: qm31(211n, 223n, 227n, 229n),
    tuple: [
      qm31(233n, 239n, 241n, 251n),
      qm31(257n, 263n, 269n, 271n),
      qm31(277n, 281n, 283n, 293n),
      qm31(307n, 311n, 313n, 317n),
      qm31(331n, 337n, 347n, 349n),
      qm31(353n, 359n, 367n, 373n),
    ] as const,
  },
  wordCopy: {
    gamma: qm31(13n, 17n, 19n, 23n),
    identity: qm31(29n, 31n, 37n, 41n),
    limbs: Array.from({ length: 8 }, (_, limb) =>
      qm31(BigInt(43 + 18 * limb), BigInt(47 + 18 * limb),
        BigInt(53 + 18 * limb), BigInt(59 + 18 * limb))) as
      unknown as LocalWordInteractionChallenges["wordCopy"]["limbs"],
  },
  boundary: {
    gamma: qm31(379n, 383n, 389n, 397n),
    identity: qm31(401n, 409n, 419n, 421n),
    limbs: Array.from({ length: 8 }, (_, limb) =>
      qm31(BigInt(431 + 18 * limb), BigInt(433 + 18 * limb),
        BigInt(439 + 18 * limb), BigInt(443 + 18 * limb))) as unknown as readonly [
      QM31El, QM31El, QM31El, QM31El, QM31El, QM31El, QM31El, QM31El,
    ],
  },
};

function relationFixture() {
  const builder = new LocalShaCircuitBuilder();
  const input = builder.input("public-input");
  const mask = builder.mask("private-mask");
  const rotated = builder.rotate(input, 7, "rotated");
  const output = builder.xor(rotated, mask, "output");
  const program = builder.finish([[output]], []);
  const inputs = [0x1234_5678, 0xffff_ffff];
  const graph: PoolLocalShaGraph = {
    profile: "deposit",
    program,
    inputs,
    inputLayout: [{
      input: 0,
      wire: input,
      label: "public-input",
      visibility: "public",
      value: inputs[0]!,
    }],
    boundaries: [],
    hashes: [],
    relationRows: localShaGeometry(program).relationRows,
    amountWires: { primary: [input], relation: "deposit-public-equality" },
    compressions: 0,
    hasChange: false,
    minerFeeSats: 0n,
  };
  const execution = executeLocalShaProgram(program, inputs);
  const trace = buildLocalShaTrace(program, execution);
  const permutation = compileLocalShaWordCopyPermutation(program);
  const multiplicities = localShaTableMultiplicitiesForExecution(program, execution);
  const interaction = buildLocalShaInteractionTrace(program, trace, CHALLENGES);
  const boundary = buildPoolLocalBoundaryTrace(graph, execution, CHALLENGES.boundary);
  const row = rotated;
  const core = localShaWordRelationFrameAt(program, execution, permutation, multiplicities, row);
  const previous = row - 1;
  const frame: LocalWordAirFrame = {
    original: core.original,
    preprocessed: [...core.preprocessed, ...poolLocalBoundaryPreprocessedAt(graph, row)],
    interaction: [
      ...interaction.columns.map((column) => column[row]!),
      boundary.columns[0][row]!,
      boundary.columns[1][row]!,
    ],
    interactionPrevious: [
      ...interaction.columns.map((column) => column[previous]!),
      boundary.columns[0][previous]!,
      boundary.columns[1][previous]!,
    ],
  };
  return { frame, boundary };
}

function encodeM31Row(values: readonly bigint[]): Uint8Array {
  return concatBytes(...values.map((value) => writeU32LE(Number(value))));
}

function proofFixture(): {
  readonly proof: Uint8Array;
  readonly mutationOffsets: readonly [number, number, number];
  readonly quotientOffset: number;
} {
  const { frame, boundary } = relationFixture();
  const publicWordCount = 8;
  const offsets = localWordProofStaticOffsets(publicWordCount);
  const proof = new Uint8Array(340_382);
  proof.set(new TextEncoder().encode("SKLW"), 0);
  proof[4] = LOCAL_WORD_PROOF_VERSION;
  proof[5] = 0;
  proof.set(writeU32BE(proof.length), LOCAL_WORD_PROOF_LENGTH_OFFSET);
  const challengeValues = [
    CHALLENGES.lookup.gamma,
    ...CHALLENGES.lookup.tuple,
    CHALLENGES.wordCopy.gamma,
    CHALLENGES.wordCopy.identity,
    ...CHALLENGES.wordCopy.limbs,
    CHALLENGES.boundary.gamma,
    CHALLENGES.boundary.identity,
    ...CHALLENGES.boundary.limbs,
  ];
  challengeValues.forEach((challenge, index) =>
    proof.set(encodeQm31(challenge), offsets.interactionChallenges + index * 16));
  proof.set(encodeQm31(boundary.claimedSum), offsets.publicClaimedSum);
  const alpha = qm31(5n, 7n, 11n, 13n);
  proof.set(encodeQm31(alpha), offsets.constraintAlpha);

  const rows = {
    preprocessed: 50_000,
    original: 55_000,
    interaction: 60_000,
    interactionGlobal: 100_000,
    quotientAndFriMask: 110_000,
  } as const;
  for (const [name, start] of Object.entries(rows)) {
    const matrix = LOCAL_WORD_MATRIX_NAMES.indexOf(name as keyof typeof rows);
    proof.set(writeU32BE(start), offsets.openingDirectory + matrix * 20 + 4);
  }
  proof[offsets.currentRanks] = 0;
  proof[offsets.globalCurrentRanks] = 0;
  proof[offsets.globalPreviousRanks] = 1;
  proof.set(encodeM31Row(frame.preprocessed), rows.preprocessed);
  proof.set(encodeM31Row(frame.original), rows.original);
  proof.set(concatBytes(
    ...[0, 1, 2, 3, 4, 5, 6, 7, 9, 10, 11, 12, 13, 15]
      .map((column) => encodeQm31(frame.interaction[column]!)),
  ), rows.interaction);
  proof.set(concatBytes(
    ...[8, 14, 16].map((column) => encodeQm31(frame.interaction[column]!)),
  ), rows.interactionGlobal);
  proof.set(concatBytes(
    ...[8, 14, 16].map((column) => encodeQm31(frame.interactionPrevious[column]!)),
  ), rows.interactionGlobal + 48);
  const residuals = localWordAirResiduals(frame, CHALLENGES, boundary.claimedSum);
  proof.set(writeU32BE(0), offsets.queries);
  const composition = mixLocalWordAirResiduals(residuals, alpha);
  const quotient = qmMulM31(composition, mInv(localWordRelationZerofierAtBitReversed(0)));
  proof.set(encodeQm31(quotient), rows.quotientAndFriMask);
  return {
    proof,
    mutationOffsets: [
      rows.preprocessed,
      rows.preprocessed + 9 * 4,
      rows.interactionGlobal + 32,
    ],
    quotientOffset: rows.quotientAndFriMask,
  };
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

describe("v17 direct local-word AIR on the May-2026 VM", () => {
  it("v17 streams the full AIR directly into the quotient with no carried partial", () => {
    const built = proofFixture();
    const lock = compileV17LocalWordAirQuotientGate({ profile: 0, query: 0 });
    const honest = evaluate(built.proof, lock);
    assert.equal(honest.vm.stateSuccess(honest.state), true, String(honest.state.error));
    for (const mutationOffset of [...built.mutationOffsets, built.quotientOffset]) {
      const changed = built.proof.slice();
      changed[mutationOffset] ^= 1;
      const rejected = evaluate(changed, lock);
      assert.notEqual(rejected.vm.stateSuccess(rejected.state), true);
    }
    console.log("v17-local-word-direct-air-quotient-gate", JSON.stringify({
      lockingBytes: lock.length,
      operationCost: honest.state.metrics.operationCost,
      requiredChunkBytes: localWordRequiredChunkBytes(Number(honest.state.metrics.operationCost)),
    }));
  });
});

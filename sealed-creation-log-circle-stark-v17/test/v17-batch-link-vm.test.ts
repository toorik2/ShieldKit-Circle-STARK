import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  createInstructionSetBch2026,
  createVirtualMachine,
} from "@bitauth/libauth";
import {
  LOCAL_WORD_MATRIX_NAMES,
  LOCAL_WORD_PROOF_LENGTH_OFFSET,
  LOCAL_WORD_PROOF_VERSION,
  localWordProofStaticOffsets,
} from "../src/backends/circle/local-word-sealed-proof.ts";
import { LOCAL_WORD_PRODUCTION_PARAMETERS } from
  "../src/backends/circle/local-word-successor-params.ts";
import {
  encodeQm31,
  liftM31,
  qm31,
  type QM31El,
} from "../src/backends/circle/qm31.ts";
import { v17DegreeCorrectedBatchValue } from
  "../src/backends/circle/v17-ood-air.ts";
import {
  deriveV17OodsChallenge,
  liftCirclePoint,
} from "../src/backends/circle/v17-oods.ts";
import { successorCirclePointAtBitReversed } from
  "../src/backends/circle/successor-domain.ts";
import { V17_THEOREM_ROUND_IDS } from
  "../src/backends/circle/v17-round-transcript.ts";
import {
  V17_MAXIMUM_CANONICAL_PROOF_BYTES,
  V17_PRODUCTION_ROUND_GRINDING,
} from "../src/construction/v17-graph.ts";
import { v17ProofFrameOffset } from "../src/backends/circle/v17-proof-layout.ts";
import {
  encodeV17BatchLeaderCell,
  V17_BATCH_LEADER_CELL_BYTES,
  V17_BATCH_LEADER_CELL_HEADER_BYTES,
} from "../src/backends/circle/v17-batch-leader-cell.ts";
import { compileLocalWordFriBatchGate } from "../src/chain/local-word-algebra-vm.ts";
import { LOCAL_WORD_CANONICAL_ROLE_NAMES } from
  "../src/chain/local-word-carrier-allocation.ts";
import {
  compileLocalWordBatchLeaderCarrierRedeem,
  compileLocalWordCarrierRedeem,
  encodeLocalWordP2shBatchLeaderUnlocking,
  encodeLocalWordP2shCarrierUnlocking,
  LOCAL_WORD_BATCH_LEADER_INPUT_INDEX,
  LOCAL_WORD_CARRIER_MIN_PROOF_BYTES,
  localWordP2sh32Lock,
  localWordPoolCarrierSequence,
  localWordVerifierCarrierSequence,
  localWordVerifierCarrierValue,
  partitionLocalWordProofBytes,
} from "../src/chain/local-word-proof-carriers.ts";
import {
  concatBytes,
  sha256,
  writeU32BE,
  writeU32LE,
} from "../src/pool/bytes.ts";
import { censusV17OpDefineBodies } from "../src/construction/v17-linker.ts";

const QUERY = 777_710;
const PROOF_BYTES = V17_MAXIMUM_CANONICAL_PROOF_BYTES;
if (PROOF_BYTES < LOCAL_WORD_CARRIER_MIN_PROOF_BYTES) {
  throw new Error("v17 batch test allocation geometry");
}

function absorb(state: Uint8Array, label: string, data: Uint8Array): Uint8Array {
  const labelBytes = new TextEncoder().encode(label);
  return sha256(concatBytes(
    Uint8Array.of(0),
    state,
    Uint8Array.of(labelBytes.length),
    labelBytes,
    writeU32LE(data.length),
    data,
  ));
}

function namedRoundBytes(id: typeof V17_THEOREM_ROUND_IDS[number]): Uint8Array {
  const ordinal = V17_THEOREM_ROUND_IDS.indexOf(id);
  const name = new TextEncoder().encode(id);
  return Uint8Array.of(17, ordinal, name.length, ...name);
}

function leadingZeroBits(bytes: Uint8Array): number {
  let bits = 0;
  for (const byte of bytes) {
    if (byte === 0) bits += 8;
    else return bits + Math.clz32(byte) - 24;
  }
  return bits;
}

function oodsTranscript(
  compositionDigest: Uint8Array,
  quotientRoot: Uint8Array,
): { readonly digest: Uint8Array; readonly nonce: number } {
  let state = absorb(
    compositionDigest,
    "local-word-v17-quotient-and-fri-mask-root",
    quotientRoot,
  );
  state = absorb(state, "v17-theorem-round", namedRoundBytes("air:ood"));
  const bits = V17_PRODUCTION_ROUND_GRINDING.find(({ id }) => id === "air:ood")!.bits;
  for (let nonce = 0; nonce <= 0xffff_ffff; nonce += 1) {
    const nonceLe = writeU32LE(nonce);
    const candidate = sha256(concatBytes(Uint8Array.of(3), state, Uint8Array.of(bits), nonceLe));
    if (leadingZeroBits(candidate) >= bits) {
      return { digest: absorb(state, "pow", concatBytes(Uint8Array.of(bits), nonceLe)), nonce };
    }
  }
  throw new Error("v17 batch test PoW exhaustion");
}

function q(seed: number): QM31El {
  return qm31(BigInt(seed + 1), BigInt(seed + 2), BigInt(seed + 3), BigInt(seed + 4));
}

function fixture(profile: 0 | 1 | 2): {
  readonly proof: Uint8Array;
  readonly queryMutations: readonly (readonly number[])[];
  readonly leaderMutations: readonly number[];
} {
  const parameters = LOCAL_WORD_PRODUCTION_PARAMETERS;
  const offsets = localWordProofStaticOffsets(8, parameters);
  const proof = new Uint8Array(PROOF_BYTES);
  proof.set(new TextEncoder().encode("SKLW"), 0);
  proof[4] = LOCAL_WORD_PROOF_VERSION;
  proof[5] = profile;
  proof.set(writeU32BE(proof.length), LOCAL_WORD_PROOF_LENGTH_OFFSET);
  const rowStarts = {
    preprocessed: 90_000,
    original: 100_000,
    interaction: 110_000,
    interactionGlobal: 120_000,
    quotientAndFriMask: 130_000,
    fri0: 140_000,
  } as const;
  LOCAL_WORD_MATRIX_NAMES.forEach((name, matrix) =>
    proof.set(writeU32BE(rowStarts[name]), offsets.openingDirectory + matrix * 20 + 4));
  proof.set(
    writeU32BE(rowStarts.fri0),
    offsets.openingDirectory + LOCAL_WORD_MATRIX_NAMES.length * 20 + 4,
  );

  const beta = q(800);
  const claims = Array.from({ length: 98 }, (_, index) => q(900 + index * 5));
  proof.set(encodeQm31(beta), offsets.batchBeta);
  proof.set(concatBytes(...claims.map(encodeQm31)), offsets.oodValues);

  const compositionDigest = sha256(new TextEncoder().encode(`v17-batch-composition-${profile}`));
  const quotientRoot = sha256(new TextEncoder().encode(`v17-batch-quotient-root-${profile}`));
  proof.set(compositionDigest, offsets.compositionDigest);
  proof.set(
    quotientRoot,
    offsets.matrixRoots + LOCAL_WORD_MATRIX_NAMES.indexOf("quotientAndFriMask") * 32,
  );
  const oods = oodsTranscript(compositionDigest, quotientRoot);
  proof.set(writeU32BE(oods.nonce), v17ProofFrameOffset("roundNonce:air:ood"));
  const oodPoint = deriveV17OodsChallenge(oods.digest).point;
  const currentColumns = [0, 1, 2, 3, 4, 5, 6, 7, 9, 10, 11, 12, 13, 15] as const;
  const globalColumns = [8, 14, 16] as const;
  const queryMutations = Array.from(
    { length: parameters.fri.queries },
    (_, item): readonly number[] => {
      const query = (QUERY + item * 7_919) % (2 ** parameters.evalLog);
      proof.set(writeU32BE(query), offsets.queries + item * 4);
      proof[offsets.currentRanks + item] = item;
      proof[offsets.globalCurrentRanks + item] = item * 2;
      proof[offsets.globalPreviousRanks + item] = item * 2 + 1;
      proof[offsets.friCosetRanks + item] = item * 4;

      const preprocessed = Array.from(
        { length: 43 },
        (_, index) => BigInt((item * 101 + index * 17 + 3) % 10_000),
      );
      const original = Array.from(
        { length: 34 },
        (_, index) => BigInt((item * 103 + index * 19 + 5) % 10_000),
      );
      const current = Array.from({ length: 14 }, (_, index) => q(200 + item * 109 + index * 7));
      const globalCurrent = Array.from(
        { length: 3 },
        (_, index) => q(400 + item * 113 + index * 11),
      );
      const globalPrevious = Array.from(
        { length: 3 },
        (_, index) => q(500 + item * 127 + index * 13),
      );
      const quotient = q(700 + item * 131);
      const mask = q(710 + item * 137);
      const preprocessedOffset = rowStarts.preprocessed + item * 172;
      const originalOffset = rowStarts.original + item * 136;
      const interactionOffset = rowStarts.interaction + item * 224;
      const globalCurrentOffset = rowStarts.interactionGlobal + item * 2 * 48;
      const globalPreviousOffset = globalCurrentOffset + 48;
      const quotientOffset = rowStarts.quotientAndFriMask + item * 32;
      proof.set(
        concatBytes(...preprocessed.map((value) => writeU32LE(Number(value)))),
        preprocessedOffset,
      );
      proof.set(
        concatBytes(...original.map((value) => writeU32LE(Number(value)))),
        originalOffset,
      );
      proof.set(concatBytes(...current.map(encodeQm31)), interactionOffset);
      proof.set(concatBytes(...globalCurrent.map(encodeQm31)), globalCurrentOffset);
      proof.set(concatBytes(...globalPrevious.map(encodeQm31)), globalPreviousOffset);
      proof.set(concatBytes(encodeQm31(quotient), encodeQm31(mask)), quotientOffset);

      const semanticInteraction: QM31El[] = [];
      for (let column = 0; column < 17; column += 1) {
        const currentIndex = currentColumns.indexOf(column as never);
        const globalIndex = globalColumns.indexOf(column as never);
        semanticInteraction.push(
          currentIndex >= 0 ? current[currentIndex]! : globalCurrent[globalIndex]!,
        );
      }
      const functionsAtPoint = [
        ...preprocessed.map(liftM31),
        ...original.map(liftM31),
        ...semanticInteraction,
        ...globalPrevious,
        quotient,
      ];
      assert.equal(functionsAtPoint.length, 98);
      const point = liftCirclePoint(successorCirclePointAtBitReversed(parameters.evalLog, query));
      const openedBatch = v17DegreeCorrectedBatchValue({
        beta,
        functionsAtPoint,
        claimsAtQ: claims,
        maskAtPoint: mask,
        oodPoint,
        point,
      });
      const friOffset = rowStarts.fri0 + item * 64 + (query & 3) * 16;
      proof.set(encodeQm31(openedBatch), friOffset);
      return [
        offsets.queries + item * 4,
        preprocessedOffset,
        originalOffset,
        interactionOffset,
        globalCurrentOffset,
        globalPreviousOffset,
        quotientOffset,
        quotientOffset + 16,
        friOffset,
      ];
    },
  );
  return {
    proof,
    queryMutations,
    leaderMutations: [
      offsets.batchBeta,
      offsets.oodValues + 37 * 16,
      offsets.compositionDigest,
      v17ProofFrameOffset("roundNonce:air:ood"),
    ],
  };
}

function batchInputIndex(query: number): number {
  const role = LOCAL_WORD_CANONICAL_ROLE_NAMES.indexOf(`batch-link-query:${query}`);
  if (role < 0) throw new Error(`v17 batch test role ${query}`);
  return role + 1;
}

function evaluateP2sh(
  proof: Uint8Array,
  verifier: Uint8Array,
  inputIndex: number,
  leaderUnlocking?: Uint8Array,
) {
  const carriers = partitionLocalWordProofBytes(proof);
  const profile = proof[5] as 0 | 1 | 2;
  const leaderVerifier = inputIndex === LOCAL_WORD_BATCH_LEADER_INPUT_INDEX
    ? verifier
    : compileLocalWordFriBatchGate({ profile, query: 0 });
  const leaderRedeem = compileLocalWordBatchLeaderCarrierRedeem({
    index: LOCAL_WORD_BATCH_LEADER_INPUT_INDEX,
    verifier: leaderVerifier,
  });
  const redeem = inputIndex === LOCAL_WORD_BATCH_LEADER_INPUT_INDEX
    ? leaderRedeem
    : compileLocalWordCarrierRedeem({ index: inputIndex, verifier });
  const lockingBytecode = localWordP2sh32Lock(redeem);
  const leaderLockingBytecode = localWordP2sh32Lock(leaderRedeem);
  const canonicalLeaderUnlocking = leaderUnlocking ?? encodeLocalWordP2shBatchLeaderUnlocking(
    carriers[LOCAL_WORD_BATCH_LEADER_INPUT_INDEX]!.chunk,
    encodeV17BatchLeaderCell(proof),
    leaderRedeem,
  );
  const transaction = {
    version: 2,
    locktime: 0,
    inputs: carriers.map((carrier, input) => ({
      outpointTransactionHash: new Uint8Array(32).fill((input + 1) & 0xff),
      outpointIndex: input,
      sequenceNumber: input === 0
        ? localWordPoolCarrierSequence(proof.length)
        : localWordVerifierCarrierSequence(input),
      unlockingBytecode: input === LOCAL_WORD_BATCH_LEADER_INPUT_INDEX
        ? canonicalLeaderUnlocking
        : input === inputIndex
          ? encodeLocalWordP2shCarrierUnlocking(carrier.chunk, redeem)
          : carrier.unlockingBytecode,
    })),
    outputs: [{ lockingBytecode: Uint8Array.of(0x51), valueSatoshis: 1_000n }],
  };
  // This focused test owns P2SH semantics and meters the exact program. The
  // allocation fixed point and independent BCHN product gates own consensus
  // density acceptance for the final linked transaction.
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
    lockingBytecode: index === LOCAL_WORD_BATCH_LEADER_INPUT_INDEX
      ? leaderLockingBytecode
      : lockingBytecode,
    valueSatoshis: index === 0 ? 1_000n : localWordVerifierCarrierValue(index),
  }));
  transaction.outputs = sourceOutputs.map((output) => ({ ...output }));
  const state = vm.evaluate({ inputIndex, sourceOutputs, transaction } as never);
  return {
    vm,
    state,
    carriers,
    redeem,
    leaderRedeem,
    unlocking: transaction.inputs[inputIndex]!.unlockingBytecode,
    leaderUnlocking: transaction.inputs[LOCAL_WORD_BATCH_LEADER_INPUT_INDEX]!.unlockingBytecode,
  };
}

describe("v17 Protocol-4 BCH batch-link role", () => {
  it("owns one shared initializer and one execution-local orchestrator for all followers", () => {
    const leaderSemantics = ([0, 1, 2] as const).map((profile) => {
      const census = censusV17OpDefineBodies(compileLocalWordFriBatchGate({ profile, query: 0 }));
      const semantic = census.filter(({ functionIdHex }) => functionIdHex === "1b");
      assert.equal(semantic.length, 1, `${profile}:0 semantic`);
      assert.equal(semantic[0]!.depth, 0, `${profile}:0 semantic depth`);
      assert.equal(census.filter(({ functionIdHex }) => functionIdHex === "1c").length, 1,
        `${profile}:0 leader authentication`);
      assert.equal(census.filter(({ functionIdHex }) => functionIdHex === "1d").length, 0,
        `${profile}:0 no follower kernel`);
      return semantic[0]!;
    });
    assert.equal(new Set(leaderSemantics.map(({ bodySha256Hex }) => bodySha256Hex)).size, 1);

    const followers = ([0, 1, 2] as const).flatMap((profile) =>
      Array.from(
        { length: LOCAL_WORD_PRODUCTION_PARAMETERS.fri.queries - 1 },
        (_, offset) => ({ profile, query: offset + 1 }),
      ));
    const initializers = followers.map(({ profile, query }) => {
      const gate = compileLocalWordFriBatchGate({ profile, query });
      const census = censusV17OpDefineBodies(gate);
      const topLevel = census.filter(({ depth }) => depth === 0);
      const semantic = census.filter(({ functionIdHex }) => functionIdHex === "1b");
      assert.equal(topLevel.length, 2, `${profile}:${query} top-level definitions`);
      assert.equal(topLevel[0]!.functionIdHex, "1d", `${profile}:${query} outer id`);
      assert.equal(topLevel[0]!.body.length, 2_235, `${profile}:${query} shared bytes`);
      assert.equal(topLevel[1]!.functionIdHex, "22", `${profile}:${query} local id`);
      assert.equal(topLevel[1]!.body.length, 2_547, `${profile}:${query} local bytes`);
      assert.equal(semantic.length, 1, `${profile}:${query} semantic`);
      assert.equal(semantic[0]!.depth, 1, `${profile}:${query} nested semantic`);
      assert.ok(census.filter(({ depth }) => depth === 1).length > 1,
        `${profile}:${query} nested helpers`);
      assert.ok(census.every(({ depth }) => depth <= 1), `${profile}:${query} control depth`);
      assert.ok(gate.length < 10_000, `${profile}:${query} gate bytes`);
      return topLevel[0]!;
    });
    assert.equal(initializers.length, 3 * 43);
    assert.equal(new Set(initializers.map(({ bodySha256Hex }) => bodySha256Hex)).size, 1);
    assert.equal(new Set(initializers.map(({ body }) => body.length)).size, 1);
  });

  it("matches the reference relation for all 3 x 44 roles with clean P2SH stacks", () => {
    const rows: {
      readonly profile: 0 | 1 | 2;
      readonly query: number;
      readonly operationCost: number;
      readonly requiredProofBytes: number;
      readonly redeemBytes: number;
      readonly unlockingBytes: number;
    }[] = [];
    for (const profile of [0, 1, 2] as const) {
      const built = fixture(profile);
      for (let query = 0; query < LOCAL_WORD_PRODUCTION_PARAMETERS.fri.queries; query += 1) {
        const inputIndex = batchInputIndex(query);
        const verifier = compileLocalWordFriBatchGate({ profile, query });
        const bounded = evaluateP2sh(built.proof, verifier, inputIndex);
        if (bounded.vm.stateSuccess(bounded.state) !== true) {
          const diagnostic = bounded.state as unknown as { readonly ip?: number };
          console.log("v17-batch-p2sh-debug", JSON.stringify({
            profile,
            query,
            ip: diagnostic.ip,
            stackItems: bounded.state.stack.length,
            alternateStackItems: bounded.state.alternateStack.length,
            top: bounded.state.stack.slice(-4).map((item) => Buffer.from(item).toString("hex")),
            error: String(bounded.state.error),
          }));
        }
        assert.equal(
          bounded.vm.stateSuccess(bounded.state),
          true,
          `${profile}:${query}: chunk=${bounded.carriers[inputIndex]!.chunk.length} ` +
            `unlocking=${bounded.unlocking.length} ${String(bounded.state.error)}`,
        );
        assert.equal(bounded.state.stack.length, 1, `${profile}:${query} clean stack`);
        assert.equal(bounded.state.alternateStack.length, 0, `${profile}:${query} clean altstack`);
        assert.ok(bounded.unlocking.length <= 10_000, `${profile}:${query} unlocking`);
        assert.ok(bounded.redeem.length <= 10_000, `${profile}:${query} redeem`);
        const operationCost = Number(bounded.state.metrics.operationCost);
        const densityControlLength = Number(bounded.state.metrics.densityControlLength);
        rows.push({
          profile,
          query,
          operationCost,
          requiredProofBytes: Math.max(256,
            Math.ceil(operationCost / 800) -
              (densityControlLength - bounded.carriers[inputIndex]!.chunk.length)),
          redeemBytes: bounded.redeem.length,
          unlockingBytes: bounded.unlocking.length,
        });
      }

      for (const query of [0, 21, 43]) {
        const changed = built.proof.slice();
        changed[built.queryMutations[query]!.at(-1)!] ^= 1;
        const rejected = evaluateP2sh(
          changed,
          compileLocalWordFriBatchGate({ profile, query }),
          batchInputIndex(query),
        );
        assert.notEqual(rejected.vm.stateSuccess(rejected.state), true,
          `${profile}:${query} opened-row mutation`);
      }

      for (const offset of built.leaderMutations) {
        const changed = built.proof.slice();
        changed[offset] ^= 1;
        let accepted = false;
        try {
          const rejected = evaluateP2sh(
            changed,
            compileLocalWordFriBatchGate({ profile, query: 0 }),
            LOCAL_WORD_BATCH_LEADER_INPUT_INDEX,
          );
          accepted = rejected.vm.stateSuccess(rejected.state) === true;
        } catch {
          // A mutated 3-bit PoW nonce may be rejected by the transaction encoder.
        }
        assert.equal(accepted, false, `${profile}:0 leader mutation ${offset}`);
      }
    }

    const familyRequired = Array.from(
      { length: LOCAL_WORD_PRODUCTION_PARAMETERS.fri.queries },
      (_, query) => Math.max(...rows.filter((row) => row.query === query)
        .map((row) => row.requiredProofBytes)),
    ).reduce((sum, value) => sum + value, 0);
    console.log("v17-batch-leader-family", JSON.stringify({
      rolesMeasured: rows.length,
      maximumOperationCost: Math.max(...rows.map((row) => row.operationCost)),
      aggregateOperationCost: rows.reduce((sum, row) => sum + row.operationCost, 0),
      maximumRedeemBytes: Math.max(...rows.map((row) => row.redeemBytes)),
      maximumUnlockingBytes: Math.max(...rows.map((row) => row.unlockingBytes)),
      aggregateRequiredProofBytes: familyRequired,
    }));
  });

  it("authenticates the exact PUSHDATA2(chunk) PUSHDATA1(cell) leader transport", () => {
    const built = fixture(0);
    const verifier0 = compileLocalWordFriBatchGate({ profile: 0, query: 0 });
    const honest = evaluateP2sh(
      built.proof,
      verifier0,
      LOCAL_WORD_BATCH_LEADER_INPUT_INDEX,
    );
    assert.equal(honest.vm.stateSuccess(honest.state), true, String(honest.state.error));
    assert.equal(honest.state.stack.length, 1);
    assert.equal(honest.state.alternateStack.length, 0);
    const chunkBytes = honest.carriers[LOCAL_WORD_BATCH_LEADER_INPUT_INDEX]!.chunk.length;
    const cellOpcode = 3 + chunkBytes;
    const cellStart = cellOpcode + 2;
    const redeemStart = cellStart + V17_BATCH_LEADER_CELL_BYTES;
    assert.equal(honest.leaderUnlocking[0], 0x4d);
    assert.equal(honest.leaderUnlocking[cellOpcode], 0x4c);
    assert.equal(honest.leaderUnlocking[cellOpcode + 1], V17_BATCH_LEADER_CELL_BYTES);
    assert.equal(honest.leaderUnlocking[redeemStart], 0x4d);
    assert.deepEqual(
      honest.leaderUnlocking.slice(cellStart, redeemStart),
      encodeV17BatchLeaderCell(built.proof),
    );

    const rejectLeaderUnlocking = (unlocking: Uint8Array, label: string): void => {
      const rejected = evaluateP2sh(
        built.proof,
        verifier0,
        LOCAL_WORD_BATCH_LEADER_INPUT_INDEX,
        unlocking,
      );
      assert.notEqual(rejected.vm.stateSuccess(rejected.state), true, label);
    };
    const nonCanonicalCellPush = honest.leaderUnlocking.slice();
    nonCanonicalCellPush[cellOpcode] = 0x4d;
    rejectLeaderUnlocking(nonCanonicalCellPush, "noncanonical cell push");
    const wrongCellLength = honest.leaderUnlocking.slice();
    wrongCellLength[cellOpcode + 1] = V17_BATCH_LEADER_CELL_BYTES - 1;
    rejectLeaderUnlocking(wrongCellLength, "wrong cell length");
    const wrongCell = honest.leaderUnlocking.slice();
    wrongCell[cellStart + V17_BATCH_LEADER_CELL_HEADER_BYTES + 8 * 16] ^= 1;
    rejectLeaderUnlocking(wrongCell, "mutated authenticated B_Q");
    const extraBeforeRedeem = concatBytes(
      honest.leaderUnlocking.slice(0, redeemStart),
      Uint8Array.of(0),
      honest.leaderUnlocking.slice(redeemStart),
    );
    rejectLeaderUnlocking(extraBeforeRedeem, "extra leader stack item");

    const follower = evaluateP2sh(
      built.proof,
      compileLocalWordFriBatchGate({ profile: 0, query: 1 }),
      batchInputIndex(1),
      nonCanonicalCellPush,
    );
    assert.notEqual(follower.vm.stateSuccess(follower.state), true,
      "follower rejects noncanonical leader input parser");
  });
});

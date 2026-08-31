import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  createInstructionSetBch2026,
  createVirtualMachine,
} from "@bitauth/libauth";
import { M31 } from "../src/backends/circle/m31.ts";
import type { LocalWordInteractionChallenges } from
  "../src/backends/circle/local-word-transcript.ts";
import { localWordInteractionChallengeValues } from
  "../src/backends/circle/local-word-transcript.ts";
import {
  LOCAL_WORD_PROOF_LENGTH_OFFSET,
  LOCAL_WORD_PROOF_MAX_BYTES,
  LOCAL_WORD_PROOF_VERSION,
} from "../src/backends/circle/local-word-sealed-proof.ts";
import {
  encodeQm31,
  qm31,
  qmInv,
  qmMul,
  type QM31El,
} from "../src/backends/circle/qm31.ts";
import {
  V17_OOD_FUNCTION_COUNT,
  v17MixOodAirResiduals,
  v17OodAirResiduals,
  v17OodFunctionValues,
  v17TraceVanishingAtPoint,
  type V17OodAirFrame,
} from "../src/backends/circle/v17-ood-air.ts";
import { deriveV17OodsChallenge } from "../src/backends/circle/v17-oods.ts";
import { v17ProofFrameOffset } from "../src/backends/circle/v17-proof-layout.ts";
import { V17_THEOREM_ROUND_IDS } from
  "../src/backends/circle/v17-round-transcript.ts";
import { V17_PRODUCTION_ROUND_GRINDING } from "../src/construction/v17-graph.ts";
import {
  compileV17OodAirQuotientGate,
  measureV17OodAirQuotientGate,
} from "../src/chain/v17-ood-air-vm.ts";
import {
  LOCAL_WORD_CARRIER_INPUTS,
  compileLocalWordCarrierRedeem,
  encodeLocalWordP2shCarrierUnlocking,
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

const PROOF_BYTES = LOCAL_WORD_PROOF_MAX_BYTES;

function q(seed: number): QM31El {
  return qm31(BigInt(seed + 1), BigInt(seed + 2), BigInt(seed + 3), BigInt(seed + 4));
}

function challenges(seed: number): LocalWordInteractionChallenges {
  let nextSeed = seed;
  const next = () => q(nextSeed += 7);
  return {
    lookup: {
      gamma: next(),
      tuple: Array.from({ length: 6 }, next) as unknown as
        LocalWordInteractionChallenges["lookup"]["tuple"],
    },
    wordCopy: {
      gamma: next(),
      identity: next(),
      limbs: Array.from({ length: 8 }, next) as unknown as
        LocalWordInteractionChallenges["wordCopy"]["limbs"],
    },
    boundary: {
      gamma: next(),
      identity: next(),
      limbs: Array.from({ length: 8 }, next) as unknown as
        LocalWordInteractionChallenges["boundary"]["limbs"],
    },
  };
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

function leadingZeroBits(bytes: Uint8Array): number {
  let bits = 0;
  for (const byte of bytes) {
    if (byte === 0) bits += 8;
    else return bits + Math.clz32(byte) - 24;
  }
  return bits;
}

function oodsTranscript(compositionDigest: Uint8Array, quotientRoot: Uint8Array): {
  readonly digest: Uint8Array;
  readonly nonce: number;
  readonly invalidNonce: number;
} {
  let state = absorb(
    compositionDigest,
    "local-word-v17-quotient-and-fri-mask-root",
    quotientRoot,
  );
  const id = "air:ood" as const;
  const ordinal = V17_THEOREM_ROUND_IDS.indexOf(id);
  const name = new TextEncoder().encode(id);
  state = absorb(state, "v17-theorem-round", Uint8Array.of(17, ordinal, name.length, ...name));
  const bits = V17_PRODUCTION_ROUND_GRINDING.find((round) => round.id === id)!.bits;
  let invalidNonce = -1;
  let accepted: { readonly digest: Uint8Array; readonly nonce: number } | undefined;
  for (let nonce = 0; nonce <= 0xffff_ffff; nonce += 1) {
    const nonceLe = writeU32LE(nonce);
    const candidate = sha256(concatBytes(
      Uint8Array.of(3),
      state,
      Uint8Array.of(bits),
      nonceLe,
    ));
    if (leadingZeroBits(candidate) < bits) {
      if (invalidNonce < 0) invalidNonce = nonce;
    } else if (!accepted) {
      accepted = {
        digest: absorb(state, "pow", concatBytes(Uint8Array.of(bits), nonceLe)),
        nonce,
      };
    }
    if (accepted && invalidNonce >= 0) return { ...accepted, invalidNonce };
  }
  throw new Error("v17 OOD AIR test PoW exhausted");
}

type Fixture = {
  readonly proof: Uint8Array;
  readonly claimOffsetsByResidual: readonly number[];
  readonly mutationOffsets: {
    readonly alpha: number;
    readonly challenge: number;
    readonly claimedSum: number;
    readonly compositionDigest: number;
    readonly quotientRoot: number;
    readonly nonce: number;
    readonly quotientClaim: number;
  };
  readonly invalidNonce: number;
};

function fixture(profile: 0 | 1 | 2): Fixture {
  const proof = new Uint8Array(PROOF_BYTES);
  proof.set(new TextEncoder().encode("SKLW"), 0);
  proof[4] = LOCAL_WORD_PROOF_VERSION;
  proof[v17ProofFrameOffset("profile")] = profile;
  proof.set(writeU32BE(proof.length), LOCAL_WORD_PROOF_LENGTH_OFFSET);

  const frame: V17OodAirFrame = {
    preprocessed: Array.from({ length: 43 }, (_, index) => q(100 + index * 11 + profile)),
    original: Array.from({ length: 34 }, (_, index) => q(1_000 + index * 13 + profile)),
    interaction: Array.from({ length: 17 }, (_, index) => q(2_000 + index * 17 + profile)),
    interactionPrevious: Array.from(
      { length: 17 },
      (_, index) => q(3_000 + index * 19 + profile),
    ),
  };
  const cs = challenges(4_000 + profile * 100);
  const claimedSum = q(5_000 + profile);
  const alpha = q(5_100 + profile);

  const compositionDigest = sha256(new TextEncoder().encode(`v17-ood-air-composition-${profile}`));
  const quotientRoot = sha256(new TextEncoder().encode(`v17-ood-air-quotient-${profile}`));
  const transcript = oodsTranscript(compositionDigest, quotientRoot);
  const oods = deriveV17OodsChallenge(transcript.digest);
  const composition = v17MixOodAirResiduals(v17OodAirResiduals(frame, cs, claimedSum), alpha);
  const zerofier = v17TraceVanishingAtPoint(oods.point, 18);
  const quotient = qmMul(composition, qmInv(zerofier));
  const claims = v17OodFunctionValues(frame, quotient);
  assert.equal(claims.length, V17_OOD_FUNCTION_COUNT);

  proof.set(compositionDigest, v17ProofFrameOffset("compositionDigest"));
  proof.set(quotientRoot, v17ProofFrameOffset("matrixRoot:quotientAndFriMask"));
  proof.set(writeU32BE(transcript.nonce), v17ProofFrameOffset("roundNonce:air:ood"));
  proof.set(
    concatBytes(...localWordInteractionChallengeValues(cs).map(encodeQm31)),
    v17ProofFrameOffset("interactionChallenges"),
  );
  proof.set(encodeQm31(alpha), v17ProofFrameOffset("constraintAlpha"));
  proof.set(encodeQm31(claimedSum), v17ProofFrameOffset("publicClaimedSum"));
  proof.set(concatBytes(...claims.map(encodeQm31)), v17ProofFrameOffset("oodValues"));

  const claimForResidual = [
    77, 78, 79, 80, 81, 82, 83, 84,
    85,
    86, 87, 88,
    89, 90, 91,
    33,
    60, 61, 62, 63, 64, 65, 66,
    92,
    93,
  ];
  assert.equal(claimForResidual.length, 25);
  const oodOffset = v17ProofFrameOffset("oodValues");
  return {
    proof,
    claimOffsetsByResidual: claimForResidual.map((claim) => oodOffset + claim * 16),
    mutationOffsets: {
      alpha: v17ProofFrameOffset("constraintAlpha"),
      challenge: v17ProofFrameOffset("interactionChallenges") + 12 * 16,
      claimedSum: v17ProofFrameOffset("publicClaimedSum"),
      compositionDigest: v17ProofFrameOffset("compositionDigest"),
      quotientRoot: v17ProofFrameOffset("matrixRoot:quotientAndFriMask"),
      nonce: v17ProofFrameOffset("roundNonce:air:ood"),
      quotientClaim: oodOffset + 97 * 16,
    },
    invalidNonce: transcript.invalidNonce,
  };
}

function vm(unbounded: boolean) {
  const instructionSet = createInstructionSetBch2026(false);
  if (!unbounded) return createVirtualMachine(instructionSet);
  const every = instructionSet.every!;
  return createVirtualMachine({
    ...instructionSet,
    every: (state) => {
      state.metrics.maximumOperationCost = 1_000_000_000;
      return every(state);
    },
  });
}

function evaluate(
  proof: Uint8Array,
  lock: Uint8Array,
  inputIndex: number,
  unbounded = true,
) {
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
    outputs: [{ lockingBytecode: Uint8Array.of(0x51), valueSatoshis: 1_000n }],
  };
  const machine = vm(unbounded);
  const sourceOutputs = carriers.map((_, index) => ({
    lockingBytecode: lock,
    valueSatoshis: index === 0 ? 1_000n : localWordVerifierCarrierValue(index),
  }));
  const state = machine.evaluate({ inputIndex, sourceOutputs, transaction } as never);
  return { carriers, machine, state };
}

function largestVerifierCarrier(proof: Uint8Array): number {
  const carriers = partitionLocalWordProofBytes(proof);
  let largest = 1;
  for (let index = 2; index < carriers.length; index += 1) {
    if (carriers[index]!.chunk.length > carriers[largest]!.chunk.length) largest = index;
  }
  return largest;
}

function mutateByte(proof: Uint8Array, offset: number): Uint8Array {
  const changed = proof.slice();
  changed[offset] ^= 1;
  return changed;
}

describe("v17 singleton OOD AIR on the BCH-2026 VM", () => {
  it("checks all 25 residuals and one whole quotient for all three profiles", () => {
    const fixtures = [fixture(0), fixture(1), fixture(2)] as const;
    const locks = [0, 1, 2].map((profile) =>
      compileV17OodAirQuotientGate({ profile: profile as 0 | 1 | 2 }));
    const carrierIndices = fixtures.map(({ proof }) => largestVerifierCarrier(proof));

    fixtures.forEach((built, profile) => {
      const honest = evaluate(built.proof, locks[profile]!, carrierIndices[profile]!);
      assert.equal(
        honest.machine.stateSuccess(honest.state),
        true,
        `${String(honest.state.error)} ${JSON.stringify(
          honest.state.stack.map((item) => Buffer.from(item).toString("hex")),
        )}`,
      );
      const measurement = measureV17OodAirQuotientGate({
        profile: profile as 0 | 1 | 2,
        operationCost: Number(honest.state.metrics.operationCost),
      });
      assert.ok(measurement.lockingBytes <= 10_000);
      assert.ok(measurement.requiredCarrierChunkBytes <= 10_000);
      assert.ok(measurement.persistentStackItems < 1_000);
      assert.ok(measurement.topLevelStackItems < 1_000);
      const productionRedeems = Array.from(
        { length: LOCAL_WORD_CARRIER_INPUTS - 1 },
        (_, offset) => compileLocalWordCarrierRedeem({
          index: offset + 1,
          verifier: locks[profile]!,
        }),
      );
      const longestRedeem = productionRedeems.reduce((longest, redeem) =>
        redeem.length > longest.length ? redeem : longest);
      const minimumProductionUnlock = encodeLocalWordP2shCarrierUnlocking(
        new Uint8Array(256),
        longestRedeem,
      );
      assert.ok(minimumProductionUnlock.length <= 10_000);
      const bounded = evaluate(
        built.proof,
        locks[profile]!,
        carrierIndices[profile]!,
        false,
      );
      assert.equal(bounded.machine.stateSuccess(bounded.state), true, String(bounded.state.error));
      console.log("v17-ood-air-vm", JSON.stringify({
        ...measurement,
        carrierBytes: honest.carriers[carrierIndices[profile]!]!.chunk.length,
        longestRedeemBytes: longestRedeem.length,
        minimumProductionUnlockBytes: minimumProductionUnlock.length,
      }));
    });

    // Each mutation targets a witness coordinate used by the named residual.
    for (let residual = 0; residual < 25; residual += 1) {
      const profile = residual % 3;
      const built = fixtures[profile]!;
      const rejected = evaluate(
        mutateByte(built.proof, built.claimOffsetsByResidual[residual]!),
        locks[profile]!,
        carrierIndices[profile]!,
      );
      assert.notEqual(
        rejected.machine.stateSuccess(rejected.state),
        true,
        `residual mutation ${residual}`,
      );
    }
  });

  it("rejects transcript, quotient, profile, and non-canonical claim mutations", () => {
    const fixtures = [fixture(0), fixture(1), fixture(2)] as const;
    const locks = fixtures.map((_, profile) =>
      compileV17OodAirQuotientGate({ profile: profile as 0 | 1 | 2 }));
    const carrierIndices = fixtures.map(({ proof }) => largestVerifierCarrier(proof));
    const mutations = fixtures.map((built, profile) => {
      const changedNonce = built.proof.slice();
      changedNonce.set(writeU32BE(built.invalidNonce), built.mutationOffsets.nonce);
      const nonCanonical = built.proof.slice();
      nonCanonical.set(writeU32LE(Number(M31)), built.claimOffsetsByResidual[profile]!);
      const wrongProfile = built.proof.slice();
      wrongProfile[v17ProofFrameOffset("profile")] = (profile + 1) % 3;
      return [
        mutateByte(built.proof, built.mutationOffsets.compositionDigest),
        mutateByte(built.proof, built.mutationOffsets.quotientRoot),
        changedNonce,
        mutateByte(built.proof, built.mutationOffsets.quotientClaim),
        mutateByte(built.proof, built.mutationOffsets.alpha),
        mutateByte(built.proof, built.mutationOffsets.challenge),
        mutateByte(built.proof, built.mutationOffsets.claimedSum),
        nonCanonical,
        wrongProfile,
      ];
    });
    mutations.forEach((profileMutations, profile) => {
      profileMutations.forEach((proof, mutation) => {
        const rejected = evaluate(proof, locks[profile]!, carrierIndices[profile]!);
        assert.notEqual(
          rejected.machine.stateSuccess(rejected.state),
          true,
          `profile ${profile} mutation ${mutation}`,
        );
      });
    });
  });
});

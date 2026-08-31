import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { encodeTransaction } from "@bitauth/libauth";
import {
  LOCAL_WORD_PROOF_LENGTH_OFFSET,
  LOCAL_WORD_PROOF_VERSION,
} from "../src/backends/circle/local-word-sealed-proof.ts";
import { V17_BATCH_LEADER_CELL_BYTES } from
  "../src/backends/circle/v17-batch-leader-cell.ts";
import { extractLocalWordProofFromTransaction } from
  "../src/backends/circle/local-word-observer-view.ts";
import {
  encodeLocalWordBatchLeaderUnlockingPrefix,
  encodeLocalWordP2shBatchLeaderUnlocking,
  LOCAL_WORD_BATCH_LEADER_ROLE_ID,
  partitionLocalWordProofBytes,
  reassembleLocalWordProofBytes,
} from "../src/chain/local-word-proof-carriers.ts";
import { V17_BOOTSTRAP_AFFINE_ALLOCATION } from
  "../src/chain/v17-affine-allocation.ts";
import {
  encodeV17CanonicalPush,
  v17CompactUintBytes,
} from "../src/chain/v17-code-rom.ts";
import { V17_PRODUCTION_ROLE_LAYOUT } from "../src/chain/v17-role-layout.ts";
import {
  V17_CONSTRUCTION_GRAPH,
  V17_PROFILES,
  buildV17VerifierPlan,
} from "../src/construction/v17-graph.ts";
import {
  previewV17Rom,
  v17DefinePoliciesForRole,
  type V17PreLinkProgramProfile,
} from "../src/construction/v17-linker.ts";
import {
  V17_ROM_PLACEMENT_INPUT_SCHEMA,
  optimizeV17RomPlacement,
  type V17ExactRoleEnvelope,
  type V17MaterializedRomPlacementCandidate,
  type V17RomPlacementOptimizerInput,
} from "../src/construction/v17-rom-placement-optimizer.ts";
import { writeU32BE } from "../src/pool/bytes.ts";

const LEADER_INPUT = V17_PRODUCTION_ROLE_LAYOUT.find(
  ({ id }) => id === LOCAL_WORD_BATCH_LEADER_ROLE_ID,
)?.logicalInputIndex;

if (LEADER_INPUT !== 2) throw new Error("v17 peripheral leader placement");

function concat(...parts: readonly Uint8Array[]): Uint8Array {
  const result = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

function canonicalProof(): Uint8Array {
  const length = V17_BOOTSTRAP_AFFINE_ALLOCATION.minimumProofBytes;
  const proof = Uint8Array.from({ length }, (_, index) => (index * 17 + 5) & 0xff);
  proof.set(new TextEncoder().encode("SKLW"), 0);
  proof[4] = LOCAL_WORD_PROOF_VERSION;
  proof[5] = 0;
  proof.set(writeU32BE(length), LOCAL_WORD_PROOF_LENGTH_OFFSET);
  return proof;
}

type PrefixMutation = (args: {
  readonly roleId: string;
  readonly ordinaryPrefix: Uint8Array;
  readonly leaderPrefix: Uint8Array;
}) => Uint8Array | undefined;

function preLinkProfiles(mutate?: PrefixMutation): readonly [
  V17PreLinkProgramProfile,
  V17PreLinkProgramProfile,
  V17PreLinkProgramProfile,
] {
  const plan = buildV17VerifierPlan();
  const proofCarrierBytes = V17_CONSTRUCTION_GRAPH.allocation.minimumProofBytesPerRole;
  const proofChunk = new Uint8Array(proofCarrierBytes);
  const ordinaryPrefix = encodeV17CanonicalPush(proofChunk);
  const leaderPrefix = encodeLocalWordBatchLeaderUnlockingPrefix(
    proofChunk,
    new Uint8Array(V17_BATCH_LEADER_CELL_BYTES),
  );
  const redeemBytecode = Uint8Array.of(0x75, 0x51); // OP_DROP OP_TRUE
  return V17_PROFILES.map((profile): V17PreLinkProgramProfile => ({
    baselinePhase: "pre-link-program-census",
    qualification: "non-executable-non-measurement",
    profile,
    baselineInputCount: plan.roles.length,
    baselineOutputCount: plan.roles.length,
    programCensusSha256Hex: (profile + 1).toString(16).padStart(2, "0").repeat(32),
    workers: plan.roles.map((role, logicalInputIndex) => {
      const expectedPrefix = role.id === LOCAL_WORD_BATCH_LEADER_ROLE_ID
        ? leaderPrefix
        : ordinaryPrefix;
      return {
        profile,
        logicalInputIndex,
        roleId: role.id,
        redeemBytecode,
        unlockingPrefixBytecode: mutate?.({
          roleId: role.id,
          ordinaryPrefix,
          leaderPrefix,
        }) ?? expectedPrefix,
        proofCarrierBytes,
        valueSatoshis: logicalInputIndex === 0 ? 0n : 1_000n + BigInt(logicalInputIndex),
        sequenceNumber: 0x8000_0000 + logicalInputIndex,
        definePolicies: v17DefinePoliciesForRole({ roleId: role.id, redeemBytecode }),
      };
    }),
  })) as unknown as readonly [
    V17PreLinkProgramProfile,
    V17PreLinkProgramProfile,
    V17PreLinkProgramProfile,
  ];
}

function hex32(byte: number): string {
  return byte.toString(16).padStart(2, "0").repeat(32);
}

function encodedPushBytes(payloadBytes: number): number {
  if (payloadBytes === 0) return 1;
  if (payloadBytes <= 75) return payloadBytes + 1;
  if (payloadBytes <= 0xff) return payloadBytes + 2;
  if (payloadBytes <= 0xffff) return payloadBytes + 3;
  return payloadBytes + 5;
}

function serializedInputBytes(unlockingBytes: number): number {
  return 40 + v17CompactUintBytes(unlockingBytes) + unlockingBytes;
}

function optimizerInput(roleId: string, unlockingBytes: number): V17RomPlacementOptimizerInput {
  const proofCarrierBytes = 256;
  const redeemBytes = 300;
  const role = (profile: 0 | 1 | 2): V17ExactRoleEnvelope => ({
    logicalInputIndex: 0,
    roleId,
    proofCarrierBytes,
    redeemBytes,
    unlockingBytes,
    redeemSha256Hex: hex32(20 + profile),
    unlockingSha256Hex: hex32(30 + profile),
    maximumOperationCost: 1_000,
    operationCostEngine: "independent-bchn-conformant",
    operationCostEvidenceSha256Hex: hex32(40 + profile),
  });
  const nonRoleTransactionBytes = 100;
  const profiles = V17_PROFILES.map((profile) => ({
    profile,
    transactionBytes: nonRoleTransactionBytes + serializedInputBytes(unlockingBytes),
    transactionSha256Hex: hex32(50 + profile),
    nonRoleTransactionBytes,
    envelopeEvidenceSha256Hex: hex32(60 + profile),
    roles: [role(profile)],
    pages: [],
  })) as unknown as V17MaterializedRomPlacementCandidate["profiles"];
  return {
    schema: V17_ROM_PLACEMENT_INPUT_SCHEMA,
    status: "complete-exact-envelope-enumeration",
    protocolIdHex: hex32(1),
    constructionGraphSha256Hex: hex32(2),
    occurrenceCensusSha256Hex: hex32(3),
    minimumProofCarrierBytesPerRole: proofCarrierBytes,
    roleIds: [roleId],
    pages: [],
    occurrences: [],
    candidates: [{
      status: "materialized-exact-envelope",
      placements: [],
      profiles,
    }],
  };
}

describe("v17 batch-leader carrier peripheral invariants", () => {
  it("keeps generic first-push proof observation and carrier reassembly unchanged", () => {
    const proof = canonicalProof();
    const carriers = partitionLocalWordProofBytes(proof);
    const cell = Uint8Array.from(
      { length: V17_BATCH_LEADER_CELL_BYTES },
      (_, index) => (index * 29 + 7) & 0xff,
    );
    const redeem = new Uint8Array(256).fill(0x51);
    const leaderUnlocking = encodeLocalWordP2shBatchLeaderUnlocking(
      carriers[LEADER_INPUT]!.chunk,
      cell,
      redeem,
    );
    const transaction = {
      version: 2,
      locktime: 0,
      inputs: carriers.map((carrier, input) => ({
        outpointTransactionHash: new Uint8Array(32).fill((input + 1) & 0xff),
        outpointIndex: input,
        sequenceNumber: 0xffff_ffff,
        unlockingBytecode: input === LEADER_INPUT ? leaderUnlocking : carrier.unlockingBytecode,
      })),
      outputs: [{ lockingBytecode: Uint8Array.of(0x51), valueSatoshis: 1n }],
    };

    assert.deepEqual(reassembleLocalWordProofBytes(carriers), proof);
    assert.deepEqual(
      extractLocalWordProofFromTransaction(
        encodeTransaction(transaction),
        V17_BOOTSTRAP_AFFINE_ALLOCATION,
      ),
      proof,
    );
    const cellOpcode = 3 + carriers[LEADER_INPUT]!.chunk.length;
    assert.equal(leaderUnlocking[cellOpcode], 0x4c);
    assert.equal(leaderUnlocking[cellOpcode + 1], V17_BATCH_LEADER_CELL_BYTES);
  });

  it("accepts only the graph-owned canonical two-push pre-link leader prefix", () => {
    const accepted = previewV17Rom({ profiles: preLinkProfiles() });
    assert.equal(accepted.certificate.status, "preview-only");

    assert.throws(() => previewV17Rom({
      profiles: preLinkProfiles(({ roleId, ordinaryPrefix }) =>
        roleId === LOCAL_WORD_BATCH_LEADER_ROLE_ID ? ordinaryPrefix : undefined),
    }), /pre-link program worker shape/);

    assert.throws(() => previewV17Rom({
      profiles: preLinkProfiles(({ roleId, ordinaryPrefix }) => roleId ===
          LOCAL_WORD_BATCH_LEADER_ROLE_ID
        ? concat(
          ordinaryPrefix,
          Uint8Array.of(
            0x4d,
            V17_BATCH_LEADER_CELL_BYTES & 0xff,
            V17_BATCH_LEADER_CELL_BYTES >>> 8,
          ),
          new Uint8Array(V17_BATCH_LEADER_CELL_BYTES),
        )
        : undefined),
    }), /pre-link program worker shape/);

    assert.throws(() => previewV17Rom({
      profiles: preLinkProfiles(({ roleId, leaderPrefix }) =>
        roleId === "batch-link-query:1" ? leaderPrefix : undefined),
    }), /pre-link program worker shape/);
  });

  it("charges the ROM optimizer exactly 218 extra leader-prefix bytes", () => {
    const proofCarrierBytes = 256;
    const redeemBytes = 300;
    const ordinaryUnlockingBytes = encodedPushBytes(proofCarrierBytes) +
      encodedPushBytes(redeemBytes);
    const leaderUnlockingBytes = ordinaryUnlockingBytes +
      encodedPushBytes(V17_BATCH_LEADER_CELL_BYTES);
    const ordinary = optimizeV17RomPlacement(
      optimizerInput("ordinary-role", ordinaryUnlockingBytes),
    ).profiles[0]!.roles[0]!;
    const leader = optimizeV17RomPlacement(
      optimizerInput(LOCAL_WORD_BATCH_LEADER_ROLE_ID, leaderUnlockingBytes),
    ).profiles[0]!.roles[0]!;

    assert.equal(encodedPushBytes(V17_BATCH_LEADER_CELL_BYTES), 218);
    assert.equal(leader.unlockingBytes - ordinary.unlockingBytes, 218);
    assert.equal(leader.serializedInputBytes - ordinary.serializedInputBytes, 218);
    assert.equal(leader.densityControlLength - ordinary.densityControlLength, 218);
    assert.equal(leader.operationCostLimit - ordinary.operationCostLimit, 218 * 800);
    assert.throws(() => optimizeV17RomPlacement(
      optimizerInput(LOCAL_WORD_BATCH_LEADER_ROLE_ID, ordinaryUnlockingBytes),
    ), /noncanonical carrier unlocking/);
  });
});

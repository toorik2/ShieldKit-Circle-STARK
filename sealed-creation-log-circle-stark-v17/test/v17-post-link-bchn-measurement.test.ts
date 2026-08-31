import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { describe, it } from "node:test";
import {
  reassembleLocalWordProofBytes,
} from "../src/chain/local-word-proof-carriers.ts";
import {
  encodeLocalWordEdgeData,
  encodeLocalWordNullifierData,
} from "../src/chain/local-word-envelope.ts";
import { hashPayoutLocking } from "../src/chain/payout.ts";
import {
  V17_BCHN_ASSAY_ENGINE_VERSION,
  V17_BCHN_ASSAY_SOURCE_TAG_COMMIT,
  V17_BCHN_MAY_2026_CONSENSUS_FLAGS,
  V17_BCHN_TRANSACTION_SIGCHECKS,
} from "../src/assurance/v17-bchn-product-gate.ts";
import {
  materializeV17PostLinkCandidateEnvelopes,
  measureV17PostLinkCandidatesWithBchn,
  type V17PostLinkAssayRequest,
  type V17PostLinkAssayRunner,
} from "../src/assurance/v17-post-link-bchn-measurement.ts";
import { deriveV17LocalSizingAllocation } from
  "../src/assurance/v17-local-sizing-allocation.ts";
import {
  appendV17DensityClosureTrace,
  createV17DensityClosureTrace,
  replayV17DensityClosureTrace,
} from
  "../src/construction/v17-density-closure.ts";
import { compileV17AffineReaderConstruction } from
  "../src/chain/v17-affine-reader-vm.ts";
import { V17_PRODUCTION_ROLE_LAYOUT } from "../src/chain/v17-role-layout.ts";
import {
  bindV17PostLinkEvidence,
  type V17PostLinkCandidateSet,
} from "../src/construction/v17-product-link.ts";
import type { V17RomPreview } from "../src/construction/v17-linker.ts";
import type { V17PublicSettlementFixture } from
  "../src/construction/v17-settlement-transaction.ts";
import { materializeV17SettlementTransaction } from
  "../src/construction/v17-settlement-transaction.ts";
import { V17_PROFILES, type V17Profile } from "../src/construction/v17-graph.ts";
import { emptyState } from "../src/pool/state.ts";
import { EdgeHistory } from "../src/pool/edge-history.ts";
import { SparseNullifierTree } from "../src/pool/sparse-nullifiers.ts";
import { applyDeposit, applyWithdraw, type PoolMachine } from "../src/pool/transition.ts";
import type { Note } from "../src/pool/notes.ts";
import { fakeV17FinalInfrastructureSet } from
  "./helpers/v17-final-infrastructure-fixture.ts";

const CATEGORY = new Uint8Array(32).fill(0x42);
const PAYOUT_LOCK = Uint8Array.of(0x51);
const NOTE: Note = {
  amountSats: 20_041n,
  rho: new Uint8Array(32).fill(0x41),
  ownerSecret: new Uint8Array(32).fill(0xbe),
};

function machine(): PoolMachine {
  return {
    state: emptyState(),
    poolCategory: CATEGORY,
    history: new EdgeHistory(),
    nullifiers: new SparseNullifierTree(),
  };
}

function publicFixture(profile: V17Profile): V17PublicSettlementFixture {
  const deposited = applyDeposit(machine(), NOTE);
  if (profile === 0) {
    return {
      profile,
      statement: deposited.statement,
      minerFeeSatoshis: 300n,
      edgeDataLockingBytecode: encodeLocalWordEdgeData({
        creationIndex: deposited.append.index,
        edge: deposited.append.edge,
        path: deposited.append.path,
      }),
      funding: {
        lockingBytecode: Uint8Array.of(0x51),
        unlockingBytecode: new Uint8Array(),
      },
    };
  }
  const withdrawn = applyWithdraw(
    deposited.machine,
    deposited.created,
    hashPayoutLocking(PAYOUT_LOCK),
    profile === 1 ? NOTE.amountSats : 7_777n,
    profile === 1 ? {} : { changeRho: new Uint8Array(32).fill(0x43) },
  );
  const common = {
    profile,
    statement: withdrawn.statement,
    minerFeeSatoshis: 250n,
    payoutLockingBytecode: PAYOUT_LOCK,
    nullifierDataLockingBytecode: encodeLocalWordNullifierData({
      nullifier: withdrawn.statement.nullifier,
      path: withdrawn.nullifierPath,
    }),
  } as const;
  if (profile === 1) return { ...common, profile: 1 };
  assert.ok(withdrawn.append);
  return {
    ...common,
    profile,
    edgeDataLockingBytecode: encodeLocalWordEdgeData({
      creationIndex: withdrawn.append.index,
      edge: withdrawn.append.edge,
      path: withdrawn.append.path,
    }),
  };
}

function candidateSet(): V17PostLinkCandidateSet {
  const final = fakeV17FinalInfrastructureSet();
  const romPreviewIdHex = final.construction.certificate.romPreviewIdHex;
  const constructionIdHex = final.construction.certificate.constructionIdHex;
  const profiles = final.profiles.map((profile) => ({
    schema: "ShieldKit/V17PostLinkCandidateProfile/v1" as const,
    status: "candidate-envelope-requires-independent-bchn-measurement" as const,
    romPreviewIdHex,
    constructionIdHex,
    profile: profile.profile,
    allocationStatus: profile.allocation.status,
    allocation: profile.allocation,
    projectedInputCount: profile.infrastructure.length + (profile.profile === 0 ? 1 : 0),
    projectedOutputCount: profile.infrastructure.length +
      (profile.profile === 0 ? 1 : profile.profile === 1 ? 2 : 3),
    proofBytes: reassembleLocalWordProofBytes(profile.roles.map((role) => role.carrier),
      profile.allocation),
    roles: profile.roles,
    pages: profile.pages,
  })) as unknown as V17PostLinkCandidateSet["profiles"];
  const linkedRedeemsByProfile = final.profiles.map((profile) =>
    profile.roles.map((role) => role.redeem));
  const preview = {
    certificate: {
      previewIdHex: romPreviewIdHex,
      protocolIdHex: final.construction.certificate.protocolIdHex,
      profiles: final.profiles.map((profile) => ({
        profile: profile.profile,
        linkedRedeemSha256Hexes: profile.roles.map((role) =>
          createHash("sha256").update(role.redeem).digest("hex")),
      })),
    },
    pages: final.construction.pages,
    linkedRedeemsByProfile,
    affineReader: final.construction.affineReader,
  } as unknown as V17RomPreview;
  return {
    schema: "ShieldKit/V17PostLinkCandidateSet/v1",
    status: "candidate-envelope-requires-independent-bchn-measurement",
    constructionIdHex,
    preview,
    profiles,
  };
}

function candidateTrace(candidates: V17PostLinkCandidateSet) {
  const trace = createV17DensityClosureTrace();
  const head = replayV17DensityClosureTrace(trace);
  const measuredRows = V17_PRODUCTION_ROLE_LAYOUT.map((role, index) => ({
    roleId: role.id,
    requiredProofBytes: 256,
    capacityProofBytes: 9_000,
    maximumOperationCost: 1_000 + index,
    profileOperationCosts: [1_000 + index, 1_000 + index, 1_000 + index] as const,
    profileRequiredProofBytes: [256, 256, 256] as const,
    profileCapacityProofBytes: [9_000, 9_000, 9_000] as const,
  }));
  const advanced = appendV17DensityClosureTrace({
    trace,
    phase: "local-sizing",
    currentAllocation: head.allocation,
    currentReader: compileV17AffineReaderConstruction(head.allocation).evidence,
    romPreviewIdHex: candidates.preview.certificate.previewIdHex,
    measurementEvidenceSha256Hex: "55".repeat(32),
    measuredRows,
  });
  assert.deepEqual(replayV17DensityClosureTrace(advanced).allocation,
    candidates.profiles[0].allocation);
  return advanced;
}

function successfulResult(request: V17PostLinkAssayRequest): string {
  const input = request.transaction.inputs[request.inputIndex]!;
  const sourceOutput = request.sourceOutputs[request.inputIndex]!;
  return JSON.stringify({
    engine: "bchn",
    engineVersion: V17_BCHN_ASSAY_ENGINE_VERSION,
    sourceTagCommit: V17_BCHN_ASSAY_SOURCE_TAG_COMMIT,
    scope: "script-input-only",
    mode: "consensus",
    flags: V17_BCHN_MAY_2026_CONSENSUS_FLAGS,
    inputIndex: request.inputIndex,
    inputCount: request.transaction.inputs.length,
    sourceOutputCount: request.sourceOutputs.length,
    transactionBytes: request.transactionBytes.length,
    sourceOutputsBytes: request.sourceOutputsBytes.length,
    unlockingBytecodeBytes: input.unlockingBytecode.length,
    lockingBytecodeBytes: sourceOutput.lockingBytecode.length,
    valid: true,
    scriptErrorCode: 0,
    scriptError: "No error",
    metricsReliable: true,
    metrics: {
      baseOpCost: 700 + request.inputIndex,
      compositeOpCost: 900 + request.inputIndex,
      opCostLimit: 1_000_000,
      hashDigestIterations: request.inputIndex % 7,
      hashDigestIterationsLimit: 1_000_000,
      sigChecks: 0,
      sigChecksInputLimit: null,
      sigChecksTransactionLimit: V17_BCHN_TRANSACTION_SIGCHECKS,
    },
  });
}

function fakeAssay(
  alter?: (result: Record<string, unknown>, request: V17PostLinkAssayRequest) => void,
): { readonly calls: V17PostLinkAssayRequest[]; readonly runner: V17PostLinkAssayRunner } {
  const calls: V17PostLinkAssayRequest[] = [];
  return {
    calls,
    runner: (request) => {
      calls.push(request);
      const result = JSON.parse(successfulResult(request)) as Record<string, unknown>;
      alter?.(result, request);
      return { status: 0, stdout: JSON.stringify(result), stderr: "" };
    },
  };
}

const diagnostics = ({ inputIndex }: { readonly inputIndex: number }) => ({
  maximumMemorySlots: 20 + inputIndex,
  maximumControlDepth: inputIndex % 4,
});

describe("v17 independent BCHN post-link measurement adapter", () => {
  it("uses the exact linked construction identity for candidate synthetic outpoints", () => {
    const candidates = candidateSet();
    const finalInfrastructure = fakeV17FinalInfrastructureSet();
    const fixtures = V17_PROFILES.map(publicFixture);
    const candidateEnvelopes = materializeV17PostLinkCandidateEnvelopes({
      candidates,
      fixtures,
    });

    assert.equal(
      candidates.constructionIdHex,
      finalInfrastructure.construction.certificate.constructionIdHex,
    );
    candidateEnvelopes.forEach((candidateEnvelope, profile) => {
      const final = materializeV17SettlementTransaction({
        infrastructureSet: finalInfrastructure,
        fixture: fixtures[profile]!,
      });
      assert.equal(candidateEnvelope.materialized.constructionIdHex, candidates.constructionIdHex);
      assert.deepEqual(
        candidateEnvelope.materialized.transaction.inputs.map((input) => ({
          outpointTransactionHash: input.outpointTransactionHash,
          outpointIndex: input.outpointIndex,
        })),
        final.transaction.inputs.map((input) => ({
          outpointTransactionHash: input.outpointTransactionHash,
          outpointIndex: input.outpointIndex,
        })),
      );
      assert.deepEqual(candidateEnvelope.materialized.rawTransactionBytes, final.rawTransactionBytes);
      assert.deepEqual(
        candidateEnvelope.materialized.encodedSourceOutputsBytes,
        final.encodedSourceOutputsBytes,
      );
    });
  });

  it("keeps the local executable sizing seed explicitly outside resource evidence", () => {
    const candidates = candidateSet();
    const sizing = deriveV17LocalSizingAllocation({
      candidates,
      fixtures: V17_PROFILES.map(publicFixture),
      trace: candidateTrace(candidates),
    });
    assert.equal(sizing.qualification, "local-sizing-only-not-resource-evidence");
    assert.equal(sizing.engine,
      "libauth-3.1.0-next.8-plus-bchn-v29-op-define-delta-diagnostic");
    assert.match(sizing.measurementSha256Hex, /^[0-9a-f]{64}$/);
    assert.deepEqual(sizing.profiles.map(({ profile, workers }) => [profile, workers]), [
      [0, 210],
      [1, 210],
      [2, 210],
    ]);
    assert.equal(JSON.stringify(sizing).includes("accepted-byte-exact-candidate-envelope"), false);
  });

  it("binds every accepted candidate-envelope input and emits verifier-role allocation rows", () => {
    const candidates = candidateSet();
    const fixtures = V17_PROFILES.map(publicFixture);
    const assay = fakeAssay();
    const envelopes = materializeV17PostLinkCandidateEnvelopes({ candidates, fixtures });
    const evidence = measureV17PostLinkCandidatesWithBchn({
      candidates,
      fixtures,
      assayRunner: assay.runner,
      injectedRunnerQualification: "test-only-nonqualifying",
      memoryControlRunner: diagnostics,
    });
    assert.equal(assay.calls.length,
      envelopes.reduce((sum, envelope) => sum + envelope.materialized.transaction.inputs.length, 0));
    evidence.forEach((profileEvidence, profile) => {
      const candidate = candidates.profiles[profile]!;
      assert.equal(profileEvidence.status, "accepted-byte-exact-candidate-envelope");
      assert.equal(profileEvidence.qualification,
        "candidate-resource-only-not-final-qualification");
      assert.deepEqual(profileEvidence.assayProvenance, {
        mode: "injected-runner-test-only",
        qualification: "test-only-nonqualifying",
      });
      assert.equal(profileEvidence.checkedEnvelopeInputs, candidate.projectedInputCount);
      assert.match(profileEvidence.candidateEnvelopeEvidenceSha256Hex, /^[0-9a-f]{64}$/);
      assert.equal(profileEvidence.workers.length, candidate.roles.length);
      assert.equal(profileEvidence.workers[0]!.fixtureInputCount, candidate.projectedInputCount);
      assert.equal(profileEvidence.workers[0]!.fixtureOutputCount, candidate.projectedOutputCount);
      assert.equal(profileEvidence.workers[17]!.maximumOperationCost, 917);
      assert.equal(profileEvidence.workers[17]!.maximumMemorySlots, 37);
      assert.equal(profileEvidence.workers[17]!.operationCostEngine, "bchn-v29.0.0");
    });
    const bound = bindV17PostLinkEvidence({ candidates, evidence });
    assert.equal(bound.length, 3);
    assert.equal(bound[2].workers.length, candidates.profiles[2].roles.length);

    const second = measureV17PostLinkCandidatesWithBchn({
      candidates,
      fixtures,
      assayRunner: fakeAssay().runner,
      injectedRunnerQualification: "test-only-nonqualifying",
      memoryControlRunner: diagnostics,
    });
    assert.deepEqual(
      second.map((item) => item.candidateEnvelopeEvidenceSha256Hex),
      evidence.map((item) => item.candidateEnvelopeEvidenceSha256Hex),
      "temporary file paths and runner identity must not enter byte-exact evidence",
    );
  });

  it("fails closed on assay identity drift or a non-bank-bound candidate settlement", () => {
    const candidates = candidateSet();
    const fixtures = V17_PROFILES.map(publicFixture);
    const wrongIdentity = fakeAssay((result, request) => {
      if (request.profile === 1 && request.inputIndex === 8) {
        result.sourceOutputCount = request.sourceOutputs.length + 1;
      }
    });
    assert.throws(() => measureV17PostLinkCandidatesWithBchn({
      candidates,
      fixtures,
      assayRunner: wrongIdentity.runner,
      memoryControlRunner: diagnostics,
    }), /injected runner is test-only/);
    assert.throws(() => measureV17PostLinkCandidatesWithBchn({
      candidates,
      fixtures,
      assayRunner: wrongIdentity.runner,
      injectedRunnerQualification: "test-only-nonqualifying",
      memoryControlRunner: diagnostics,
    }), /identity or acceptance 1:8/);

    const roles = [...candidates.profiles[0].roles];
    roles[0] = { ...roles[0]!, verifier: Uint8Array.of(0x51) };
    const wrongSettlement = {
      ...candidates,
      profiles: [
        { ...candidates.profiles[0], roles },
        candidates.profiles[1],
        candidates.profiles[2],
      ] as V17PostLinkCandidateSet["profiles"],
    };
    assert.throws(() => materializeV17PostLinkCandidateEnvelopes({
      candidates: wrongSettlement,
      fixtures,
    }), /candidate settlement bank 0/);
  });
});

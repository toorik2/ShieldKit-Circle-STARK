import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { describe, it } from "node:test";
import {
  binToHex,
  cashAssemblyToBin,
  encodeLockingBytecodeP2sh32,
  hash256,
} from "@bitauth/libauth";
import { compileLocalWordValueSettlementGate } from
  "../src/chain/local-word-balanced-vm.ts";
import {
  LOCAL_WORD_CARRIER_BUDGETS,
} from "../src/chain/local-word-carrier-allocation.ts";
import {
  LOCAL_WORD_CARRIER_WEIGHTS,
  encodeLocalWordBatchLeaderUnlockingPrefix,
  encodeLocalWordP2shBatchLeaderUnlocking,
  encodeLocalWordP2shCarrierUnlocking,
  LOCAL_WORD_BATCH_LEADER_ROLE_ID,
  compileLocalWordPoolCarrierRedeem,
  localWordVerifierBankDigestFromInputs,
  localWordPoolCarrierSequence,
  localWordVerifierCarrierSequence,
  localWordVerifierCarrierValue,
} from "../src/chain/local-word-proof-carriers.ts";
import {
  LOCAL_WORD_PROOF_LENGTH_OFFSET,
  LOCAL_WORD_PROOF_VERSION,
} from "../src/backends/circle/local-word-sealed-proof.ts";
import {
  encodeV17BatchLeaderCell,
  V17_BATCH_LEADER_CELL_BYTES,
} from "../src/backends/circle/v17-batch-leader-cell.ts";
import { v17ProofFrameOffset } from "../src/backends/circle/v17-proof-layout.ts";
import { writeU32BE } from "../src/pool/bytes.ts";
import {
  V17_BOOTSTRAP_AFFINE_ALLOCATION,
  v17AffineCarrierBounds,
  type V17AffineAllocation,
} from "../src/chain/v17-affine-allocation.ts";
import { compileV17AffineReaderConstruction } from
  "../src/chain/v17-affine-reader-vm.ts";
import {
  buildV17VerifierPlan,
  V17_CONSTRUCTION_GRAPH,
  V17_PROFILES,
  v17ConstructionIdHex,
  v17ProtocolIdHex,
} from "../src/construction/v17-graph.ts";
import {
  encodeV17CanonicalPush,
} from "../src/chain/v17-code-rom.ts";
import {
  previewV17Rom,
  v17DefinePoliciesForRole,
  type V17PreLinkProgramProfile,
} from "../src/construction/v17-linker.ts";
import {
  assessV17AllocationIteration,
  assessV17FinalAllocationStability,
  bindV17PostLinkEvidence,
  certifyV17ProductLink,
  materializeV17PostLinkCandidates,
  previewV17ProductRom,
  type V17IndependentPostLinkEvidence,
  type V17PostLinkCandidateSet,
  type V17ProfileProofMaterial,
} from "../src/construction/v17-product-link.ts";
import { createV17DensityClosureTrace } from
  "../src/construction/v17-density-closure.ts";

function compile(assembly: string): Uint8Array {
  const result = cashAssemblyToBin(assembly);
  if (typeof result === "string") throw new Error(result);
  return result;
}

function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function leaderCompatibleProof(profile: 0 | 1 | 2, length: number): Uint8Array {
  const proof = new Uint8Array(length);
  proof.set(new TextEncoder().encode("SKLW"), 0);
  proof[4] = LOCAL_WORD_PROOF_VERSION;
  proof[5] = profile;
  proof.set(writeU32BE(length), LOCAL_WORD_PROOF_LENGTH_OFFSET);
  const nonceOffset = v17ProofFrameOffset("roundNonce:air:ood");
  for (let nonce = 0; nonce < 256; nonce += 1) {
    proof.set(writeU32BE(nonce), nonceOffset);
    try {
      encodeV17BatchLeaderCell(proof);
      return proof;
    } catch (error) {
      if (!String(error).includes("OODS nonce")) throw error;
    }
  }
  throw new Error("v17 product-link test OODS nonce");
}

function fixtureProfiles(): readonly [
  V17PreLinkProgramProfile,
  V17PreLinkProgramProfile,
  V17PreLinkProgramProfile,
] {
  const plan = buildV17VerifierPlan();
  const reusable = new Uint8Array(3_000).fill(0x61);
  reusable[reusable.length - 1] = 0x51;
  const bounded = new Uint8Array(80).fill(0x61);
  bounded[bounded.length - 1] = 0x51;
  const retained = new Uint8Array(300).fill(0x61);
  const prefix = encodeV17CanonicalPush(new Uint8Array(256));
  const leaderPrefix = encodeLocalWordBatchLeaderUnlockingPrefix(
    new Uint8Array(256),
    new Uint8Array(V17_BATCH_LEADER_CELL_BYTES),
  );
  return [0, 1, 2].map((profile): V17PreLinkProgramProfile => ({
    baselinePhase: "pre-link-program-census",
    qualification: "non-executable-non-measurement",
    profile: profile as 0 | 1 | 2,
    baselineInputCount: plan.roles.length + (profile === 0 ? 1 : 0),
    baselineOutputCount: plan.roles.length + profile + 1,
    programCensusSha256Hex: (profile + 71).toString(16).padStart(2, "0").repeat(32),
    workers: plan.roles.map((role, index) => {
      const selected = index === 0 ? bounded : reusable;
      const redeemBytecode = compile(
        `OP_DROP <0x${binToHex(selected)}> <1> OP_DEFINE
<0x${binToHex(retained)}> OP_DROP OP_1`,
      );
      return {
        profile: profile as 0 | 1 | 2,
        logicalInputIndex: index,
        roleId: role.id,
        redeemBytecode,
        unlockingPrefixBytecode: role.id === LOCAL_WORD_BATCH_LEADER_ROLE_ID
          ? leaderPrefix
          : prefix,
        proofCarrierBytes: 256,
        valueSatoshis: index === 0 ? 0n : 1_000n + BigInt(index),
        sequenceNumber: 0x8000_0000 + index,
        definePolicies: v17DefinePoliciesForRole({ roleId: role.id, redeemBytecode }),
      };
    }),
  })) as unknown as readonly [
    V17PreLinkProgramProfile,
    V17PreLinkProgramProfile,
    V17PreLinkProgramProfile,
  ];
}

function nearLimitOodProfiles(): readonly [
  V17PreLinkProgramProfile,
  V17PreLinkProgramProfile,
  V17PreLinkProgramProfile,
] {
  return fixtureProfiles().map((profile): V17PreLinkProgramProfile => ({
    ...profile,
    workers: profile.workers.map((worker, index) => {
      // The settlement's construction-bound definition must not poison the
      // otherwise construction-independent body classes. The large class pays
      // for its page and makes the final unlocking executable; the one-byte
      // class is deliberately smaller than its authenticated loader.
      const largeBody = new Uint8Array(1_000).fill(0x61);
      largeBody[largeBody.length - 1] = index === 0 ? 0x52 : 0x51;
      const tinyBody = index === 0 ? Uint8Array.of(0x52) : Uint8Array.of(0x51);
      const retainedBytes = worker.roleId === "ood-air" ? 8_981 : 20;
      const retained = new Uint8Array(retainedBytes).fill(0x61);
      const redeemBytecode = compile(
        `<0x${binToHex(largeBody)}> <1> OP_DEFINE
<0x${binToHex(tinyBody)}> <2> OP_DEFINE
<0x${binToHex(retained)}> OP_DROP OP_1`,
      );
      return {
        ...worker,
        redeemBytecode,
        definePolicies: v17DefinePoliciesForRole({
          roleId: worker.roleId,
          redeemBytecode,
        }),
      };
    }),
  })) as unknown as readonly [
    V17PreLinkProgramProfile,
    V17PreLinkProgramProfile,
    V17PreLinkProgramProfile,
  ];
}

function candidateSet(
  allocation: V17AffineAllocation = V17_BOOTSTRAP_AFFINE_ALLOCATION,
): V17PostLinkCandidateSet {
  const affineReader = compileV17AffineReaderConstruction(allocation);
  const proofLength = allocation.maximumProofBytes;
  const proofBytesByProfile = V17_PROFILES.map((profile) =>
    leaderCompatibleProof(profile, proofLength));
  const exactProfiles = fixtureProfiles().map((profile): V17PreLinkProgramProfile => {
    const proofBytes = proofBytesByProfile[profile.profile]!;
    const carriers = profile.workers.map((_, index) => {
      const [start, end] = v17AffineCarrierBounds(allocation, proofLength, index);
      const chunk = proofBytes.slice(start, end);
      return {
        chunk,
        ordinaryPrefix: encodeV17CanonicalPush(chunk),
      };
    });
    return {
      ...profile,
      workers: profile.workers.map((worker, index) => ({
        ...worker,
        unlockingPrefixBytecode: worker.roleId === LOCAL_WORD_BATCH_LEADER_ROLE_ID
          ? encodeLocalWordBatchLeaderUnlockingPrefix(
            carriers[index]!.chunk,
            encodeV17BatchLeaderCell(proofBytes),
          )
          : carriers[index]!.ordinaryPrefix,
        proofCarrierBytes: carriers[index]!.chunk.length,
      })),
    };
  }) as unknown as readonly [
    V17PreLinkProgramProfile,
    V17PreLinkProgramProfile,
    V17PreLinkProgramProfile,
  ];
  const provisionalPreview = previewV17Rom({ profiles: exactProfiles, affineReader });
  const settlementFor = (source: ReturnType<typeof previewV17Rom>): Uint8Array => {
    const banks = V17_PROFILES.map((profile) =>
      localWordVerifierBankDigestFromInputs(profile, [
        ...source.linkedRedeemsByProfile[profile]!.slice(1).map((redeem, local) => {
          const index = local + 1;
          return {
            lockingBytecode: encodeLockingBytecodeP2sh32(hash256(redeem)),
            valueSatoshis: localWordVerifierCarrierValue(index, allocation),
            sequenceNumber: localWordVerifierCarrierSequence(index, allocation),
          };
        }),
        ...source.pages.map((page) => ({
          lockingBytecode: page.lockingBytecode,
          valueSatoshis: page.valueSatoshis,
          sequenceNumber: page.sequenceNumber,
        })),
      ])) as unknown as readonly [Uint8Array, Uint8Array, Uint8Array];
    return compileLocalWordPoolCarrierRedeem(
      compileLocalWordValueSettlementGate(banks, affineReader.vm),
    );
  };
  const withSettlement = (
    profiles: typeof exactProfiles,
    settlementRedeem: Uint8Array,
  ): typeof exactProfiles => profiles.map((profile): V17PreLinkProgramProfile => ({
    ...profile,
    workers: profile.workers.map((worker, index) => index === 0
      ? {
        ...worker,
        redeemBytecode: settlementRedeem,
        definePolicies: v17DefinePoliciesForRole({
          roleId: worker.roleId,
          redeemBytecode: settlementRedeem,
        }),
      }
      : worker),
  })) as unknown as typeof exactProfiles;
  const settlementPreview = previewV17Rom({
    profiles: withSettlement(exactProfiles, settlementFor(provisionalPreview)),
    affineReader,
  });
  const exactSettlementRedeem = settlementFor(settlementPreview);
  const preview = previewV17Rom({
    profiles: withSettlement(exactProfiles, exactSettlementRedeem),
    affineReader,
  });
  assert.deepEqual(preview.pages, settlementPreview.pages,
    "the exact settlement/page fixture must reach a stable ROM identity");
  const profiles = [0, 1, 2].map((profile) => {
    const proofBytes = proofBytesByProfile[profile]!;
    const leaderCell = encodeV17BatchLeaderCell(proofBytes);
    const roles = preview.linkedRedeemsByProfile[profile]!.map((redeem, index) => {
      const [start, end] = v17AffineCarrierBounds(allocation, proofLength, index);
      const chunk = new Uint8Array(end - start);
      return {
        index,
        name: preview.verifierPlan.roles[index]!.id,
        carrier: {
          index,
          start,
          end,
          proofLength,
          budget: LOCAL_WORD_CARRIER_BUDGETS[index]!,
          weight: LOCAL_WORD_CARRIER_WEIGHTS[index]!,
          chunk,
          unlockingBytecode: encodeV17CanonicalPush(chunk),
        },
        verifier: Uint8Array.of(0x51),
        redeem,
        unlockingBytecode: preview.verifierPlan.roles[index]!.id ===
            LOCAL_WORD_BATCH_LEADER_ROLE_ID
          ? encodeLocalWordP2shBatchLeaderUnlocking(chunk, leaderCell, redeem)
          : encodeLocalWordP2shCarrierUnlocking(chunk, redeem),
      };
    });
    const baseline = preview.certificate.profiles[profile]!;
    return {
      schema: "ShieldKit/V17PostLinkCandidateProfile/v1" as const,
      status: "candidate-envelope-requires-independent-bchn-measurement" as const,
      romPreviewIdHex: preview.certificate.previewIdHex,
      profile: profile as 0 | 1 | 2,
      allocationStatus: allocation.status,
      allocation,
      projectedInputCount: baseline.baselineInputCount + preview.pages.length,
      projectedOutputCount: baseline.baselineOutputCount + preview.pages.length,
      proofBytes,
      roles,
      pages: preview.pages,
    };
  }) as unknown as V17PostLinkCandidateSet["profiles"];
  const banks = ([0, 1, 2] as const).map((profile) =>
    localWordVerifierBankDigestFromInputs(profile, [
      ...profiles[profile].roles.slice(1).map((role) => ({
        lockingBytecode: encodeLockingBytecodeP2sh32(hash256(role.redeem)),
        valueSatoshis: localWordVerifierCarrierValue(role.index, allocation),
        sequenceNumber: localWordVerifierCarrierSequence(role.index, allocation),
      })),
      ...preview.pages.map((page) => ({
        lockingBytecode: page.lockingBytecode,
        valueSatoshis: page.valueSatoshis,
        sequenceNumber: page.sequenceNumber,
      })),
    ])) as unknown as readonly [Uint8Array, Uint8Array, Uint8Array];
  const constructionIdHex = v17ConstructionIdHex({
    protocolIdHex: v17ProtocolIdHex(),
    bankDigests: banks.map(binToHex) as unknown as
      readonly [string, string, string],
  });
  const settlementVerifier = compileLocalWordValueSettlementGate(banks, affineReader.vm);
  const settlementRedeem = compileLocalWordPoolCarrierRedeem(settlementVerifier);
  ([0, 1, 2] as const).forEach((profile) => {
    const row = profiles[profile];
    const first = row.roles[0]!;
    (row.roles as unknown as typeof first[])[0] = {
      ...first,
      verifier: settlementVerifier,
      redeem: settlementRedeem,
      unlockingBytecode: encodeLocalWordP2shCarrierUnlocking(
        first.carrier.chunk,
        settlementRedeem,
      ),
    };
  });
  return {
    schema: "ShieldKit/V17PostLinkCandidateSet/v1",
    status: "candidate-envelope-requires-independent-bchn-measurement",
    constructionIdHex,
    preview,
    profiles: profiles.map((profile) => ({
      ...profile,
      constructionIdHex,
    })) as unknown as V17PostLinkCandidateSet["profiles"],
  };
}

function exactProductProofs(lengths: readonly [number, number, number]): readonly [
  V17ProfileProofMaterial,
  V17ProfileProofMaterial,
  V17ProfileProofMaterial,
] {
  const protocolId = Uint8Array.from(Buffer.from(v17ProtocolIdHex(), "hex"));
  return V17_PROFILES.map((profile): V17ProfileProofMaterial => {
    const key = V17_CONSTRUCTION_GRAPH.verifierKeyDigests[profile]!;
    return {
      profile,
      constructionId: protocolId,
      constructionDigest: Uint8Array.from(Buffer.from(
        key.relationConstructionDigestHex,
        "hex",
      )),
      expectedPreprocessedRoot: Uint8Array.from(Buffer.from(
        key.preprocessedRootHex,
        "hex",
      )),
      proofBytes: leaderCompatibleProof(profile, lengths[profile]),
    };
  }) as unknown as readonly [
    V17ProfileProofMaterial,
    V17ProfileProofMaterial,
    V17ProfileProofMaterial,
  ];
}

function evidenceFor(
  candidates: V17PostLinkCandidateSet,
): readonly V17IndependentPostLinkEvidence[] {
  return candidates.profiles.map((candidate): V17IndependentPostLinkEvidence => ({
    schema: "ShieldKit/V17IndependentPostLinkEvidence/v1",
    status: "accepted-byte-exact-candidate-envelope",
    qualification: "candidate-resource-only-not-final-qualification",
    romPreviewIdHex: candidate.romPreviewIdHex,
    profile: candidate.profile,
    projectedInputCount: candidate.projectedInputCount,
    projectedOutputCount: candidate.projectedOutputCount,
    candidateEnvelopeEvidenceSha256Hex:
      (candidate.profile + 81).toString(16).padStart(2, "0").repeat(32),
    workers: candidate.roles.map((role, index) => ({
      accepted: true,
      fixtureInputCount: candidate.projectedInputCount,
      fixtureOutputCount: candidate.projectedOutputCount,
      logicalInputIndex: index,
      roleId: role.name,
      redeemSha256Hex: sha256Hex(role.redeem),
      unlockingSha256Hex: sha256Hex(role.unlockingBytecode),
      maximumOperationCost: 1_000 + index,
      densityControlLength: 41 + role.unlockingBytecode.length,
      maximumMemorySlots: 2,
      maximumControlDepth: 0,
      valueSatoshis: index === 0
        ? 50_000n
        : localWordVerifierCarrierValue(index, candidate.allocation),
      sequenceNumber: index === 0
        ? localWordPoolCarrierSequence(candidate.proofBytes.length, candidate.allocation)
        : localWordVerifierCarrierSequence(index, candidate.allocation),
      operationCostEngine: "bchn-v29.0.0",
      operationCostEvidenceSha256Hex:
        (candidate.profile + 91).toString(16).padStart(2, "0").repeat(32),
    })),
  }));
}

describe("v17 staged product linker", () => {
  it("leaves an expanding ROM occurrence inline at the near-limit OOD role", () => {
    const profiles = nearLimitOodProfiles();
    const oodIndex = buildV17VerifierPlan().roles.findIndex(({ id }) => id === "ood-air");
    assert.ok(oodIndex > 0);
    assert.deepEqual(
      profiles.map((profile) => profile.workers[oodIndex]!.redeemBytecode.length),
      [9_995, 9_995, 9_995],
    );

    const preview = previewV17Rom({ profiles });
    assert.equal(preview.pages.length, 1,
      "only the large definition justifies an authenticated ROM page");
    assert.equal(preview.certificate.census.promotedBodySha256Hexes.length, 1);
    preview.linkedRedeemsByProfile.forEach((redeems, profile) => {
      assert.ok(redeems[oodIndex]!.length <
        profiles[profile]!.workers[oodIndex]!.redeemBytecode.length);
      redeems.forEach((redeem, index) => assert.ok(
        redeem.length <= profiles[profile]!.workers[index]!.redeemBytecode.length,
        `${profile}:${index}:ROM linking may not expand a verifier`,
      ));
    });
  });

  it("prices unlinked and linked ROM layouts against identical real proof carriers", () => {
    const minimum = V17_BOOTSTRAP_AFFINE_ALLOCATION.minimumProofBytes;
    const maximum = V17_BOOTSTRAP_AFFINE_ALLOCATION.maximumProofBytes;
    const proofs = exactProductProofs([
      minimum,
      minimum + Math.floor((maximum - minimum) / 2),
      maximum,
    ]);

    const firstLink = previewV17ProductRom(proofs, V17_BOOTSTRAP_AFFINE_ALLOCATION);
    const firstCandidates = materializeV17PostLinkCandidates({
      link: firstLink,
      proofs,
      allocation: V17_BOOTSTRAP_AFFINE_ALLOCATION,
    });
    const first = assessV17AllocationIteration({
      candidates: firstCandidates,
      evidence: evidenceFor(firstCandidates),
      trace: createV17DensityClosureTrace(),
    });

    const stableLink = previewV17ProductRom(proofs, first.measuredAllocation);
    const mutatedProofs = proofs.map((proof): V17ProfileProofMaterial => {
      const proofBytes = proof.proofBytes.slice();
      proofBytes[100] ^= 0xff;
      return { ...proof, proofBytes };
    }) as unknown as typeof proofs;
    const contentMutatedLink = previewV17ProductRom(mutatedProofs, first.measuredAllocation);
    assert.equal(
      contentMutatedLink.preview.certificate.previewIdHex,
      stableLink.preview.certificate.previewIdHex,
      "fixed-length proof content must not enter the ROM preview identity",
    );
    assert.deepEqual(contentMutatedLink.preview.pages, stableLink.preview.pages);
    assert.deepEqual(
      contentMutatedLink.preview.linkedRedeemsByProfile,
      stableLink.preview.linkedRedeemsByProfile,
    );
    const stableCandidates = materializeV17PostLinkCandidates({
      link: stableLink,
      proofs,
      allocation: first.measuredAllocation,
    });
    const stableEvidence = evidenceFor(stableCandidates);
    const second = assessV17AllocationIteration({
      candidates: stableCandidates,
      evidence: stableEvidence,
      trace: first.trace,
    });
    assert.equal(second.status, "stable");
    const construction = certifyV17ProductLink({
      candidates: stableCandidates,
      evidence: stableEvidence,
      trace: second.trace,
    });

    const prefixTotals = stableLink.profiles.map((profile) =>
      profile.workers.reduce((sum, worker) => sum + worker.unlockingPrefixBytecode.length, 0));
    assert.ok(Math.max(...prefixTotals) - Math.min(...prefixTotals) > 300_000,
      "the regression must exercise dramatically different carrier prefixes");
    construction.certificate.profiles.forEach((certified, profile) => {
      const projected = stableLink.preview.certificate.profiles[profile]!;
      assert.equal(certified.baselineRelevantBytes, projected.baselineRelevantBytes);
      assert.equal(certified.linkedRelevantBytes, projected.projectedLinkedRelevantBytes);
      assert.equal(certified.strictSavingBytes, projected.projectedSavingBytes);
    });
  });

  it("binds byte-exact post-link evidence and keeps the certificate construction-only", () => {
    const candidates = candidateSet();
    const evidence = evidenceFor(candidates);
    const measured = bindV17PostLinkEvidence({ candidates, evidence });
    assert.equal(measured.length, 3);
    assert.equal(measured[0].measurementPhase, "post-link");
    assert.deepEqual(measured[0].workers[1]!.redeemBytecode,
      candidates.profiles[0].roles[1]!.redeem);

    const first = assessV17AllocationIteration({
      candidates,
      evidence,
      trace: createV17DensityClosureTrace(),
    });
    assert.equal(first.status, "requires-remeasurement");
    assert.throws(() => certifyV17ProductLink({ candidates, evidence, trace: first.trace }),
      /allocation requires post-link remeasurement/);

    const stableCandidates = candidateSet(first.measuredAllocation);
    const stableEvidence = evidenceFor(stableCandidates);
    const second = assessV17AllocationIteration({
      candidates: stableCandidates,
      evidence: stableEvidence,
      trace: first.trace,
    });
    assert.equal(second.status, "stable");
    const linked = certifyV17ProductLink({
      candidates: stableCandidates,
      evidence: stableEvidence,
      trace: second.trace,
    });
    assert.equal(linked.certificate.status, "post-link-measured");
    assert.equal(linked.certificate.qualification, "construction-only-not-qualified");
    assert.equal(linked.verifierPlan.allocation.status, "measured");
    assert.equal(linked.certificate.densityClosureSha256Hex,
      second.densityClosure.closureSha256Hex);
    assert.deepEqual(linked.certificate.terminalMeasurementRows, second.measuredRows);

    const finalStable = assessV17FinalAllocationStability({
      construction: linked,
      finalProfiles: second.postLinkProfiles,
      trace: second.trace,
    });
    assert.equal(finalStable.status, "stable",
      "a conservative envelope accepts exact final rows it dominates");
    assert.equal(finalStable.trace.entries.at(-1)!.phase, "final-bchn");
    assert.equal(finalStable.trace.entries.at(-1)!.noChange, true);

    const raisedWorkers = [...second.postLinkProfiles[0].workers];
    raisedWorkers[1] = {
      ...raisedWorkers[1]!,
      maximumOperationCost: raisedWorkers[1]!.maximumOperationCost + 800,
    };
    const raisedProfiles = [
      { ...second.postLinkProfiles[0], workers: raisedWorkers },
      second.postLinkProfiles[1],
      second.postLinkProfiles[2],
    ] as unknown as typeof second.postLinkProfiles;
    const finalRaised = assessV17FinalAllocationStability({
      construction: linked,
      finalProfiles: raisedProfiles,
      trace: second.trace,
    });
    assert.equal(finalRaised.status, "restart-post-link-loop");

    const editedTrace = structuredClone(second.trace);
    (editedTrace.entries.at(-1) as { measurementEvidenceSha256Hex: string })
      .measurementEvidenceSha256Hex = "ee".repeat(32);
    assert.throws(() => certifyV17ProductLink({
      candidates: stableCandidates,
      evidence: stableEvidence,
      trace: editedTrace,
    }), /trace entry|terminal trace replay/);

    const stale = structuredClone(stableEvidence) as V17IndependentPostLinkEvidence[];
    const staleWorkers = [...stale[0]!.workers];
    staleWorkers[1] = { ...staleWorkers[1]!, redeemSha256Hex: "ff".repeat(32) };
    stale[0] = { ...stale[0]!, workers: staleWorkers };
    assert.throws(() => bindV17PostLinkEvidence({ candidates: stableCandidates, evidence: stale }),
      /worker evidence/);

    const wrongFixture = structuredClone(stableEvidence) as V17IndependentPostLinkEvidence[];
    const wrongFixtureWorkers = [...wrongFixture[1]!.workers];
    wrongFixtureWorkers[0] = {
      ...wrongFixtureWorkers[0]!,
      fixtureInputCount: stableCandidates.profiles[1]!.projectedInputCount + 1,
    };
    wrongFixture[1] = { ...wrongFixture[1]!, workers: wrongFixtureWorkers };
    assert.throws(() => bindV17PostLinkEvidence({
      candidates: stableCandidates,
      evidence: wrongFixture,
    }), /worker evidence/);
  });
});

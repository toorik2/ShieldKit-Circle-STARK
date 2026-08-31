import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  binToHex,
  cashAssemblyToBin,
  createVirtualMachineBch2026,
  encodeLockingBytecodeP2sh32,
  hash256,
} from "@bitauth/libauth";
import { compileLocalWordValueSettlementGate } from
  "../src/chain/local-word-balanced-vm.ts";
import {
  compileLocalWordPoolCarrierRedeem,
  encodeLocalWordBatchLeaderUnlockingPrefix,
  LOCAL_WORD_BATCH_LEADER_ROLE_ID,
  localWordVerifierBankDigestFromInputs,
} from "../src/chain/local-word-proof-carriers.ts";
import { V17_BATCH_LEADER_CELL_BYTES } from
  "../src/backends/circle/v17-batch-leader-cell.ts";
import {
  measuredV17AffineAllocation,
  v17AffineBoundarySequence,
  v17AffineVerifierValue,
} from "../src/chain/v17-affine-allocation.ts";
import { compileV17AffineReaderConstruction } from
  "../src/chain/v17-affine-reader-vm.ts";
import {
  V17_CONSTRUCTION_GRAPH,
  buildV17VerifierPlan,
  v17BankDigestHex,
  v17ProtocolIdHex,
} from "../src/construction/v17-graph.ts";
import {
  allocateV17Density,
  assessV17Density,
  censusV17OpDefineBodies,
  certifyV17LinkedConstruction,
  linkV17Construction,
  partitionV17ProofByDensity,
  v17DefinePoliciesForRole,
  v17PostLinkMeasurementEvidenceDigestHex,
  type V17DefinePolicy,
  type V17MeasuredProfile,
  type V17MeasuredWorker,
  type V17PostLinkMeasuredProfile,
  type V17PreLinkProgramProfile,
  type V17RomPreview,
} from "../src/construction/v17-linker.ts";
import {
  appendV17DensityClosureTrace,
  createV17DensityClosureTrace,
  replayV17DensityClosureTrace,
} from "../src/construction/v17-density-closure.ts";
import {
  V17_MAX_FUNCTION_ID_BYTES,
  V17_MAX_SCRIPT_BYTES,
  createV17RomPage,
  encodeV17CanonicalPush,
  validateV17RomPage,
} from "../src/chain/v17-code-rom.ts";
import { V17_PRODUCTION_ROLE_LAYOUT } from "../src/chain/v17-role-layout.ts";

function compile(assembly: string): Uint8Array {
  const result = cashAssemblyToBin(assembly);
  if (typeof result === "string") throw new Error(result);
  return result;
}

function body(ordinal: number, bytes = 3_300): Uint8Array {
  const out = new Uint8Array(bytes).fill(0x61); // OP_NOP
  out[out.length - 1] = 0x51 + ordinal; // distinct, valid terminal push
  return out;
}

function workerRedeem(functionBody: Uint8Array, functionId = 1): Uint8Array {
  return compile(`OP_DROP <0x${binToHex(functionBody)}> <${functionId}> OP_DEFINE OP_1`);
}

function romPlacement(preview: V17RomPreview, target: Uint8Array) {
  for (const page of preview.pages) {
    const entry = page.entries.find(({ body: candidate }) =>
      candidate.length === target.length && candidate.every((byte, index) => byte === target[index]));
    if (entry !== undefined) return {
      pageIndex: page.pageIndex,
      functionIdHex: entry.functionIdHex,
      bodyOffset: entry.bodyOffset,
      bodyLength: entry.bodyLength,
      bodySha256Hex: entry.bodySha256Hex,
    };
  }
  throw new Error("v17 linker test ROM body placement");
}

function measuredProfiles(bodies: readonly Uint8Array[]): readonly [
  V17MeasuredProfile,
  V17MeasuredProfile,
  V17MeasuredProfile,
] {
  const plan = buildV17VerifierPlan();
  return [0, 1, 2].map((profile): V17MeasuredProfile => {
    const workers = plan.roles.map((role, index): V17MeasuredWorker => {
      const selected = index === 0 ? body(15, 80) : bodies[(index - 1) % bodies.length]!;
      const redeemBytecode = workerRedeem(selected);
      const proofCarrierBytes = 256;
      const proofChunk = new Uint8Array(proofCarrierBytes);
      const unlockingPrefixBytecode = role.id === LOCAL_WORD_BATCH_LEADER_ROLE_ID
        ? encodeLocalWordBatchLeaderUnlockingPrefix(
          proofChunk,
          new Uint8Array(V17_BATCH_LEADER_CELL_BYTES),
        )
        : encodeV17CanonicalPush(proofChunk);
      return {
        profile: profile as 0 | 1 | 2,
        logicalInputIndex: index,
        roleId: role.id,
        redeemBytecode,
        unlockingPrefixBytecode,
        maximumOperationCost: 801 + index * 37 + profile * 113,
        densityControlLength: 41 + unlockingPrefixBytecode.length +
          encodeV17CanonicalPush(redeemBytecode).length,
        proofCarrierBytes,
        maximumMemorySlots: 2,
        maximumControlDepth: 0,
        valueSatoshis: 2_000n + BigInt(index),
        sequenceNumber: 0x8000_0000 + index,
        operationCostEngine: "independent-bchn-conformant",
        operationCostEvidenceSha256Hex: (profile + 1).toString(16).padStart(2, "0").repeat(32),
        definePolicies: v17DefinePoliciesForRole({ roleId: role.id, redeemBytecode }),
      };
    });
    return {
      profile: profile as 0 | 1 | 2,
      workers,
      baselineInputCount: workers.length,
      baselineOutputCount: workers.length,
      envelopeEvidenceSha256Hex: (profile + 9).toString(16).padStart(2, "0").repeat(32),
    };
  }) as unknown as readonly [V17MeasuredProfile, V17MeasuredProfile, V17MeasuredProfile];
}

function postLinkProfiles(
  preview: V17RomPreview,
  baseline: readonly [V17MeasuredProfile, V17MeasuredProfile, V17MeasuredProfile],
): readonly [V17PostLinkMeasuredProfile, V17PostLinkMeasuredProfile, V17PostLinkMeasuredProfile] {
  const provisional = baseline.map((profile, profileIndex): V17PostLinkMeasuredProfile => ({
    measurementPhase: "post-link",
    romPreviewIdHex: preview.certificate.previewIdHex,
    profile: profile.profile,
    inputCount: profile.baselineInputCount + preview.pages.length,
    outputCount: profile.baselineOutputCount + preview.pages.length,
    envelopeEvidenceSha256Hex: (profileIndex + 21).toString(16).padStart(2, "0").repeat(32),
    workers: profile.workers.map((worker, index) => {
      const { definePolicies: ignored, ...resourceMeasurement } = worker;
      void ignored;
      const redeemBytecode = preview.linkedRedeemsByProfile[profileIndex]![index]!;
      return {
        ...resourceMeasurement,
        redeemBytecode,
        maximumOperationCost: worker.maximumOperationCost + (index === 1 ? 2_000_000 : 10_000),
        valueSatoshis: worker.valueSatoshis + BigInt(100 + profileIndex),
        sequenceNumber: worker.sequenceNumber + 100,
        densityControlLength: 41 + worker.unlockingPrefixBytecode.length +
          encodeV17CanonicalPush(redeemBytecode).length,
        operationCostEvidenceSha256Hex:
          (profileIndex + 31).toString(16).padStart(2, "0").repeat(32),
      };
    }),
  })) as unknown as readonly [
    V17PostLinkMeasuredProfile,
    V17PostLinkMeasuredProfile,
    V17PostLinkMeasuredProfile,
  ];
  let current = provisional;
  const seen = new Set<string>();
  for (;;) {
    const allocation = measuredV17AffineAllocation(
      allocateV17Density(V17_CONSTRUCTION_GRAPH, current),
    );
    const key = JSON.stringify(allocation.assignments.map((assignment) => [
      assignment.basePrefixStart,
      assignment.basePrefixEnd,
      assignment.elasticPrefixStart,
      assignment.elasticPrefixEnd,
    ]));
    if (seen.has(key)) throw new Error("v17 linker test allocation cycle");
    seen.add(key);
    const bankDigests = ([0, 1, 2] as const).map((profile) =>
      localWordVerifierBankDigestFromInputs(profile, [
        ...current[profile].workers.slice(1).map((worker) => ({
          lockingBytecode: encodeLockingBytecodeP2sh32(hash256(worker.redeemBytecode)),
          valueSatoshis: v17AffineVerifierValue(allocation, worker.logicalInputIndex),
          sequenceNumber: v17AffineBoundarySequence(allocation, worker.logicalInputIndex),
        })),
        ...preview.pages.map((page) => ({
          lockingBytecode: page.lockingBytecode,
          valueSatoshis: page.valueSatoshis,
          sequenceNumber: page.sequenceNumber,
        })),
      ])) as unknown as readonly [Uint8Array, Uint8Array, Uint8Array];
    const settlementRedeem = compileLocalWordPoolCarrierRedeem(
      compileLocalWordValueSettlementGate(bankDigests),
    );
    const next = current.map((profile) => ({
      ...profile,
      workers: profile.workers.map((worker, index) => index === 0 ? {
        ...worker,
        redeemBytecode: settlementRedeem,
        densityControlLength: 41 + worker.unlockingPrefixBytecode.length +
          encodeV17CanonicalPush(settlementRedeem).length,
      } : worker),
    })) as unknown as typeof current;
    const nextAllocation = measuredV17AffineAllocation(
      allocateV17Density(V17_CONSTRUCTION_GRAPH, next),
    );
    const nextKey = JSON.stringify(nextAllocation.assignments.map((assignment) => [
      assignment.basePrefixStart,
      assignment.basePrefixEnd,
      assignment.elasticPrefixStart,
      assignment.elasticPrefixEnd,
    ]));
    if (nextKey === key) return next;
    current = next;
  }
}

function terminalDensityTrace(
  preview: V17RomPreview,
  profiles: readonly [V17PostLinkMeasuredProfile, V17PostLinkMeasuredProfile,
    V17PostLinkMeasuredProfile],
) {
  const rows = assessV17Density(V17_CONSTRUCTION_GRAPH, profiles).rows;
  const evidence = v17PostLinkMeasurementEvidenceDigestHex(
    preview.certificate.previewIdHex,
    profiles,
  );
  let trace = createV17DensityClosureTrace();
  for (let pass = 0; pass < 2; pass += 1) {
    const head = replayV17DensityClosureTrace(trace);
    trace = appendV17DensityClosureTrace({
      trace,
      phase: "post-link-bchn",
      currentAllocation: head.allocation,
      currentReader: compileV17AffineReaderConstruction(head.allocation).evidence,
      romPreviewIdHex: preview.certificate.previewIdHex,
      measurementEvidenceSha256Hex: evidence,
      measuredRows: rows,
    });
  }
  assert.equal(replayV17DensityClosureTrace(trace).terminalNoChange, true);
  return trace;
}

function preLinkProgramProfiles(
  measured: readonly [V17MeasuredProfile, V17MeasuredProfile, V17MeasuredProfile],
): readonly [V17PreLinkProgramProfile, V17PreLinkProgramProfile, V17PreLinkProgramProfile] {
  return measured.map((profile): V17PreLinkProgramProfile => ({
    baselinePhase: "pre-link-program-census",
    qualification: "non-executable-non-measurement",
    profile: profile.profile,
    baselineInputCount: profile.baselineInputCount,
    baselineOutputCount: profile.baselineOutputCount,
    programCensusSha256Hex: (profile.profile + 61).toString(16).padStart(2, "0").repeat(32),
    workers: profile.workers.map((worker) => ({
      profile: worker.profile,
      logicalInputIndex: worker.logicalInputIndex,
      roleId: worker.roleId,
      redeemBytecode: worker.redeemBytecode,
      unlockingPrefixBytecode: worker.unlockingPrefixBytecode,
      proofCarrierBytes: worker.proofCarrierBytes,
      valueSatoshis: worker.valueSatoshis,
      sequenceNumber: worker.sequenceNumber,
      definePolicies: worker.definePolicies,
    })),
  })) as unknown as readonly [
    V17PreLinkProgramProfile,
    V17PreLinkProgramProfile,
    V17PreLinkProgramProfile,
  ];
}

function p2shPageFixture(page: ReturnType<typeof createV17RomPage>) {
  const count = page.inputIndex + 1;
  const inputs = Array.from({ length: count }, (_, index) => ({
    outpointTransactionHash: new Uint8Array(32).fill((index + 1) & 0xff),
    outpointIndex: index,
    sequenceNumber: index === page.inputIndex ? page.sequenceNumber : 0xffff_fffe,
    unlockingBytecode: index === page.inputIndex ? page.unlockingBytecode : new Uint8Array(),
  }));
  const sourceOutputs = Array.from({ length: count }, (_, index) => ({
    lockingBytecode: index === page.inputIndex ? page.lockingBytecode : Uint8Array.of(0x51),
    valueSatoshis: index === page.inputIndex ? page.valueSatoshis : 1_000n,
  }));
  const outputs = Array.from({ length: count }, (_, index) => ({
    lockingBytecode: index === page.outputIndex ? page.lockingBytecode : Uint8Array.of(0x51),
    valueSatoshis: index === page.outputIndex ? page.valueSatoshis : 1_000n,
  }));
  return {
    sourceOutputs,
    transaction: { version: 2, locktime: 0, inputs, outputs },
  };
}

describe("v17 exact density linker", () => {
  it("maps exact opcost floors and unlocking capacities into one bounded affine union", () => {
    const profiles = measuredProfiles([body(0, 80)]);
    const allocation = allocateV17Density(V17_CONSTRUCTION_GRAPH, profiles);
    assert.equal(allocation.length, buildV17VerifierPlan().roles.length);
    assert.equal(allocation[0]!.basePrefixStart, 0);
    assert.equal(allocation[0]!.elasticPrefixStart, 0);
    assert.equal(allocation.at(-1)!.elasticPrefixEnd, 4_095);
    allocation.forEach((assignment, index) => {
      const expected = Math.max(...profiles.map((profile) => {
        const worker = profile.workers[index]!;
        return Math.max(256, Math.ceil(worker.maximumOperationCost / 800) -
          (worker.densityControlLength - worker.proofCarrierBytes));
      }));
      const capacity = Math.min(...profiles.map((profile) => {
        const worker = profile.workers[index]!;
        return 10_000 - (worker.unlockingPrefixBytecode.length - worker.proofCarrierBytes) -
          encodeV17CanonicalPush(worker.redeemBytecode).length;
      }));
      assert.equal(assignment.requiredProofBytes, expected);
      assert.equal(assignment.capacityProofBytes, capacity);
      if (index > 0) {
        assert.equal(assignment.basePrefixStart, allocation[index - 1]!.basePrefixEnd);
        assert.equal(assignment.elasticPrefixStart, allocation[index - 1]!.elasticPrefixEnd);
      }
      assert.ok(assignment.basePrefixEnd > assignment.basePrefixStart);
      assert.ok(assignment.elasticPrefixEnd >= assignment.elasticPrefixStart);
    });

    const minimum = allocation.at(-1)!.basePrefixEnd;
    for (const length of [minimum, minimum + 1, 100_003, 457_514]) {
      const proof = Uint8Array.from({ length }, (_, index) => index & 0xff);
      const parts = partitionV17ProofByDensity(proof, allocation);
      assert.equal(parts[0]!.start, 0);
      assert.equal(parts.at(-1)!.end, proof.length);
      parts.forEach((part, index) => {
        if (index > 0) assert.equal(part.start, parts[index - 1]!.end);
        assert.ok(part.bytes.length >= allocation[index]!.requiredProofBytes);
        assert.ok(part.bytes.length <= allocation[index]!.capacityProofBytes);
      });
      assert.deepEqual(Uint8Array.from(parts.flatMap((part) => [...part.bytes])), proof);
    }
  });

  it("fails closed on incomplete measurements and invalid BCH2026 resource evidence", () => {
    const profiles = measuredProfiles([body(0, 80)]);
    const short = [{ ...profiles[0], workers: profiles[0].workers.slice(1) }, profiles[1], profiles[2]] as const;
    assert.throws(() => allocateV17Density(V17_CONSTRUCTION_GRAPH, short), /profile shape/);

    const workers = [...profiles[0].workers];
    workers[0] = { ...workers[0]!, maximumControlDepth: 101 };
    const deep = [{ ...profiles[0], workers }, profiles[1], profiles[2]] as const;
    assert.throws(() => allocateV17Density(V17_CONSTRUCTION_GRAPH, deep), /worker shape/);
  });
});

describe("v17 exact OP_DEFINE census and ROM selection", () => {
  it("recursively censuses literal definitions and rejects dynamic or oversized identifiers", () => {
    const inner = workerRedeem(Uint8Array.of(0x51), 2);
    const outer = workerRedeem(inner, 1);
    const census = censusV17OpDefineBodies(outer);
    assert.deepEqual(census.map((entry) => [entry.path, entry.depth, entry.functionIdHex]), [
      ["0", 0, "01"],
      ["0/0", 1, "02"],
    ]);
    assert.equal(censusV17OpDefineBodies(compile("<0x51> <0> OP_DEFINE"))[0]!.functionIdHex, "",
      "the valid empty-vector function identifier remains within the seven-byte maximum");
    assert.throws(() => censusV17OpDefineBodies(compile("OP_1 OP_DUP OP_DEFINE")),
      /dynamic OP_DEFINE/);
    const longId = new Uint8Array(V17_MAX_FUNCTION_ID_BYTES + 1).fill(1);
    assert.throws(() => censusV17OpDefineBodies(
      compile(`<0x51> <0x${binToHex(longId)}> OP_DEFINE`)), /identifier width/);
  });

  it("previews deterministically, then certifies only post-link measurements", () => {
    const seedProfiles = measuredProfiles([body(0), body(1), body(2)]);
    const seedPreview = linkV17Construction({ profiles: seedProfiles });
    const seedPostLink = postLinkProfiles(seedPreview, seedProfiles);
    const profiles = seedProfiles.map((profile, profileIndex): V17MeasuredProfile => ({
      ...profile,
      workers: profile.workers.map((worker, index) => {
        if (index !== 0) return worker;
        const redeemBytecode = seedPostLink[profileIndex]!.workers[0]!.redeemBytecode;
        return {
          ...worker,
          redeemBytecode,
          densityControlLength: 41 + worker.unlockingPrefixBytecode.length +
            encodeV17CanonicalPush(redeemBytecode).length,
          definePolicies: v17DefinePoliciesForRole({
            roleId: worker.roleId,
            redeemBytecode,
          }),
        };
      }),
    })) as unknown as typeof seedProfiles;
    const preview = linkV17Construction({ profiles });
    assert.equal(preview.certificate.status, "preview-only");
    assert.equal(preview.certificate.protocolIdHex, v17ProtocolIdHex());
    assert.equal(preview.certificate.census.exactBodyClasses, 3,
      "the exact settlement adds no synthetic OP_DEFINE class to the ROM census");
    assert.equal(preview.certificate.census.promotedBodySha256Hexes.length, 3);
    assert.equal(preview.pages.length, 2, "three 3300-byte bodies require exactly two pages");
    assert.deepEqual(preview.pages.map((page) => page.pageIndex), [0, 1]);
    preview.pages.forEach((page, index) => {
      assert.equal(page.inputIndex, buildV17VerifierPlan().roles.length + index);
      assert.equal(page.outputIndex, page.inputIndex);
      assert.ok(page.payload.length <= V17_MAX_SCRIPT_BYTES);
      assert.ok(page.redeemBytecode.length <= V17_MAX_SCRIPT_BYTES);
      assert.ok(page.unlockingBytecode.length <= V17_MAX_SCRIPT_BYTES);
      assert.equal(validateV17RomPage(page), page);
    });
    preview.certificate.profiles.forEach((profile) => assert.ok(profile.projectedSavingBytes > 0));
    assert.equal(preview.verifierPlan.allocation.status, "unmeasured");
    assert.equal(preview.verifierPlan.rom.status, "unmeasured");
    assert.equal("constructionIdHex" in preview.certificate, false);

    const postLink = postLinkProfiles(preview, profiles);
    const densityTrace = terminalDensityTrace(preview, postLink);
    const linked = certifyV17LinkedConstruction({
      preview,
      postLinkProfiles: postLink,
      densityTrace,
    });
    assert.equal(linked.certificate.status, "post-link-measured");
    linked.certificate.profiles.forEach((profile) => assert.ok(profile.strictSavingBytes > 0));
    assert.equal(new Set(linked.certificate.profiles.map((row) => row.bankDigestHex)).size, 3);
    assert.match(linked.certificate.constructionIdHex, /^[0-9a-f]{64}$/);
    assert.match(linked.certificate.certificateIdHex, /^[0-9a-f]{64}$/);
    assert.equal(linked.verifierPlan.allocation.status, "measured");
    assert.equal(linked.verifierPlan.rom.status, "measured");
    assert.equal(linked.verifierPlan.rom.pages.length, 2);
    assert.equal(linked.certificate.allocation[1]!.maximumOperationCost,
      Math.max(...postLink.map((profile) => profile.workers[1]!.maximumOperationCost)),
      "the final allocation is derived from post-link rather than baseline opcost");

    const profileWorkers = linked.workersByProfile[0]!;
    const bankRoles = [
      ...profileWorkers.slice(1).map((worker) => ({
        index: worker.logicalInputIndex,
        lockingBytecode: worker.lockingBytecode,
        valueSatoshis: worker.valueSatoshis,
        sequenceNumber: worker.sequenceNumber,
      })),
      ...linked.pages.map((page) => ({
        index: page.inputIndex,
        lockingBytecode: page.lockingBytecode,
        valueSatoshis: page.valueSatoshis,
        sequenceNumber: page.sequenceNumber,
      })),
    ];
    const verifierWorkerCount = V17_PRODUCTION_ROLE_LAYOUT.length - 1;
    assert.equal(bankRoles.length, verifierWorkerCount + linked.pages.length);
    assert.deepEqual(bankRoles.slice(0, verifierWorkerCount).map(({ index }) => index),
      Array.from({ length: verifierWorkerCount }, (_, index) => index + 1));
    assert.equal(linked.certificate.profiles[0]!.bankDigestHex, v17BankDigestHex({
      protocolIdHex: linked.certificate.protocolIdHex,
      profile: 0,
      roles: bankRoles,
    }), "bank identity excludes settlement zero and includes verifier inputs plus ROM pages");

    const sourceOutputs = [
      ...profileWorkers.map((worker) => ({
        lockingBytecode: worker.lockingBytecode,
        valueSatoshis: worker.valueSatoshis,
      })),
      ...preview.pages.map((page) => ({
        lockingBytecode: page.lockingBytecode,
        valueSatoshis: page.valueSatoshis,
      })),
    ];
    const transaction = {
      version: 2,
      locktime: 0,
      inputs: [
        ...profileWorkers.map((worker, index) => ({
          outpointTransactionHash: new Uint8Array(32).fill((index + 1) & 0xff),
          outpointIndex: index,
          sequenceNumber: worker.sequenceNumber,
          unlockingBytecode: worker.unlockingBytecode,
        })),
        ...preview.pages.map((page) => ({
          outpointTransactionHash: new Uint8Array(32).fill((page.inputIndex + 1) & 0xff),
          outpointIndex: page.inputIndex,
          sequenceNumber: page.sequenceNumber,
          unlockingBytecode: page.unlockingBytecode,
        })),
      ],
      outputs: sourceOutputs.map((output) => ({ ...output })),
    };
    const vm = createVirtualMachineBch2026(false);
    const workerState = vm.evaluate({ inputIndex: 1, sourceOutputs, transaction } as never);
    assert.equal(vm.stateSuccess(workerState), true,
      `linked worker imports authenticated ROM body: ${String(workerState.error)}`);
    for (const page of preview.pages) {
      const pageState = vm.evaluate({ inputIndex: page.inputIndex, sourceOutputs, transaction } as never);
      assert.equal(vm.stateSuccess(pageState), true, `ROM page ${page.pageIndex}: ${String(pageState.error)}`);
    }

    const replay = linkV17Construction({ profiles });
    assert.equal(replay.certificate.previewIdHex, preview.certificate.previewIdHex);
    assert.deepEqual(replay.certificate.romPages, preview.certificate.romPages);
    const certifiedReplay = certifyV17LinkedConstruction({
      preview: replay,
      postLinkProfiles: postLinkProfiles(replay, profiles),
      densityTrace,
    });
    assert.equal(certifiedReplay.certificate.certificateIdHex,
      linked.certificate.certificateIdHex);

    const bound = measuredProfiles([body(0), body(1), body(2)]);
    const firstWorkers = [...bound[0].workers];
    const firstPolicies: readonly V17DefinePolicy[] = [{
      path: "0", classification: "construction-bound",
    }];
    firstWorkers[1] = { ...firstWorkers[1]!, definePolicies: firstPolicies };
    assert.throws(() => linkV17Construction({
      profiles: [{ ...bound[0], workers: firstWorkers }, bound[1], bound[2]],
    }), /graph OP_DEFINE policy/,
    "callers cannot override the graph's defineBodyIdentity policy");
  });

  it("keeps semantic function placement stable across same-size body identity changes", () => {
    const earlyBefore = body(0);
    earlyBefore[0] = 0xb0;
    const earlyAfter = earlyBefore.slice();
    earlyAfter[0] = 0x51;
    const later = body(1);
    later[0] = 0x61;
    assert.ok(Buffer.compare(earlyBefore, later) > 0 && Buffer.compare(earlyAfter, later) < 0,
      "the mutation crosses the old body-lexical ordering boundary");

    const before = linkV17Construction({ profiles: measuredProfiles([earlyBefore, later]) });
    const after = linkV17Construction({ profiles: measuredProfiles([earlyAfter, later]) });
    const beforeEarly = romPlacement(before, earlyBefore);
    const afterEarly = romPlacement(after, earlyAfter);
    const beforeLater = romPlacement(before, later);
    const afterLater = romPlacement(after, later);
    assert.deepEqual(
      { ...beforeEarly, bodySha256Hex: undefined },
      { ...afterEarly, bodySha256Hex: undefined },
      "same semantic anchor, size, function ID, page, and offset survive a body hash crossing",
    );
    assert.deepEqual(beforeLater, afterLater,
      "an unrelated semantic body does not move when another same-size body changes");
    assert.notEqual(beforeEarly.bodySha256Hex, afterEarly.bodySha256Hex);
    assert.notEqual(before.pages[beforeEarly.pageIndex]!.payloadSha256Hex,
      after.pages[afterEarly.pageIndex]!.payloadSha256Hex);
    assert.notEqual(before.certificate.previewIdHex, after.certificate.previewIdHex,
      "body identity remains certificate-bound");

    const swapped = linkV17Construction({ profiles: measuredProfiles([later, earlyBefore]) });
    assert.notEqual(romPlacement(swapped, earlyBefore).functionIdHex, beforeEarly.functionIdHex,
      "moving the same bytes to another semantic anchor changes their function identity");
    assert.deepEqual(
      swapped.pages.flatMap(({ entries }) => entries.map(({ bodySha256Hex }) => bodySha256Hex)).sort(),
      before.pages.flatMap(({ entries }) => entries.map(({ bodySha256Hex }) => bodySha256Hex)).sort(),
      "the anchor swap retains the same authenticated body set",
    );
    assert.notEqual(swapped.certificate.previewIdHex, before.certificate.previewIdHex,
      "the preview binds the exact anchor-to-function mapping");
  });

  it("keeps later semantic IDs stable when earlier exact-body classes split or merge", () => {
    const early = body(0);
    const middle = body(1);
    const later = body(2);
    const baseline = measuredProfiles([early, middle, later]);
    const before = linkV17Construction({ profiles: baseline });
    const beforeLater = romPlacement(before, later);

    const splitBody = early.slice();
    splitBody[17] = 0x51;
    const splitWorkers = [...baseline[0].workers];
    const original = splitWorkers[1]!;
    const splitRedeem = workerRedeem(splitBody);
    splitWorkers[1] = {
      ...original,
      redeemBytecode: splitRedeem,
      densityControlLength: 41 + original.unlockingPrefixBytecode.length +
        encodeV17CanonicalPush(splitRedeem).length,
      definePolicies: v17DefinePoliciesForRole({
        roleId: original.roleId,
        redeemBytecode: splitRedeem,
      }),
    };
    const splitProfiles = [{ ...baseline[0], workers: splitWorkers }, baseline[1], baseline[2]] as
      unknown as typeof baseline;
    const split = linkV17Construction({ profiles: splitProfiles });
    assert.equal(split.certificate.census.exactBodyClasses,
      before.certificate.census.exactBodyClasses + 1);
    assert.equal(romPlacement(split, later).functionIdHex, beforeLater.functionIdHex,
      "a one-occurrence split cannot renumber a later semantic anchor");

    const merged = linkV17Construction({ profiles: measuredProfiles([early, early, later]) });
    assert.equal(merged.certificate.census.exactBodyClasses,
      before.certificate.census.exactBodyClasses - 1);
    assert.equal(romPlacement(merged, later).functionIdHex, beforeLater.functionIdHex,
      "merging earlier exact bodies cannot renumber a later semantic anchor");
  });

  it("accepts a non-executable pre-link program census without inventing opcost evidence", () => {
    const measured = measuredProfiles([body(0), body(1), body(2)]);
    const programs = preLinkProgramProfiles(measured);
    const preview = linkV17Construction({ profiles: programs });
    assert.equal(preview.certificate.status, "preview-only");
    assert.equal("baselinePhase" in preview.baselineProfiles[0] &&
      preview.baselineProfiles[0].baselinePhase, "pre-link-program-census");
    assert.equal(preview.pages.length, 2);
    assert.equal("maximumOperationCost" in programs[0].workers[0]!, false);

    assert.throws(() => linkV17Construction({
      profiles: [programs[0], measured[1], programs[2]],
    }), /mixed pre-link baseline phases/);

    const workers = [...programs[0].workers];
    workers[0] = {
      ...workers[0]!,
      unlockingPrefixBytecode: Uint8Array.of(0x51, 0x51),
    };
    assert.throws(() => linkV17Construction({
      profiles: [{ ...programs[0], workers }, programs[1], programs[2]],
    }), /pre-link program worker shape/);
  });

  it("rejects baseline, stale-preview, and byte-stale post-link profiles", () => {
    const baseline = measuredProfiles([body(0), body(1), body(2)]);
    const preview = linkV17Construction({ profiles: baseline });
    assert.throws(() => certifyV17LinkedConstruction({
      preview,
      postLinkProfiles: baseline as unknown as readonly [
        V17PostLinkMeasuredProfile,
        V17PostLinkMeasuredProfile,
        V17PostLinkMeasuredProfile,
      ],
      densityTrace: createV17DensityClosureTrace(),
    }), /stale or unmeasured post-link profile/);

    const wrongPreview = postLinkProfiles(preview, baseline).map((profile) => ({
      ...profile,
      romPreviewIdHex: "ff".repeat(32),
    })) as unknown as readonly [
      V17PostLinkMeasuredProfile,
      V17PostLinkMeasuredProfile,
      V17PostLinkMeasuredProfile,
    ];
    assert.throws(() => certifyV17LinkedConstruction({
      preview,
      postLinkProfiles: wrongPreview,
      densityTrace: createV17DensityClosureTrace(),
    }),
      /stale or unmeasured post-link profile/);

    const byteStale = postLinkProfiles(preview, baseline);
    const workers = [...byteStale[0].workers];
    const staleRedeem = baseline[0].workers[1]!.redeemBytecode;
    workers[1] = {
      ...workers[1]!,
      redeemBytecode: staleRedeem,
      densityControlLength: 41 + workers[1]!.unlockingPrefixBytecode.length +
        encodeV17CanonicalPush(staleRedeem).length,
    };
    const staleProfiles = [{ ...byteStale[0], workers }, byteStale[1], byteStale[2]] as const;
    assert.throws(() => certifyV17LinkedConstruction({
      preview,
      postLinkProfiles: staleProfiles,
      densityTrace: createV17DensityClosureTrace(),
    }), /stale or unmeasured post-link profile/);
  });
});

describe("v17 authenticated value-neutral ROM pages in the BCH2026 VM", () => {
  it("orders page entries by unsigned function ID rather than body bytes", () => {
    const inputs = [
      { functionId: Uint8Array.of(2), body: Uint8Array.of(0x01) },
      { functionId: Uint8Array.of(1), body: Uint8Array.of(0xfe) },
      { functionId: Uint8Array.of(1, 0), body: Uint8Array.of(0x02) },
      { functionId: Uint8Array.of(0xff), body: Uint8Array.of(0x03) },
    ];
    const forward = createV17RomPage({
      pageIndex: 0,
      inputIndex: 2,
      outputIndex: 2,
      entries: inputs,
    });
    const reverse = createV17RomPage({
      pageIndex: 0,
      inputIndex: 2,
      outputIndex: 2,
      entries: [...inputs].reverse(),
    });
    assert.deepEqual(forward.entries.map(({ functionIdHex }) => functionIdHex),
      ["01", "02", "ff", "0100"]);
    assert.deepEqual(forward.entries.map(({ body }) => binToHex(body)),
      ["fe", "01", "03", "02"], "body identity remains attached to its function ID");
    assert.deepEqual(forward.payload, reverse.payload,
      "caller entry order cannot perturb the canonical page");
    assert.deepEqual(forward.entries, reverse.entries);
  });

  it("accepts the canonical page and rejects mutation, order, position, lock, value, and token state", () => {
    const page = createV17RomPage({
      pageIndex: 0,
      inputIndex: 2,
      outputIndex: 2,
      entries: [{ functionId: Uint8Array.of(1), body: body(0, 300) }],
    });
    const vm = createVirtualMachineBch2026(false);
    const fixture = p2shPageFixture(page);
    const evaluate = (candidate: typeof fixture) => vm.evaluate({ inputIndex: 2, ...candidate } as never);
    assert.equal(vm.stateSuccess(evaluate(fixture)), true);

    const payloadMutation = structuredClone(fixture);
    payloadMutation.transaction.inputs[2]!.unlockingBytecode[3 + 12] ^= 1;
    assert.notEqual(vm.stateSuccess(evaluate(payloadMutation)), true);

    const wrongOutputLock = structuredClone(fixture);
    wrongOutputLock.transaction.outputs[2]!.lockingBytecode[10] ^= 1;
    assert.notEqual(vm.stateSuccess(evaluate(wrongOutputLock)), true);

    const wrongSourceLock = structuredClone(fixture);
    wrongSourceLock.sourceOutputs[2]!.lockingBytecode[10] ^= 1;
    assert.notEqual(vm.stateSuccess(evaluate(wrongSourceLock)), true);

    const wrongInputValue = structuredClone(fixture);
    wrongInputValue.sourceOutputs[2]!.valueSatoshis += 1n;
    assert.notEqual(vm.stateSuccess(evaluate(wrongInputValue)), true);

    const wrongOutputValue = structuredClone(fixture);
    wrongOutputValue.transaction.outputs[2]!.valueSatoshis += 1n;
    assert.notEqual(vm.stateSuccess(evaluate(wrongOutputValue)), true);

    const moved = structuredClone(fixture);
    [moved.transaction.inputs[1], moved.transaction.inputs[2]] =
      [moved.transaction.inputs[2]!, moved.transaction.inputs[1]!];
    [moved.sourceOutputs[1], moved.sourceOutputs[2]] =
      [moved.sourceOutputs[2]!, moved.sourceOutputs[1]!];
    const movedState = vm.evaluate({ inputIndex: 1, ...moved } as never);
    assert.notEqual(vm.stateSuccess(movedState), true);

    const inputToken = structuredClone(fixture) as typeof fixture & {
      sourceOutputs: Array<(typeof fixture.sourceOutputs)[number] & { token?: unknown }>;
    };
    inputToken.sourceOutputs[2]!.token = {
      category: new Uint8Array(32).fill(7), amount: 1n,
    };
    assert.notEqual(vm.stateSuccess(evaluate(inputToken as typeof fixture)), true);

    const outputToken = structuredClone(fixture) as typeof fixture & {
      transaction: typeof fixture.transaction & {
        outputs: Array<(typeof fixture.transaction.outputs)[number] & { token?: unknown }>;
      };
    };
    outputToken.transaction.outputs[2]!.token = {
      category: new Uint8Array(32).fill(8), amount: 1n,
    };
    assert.notEqual(vm.stateSuccess(evaluate(outputToken as typeof fixture)), true);
  });
});

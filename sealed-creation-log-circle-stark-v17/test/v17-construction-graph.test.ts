import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";
import {
  V17_GENERATED_ARTIFACT_PATHS,
  assertV17VerifierPlanConformsToSchema,
  buildV17VerifierPlanSchema,
  generateV17ConstructionArtifacts,
} from "../src/construction/v17-artifacts.ts";
import {
  V17_COMPLETENESS_IDS,
  V17_CONSTRUCTION_GRAPH,
  V17_PRODUCTION_ROUND_GRINDING,
  V17_QUALIFICATION_GATE_IDS,
  assertV17Qualified,
  buildV17VerifierPlan,
  canonicalV17Json,
  createPendingV17Qualification,
  type V17ConstructionGraph,
  type V17ObligationSpec,
  type V17ProofFrameSpec,
  type V17QualificationGateId,
  type V17QualificationGateState,
  type V17QualificationStatus,
  type V17TranscriptPhaseSpec,
  v17BankDigestHex,
  v17ConstructionIdHex,
  v17ProtocolIdHex,
  validateV17ConstructionGraph,
} from "../src/construction/v17-graph.ts";
import {
  V17_GENERATED_FOUNDATION,
  V17_GENERATED_FIXED_PREFIX_BYTES,
  V17_GENERATED_FRI_FOLD_CHALLENGE_COUNTS,
  V17_GENERATED_PROTOCOL_ID_HEX,
} from "../src/construction/generated/v17-layout.ts";
import { v17ProductionMerkleDescriptors } from
  "../src/backends/circle/v17-merkle.ts";
import { V17_PRODUCTION_ROLE_LAYOUT } from "../src/chain/v17-role-layout.ts";
import { LOCAL_WORD_RELATION_CONSTRUCTION_VERSION } from
  "../src/chain/local-word-relation-version.ts";

function copyGraph(): V17ConstructionGraph {
  return structuredClone(V17_CONSTRUCTION_GRAPH);
}

function p2sh32Lock(fill: number): Uint8Array {
  return Uint8Array.of(0xaa, 0x20, ...new Uint8Array(32).fill(fill), 0x87);
}

function replaceFrames(
  graph: V17ConstructionGraph,
  frames: readonly V17ProofFrameSpec[],
): V17ConstructionGraph {
  return { ...graph, proof: { ...graph.proof, frames } };
}

function replaceTranscript(
  graph: V17ConstructionGraph,
  transcript: readonly V17TranscriptPhaseSpec[],
): V17ConstructionGraph {
  return { ...graph, transcript };
}

function replaceObligations(
  graph: V17ConstructionGraph,
  obligations: readonly V17ObligationSpec[],
): V17ConstructionGraph {
  return { ...graph, obligations };
}

describe("v17 typed construction graph", () => {
  it("validates one gap-free, transcript-complete C1-C33 graph", () => {
    assert.equal(validateV17ConstructionGraph(V17_CONSTRUCTION_GRAPH), V17_CONSTRUCTION_GRAPH);
    assert.equal(V17_CONSTRUCTION_GRAPH.proof.dynamicTail.offsetBytes, 4_474);
    assert.equal(V17_GENERATED_FIXED_PREFIX_BYTES, 4_474);
    assert.equal(V17_CONSTRUCTION_GRAPH.foundation.queries, 44);
    assert.equal(V17_CONSTRUCTION_GRAPH.foundation.relationConstructionVersion,
      LOCAL_WORD_RELATION_CONSTRUCTION_VERSION);
    assert.equal(V17_CONSTRUCTION_GRAPH.foundation.evaluationLog, 24);
    assert.equal(V17_CONSTRUCTION_GRAPH.foundation.degreeCorrectedBatchWidth, 197);
    assert.deepEqual(V17_GENERATED_FOUNDATION, V17_CONSTRUCTION_GRAPH.foundation);
    assert.deepEqual(V17_GENERATED_FRI_FOLD_CHALLENGE_COUNTS,
      V17_CONSTRUCTION_GRAPH.foundation.friFoldChallengeCounts);
    assert.deepEqual(V17_CONSTRUCTION_GRAPH.foundation.roundGrinding,
      V17_PRODUCTION_ROUND_GRINDING);
    assert.equal(V17_CONSTRUCTION_GRAPH.proof.frames.filter(({ id }) =>
      id.startsWith("friAlpha:")).length, 17);
    assert.equal(V17_CONSTRUCTION_GRAPH.proof.frames.some((frame) =>
      frame.id === "compositionPartials"), false);
    assert.deepEqual(V17_CONSTRUCTION_GRAPH.obligations.map((obligation) => obligation.id),
      V17_COMPLETENESS_IDS);

    const mislabeledRelation = copyGraph() as unknown as {
      foundation: { relationConstructionVersion: number };
    };
    mislabeledRelation.foundation.relationConstructionVersion = 17;
    assert.throws(() => validateV17ConstructionGraph(
      mislabeledRelation as unknown as V17ConstructionGraph,
    ), /v17 construction foundation/);
  });

  it("binds the exact production mixed-Merkle descriptor inventory", () => {
    const production = v17ProductionMerkleDescriptors();
    const descriptors = [
      ...Object.entries(production.matrices).map(([name, descriptor]) =>
        [`matrix:${name}`, descriptor] as const),
      ...production.fri.map((descriptor, layer) => [`fri:${layer}`, descriptor] as const),
    ];
    assert.equal(V17_CONSTRUCTION_GRAPH.commitments.length, descriptors.length);
    for (const [id, descriptor] of descriptors) {
      const commitment = V17_CONSTRUCTION_GRAPH.commitments.find((candidate) => candidate.id === id);
      assert.ok(commitment, id);
      assert.equal(commitment.hashLabel, descriptor.label, id);
      assert.equal(commitment.domainLog, descriptor.logRows, id);
      assert.equal(Number(commitment.leafCodec.match(/(\d+)-bytes$/)?.[1] ?? 16),
        descriptor.rowWidth, id);
      assert.equal(commitment.arities[0], descriptor.shape === "quartet-first" ? 4 : 2, id);
      assert.equal(commitment.arities.reduce((sum, arity) => sum + (arity === 4 ? 2 : 1), 0),
        descriptor.logRows, id);
    }
  });

  it("rejects duplicate frame IDs and physical gaps", () => {
    const duplicate = copyGraph();
    const duplicateFrames = [...duplicate.proof.frames];
    duplicateFrames[1] = { ...duplicateFrames[1]!, id: duplicateFrames[0]!.id };
    assert.throws(() => validateV17ConstructionGraph(replaceFrames(duplicate, duplicateFrames)),
      /duplicate proof frame id/);

    const gap = copyGraph();
    const gapFrames = [...gap.proof.frames];
    gapFrames[2] = { ...gapFrames[2]!, offsetBytes: gapFrames[2]!.offsetBytes + 1 };
    assert.throws(() => validateV17ConstructionGraph(replaceFrames(gap, gapFrames)),
      /proof frame gap/);
  });

  it("rejects transcript dependency inversions and unbound sections", () => {
    const inverted = copyGraph();
    const invertedPhases = [...inverted.transcript];
    invertedPhases[1] = { ...invertedPhases[1]!, dependsOn: ["openings"] };
    assert.throws(() => validateV17ConstructionGraph(replaceTranscript(inverted, invertedPhases)),
      /transcript (?:cycle|dependency order)/);

    const uncovered = copyGraph();
    const uncoveredPhases = [...uncovered.transcript];
    uncoveredPhases[0] = {
      ...uncoveredPhases[0]!,
      consumesSections: uncoveredPhases[0]!.consumesSections.filter(({ id }) => id !== "magic"),
    };
    assert.throws(() => validateV17ConstructionGraph(replaceTranscript(uncovered, uncoveredPhases)),
      /transcript section coverage/);
  });

  it("distinguishes absorption, derived snapshots, PoW witnesses, and terminal codec fields", () => {
    const section = (phaseId: string, sectionId: string) =>
      V17_CONSTRUCTION_GRAPH.transcript.find(({ id }) => id === phaseId)!
        .consumesSections.find(({ id }) => id === sectionId)!;
    assert.equal(section("header", "matrixRoot:original").mode, "transcript-absorb");
    assert.equal(section("air:composition", "interactionChallenges").mode, "derived-snapshot");
    assert.equal(section("air:composition", "publicInverses").mode, "transcript-absorb");
    assert.equal(section("air:logup", "roundNonce:air:logup").mode, "named-round-pow");
    assert.equal(section("openings", "totalLength").mode, "terminal-strict-codec");
    assert.equal(section("openings", "openingDirectory").mode, "terminal-strict-codec");
    assert.equal(section("openings", "queryDigest").mode, "derived-snapshot");

    const wrongCacheMode = copyGraph();
    const cachePhases = [...wrongCacheMode.transcript];
    const composition = cachePhases.findIndex(({ id }) => id === "air:composition");
    cachePhases[composition] = {
      ...cachePhases[composition]!,
      consumesSections: cachePhases[composition]!.consumesSections.map((item) =>
        item.id === "interactionChallenges" ? { ...item, mode: "transcript-absorb" as const } : item),
    };
    assert.throws(() => validateV17ConstructionGraph(replaceTranscript(wrongCacheMode, cachePhases)),
      /transcript section mode interactionChallenges/);

    const earlyTerminal = copyGraph();
    const terminalPhases = [...earlyTerminal.transcript];
    const query = terminalPhases.findIndex(({ id }) => id === "fri:query");
    const openings = terminalPhases.findIndex(({ id }) => id === "openings");
    const directory = terminalPhases[openings]!.consumesSections.find(
      ({ id }) => id === "openingDirectory")!;
    terminalPhases[openings] = {
      ...terminalPhases[openings]!,
      consumesSections: terminalPhases[openings]!.consumesSections.filter(
        ({ id }) => id !== "openingDirectory"),
    };
    terminalPhases[query] = {
      ...terminalPhases[query]!,
      consumesSections: [...terminalPhases[query]!.consumesSections, directory],
    };
    assert.throws(() => validateV17ConstructionGraph(replaceTranscript(earlyTerminal, terminalPhases)),
      /terminal section before challenge openingDirectory/);
  });

  it("enforces the causal placement of public reductions and query-dependent length", () => {
    for (const [sourceId, sectionId] of [
      ["air:composition", "publicInverses"],
      ["air:composition", "publicClaimedSum"],
      ["openings", "totalLength"],
    ] as const) {
      const graph = copyGraph();
      const phases = [...graph.transcript];
      const source = phases.findIndex(({ id }) => id === sourceId);
      const header = phases.findIndex(({ id }) => id === "header");
      const consumed = phases[source]!.consumesSections.find(({ id }) => id === sectionId)!;
      phases[source] = {
        ...phases[source]!,
        consumesSections: phases[source]!.consumesSections.filter(({ id }) => id !== sectionId),
      };
      phases[header] = {
        ...phases[header]!,
        consumesSections: [...phases[header]!.consumesSections, consumed],
      };
      assert.throws(() => validateV17ConstructionGraph(replaceTranscript(graph, phases)),
        /transcript causal section placement/, sectionId);
    }
  });

  it("rejects missing, multiply-owned, cyclic, and ownerless completeness obligations", () => {
    const missing = copyGraph();
    assert.throws(() => validateV17ConstructionGraph(
      replaceObligations(missing, missing.obligations.slice(1))), /C1-C33 coverage/);

    const duplicate = copyGraph();
    assert.throws(() => validateV17ConstructionGraph(
      replaceObligations(duplicate, [...duplicate.obligations, duplicate.obligations[0]!])),
    /duplicate completeness id/);

    const cycle = copyGraph();
    const cycleObligations = [...cycle.obligations];
    cycleObligations[0] = { ...cycleObligations[0]!, dependsOn: ["C33"] };
    assert.throws(() => validateV17ConstructionGraph(
      replaceObligations(cycle, cycleObligations)), /obligation cycle/);

    const ownerless = copyGraph();
    const ownerlessObligations = [...ownerless.obligations];
    ownerlessObligations[0] = { ...ownerlessObligations[0]!, ownerRole: "missing-role" };
    assert.throws(() => validateV17ConstructionGraph(
      replaceObligations(ownerless, ownerlessObligations)), /unknown obligation owner/);
  });

  it("canonicalizes object keys and domain-separates the acyclic identities", () => {
    assert.equal(canonicalV17Json({ z: 1, a: { y: 2, b: 3 } }),
      '{"a":{"b":3,"y":2},"z":1}');
    assert.throws(() => canonicalV17Json({ bad: undefined }), /undefined canonical field/);

    const protocolIdHex = v17ProtocolIdHex();
    assert.equal(protocolIdHex, V17_GENERATED_PROTOCOL_ID_HEX);
    const changed = copyGraph();
    const changedRoles = [...changed.roles];
    changedRoles[0] = { ...changedRoles[0]!, description: `${changedRoles[0]!.description} changed` };
    assert.notEqual(v17ProtocolIdHex({ ...changed, roles: changedRoles }), protocolIdHex);

    const roles = [
      { index: 1, lockingBytecode: p2sh32Lock(0xaa), valueSatoshis: 1_000n,
        sequenceNumber: 0x8000_0000 },
      { index: 2, lockingBytecode: p2sh32Lock(0xbb), valueSatoshis: 1_001n,
        sequenceNumber: 0x8000_0001 },
    ] as const;
    const bank0 = v17BankDigestHex({ protocolIdHex, profile: 0, roles });
    const bank1 = v17BankDigestHex({ protocolIdHex, profile: 1, roles });
    const bank2 = v17BankDigestHex({ protocolIdHex, profile: 2, roles });
    assert.notEqual(bank0, bank1);
    assert.notEqual(bank1, bank2);
    const changedBank = v17BankDigestHex({
      protocolIdHex,
      profile: 0,
      roles: [{ ...roles[0], lockingBytecode: p2sh32Lock(0xab) }, roles[1]],
    });
    assert.notEqual(changedBank, bank0);
    const construction = v17ConstructionIdHex({
      protocolIdHex,
      bankDigests: [bank0, bank1, bank2],
    });
    assert.equal(construction, v17ConstructionIdHex({
      protocolIdHex,
      bankDigests: [bank0, bank1, bank2],
    }));
    assert.notEqual(construction, v17ConstructionIdHex({
      protocolIdHex,
      bankDigests: [changedBank, bank1, bank2],
    }));
  });

  it("generates the fused typed role surface and leaves measurement fail-closed", () => {
    const plan = buildV17VerifierPlan();
    assert.equal(plan.roles.length, 210);
    assert.equal(plan.roles[0]!.id, "settlement");
    assert.equal(plan.roles.filter((role) => role.familyId === "ood-air").length, 1);
    assert.equal(plan.roles.filter((role) => role.familyId === "batch-link-query").length, 44);
    assert.equal(plan.roles.some((role) => role.familyId === "air-algebra-query"), false);
    assert.equal(plan.roles.filter((role) => role.familyId === "fri-fold-query").length, 44);
    assert.equal(plan.roles.filter((role) => role.familyId === "opening-schedule").length, 31);
    assert.equal(plan.roles.filter((role) => role.familyId === "matrix-merkle").length, 31);
    assert.equal(plan.roles.filter((role) => role.familyId === "fri-merkle").length, 43);
    assert.equal(plan.allocation.strategy, "base-plus-elastic-prefix");
    assert.equal(plan.allocation.elasticScaleUnits, 4_095);
    assert.equal(plan.allocation.minimumProofBytes, null);
    assert.equal(plan.allocation.maximumProofBytes, 457_514);
    assert.equal(plan.allocation.densityCredit, "max-profile-residual-proof-bytes");
    assert.equal(plan.allocation.closure, "coordinatewise-monotone-profile-envelope");
    assert.equal(plan.allocation.closureGenesis, "canonical-bootstrap-affine-allocation");
    assert.equal(plan.allocation.closureJoin,
      "profile-opcost-max-required-max-capacity-min");
    assert.equal(plan.allocation.closureTerminal, "explicit-no-change-replay");
    assert.equal(plan.allocation.closureTrace, "domain-separated-sha256-chain");
    assert.equal(plan.allocation.minimumProofBytesPerRole, 256);
    assert.equal(plan.allocation.capacityLimitBytes, 10_000);
    assert.equal(plan.allocation.metadataEncoding, "base19-elastic12-disabled-sequence");
    assert.equal(plan.allocation.status, "unmeasured");
    assert.deepEqual(plan.allocation.assignments, []);
    assert.equal(plan.rom.status, "unmeasured");
    assert.equal(plan.rom.functionIdentifiers,
      "minimal-positive-unsigned-be-earliest-static-occurrence-anchor");
    assert.equal(plan.rom.packing, "minimum-pages-then-semantic-anchor");
    assert.deepEqual(plan.rom.pages, []);
  });

  it("uses graph-owned semantic instances as the only exact role inventory", () => {
    const plan = buildV17VerifierPlan();
    const graphSemantics = V17_CONSTRUCTION_GRAPH.roles.flatMap((family) =>
      family.semanticInstances);
    assert.equal(plan.roles.length, 210);
    assert.equal(graphSemantics.length, plan.roles.length);
    assert.deepEqual(plan.roles.map(({ semantic }) => semantic), graphSemantics);
    assert.deepEqual(V17_PRODUCTION_ROLE_LAYOUT.map(({ familyKind, ...role }) => ({
      familyKind,
      semantic: Object.fromEntries(Object.entries(role).filter(([key]) => [
        "kind", "query", "root", "segment", "part", "stage", "layer",
        "mappingShard", "matrix", "shard", "shards",
      ].includes(key))),
    })).map(({ semantic }) => semantic), graphSemantics);
    assert.equal(V17_CONSTRUCTION_GRAPH.roles.some((family) => "count" in family), false);
  });

  it("fails closed if graph role meaning or order drifts", () => {
    const changed = copyGraph();
    const roles = [...changed.roles];
    const familyIndex = roles.findIndex(({ id }) => id === "batch-link-query");
    const family = roles[familyIndex]!;
    const semanticInstances = [...family.semanticInstances];
    semanticInstances[0] = { kind: "batch-link-query", query: 1 };
    roles[familyIndex] = { ...family, semanticInstances };
    assert.throws(() => validateV17ConstructionGraph({ ...changed, roles }),
      /role semantic instances batch-link-query/);

    const swapped = copyGraph();
    const swappedRoles = [...swapped.roles];
    const transcriptIndex = swappedRoles.findIndex(({ id }) => id === "transcript");
    const transcript = swappedRoles[transcriptIndex]!;
    const transcriptInstances = [...transcript.semanticInstances];
    [transcriptInstances[0], transcriptInstances[1]] =
      [transcriptInstances[1]!, transcriptInstances[0]!];
    swappedRoles[transcriptIndex] = { ...transcript, semanticInstances: transcriptInstances };
    assert.throws(() => validateV17ConstructionGraph({ ...swapped, roles: swappedRoles }),
      /role semantic instances transcript/);

    const wrongFamily = copyGraph();
    const wrongFamilyRoles = [...wrongFamily.roles];
    const wrongTranscript = wrongFamilyRoles[transcriptIndex]!;
    wrongFamilyRoles[transcriptIndex] = { ...wrongTranscript, kind: "matrix-merkle" };
    assert.throws(() => validateV17ConstructionGraph({
      ...wrongFamily, roles: wrongFamilyRoles,
    }), /role family transcript/);
  });

  it("reproduces every checked-in generated artifact exactly", () => {
    const artifacts = generateV17ConstructionArtifacts();
    for (const path of V17_GENERATED_ARTIFACT_PATHS) {
      assert.equal(readFileSync(path, "utf8"), artifacts[path], path);
    }
  });

  it("validates the emitted verifier plan against its graph-derived schema", () => {
    const artifacts = generateV17ConstructionArtifacts();
    const plan = JSON.parse(
      artifacts["src/construction/generated/v17-verifier-plan.json"],
    ) as { rom: { bankIdentity: string } };
    const schema = JSON.parse(
      artifacts["src/construction/generated/v17-verifier-plan.schema.json"],
    ) as {
      properties: { rom: { properties: { bankIdentity: { const: string } } } };
    };
    assert.equal(
      schema.properties.rom.properties.bankIdentity.const,
      V17_CONSTRUCTION_GRAPH.rom.bankIdentity,
    );
    assert.doesNotThrow(() => assertV17VerifierPlanConformsToSchema({ plan, schema }));

    const driftedPlan = structuredClone(plan);
    driftedPlan.rom.bankIdentity = "stale-bank-identity";
    assert.throws(
      () => assertV17VerifierPlanConformsToSchema({ plan: driftedPlan, schema }),
      /bankIdentity must be equal to constant/,
    );

    const graphSchema = buildV17VerifierPlanSchema(V17_CONSTRUCTION_GRAPH) as typeof schema;
    assert.equal(
      graphSchema.properties.rom.properties.bankIdentity.const,
      V17_CONSTRUCTION_GRAPH.rom.bankIdentity,
    );
  });

  it("cannot report qualification while a gate or unresolved claim remains", () => {
    const pending = createPendingV17Qualification();
    assert.equal(pending.overall, "incomplete");
    assert.throws(() => assertV17Qualified(pending), /not qualified/);
    assert.throws(() => assertV17Qualified({ ...pending, overall: "qualified" }), /not qualified/);

    const evidence = Object.fromEntries(V17_QUALIFICATION_GATE_IDS.map((id) => [id, {
      status: "passed" as const,
      evidence: { sha256Hex: "11".repeat(32), summary: `evidence for ${id}` },
    }])) as Record<V17QualificationGateId, V17QualificationGateState>;
    const qualified: V17QualificationStatus = {
      ...pending,
      constructionIdHex: "22".repeat(32),
      overall: "qualified",
      gates: evidence,
      unresolved: [],
    };
    assert.doesNotThrow(() => assertV17Qualified(qualified));
    assert.throws(() => assertV17Qualified({
      ...qualified,
      unresolved: ["soundness theorem remains unresolved"],
    }), /not qualified/);
  });
});

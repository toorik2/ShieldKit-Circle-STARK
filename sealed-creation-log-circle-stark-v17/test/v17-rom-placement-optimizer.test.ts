import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  V17_ROM_PLACEMENT_INPUT_SCHEMA,
  optimizeV17RomPlacement,
  type V17ExactRoleEnvelope,
  type V17ExactRomPageEnvelope,
  type V17ExactRomPlacementCandidate,
  type V17ExactRomPlacementProfile,
  type V17MaterializedRomPlacementCandidate,
  type V17RomPlacementDecision,
  type V17RomPlacementOptimizerInput,
} from "../src/construction/v17-rom-placement-optimizer.ts";

const ROLE_ID = "role:0";
const PAGE_ID = "page:0";
const BODY_HASH = byteHex(2);

function byteHex(byte: number): string {
  return byte.toString(16).padStart(2, "0").repeat(32);
}

function pushBytes(payloadBytes: number): number {
  if (payloadBytes === 0) return 1;
  if (payloadBytes <= 75) return payloadBytes + 1;
  if (payloadBytes <= 0xff) return payloadBytes + 2;
  if (payloadBytes <= 0xffff) return payloadBytes + 3;
  return payloadBytes + 5;
}

function compactUintBytes(value: number): number {
  if (value <= 0xfc) return 1;
  if (value <= 0xffff) return 3;
  if (value <= 0xffff_ffff) return 5;
  return 9;
}

function inputBytes(unlockingBytes: number): number {
  return 40 + compactUintBytes(unlockingBytes) + unlockingBytes;
}

function outputBytes(lockingBytes: number): number {
  return 8 + compactUintBytes(lockingBytes) + lockingBytes;
}

function role(args: {
  readonly profile: 0 | 1 | 2;
  readonly redeemBytes: number;
  readonly operationCost?: number;
  readonly tag: number;
}): V17ExactRoleEnvelope {
  const proofCarrierBytes = 256;
  const unlockingBytes = pushBytes(proofCarrierBytes) + pushBytes(args.redeemBytes);
  return {
    logicalInputIndex: 0,
    roleId: ROLE_ID,
    proofCarrierBytes,
    redeemBytes: args.redeemBytes,
    unlockingBytes,
    redeemSha256Hex: byteHex(args.tag),
    unlockingSha256Hex: byteHex(args.tag + 1),
    maximumOperationCost: args.operationCost ?? 50_000,
    operationCostEngine: "independent-bchn-conformant",
    operationCostEvidenceSha256Hex: byteHex(args.tag + 2),
  };
}

function page(profile: 0 | 1 | 2): V17ExactRomPageEnvelope {
  const payloadBytes = 100;
  const redeemBytes = 50;
  const lockingBytes = 35;
  const unlockingBytes = pushBytes(payloadBytes) + pushBytes(redeemBytes);
  return {
    pageId: PAGE_ID,
    pageIndex: 0,
    inputIndex: 1,
    outputIndex: 1,
    payloadBytes,
    payloadSha256Hex: byteHex(3),
    redeemBytes,
    lockingBytes,
    unlockingBytes,
    redeemSha256Hex: byteHex(40 + profile),
    lockingSha256Hex: byteHex(50 + profile),
    unlockingSha256Hex: byteHex(60 + profile),
    maximumOperationCost: 1_000,
    operationCostEngine: "independent-bchn-conformant",
    operationCostEvidenceSha256Hex: byteHex(70 + profile),
    bodyLoaders: [{ bodySha256Hex: BODY_HASH, loaderBytes: 13 }],
  };
}

function profile(args: {
  readonly profile: 0 | 1 | 2;
  readonly activePage: boolean;
  readonly selectedRole: V17ExactRoleEnvelope;
  readonly tag: number;
}): V17ExactRomPlacementProfile {
  const pages = args.activePage ? [page(args.profile)] : [];
  const pageBytes = pages.reduce((sum, value) =>
    sum + inputBytes(value.unlockingBytes) + outputBytes(value.lockingBytes), 0);
  const nonRoleTransactionBytes = 100 + pageBytes;
  const transactionBytes = nonRoleTransactionBytes + inputBytes(args.selectedRole.unlockingBytes);
  return {
    profile: args.profile,
    transactionBytes,
    transactionSha256Hex: byteHex(args.tag),
    nonRoleTransactionBytes,
    envelopeEvidenceSha256Hex: byteHex(args.tag + 1),
    roles: [args.selectedRole],
    pages,
  };
}

function materializedCandidate(args: {
  readonly placement: V17RomPlacementDecision;
  readonly inlineRedeemBytes: number;
  readonly romOperationCost?: number;
  readonly tag: number;
}): V17MaterializedRomPlacementCandidate {
  const activePage = args.placement === "rom";
  const profiles = ([0, 1, 2] as const).map((profileIndex) => {
    const selectedRole = role({
      profile: profileIndex,
      redeemBytes: profileIndex === 0
        ? (activePage ? 40 : args.inlineRedeemBytes)
        : 100,
      operationCost: profileIndex === 0 && activePage
        ? args.romOperationCost
        : undefined,
      tag: args.tag + profileIndex * 5,
    });
    return profile({
      profile: profileIndex,
      activePage,
      selectedRole,
      tag: args.tag + 20 + profileIndex * 5,
    });
  }) as unknown as V17MaterializedRomPlacementCandidate["profiles"];
  return {
    status: "materialized-exact-envelope",
    placements: [{
      profile: 0,
      roleId: ROLE_ID,
      path: "0",
      bodySha256Hex: BODY_HASH,
      placement: args.placement,
    }],
    profiles,
  };
}

function model(args: {
  readonly inlineRedeemBytes: number;
  readonly romOperationCost?: number;
  readonly candidates?: readonly V17ExactRomPlacementCandidate[];
}): V17RomPlacementOptimizerInput {
  const candidates = args.candidates ?? [
    materializedCandidate({
      placement: "inline",
      inlineRedeemBytes: args.inlineRedeemBytes,
      tag: 80,
    }),
    materializedCandidate({
      placement: "rom",
      inlineRedeemBytes: args.inlineRedeemBytes,
      romOperationCost: args.romOperationCost,
      tag: 100,
    }),
  ];
  return {
    schema: V17_ROM_PLACEMENT_INPUT_SCHEMA,
    status: "complete-exact-envelope-enumeration",
    protocolIdHex: byteHex(10),
    constructionGraphSha256Hex: byteHex(11),
    occurrenceCensusSha256Hex: byteHex(12),
    minimumProofCarrierBytesPerRole: 256,
    roleIds: [ROLE_ID],
    pages: [{
      pageId: PAGE_ID,
      payloadSha256Hex: byteHex(3),
      payloadBytes: 100,
      bodyClasses: [{ bodySha256Hex: BODY_HASH, bodyBytes: 80 }],
    }],
    occurrences: [{
      profile: 0,
      roleId: ROLE_ID,
      path: "0",
      functionIdHex: "01",
      bodySha256Hex: BODY_HASH,
      bodyBytes: 80,
      pageId: PAGE_ID,
    }],
    candidates,
  };
}

function repeatedBodyClassModel(args: {
  readonly memberCount: number;
  readonly inlineRedeemBytes: number;
}): V17RomPlacementOptimizerInput {
  const base = model({ inlineRedeemBytes: args.inlineRedeemBytes });
  const occurrences = Array.from({ length: args.memberCount }, (_, index) => ({
    profile: (index % 3) as 0 | 1 | 2,
    roleId: ROLE_ID,
    path: Math.floor(index / 3).toString(),
    functionIdHex: "01",
    bodySha256Hex: BODY_HASH,
    bodyBytes: 80,
    pageId: PAGE_ID,
  }));
  return {
    ...base,
    occurrences,
    candidates: base.candidates.map((candidate) => {
      const placement = candidate.placements[0]!.placement;
      return {
        ...candidate,
        placements: occurrences.map((occurrence) => ({
          profile: occurrence.profile,
          roleId: occurrence.roleId,
          path: occurrence.path,
          bodySha256Hex: occurrence.bodySha256Hex,
          placement,
        })),
      };
    }),
  };
}

type SemanticBodyClassFixture = {
  readonly path: string;
  readonly functionIdHex: string;
  readonly bodySha256Hex: string;
};

const SEMANTIC_PAGE_ID = "page:semantic";
const SEMANTIC_PAGE_PAYLOAD_HASH = byteHex(9);

function semanticPageEnvelope(
  profileIndex: 0 | 1 | 2,
  classes: readonly SemanticBodyClassFixture[],
): V17ExactRomPageEnvelope {
  const payloadBytes = 200;
  const redeemBytes = 50;
  const lockingBytes = 35;
  const unlockingBytes = pushBytes(payloadBytes) + pushBytes(redeemBytes);
  return {
    pageId: SEMANTIC_PAGE_ID,
    pageIndex: 0,
    inputIndex: 1,
    outputIndex: 1,
    payloadBytes,
    payloadSha256Hex: SEMANTIC_PAGE_PAYLOAD_HASH,
    redeemBytes,
    lockingBytes,
    unlockingBytes,
    redeemSha256Hex: byteHex(20 + profileIndex),
    lockingSha256Hex: byteHex(30 + profileIndex),
    unlockingSha256Hex: byteHex(40 + profileIndex),
    maximumOperationCost: 1_000,
    operationCostEngine: "independent-bchn-conformant",
    operationCostEvidenceSha256Hex: byteHex(50 + profileIndex),
    bodyLoaders: classes.map(({ bodySha256Hex }) => ({ bodySha256Hex, loaderBytes: 13 })),
  };
}

function semanticClassModel(
  classes: readonly [SemanticBodyClassFixture, SemanticBodyClassFixture],
): V17RomPlacementOptimizerInput {
  const occurrences = classes.map((bodyClass) => ({
    profile: 0 as const,
    roleId: ROLE_ID,
    path: bodyClass.path,
    functionIdHex: bodyClass.functionIdHex,
    bodySha256Hex: bodyClass.bodySha256Hex,
    bodyBytes: 80,
    pageId: SEMANTIC_PAGE_ID,
  }));
  const candidates = Array.from({ length: 4 }, (_, mask): V17ExactRomPlacementCandidate => {
    const decisions = classes.map((_, index): V17RomPlacementDecision =>
      (mask & (1 << index)) === 0 ? "inline" : "rom");
    const activePage = decisions.includes("rom");
    const profiles = ([0, 1, 2] as const).map((profileIndex) => {
      const selectedRole = role({
        profile: profileIndex,
        redeemBytes: activePage ? 40 : 1_000,
        tag: 80 + mask * 20 + profileIndex * 3,
      });
      const pages = activePage ? [semanticPageEnvelope(profileIndex, classes)] : [];
      const pageBytes = pages.reduce((sum, value) =>
        sum + inputBytes(value.unlockingBytes) + outputBytes(value.lockingBytes), 0);
      const nonRoleTransactionBytes = 100 + pageBytes;
      return {
        profile: profileIndex,
        transactionBytes: nonRoleTransactionBytes + inputBytes(selectedRole.unlockingBytes),
        transactionSha256Hex: byteHex(140 + mask * 10 + profileIndex * 2),
        nonRoleTransactionBytes,
        envelopeEvidenceSha256Hex: byteHex(141 + mask * 10 + profileIndex * 2),
        roles: [selectedRole],
        pages,
      };
    }) as unknown as V17MaterializedRomPlacementCandidate["profiles"];
    return {
      status: "materialized-exact-envelope",
      placements: occurrences.map((occurrence, index) => ({
        profile: occurrence.profile,
        roleId: occurrence.roleId,
        path: occurrence.path,
        bodySha256Hex: occurrence.bodySha256Hex,
        placement: decisions[index]!,
      })),
      profiles,
    };
  });
  return {
    schema: V17_ROM_PLACEMENT_INPUT_SCHEMA,
    status: "complete-exact-envelope-enumeration",
    protocolIdHex: byteHex(10),
    constructionGraphSha256Hex: byteHex(11),
    occurrenceCensusSha256Hex: byteHex(12),
    minimumProofCarrierBytesPerRole: 256,
    roleIds: [ROLE_ID],
    pages: [{
      pageId: SEMANTIC_PAGE_ID,
      payloadSha256Hex: SEMANTIC_PAGE_PAYLOAD_HASH,
      payloadBytes: 200,
      bodyClasses: classes.map(({ bodySha256Hex }) => ({ bodySha256Hex, bodyBytes: 80 })),
    }],
    occurrences,
    candidates,
  };
}

describe("v17 exact coherent body-class ROM placement planner", () => {
  it("selects ROM when its exact page topology is smaller and certifies local limits", () => {
    const certificate = optimizeV17RomPlacement(model({ inlineRedeemBytes: 1_000 }));
    assert.equal(certificate.status, "exact-optimum-over-complete-envelope-enumeration");
    assert.equal(certificate.qualification,
      "planning-only-requires-byte-replay-and-independent-bchn");
    assert.equal(certificate.placements[0]!.placement, "rom");
    assert.deepEqual(certificate.pageEffects.activePageIds, [PAGE_ID]);
    assert.deepEqual(certificate.pageEffects.removedPageIds, []);
    assert.equal(certificate.placements[0]!.inlineEncodedBytes, 82);
    assert.equal(certificate.placements[0]!.selectedEncodingBytes, 13);
    certificate.profiles.forEach((selected) => {
      assert.ok(selected.transactionBytes <= 1_000_000);
      assert.ok(selected.roles[0]!.operationCostHeadroom >= 0);
      assert.ok(selected.pages[0]!.operationCostHeadroom >= 0);
    });
    assert.match(certificate.modelDigestHex, /^[0-9a-f]{64}$/);
    assert.match(certificate.certificateIdHex, /^[0-9a-f]{64}$/);
  });

  it("removes an unused page when exact non-role page cost exceeds body savings", () => {
    const certificate = optimizeV17RomPlacement(model({ inlineRedeemBytes: 100 }));
    assert.equal(certificate.placements[0]!.placement, "inline");
    assert.deepEqual(certificate.pageEffects.activePageIds, []);
    assert.deepEqual(certificate.pageEffects.removedPageIds, [PAGE_ID]);
    assert.deepEqual(certificate.pageEffects.exactNonRoleBytesRemovedFromAllRom,
      [238, 238, 238]);
  });

  it("never buys transaction bytes with a locally density-infeasible caller", () => {
    const romUnlockingBytes = pushBytes(256) + pushBytes(40);
    const romLimit = (41 + romUnlockingBytes) * 800;
    const certificate = optimizeV17RomPlacement(model({
      inlineRedeemBytes: 1_000,
      romOperationCost: romLimit + 1,
    }));
    assert.equal(certificate.placements[0]!.placement, "inline");
    assert.deepEqual(certificate.pageEffects.removedPageIds, [PAGE_ID]);
  });

  it("is order-independent and applies a canonical certificate digest", () => {
    const original = model({ inlineRedeemBytes: 1_000 });
    const reordered: V17RomPlacementOptimizerInput = {
      ...original,
      candidates: [...original.candidates].reverse(),
    };
    const first = optimizeV17RomPlacement(original);
    const second = optimizeV17RomPlacement(reordered);
    assert.equal(second.modelDigestHex, first.modelDigestHex);
    assert.equal(second.selectedCandidateDigestHex, first.selectedCandidateDigestHex);
    assert.equal(second.certificateIdHex, first.certificateIdHex);
  });

  it("enumerates one decision for 132 identical occurrences without combinatorial blowup", () => {
    const input = repeatedBodyClassModel({ memberCount: 132, inlineRedeemBytes: 1_000 });
    assert.equal(input.candidates.length, 2);
    const certificate = optimizeV17RomPlacement(input, {
      maximumCandidateEvaluations: 2,
    });
    assert.equal(certificate.placements.length, 132);
    assert.ok(certificate.placements.every(({ placement }) => placement === "rom"));
    assert.deepEqual(new Set(certificate.placements.map(({ bodySha256Hex }) =>
      bodySha256Hex)), new Set([BODY_HASH]));
  });

  it("rejects mixed decisions inside one exact body class", () => {
    const input = structuredClone(repeatedBodyClassModel({
      memberCount: 2,
      inlineRedeemBytes: 1_000,
    }));
    const first = input.candidates[0]!;
    (first.placements[1] as { placement: V17RomPlacementDecision }).placement = "rom";
    assert.throws(() => optimizeV17RomPlacement(input),
      /incoherent body-class placement page:0:/);
  });

  it("canonically binds every class member and its occurrence provenance", () => {
    const original = repeatedBodyClassModel({ memberCount: 9, inlineRedeemBytes: 1_000 });
    const reordered: V17RomPlacementOptimizerInput = {
      ...original,
      occurrences: [...original.occurrences].reverse(),
      candidates: [...original.candidates].reverse().map((candidate) => ({
        ...candidate,
        placements: [...candidate.placements].reverse(),
      })),
    };
    const first = optimizeV17RomPlacement(original);
    const second = optimizeV17RomPlacement(reordered);
    assert.equal(second.modelDigestHex, first.modelDigestHex);
    assert.equal(second.selectedCandidateDigestHex, first.selectedCandidateDigestHex);
    assert.equal(second.certificateIdHex, first.certificateIdHex);

    const changed = structuredClone(original);
    const oldPath = changed.occurrences[0]!.path;
    (changed.occurrences[0] as { path: string }).path = "999";
    changed.candidates.forEach((candidate) => {
      const member = candidate.placements.find((placement) =>
        placement.profile === 0 && placement.roleId === ROLE_ID && placement.path === oldPath);
      assert.ok(member);
      (member as { path: string }).path = "999";
    });
    const third = optimizeV17RomPlacement(changed);
    assert.notEqual(third.modelDigestHex, first.modelDigestHex);
    assert.notEqual(third.selectedCandidateDigestHex, first.selectedCandidateDigestHex);
    assert.notEqual(third.certificateIdHex, first.certificateIdHex);
  });

  it("rejects a sparse measurement list rather than assuming additive costs", () => {
    const complete = model({ inlineRedeemBytes: 100 });
    const incomplete: V17RomPlacementOptimizerInput = {
      ...complete,
      candidates: complete.candidates.slice(0, 1),
    };
    assert.throws(() => optimizeV17RomPlacement(incomplete),
      /under-specified candidate enumeration 1\/2/);
  });

  it("accepts an exact pre-measurement limit rejection as one enumerated vector", () => {
    const rom = materializedCandidate({
      placement: "rom",
      inlineRedeemBytes: 1_000,
      tag: 120,
    });
    const rejected: V17ExactRomPlacementCandidate = {
      status: "proven-infeasible-before-exact-vm-measurement",
      placements: [{
        profile: 0,
        roleId: ROLE_ID,
        path: "0",
        bodySha256Hex: BODY_HASH,
        placement: "inline",
      }],
      rejection: {
        metric: "unlockingBytes",
        actual: 10_001,
        limit: 10_000,
        profile: 0,
        roleId: ROLE_ID,
        evidenceSha256Hex: byteHex(121),
      },
    };
    const certificate = optimizeV17RomPlacement(model({
      inlineRedeemBytes: 1_000,
      candidates: [rejected, rom],
    }));
    assert.equal(certificate.placements[0]!.placement, "rom");
  });

  it("rejects noncanonical role byte accounting", () => {
    const input = structuredClone(model({ inlineRedeemBytes: 100 }));
    const inline = input.candidates[0] as V17MaterializedRomPlacementCandidate;
    const brokenRole = inline.profiles[0].roles[0]!;
    (brokenRole as { unlockingBytes: number }).unlockingBytes += 1;
    assert.throws(() => optimizeV17RomPlacement(input), /noncanonical carrier unlocking/);
  });

  it("accepts only minimal positive unsigned-BE ROM function identifiers", () => {
    for (const functionIdHex of ["01", "ff", "0100"]) {
      const input = structuredClone(model({ inlineRedeemBytes: 100 }));
      (input.occurrences[0] as { functionIdHex: string }).functionIdHex = functionIdHex;
      assert.doesNotThrow(() => optimizeV17RomPlacement(input), functionIdHex);
    }
    for (const functionIdHex of ["00", "0001"]) {
      const input = structuredClone(model({ inlineRedeemBytes: 100 }));
      (input.occurrences[0] as { functionIdHex: string }).functionIdHex = functionIdHex;
      assert.throws(() => optimizeV17RomPlacement(input), /function id/, functionIdHex);
    }

    const aliases = structuredClone(repeatedBodyClassModel({
      memberCount: 2,
      inlineRedeemBytes: 100,
    }));
    (aliases.occurrences[1] as { functionIdHex: string }).functionIdHex = "0001";
    assert.throws(() => optimizeV17RomPlacement(aliases), /function id/,
      "01 and 0001 cannot alias one unsigned ordinal");
  });

  it("rejects duplicate semantic occurrence anchors independently of body identity", () => {
    const input = semanticClassModel([
      { path: "2", functionIdHex: "01", bodySha256Hex: byteHex(2) },
      { path: "2", functionIdHex: "02", bodySha256Hex: byteHex(3) },
    ]);
    assert.throws(() => optimizeV17RomPlacement(input),
      /duplicate semantic occurrence anchor/);
  });

  it("rejects one function identifier assigned to distinct body classes", () => {
    const input = semanticClassModel([
      { path: "2", functionIdHex: "01", bodySha256Hex: byteHex(2) },
      { path: "10", functionIdHex: "01", bodySha256Hex: byteHex(3) },
    ]);
    assert.throws(() => optimizeV17RomPlacement(input),
      /function id aliases body classes 01/);
  });

  it("orders numeric paths and placement ties by stable semantic anchors", () => {
    const before = semanticClassModel([
      { path: "10", functionIdHex: "02", bodySha256Hex: byteHex(1) },
      { path: "2", functionIdHex: "01", bodySha256Hex: byteHex(2) },
    ]);
    const after = semanticClassModel([
      { path: "10", functionIdHex: "02", bodySha256Hex: byteHex(3) },
      { path: "2", functionIdHex: "01", bodySha256Hex: byteHex(0) },
    ]);
    const first = optimizeV17RomPlacement(before);
    const second = optimizeV17RomPlacement(after);
    for (const certificate of [first, second]) {
      assert.deepEqual(certificate.placements.map(({ path }) => path), ["2", "10"]);
      assert.deepEqual(certificate.placements.map(({ placement }) => placement),
        ["inline", "rom"], "the earliest semantic class owns the inline-first tie-break");
    }
    assert.notEqual(second.modelDigestHex, first.modelDigestHex,
      "body identity remains bound even though unrelated semantic placement is stable");
  });
});

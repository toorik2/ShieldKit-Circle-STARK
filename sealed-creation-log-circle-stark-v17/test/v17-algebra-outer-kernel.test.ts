import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  binToHex,
  cashAssemblyToBin,
  createVirtualMachineBch2026,
  decodeAuthenticationInstructions,
  OpcodesBch,
} from "@bitauth/libauth";
import { LOCAL_WORD_PRODUCTION_PARAMETERS } from
  "../src/backends/circle/local-word-successor-params.ts";
import {
  compileLocalWordFriBatchGate,
  compileV17LocalWordFriFoldGate,
} from "../src/chain/local-word-algebra-vm.ts";
import {
  encodeLocalWordBatchLeaderUnlockingPrefix,
  LOCAL_WORD_BATCH_LEADER_ROLE_ID,
} from "../src/chain/local-word-proof-carriers.ts";
import { V17_BATCH_LEADER_CELL_BYTES } from
  "../src/backends/circle/v17-batch-leader-cell.ts";
import { encodeV17CanonicalPush } from "../src/chain/v17-code-rom.ts";
import {
  V17_PROFILES,
  buildV17VerifierPlan,
} from "../src/construction/v17-graph.ts";
import {
  censusV17OpDefineBodies,
  previewV17Rom,
  v17DefinePoliciesForRole,
  type V17PreLinkProgramProfile,
} from "../src/construction/v17-linker.ts";

const QUERIES = LOCAL_WORD_PRODUCTION_PARAMETERS.fri.queries;

function compile(assembly: string): Uint8Array {
  const bytecode = cashAssemblyToBin(assembly);
  if (typeof bytecode === "string") throw new Error(bytecode);
  return bytecode;
}

function program(lockingBytecode: Uint8Array) {
  return {
    inputIndex: 0,
    sourceOutputs: [{ lockingBytecode, valueSatoshis: 1_000n }],
    transaction: {
      version: 2,
      locktime: 0,
      inputs: [{
        outpointTransactionHash: new Uint8Array(32).fill(1),
        outpointIndex: 0,
        sequenceNumber: 0xffff_fffe,
        unlockingBytecode: new Uint8Array(),
      }],
      outputs: [{ lockingBytecode: Uint8Array.of(0x51), valueSatoshis: 1_000n }],
    },
  };
}

function invokeOuterWith(body: Uint8Array, functionId: number, query: number): Uint8Array {
  return compile(`<0x${binToHex(body)}> <${functionId}> OP_DEFINE
<${query}> <${functionId}> OP_INVOKE OP_1`);
}

function outerBody(gate: Uint8Array, functionIdHex: string): Uint8Array {
  const matches = censusV17OpDefineBodies(gate)
    .filter(({ depth, functionIdHex: id }) => depth === 0 && id === functionIdHex);
  assert.equal(matches.length, 1);
  return matches[0]!.body;
}

function includesBytes(container: Uint8Array, expected: Uint8Array): boolean {
  if (expected.length === 0 || expected.length > container.length) return false;
  for (let start = 0; start <= container.length - expected.length; start += 1) {
    if (expected.every((byte, offset) => byte === container[start + offset])) return true;
  }
  return false;
}

function previewProfiles(): readonly [
  V17PreLinkProgramProfile,
  V17PreLinkProgramProfile,
  V17PreLinkProgramProfile,
] {
  const plan = buildV17VerifierPlan();
  const proofBytes = 256;
  const ordinaryPrefix = encodeV17CanonicalPush(new Uint8Array(proofBytes));
  const leaderPrefix = encodeLocalWordBatchLeaderUnlockingPrefix(
    new Uint8Array(proofBytes),
    new Uint8Array(V17_BATCH_LEADER_CELL_BYTES),
  );
  const trivial = compile("OP_DROP OP_1");
  const batch = Array.from({ length: QUERIES }, (_, query) => query === 0
    ? trivial
    : compileLocalWordFriBatchGate({ profile: 0, query }));
  const fri = Array.from({ length: QUERIES }, (_, query) =>
    compileV17LocalWordFriFoldGate({ profile: 0, query }));
  const verifierFor = (roleId: string): Uint8Array => {
    const batchMatch = /^batch-link-query:(\d+)$/.exec(roleId);
    if (batchMatch !== null) return batch[Number(batchMatch[1])]!;
    const friMatch = /^fri-fold-query:(\d+)$/.exec(roleId);
    if (friMatch !== null) return fri[Number(friMatch[1])]!;
    return trivial;
  };
  return V17_PROFILES.map((profile): V17PreLinkProgramProfile => ({
    baselinePhase: "pre-link-program-census",
    qualification: "non-executable-non-measurement",
    profile,
    baselineInputCount: plan.roles.length,
    baselineOutputCount: plan.roles.length,
    programCensusSha256Hex: (profile + 91).toString(16).padStart(2, "0").repeat(32),
    workers: plan.roles.map((role, logicalInputIndex) => {
      const redeemBytecode = verifierFor(role.id);
      return {
        profile,
        logicalInputIndex,
        roleId: role.id,
        redeemBytecode,
        unlockingPrefixBytecode: role.id === LOCAL_WORD_BATCH_LEADER_ROLE_ID
          ? leaderPrefix
          : ordinaryPrefix,
        proofCarrierBytes: proofBytes,
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

describe("v17 query-parameterized algebra outer kernels", () => {
  it("rejects forged runtime ordinals before any proof read", () => {
    const batchBody = outerBody(
      compileLocalWordFriBatchGate({ profile: 0, query: 1 }),
      "22",
    );
    const friBody = outerBody(
      compileV17LocalWordFriFoldGate({ profile: 0, query: 0 }),
      "23",
    );
    const vm = createVirtualMachineBch2026(false);
    for (const [label, body, id, query] of [
      ["batch zero", batchBody, 34, 0],
      ["batch upper", batchBody, 34, QUERIES],
      ["FRI negative", friBody, 35, -1],
      ["FRI upper", friBody, 35, QUERIES],
    ] as const) {
      const state = vm.evaluate(program(invokeOuterWith(body, id, query)) as never);
      assert.notEqual(vm.stateSuccess(state), true, label);
      assert.equal(state.alternateStack.length, 0, `${label} alternate stack`);
    }
    assert.throws(() => compileLocalWordFriBatchGate({ profile: 0, query: -1 }),
      /verifier key/);
    assert.throws(() => compileLocalWordFriBatchGate({ profile: 0, query: QUERIES }),
      /verifier key/);
    assert.throws(() => compileV17LocalWordFriFoldGate({ profile: 0, query: -1 }),
      /verifier key/);
    assert.throws(() => compileV17LocalWordFriFoldGate({ profile: 0, query: QUERIES }),
      /verifier key/);
  });

  it("links only each shared initializer and retains the local orchestrator literally", () => {
    const preview = previewV17Rom({ profiles: previewProfiles() });
    const plan = preview.verifierPlan;
    const batchGates = [1, 17].map((query) =>
      compileLocalWordFriBatchGate({ profile: 0, query }));
    const friGates = [0, 17].map((query) =>
      compileV17LocalWordFriFoldGate({ profile: 0, query }));
    const batchTopLevel = censusV17OpDefineBodies(batchGates[0]!)
      .filter(({ depth }) => depth === 0);
    const friTopLevel = censusV17OpDefineBodies(friGates[0]!)
      .filter(({ depth }) => depth === 0);
    assert.deepEqual(batchTopLevel.map(({ functionIdHex }) => functionIdHex), ["1d", "22"]);
    assert.deepEqual(friTopLevel.map(({ functionIdHex }) => functionIdHex), ["1e", "23"]);
    const [batchShared, batchLocal] = batchTopLevel;
    const [friShared, friLocal] = friTopLevel;
    assert.equal(batchShared!.body.length, 2_235);
    assert.equal(batchLocal!.body.length, 2_547);
    assert.equal(friShared!.body.length, 2_619);
    assert.equal(friLocal!.body.length, 4_107);
    assert.ok(preview.certificate.census.promotedBodySha256Hexes
      .includes(batchShared!.bodySha256Hex));
    assert.ok(preview.certificate.census.promotedBodySha256Hexes
      .includes(friShared!.bodySha256Hex));
    assert.ok(!preview.certificate.census.promotedBodySha256Hexes
      .includes(batchLocal!.bodySha256Hex));
    assert.ok(!preview.certificate.census.promotedBodySha256Hexes
      .includes(friLocal!.bodySha256Hex));
    assert.equal(preview.certificate.census.promotedBodySha256Hexes.length, 2);

    const batchPolicies = v17DefinePoliciesForRole({
      roleId: "batch-link-query:1", redeemBytecode: batchGates[0]!,
    });
    const friPolicies = v17DefinePoliciesForRole({
      roleId: "fri-fold-query:0", redeemBytecode: friGates[0]!,
    });
    assert.ok(batchPolicies.filter(({ path }) => path === "0" || path.startsWith("0/"))
      .every(({ classification }) => classification === "construction-independent"));
    assert.equal(batchPolicies.find(({ path }) => path === "1")?.classification,
      "construction-independent-execution-local");
    assert.ok(batchPolicies.filter(({ path }) => path.startsWith("1/"))
      .every(({ classification }) => classification === "construction-independent"));
    assert.ok(friPolicies.filter(({ path }) => path === "0" || path.startsWith("0/"))
      .every(({ classification }) => classification === "construction-independent"));
    assert.equal(friPolicies.find(({ path }) => path === "1")?.classification,
      "construction-independent-execution-local");
    assert.ok(friPolicies.filter(({ path }) => path.startsWith("1/"))
      .every(({ classification }) => classification === "construction-independent"));

    const linkedBytes: number[] = [];
    for (const profile of V17_PROFILES) {
      for (const [index, role] of plan.roles.entries()) {
        const affected = /^batch-link-query:(?!0$)\d+$/.test(role.id) ||
          /^fri-fold-query:\d+$/.test(role.id);
        if (!affected) continue;
        const linked = preview.linkedRedeemsByProfile[profile]![index]!;
        linkedBytes.push(linked.length);
        const local = role.id.startsWith("batch-link-query:") ? batchLocal! : friLocal!;
        assert.ok(includesBytes(linked, local.body), `${profile}:${role.id}:local wrapper literal`);
        assert.ok(linked.length < 10_000, `${profile}:${role.id}:linked bytes`);
        const reads = decodeAuthenticationInstructions(linked)
          .filter(({ opcode }) => opcode === OpcodesBch.OP_INPUTBYTECODE);
        assert.equal(reads.length, 1, `${profile}:${role.id}`);
      }
    }
    console.log("v17-algebra-outer-kernel-link", JSON.stringify({
      promotedOuterBodies: 2,
      romPages: preview.pages.length,
      batchSharedBodyBytes: batchShared!.body.length,
      batchLocalBodyBytes: batchLocal!.body.length,
      friSharedBodyBytes: friShared!.body.length,
      friLocalBodyBytes: friLocal!.body.length,
      rawGateBytes: {
        batch: batchGates.map(({ length }) => length),
        fri: friGates.map(({ length }) => length),
      },
      linkedGateBytes: { minimum: Math.min(...linkedBytes), maximum: Math.max(...linkedBytes) },
      linkedRoles: linkedBytes.length,
    }));
  });
});

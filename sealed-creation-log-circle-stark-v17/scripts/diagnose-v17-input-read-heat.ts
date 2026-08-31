import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { basename, resolve } from "node:path";
import {
  cashAssemblyToBin,
  createVirtualMachine,
} from "@bitauth/libauth";
import { verifyLocalWordSealedProofBytes } from
  "../src/backends/circle/local-word-verifier.ts";
import { V17_PROOF_PROTOCOL_ID } from
  "../src/backends/circle/v17-proof-layout.ts";
import { createV17LibauthBchnOpDefineDiagnosticInstructionSet } from
  "../src/assurance/v17-libauth-opdefine-diagnostic.ts";
import { materializeV17PostLinkCandidateEnvelopes } from
  "../src/assurance/v17-post-link-bchn-measurement.ts";
import { V17_BOOTSTRAP_AFFINE_ALLOCATION } from
  "../src/chain/v17-affine-allocation.ts";
import { buildV17LabProductFixture } from
  "../src/construction/v17-lab-product-fixtures.ts";
import {
  materializeV17PostLinkCandidates,
  previewV17ProductRom,
  type V17ProfileProofMaterial,
} from "../src/construction/v17-product-link.ts";
import {
  V17_PROFILES,
  v17ProtocolIdHex,
} from "../src/construction/v17-graph.ts";

type Marker = {
  readonly schema: string;
  readonly status: string;
  readonly proofSource: string;
  readonly protocolIdHex: string;
};

const checkpointArgument = process.argv[2];
if (checkpointArgument === undefined) {
  throw new Error("usage: npm run diagnose:read-heat -- .local/v17-fresh-diagnostic-...");
}
const checkpoint = resolve(process.cwd(), checkpointArgument);
if (!basename(checkpoint).startsWith("v17-fresh-diagnostic-")) {
  throw new Error("v17 read heat requires an explicit diagnostic checkpoint");
}
const marker = JSON.parse(readFileSync(resolve(checkpoint, "NOT-QUALIFIED.json"), "utf8")) as
  Marker;
assert.deepEqual(marker, {
  schema: "ShieldKit/V17FreshDiagnosticCheckpoint/v1",
  status: "partial-diagnostic-only-not-qualification-evidence",
  proofSource: "fresh-current-process-no-cache",
  protocolIdHex: v17ProtocolIdHex(),
});

const fixtures = V17_PROFILES.map((profile) => buildV17LabProductFixture(profile));
const proofs = V17_PROFILES.map((profile): V17ProfileProofMaterial => {
  const fixture = fixtures[profile]!;
  const proofBytes = new Uint8Array(readFileSync(resolve(checkpoint, `profile-${profile}.proof`)));
  const verified = verifyLocalWordSealedProofBytes(proofBytes, {
    profile,
    transcriptInitial: fixture.transcriptInitial,
    constructionDescriptor: fixture.constructionDescriptor,
    publicWords: fixture.publicWords,
    expectedPreprocessedRoot: fixture.expectedPreprocessedRoot,
  });
  if (!verified.ok) throw new Error(`v17 read heat proof ${profile}: ${verified.reason}`);
  return {
    profile,
    proofBytes,
    constructionId: V17_PROOF_PROTOCOL_ID,
    constructionDigest: fixture.constructionDigest,
    expectedPreprocessedRoot: fixture.expectedPreprocessedRoot,
  };
}) as unknown as readonly [
  V17ProfileProofMaterial,
  V17ProfileProofMaterial,
  V17ProfileProofMaterial,
];

const link = previewV17ProductRom(proofs);
const candidates = materializeV17PostLinkCandidates({
  link,
  proofs,
  allocation: V17_BOOTSTRAP_AFFINE_ALLOCATION,
});
const envelopes = materializeV17PostLinkCandidateEnvelopes({
  candidates,
  fixtures: fixtures.map(({ settlementFixture }) => settlementFixture),
});
const encodedOpcode = cashAssemblyToBin("OP_INPUTBYTECODE");
if (typeof encodedOpcode === "string" || encodedOpcode.length !== 1) {
  throw new Error("v17 read heat opcode");
}
const inputBytecodeOpcode = encodedOpcode[0]!;
const requestedProfileArgument = process.argv.find((value) => value.startsWith("--profile="));
const summaryOnly = process.argv.includes("--summary");
const requestedProfile = requestedProfileArgument === undefined
  ? undefined
  : Number(requestedProfileArgument.slice("--profile=".length));
if (requestedProfile !== undefined && !V17_PROFILES.includes(requestedProfile as 0 | 1 | 2)) {
  throw new Error(`v17 read heat profile ${requestedProfileArgument}`);
}

const report = envelopes.filter((envelope) => requestedProfile === undefined ||
  envelope.profile === requestedProfile).map((envelope) => {
  const reads = envelope.materialized.transaction.inputs.map((input, targetInput) => ({
    targetInput,
    targetRoleId: envelope.candidate.roles[targetInput]?.name ??
      `rom-page:${targetInput - envelope.candidate.roles.length}`,
    unlockingBytes: input.unlockingBytecode.length,
    calls: 0,
    operationCost: 0,
    callers: new Map<string, number>(),
  }));
  for (const caller of envelope.candidate.roles) {
    const instructionSet = createV17LibauthBchnOpDefineDiagnosticInstructionSet(false);
    const every = instructionSet.every!;
    const vm = createVirtualMachine({
      ...instructionSet,
      every: (state) => {
        state.metrics.maximumOperationCost = 1_000_000_000;
        const instruction = state.instructions[state.ip];
        if (instruction?.opcode !== inputBytecodeOpcode ||
          state.controlStack.some((active) => !active)) return every(state);
        const before = Number(state.metrics.operationCost);
        const next = every(state);
        const pushed = next.stack.at(-1);
        if (pushed === undefined) throw new Error("v17 read heat missing result");
        const target = envelope.materialized.transaction.inputs.findIndex(({ unlockingBytecode }) =>
          unlockingBytecode.length === pushed.length && unlockingBytecode.every((byte, index) =>
            byte === pushed[index]));
        const row = reads[target];
        if (row === undefined) throw new Error(`v17 read heat target ${target}`);
        row.calls += 1;
        row.operationCost += Number(next.metrics.operationCost) - before;
        row.callers.set(caller.name, (row.callers.get(caller.name) ?? 0) + 1);
        return next;
      },
    });
    const state = vm.evaluate({
      inputIndex: caller.index,
      sourceOutputs: envelope.materialized.sourceOutputs,
      transaction: envelope.materialized.transaction,
    } as never);
    if (vm.stateSuccess(state) !== true) {
      throw new Error(`v17 read heat execution ${envelope.profile}:${caller.name}: ${String(state.error)}`);
    }
  }
  return {
    profile: envelope.profile,
    proofBytes: envelope.candidate.proofBytes.length,
    transactionBytes: envelope.materialized.rawTransactionBytes.length,
    reads: reads.filter(({ calls }) => calls > 0).map((row) => ({
      targetInput: row.targetInput,
      targetRoleId: row.targetRoleId,
      unlockingBytes: row.unlockingBytes,
      calls: row.calls,
      copiedUnlockingBytes: row.calls * row.unlockingBytes,
      operationCost: row.operationCost,
      callers: [...row.callers].sort((left, right) => right[1] - left[1] ||
        left[0].localeCompare(right[0])),
    })).sort((left, right) => right.copiedUnlockingBytes - left.copiedUnlockingBytes ||
      left.targetInput - right.targetInput).slice(0, summaryOnly ? 40 : undefined).map((row) =>
      summaryOnly ? { ...row, callers: row.callers.slice(0, 8) } : row),
  };
});

console.log(JSON.stringify({
  schema: "ShieldKit/V17InputReadHeatDiagnostic/v1",
  status: "diagnostic-only-not-qualification-evidence",
  checkpoint: basename(checkpoint),
  allocation: "bootstrap",
  profiles: report,
}, null, 2));

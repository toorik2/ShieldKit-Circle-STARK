import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { dirname, resolve } from "node:path";
import {
  decodeTransaction,
  encodeTransaction,
} from "@bitauth/libauth";
import {
  verifyLocalWordSealedProofBytes,
} from "../src/backends/circle/local-word-verifier.ts";
import {
  LOCAL_WORD_PROOF_VERSION,
  localWordProofStaticOffsets,
} from "../src/backends/circle/local-word-sealed-proof.ts";
import {
  analyzeLocalWordObserverTransaction,
  extractLocalWordProofFromTransaction,
} from "../src/backends/circle/local-word-observer-view.ts";
import {
  V17_PROOF_PROTOCOL_ID,
} from "../src/backends/circle/v17-proof-layout.ts";
import {
  V17_BOOTSTRAP_AFFINE_ALLOCATION,
  type V17AffineAllocation,
} from "../src/chain/v17-affine-allocation.ts";
import {
  assertV17BchnProductGateResult,
  assertV17BchnProductEvidence,
  qualifyV17BchnProductWithTrace,
  type V17BchnProductArtifact,
} from "../src/assurance/v17-bchn-product-gate.ts";
import {
  assertV17FinalInfrastructureIdentity,
  replayV17FinalInfrastructureIdentity,
} from "../src/assurance/v17-final-infrastructure-identity.ts";
import {
  materializeV17PostLinkCandidateEnvelopes,
  measureV17PostLinkCandidatesWithBchn,
  type V17BchnPostLinkEvidence,
} from "../src/assurance/v17-post-link-bchn-measurement.ts";
import {
  deriveV17LocalSizingAllocation,
  type V17LocalSizingAllocation,
} from "../src/assurance/v17-local-sizing-allocation.ts";
import {
  assertV17RuntimeProductTheoremEvidence,
  certifyV17RuntimeProductTheorem,
  type V17ReferenceAdversarialRejection,
} from "../src/assurance/v17-runtime-product-theorem.ts";
import {
  V17_PROFILES,
  canonicalV17Json,
  v17ProtocolIdHex,
  type V17Profile,
} from "../src/construction/v17-graph.ts";
import {
  createV17DensityClosureTrace,
  replayV17DensityClosureTrace,
  type V17DensityClosureTrace,
} from "../src/construction/v17-density-closure.ts";
import {
  assertV17VerifierPlanSchemaConsistency,
} from "../src/construction/v17-artifacts.ts";
import {
  assertV17NormativeSpecFiles,
} from "../src/construction/v17-spec-identity.ts";
import {
  buildV17LabProductFixture,
} from "../src/construction/v17-lab-product-fixtures.ts";
import {
  assessV17AllocationIteration,
  assessV17FinalAllocationStability,
  certifyV17ProductLink,
  materializeV17FinalInfrastructure,
  materializeV17PostLinkCandidates,
  previewV17ProductRom,
  type V17AllocationIteration,
  type V17FinalInfrastructureSet,
  type V17ProfileProofMaterial,
} from "../src/construction/v17-product-link.ts";
import {
  materializeV17SettlementTransaction,
  writeV17SettlementTransactionFiles,
  type V17SettlementTransaction,
} from "../src/construction/v17-settlement-transaction.ts";

type WorkerProof = {
  readonly ok: boolean;
  readonly profile: number;
  readonly proofHex: string;
  readonly proofBytes: number;
  readonly constructionDigestHex: string;
  readonly protocolIdHex: string;
  readonly proofVersion?: number;
  readonly expectedPreprocessedRootHex: string;
  readonly publicWords: number;
  readonly quotientDegreeBound: number;
};

type BuiltFixture = ReturnType<typeof buildV17LabProductFixture>;

const laneRoot = process.cwd();
const artifactRoot = resolve(laneRoot, ".local/v17-qualification");
const assayExecutablePath = resolve(
  process.env.V17_BCHN_ASSAY ??
    ".local/bchn-v29-assay/build/bin/v17-bchn-v29-assay",
);
const workerManifest = "crates/circle-fri-worker/Cargo.toml";
const workerTemporaryRoot = resolve(laneRoot, ".local/v17-prover-tmp");
const diagnosticCheckpointFlag = process.argv.indexOf("--diagnostic-checkpoint");
const diagnosticCheckpointSource = diagnosticCheckpointFlag < 0
  ? null
  : process.argv[diagnosticCheckpointFlag + 1];
if (diagnosticCheckpointFlag >= 0 &&
  (typeof diagnosticCheckpointSource !== "string" || diagnosticCheckpointSource.startsWith("--") ||
    process.argv.indexOf("--diagnostic-checkpoint", diagnosticCheckpointFlag + 1) >= 0 ||
    process.argv.includes("--dry-run"))) {
  throw new Error("v17 diagnostic checkpoint usage");
}

function progress(stage: string, detail: Record<string, unknown> = {}): void {
  console.error("v17-qualification-progress", JSON.stringify({ stage, ...detail }));
}

function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function equal(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((byte, index) => byte === right[index]);
}

function json(value: unknown): string {
  return `${JSON.stringify(value, (_key, item) => {
    if (typeof item === "bigint") return item.toString();
    if (item instanceof Uint8Array) return Buffer.from(item).toString("hex");
    return item;
  }, 2)}\n`;
}

function atomicWrite(path: string, bytes: Uint8Array | string): void {
  mkdirSync(dirname(path), { recursive: true });
  const temporary = `${path}.tmp`;
  writeFileSync(temporary, bytes, { mode: 0o600 });
  renameSync(temporary, path);
}

function runWorker(request: unknown): unknown {
  // A production proof's disk-backed LDE exceeds the machine's tmpfs quota.
  // Keep ephemeral prover files on the lane filesystem; the Rust worker owns
  // and removes its uniquely named child directory on both success and error.
  mkdirSync(workerTemporaryRoot, { recursive: true });
  const execution = spawnSync(
    "cargo",
    [
      "+nightly-2026-01-15",
      "run",
      "--release",
      "--quiet",
      "--manifest-path",
      workerManifest,
    ],
    {
      cwd: laneRoot,
      input: JSON.stringify(request),
      encoding: "utf8",
      maxBuffer: 64 * 1024 * 1024,
      env: { ...process.env, TMPDIR: workerTemporaryRoot },
    },
  );
  if (execution.error !== undefined || execution.status !== 0) {
    throw new Error([
      execution.error?.message,
      execution.stderr,
      execution.stdout,
    ].filter((value) => value !== undefined && value.length > 0).join("\n"));
  }
  return JSON.parse(execution.stdout.trim()) as unknown;
}

function preflightFixture(fixture: BuiltFixture): void {
  const checked = runWorker({
    cmd: "local-word-bundle-kat",
    bundleHex: Buffer.from(fixture.bundle).toString("hex"),
  }) as {
    readonly ok: boolean;
    readonly interactionPreflight: boolean;
    readonly activeWordSlots: number;
    readonly descriptorDigest: string;
  };
  if (checked.ok !== true || checked.interactionPreflight !== true ||
    !Number.isSafeInteger(checked.activeWordSlots) || checked.activeWordSlots < 1 ||
    checked.descriptorDigest !== Buffer.from(fixture.constructionDigest).toString("hex")) {
    throw new Error(`v17 qualification bundle preflight ${fixture.profile}`);
  }
}

function proveFixture(fixture: BuiltFixture): V17ProfileProofMaterial & {
  readonly quotientDegreeBound: number;
} {
  const proved = runWorker({
    cmd: "local-word-prove",
    bundleHex: Buffer.from(fixture.bundle).toString("hex"),
  }) as WorkerProof;
  const constructionDigestHex = Buffer.from(fixture.constructionDigest).toString("hex");
  const expectedRootHex = Buffer.from(fixture.expectedPreprocessedRoot).toString("hex");
  const proofBytes = Uint8Array.from(Buffer.from(proved.proofHex, "hex"));
  const checks = {
    ok: proved.ok === true,
    profile: proved.profile === fixture.profile,
    publicWords: proved.publicWords === 8,
    proofLength: proved.proofBytes === proofBytes.length,
    constructionDigest: proved.constructionDigestHex === constructionDigestHex,
    preprocessedRoot: proved.expectedPreprocessedRootHex === expectedRootHex,
    reportedProtocol: proved.protocolIdHex === v17ProtocolIdHex(),
    reportedVersion: proved.proofVersion === undefined ||
      proved.proofVersion === LOCAL_WORD_PROOF_VERSION,
    encodedVersion: proofBytes[4] === LOCAL_WORD_PROOF_VERSION,
    encodedProfile: proofBytes[5] === fixture.profile,
    encodedProtocol: equal(proofBytes.subarray(6, 38), V17_PROOF_PROTOCOL_ID),
  };
  if (Object.values(checks).some((passed) => !passed)) {
    throw new Error(`v17 qualification proof worker contract ${fixture.profile}: ${
      JSON.stringify({
        checks,
        reported: {
          profile: proved.profile,
          publicWords: proved.publicWords,
          proofBytes: proved.proofBytes,
          decodedProofBytes: proofBytes.length,
          constructionDigestHex: proved.constructionDigestHex,
          expectedPreprocessedRootHex: proved.expectedPreprocessedRootHex,
          protocolIdHex: proved.protocolIdHex,
          proofVersion: proved.proofVersion,
          encodedVersion: proofBytes[4],
          encodedProfile: proofBytes[5],
          encodedProtocolHex: Buffer.from(proofBytes.subarray(6, 38)).toString("hex"),
        },
        expected: {
          profile: fixture.profile,
          constructionDigestHex,
          expectedRootHex,
          protocolIdHex: v17ProtocolIdHex(),
          proofVersion: LOCAL_WORD_PROOF_VERSION,
        },
      })}`);
  }
  const reference = verifyLocalWordSealedProofBytes(proofBytes, {
    profile: fixture.profile,
    transcriptInitial: fixture.transcriptInitial,
    constructionDescriptor: fixture.constructionDescriptor,
    publicWords: fixture.publicWords,
    expectedPreprocessedRoot: fixture.expectedPreprocessedRoot,
  });
  if (!reference.ok) {
    throw new Error(`v17 qualification reference proof ${fixture.profile}: ${reference.reason}`);
  }
  return {
    profile: fixture.profile,
    proofBytes,
    constructionId: V17_PROOF_PROTOCOL_ID,
    constructionDigest: fixture.constructionDigest,
    expectedPreprocessedRoot: fixture.expectedPreprocessedRoot,
    quotientDegreeBound: proved.quotientDegreeBound,
  };
}

function allocationGeometry(allocation: V17AffineAllocation): unknown {
  return {
    status: allocation.status,
    minimumProofBytes: allocation.minimumProofBytes,
    maximumProofBytes: allocation.maximumProofBytes,
    elasticScaleUnits: allocation.elasticScaleUnits,
    assignments: allocation.assignments,
  };
}

function exactCandidateEqualsFinal(
  candidates: ReturnType<typeof materializeV17PostLinkCandidates>,
  fixtures: readonly BuiltFixture[],
  finalTransactions: readonly V17SettlementTransaction[],
): void {
  const firstDifference = (left: Uint8Array, right: Uint8Array): number => {
    const shared = Math.min(left.length, right.length);
    for (let index = 0; index < shared; index += 1) {
      if (left[index] !== right[index]) return index;
    }
    return left.length === right.length ? -1 : shared;
  };
  const candidateEnvelopes = materializeV17PostLinkCandidateEnvelopes({
    candidates,
    fixtures: fixtures.map(({ settlementFixture }) => settlementFixture),
  });
  candidateEnvelopes.forEach((envelope, profile) => {
    const final = finalTransactions[profile]!;
    if (!equal(envelope.materialized.rawTransactionBytes, final.rawTransactionBytes) ||
      !equal(
        envelope.materialized.encodedSourceOutputsBytes,
        final.encodedSourceOutputsBytes,
      )) {
      throw new Error(`v17 qualification candidate/final byte split ${profile}: ${
        JSON.stringify({
          transaction: {
            candidateBytes: envelope.materialized.rawTransactionBytes.length,
            finalBytes: final.rawTransactionBytes.length,
            firstDifference: firstDifference(
              envelope.materialized.rawTransactionBytes,
              final.rawTransactionBytes,
            ),
            candidateSha256Hex: sha256Hex(envelope.materialized.rawTransactionBytes),
            finalSha256Hex: sha256Hex(final.rawTransactionBytes),
          },
          sourceOutputs: {
            candidateBytes: envelope.materialized.encodedSourceOutputsBytes.length,
            finalBytes: final.encodedSourceOutputsBytes.length,
            firstDifference: firstDifference(
              envelope.materialized.encodedSourceOutputsBytes,
              final.encodedSourceOutputsBytes,
            ),
            candidateSha256Hex: sha256Hex(
              envelope.materialized.encodedSourceOutputsBytes,
            ),
            finalSha256Hex: sha256Hex(final.encodedSourceOutputsBytes),
          },
          differingInputs: envelope.materialized.transaction.inputs.flatMap(
            (candidateInput, inputIndex) => {
              const finalInput = final.transaction.inputs[inputIndex];
              if (finalInput !== undefined &&
                candidateInput.outpointIndex === finalInput.outpointIndex &&
                equal(candidateInput.outpointTransactionHash, finalInput.outpointTransactionHash) &&
                candidateInput.sequenceNumber === finalInput.sequenceNumber &&
                equal(candidateInput.unlockingBytecode, finalInput.unlockingBytecode)) return [];
              return [{
                inputIndex,
                candidateSequence: candidateInput.sequenceNumber,
                finalSequence: finalInput?.sequenceNumber,
                candidateUnlockingBytes: candidateInput.unlockingBytecode.length,
                finalUnlockingBytes: finalInput?.unlockingBytecode.length,
                candidateUnlockingSha256Hex: sha256Hex(candidateInput.unlockingBytecode),
                finalUnlockingSha256Hex: finalInput === undefined
                  ? null
                  : sha256Hex(finalInput.unlockingBytecode),
              }];
            },
          ),
          differingOutputs: envelope.materialized.transaction.outputs.flatMap(
            (candidateOutput, outputIndex) => {
              const finalOutput = final.transaction.outputs[outputIndex];
              if (finalOutput !== undefined &&
                candidateOutput.valueSatoshis === finalOutput.valueSatoshis &&
                equal(candidateOutput.lockingBytecode, finalOutput.lockingBytecode) &&
                (candidateOutput.token === undefined) === (finalOutput.token === undefined)) return [];
              return [{
                outputIndex,
                candidateValueSatoshis: candidateOutput.valueSatoshis.toString(),
                finalValueSatoshis: finalOutput?.valueSatoshis.toString(),
                candidateLockingSha256Hex: sha256Hex(candidateOutput.lockingBytecode),
                finalLockingSha256Hex: finalOutput === undefined
                  ? null
                  : sha256Hex(finalOutput.lockingBytecode),
                candidateHasToken: candidateOutput.token !== undefined,
                finalHasToken: finalOutput?.token !== undefined,
              }];
            },
          ),
        })}`);
    }
  });
}

type StableProduct = {
  readonly localSizing: V17LocalSizingAllocation;
  readonly allocationIteration: V17AllocationIteration;
  readonly finalAllocation: ReturnType<typeof assessV17FinalAllocationStability>;
  readonly densityTrace: V17DensityClosureTrace;
  readonly postLinkEvidence: readonly [
    V17BchnPostLinkEvidence,
    V17BchnPostLinkEvidence,
    V17BchnPostLinkEvidence,
  ];
  readonly infrastructure: V17FinalInfrastructureSet;
  readonly transactions: readonly [
    V17SettlementTransaction,
    V17SettlementTransaction,
    V17SettlementTransaction,
  ];
};

function buildStableProduct(
  fixtures: readonly [BuiltFixture, BuiltFixture, BuiltFixture],
  proofs: readonly [V17ProfileProofMaterial, V17ProfileProofMaterial, V17ProfileProofMaterial],
): StableProduct {
  let allocation = V17_BOOTSTRAP_AFFINE_ALLOCATION;
  let densityTrace = createV17DensityClosureTrace();
  const visited = new Set<string>();
  let pass = 0;
  for (;;) {
    pass += 1;
    const traceHead = replayV17DensityClosureTrace(densityTrace);
    const geometry = canonicalV17Json({
      allocation: allocationGeometry(allocation),
      closureSha256Hex: traceHead.closure?.closureSha256Hex ?? null,
    });
    if (visited.has(geometry)) {
      throw new Error(`v17 qualification allocation cycle before fixed point at pass ${pass}`);
    }
    visited.add(geometry);
    progress("post-link-bchn-measurement", {
      pass,
      allocation: allocation.status,
      minimumProofBytes: allocation.minimumProofBytes,
    });
    // Allocation metadata is executable reader code. Recompile the complete
    // prelink census and ROM preview on every pass rather than reusing a link
    // built for a previous affine geometry.
    const link = previewV17ProductRom(proofs, allocation);
    const candidates = materializeV17PostLinkCandidates({ link, proofs, allocation });
    const localSizing = deriveV17LocalSizingAllocation({
      candidates,
      fixtures: fixtures.map(({ settlementFixture }) => settlementFixture),
      trace: densityTrace,
    });
    progress("post-link-local-sizing", {
      pass,
      status: localSizing.status,
      currentMinimumProofBytes: localSizing.currentAllocation.minimumProofBytes,
      measuredMinimumProofBytes: localSizing.measuredAllocation.minimumProofBytes,
    });
    if (localSizing.status !== "fixed-point") {
      densityTrace = localSizing.trace;
      allocation = localSizing.measuredAllocation;
      continue;
    }
    densityTrace = localSizing.trace;
    const evidence = measureV17PostLinkCandidatesWithBchn({
      candidates,
      fixtures: fixtures.map(({ settlementFixture }) => settlementFixture),
      assayExecutablePath,
    });
    const prePostLinkTrace = densityTrace;
    const iteration = assessV17AllocationIteration({
      candidates,
      evidence,
      trace: prePostLinkTrace,
    });
    densityTrace = iteration.trace;
    if (iteration.status !== "stable") {
      allocation = iteration.measuredAllocation;
      continue;
    }
    const construction = certifyV17ProductLink({
      candidates,
      evidence,
      trace: iteration.trace,
    });
    const infrastructure = materializeV17FinalInfrastructure({ construction, proofs });
    const identity = replayV17FinalInfrastructureIdentity(infrastructure);
    assertV17FinalInfrastructureIdentity(identity);
    const transactions = V17_PROFILES.map((profile) =>
      materializeV17SettlementTransaction({
        infrastructureSet: infrastructure,
        fixture: fixtures[profile]!.settlementFixture,
      })) as unknown as StableProduct["transactions"];
    exactCandidateEqualsFinal(candidates, fixtures, transactions);
    const finalAllocation = assessV17FinalAllocationStability({
      construction,
      // The candidate transaction and final transaction were just proven byte
      // identical, so these are measurements of the exact final worker bytes.
      finalProfiles: iteration.postLinkProfiles,
      trace: densityTrace,
    });
    if (finalAllocation.status !== "stable") {
      densityTrace = finalAllocation.trace;
      allocation = finalAllocation.finalMeasuredAllocation;
      continue;
    }
    return {
      localSizing,
      allocationIteration: iteration,
      finalAllocation,
      densityTrace: finalAllocation.trace,
      postLinkEvidence: evidence,
      infrastructure,
      transactions,
    };
  }
}

function referenceAdversarialAudit(
  fixture: BuiltFixture,
  proof: V17ProfileProofMaterial,
): readonly Omit<V17ReferenceAdversarialRejection, "profile">[] {
  const offsets = localWordProofStaticOffsets(fixture.publicWords.length);
  const context = {
    profile: fixture.profile,
    transcriptInitial: fixture.transcriptInitial,
    constructionDescriptor: fixture.constructionDescriptor,
    publicWords: fixture.publicWords,
    expectedPreprocessedRoot: fixture.expectedPreprocessedRoot,
  } as const;
  const cases: readonly {
    readonly mutation: V17ReferenceAdversarialRejection["mutation"];
    readonly proof: Uint8Array;
    readonly context: typeof context;
  }[] = [
    (() => {
      const changed = proof.proofBytes.slice();
      changed[offsets.matrixRoots] ^= 1;
      return { mutation: "matrix-root-byte", proof: changed, context };
    })(),
    (() => {
      const changed = proof.proofBytes.slice();
      changed[offsets.openingBodies] ^= 1;
      return { mutation: "opening-body-byte", proof: changed, context };
    })(),
    {
      mutation: "truncated-proof",
      proof: proof.proofBytes.slice(0, -1),
      context,
    },
    (() => {
      const transcriptInitial = fixture.transcriptInitial.slice();
      transcriptInitial[0] ^= 1;
      return {
        mutation: "false-public-transcript",
        proof: proof.proofBytes,
        context: { ...context, transcriptInitial },
      };
    })(),
  ];
  return cases.map((candidate) => {
    const result = verifyLocalWordSealedProofBytes(candidate.proof, candidate.context);
    if (result.ok) throw new Error(`v17 qualification adversarial acceptance ${candidate.mutation}`);
    return { mutation: candidate.mutation, rejected: true, reason: result.reason };
  });
}

function carrierAdversarialAudit(
  transaction: V17SettlementTransaction,
  allocation: V17AffineAllocation,
): { readonly swappedCarriersRejected: true; readonly reason: string } {
  const decoded = decodeTransaction(transaction.rawTransactionBytes);
  if (typeof decoded === "string") throw new Error(`v17 qualification decode: ${decoded}`);
  [decoded.inputs[1]!.unlockingBytecode, decoded.inputs[2]!.unlockingBytecode] = [
    decoded.inputs[2]!.unlockingBytecode,
    decoded.inputs[1]!.unlockingBytecode,
  ];
  let reason = "";
  try {
    extractLocalWordProofFromTransaction(encodeTransaction(decoded), allocation);
  } catch (error) {
    reason = String(error);
  }
  if (reason.length === 0) throw new Error("v17 qualification swapped carrier accepted");
  return { swappedCarriersRejected: true, reason };
}

function writeGateArtifacts(
  stable: StableProduct,
  directory: string,
): readonly [V17BchnProductArtifact, V17BchnProductArtifact, V17BchnProductArtifact] {
  mkdirSync(directory, { recursive: true });
  const artifacts = V17_PROFILES.map((profile): V17BchnProductArtifact => {
    const transactionPath = resolve(directory, `profile-${profile}.tx`);
    const sourceOutputsPath = resolve(directory, `profile-${profile}.source-outputs`);
    writeV17SettlementTransactionFiles(stable.transactions[profile]!, {
      transactionPath,
      sourceOutputsPath,
    });
    return { profile, transactionPath, sourceOutputsPath };
  }) as unknown as readonly [V17BchnProductArtifact, V17BchnProductArtifact, V17BchnProductArtifact];
  return artifacts;
}

function persistStableProduct(args: {
  readonly proofs: readonly [V17ProfileProofMaterial, V17ProfileProofMaterial, V17ProfileProofMaterial];
  readonly stable: StableProduct;
}): void {
  mkdirSync(artifactRoot, { recursive: true });
  V17_PROFILES.forEach((profile) => {
    atomicWrite(resolve(artifactRoot, `profile-${profile}.proof`),
      args.proofs[profile]!.proofBytes);
    atomicWrite(resolve(artifactRoot, `profile-${profile}.tx`),
      args.stable.transactions[profile]!.rawTransactionBytes);
    atomicWrite(resolve(artifactRoot, `profile-${profile}.source-outputs`),
      args.stable.transactions[profile]!.encodedSourceOutputsBytes);
  });
  atomicWrite(
    resolve(artifactRoot, "linker-certificate.json"),
    json(args.stable.infrastructure.construction.certificate),
  );
  atomicWrite(
    resolve(artifactRoot, "post-link-bchn-evidence.json"),
    json(args.stable.postLinkEvidence),
  );
  atomicWrite(
    resolve(artifactRoot, "local-sizing-certificate.json"),
    json(args.stable.localSizing),
  );
}

const normativeSpecReceipt = assertV17NormativeSpecFiles({ laneRoot });
progress("normative-spec-identity-passed", {
  documents: normativeSpecReceipt.documents.map(({ id, actualSha256Hex }) => ({
    id,
    sha256Hex: actualSha256Hex,
  })),
});
assertV17VerifierPlanSchemaConsistency();
progress("verifier-plan-schema-passed");

const fixtures = V17_PROFILES.map(buildV17LabProductFixture) as unknown as readonly [
  BuiltFixture,
  BuiltFixture,
  BuiltFixture,
];

progress("bundle-preflight-start", { profiles: V17_PROFILES });
fixtures.forEach((fixture) => {
  preflightFixture(fixture);
  progress("bundle-preflight-passed", { profile: fixture.profile });
});
if (process.argv.includes("--dry-run")) {
  console.log("v17-product-preflight", JSON.stringify({
    status: "passed",
    profiles: fixtures.map((fixture) => ({
      profile: fixture.profile,
      bundleBytes: fixture.bundle.length,
      constructionDigestHex: Buffer.from(fixture.constructionDigest).toString("hex"),
    })),
  }));
  process.exit(0);
}

// A downstream sizing failure must not force another expensive proof merely to
// reproduce that failure. A checkpoint can be replayed only through the
// explicitly diagnostic path below, which exits before theorem certification
// or qualification artifacts. The production path always proves afresh.
mkdirSync(resolve(laneRoot, ".local"), { recursive: true });
const diagnosticOnly = diagnosticCheckpointSource !== null;
const diagnosticCheckpointRoot = diagnosticOnly
  ? resolve(diagnosticCheckpointSource!)
  : mkdtempSync(resolve(laneRoot, ".local/v17-fresh-diagnostic-"));
const proved = [] as Array<V17ProfileProofMaterial & { readonly quotientDegreeBound: number }>;
if (diagnosticOnly) {
  const marker = JSON.parse(readFileSync(
    resolve(diagnosticCheckpointRoot, "NOT-QUALIFIED.json"),
    "utf8",
  )) as Record<string, unknown>;
  if (marker.schema !== "ShieldKit/V17FreshDiagnosticCheckpoint/v1" ||
    marker.status !== "partial-diagnostic-only-not-qualification-evidence" ||
    marker.proofSource !== "fresh-current-process-no-cache" ||
    marker.protocolIdHex !== v17ProtocolIdHex()) {
    throw new Error("v17 diagnostic checkpoint identity");
  }
  for (const fixture of fixtures) {
    const proofBytes = new Uint8Array(readFileSync(
      resolve(diagnosticCheckpointRoot, `profile-${fixture.profile}.proof`),
    ));
    const reference = verifyLocalWordSealedProofBytes(proofBytes, {
      profile: fixture.profile,
      transcriptInitial: fixture.transcriptInitial,
      constructionDescriptor: fixture.constructionDescriptor,
      publicWords: fixture.publicWords,
      expectedPreprocessedRoot: fixture.expectedPreprocessedRoot,
    });
    if (!reference.ok || proofBytes[4] !== LOCAL_WORD_PROOF_VERSION ||
      proofBytes[5] !== fixture.profile ||
      !equal(proofBytes.subarray(6, 38), V17_PROOF_PROTOCOL_ID)) {
      throw new Error(`v17 diagnostic checkpoint proof ${fixture.profile}`);
    }
    proved.push({
      profile: fixture.profile,
      proofBytes,
      constructionId: V17_PROOF_PROTOCOL_ID,
      constructionDigest: fixture.constructionDigest,
      expectedPreprocessedRoot: fixture.expectedPreprocessedRoot,
      // Diagnostic replay exits before the runtime theorem consumes this field.
      quotientDegreeBound: 0,
    });
    progress("diagnostic-proof-loaded", {
      profile: fixture.profile,
      proofBytes: proofBytes.length,
      proofSha256Hex: sha256Hex(proofBytes),
    });
  }
} else {
  atomicWrite(resolve(diagnosticCheckpointRoot, "NOT-QUALIFIED.json"), json({
    schema: "ShieldKit/V17FreshDiagnosticCheckpoint/v1",
    status: "partial-diagnostic-only-not-qualification-evidence",
    proofSource: "fresh-current-process-no-cache",
    protocolIdHex: v17ProtocolIdHex(),
  }));
  for (const fixture of fixtures) {
    progress("fresh-proof-start", { profile: fixture.profile });
    const proof = proveFixture(fixture);
    proved.push(proof);
    atomicWrite(
      resolve(diagnosticCheckpointRoot, `profile-${fixture.profile}.proof`),
      proof.proofBytes,
    );
    progress("fresh-proof-passed", {
      profile: fixture.profile,
      proofBytes: proof.proofBytes.length,
      proofSha256Hex: sha256Hex(proof.proofBytes),
    });
  }
}
const proofs = proved as unknown as readonly [
  V17ProfileProofMaterial,
  V17ProfileProofMaterial,
  V17ProfileProofMaterial,
];

const referenceAudit = V17_PROFILES.map((profile) => ({
  profile,
  cases: referenceAdversarialAudit(fixtures[profile]!, proofs[profile]!),
}));
progress("fresh-reference-and-adversarial-audit-passed", {
  profiles: referenceAudit.length,
  mutations: referenceAudit.reduce((sum, profile) => sum + profile.cases.length, 0),
});

const stable = buildStableProduct(fixtures, proofs);
const identity = replayV17FinalInfrastructureIdentity(stable.infrastructure);
assertV17FinalInfrastructureIdentity(identity);
mkdirSync(resolve(laneRoot, ".local"), { recursive: true });
const gateDirectory = mkdtempSync(resolve(laneRoot, ".local/v17-gate-stage-"));
const bchnResult = (() => {
  try {
    const artifacts = writeGateArtifacts(stable, gateDirectory);
    progress("final-bchn-product-gate", {
      inputs: stable.transactions.map((transaction) => transaction.transaction.inputs.length),
    });
    return qualifyV17BchnProductWithTrace({
      assayExecutablePath,
      artifacts,
      canonicalProduct: {
        proofs,
        allocation: stable.allocationIteration.measuredAllocation,
        postLinkEvidence: stable.postLinkEvidence,
        densityTrace: stable.allocationIteration.trace,
      },
    });
  } finally {
    rmSync(gateDirectory, { recursive: true, force: true });
  }
})();
assertV17BchnProductGateResult(bchnResult);
const bchn = bchnResult.evidence;
const finalDensityTrace = bchnResult.finalDensityTrace;
const finalDensityHead = replayV17DensityClosureTrace(finalDensityTrace);
assertV17BchnProductEvidence(bchn);
assert.equal(finalDensityHead.traceRootSha256Hex, bchn.finalDensityTraceRootSha256Hex);
assert.match(bchn.finalDensityTraceRootSha256Hex, /^[0-9a-f]{64}$/);
assert.match(bchn.finalDensityRowsSha256Hex, /^[0-9a-f]{64}$/);

const observers = V17_PROFILES.map((profile) => {
  const fixture = fixtures[profile]!;
  const allocation = stable.infrastructure.profiles[profile]!.allocation;
  const observer = analyzeLocalWordObserverTransaction(
    stable.transactions[profile]!.rawTransactionBytes,
    {
      profile,
      transcriptInitial: fixture.transcriptInitial,
      constructionDescriptor: fixture.constructionDescriptor,
      publicWords: fixture.publicWords,
      expectedPreprocessedRoot: fixture.expectedPreprocessedRoot,
    },
    allocation,
  );
  assert.equal(observer.carrierUnionExact, true);
  assert.equal(observer.protectedTraceRecovery.recovered, false);
  return observer;
});
const carrierAudit = V17_PROFILES.map((profile) => ({
  profile,
  ...carrierAdversarialAudit(
    stable.transactions[profile]!,
    stable.infrastructure.profiles[profile]!.allocation,
  ),
}));

if (diagnosticOnly) {
  console.log("v17-product-diagnostic", JSON.stringify({
    status: "passed-diagnostic-only-not-qualification-evidence",
    protocolIdHex: v17ProtocolIdHex(),
    constructionIdHex: identity.constructionIdHex,
    proofBytes: proofs.map(({ proofBytes }) => proofBytes.length),
    minimumProofBytes: stable.allocationIteration.measuredAllocation.minimumProofBytes,
    transactionBytes: stable.transactions.map(({ rawTransactionBytes }) =>
      rawTransactionBytes.length),
    finalDensityTraceRootSha256Hex: bchn.finalDensityTraceRootSha256Hex,
    finalDensityRowsSha256Hex: bchn.finalDensityRowsSha256Hex,
  }));
  process.exit(0);
}

const runtimeTheorem = certifyV17RuntimeProductTheorem({
  proofs,
  contexts: V17_PROFILES.map((profile) => ({
    profile,
    context: {
      profile,
      transcriptInitial: fixtures[profile]!.transcriptInitial,
      constructionDescriptor: fixtures[profile]!.constructionDescriptor,
      publicWords: fixtures[profile]!.publicWords,
      expectedPreprocessedRoot: fixtures[profile]!.expectedPreprocessedRoot,
    },
  })),
  attestations: V17_PROFILES.map((profile) => ({
    profile,
    source: "fresh-rust-worker-current-run-no-cache" as const,
    proofBytes: proofs[profile]!.proofBytes.length,
    proofSha256Hex: sha256Hex(proofs[profile]!.proofBytes),
    quotientDegreeBound: proved[profile]!.quotientDegreeBound,
  })),
  adversarialRejections: referenceAudit.flatMap(({ profile, cases }) =>
    cases.map((item) => ({ profile, ...item }))),
  observers: V17_PROFILES.map((profile) => ({ profile, observer: observers[profile]! })),
  bchnEvidence: bchn,
  finalIdentity: identity,
  linkerCertificate: stable.infrastructure.construction.certificate,
});
assertV17RuntimeProductTheoremEvidence(runtimeTheorem.evidence);

persistStableProduct({ proofs, stable });
atomicWrite(resolve(artifactRoot, "final-infrastructure-identity.json"), json(identity));
atomicWrite(resolve(artifactRoot, "bchn-product-evidence.json"), json(bchn));
atomicWrite(resolve(artifactRoot, "runtime-theorem-certificate.json"),
  json(runtimeTheorem.evidence));
const report = {
  schema: "ShieldKit/V17FreshProductQualification/v1",
  status: "offline-theorem-qualified-candidate",
  proofSource: "fresh-generated-no-cache",
  protocolIdHex: v17ProtocolIdHex(),
  constructionIdHex: identity.constructionIdHex,
  linkerCertificateIdHex: identity.linkerCertificateIdHex,
  finalInfrastructureIdentitySha256Hex: identity.identitySha256Hex,
  assayExecutablePath,
  assayExecutableSha256Hex: bchn.engine.executableSha256Hex,
  proofs: V17_PROFILES.map((profile) => ({
    profile,
    bytes: proofs[profile]!.proofBytes.length,
    sha256Hex: sha256Hex(proofs[profile]!.proofBytes),
    quotientDegreeBound: proved[profile]!.quotientDegreeBound,
  })),
  allocation: stable.allocationIteration.measuredAllocation,
  densityClosureSha256Hex: stable.finalAllocation.densityClosure.closureSha256Hex,
  densityTraceRootSha256Hex: bchn.finalDensityTraceRootSha256Hex,
  densityRowsSha256Hex: bchn.finalDensityRowsSha256Hex,
  localSizing: stable.localSizing,
  transactions: stable.transactions.map((transaction) => ({
    profile: transaction.profile,
    bytes: transaction.rawTransactionBytes.length,
    sha256Hex: transaction.transactionSha256Hex,
    inputs: transaction.transaction.inputs.length,
    outputs: transaction.transaction.outputs.length,
  })),
  bchnEvidenceSha256Hex: bchn.evidenceSha256Hex,
  runtimeTheoremEvidenceSha256Hex: runtimeTheorem.evidence.evidenceSha256Hex,
  observers,
  referenceAudit,
  carrierAudit,
  explicitExclusions: bchn.scope.excluded,
} as const;
assert.equal(report.densityTraceRootSha256Hex, finalDensityHead.traceRootSha256Hex);
atomicWrite(resolve(artifactRoot, "density-closure-trace.json"), json(finalDensityTrace));
atomicWrite(resolve(artifactRoot, "qualification-report.json"), json(report));
rmSync(diagnosticCheckpointRoot, { recursive: true, force: true });
console.log("v17-product-qualification", JSON.stringify({
  status: report.status,
  artifactRoot,
  protocolIdHex: report.protocolIdHex,
  constructionIdHex: report.constructionIdHex,
  proofBytes: report.proofs.map(({ bytes }) => bytes),
  transactionBytes: report.transactions.map(({ bytes }) => bytes),
  bchnEvidenceSha256Hex: report.bchnEvidenceSha256Hex,
  runtimeTheoremEvidenceSha256Hex: report.runtimeTheoremEvidenceSha256Hex,
}));

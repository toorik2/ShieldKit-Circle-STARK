import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  existsSync,
  lstatSync,
  readFileSync,
} from "node:fs";
import { basename, resolve } from "node:path";
import {
  LOCAL_WORD_V16_COMPONENTS,
  LOCAL_WORD_V16_CONSTRUCTION_ID_HEX,
} from "../src/backends/circle/local-word-construction-v16.ts";
import {
  V17_CONSTRUCTION_GRAPH,
  V17_PROOF_VERSION,
  v17ProtocolIdHex,
} from "../src/construction/v17-graph.ts";

type JsonObject = Record<string, any>;

const laneRoot = resolve(process.cwd());
const qualificationRoot = resolve(laneRoot, ".local/v17-qualification");
const receiptPath = resolve(laneRoot, "evidence/v17-offline-qualification-receipt.json");

const sha256Hex = (bytes: Uint8Array): string =>
  createHash("sha256").update(bytes).digest("hex");

function readJson(path: string): JsonObject {
  return JSON.parse(readFileSync(path, "utf8")) as JsonObject;
}

function fileBinding(path: string): { readonly bytes: number; readonly sha256Hex: string } {
  const bytes = readFileSync(path);
  return { bytes: bytes.length, sha256Hex: sha256Hex(bytes) };
}

function qualificationJson(name: string): JsonObject {
  return readJson(resolve(qualificationRoot, name));
}

function canonicalImportAudit(root: string): JsonObject {
  const output = execFileSync(
    process.execPath,
    ["--import", "tsx", "scripts/audit-local-word-product-imports.ts"],
    { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
  );
  const match = output.match(/local-word-product-import-audit (\{[^\n]+\})/);
  assert.ok(match, "canonical product import audit did not emit a receipt");
  return JSON.parse(match[1]!) as JsonObject;
}

function gitUnignoredFiles(): string[] {
  const output = execFileSync(
    "git",
    ["ls-files", "--cached", "--others", "--exclude-standard", "--", "."],
    { cwd: laneRoot, encoding: "utf8" },
  );
  return output.split("\n").filter((path) => path.length > 0).sort();
}

function assertIgnored(path: string): void {
  execFileSync("git", ["check-ignore", "-q", "--", path], {
    cwd: laneRoot,
    stdio: "ignore",
  });
}

function unignoredPurityReceipt(files: readonly string[]): JsonObject {
  const rawArtifact = /(?:\.proof|\.tx|\.source-outputs)$/i;
  const credentialName = /(?:^\.env(?:\.|$)|\.(?:pem|p12|pfx|keystore|wallet|wif|mnemonic)$|(?:^|[-_.])(?:credentials?|mnemonic|private[-_.]?key|wallet[-_.]?material|wif)(?:[-_.]|$))/i;
  const machinePathMarkers = [
    `/${"home"}/`,
    `/${"Users"}/`,
    `${"C:"}\\${"Users"}\\`,
  ].map((value) => Buffer.from(value));
  let rawProofTransactionOrSourceOutputFiles = 0;
  let credentialPatternFiles = 0;
  let absoluteMachinePathFiles = 0;
  let symbolicLinks = 0;
  let filesAboveOneMiB = 0;
  for (const path of files) {
    const absolute = resolve(laneRoot, path);
    const metadata = lstatSync(absolute);
    if (metadata.isSymbolicLink()) symbolicLinks += 1;
    if (!metadata.isFile()) continue;
    if (rawArtifact.test(path)) rawProofTransactionOrSourceOutputFiles += 1;
    if (credentialName.test(basename(path))) credentialPatternFiles += 1;
    if (metadata.size > 1024 * 1024) filesAboveOneMiB += 1;
    const bytes = readFileSync(absolute);
    if (machinePathMarkers.some((marker) => bytes.includes(marker))) {
      absoluteMachinePathFiles += 1;
    }
  }
  return {
    rawProofTransactionOrSourceOutputFiles,
    credentialPatternFiles,
    absoluteMachinePathFiles,
    symbolicLinks,
    filesAboveOneMiB,
  };
}

const receipt = readJson(receiptPath);
const qualification = qualificationJson("qualification-report.json");
const linker = qualificationJson("linker-certificate.json");
const finalIdentity = qualificationJson("final-infrastructure-identity.json");
const trace = qualificationJson("density-closure-trace.json");
const bchn = qualificationJson("bchn-product-evidence.json");
const theorem = qualificationJson("runtime-theorem-certificate.json");
const verifierPlan = readJson(resolve(laneRoot,
  "src/construction/generated/v17-verifier-plan.json"));
const v16ArtifactMeta = readJson(resolve(laneRoot,
  "survey/artifacts/local-word-v16-offline/meta.json"));
const v16ArtifactMeters = readJson(resolve(laneRoot,
  "survey/artifacts/local-word-v16-offline/meters.json"));

const sourceArtifactNames = [
  "qualification-report.json",
  "linker-certificate.json",
  "final-infrastructure-identity.json",
  "density-closure-trace.json",
  "local-sizing-certificate.json",
  "post-link-bchn-evidence.json",
  "bchn-product-evidence.json",
  "runtime-theorem-certificate.json",
] as const;
const sourceArtifactFiles = Object.fromEntries(sourceArtifactNames.map((name) => [
  name,
  fileBinding(resolve(qualificationRoot, name)),
]));

for (const name of sourceArtifactNames) assertIgnored(`.local/v17-qualification/${name}`);
for (const profile of [0, 1, 2]) {
  for (const suffix of ["proof", "tx", "source-outputs"]) {
    assertIgnored(`.local/v17-qualification/profile-${profile}.${suffix}`);
  }
}

assert.equal(qualification.status, "offline-theorem-qualified-candidate");
assert.equal(theorem.status, qualification.status);
assert.equal(v17ProtocolIdHex(V17_CONSTRUCTION_GRAPH), qualification.protocolIdHex);
assert.equal(verifierPlan.protocolIdHex, qualification.protocolIdHex);
for (const artifact of [linker, finalIdentity, bchn, theorem]) {
  assert.equal(artifact.protocolIdHex, qualification.protocolIdHex);
  assert.equal(artifact.constructionIdHex, qualification.constructionIdHex);
}
for (const artifact of [finalIdentity, bchn, theorem]) {
  assert.equal(artifact.linkerCertificateIdHex, qualification.linkerCertificateIdHex);
}
assert.equal(linker.certificateIdHex, qualification.linkerCertificateIdHex);
assert.equal(finalIdentity.identitySha256Hex,
  qualification.finalInfrastructureIdentitySha256Hex);
assert.equal(bchn.finalInfrastructureIdentitySha256Hex,
  qualification.finalInfrastructureIdentitySha256Hex);
assert.equal(theorem.finalInfrastructureIdentitySha256Hex,
  qualification.finalInfrastructureIdentitySha256Hex);
assert.equal(bchn.evidenceSha256Hex, qualification.bchnEvidenceSha256Hex);
assert.equal(theorem.bchnProductEvidenceSha256Hex, bchn.evidenceSha256Hex);
assert.equal(theorem.evidenceSha256Hex, qualification.runtimeTheoremEvidenceSha256Hex);

const normativeDocuments = V17_CONSTRUCTION_GRAPH.normativeSpec.documents.map((document) => {
  const path = resolve(laneRoot, document.path);
  const bytes = readFileSync(path);
  assert.ok(bytes.length > 1, `empty normative document ${document.path}`);
  assert.equal(bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf,
    false, `UTF-8 BOM ${document.path}`);
  new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  assert.equal(bytes.includes(0x0d), false, `non-LF line ending ${document.path}`);
  assert.equal(bytes.at(-1), 0x0a, `missing terminal LF ${document.path}`);
  assert.notEqual(bytes.at(-2), 0x0a, `multiple terminal LFs ${document.path}`);
  assert.equal(sha256Hex(bytes), document.sha256Hex,
    `normative document hash drift ${document.path}`);
  return {
    id: document.id,
    path: document.path,
    bytes: bytes.length,
    sha256Hex: document.sha256Hex,
  };
});

const proofRows = qualification.proofs as JsonObject[];
assert.equal(proofRows.length, 3);
const proofs = proofRows.map((proof) => {
  const path = resolve(qualificationRoot, `profile-${proof.profile}.proof`);
  const binding = fileBinding(path);
  assert.equal(binding.bytes, proof.bytes);
  assert.equal(binding.sha256Hex, proof.sha256Hex);
  return {
    profile: proof.profile,
    bytes: proof.bytes,
    sha256Hex: proof.sha256Hex,
    quotientDegreeBound: proof.quotientDegreeBound,
    canonicalEnvelopeHeadroomBytes:
      qualification.allocation.maximumProofBytes - proof.bytes,
  };
});

const closureRows = linker.densityClosure.rows as JsonObject[];
const traceEntries = trace.entries as JsonObject[];
const finalTrace = traceEntries.at(-1)!;
const linkerTrace = traceEntries.find((entry) => entry.phase === "post-link-bchn")!;
assert.ok(finalTrace);
assert.ok(linkerTrace);
assert.equal(finalTrace.phase, "final-bchn");
assert.equal(finalTrace.entrySha256Hex, qualification.densityTraceRootSha256Hex);
assert.equal(finalTrace.entrySha256Hex, bchn.finalDensityTraceRootSha256Hex);
assert.equal(linkerTrace.entrySha256Hex, linker.densityTraceRootSha256Hex);
assert.equal(linker.densityClosureSha256Hex, qualification.densityClosureSha256Hex);
assert.equal(linker.densityClosure.closureSha256Hex,
  qualification.densityClosureSha256Hex);
assert.equal(finalTrace.joinedClosure.closureSha256Hex,
  qualification.densityClosureSha256Hex);

const closure = {
  status: linker.densityClosure.status,
  sha256Hex: linker.densityClosure.closureSha256Hex,
  roleCount: closureRows.length,
  sumRequiredProofBytes: closureRows.reduce((sum, row) => sum + row.requiredProofBytes, 0),
  sumCapacityProofBytes: closureRows.reduce((sum, row) => sum + row.capacityProofBytes, 0),
  minimumRoleSlackBytes: Math.min(...closureRows.map((row) =>
    row.capacityProofBytes - row.requiredProofBytes)),
  maximumRoleRequiredProofBytes: Math.max(...closureRows.map((row) =>
    row.requiredProofBytes)),
  maximumRoleCapacityProofBytes: Math.max(...closureRows.map((row) =>
    row.capacityProofBytes)),
  maximumRoleOperationCost: Math.max(...closureRows.map((row) =>
    row.maximumOperationCost)),
};

const page = (linker.romPages as JsonObject[])[0]!;
assert.equal((linker.romPages as JsonObject[]).length, 1);
assert.equal(page.pageIndex, 0);
assert.equal(page.bodySha256Hexes.length, page.functionIds.length);
assert.deepEqual(page.bodySha256Hexes, linker.census.promotedBodySha256Hexes);

const transactionRows = bchn.profiles as JsonObject[];
assert.equal(transactionRows.length, 3);
const transactions = transactionRows.map((transaction) => {
  const profile = transaction.profile;
  const reportTransaction = (qualification.transactions as JsonObject[])
    .find((row) => row.profile === profile)!;
  const proof = proofRows.find((row) => row.profile === profile)!;
  const infrastructure = (finalIdentity.profiles as JsonObject[])
    .find((row) => row.profile === profile)!;
  const rawTransaction = fileBinding(resolve(qualificationRoot, `profile-${profile}.tx`));
  const rawSourceOutputs = fileBinding(resolve(qualificationRoot,
    `profile-${profile}.source-outputs`));
  assert.deepEqual(rawTransaction, {
    bytes: transaction.transactionBytes,
    sha256Hex: transaction.transactionSha256Hex,
  });
  assert.deepEqual(rawSourceOutputs, {
    bytes: transaction.sourceOutputsBytes,
    sha256Hex: transaction.sourceOutputsSha256Hex,
  });
  assert.equal(reportTransaction.bytes, transaction.transactionBytes);
  assert.equal(reportTransaction.sha256Hex, transaction.transactionSha256Hex);
  assert.equal(reportTransaction.inputs, transaction.inputCount);
  assert.equal(reportTransaction.outputs, transaction.outputCount);
  assert.equal(transaction.proofBytes, proof.bytes);
  assert.equal(transaction.proofSha256Hex, proof.sha256Hex);
  assert.equal(transaction.bankDigestHex, infrastructure.bankDigestHex);
  assert.equal(transaction.infrastructureInventorySha256Hex,
    infrastructure.infrastructureInventorySha256Hex);
  assert.equal(transaction.infrastructureIdentityCheck, "passed-byte-exact");
  assert.equal(transaction.v17TopologyCheck, "passed");
  assert.equal(transaction.inputs.length, transaction.inputCount);
  return {
    profile,
    bytes: transaction.transactionBytes,
    sha256Hex: transaction.transactionSha256Hex,
    consensusEnvelopeHeadroomBytes:
      bchn.limits.transactionBytes - transaction.transactionBytes,
    inputs: transaction.inputCount,
    outputs: transaction.outputCount,
    sourceOutputsBytes: transaction.sourceOutputsBytes,
    sourceOutputsSha256Hex: transaction.sourceOutputsSha256Hex,
    bankDigestHex: transaction.bankDigestHex,
    infrastructureInventorySha256Hex: transaction.infrastructureInventorySha256Hex,
  };
});

const assayBinding = fileBinding(qualification.assayExecutablePath);
assert.equal(assayBinding.sha256Hex, qualification.assayExecutableSha256Hex);
const checkedInputs = transactionRows.reduce((sum, profile) => sum + profile.inputs.length, 0);
assert.equal(checkedInputs, bchn.aggregate.checkedInputs);

const observers = qualification.observers as JsonObject[];
const referenceRows = qualification.referenceAudit as JsonObject[];
const carrierRows = qualification.carrierAudit as JsonObject[];
assert.equal(observers.length, 3);
assert.equal(referenceRows.length, 3);
assert.equal(carrierRows.length, 3);
for (const observer of observers) {
  assert.equal(observer.proofVersion, V17_PROOF_VERSION);
  assert.equal(observer.carrierUnionExact, true);
  assert.equal(observer.carrierAllocation.exactOwnershipReplay, true);
  assert.equal(observer.protectedTraceRecovery.recovered, false);
  assert.equal(observer.protectedTraceRecovery.compensatingWitness.allOpeningResidualsZero,
    true);
  assert.equal(observer.protectedTraceRecovery.compensatingWitness.changesProtectedTrace,
    true);
}
const privacySystem = observers[0]!.protectedTraceRecovery.linearSystem;
for (const observer of observers.slice(1)) {
  assert.deepEqual(observer.protectedTraceRecovery.linearSystem, privacySystem);
}
const referenceCases = referenceRows.flatMap((row) => row.cases as JsonObject[]);
const carrierCases = carrierRows.length;

const v17ImportAudit = canonicalImportAudit(laneRoot);
assert.equal(v17ImportAudit.reachableFiles, 87);
const v16Names = new Set(LOCAL_WORD_V16_COMPONENTS.map((component) => component.name));
const v16Paths = new Set(LOCAL_WORD_V16_COMPONENTS.map((component) => component.path));
assert.equal(v16Names.size, LOCAL_WORD_V16_COMPONENTS.length);
assert.equal(v16Paths.size, LOCAL_WORD_V16_COMPONENTS.length);
assert.equal(LOCAL_WORD_V16_COMPONENTS.length, 61);
assert.equal(LOCAL_WORD_V16_CONSTRUCTION_ID_HEX,
  "f29ef06d0e2868a4e6207f060b6246fd49a51fabd0bd14e7d41b48324a1e70e5");
assert.equal(v16ArtifactMeta.version, 16);
assert.equal(v16ArtifactMeta.constructionId, LOCAL_WORD_V16_CONSTRUCTION_ID_HEX);
assert.equal(v16ArtifactMeters.constructionId, LOCAL_WORD_V16_CONSTRUCTION_ID_HEX);

const retainedDiagnostics = [
  "scripts/diagnose-v17-input-read-heat.ts",
  "scripts/diagnose-v17-retained-sizing.ts",
] as const;
const removedDiagnostics = [
  "scripts/diagnose-v17-frontier.tmp.ts",
  "scripts/diagnose-v17-parent-read.tmp.ts",
  "scripts/diagnose-v17-semantic-cut.tmp.ts",
  "scripts/diagnose-v17-algebra-opcost.ts",
  "scripts/diagnose-v17-fused-fold-pair.ts",
  "scripts/diagnose-v17-packed-beta-dot.ts",
] as const;
const removedLegacyTests = ["test/local-word-sealed-proof.test.ts"] as const;
for (const path of retainedDiagnostics) assert.equal(existsSync(resolve(laneRoot, path)), true);
for (const path of [...removedDiagnostics, ...removedLegacyTests]) {
  assert.equal(existsSync(resolve(laneRoot, path)), false, `obsolete file remains ${path}`);
}
const unignoredAudit = unignoredPurityReceipt(gitUnignoredFiles());
assert.deepEqual(unignoredAudit, {
  rawProofTransactionOrSourceOutputFiles: 0,
  credentialPatternFiles: 0,
  absoluteMachinePathFiles: 0,
  symbolicLinks: 0,
  filesAboveOneMiB: 0,
});

const expected = {
  schema: "ShieldKit/V17OfflineQualificationReceipt/v1",
  status: qualification.status,
  claimClass: {
    measurements: "fresh-exact-offline-artifacts",
    productCorrespondence: "identity-bound-runtime-theorem-certificate",
    privacy: "opening-view-non-uniqueness-only-no-complete-zk-claim",
    bchnExecution: "every-input-VerifyScript-only",
    networkQualification: "not-claimed",
    humanDeclaredCompletion: false,
  },
  versionBoundary: {
    proofVersion: V17_PROOF_VERSION,
    productGraphVersion: 17,
    frozenRelationConstructionDescriptorVersion:
      V17_CONSTRUCTION_GRAPH.foundation.relationConstructionVersion,
    profiles: [
      { profile: 0, action: "deposit" },
      { profile: 1, action: "full-withdrawal" },
      { profile: 2, action: "withdrawal-with-change" },
    ],
  },
  identity: {
    protocolIdHex: qualification.protocolIdHex,
    constructionIdHex: qualification.constructionIdHex,
    linkerCertificateIdHex: qualification.linkerCertificateIdHex,
    finalInfrastructureIdentitySha256Hex:
      qualification.finalInfrastructureIdentitySha256Hex,
    romPreviewIdHex: linker.romPreviewIdHex,
  },
  normativeSpecification: {
    bytePolicy: "utf-8-no-bom-lf-only-one-terminal-lf-sha256-exact-bytes",
    documents: normativeDocuments,
  },
  proofs,
  allocationAndDensityClosure: {
    strategy: trace.genesis.graphAllocation.strategy,
    closureLaw: trace.genesis.graphAllocation.closureJoin,
    proofCarrierRoleCount: linker.allocation.length,
    minimumProofBytes: qualification.allocation.minimumProofBytes,
    maximumCanonicalProofBytes: qualification.allocation.maximumProofBytes,
    elasticScaleUnits: qualification.allocation.elasticScaleUnits,
    linkerAssignmentDigestHex: linker.allocationDigestHex,
    canonicalAllocationStateSha256Hex: finalTrace.nextAllocationSha256Hex,
    readerPlanSha256Hex: finalTrace.nextReaderPlanSha256Hex,
    readerBytecodeSha256Hex: finalTrace.nextReaderBytecodeSha256Hex,
    closure,
    trace: {
      genesisSha256Hex: trace.genesis.genesisSha256Hex,
      entryCount: traceEntries.length,
      localSizingEntries: traceEntries.filter((entry) => entry.phase === "local-sizing").length,
      postLinkBchnEntries: traceEntries.filter((entry) => entry.phase === "post-link-bchn").length,
      finalBchnEntries: traceEntries.filter((entry) => entry.phase === "final-bchn").length,
      linkerTerminalTraceRootSha256Hex: linkerTrace.entrySha256Hex,
      finalTraceRootSha256Hex: finalTrace.entrySha256Hex,
      linkerTerminalMeasurementRowsSha256Hex: linker.terminalMeasurementRowsSha256Hex,
      finalBchnDensityRowsSha256Hex: bchn.finalDensityRowsSha256Hex,
      finalEntryMeasuredRowsSha256Hex: finalTrace.measuredRowsSha256Hex,
      finalMeasurementEvidenceSha256Hex: finalTrace.measurementEvidenceSha256Hex,
      terminalNoChange: finalTrace.noChange,
      terminalChangedRoleCount: finalTrace.changedRoleIds.length,
    },
  },
  authenticatedCodeRom: {
    pageCount: linker.romPages.length,
    roleIndex: page.inputIndex,
    functionIdentifierPolicy: verifierPlan.rom.functionIdentifiers,
    packingPolicy: verifierPlan.rom.packing,
    staticDefinitionOccurrences: linker.census.staticDefinitionOccurrences,
    exactBodyClasses: linker.census.exactBodyClasses,
    page: {
      inputIndex: page.inputIndex,
      outputIndex: page.outputIndex,
      valueSatoshis: page.valueSatoshis,
      sequenceNumber: page.sequenceNumber,
      payloadBytes: page.payloadBytes,
      payloadSha256Hex: page.payloadSha256Hex,
      redeemBytes: page.redeemBytes,
      redeemSha256Hex: page.redeemSha256Hex,
      unlockingBytes: page.unlockingBytes,
      functionIds: page.functionIds,
      bodySha256Hexes: page.bodySha256Hexes,
    },
  },
  transactions,
  bchnAssay: {
    schema: bchn.schema,
    status: bchn.status,
    scope: bchn.scope.bchn,
    engine: {
      name: bchn.engine.name,
      version: bchn.engine.version,
      sourceTagCommit: bchn.engine.sourceTagCommit,
      mode: bchn.engine.mode,
      flags: bchn.engine.flags,
      executableBytes: assayBinding.bytes,
      executableSha256Hex: assayBinding.sha256Hex,
    },
    recordedLimits: {
      transactionBytes: bchn.limits.transactionBytes,
      scriptBytes: bchn.limits.scriptBytes,
      sigChecksPerTransaction: bchn.limits.sigChecksPerTransaction,
      tokenCommitmentBytes: bchn.limits.tokenCommitmentBytes,
      bchConstantsSourceCommit: bchn.limits.bchConstantsSourceCommit,
    },
    checkedInputs,
    acceptedInputs: bchn.status === "passed" ? checkedInputs : 0,
    maximumProfileSigChecks: bchn.aggregate.maximumProfileSigChecks,
    maximumCompositeOperationCost: bchn.aggregate.maximumCompositeOpCost,
    maximumHashDigestIterations: bchn.aggregate.maximumHashDigestIterations,
    evidenceSha256Hex: bchn.evidenceSha256Hex,
  },
  assurance: {
    proofSource: qualification.proofSource,
    strictReferenceReplayProfiles: referenceRows.filter((row) =>
      row.cases.every((testCase: JsonObject) => testCase.rejected === true)).length,
    byteExactInfrastructureProfiles: transactionRows.filter((row) =>
      row.infrastructureIdentityCheck === "passed-byte-exact").length,
    adversarial: {
      referenceCases: referenceCases.length,
      referenceRejections: referenceCases.filter((testCase) => testCase.rejected === true).length,
      carrierSwapCases: carrierCases,
      carrierSwapRejections: carrierRows.filter((row) =>
        row.swappedCarriersRejected === true).length,
      evidenceSha256Hex: theorem.adversarialEvidenceSha256Hex,
    },
    privacyObserver: {
      profileCount: observers.length,
      exactCarrierUnionProfiles: observers.filter((observer) =>
        observer.carrierUnionExact === true).length,
      exactOwnershipReplayProfiles: observers.filter((observer) =>
        observer.carrierAllocation.exactOwnershipReplay === true).length,
      protectedTraceRecoveryFalseProfiles: observers.filter((observer) =>
        observer.protectedTraceRecovery.recovered === false).length,
      equationsPerOriginalColumn: privacySystem.equationsPerColumn,
      certifiedRankPerOriginalColumn: privacySystem.certifiedRankPerColumn,
      conditionedMaskNullityPerOriginalColumn: privacySystem.conditionedMaskNullityPerColumn,
      jointTraceAndMaskNullityPerOriginalColumn: privacySystem.jointTraceAndMaskNullityPerColumn,
      claimBoundary: "opening-view non-uniqueness only; complete honest-verifier simulation, AIR-valid semantic alternatives, statistical ZK, computational ZK, and QROM ZK are not claimed",
      evidenceSha256Hex: theorem.privacyEvidenceSha256Hex,
    },
    runtimeTheorem: {
      schema: theorem.schema,
      status: theorem.status,
      proofSetSha256Hex: theorem.proofSetSha256Hex,
      assuranceRows: theorem.theorem.assuranceRows,
      randomizedRounds: theorem.theorem.randomizedRounds,
      promotedProductRows: theorem.promotedRows.length,
      allTEndpointsPassed: theorem.theorem.allTEndpointsPassed,
      classicalFloor: theorem.theorem.classicalFloor,
      classicalFiatShamir: theorem.privacyClaim.classicalFiatShamir,
      qromZeroKnowledge: theorem.privacyClaim.qromZeroKnowledge,
      quantumClaim: theorem.quantumClaim,
      evidenceSha256Hex: theorem.evidenceSha256Hex,
    },
  },
  evidenceBindings: { sourceArtifactFiles },
  sourcePurity: {
    v17ProductImportAudit: {
      reachableFiles: v17ImportAudit.reachableFiles,
      forbiddenFilesReached: 0,
      forbiddenSymbolsReached: 0,
    },
    frozenV16Fingerprint: {
      constructionIdHex: LOCAL_WORD_V16_CONSTRUCTION_ID_HEX,
      manifestComponents: LOCAL_WORD_V16_COMPONENTS.length,
      embeddedManifestConstructionIdRecomputed: true,
      laneLocalHistoricalEvidenceMatched: true,
      v17EmbeddedManifestBoundaryTestPassed: true,
    },
    unignoredAudit,
    retainedReproducibleDiagnostics: retainedDiagnostics,
    removedExploratoryDiagnostics: removedDiagnostics,
    removedObsoleteLegacyTests: removedLegacyTests,
  },
  explicitExclusions: [
    ...qualification.explicitExclusions,
    "complete honest-verifier simulation",
    "statistical zero knowledge",
    "computational zero knowledge",
    "QROM zero knowledge",
    "human declaration of named completion",
  ],
  sanitization: {
    rawProofBytesIncluded: false,
    rawTransactionBytesIncluded: false,
    rawSourceOutputBytesIncluded: false,
    assayExecutableBytesIncluded: false,
    absoluteMachinePathsIncluded: false,
    walletOrCredentialMaterialIncluded: false,
    excludedArtifactsAreBoundByLengthAndSha256: true,
    rawEvidenceStorageClass: "ignored-local-cache-only",
  },
};

assert.deepEqual(receipt, expected, "offline qualification receipt drift");
const receiptBytes = readFileSync(receiptPath);
assert.equal(receiptBytes.includes(Buffer.from(`/${"home"}/`)), false,
  "receipt contains an absolute machine path");
assert.equal(receiptBytes.includes(Buffer.from(qualification.assayExecutablePath)), false,
  "receipt contains the assay executable path");

console.log("v17-offline-qualification-receipt-verified", JSON.stringify({
  receiptBytes: receiptBytes.length,
  receiptSha256Hex: sha256Hex(receiptBytes),
  protocolIdHex: receipt.identity.protocolIdHex,
  constructionIdHex: receipt.identity.constructionIdHex,
  reachableFiles: v17ImportAudit.reachableFiles,
  sourceArtifactFiles: sourceArtifactNames.length,
  proofProfiles: proofs.length,
  transactionProfiles: transactions.length,
}));

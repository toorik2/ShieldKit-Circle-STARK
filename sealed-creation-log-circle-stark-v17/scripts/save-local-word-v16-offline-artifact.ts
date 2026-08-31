import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { LOCAL_WORD_V16_CONSTRUCTION_ID_HEX } from
  "../src/backends/circle/local-word-construction-v16.ts";
import { LOCAL_WORD_PROOF_VERSION } from
  "../src/backends/circle/local-word-sealed-proof.ts";
import { LOCAL_WORD_CARRIER_INPUTS } from
  "../src/chain/local-word-proof-carriers.ts";

type ProductReport = {
  readonly profile: number;
  readonly proofBytes: number;
  readonly proofSha256: string;
  readonly proofSource: "generated" | "cache";
  readonly constructionId: string;
  readonly transactionBytes: number;
  readonly transactionSha256: string;
  readonly remainingConsensusBytes: number;
  readonly roles: number;
  readonly maxVerifierBytes: number;
  readonly maxRedeemBytes: number;
  readonly maxUnlockingBytes: number;
  readonly soundnessWorksheet: {
    readonly conservativeUnionBits: number;
    readonly meetsFloor: boolean;
    readonly claimBoundary: string;
  };
  readonly observer: {
    readonly proofVersion: number;
    readonly proofBytes: number;
    readonly transactionBytes: number;
    readonly carrierInputs: number;
    readonly carrierUnionExact: boolean;
    readonly protectedTraceRecovery: { readonly recovered: boolean };
  };
  readonly artifactAudit: {
    readonly proofMutations: readonly unknown[];
    readonly falseStatement: unknown;
    readonly carrierPlacement: unknown;
  } | null;
  readonly vm: {
    readonly checkedInputs: number;
    readonly maximumOperationCost: number;
  } | null;
  readonly vmRoles: readonly unknown[] | null;
};

type ArtifactMeta = {
  readonly version: 16;
  readonly constructionId: string;
  readonly proofBytes: number;
  readonly proofSha256: string;
  readonly transactionBytes: number;
  readonly transactionSha256: string;
  readonly freshProofGenerated: true;
  readonly independentReplayVerified: boolean;
  readonly rawArtifacts: ".local only; intentionally not committed";
  readonly qualificationBoundary: "offline; no RPC or chain mutation";
};

const lane = process.cwd();
const local = resolve(lane, ".local");
const output = resolve(lane, "survey/artifacts/local-word-v16-offline");
const reportPath = resolve(local, "local-word-product-v16-report.json");
const proofPath = resolve(local, "local-word-product-v16.proof");
const transactionPath = resolve(local, "local-word-product-v16.tx");
const metaPath = resolve(output, "meta.json");

function sha256File(path: string): string {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function writeAtomic(path: string, contents: string): void {
  const temporary = `${path}.tmp`;
  writeFileSync(temporary, contents);
  renameSync(temporary, path);
}

const report = JSON.parse(readFileSync(reportPath, "utf8")) as ProductReport;
assert.equal(report.profile, 2);
assert.equal(report.constructionId, LOCAL_WORD_V16_CONSTRUCTION_ID_HEX);
assert.equal(report.roles, LOCAL_WORD_CARRIER_INPUTS);
assert.ok(report.transactionBytes <= 1_000_000);
assert.equal(report.remainingConsensusBytes, 1_000_000 - report.transactionBytes);
assert.ok(report.maxVerifierBytes <= 10_000);
assert.ok(report.maxRedeemBytes <= 10_000);
assert.ok(report.maxUnlockingBytes <= 10_000);
assert.equal(sha256File(proofPath), report.proofSha256);
assert.equal(sha256File(transactionPath), report.transactionSha256);
assert.equal(readFileSync(proofPath).length, report.proofBytes);
assert.equal(readFileSync(transactionPath).length, report.transactionBytes);
assert.equal(report.soundnessWorksheet.meetsFloor, true);
assert.equal(report.soundnessWorksheet.claimBoundary,
  "fri-query-term-conjectural-classical-rom");
assert.equal(report.observer.proofVersion, LOCAL_WORD_PROOF_VERSION);
assert.equal(report.observer.proofBytes, report.proofBytes);
assert.equal(report.observer.transactionBytes, report.transactionBytes);
assert.equal(report.observer.carrierInputs, LOCAL_WORD_CARRIER_INPUTS);
assert.equal(report.observer.carrierUnionExact, true);
assert.equal(report.observer.protectedTraceRecovery.recovered, false);

mkdirSync(output, { recursive: true });
const replay = process.argv.includes("--replay");
if (replay) {
  assert.equal(report.proofSource, "cache");
  const previous = JSON.parse(readFileSync(metaPath, "utf8")) as ArtifactMeta;
  assert.equal(previous.freshProofGenerated, true);
  assert.equal(previous.constructionId, report.constructionId);
  assert.equal(previous.proofSha256, report.proofSha256);
  assert.equal(previous.transactionSha256, report.transactionSha256);
  const meta: ArtifactMeta = { ...previous, independentReplayVerified: true };
  writeAtomic(metaPath, `${JSON.stringify(meta, null, 2)}\n`);
  console.log("local-word-v16-artifact-replay", JSON.stringify(meta));
  process.exit(0);
}

assert.equal(report.proofSource, "generated");
assert.ok(report.artifactAudit);
assert.equal(report.artifactAudit.proofMutations.length, 4);
assert.ok(report.artifactAudit.falseStatement);
assert.ok(report.artifactAudit.carrierPlacement);
assert.ok(report.vm);
assert.equal(report.vm.checkedInputs, LOCAL_WORD_CARRIER_INPUTS);
assert.equal(report.vmRoles?.length, LOCAL_WORD_CARRIER_INPUTS);

const meta: ArtifactMeta = {
  version: 16,
  constructionId: report.constructionId,
  proofBytes: report.proofBytes,
  proofSha256: report.proofSha256,
  transactionBytes: report.transactionBytes,
  transactionSha256: report.transactionSha256,
  freshProofGenerated: true,
  independentReplayVerified: false,
  rawArtifacts: ".local only; intentionally not committed",
  qualificationBoundary: "offline; no RPC or chain mutation",
};
writeAtomic(metaPath, `${JSON.stringify(meta, null, 2)}\n`);
writeAtomic(resolve(output, "meters.json"), `${JSON.stringify(report, null, 2)}\n`);
writeAtomic(resolve(output, "README.md"), `# V16 offline evidence\n\n` +
  `Construction \`${report.constructionId}\` was exercised with a fresh profile-2 ` +
  `proof and one exact ${report.roles}-input BCH2026 consensus transaction. ` +
  `All VM meters, observer output, and mutation results are in \`meters.json\`.\n\n` +
  `The raw ${report.proofBytes}-byte proof and ${report.transactionBytes}-byte ` +
  `transaction remain in ignored \`.local/\`; their SHA-256 digests are pinned in ` +
  `\`meta.json\`. This is offline evidence only and records no RPC, broadcast, ` +
  `funding, spending, or mining.\n`);
console.log("local-word-v16-artifact-fresh", JSON.stringify(meta));

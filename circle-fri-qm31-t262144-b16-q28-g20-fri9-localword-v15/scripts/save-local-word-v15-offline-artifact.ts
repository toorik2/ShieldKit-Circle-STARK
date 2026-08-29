import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  LOCAL_WORD_V15_COMPONENTS,
  LOCAL_WORD_V15_CONSTRUCTION_ID_HEX,
} from "../src/backends/circle/local-word-construction-v15.ts";
import { localWordV15VerifierKey } from
  "../src/backends/circle/local-word-verifier-keys-v15.ts";
import { LOCAL_WORD_V15_VERIFIER_BANK_DIGESTS_HEX } from
  "../src/chain/local-word-verifier-bank-digests-v15.ts";

type VmRoleMeasurement = {
  readonly index: number;
  readonly name: string;
  readonly operationCost: number;
  readonly maximumOperationCost: number;
  readonly hashDigestIterations: number;
  readonly maximumHashDigestIterations: number;
  readonly redeemBytes: number;
  readonly unlockingBytes: number;
};

type Rejection = {
  readonly label?: string;
  readonly reference: string;
  readonly vmRole: { readonly index: number; readonly name: string };
};

type ProductReport = {
  readonly profile: number;
  readonly proofBytes: number;
  readonly proofSha256: string;
  readonly proofSource: string;
  readonly constructionId: string;
  readonly constructionDigest: string;
  readonly expectedPreprocessedRoot: string;
  readonly quotientDegreeBound: number;
  readonly roles: number;
  readonly transactionBytes: number;
  readonly transactionSha256: string;
  readonly remainingConsensusBytes: number;
  readonly bankDigests: readonly string[];
  readonly maxVerifierBytes: number;
  readonly maxRedeemBytes: number;
  readonly maxUnlockingBytes: number;
  readonly observer: {
    readonly proofVersion: number;
    readonly carrierInputs: number;
    readonly carrierUnionExact: boolean;
    readonly protectedTraceRecovery: { readonly recovered: boolean };
    readonly [key: string]: unknown;
  };
  readonly artifactAudit: {
    readonly proofMutations: readonly Rejection[];
    readonly falseStatement: Rejection;
    readonly carrierPlacement: Rejection;
  };
  readonly vm: {
    readonly checkedInputs: number;
    readonly maximumOperationCost: number;
    readonly maximumOperationCostRole: { readonly index: number; readonly name: string };
  };
  readonly vmRoles: readonly VmRoleMeasurement[];
};

const local = resolve(".local");
const reportPath = resolve(local, "local-word-product-v15-report.json");
const proofPath = resolve(local, "local-word-product-v15.proof");
const transactionPath = resolve(local, "local-word-product-v15.tx");
const report = JSON.parse(readFileSync(reportPath, "utf8")) as ProductReport;
const proof = readFileSync(proofPath);
const transaction = readFileSync(transactionPath);
const verifierKey = localWordV15VerifierKey(2);
const rulesSha256 = LOCAL_WORD_V15_COMPONENTS
  .find(({ role }) => role === "rules")?.sha256Hex;
assert.ok(rulesSha256 !== undefined);
const hex = (bytes: Uint8Array) => Buffer.from(bytes).toString("hex");
const sha256Hex = (bytes: Uint8Array) =>
  createHash("sha256").update(bytes).digest("hex");

assert.equal(report.profile, 2);
assert.equal(report.proofSource, "generated",
  "save qualification evidence directly from a --fresh-proof run");
assert.equal(report.constructionId, LOCAL_WORD_V15_CONSTRUCTION_ID_HEX);
assert.equal(report.constructionDigest, hex(verifierKey.constructionDigest));
assert.equal(report.expectedPreprocessedRoot, hex(verifierKey.preprocessedRoot));
assert.equal(report.proofBytes, proof.length);
assert.equal(report.proofSha256, sha256Hex(proof));
assert.ok(proof.length <= verifierKey.maximumProofBytes);
assert.equal(report.transactionBytes, transaction.length);
assert.equal(report.transactionSha256, sha256Hex(transaction));
assert.ok(transaction.length <= 1_000_000);
assert.equal(report.remainingConsensusBytes, 1_000_000 - transaction.length);
assert.equal(report.roles, 168);
assert.equal(report.vm.checkedInputs, 168);
assert.equal(report.vmRoles.length, 168);
assert.deepEqual(report.vmRoles.map(({ index }) => index),
  Array.from({ length: 168 }, (_, index) => index));
assert.deepEqual(report.bankDigests, LOCAL_WORD_V15_VERIFIER_BANK_DIGESTS_HEX);
assert.ok(report.maxRedeemBytes <= 10_000);
assert.ok(report.maxUnlockingBytes <= 10_000);
assert.equal(report.observer.proofVersion, 15);
assert.equal(report.observer.carrierInputs, 168);
assert.equal(report.observer.carrierUnionExact, true);
assert.equal(report.observer.protectedTraceRecovery.recovered, false);

for (const role of report.vmRoles) {
  assert.ok(role.operationCost <= role.maximumOperationCost, `${role.name}: operation cost`);
  assert.ok(role.hashDigestIterations <= role.maximumHashDigestIterations,
    `${role.name}: hash iterations`);
  assert.ok(role.redeemBytes <= 10_000, `${role.name}: redeem bytes`);
  assert.ok(role.unlockingBytes <= 10_000, `${role.name}: unlocking bytes`);
}

const maximumOperationCost = [...report.vmRoles]
  .sort((left, right) => right.operationCost - left.operationCost)[0]!;
const tightestOperationCost = [...report.vmRoles]
  .sort((left, right) =>
    (left.maximumOperationCost - left.operationCost) -
    (right.maximumOperationCost - right.operationCost))[0]!;
const maximumHashIterations = [...report.vmRoles]
  .sort((left, right) => right.hashDigestIterations - left.hashDigestIterations)[0]!;
const tightestHashIterations = [...report.vmRoles]
  .sort((left, right) =>
    (left.maximumHashDigestIterations - left.hashDigestIterations) -
    (right.maximumHashDigestIterations - right.hashDigestIterations))[0]!;
assert.equal(maximumOperationCost.operationCost, report.vm.maximumOperationCost);
assert.deepEqual(
  { index: maximumOperationCost.index, name: maximumOperationCost.name },
  report.vm.maximumOperationCostRole,
);

assert.deepEqual(
  [...report.artifactAudit.proofMutations].map(({ label }) => label).sort(),
  ["fold", "mask", "opening", "root"],
);
for (const rejected of [
  ...report.artifactAudit.proofMutations,
  report.artifactAudit.falseStatement,
  report.artifactAudit.carrierPlacement,
]) {
  assert.notEqual(rejected.reference, "accepted");
  assert.ok(rejected.vmRole.index >= 0 && rejected.vmRole.index < 168);
}

const meta = {
  schema: "shieldkit.local-word-v15.offline-artifact/v1",
  qualificationDate: "2026-08-29",
  status: "offline-qualified-candidate",
  namedEnd: false,
  construction: {
    proofVersion: 15,
    constructionId: report.constructionId,
    rulesSha256,
    constructionDigest: report.constructionDigest,
    preprocessedRoot: report.expectedPreprocessedRoot,
    profile: report.profile,
    bankDigests: report.bankDigests,
  },
  proof: {
    source: "fresh --fresh-proof run",
    bytes: report.proofBytes,
    maximumBytes: verifierKey.maximumProofBytes,
    sha256: report.proofSha256,
    quotientDegreeBound: report.quotientDegreeBound,
    rawPath: ".local/local-word-product-v15.proof",
  },
  transaction: {
    bytes: report.transactionBytes,
    maximumBytes: 1_000_000,
    remainingBytes: report.remainingConsensusBytes,
    sha256: report.transactionSha256,
    inputs: 168,
    outputs: 170,
    rawPath: ".local/local-word-product-v15.tx",
  },
  limitsEvidence: {
    bchnSourceCommit: "864c53ee34924cca6c6b6d96607ff2cedcdccf02",
    cashc: "0.14.0-next.4",
    cashScriptEvidenceIds: ["LIM-001", "LIM-003", "LIM-006", "INT-001"],
  },
  verification: {
    passed: [
      "product import audit: 50 reachable files, zero forbidden v15 paths",
      "Rust/TypeScript worst-profile preflight",
      "fresh proof, independent reference verification, exact artifact mutations, and 168/168 VM inputs",
      "focused v15 TypeScript tests: 81/81",
      "cargo +nightly-2026-01-15 check --release",
    ],
    inheritedFailure: {
      command: "npm run typecheck",
      errors: 10,
      files: 7,
      changedProductOrEvidenceFiles: 0,
    },
    deliberatelySkipped: [
      "complete historical npm test suite",
      "complete Cargo test suite",
      "broad rustfmt rewrite of inherited worker source",
      "all RPC, mempool, funding, broadcast, and chain-mutation checks",
    ],
  },
  chipnet: {
    mined: false,
    reason: "chain mutation requires a separate explicit authorization",
  },
  rawReportPath: ".local/local-word-product-v15-report.json",
} as const;

const meters = {
  schema: "shieldkit.local-word-v15.offline-meters/v1",
  constructionId: report.constructionId,
  transactionSha256: report.transactionSha256,
  allInputsAccepted: true,
  allWithinLimits: true,
  scripts: {
    maximumVerifierBytes: report.maxVerifierBytes,
    maximumRedeemBytes: report.maxRedeemBytes,
    maximumUnlockingBytes: report.maxUnlockingBytes,
  },
  vm: {
    checkedInputs: report.vm.checkedInputs,
    maximumOperationCost: {
      index: maximumOperationCost.index,
      name: maximumOperationCost.name,
      used: maximumOperationCost.operationCost,
      budget: maximumOperationCost.maximumOperationCost,
    },
    tightestOperationCost: {
      index: tightestOperationCost.index,
      name: tightestOperationCost.name,
      used: tightestOperationCost.operationCost,
      budget: tightestOperationCost.maximumOperationCost,
      remaining: tightestOperationCost.maximumOperationCost - tightestOperationCost.operationCost,
    },
    maximumHashIterations: {
      index: maximumHashIterations.index,
      name: maximumHashIterations.name,
      used: maximumHashIterations.hashDigestIterations,
      budget: maximumHashIterations.maximumHashDigestIterations,
    },
    tightestHashIterations: {
      index: tightestHashIterations.index,
      name: tightestHashIterations.name,
      used: tightestHashIterations.hashDigestIterations,
      budget: tightestHashIterations.maximumHashDigestIterations,
      remaining: tightestHashIterations.maximumHashDigestIterations -
        tightestHashIterations.hashDigestIterations,
    },
    inputs: report.vmRoles,
  },
  observer: report.observer,
  adversarial: report.artifactAudit,
} as const;

const output = resolve("survey/artifacts/local-word-v15-offline");
mkdirSync(output, { recursive: true });
for (const [name, value] of [["meta.json", meta], ["meters.json", meters]] as const) {
  const path = resolve(output, name);
  const temporary = `${path}.tmp`;
  writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`);
  renameSync(temporary, path);
}
console.log("local-word-v15-offline-artifact", JSON.stringify({ output, meta, meters: {
  inputs: meters.vm.inputs.length,
  maximumOperationCost: meters.vm.maximumOperationCost,
  tightestOperationCost: meters.vm.tightestOperationCost,
} }));

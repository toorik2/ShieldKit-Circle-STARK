import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, relative, resolve } from "node:path";
import { LOCAL_WORD_V15_CONSTRUCTION_ID_HEX } from
  "../src/backends/circle/local-word-construction-v15.ts";

export const LOCAL_WORD_V15_EXPORT_FOLDER =
  "circle-fri-qm31-t262144-b16-q28-g20-fri9-localword-v15";

const root = process.cwd();
const argument = process.argv.find((value) => value.startsWith("--destination="));
if (argument === undefined) {
  throw new Error("usage: export-local-word-v15.ts --destination=/new/folder");
}
const destination = resolve(argument.slice("--destination=".length));
assert.equal(basename(destination), LOCAL_WORD_V15_EXPORT_FOLDER,
  "local-word export folder name");
assert.equal(existsSync(destination), false, "local-word export destination must not exist");
assert.equal(existsSync(dirname(destination)), true, "local-word export parent must exist");

const documents = [
  ".gitignore",
  "AGENTS.md",
  "ARGUMENT.md",
  "COMPLETENESS.md",
  "GOAL.md",
  "NEXT.md",
  "OBSERVER-LEDGER.md",
  "PRIVACY-AUDIT.md",
  "PROMPT.md",
  "README.md",
  "RULES.md",
  "STATUS.md",
  "SUCCESSOR-CONSTRUCTION.md",
  "UPSTREAM.md",
  "ZK-MEMBRANE.md",
  "lane.json",
  "package-lock.json",
  "package.json",
  "tsconfig.json",
] as const;

const scripts = [
  "scripts/audit-local-word-product-imports.ts",
  "scripts/derive-local-word-verifier-bank-digests.ts",
  "scripts/derive-local-word-verifier-keys.ts",
  "scripts/export-local-word-v15.ts",
  "scripts/prove-local-word-product.ts",
  "scripts/save-local-word-v15-offline-artifact.ts",
] as const;

const focusedTests = [
  "test/canonical-merkle-program.test.ts",
  "test/canonical-merkle.test.ts",
  "test/local-word-air-v14.test.ts",
  "test/local-word-air.test.ts",
  "test/local-word-algebra-vm.test.ts",
  "test/local-word-balanced-vm.test.ts",
  "test/local-word-construction-v15.test.ts",
  "test/local-word-envelope.test.ts",
  "test/local-word-merkle-vm.test.ts",
  "test/local-word-proof-carriers.test.ts",
  "test/local-word-prover-bundle-v15.test.ts",
  "test/local-word-public-statement.test.ts",
  "test/local-word-reference-verifier.test.ts",
  "test/local-word-sealed-proof.test.ts",
  "test/local-word-settlement-vm.test.ts",
  "test/local-word-verifier-bank-digests-v15.test.ts",
  "test/pool-relation-local-word-boundary.test.ts",
  "test/pool-relation-local-word-machine.test.ts",
  "test/sealed-oracle.test.ts",
  "test/sha256-local-word-codec.test.ts",
  "test/sha256-local-word-machine.test.ts",
  "test/sha256-local-word-permutation.test.ts",
  "test/sha256-local-word-vm.test.ts",
] as const;

const evidence = [
  "survey/artifacts/local-word-v15-offline/README.md",
  "survey/artifacts/local-word-v15-offline/meta.json",
  "survey/artifacts/local-word-v15-offline/meters.json",
] as const;

const rust = [
  "crates/circle-fri-worker/Cargo.lock",
  "crates/circle-fri-worker/Cargo.toml",
  "crates/circle-fri-worker/rust-toolchain.toml",
  ...readdirSync(resolve(root, "crates/circle-fri-worker/src"))
    .filter((name) => name.endsWith(".rs"))
    .sort()
    .map((name) => `crates/circle-fri-worker/src/${name}`),
] as const;

function resolveLocalImport(importer: string, specifier: string): string | undefined {
  if (!specifier.startsWith(".")) return undefined;
  const candidate = resolve(dirname(importer), specifier);
  for (const path of [candidate, `${candidate}.ts`, `${candidate}.json`, resolve(candidate, "index.ts")]) {
    if (existsSync(path) && statSync(path).isFile()) return path;
  }
  throw new Error(`unresolved export import ${relative(root, importer)} -> ${specifier}`);
}

function localImports(path: string): string[] {
  const source = readFileSync(path, "utf8");
  const specifiers = new Set<string>();
  for (const expression of [
    /\bfrom\s+["']([^"']+)["']/g,
    /\bimport\s+["']([^"']+)["']/g,
    /\bimport\s*\(\s*["']([^"']+)["']\s*\)/g,
  ]) {
    for (const match of source.matchAll(expression)) specifiers.add(match[1]!);
  }
  return [...specifiers].flatMap((specifier) => {
    const resolved = resolveLocalImport(path, specifier);
    return resolved === undefined ? [] : [resolved];
  });
}

const files = new Set<string>([...documents, ...evidence, ...rust]);
const pending = [...scripts, ...focusedTests].map((path) => resolve(root, path));
while (pending.length > 0) {
  const absolute = pending.pop()!;
  const path = relative(root, absolute);
  if (files.has(path)) continue;
  files.add(path);
  for (const imported of localImports(absolute)) pending.push(imported);
}

const forbidden = [
  "src/backends/circle/air.ts",
  "src/backends/circle/fri.ts",
  "src/backends/circle/observer-view.ts",
  "src/backends/circle/witness-mask.ts",
  "src/chain/bchn-rpc.ts",
  "src/chain/booleanity-kernel.ts",
  "src/chain/broadcast-tx.ts",
  "src/chain/chipnet.ts",
  "src/chain/electrum.ts",
  "src/chain/note-auth-air.ts",
  "src/chain/note-auth-bind.ts",
  "src/chain/send.ts",
  "src/chain/sha-bit-air.ts",
  "src/chain/wallet.ts",
] as const;
for (const path of forbidden) assert.equal(files.has(path), false, `forbidden export ${path}`);

const sorted = [...files].sort();
const entries = sorted.map((path) => {
  const source = resolve(root, path);
  assert.equal(existsSync(source), true, `missing export source ${path}`);
  const bytes = readFileSync(source);
  return {
    path,
    bytes: bytes.length,
    sha256: createHash("sha256").update(bytes).digest("hex"),
  };
});
const totalBytes = entries.reduce((sum, entry) => sum + entry.bytes, 0);
assert.ok(totalBytes < 3_500_000, `local-word export unexpectedly large: ${totalBytes}`);

for (const path of documents.filter((path) => path.endsWith(".md"))) {
  const source = readFileSync(resolve(root, path), "utf8");
  for (const match of source.matchAll(/\]\(([^)]+)\)/g)) {
    const link = match[1]!.split("#", 1)[0]!;
    if (link.length === 0 || /^(?:https?:|mailto:)/.test(link)) continue;
    const target = relative(root, resolve(root, dirname(path), decodeURIComponent(link)));
    const present = link.endsWith("/")
      ? sorted.some((candidate) => candidate.startsWith(`${target}/`))
      : files.has(target);
    assert.equal(present, true, `export document link ${path} -> ${link}`);
  }
}

const sensitivePatterns = [
  /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/,
  /\bgh[pousr]_[A-Za-z0-9_]{20,}\b/,
  /\b(?:5[HJK][1-9A-HJ-NP-Za-km-z]{49}|[KL][1-9A-HJ-NP-Za-km-z]{51})\b/,
  /\b(?:9[1-9A-HJ-NP-Za-km-z]{50}|c[1-9A-HJ-NP-Za-km-z]{51})\b/,
  /\b(?:rpcpassword|rpc_password)\s*[:=]\s*["'][^"'$<{]{4,}["']/i,
] as const;
for (const { path } of entries) {
  const source = readFileSync(resolve(root, path), "utf8");
  for (const pattern of sensitivePatterns) {
    assert.equal(pattern.test(source), false, `sensitive export content ${path}`);
  }
}

mkdirSync(destination);
for (const { path } of entries) {
  const output = resolve(destination, path);
  mkdirSync(dirname(output), { recursive: true });
  copyFileSync(resolve(root, path), output);
}
const manifest = {
  schema: "shieldkit.local-word-v15.export/v1",
  folder: LOCAL_WORD_V15_EXPORT_FOLDER,
  constructionId: LOCAL_WORD_V15_CONSTRUCTION_ID_HEX,
  purpose: "minimal self-contained source, focused tests, and offline evidence",
  exclusions: [
    "historical FRI11 implementation",
    "historical batch-exit and landing implementations",
    "wallet, RPC, funding, broadcast, and Electrum helpers",
    "old proof and transaction artifacts",
    ".local qualification binaries",
    "node_modules and Cargo target output",
  ],
  fileCount: entries.length + 1,
  sourceBytes: totalBytes,
  files: entries,
} as const;
writeFileSync(resolve(destination, "EXPORT-MANIFEST.json"),
  `${JSON.stringify(manifest, null, 2)}\n`);
console.log("local-word-v15-export", JSON.stringify({
  destination,
  constructionId: manifest.constructionId,
  fileCount: manifest.fileCount,
  sourceBytes: manifest.sourceBytes,
}));

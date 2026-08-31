import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, relative, resolve } from "node:path";

const root = process.cwd();
const entry = resolve(root, "scripts/qualify-v17-product.ts");
const forbiddenFiles = new Set([
  "src/backends/circle/air.ts",
  "src/backends/circle/fri.ts",
  "src/backends/circle/observer-view.ts",
  "src/backends/circle/witness-mask.ts",
  "src/chain/booleanity-kernel.ts",
  "src/chain/note-auth-air.ts",
  "src/chain/note-auth-bind.ts",
  "src/chain/sha-bit-air.ts",
]);
const forbiddenSymbols = [
  "FriAuth",
  "maskAuth",
  "openShaBit",
  "occupancyBoolShardsFromNote",
] as const;

function localImports(path: string): string[] {
  const source = readFileSync(path, "utf8");
  const specifiers: string[] = [];
  for (const expression of [
    /\bfrom\s+["']([^"']+)["']/g,
    /\bimport\s+["']([^"']+)["']/g,
  ]) {
    for (const match of source.matchAll(expression)) specifiers.push(match[1]!);
  }
  return specifiers.flatMap((specifier) => {
    if (!specifier.startsWith(".")) return [];
    const candidate = resolve(dirname(path), specifier);
    for (const resolved of [candidate, `${candidate}.ts`, resolve(candidate, "index.ts")]) {
      if (existsSync(resolved)) return [resolved];
    }
    throw new Error(`unresolved local-word product import ${relative(root, path)} -> ${specifier}`);
  });
}

const reachable = new Set<string>();
const parent = new Map<string, string>();
const pending = [entry];
while (pending.length > 0) {
  const path = pending.pop()!;
  if (reachable.has(path)) continue;
  reachable.add(path);
  for (const imported of localImports(path)) {
    if (!parent.has(imported)) parent.set(imported, path);
    pending.push(imported);
  }
}
const relativeReachable = [...reachable].map((path) => relative(root, path)).sort();
const forbiddenReached = relativeReachable.filter((path) => forbiddenFiles.has(path));
if (forbiddenReached.length > 0) {
  const chains = forbiddenReached.map((forbidden) => {
    const chain = [resolve(root, forbidden)];
    while (chain[0] !== entry) chain.unshift(parent.get(chain[0]!)!);
    return chain.map((path) => relative(root, path));
  });
  throw new Error(`forbidden local-word product imports: ${JSON.stringify(chains)}`);
}
for (const path of reachable) {
  const source = readFileSync(path, "utf8");
  for (const symbol of forbiddenSymbols) {
    assert.equal(source.includes(symbol), false,
      `${symbol} reachable through ${relative(root, path)}`);
  }
}
assert.equal(relativeReachable.includes("src/pool/relation-witness.ts"), true);
assert.equal(relativeReachable.includes("src/chain/sha256-primitives.ts"), true);
console.log("local-word-product-import-audit", JSON.stringify({
  entry: relative(root, entry),
  reachableFiles: relativeReachable.length,
  forbiddenFiles: [...forbiddenFiles],
  forbiddenSymbols,
  ...(process.argv.includes("--list") ? { files: relativeReachable } : {}),
}));

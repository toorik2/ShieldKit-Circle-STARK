import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { encodeStatement, type PoolStatement } from "../../pool/statement.ts";
import { bytesToHex, hexToBytes } from "../../pool/bytes.ts";
import { decodeFriProof, type FriProof } from "./fri.ts";

const crateDir = join(dirname(fileURLToPath(import.meta.url)), "../../../crates/circle-fri-worker");

export function rustWorkerManifestPath(): string {
  return join(crateDir, "Cargo.toml");
}

export function rustWorkerAvailable(): boolean {
  return existsSync(rustWorkerManifestPath());
}

export function rustProve(statement: PoolStatement): FriProof {
  const input = JSON.stringify({
    cmd: "prove",
    statementHex: bytesToHex(encodeStatement(statement)),
  });
  const r = spawnSync(
    "cargo",
    ["run", "--quiet", "--manifest-path", rustWorkerManifestPath(), "--"],
    { input, encoding: "utf8", timeout: 120_000 },
  );
  if (r.status !== 0) {
    throw new Error(`rust worker: ${(r.stderr || r.stdout || "exit " + r.status).slice(0, 800)}`);
  }
  const parsed = JSON.parse(r.stdout.trim().split("\n").pop() ?? "{}") as {
    ok?: boolean;
    proofHex?: string;
    error?: string;
  };
  if (!parsed.ok || !parsed.proofHex) throw new Error(parsed.error ?? "rust prove missing proof");
  return decodeFriProof(hexToBytes(parsed.proofHex));
}

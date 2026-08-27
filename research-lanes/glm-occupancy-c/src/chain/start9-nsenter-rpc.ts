/**
 * Consensus-size Chipnet send via Start9 BCHN netns.
 * Secrets come from process env (START9_PASS, store.json on the box). Never log them.
 */
import { spawn } from "node:child_process";
import { mkdtemp, writeFile, unlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import type { BchnRpcConfig, RpcAuth } from "./bchn-rpc.ts";

function env(name: string, fallback?: string): string {
  const v = process.env[name]?.trim() ?? fallback ?? "";
  if (!v) throw new Error(`${name} required for Start9 nsenter RPC`);
  return v;
}

function run(bin: string, args: string[], input?: string): Promise<{ stdout: string; stderr: string; status: number }> {
  return new Promise((resolve, reject) => {
    const child = spawn(bin, args, { windowsHide: true });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d: Buffer) => {
      stdout += d.toString("utf8");
    });
    child.stderr.on("data", (d: Buffer) => {
      stderr += d.toString("utf8");
    });
    child.on("error", reject);
    child.on("close", (status) => resolve({ stdout, stderr, status: status ?? 1 }));
    if (input !== undefined) {
      child.stdin.write(input);
      child.stdin.end();
    }
  });
}

function plinkBase(): string[] {
  const hostkey = process.env.START9_PLINK_HOSTKEY?.trim();
  const args = [
    "-ssh",
    "-batch",
    "-P",
    env("START9_SSH_PORT", "2222"),
    "-l",
    env("START9_USER", "start9"),
    "-pw",
    env("START9_PASS"),
  ];
  if (hostkey) args.push("-hostkey", hostkey);
  args.push(env("START9_HOST", "start9oslinux.local"));
  return args;
}

const REMOTE_HEX = "/tmp/shieldkit-land.hex";
const REMOTE_PY = "/tmp/shieldkit-sendraw.py";

async function upload(local: string, remote: string): Promise<void> {
  const host = `${env("START9_USER", "start9")}@${env("START9_HOST", "start9oslinux.local")}:${remote}`;
  const args = [
    "-batch",
    "-P",
    env("START9_SSH_PORT", "2222"),
    "-pw",
    env("START9_PASS"),
  ];
  const hostkey = process.env.START9_PLINK_HOSTKEY?.trim();
  if (hostkey) args.push("-hostkey", hostkey);
  args.push(local, host);
  const r = await run("pscp", args);
  if (r.status !== 0) throw new Error(`pscp ${remote}: ${(r.stderr || r.stdout).slice(0, 400)}`);
}

export async function start9NsenterPost(_url: string, body: unknown, _auth?: RpcAuth): Promise<unknown> {
  const req = body as { method?: string; params?: unknown[] };
  if (req.method !== "sendrawtransaction") {
    throw new Error(`start9 nsenter only implements sendrawtransaction (got ${req.method})`);
  }
  const hex = req.params?.[0];
  if (typeof hex !== "string" || hex.length < 200) throw new Error("empty hex");
  const dir = await mkdtemp(join(tmpdir(), "land-"));
  const localHex = join(dir, "tx.hex");
  await writeFile(localHex, hex, "utf8");
  const py = fileURLToPath(new URL("../../scripts/start9-sendraw.py", import.meta.url));
  try {
    await upload(localHex, REMOTE_HEX);
    await upload(py, REMOTE_PY);
    const remote = [
      "set -e",
      `BPID=$(sudo pgrep -x bitcoind | head -1)`,
      `test -n "$BPID"`,
      `sudo nsenter -t "$BPID" -n env LAND_HEX=${REMOTE_HEX} python3 ${REMOTE_PY}`,
    ].join(" ; ");
    const r = await run("plink", [...plinkBase(), remote]);
    const out = (r.stdout + r.stderr).trim();
    const line = out.split(/\r?\n/).filter((s) => /^[0-9a-f]{64}$/i.test(s.trim())).pop();
    if (line) return { result: line.trim() };
    throw new Error(`nsenter sendraw: ${out.slice(0, 500) || `status ${r.status}`}`);
  } finally {
    await unlink(localHex).catch(() => undefined);
  }
}

export function start9NsenterRpc(): BchnRpcConfig {
  return { url: "nsenter://bitcoincashd", post: start9NsenterPost };
}

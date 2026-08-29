import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, renameSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { wDeposit, wWithdraw } from "../src/pool/relation-witness.ts";
import { LOCAL_WORD_V15_CONSTRUCTION_ID } from
  "../src/backends/circle/local-word-construction-v15.ts";
import { encodeLocalWordProverBundle } from
  "../src/backends/circle/local-word-prover-bundle.ts";
import { localWordMaximumCanonicalProofBytes } from
  "../src/backends/circle/local-word-sealed-proof.ts";
import { compilePoolLocalShaGraph } from
  "../src/chain/pool-relation-local-word-machine.ts";
import { IncrementalMerkle, NullifierSet, type Note } from "../src/pool/notes.ts";
import { emptyState } from "../src/pool/state.ts";
import { applyDeposit, applyWithdraw } from "../src/pool/transition.ts";

const minerFeeSats = 1_000n;
const note: Note = {
  amountSats: 20_041n,
  rho: new Uint8Array(32).fill(0x41),
  ownerSecret: new Uint8Array(32).fill(0xbe),
};
const depositedFixture = () => applyDeposit({
  state: emptyState(new Uint8Array(32).fill(0x42)),
  notes: new IncrementalMerkle(),
  nullifiers: new NullifierSet(),
}, note);
const deposited = depositedFixture();
const fullBase = depositedFixture();
const full = applyWithdraw(
  fullBase.machine,
  note,
  fullBase.index,
  new Uint8Array(32).fill(0x70),
  note.amountSats,
);
const changeBase = depositedFixture();
const change = applyWithdraw(
  changeBase.machine,
  note,
  changeBase.index,
  new Uint8Array(32).fill(0x70),
  7_777n,
);

const fixtures = [
  {
    profile: 0 as const,
    statement: deposited.statement,
    witness: wDeposit(note, deposited.index, deposited.path),
  },
  {
    profile: 1 as const,
    statement: full.statement,
    witness: wWithdraw(note, fullBase.index, full.path),
  },
  {
    profile: 2 as const,
    statement: change.statement,
    witness: wWithdraw(note, changeBase.index, change.path, change.created),
  },
] as const;

const keys = fixtures.map((fixture) => {
  const graph = compilePoolLocalShaGraph(
    fixture.statement,
    fixture.witness,
    minerFeeSats,
  );
  assert.equal(graph.profile === "deposit" ? 0 : graph.profile === "withdraw-full" ? 1 : 2,
    fixture.profile);
  const bundle = encodeLocalWordProverBundle({
    statement: fixture.statement,
    constructionId: LOCAL_WORD_V15_CONSTRUCTION_ID,
    graph,
    minerFeeSats,
  });
  const worker = spawnSync(
    "cargo",
    [
      "+nightly-2026-01-15",
      "run",
      "--release",
      "--quiet",
      "--manifest-path",
      "crates/circle-fri-worker/Cargo.toml",
    ],
    {
      cwd: process.cwd(),
      input: JSON.stringify({
        cmd: "local-word-verifier-key",
        bundleHex: Buffer.from(bundle).toString("hex"),
      }),
      encoding: "utf8",
      maxBuffer: 64 * 1024 * 1024,
    },
  );
  if (worker.status !== 0) throw new Error(worker.stderr || worker.stdout);
  const result = JSON.parse(worker.stdout.trim()) as {
    readonly ok: boolean;
    readonly profile: number;
    readonly publicWords: number;
    readonly constructionDigestHex: string;
    readonly expectedPreprocessedRootHex: string;
  };
  assert.equal(result.ok, true);
  assert.equal(result.profile, fixture.profile);
  return {
    ...result,
    maximumProofBytes: localWordMaximumCanonicalProofBytes(result.publicWords),
  };
});

mkdirSync(resolve(".local"), { recursive: true });
const path = resolve(".local/local-word-verifier-keys-v15.json");
const temporary = `${path}.tmp`;
writeFileSync(temporary, `${JSON.stringify({ version: 1, keys }, null, 2)}\n`, { mode: 0o600 });
renameSync(temporary, path);
console.log("local-word-verifier-keys", JSON.stringify({ path, keys }));

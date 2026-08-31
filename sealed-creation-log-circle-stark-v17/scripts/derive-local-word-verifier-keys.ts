import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, renameSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { wDeposit, wWithdraw } from "../src/pool/relation-witness.ts";
import { encodeLocalWordProverBundle } from
  "../src/backends/circle/local-word-prover-bundle.ts";
import { localWordMaximumCanonicalProofBytes } from
  "../src/backends/circle/local-word-sealed-proof.ts";
import { compilePoolLocalShaGraph } from
  "../src/chain/pool-relation-local-word-machine.ts";
import { EdgeHistory } from "../src/pool/edge-history.ts";
import type { Note } from "../src/pool/notes.ts";
import { SparseNullifierTree } from "../src/pool/sparse-nullifiers.ts";
import { emptyState } from "../src/pool/state.ts";
import { applyDeposit, applyWithdraw, type PoolMachine } from "../src/pool/transition.ts";

const minerFeeSats = 1_000n;
const poolCategory = new Uint8Array(32).fill(0x42);

/**
 * Verifier-key derivation commits only the relation's preprocessed matrix.
 * The Rust `local-word-verifier-key` command decodes this transcript initial
 * but never consumes it while building that matrix, so the eventual artifact
 * construction ID cannot affect these keys. A zero placeholder avoids a
 * construction-manifest self-reference without pretending it is normative.
 */
const nonNormativeConstructionId = new Uint8Array(32);

const note: Note = {
  amountSats: 20_041n,
  rho: new Uint8Array(32).fill(0x41),
  ownerSecret: new Uint8Array(32).fill(0xbe),
};

function machine(): PoolMachine {
  return {
    state: emptyState(),
    poolCategory,
    history: new EdgeHistory(),
    nullifiers: new SparseNullifierTree(),
  };
}

const depositedFixture = () => applyDeposit(machine(), note);
const deposited = depositedFixture();

const fullBase = depositedFixture();
const full = applyWithdraw(
  fullBase.machine,
  fullBase.created,
  new Uint8Array(32).fill(0x70),
  note.amountSats,
);

const changeBase = depositedFixture();
const change = applyWithdraw(
  changeBase.machine,
  changeBase.created,
  new Uint8Array(32).fill(0x70),
  7_777n,
  { changeRho: new Uint8Array(32).fill(0x43) },
);

const fixtures = [
  {
    profile: 0 as const,
    statement: deposited.statement,
    witness: wDeposit(note),
  },
  {
    profile: 1 as const,
    statement: full.statement,
    witness: wWithdraw({
      note: full.spent.note,
      creationIndex: full.spent.creationIndex,
      previousHead: full.spent.previousHead,
      path: full.membership.path,
    }),
  },
  {
    profile: 2 as const,
    statement: change.statement,
    witness: wWithdraw({
      note: change.spent.note,
      creationIndex: change.spent.creationIndex,
      previousHead: change.spent.previousHead,
      path: change.membership.path,
    }, change.change?.note),
  },
] as const;

const keys = fixtures.map((fixture) => {
  const graph = compilePoolLocalShaGraph(
    fixture.statement,
    fixture.witness,
    minerFeeSats,
  );
  assert.equal(
    graph.profile === "deposit" ? 0 : graph.profile === "withdraw-full" ? 1 : 2,
    fixture.profile,
  );
  const bundle = encodeLocalWordProverBundle({
    statement: fixture.statement,
    constructionId: nonNormativeConstructionId,
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
  if (worker.status !== 0) {
    throw new Error([worker.stderr, worker.stdout].filter((value) => value.length > 0).join("\n"));
  }
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
const path = resolve(".local/local-word-verifier-keys-v17.json");
const temporary = `${path}.tmp`;
writeFileSync(temporary, `${JSON.stringify({ version: 17, keys }, null, 2)}\n`, { mode: 0o600 });
renameSync(temporary, path);
console.log("local-word-v17-verifier-keys", JSON.stringify({ path, keys }));

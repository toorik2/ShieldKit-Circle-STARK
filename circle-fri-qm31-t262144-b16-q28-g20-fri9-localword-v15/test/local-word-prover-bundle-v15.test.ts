import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { describe, it } from "node:test";
import { wDeposit, wWithdraw } from "../src/pool/relation-witness.ts";
import { LOCAL_WORD_V15_CONSTRUCTION_ID } from
  "../src/backends/circle/local-word-construction-v15.ts";
import { encodeLocalWordProverBundle } from
  "../src/backends/circle/local-word-prover-bundle.ts";
import { LOCAL_WORD_PRODUCTION_PARAMETERS } from
  "../src/backends/circle/local-word-successor-params.ts";
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

function depositedFixture() {
  return applyDeposit({
    state: emptyState(new Uint8Array(32).fill(0x42)),
    notes: new IncrementalMerkle(),
    nullifiers: new NullifierSet(),
  }, note);
}

function fixtures() {
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
  return [
    {
      profile: 0,
      statement: deposited.statement,
      witness: wDeposit(note, deposited.index, deposited.path),
    },
    {
      profile: 1,
      statement: full.statement,
      witness: wWithdraw(note, fullBase.index, full.path),
    },
    {
      profile: 2,
      statement: change.statement,
      witness: wWithdraw(note, changeBase.index, change.path, change.created),
    },
  ] as const;
}

describe("local-word v15 prover bundle", () => {
  it("uses the fixed 2^18 relation domain for every action profile", () => {
    const bundles = fixtures().map((fixture) => {
      const graph = compilePoolLocalShaGraph(
        fixture.statement,
        fixture.witness,
        minerFeeSats,
      );
      const bundle = encodeLocalWordProverBundle({
        statement: fixture.statement,
        constructionId: LOCAL_WORD_V15_CONSTRUCTION_ID,
        graph,
        minerFeeSats,
      });
      assert.equal(new TextDecoder().decode(bundle.subarray(0, 4)), "SKLB");
      assert.equal(bundle[4], 1);
      assert.equal(bundle[5], fixture.profile);
      assert.equal(new DataView(bundle.buffer, bundle.byteOffset, bundle.byteLength)
        .getUint32(6, false), 2 ** LOCAL_WORD_PRODUCTION_PARAMETERS.relationLog);
      return bundle;
    });

    // Profile 1 used to be rejected because its minimal graph domain was
    // smaller than the fixed production domain. Exercise the Rust decoder and
    // fixed-row relation builder, not just the TypeScript header.
    const checked = spawnSync(
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
          cmd: "local-word-bundle-kat",
          bundleHex: Buffer.from(bundles[1]!).toString("hex"),
        }),
        encoding: "utf8",
        maxBuffer: 64 * 1024 * 1024,
      },
    );
    assert.equal(checked.status, 0, checked.stderr || checked.stdout);
    const result = JSON.parse(checked.stdout.trim()) as {
      readonly ok: boolean;
      readonly interactionPreflight: boolean;
    };
    assert.equal(result.ok, true);
    assert.equal(result.interactionPreflight, true);
  });
});

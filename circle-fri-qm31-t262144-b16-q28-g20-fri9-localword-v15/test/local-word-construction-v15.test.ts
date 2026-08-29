import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, it } from "node:test";
import {
  LOCAL_WORD_CONSTRUCTION_VERSION,
  LOCAL_WORD_V15_COMPONENTS,
  LOCAL_WORD_V15_CONSTRUCTION_ID,
  LOCAL_WORD_V15_CONSTRUCTION_ID_HEX,
  encodeLocalWordV15ConstructionManifest,
} from "../src/backends/circle/local-word-construction-v15.ts";
import { LOCAL_WORD_PROOF_VERSION } from
  "../src/backends/circle/local-word-sealed-proof.ts";
import { LOCAL_WORD_RELATION_CONSTRUCTION_VERSION } from
  "../src/chain/sha256-local-word-codec.ts";
import { sha256 } from "../src/pool/bytes.ts";

const ROOT = new URL("../", import.meta.url);
const EXPECTED_ID = "8d583c84312f7c79519b65bf374dc2ffb6597544a504d88a587c578f9bed2133";
const RULES_SHA256 = "49542e5f5fc9a13a16a3e205fe1408b1cfca49311c1f4e2613527d530fed9db5";

describe("local-word construction v15 identity", () => {
  it("binds every normative component byte-for-byte", () => {
    assert.equal(LOCAL_WORD_CONSTRUCTION_VERSION, 15);
    assert.equal(LOCAL_WORD_PROOF_VERSION, 15);
    assert.equal(LOCAL_WORD_RELATION_CONSTRUCTION_VERSION, 15);
    assert.equal(new Set(LOCAL_WORD_V15_COMPONENTS.map(({ role }) => role)).size,
      LOCAL_WORD_V15_COMPONENTS.length);
    assert.equal(new Set(LOCAL_WORD_V15_COMPONENTS.map(({ path }) => path)).size,
      LOCAL_WORD_V15_COMPONENTS.length);
    assert.deepEqual(LOCAL_WORD_V15_COMPONENTS.map(({ role }) => role), [
      "rules",
      "membrane",
      "completeness",
      "construction-document",
      "parameters",
      "transcript",
      "proof-codec",
      "prover-codec",
      "verifier-keys",
      "relation-codec",
      "soundness",
      "carrier-codec",
      "carrier-allocation",
      "verifier-manifest",
    ]);

    for (const component of LOCAL_WORD_V15_COMPONENTS) {
      const bytes = readFileSync(fileURLToPath(new URL(component.path, ROOT)));
      const actual = createHash("sha256").update(bytes).digest("hex");
      assert.equal(actual, component.sha256Hex, component.role + ":" + component.path);
    }
    assert.equal(LOCAL_WORD_V15_COMPONENTS.find(({ role }) => role === "rules")?.sha256Hex,
      RULES_SHA256);
  });

  it("has one pinned canonical family identifier", () => {
    const manifest = encodeLocalWordV15ConstructionManifest();
    assert.equal(manifest.length, 1276);
    assert.deepEqual(sha256(manifest), LOCAL_WORD_V15_CONSTRUCTION_ID);
    assert.equal(LOCAL_WORD_V15_CONSTRUCTION_ID_HEX, EXPECTED_ID);
  });
});

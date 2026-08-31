import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  LOCAL_WORD_V16_COMPONENTS,
  LOCAL_WORD_V16_CONSTRUCTION_ID_HEX,
} from "../src/backends/circle/local-word-construction-v16.ts";

const EXPECTED_ID = "f29ef06d0e2868a4e6207f060b6246fd49a51fabd0bd14e7d41b48324a1e70e5";

describe("local-word v16 construction identity", () => {
  it("preserves the historical frozen manifest without treating v17 files as v16", () => {
    assert.equal(LOCAL_WORD_V16_COMPONENTS.length, 61);
    assert.equal(LOCAL_WORD_V16_CONSTRUCTION_ID_HEX, EXPECTED_ID);
    const names = new Set<string>();
    const paths = new Set<string>();
    for (const component of LOCAL_WORD_V16_COMPONENTS) {
      assert.equal(names.has(component.name), false, component.name);
      assert.equal(paths.has(component.path), false, component.path);
      names.add(component.name);
      paths.add(component.path);
      assert.match(component.sha256Hex, /^[0-9a-f]{64}$/, component.path);
    }
    assert.equal(paths.has("src/backends/circle/local-word-construction-v16.ts"), false);
    assert.equal(paths.has("src/chain/local-word-verifier-bank-digests-v16.ts"), false);
  });
});

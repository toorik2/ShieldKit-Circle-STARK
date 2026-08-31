import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  LOCAL_WORD_AIR_CONSTRAINTS,
  LOCAL_WORD_AIR_PARTIAL_WIDTHS,
  LOCAL_WORD_INTERACTION_QM31_COLUMNS,
  LOCAL_WORD_PREPROCESSED_COLUMNS,
  combineLocalWordAirCompositionPartials,
  localWordAirCompositionPartials,
  localWordAirResiduals,
  mixLocalWordAirResiduals,
} from "../src/backends/circle/local-word-air.ts";
describe("production local-word AIR", () => {
  it("has one neutral, frozen quadratic interface", () => {
    assert.equal(LOCAL_WORD_AIR_CONSTRAINTS, 25);
    assert.deepEqual(LOCAL_WORD_AIR_PARTIAL_WIDTHS, [9, 8, 8]);
    assert.equal(LOCAL_WORD_PREPROCESSED_COLUMNS, 43);
    assert.equal(LOCAL_WORD_INTERACTION_QM31_COLUMNS, 17);
    assert.equal(typeof localWordAirResiduals, "function");
    assert.equal(typeof mixLocalWordAirResiduals, "function");
    assert.equal(typeof localWordAirCompositionPartials, "function");
    assert.equal(typeof combineLocalWordAirCompositionPartials, "function");
  });
});

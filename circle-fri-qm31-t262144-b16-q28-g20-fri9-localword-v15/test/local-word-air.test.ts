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
import {
  LOCAL_WORD_V14_AIR_CONSTRAINTS,
  LOCAL_WORD_V14_AIR_PARTIAL_WIDTHS,
  LOCAL_WORD_V14_INTERACTION_QM31_COLUMNS,
  LOCAL_WORD_V14_PREPROCESSED_COLUMNS,
  combineLocalWordV14AirCompositionPartials,
  localWordV14AirCompositionPartials,
  localWordV14AirResiduals,
  mixLocalWordV14AirResiduals,
} from "../src/backends/circle/local-word-air-v14.ts";

describe("production local-word AIR", () => {
  it("is exactly the exhaustively tested word-compressed v14 AIR", () => {
    assert.equal(LOCAL_WORD_AIR_CONSTRAINTS, 25);
    assert.deepEqual(LOCAL_WORD_AIR_PARTIAL_WIDTHS, [9, 8, 8]);
    assert.equal(LOCAL_WORD_PREPROCESSED_COLUMNS, 43);
    assert.equal(LOCAL_WORD_INTERACTION_QM31_COLUMNS, 17);
    assert.equal(LOCAL_WORD_AIR_CONSTRAINTS, LOCAL_WORD_V14_AIR_CONSTRAINTS);
    assert.equal(LOCAL_WORD_AIR_PARTIAL_WIDTHS, LOCAL_WORD_V14_AIR_PARTIAL_WIDTHS);
    assert.equal(LOCAL_WORD_PREPROCESSED_COLUMNS, LOCAL_WORD_V14_PREPROCESSED_COLUMNS);
    assert.equal(LOCAL_WORD_INTERACTION_QM31_COLUMNS, LOCAL_WORD_V14_INTERACTION_QM31_COLUMNS);
    assert.equal(localWordAirResiduals, localWordV14AirResiduals);
    assert.equal(mixLocalWordAirResiduals, mixLocalWordV14AirResiduals);
    assert.equal(localWordAirCompositionPartials, localWordV14AirCompositionPartials);
    assert.equal(combineLocalWordAirCompositionPartials, combineLocalWordV14AirCompositionPartials);
  });
});

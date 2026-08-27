import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { circleFriPlugin } from "../src/backends/circle/plugin.ts";
import { FRI_N, FRI_QUERIES, TRACE_LEN } from "../src/backends/circle/params.ts";
import { soundnessWorksheet } from "../src/backends/circle/soundness.ts";

describe("soundness worksheet gates the old n=32/q=8 stub", () => {
  it("is not the unsound bench and meets the 100-bit floor", () => {
    const w = soundnessWorksheet();
    assert.notEqual(FRI_N, 32);
    assert.notEqual(FRI_QUERIES, 8);
    assert.ok(w.conjecturalBits >= 100, `bits ${w.conjecturalBits}`);
    assert.equal(w.sound, true);
    assert.equal(circleFriPlugin.sound, true);
    assert.ok(TRACE_LEN >= 32);
    assert.notEqual(circleFriPlugin.vkId, "circle-fri-m31-bench-n32-q8");
  });
});

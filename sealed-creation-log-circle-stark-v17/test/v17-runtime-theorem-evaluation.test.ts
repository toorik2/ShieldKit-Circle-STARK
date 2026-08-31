import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  V17_PRODUCTION_ASSURANCE_ROWS,
  evaluateV17ProductionTheorem,
} from "../src/assurance/v17-production-theorem.ts";

const PRODUCT_ROWS = new Set([
  "product-first-reduction-transcript",
  "product-ood-air-role",
  "product-batch-link-roles",
  "product-grouped-fri-transcript",
  "product-mixed-merkle-codec",
]);

describe("v17 runtime theorem evaluation", () => {
  it("qualifies exactly when all identity-bound product correspondences are proved", () => {
    const exact = V17_PRODUCTION_ASSURANCE_ROWS.map((row) => PRODUCT_ROWS.has(row.id)
      ? { ...row, status: "proved" as const, evidence: `exact-product:${row.id}` }
      : row);
    const qualified = evaluateV17ProductionTheorem(exact);
    assert.equal(qualified.qualified, true);
    assert.deepEqual(qualified.reasons, []);
    assert.equal(qualified.assurance.qualified, true);
    assert.equal(qualified.theoremMap.certificate.qualified, true);
    assert.equal(qualified.theoremMap.rounds.length, 14);
    assert.ok(qualified.theoremMap.certificate.endpoints.every(({ passes }) => passes));
  });

  it("fails the all-T theorem closed for every non-qualifying product status", () => {
    for (const status of ["conjectural", "unresolved", "skipped", "cache-only"] as const) {
      const rows = V17_PRODUCTION_ASSURANCE_ROWS.map((row) => PRODUCT_ROWS.has(row.id)
        ? {
          ...row,
          status: row.id === "product-ood-air-role" ? status : "proved" as const,
          evidence: `exact-product:${row.id}`,
        }
        : row);
      const evaluated = evaluateV17ProductionTheorem(rows);
      assert.equal(evaluated.qualified, false, status);
      assert.ok(evaluated.reasons.some((reason) =>
        reason === `assurance:product-ood-air-role:${status}`), status);
      assert.equal(evaluated.theoremMap.certificate.qualified, false, status);
    }
  });
});

import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  assertV17BchnProductGateResult,
  assertV17BchnProductEvidence,
  qualifyV17BchnProduct,
} from "../src/assurance/v17-bchn-product-gate.ts";
import { V17_BOOTSTRAP_AFFINE_ALLOCATION } from
  "../src/chain/v17-affine-allocation.ts";
import { createV17DensityClosureTrace } from
  "../src/construction/v17-density-closure.ts";

describe("v17 BCHN final-product qualification boundary", () => {
  it("refuses to begin from caller-supplied final infrastructure", () => {
    assert.throws(() => qualifyV17BchnProduct({
      assayExecutablePath: "/must-not-run",
      artifacts: [],
      canonicalProduct: {
        proofs: [],
        allocation: V17_BOOTSTRAP_AFFINE_ALLOCATION,
        postLinkEvidence: [],
        densityTrace: createV17DensityClosureTrace(),
      },
      // A structural OP_TRUE bank has no API path into the qualifier. The gate
      // starts by recompiling the canonical verifier programs from exact keys.
    }), /verifier-key order/);
  });

  it("rejects evidence that was not emitted by the complete gate", () => {
    assert.throws(
      () => assertV17BchnProductEvidence({} as never),
      /Cannot destructure|integrity/,
    );
  });

  it("rejects an external final trace that does not open the receipt root", () => {
    assert.throws(() => assertV17BchnProductGateResult({
      evidence: {
        finalDensityTraceRootSha256Hex: "ff".repeat(32),
        finalDensityRowsSha256Hex: "ee".repeat(32),
      } as never,
      finalDensityTrace: createV17DensityClosureTrace(),
    }), /gate result final density trace/);
  });
});

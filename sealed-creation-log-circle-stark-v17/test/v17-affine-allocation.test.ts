import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  V17_AFFINE_SEQUENCE_BASE,
  V17_BOOTSTRAP_AFFINE_ALLOCATION,
  decodeV17AffineBoundarySequence,
  v17AffineBoundarySequence,
  v17AffineCarrierBounds,
} from "../src/chain/v17-affine-allocation.ts";

describe("v17 base-plus-bounded-elastic proof allocation", () => {
  it("covers the bootstrap endpoint and representative elastic lengths once, in order", () => {
    const allocation = V17_BOOTSTRAP_AFFINE_ALLOCATION;
    const lengths = [
      allocation.minimumProofBytes,
      allocation.minimumProofBytes + 1,
      Math.floor((allocation.minimumProofBytes + allocation.maximumProofBytes) / 2),
      allocation.maximumProofBytes - 1,
      allocation.maximumProofBytes,
    ];
    for (const proofLength of lengths) {
      let cursor = 0;
      allocation.assignments.forEach((assignment, index) => {
        const [start, end] = v17AffineCarrierBounds(allocation, proofLength, index);
        assert.equal(start, cursor);
        assert.ok(end > start, assignment.roleId);
        cursor = end;
      });
      assert.equal(cursor, proofLength);
    }
  });

  it("round-trips every internal boundary through one disabled sequence", () => {
    const allocation = V17_BOOTSTRAP_AFFINE_ALLOCATION;
    for (let boundary = 1; boundary < allocation.assignments.length; boundary += 1) {
      const sequence = v17AffineBoundarySequence(allocation, boundary);
      const decoded = decodeV17AffineBoundarySequence(sequence);
      assert.ok(sequence >= V17_AFFINE_SEQUENCE_BASE && sequence <= 0xffff_ffff);
      assert.deepEqual(decoded, {
        basePrefix: allocation.assignments[boundary]!.basePrefixStart,
        elasticPrefix: allocation.assignments[boundary]!.elasticPrefixStart,
      });
    }
  });

  it("locks the exact counterexample that makes a fixed fraction impossible", () => {
    const lowerProofBytes = 444_832;
    const upperProofBytes = 457_514;
    const scale = 65_536;
    const required = 9_222;
    const capacity = 9_246;
    const minimumWidth = Math.floor((required - 1) * scale / lowerProofBytes) + 1;
    assert.equal(minimumWidth, 1_359);
    assert.ok(Math.floor(upperProofBytes * minimumWidth / scale) > capacity);
  });
});

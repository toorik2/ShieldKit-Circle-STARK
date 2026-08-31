import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { onCircle } from "../src/backends/circle/group.ts";
import {
  bitReverseIndex,
  successorCirclePointAt,
  successorCirclePointAtBitReversed,
  successorLineXAtBitReversed,
  successorTraceOffsetIndex,
} from "../src/backends/circle/successor-domain.ts";

describe("pinned Stwo successor domains", () => {
  it("uses the canonical conjugate circle ordering", () => {
    for (const logSize of [6, 13, 18]) {
      const half = 2 ** (logSize - 1);
      for (const index of [0, 1, 7, half - 1]) {
        const point = successorCirclePointAt(logSize, index);
        const conjugate = successorCirclePointAt(logSize, index + half);
        assert.equal(onCircle(point), true);
        assert.equal(conjugate.x, point.x);
        assert.equal((conjugate.y + point.y) % 2147483647n, 0n);
      }
    }
  });

  it("maps bit-reversed points, line x values, and trace rotations exactly", () => {
    assert.deepEqual(successorCirclePointAtBitReversed(6, 13), successorCirclePointAt(6, bitReverseIndex(13, 6)));
    assert.notEqual(successorLineXAtBitReversed(5, 0), 0n);
    for (const index of [0, 1, 17, 12345, 262143]) {
      assert.equal(successorTraceOffsetIndex(index, 13, 18, 0), index);
      const next = successorTraceOffsetIndex(index, 13, 18, 1);
      assert.equal(successorTraceOffsetIndex(next, 13, 18, -1), index);
    }
  });
});

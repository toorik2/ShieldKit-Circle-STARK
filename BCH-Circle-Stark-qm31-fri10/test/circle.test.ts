import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { add, inv, mul, M31 } from "../src/backends/circle/m31.ts";
import {
  CIRCLE_GEN,
  CIRCLE_ONE,
  addPoints,
  doublePoint,
  onCircle,
  projectPi,
  scalarMul,
} from "../src/backends/circle/group.ts";
import { conjugate, foldPair } from "../src/backends/circle/fold.ts";

describe("M31", () => {
  it("mul/add wrap at p", () => {
    assert.equal(add(M31 - 1n, 2n), 1n);
    assert.equal(mul(2n, inv(2n)), 1n);
  });
});

describe("circle group", () => {
  it("generator is on x^2+y^2=1", () => {
    assert.ok(onCircle(CIRCLE_GEN));
    assert.ok(onCircle(CIRCLE_ONE));
  });

  it("add is associative enough for 8-doublings", () => {
    let p = CIRCLE_GEN;
    for (let i = 0; i < 8; i += 1) {
      const d = doublePoint(p);
      assert.deepEqual(d, addPoints(p, p));
      assert.ok(onCircle(d));
      p = d;
    }
  });

  it("π is doubling", () => {
    const p = scalarMul(CIRCLE_GEN, 5n);
    assert.deepEqual(projectPi(p), doublePoint(p));
  });

  it("[n]G + [m]G = [n+m]G", () => {
    const a = scalarMul(CIRCLE_GEN, 17n);
    const b = scalarMul(CIRCLE_GEN, 9n);
    assert.deepEqual(addPoints(a, b), scalarMul(CIRCLE_GEN, 26n));
  });
});

describe("one Circle FRI fold", () => {
  it("even function is invariant in the odd slot", () => {
    const p = scalarMul(CIRCLE_GEN, 3n);
    const q = conjugate(p);
    assert.equal(p.x, q.x);
    assert.equal(p.y + q.y, 2147483647n);
    const fEven = 11n;
    const folded = foldPair(p, fEven, fEven, 99n);
    assert.ok(onCircle(folded.domain));
    assert.equal(folded.value, fEven);
  });
});

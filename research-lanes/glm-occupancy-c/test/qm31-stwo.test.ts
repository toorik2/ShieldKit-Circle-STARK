import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { FRI_N, FRI_QUERIES } from "../src/backends/circle/params.ts";
import { M31 } from "../src/backends/circle/m31.ts";
import {
  cmAdd,
  cmInv,
  cmMul,
  cm31,
  liftM31,
  qm31,
  qmAdd,
  qmEq,
  qmInv,
  qmMul,
  qmMulM31,
  qmNeg,
  qmSub,
  QM31_ONE,
} from "../src/backends/circle/qm31.ts";

const P = M31;

describe("Stwo KATs for CM31/QM31", () => {
  it("refuses the unsound n=32/q=8 bench", () => {
    assert.notEqual(FRI_N, 32);
    assert.notEqual(FRI_QUERIES, 8);
  });

  it("CM31: (1+2i)(4+5i) = (P-6)+13i  (Stwo cm31.rs)", () => {
    const prod = cmMul(cm31(1n, 2n), cm31(4n, 5n));
    assert.deepEqual(prod, cm31(P - 6n, 13n));
    assert.deepEqual(cmAdd(cm31(1n, 2n), cm31(4n, 5n)), cm31(5n, 7n));
  });

  it("CM31 inverse: (1+2i) * inv = 1", () => {
    const z = cm31(1n, 2n);
    const w = cmInv(z);
    assert.deepEqual(cmMul(z, w), cm31(1n, 0n));
  });

  it("QM31 ops match Stwo qm31.rs test_ops", () => {
    const qm0 = qm31(1n, 2n, 3n, 4n);
    const qm1 = qm31(4n, 5n, 6n, 7n);
    assert.deepEqual(qmAdd(qm0, qm1), qm31(5n, 7n, 9n, 11n));
    assert.deepEqual(qmMul(qm0, qm1), qm31(P - 71n, 93n, P - 16n, 50n));
    assert.deepEqual(qmNeg(qm0), qm31(P - 1n, P - 2n, P - 3n, P - 4n));
    assert.deepEqual(qmSub(qm0, qm1), qm31(P - 3n, P - 3n, P - 3n, P - 3n));
  });

  it("QM31 inverse: (1,2,3,4) * inv = 1  (Stwo test_inverse)", () => {
    const qm = qm31(1n, 2n, 3n, 4n);
    const inv = qmInv(qm);
    assert.equal(qmEq(qmMul(qm, inv), QM31_ONE), true);
  });

  it("QM31 * M31 is the first-fold scalar mix", () => {
    const λ = qm31(1n, 2n, 3n, 4n);
    const odd = 8n;
    assert.deepEqual(qmMulM31(λ, odd), qmMul(λ, liftM31(odd)));
  });
});

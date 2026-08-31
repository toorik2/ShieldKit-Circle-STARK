import assert from "node:assert/strict";
import test from "node:test";
import {
  localWordAirResiduals,
  mixLocalWordAirResiduals,
} from "../src/backends/circle/local-word-air.ts";
import type { LocalWordInteractionChallenges } from
  "../src/backends/circle/local-word-transcript.ts";
import {
  QM31_ONE,
  QM31_ZERO,
  liftM31,
  qmAdd,
  qmEq,
  qmInv,
  qmMul,
  qmSub,
  type QM31El,
} from "../src/backends/circle/qm31.ts";
import { successorCirclePointAtBitReversed } from
  "../src/backends/circle/successor-domain.ts";
import {
  liftCirclePoint,
  v17CayleyPoint,
  v17EvaluationQuotient,
  v17PointVanishing,
} from "../src/backends/circle/v17-oods.ts";
import {
  V17_DEGREE_CORRECTED_BATCH_WIDTH,
  V17_OOD_FUNCTION_COUNT,
  v17DegreeCorrectedBatchValue,
  v17DegreeCorrectedBatchIdentity,
  v17MixOodAirResiduals,
  v17OodAirQuotientIdentity,
  v17OodAirResiduals,
  v17OodFunctionValues,
  v17TraceVanishingAtPoint,
} from "../src/backends/circle/v17-ood-air.ts";

const q = (seed: number): QM31El => [
  BigInt(seed + 1),
  BigInt(seed + 2),
  BigInt(seed + 3),
  BigInt(seed + 4),
];

function challenges(): LocalWordInteractionChallenges {
  let seed = 10;
  const next = () => q(seed++);
  return {
    lookup: {
      gamma: next(),
      tuple: Array.from({ length: 6 }, next) as unknown as
        LocalWordInteractionChallenges["lookup"]["tuple"],
    },
    wordCopy: {
      gamma: next(),
      identity: next(),
      limbs: Array.from({ length: 8 }, next) as unknown as
        LocalWordInteractionChallenges["wordCopy"]["limbs"],
    },
    boundary: {
      gamma: next(),
      identity: next(),
      limbs: Array.from({ length: 8 }, next) as unknown as
        LocalWordInteractionChallenges["boundary"]["limbs"],
    },
  };
}

test("v17 OOD AIR is the scalar AIR extension on lifted base-domain rows", () => {
  const original = Array.from({ length: 34 }, (_, index) => BigInt((index * 7 + 3) % 17));
  const preprocessed = Array.from({ length: 43 }, (_, index) => BigInt((index * 5 + 1) % 13));
  const interaction = Array.from({ length: 17 }, (_, index) => q(100 + index * 5));
  const interactionPrevious = Array.from({ length: 17 }, (_, index) => q(300 + index * 5));
  const cs = challenges();
  const claimedSum = q(900);
  const base = localWordAirResiduals({
    original,
    preprocessed,
    interaction,
    interactionPrevious,
  }, cs, claimedSum);
  const ood = v17OodAirResiduals({
    original: original.map(liftM31),
    preprocessed: preprocessed.map(liftM31),
    interaction,
    interactionPrevious,
  }, cs, claimedSum);
  assert.deepEqual(ood, base);
  const alpha = q(1200);
  assert.ok(qmEq(v17MixOodAirResiduals(ood, alpha), mixLocalWordAirResiduals(base, alpha)));
});

test("v17 function list is exactly 98 claims and includes only three translated globals", () => {
  const frame = {
    preprocessed: Array.from({ length: 43 }, (_, index) => q(index)),
    original: Array.from({ length: 34 }, (_, index) => q(100 + index)),
    interaction: Array.from({ length: 17 }, (_, index) => q(200 + index)),
    interactionPrevious: Array.from({ length: 17 }, (_, index) => q(300 + index)),
  };
  const values = v17OodFunctionValues(frame, q(999));
  assert.equal(V17_OOD_FUNCTION_COUNT, 98);
  assert.equal(V17_DEGREE_CORRECTED_BATCH_WIDTH, 197);
  assert.equal(values.length, 98);
  assert.deepEqual(values.slice(-4), [frame.interactionPrevious[8],
    frame.interactionPrevious[14], frame.interactionPrevious[16], q(999)]);
});

test("one OOD role checks all residuals against one whole quotient", () => {
  const frame = {
    preprocessed: Array.from({ length: 43 }, (_, index) => q(index)),
    original: Array.from({ length: 34 }, (_, index) => q(100 + index)),
    interaction: Array.from({ length: 17 }, (_, index) => q(200 + index)),
    interactionPrevious: Array.from({ length: 17 }, (_, index) => q(300 + index)),
  };
  const cs = challenges();
  const claimedSum = q(800);
  const alpha = q(900);
  const oodPoint = v17CayleyPoint(q(1_000));
  const zerofier = v17TraceVanishingAtPoint(oodPoint, 18);
  assert.equal(qmEq(zerofier, QM31_ZERO), false);
  const composition = v17MixOodAirResiduals(
    v17OodAirResiduals(frame, cs, claimedSum),
    alpha,
  );
  const quotientAtQ = qmMul(composition, qmInv(zerofier));
  const input = {
    frame,
    challenges: cs,
    boundaryClaimedSum: claimedSum,
    constraintAlpha: alpha,
    quotientAtQ,
    oodPoint,
    relationLog: 18,
  } as const;
  assert.equal(v17OodAirQuotientIdentity(input), true);
  assert.equal(v17OodAirQuotientIdentity({
    ...input,
    quotientAtQ: qmAdd(quotientAtQ, q(1)),
  }), false);
});

test("fused degree-corrected batch equals all 197 distinct beta powers", () => {
  const beta = q(2);
  const functionsAtPoint = Array.from({ length: V17_OOD_FUNCTION_COUNT }, (_, index) => q(50 + index));
  const claimsAtQ = Array.from({ length: V17_OOD_FUNCTION_COUNT }, (_, index) => q(300 + index));
  const maskAtPoint = q(700);
  const oodPoint = v17CayleyPoint(q(800));
  const point = liftCirclePoint(successorCirclePointAtBitReversed(10, 17));
  const denominator = v17PointVanishing(oodPoint, point);
  const corrections = functionsAtPoint.map((value, index) =>
    qmMul(qmSub(value, claimsAtQ[index]!), qmInv(denominator)));
  const explicit = [maskAtPoint, ...functionsAtPoint, ...corrections].reduce(
    ({ sum, power }, value) => ({
      sum: qmAdd(sum, qmMul(power, value)),
      power: qmMul(power, beta),
    }),
    { sum: QM31_ZERO, power: liftM31(1n) },
  ).sum;
  const fused = v17DegreeCorrectedBatchValue({
    beta,
    functionsAtPoint,
    claimsAtQ,
    maskAtPoint,
    oodPoint,
    point,
  });
  assert.ok(qmEq(fused, explicit));
  assert.ok(!qmEq(v17EvaluationQuotient(
    functionsAtPoint[0]!, claimsAtQ[0]!, oodPoint, point,
  ), functionsAtPoint[0]!));
});

test("mask and f0 occupy distinct powers", () => {
  const beta = q(3);
  const oodPoint = v17CayleyPoint(q(900));
  const point = liftCirclePoint(successorCirclePointAtBitReversed(10, 23));
  const functions = Array.from({ length: V17_OOD_FUNCTION_COUNT }, () => QM31_ZERO);
  const claims = Array.from({ length: V17_OOD_FUNCTION_COUNT }, () => QM31_ZERO);
  functions[0] = q(42);
  const cancelledMask = qmSub(QM31_ZERO, functions[0]);
  assert.ok(!qmEq(v17DegreeCorrectedBatchValue({
    beta,
    functionsAtPoint: functions,
    claimsAtQ: claims,
    maskAtPoint: cancelledMask,
    oodPoint,
    point,
  }), QM31_ZERO));
});

test("the inversion-free BCH identity is exactly the fused Protocol-4 batch", () => {
  const beta = q(5);
  const functionsAtPoint = Array.from({ length: V17_OOD_FUNCTION_COUNT }, (_, index) => q(90 + index));
  const claimsAtQ = Array.from({ length: V17_OOD_FUNCTION_COUNT }, (_, index) => q(400 + index));
  const maskAtPoint = q(800);
  const oodT = q(1_100);
  const oodPoint = v17CayleyPoint(oodT);
  const point = liftCirclePoint(successorCirclePointAtBitReversed(10, 41));
  const openedBatch = v17DegreeCorrectedBatchValue({
    beta,
    functionsAtPoint,
    claimsAtQ,
    maskAtPoint,
    oodPoint,
    point,
  });
  const input = {
    beta,
    functionsAtPoint,
    claimsAtQ,
    maskAtPoint,
    openedBatch,
    oodT,
    point,
  } as const;
  assert.equal(v17DegreeCorrectedBatchIdentity(input), true);
  assert.equal(v17DegreeCorrectedBatchIdentity({
    ...input,
    openedBatch: qmAdd(openedBatch, QM31_ONE),
  }), false);
});

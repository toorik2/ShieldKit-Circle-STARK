import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  V17_BOOTSTRAP_AFFINE_ALLOCATION,
  measuredV17AffineAllocation,
  v17AffineBoundary,
} from "../src/chain/v17-affine-allocation.ts";
import {
  V17_AFFINE_READER_PLAN_CERTIFICATION,
  V17_AFFINE_READER_PLAN_GEOMETRY,
  V17_AFFINE_READER_PLAN_SCHEMA,
  buildV17AffineReaderPlan,
  encodeV17AffineReaderPlan,
  locateV17AffineReaderCarrier,
  v17AffineReaderPlanDigestHex,
  v17AffineReaderPlanInterval,
} from "../src/construction/v17-affine-reader-plan.ts";

const allocation = V17_BOOTSTRAP_AFFINE_ALLOCATION;
const plan = buildV17AffineReaderPlan(allocation);

function assertBracketed(proofLength: number, proofOffset: number): void {
  const exactCarrier = locateV17AffineReaderCarrier(
    allocation,
    proofLength,
    proofOffset,
  );
  const interval = v17AffineReaderPlanInterval(plan, proofLength, proofOffset);
  assert.ok(interval.lowCarrier <= exactCarrier, `${proofLength}:${proofOffset}:low`);
  assert.ok(interval.highCarrier >= exactCarrier, `${proofLength}:${proofOffset}:high`);
}

describe("v17 allocation-specialized affine reader plan", () => {
  it("exhaustively certifies every integer proof length and normalized offset cell", () => {
    const proofLengths = allocation.maximumProofBytes - allocation.minimumProofBytes + 1;
    assert.equal(plan.schema, V17_AFFINE_READER_PLAN_SCHEMA);
    assert.equal(plan.certification, V17_AFFINE_READER_PLAN_CERTIFICATION);
    assert.equal(plan.lengthCells, V17_AFFINE_READER_PLAN_GEOMETRY.lengthCells);
    assert.equal(
      plan.normalizedOffsetCells,
      V17_AFFINE_READER_PLAN_GEOMETRY.normalizedOffsetCells,
    );
    assert.equal(plan.certifiedProofLengths, proofLengths);
    assert.equal(
      plan.certifiedNormalizedOffsetCells,
      proofLengths * plan.normalizedOffsetCells,
    );
    assert.equal(plan.certifiedEndpointChecks, proofLengths * plan.normalizedOffsetCells * 2);
    assert.equal(plan.intervals.length, plan.lengthCells * plan.normalizedOffsetCells);
    assert.equal(plan.maximumIntervalCarriers, 33);
    for (const interval of plan.intervals) {
      assert.ok(interval.lowCarrier >= 0);
      assert.ok(interval.highCarrier >= interval.lowCarrier);
      assert.ok(interval.highCarrier < allocation.assignments.length);
    }
  });

  it("brackets exact carrier transitions at every critical length", () => {
    const proofLengthCount = plan.certifiedProofLengths;
    const lengths = new Set<number>([
      allocation.minimumProofBytes,
      allocation.minimumProofBytes + 1,
      Math.floor((allocation.minimumProofBytes + allocation.maximumProofBytes) / 2),
      allocation.maximumProofBytes - 1,
      allocation.maximumProofBytes,
    ]);
    for (let lengthCell = 1; lengthCell < plan.lengthCells; lengthCell += 1) {
      const boundary = allocation.minimumProofBytes +
        Math.ceil(lengthCell * proofLengthCount / plan.lengthCells);
      for (const candidate of [boundary - 1, boundary, boundary + 1]) {
        if (candidate >= allocation.minimumProofBytes &&
          candidate <= allocation.maximumProofBytes) lengths.add(candidate);
      }
    }
    for (const proofLength of lengths) {
      for (let boundaryIndex = 0;
        boundaryIndex <= allocation.assignments.length;
        boundaryIndex += 1) {
        const boundary = v17AffineBoundary(allocation, proofLength, boundaryIndex);
        for (const proofOffset of [boundary - 1, boundary, boundary + 1]) {
          if (proofOffset >= 0 && proofOffset < proofLength) {
            assertBracketed(proofLength, proofOffset);
          }
        }
      }
      for (let offsetCell = 0;
        offsetCell <= plan.normalizedOffsetCells;
        offsetCell += 1) {
        const boundary = Math.ceil(offsetCell * proofLength / plan.normalizedOffsetCells);
        for (const proofOffset of [boundary - 1, boundary]) {
          if (proofOffset >= 0 && proofOffset < proofLength) {
            assertBracketed(proofLength, proofOffset);
          }
        }
      }
    }
  });

  it("emits deterministic canonical bytes bound to the complete allocation identity", () => {
    const duplicate = buildV17AffineReaderPlan(allocation);
    const encoded = encodeV17AffineReaderPlan(plan);
    assert.deepEqual(duplicate, plan);
    assert.deepEqual(encodeV17AffineReaderPlan(duplicate), encoded);
    assert.equal(encoded.length, 279);
    assert.equal(
      plan.allocationSha256Hex,
      "25e79d117a9710c6a915ec6d995a5b447c7f58fbdeefcf0dd900c693555664e9",
    );
    assert.equal(
      v17AffineReaderPlanDigestHex(plan),
      "71fbc21c752482c307213e0d807aa7cc86d6e6e2289d1e98ec002e0eaf570b8c",
    );
    assert.equal(v17AffineReaderPlanDigestHex(duplicate), v17AffineReaderPlanDigestHex(plan));

    const measured = buildV17AffineReaderPlan(
      measuredV17AffineAllocation(allocation.assignments),
    );
    assert.deepEqual(measured.intervals, plan.intervals);
    assert.notEqual(measured.allocationSha256Hex, plan.allocationSha256Hex);
    assert.notEqual(v17AffineReaderPlanDigestHex(measured), v17AffineReaderPlanDigestHex(plan));
  });

  it("rejects addresses outside the certified affine envelope", () => {
    assert.throws(
      () => v17AffineReaderPlanInterval(plan, allocation.minimumProofBytes - 1, 0),
      /plan location/,
    );
    assert.throws(
      () => v17AffineReaderPlanInterval(plan, allocation.minimumProofBytes, -1),
      /plan location/,
    );
    assert.throws(
      () => v17AffineReaderPlanInterval(
        plan,
        allocation.minimumProofBytes,
        allocation.minimumProofBytes,
      ),
      /plan location/,
    );
  });
});

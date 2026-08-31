import { createHash } from "node:crypto";
import {
  type V17AffineAllocation,
  validateV17AffineAllocation,
} from "../chain/v17-affine-allocation.ts";
import {
  bytesToHex,
  concatBytes,
  hexToBytes,
  writeU16BE,
  writeU32BE,
} from "../pool/bytes.ts";
import { canonicalV17Json } from "./v17-graph.ts";

export const V17_AFFINE_READER_PLAN_SCHEMA =
  "ShieldKit/V17AffineReaderPlan/v1" as const;
export const V17_AFFINE_READER_PLAN_CERTIFICATION =
  "all-integer-lengths-monotone-offset-endpoints" as const;

/**
 * A deliberately small, proof-independent address space for partial evaluation
 * of the affine carrier reader. Length is quantized first; the byte offset is
 * then quantized relative to that exact length.
 */
export const V17_AFFINE_READER_PLAN_GEOMETRY = Object.freeze({
  lengthCells: 5,
  normalizedOffsetCells: 21,
} as const);

export type V17AffineReaderPlanGeometry = {
  readonly lengthCells: number;
  readonly normalizedOffsetCells: number;
};

export type V17AffineReaderCarrierInterval = {
  readonly lengthCell: number;
  readonly normalizedOffsetCell: number;
  /** Inclusive carrier index. */
  readonly lowCarrier: number;
  /** Inclusive carrier index. */
  readonly highCarrier: number;
};

export type V17AffineReaderPlan = {
  readonly schema: typeof V17_AFFINE_READER_PLAN_SCHEMA;
  readonly certification: typeof V17_AFFINE_READER_PLAN_CERTIFICATION;
  /** SHA-256 of the complete canonical allocation, including its status. */
  readonly allocationSha256Hex: string;
  readonly minimumProofBytes: number;
  readonly maximumProofBytes: number;
  readonly elasticScaleUnits: number;
  readonly carrierCount: number;
  readonly lengthCells: number;
  readonly normalizedOffsetCells: number;
  readonly certifiedProofLengths: number;
  readonly certifiedNormalizedOffsetCells: number;
  readonly certifiedEndpointChecks: number;
  readonly maximumIntervalCarriers: number;
  /** Canonical order: length cell major, then normalized-offset cell. */
  readonly intervals: readonly V17AffineReaderCarrierInterval[];
};

const PLAN_MAGIC = new TextEncoder().encode("SKV17ARP");
const PLAN_VERSION = 1;

function assertSafeIntegerInRange(
  value: number,
  minimum: number,
  maximum: number,
  label: string,
): void {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(`v17 affine reader ${label}`);
  }
}

function allocationIdentity(allocation: V17AffineAllocation): unknown {
  return {
    status: allocation.status,
    minimumProofBytes: allocation.minimumProofBytes,
    maximumProofBytes: allocation.maximumProofBytes,
    elasticScaleUnits: allocation.elasticScaleUnits,
    assignments: allocation.assignments.map((assignment) => ({ ...assignment })),
  };
}

function allocationDigestHex(allocation: V17AffineAllocation): string {
  return createHash("sha256")
    .update(canonicalV17Json(allocationIdentity(allocation)))
    .digest("hex");
}

function lengthCellFor(
  minimumProofBytes: number,
  maximumProofBytes: number,
  lengthCells: number,
  proofLength: number,
): number {
  const proofLengthCount = maximumProofBytes - minimumProofBytes + 1;
  return Math.min(
    lengthCells - 1,
    Math.floor((proofLength - minimumProofBytes) * lengthCells / proofLengthCount),
  );
}

function normalizedOffsetCellFor(
  normalizedOffsetCells: number,
  proofLength: number,
  proofOffset: number,
): number {
  return Math.min(
    normalizedOffsetCells - 1,
    Math.floor(proofOffset * normalizedOffsetCells / proofLength),
  );
}

function normalizedCellLowOffset(
  proofLength: number,
  normalizedOffsetCells: number,
  normalizedOffsetCell: number,
): number {
  return Math.floor(
    (normalizedOffsetCell * proofLength + normalizedOffsetCells - 1) /
      normalizedOffsetCells,
  );
}

function boundaryUnchecked(
  allocation: V17AffineAllocation,
  proofLength: number,
  boundaryIndex: number,
): number {
  if (boundaryIndex === 0) return 0;
  if (boundaryIndex === allocation.assignments.length) return proofLength;
  const assignment = allocation.assignments[boundaryIndex]!;
  return assignment.basePrefixStart + Math.floor(
    (proofLength - allocation.minimumProofBytes) * assignment.elasticPrefixStart /
      allocation.elasticScaleUnits,
  );
}

function locateCarrierUnchecked(
  allocation: V17AffineAllocation,
  proofLength: number,
  proofOffset: number,
): number {
  let low = 0;
  let high = allocation.assignments.length - 1;
  while (low < high) {
    const middle = Math.floor((low + high) / 2);
    if (proofOffset < boundaryUnchecked(allocation, proofLength, middle + 1)) {
      high = middle;
    } else {
      low = middle + 1;
    }
  }
  return low;
}

/** Return the exact carrier containing one byte of an affine proof envelope. */
export function locateV17AffineReaderCarrier(
  allocation: V17AffineAllocation,
  proofLength: number,
  proofOffset: number,
): number {
  validateV17AffineAllocation(allocation);
  if (!Number.isSafeInteger(proofLength) ||
    proofLength < allocation.minimumProofBytes ||
    proofLength > allocation.maximumProofBytes ||
    !Number.isSafeInteger(proofOffset) || proofOffset < 0 || proofOffset >= proofLength) {
    throw new Error("v17 affine reader location");
  }
  return locateCarrierUnchecked(allocation, proofLength, proofOffset);
}

function validateGeometry(
  allocation: V17AffineAllocation,
  geometry: V17AffineReaderPlanGeometry,
): void {
  assertSafeIntegerInRange(geometry.lengthCells, 1, 0xff, "length cells");
  assertSafeIntegerInRange(
    geometry.normalizedOffsetCells,
    1,
    0xff,
    "normalized offset cells",
  );
  if (geometry.normalizedOffsetCells > allocation.minimumProofBytes) {
    throw new Error("v17 affine reader empty normalized cell");
  }
  if (geometry.lengthCells >
    allocation.maximumProofBytes - allocation.minimumProofBytes + 1) {
    throw new Error("v17 affine reader empty length cell");
  }
  if (allocation.assignments.length > 0x100) {
    throw new Error("v17 affine reader carrier byte width");
  }
}

/**
 * Build the exact minimal carrier bracket for every quantized address cell.
 *
 * Every integer proof length in [R,U] is visited. For each normalized-offset
 * cell at that length, the exact first and last integer offsets are located.
 * Affine carrier boundaries are ordered, so carrier(offset) is monotone: these
 * two endpoint checks are a complete proof for every byte in the cell, not a
 * sample. Taking extrema over all lengths makes each emitted interval exact.
 */
export function buildV17AffineReaderPlan(
  candidate: V17AffineAllocation,
  geometry: V17AffineReaderPlanGeometry = V17_AFFINE_READER_PLAN_GEOMETRY,
): V17AffineReaderPlan {
  const allocation = validateV17AffineAllocation(candidate);
  validateGeometry(allocation, geometry);
  const intervalCount = geometry.lengthCells * geometry.normalizedOffsetCells;
  const lows = new Int16Array(intervalCount);
  lows.fill(0x7fff);
  const highs = new Int16Array(intervalCount);
  highs.fill(-1);
  const proofLengthCount =
    allocation.maximumProofBytes - allocation.minimumProofBytes + 1;

  for (let proofLength = allocation.minimumProofBytes;
    proofLength <= allocation.maximumProofBytes;
    proofLength += 1) {
    const lengthCell = lengthCellFor(
      allocation.minimumProofBytes,
      allocation.maximumProofBytes,
      geometry.lengthCells,
      proofLength,
    );
    // Offset-cell endpoints are already ordered, so one monotone carrier walk
    // replaces independent searches without weakening the exhaustive proof.
    let carrier = 0;
    let nextBoundary = boundaryUnchecked(allocation, proofLength, 1);
    for (let offsetCell = 0;
      offsetCell < geometry.normalizedOffsetCells;
      offsetCell += 1) {
      const lowOffset = normalizedCellLowOffset(
        proofLength,
        geometry.normalizedOffsetCells,
        offsetCell,
      );
      const highOffset = normalizedCellLowOffset(
        proofLength,
        geometry.normalizedOffsetCells,
        offsetCell + 1,
      ) - 1;
      while (carrier < allocation.assignments.length - 1 && lowOffset >= nextBoundary) {
        carrier += 1;
        nextBoundary = boundaryUnchecked(allocation, proofLength, carrier + 1);
      }
      const lowCarrier = carrier;
      while (carrier < allocation.assignments.length - 1 && highOffset >= nextBoundary) {
        carrier += 1;
        nextBoundary = boundaryUnchecked(allocation, proofLength, carrier + 1);
      }
      const intervalIndex =
        lengthCell * geometry.normalizedOffsetCells + offsetCell;
      lows[intervalIndex] = Math.min(lows[intervalIndex]!, lowCarrier);
      highs[intervalIndex] = Math.max(highs[intervalIndex]!, carrier);
    }
  }

  const intervals = Array.from({ length: intervalCount }, (_, intervalIndex) => {
    const lengthCell = Math.floor(intervalIndex / geometry.normalizedOffsetCells);
    const normalizedOffsetCell = intervalIndex % geometry.normalizedOffsetCells;
    const lowCarrier = lows[intervalIndex]!;
    const highCarrier = highs[intervalIndex]!;
    if (lowCarrier < 0 || highCarrier < lowCarrier ||
      highCarrier >= allocation.assignments.length) {
      throw new Error(
        `v17 affine reader uncertified cell ${lengthCell}:${normalizedOffsetCell}`,
      );
    }
    return Object.freeze({
      lengthCell,
      normalizedOffsetCell,
      lowCarrier,
      highCarrier,
    });
  });
  const maximumIntervalCarriers = Math.max(
    ...intervals.map((interval) => interval.highCarrier - interval.lowCarrier + 1),
  );
  const certifiedNormalizedOffsetCells =
    proofLengthCount * geometry.normalizedOffsetCells;
  const certifiedEndpointChecks = certifiedNormalizedOffsetCells * 2;
  assertSafeIntegerInRange(proofLengthCount, 1, 0xffff_ffff, "proof length count");
  assertSafeIntegerInRange(
    certifiedNormalizedOffsetCells,
    1,
    0xffff_ffff,
    "certified normalized cells",
  );
  assertSafeIntegerInRange(
    certifiedEndpointChecks,
    1,
    0xffff_ffff,
    "certified endpoint checks",
  );
  return Object.freeze({
    schema: V17_AFFINE_READER_PLAN_SCHEMA,
    certification: V17_AFFINE_READER_PLAN_CERTIFICATION,
    allocationSha256Hex: allocationDigestHex(allocation),
    minimumProofBytes: allocation.minimumProofBytes,
    maximumProofBytes: allocation.maximumProofBytes,
    elasticScaleUnits: allocation.elasticScaleUnits,
    carrierCount: allocation.assignments.length,
    lengthCells: geometry.lengthCells,
    normalizedOffsetCells: geometry.normalizedOffsetCells,
    certifiedProofLengths: proofLengthCount,
    certifiedNormalizedOffsetCells,
    certifiedEndpointChecks,
    maximumIntervalCarriers,
    intervals: Object.freeze(intervals),
  });
}

/** Resolve the certified inclusive carrier bracket for one proof byte. */
export function v17AffineReaderPlanInterval(
  plan: V17AffineReaderPlan,
  proofLength: number,
  proofOffset: number,
): V17AffineReaderCarrierInterval {
  if (!Number.isSafeInteger(proofLength) ||
    proofLength < plan.minimumProofBytes || proofLength > plan.maximumProofBytes ||
    !Number.isSafeInteger(proofOffset) || proofOffset < 0 || proofOffset >= proofLength) {
    throw new Error("v17 affine reader plan location");
  }
  const lengthCell = lengthCellFor(
    plan.minimumProofBytes,
    plan.maximumProofBytes,
    plan.lengthCells,
    proofLength,
  );
  const normalizedOffsetCell = normalizedOffsetCellFor(
    plan.normalizedOffsetCells,
    proofLength,
    proofOffset,
  );
  const interval = plan.intervals[
    lengthCell * plan.normalizedOffsetCells + normalizedOffsetCell
  ];
  if (interval === undefined || interval.lengthCell !== lengthCell ||
    interval.normalizedOffsetCell !== normalizedOffsetCell) {
    throw new Error("v17 affine reader plan interval");
  }
  return interval;
}

function validatePlanForEncoding(plan: V17AffineReaderPlan): void {
  if (plan.schema !== V17_AFFINE_READER_PLAN_SCHEMA ||
    plan.certification !== V17_AFFINE_READER_PLAN_CERTIFICATION ||
    !/^[0-9a-f]{64}$/.test(plan.allocationSha256Hex)) {
    throw new Error("v17 affine reader plan identity");
  }
  assertSafeIntegerInRange(plan.lengthCells, 1, 0xff, "encoded length cells");
  assertSafeIntegerInRange(
    plan.normalizedOffsetCells,
    1,
    0xff,
    "encoded normalized offset cells",
  );
  assertSafeIntegerInRange(plan.carrierCount, 1, 0x100, "encoded carrier count");
  for (const [value, label] of [
    [plan.minimumProofBytes, "encoded minimum proof bytes"],
    [plan.maximumProofBytes, "encoded maximum proof bytes"],
    [plan.elasticScaleUnits, "encoded elastic scale"],
    [plan.certifiedProofLengths, "encoded proof lengths"],
    [plan.certifiedNormalizedOffsetCells, "encoded normalized cells"],
    [plan.certifiedEndpointChecks, "encoded endpoint checks"],
  ] as const) {
    assertSafeIntegerInRange(value, 1, 0xffff_ffff, label);
  }
  const expectedProofLengths = plan.maximumProofBytes - plan.minimumProofBytes + 1;
  if (plan.certifiedProofLengths !== expectedProofLengths ||
    plan.certifiedNormalizedOffsetCells !==
      expectedProofLengths * plan.normalizedOffsetCells ||
    plan.certifiedEndpointChecks !== plan.certifiedNormalizedOffsetCells * 2 ||
    plan.intervals.length !== plan.lengthCells * plan.normalizedOffsetCells) {
    throw new Error("v17 affine reader plan certificate counts");
  }
  let maximumIntervalCarriers = 0;
  plan.intervals.forEach((interval, index) => {
    const expectedLengthCell = Math.floor(index / plan.normalizedOffsetCells);
    const expectedOffsetCell = index % plan.normalizedOffsetCells;
    if (interval.lengthCell !== expectedLengthCell ||
      interval.normalizedOffsetCell !== expectedOffsetCell ||
      !Number.isInteger(interval.lowCarrier) || !Number.isInteger(interval.highCarrier) ||
      interval.lowCarrier < 0 || interval.highCarrier < interval.lowCarrier ||
      interval.highCarrier >= plan.carrierCount || interval.highCarrier > 0xff) {
      throw new Error(`v17 affine reader encoded interval ${index}`);
    }
    maximumIntervalCarriers = Math.max(
      maximumIntervalCarriers,
      interval.highCarrier - interval.lowCarrier + 1,
    );
  });
  if (plan.maximumIntervalCarriers !== maximumIntervalCarriers) {
    throw new Error("v17 affine reader maximum interval");
  }
}

/**
 * Canonical binary form. The fixed 69-byte header is followed by exactly two
 * bytes (inclusive low/high carrier) per canonical table cell.
 */
export function encodeV17AffineReaderPlan(plan: V17AffineReaderPlan): Uint8Array {
  validatePlanForEncoding(plan);
  const intervalBytes = new Uint8Array(plan.intervals.length * 2);
  plan.intervals.forEach((interval, index) => {
    intervalBytes[index * 2] = interval.lowCarrier;
    intervalBytes[index * 2 + 1] = interval.highCarrier;
  });
  return concatBytes(
    PLAN_MAGIC,
    Uint8Array.of(
      PLAN_VERSION,
      plan.lengthCells,
      plan.normalizedOffsetCells,
    ),
    writeU16BE(plan.carrierCount),
    writeU32BE(plan.minimumProofBytes),
    writeU32BE(plan.maximumProofBytes),
    writeU32BE(plan.elasticScaleUnits),
    writeU32BE(plan.certifiedProofLengths),
    writeU32BE(plan.certifiedNormalizedOffsetCells),
    writeU32BE(plan.certifiedEndpointChecks),
    hexToBytes(plan.allocationSha256Hex, "v17 affine allocation digest"),
    intervalBytes,
  );
}

export function v17AffineReaderPlanDigestHex(plan: V17AffineReaderPlan): string {
  return bytesToHex(new Uint8Array(
    createHash("sha256").update(encodeV17AffineReaderPlan(plan)).digest(),
  ));
}

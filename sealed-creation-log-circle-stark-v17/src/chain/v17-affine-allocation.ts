import {
  V17_CONSTRUCTION_GRAPH,
  V17_ELASTIC_PREFIX_SCALE,
  V17_MAXIMUM_CANONICAL_PROOF_BYTES,
} from "../construction/v17-graph.ts";
import { LOCAL_WORD_CARRIER_BUDGETS } from "./local-word-carrier-allocation.ts";
import { V17_PRODUCTION_ROLE_LAYOUT } from "./v17-role-layout.ts";

export const V17_AFFINE_SEQUENCE_BASE = 0x8000_0000 as const;
export const V17_AFFINE_SEQUENCE_RADIX = 4_096 as const;
export const V17_AFFINE_VALUE_BASE = 1_000n as const;

export type V17AffineAssignment = {
  readonly roleId: string;
  readonly basePrefixStart: number;
  readonly basePrefixEnd: number;
  readonly elasticPrefixStart: number;
  readonly elasticPrefixEnd: number;
};

export type V17AffineAllocation = {
  readonly status: "bootstrap" | "measured";
  readonly minimumProofBytes: number;
  readonly maximumProofBytes: typeof V17_MAXIMUM_CANONICAL_PROOF_BYTES;
  readonly elasticScaleUnits: typeof V17_ELASTIC_PREFIX_SCALE;
  readonly assignments: readonly V17AffineAssignment[];
};

/** Deterministic Hamilton apportionment with logical-order remainder ties. */
export function apportionV17Units(
  weights: readonly number[],
  totalUnits: number,
): readonly number[] {
  if (weights.length < 1 || weights.some((weight) => !Number.isSafeInteger(weight) || weight < 0) ||
    !Number.isSafeInteger(totalUnits) || totalUnits < 1) {
    throw new Error("v17 affine apportionment shape");
  }
  const totalWeight = weights.reduce((sum, weight) => sum + weight, 0);
  if (totalWeight < 1) throw new Error("v17 affine apportionment weight");
  const units = weights.map((weight) => Math.floor(totalUnits * weight / totalWeight));
  let remaining = totalUnits - units.reduce((sum, value) => sum + value, 0);
  const remainders = weights.map((weight, index) => ({
    index,
    remainder: (totalUnits * weight) % totalWeight,
  })).sort((left, right) => right.remainder - left.remainder || left.index - right.index);
  for (const { index } of remainders) {
    if (remaining === 0) break;
    units[index]! += 1;
    remaining -= 1;
  }
  if (remaining !== 0) throw new Error("v17 affine apportionment remainder");
  return units;
}

export function validateV17AffineAllocation(
  allocation: V17AffineAllocation,
): V17AffineAllocation {
  if ((allocation.status !== "bootstrap" && allocation.status !== "measured") ||
    allocation.maximumProofBytes !== V17_MAXIMUM_CANONICAL_PROOF_BYTES ||
    allocation.elasticScaleUnits !== V17_ELASTIC_PREFIX_SCALE ||
    !Number.isSafeInteger(allocation.minimumProofBytes) || allocation.minimumProofBytes < 1 ||
    allocation.minimumProofBytes >= allocation.maximumProofBytes ||
    allocation.minimumProofBytes >= 2 ** 19 ||
    allocation.assignments.length !== V17_PRODUCTION_ROLE_LAYOUT.length) {
    throw new Error("v17 affine allocation envelope");
  }
  allocation.assignments.forEach((assignment, index) => {
    const role = V17_PRODUCTION_ROLE_LAYOUT[index]!;
    const previous = allocation.assignments[index - 1];
    if (assignment.roleId !== role.id ||
      !Number.isSafeInteger(assignment.basePrefixStart) ||
      !Number.isSafeInteger(assignment.basePrefixEnd) ||
      !Number.isSafeInteger(assignment.elasticPrefixStart) ||
      !Number.isSafeInteger(assignment.elasticPrefixEnd) ||
      assignment.basePrefixStart < 0 || assignment.basePrefixEnd <= assignment.basePrefixStart ||
      assignment.elasticPrefixStart < 0 ||
      assignment.elasticPrefixEnd < assignment.elasticPrefixStart ||
      assignment.elasticPrefixEnd > V17_ELASTIC_PREFIX_SCALE ||
      (index === 0
        ? assignment.basePrefixStart !== 0 || assignment.elasticPrefixStart !== 0
        : assignment.basePrefixStart !== previous!.basePrefixEnd ||
          assignment.elasticPrefixStart !== previous!.elasticPrefixEnd)) {
      throw new Error(`v17 affine assignment ${index}:${role.id}`);
    }
  });
  const terminal = allocation.assignments.at(-1)!;
  if (terminal.basePrefixEnd !== allocation.minimumProofBytes ||
    terminal.elasticPrefixEnd !== allocation.elasticScaleUnits) {
    throw new Error("v17 affine terminal boundary");
  }
  return allocation;
}

function bootstrapAllocation(): V17AffineAllocation {
  // Bootstrap is only a feasible measurement seed. Give every role the
  // graph-owned minimum and use the historical budgets solely as relative
  // weights for the remaining real proof bytes. Exact BCHN residual-density
  // measurements replace both endpoints before certification.
  const baseBytes = V17_PRODUCTION_ROLE_LAYOUT.map(() =>
    V17_CONSTRUCTION_GRAPH.allocation.minimumProofBytesPerRole);
  const elasticUnits = apportionV17Units(
    LOCAL_WORD_CARRIER_BUDGETS,
    V17_ELASTIC_PREFIX_SCALE,
  );
  let basePrefix = 0;
  let elasticPrefix = 0;
  const assignments = V17_PRODUCTION_ROLE_LAYOUT.map((role, index): V17AffineAssignment => {
    const basePrefixStart = basePrefix;
    const elasticPrefixStart = elasticPrefix;
    basePrefix += baseBytes[index]!;
    elasticPrefix += elasticUnits[index]!;
    return {
      roleId: role.id,
      basePrefixStart,
      basePrefixEnd: basePrefix,
      elasticPrefixStart,
      elasticPrefixEnd: elasticPrefix,
    };
  });
  return validateV17AffineAllocation({
    status: "bootstrap",
    minimumProofBytes: basePrefix,
    maximumProofBytes: V17_MAXIMUM_CANONICAL_PROOF_BYTES,
    elasticScaleUnits: V17_ELASTIC_PREFIX_SCALE,
    assignments,
  });
}

/** Provisional geometry used only before exact post-link BCHN certification. */
export const V17_BOOTSTRAP_AFFINE_ALLOCATION = bootstrapAllocation();

export function measuredV17AffineAllocation(
  assignments: readonly V17AffineAssignment[],
): V17AffineAllocation {
  return validateV17AffineAllocation({
    status: "measured",
    minimumProofBytes: assignments.at(-1)?.basePrefixEnd ?? 0,
    maximumProofBytes: V17_MAXIMUM_CANONICAL_PROOF_BYTES,
    elasticScaleUnits: V17_ELASTIC_PREFIX_SCALE,
    // Normalize the typed affine geometry. Density evidence rows carry extra
    // resource fields, but those are certificate evidence rather than reader
    // parameters and must not silently enter the reader-plan identity.
    assignments: assignments.map((assignment) => ({
      roleId: assignment.roleId,
      basePrefixStart: assignment.basePrefixStart,
      basePrefixEnd: assignment.basePrefixEnd,
      elasticPrefixStart: assignment.elasticPrefixStart,
      elasticPrefixEnd: assignment.elasticPrefixEnd,
    })),
  });
}

export function v17AffineBoundary(
  allocation: V17AffineAllocation,
  proofLength: number,
  boundaryIndex: number,
): number {
  validateV17AffineAllocation(allocation);
  if (!Number.isSafeInteger(proofLength) || proofLength < allocation.minimumProofBytes ||
    proofLength > allocation.maximumProofBytes || !Number.isInteger(boundaryIndex) ||
    boundaryIndex < 0 || boundaryIndex > allocation.assignments.length) {
    throw new Error("v17 affine boundary shape");
  }
  if (boundaryIndex === 0) return 0;
  if (boundaryIndex === allocation.assignments.length) return proofLength;
  const assignment = allocation.assignments[boundaryIndex]!;
  const elasticBytes = proofLength - allocation.minimumProofBytes;
  return assignment.basePrefixStart + Math.floor(
    elasticBytes * assignment.elasticPrefixStart / allocation.elasticScaleUnits,
  );
}

export function v17AffineCarrierBounds(
  allocation: V17AffineAllocation,
  proofLength: number,
  index: number,
): readonly [number, number] {
  if (!Number.isInteger(index) || index < 0 || index >= allocation.assignments.length) {
    throw new Error("v17 affine carrier index");
  }
  return [
    v17AffineBoundary(allocation, proofLength, index),
    v17AffineBoundary(allocation, proofLength, index + 1),
  ];
}

/** Pack one authenticated internal boundary into the 31 disabled-sequence payload bits. */
export function v17AffineBoundarySequence(
  allocation: V17AffineAllocation,
  boundaryIndex: number,
): number {
  validateV17AffineAllocation(allocation);
  if (!Number.isInteger(boundaryIndex) || boundaryIndex < 1 ||
    boundaryIndex >= allocation.assignments.length) {
    throw new Error("v17 affine sequence boundary");
  }
  const assignment = allocation.assignments[boundaryIndex]!;
  const payload = assignment.basePrefixStart * V17_AFFINE_SEQUENCE_RADIX +
    assignment.elasticPrefixStart;
  const sequence = V17_AFFINE_SEQUENCE_BASE + payload;
  if (!Number.isSafeInteger(sequence) || sequence > 0xffff_ffff) {
    throw new Error("v17 affine sequence width");
  }
  return sequence;
}

/** Input one authenticates R; later values stay small and value-neutral. */
export function v17AffineVerifierValue(
  allocation: V17AffineAllocation,
  inputIndex: number,
): bigint {
  validateV17AffineAllocation(allocation);
  if (!Number.isInteger(inputIndex) || inputIndex < 1 ||
    inputIndex >= allocation.assignments.length) {
    throw new Error("v17 affine verifier value index");
  }
  return inputIndex === 1
    ? V17_AFFINE_VALUE_BASE + BigInt(allocation.minimumProofBytes)
    : V17_AFFINE_VALUE_BASE + BigInt(inputIndex);
}

export function decodeV17AffineBoundarySequence(sequence: number): {
  readonly basePrefix: number;
  readonly elasticPrefix: number;
} {
  if (!Number.isSafeInteger(sequence) || sequence < V17_AFFINE_SEQUENCE_BASE ||
    sequence > 0xffff_ffff) {
    throw new Error("v17 affine sequence encoding");
  }
  const payload = sequence - V17_AFFINE_SEQUENCE_BASE;
  return {
    basePrefix: Math.floor(payload / V17_AFFINE_SEQUENCE_RADIX),
    elasticPrefix: payload % V17_AFFINE_SEQUENCE_RADIX,
  };
}

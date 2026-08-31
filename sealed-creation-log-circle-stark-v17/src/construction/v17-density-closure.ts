import { createHash } from "node:crypto";
import {
  V17_BOOTSTRAP_AFFINE_ALLOCATION,
  apportionV17Units,
  measuredV17AffineAllocation,
  validateV17AffineAllocation,
  type V17AffineAllocation,
} from "../chain/v17-affine-allocation.ts";
import {
  compileV17AffineReaderConstruction,
  type V17AffineReaderConstructionEvidence,
} from "../chain/v17-affine-reader-vm.ts";
import { V17_PRODUCTION_ROLE_LAYOUT } from "../chain/v17-role-layout.ts";
import {
  V17_CONSTRUCTION_GRAPH,
  canonicalV17Json,
  v17ProtocolIdHex,
  type V17ConstructionGraph,
} from "./v17-graph.ts";

export const V17_DENSITY_CLOSURE_SCHEMA = "ShieldKit/V17DensityClosure/v1" as const;
export const V17_DENSITY_TRACE_SCHEMA = "ShieldKit/V17DensityClosureTrace/v1" as const;

export type V17DensityFeasibilityRow = {
  readonly roleId: string;
  readonly requiredProofBytes: number;
  readonly capacityProofBytes: number;
  readonly maximumOperationCost: number;
  readonly profileOperationCosts: readonly [number, number, number];
  readonly profileRequiredProofBytes: readonly [number, number, number];
  readonly profileCapacityProofBytes: readonly [number, number, number];
};

export type V17DensityAssignment = V17DensityFeasibilityRow & {
  readonly basePrefixStart: number;
  readonly basePrefixEnd: number;
  readonly elasticPrefixStart: number;
  readonly elasticPrefixEnd: number;
};

export type V17DensityFeasibility = {
  readonly status: "feasible" | "infeasible";
  readonly rows: readonly V17DensityFeasibilityRow[];
  readonly minimumProofBytes: number;
  readonly maximumProofBytes: number;
  readonly infeasibleRoleIds: readonly string[];
};

export type V17DensityClosure = {
  readonly schema: typeof V17_DENSITY_CLOSURE_SCHEMA;
  readonly status: "monotone-conservative-envelope";
  readonly minimumProofBytes: number;
  readonly maximumProofBytes: number;
  readonly rows: readonly V17DensityFeasibilityRow[];
  readonly closureSha256Hex: string;
};

export type V17DensityTracePhase = "local-sizing" | "post-link-bchn" | "final-bchn";

export type V17DensityTraceGenesis = {
  readonly schema: "ShieldKit/V17DensityClosureTraceGenesis/v1";
  readonly protocolIdHex: string;
  readonly graphAllocation: V17ConstructionGraph["allocation"];
  readonly bootstrapAllocation: V17AffineAllocation;
  readonly bootstrapAllocationSha256Hex: string;
  readonly bootstrapReader: V17AffineReaderConstructionEvidence;
  readonly genesisSha256Hex: string;
};

export type V17DensityTraceEntry = {
  readonly schema: "ShieldKit/V17DensityClosureTraceEntry/v1";
  readonly ordinal: number;
  readonly phase: V17DensityTracePhase;
  readonly priorTraceRootSha256Hex: string;
  readonly currentAllocationSha256Hex: string;
  readonly currentReaderPlanSha256Hex: string;
  readonly currentReaderBytecodeSha256Hex: string;
  readonly romPreviewIdHex: string;
  readonly measurementEvidenceSha256Hex: string;
  readonly measuredRowsSha256Hex: string;
  readonly measuredRows: readonly V17DensityFeasibilityRow[];
  readonly priorClosureSha256Hex: string | null;
  readonly joinedClosure: V17DensityClosure;
  readonly nextAllocation: V17AffineAllocation;
  readonly nextAllocationSha256Hex: string;
  readonly nextReaderPlanSha256Hex: string;
  readonly nextReaderBytecodeSha256Hex: string;
  readonly changedRoleIds: readonly string[];
  readonly closureChanged: boolean;
  readonly allocationChanged: boolean;
  readonly readerChanged: boolean;
  readonly noChange: boolean;
  readonly entrySha256Hex: string;
};

export type V17DensityClosureTrace = {
  readonly schema: typeof V17_DENSITY_TRACE_SCHEMA;
  readonly genesis: V17DensityTraceGenesis;
  readonly entries: readonly V17DensityTraceEntry[];
};

export type V17DensityTraceHead = {
  readonly allocation: V17AffineAllocation;
  readonly closure: V17DensityClosure | null;
  readonly traceRootSha256Hex: string;
  readonly terminalNoChange: boolean;
  readonly terminalPhase: V17DensityTracePhase | null;
};

function digest(domain: string, value: unknown): string {
  return createHash("sha256")
    .update(domain)
    .update(Uint8Array.of(0))
    .update(canonicalV17Json(value))
    .digest("hex");
}

function assertHex32(label: string, value: string): void {
  if (!/^[0-9a-f]{64}$/.test(value)) throw new Error(`v17 density ${label}`);
}

function allocationGeometry(allocation: V17AffineAllocation): unknown {
  return {
    status: allocation.status,
    minimumProofBytes: allocation.minimumProofBytes,
    maximumProofBytes: allocation.maximumProofBytes,
    elasticScaleUnits: allocation.elasticScaleUnits,
    assignments: allocation.assignments,
  };
}

export function v17DensityAllocationDigestHex(allocation: V17AffineAllocation): string {
  validateV17AffineAllocation(allocation);
  return digest("ShieldKit/V17DensityAffineAllocation/v1", allocationGeometry(allocation));
}

function closureCore(closure: Omit<V17DensityClosure, "closureSha256Hex">): unknown {
  return closure;
}

function validateTriple(label: string, values: readonly number[]): asserts values is
  readonly [number, number, number] {
  if (values.length !== 3 || values.some((value) => !Number.isSafeInteger(value) || value < 0)) {
    throw new Error(`v17 density ${label}`);
  }
}

function canonicalDensityRow(row: V17DensityFeasibilityRow): V17DensityFeasibilityRow {
  return {
    roleId: row.roleId,
    requiredProofBytes: row.requiredProofBytes,
    capacityProofBytes: row.capacityProofBytes,
    maximumOperationCost: row.maximumOperationCost,
    profileOperationCosts: [...row.profileOperationCosts] as unknown as
      readonly [number, number, number],
    profileRequiredProofBytes: [...row.profileRequiredProofBytes] as unknown as
      readonly [number, number, number],
    profileCapacityProofBytes: [...row.profileCapacityProofBytes] as unknown as
      readonly [number, number, number],
  };
}

export function validateV17DensityRows(
  rows: readonly V17DensityFeasibilityRow[],
  graph: V17ConstructionGraph = V17_CONSTRUCTION_GRAPH,
): readonly V17DensityFeasibilityRow[] {
  if (rows.length !== V17_PRODUCTION_ROLE_LAYOUT.length) {
    throw new Error("v17 density row count");
  }
  rows.forEach((row, index) => {
    validateTriple(`${row.roleId} profile opcost`, row.profileOperationCosts);
    validateTriple(`${row.roleId} profile required`, row.profileRequiredProofBytes);
    validateTriple(`${row.roleId} profile capacity`, row.profileCapacityProofBytes);
    if (row.roleId !== V17_PRODUCTION_ROLE_LAYOUT[index]!.id ||
      row.profileOperationCosts.some((value) => value < 1) ||
      row.profileRequiredProofBytes.some((value) =>
        value < graph.allocation.minimumProofBytesPerRole) ||
      row.profileCapacityProofBytes.some((value) =>
        value < graph.allocation.minimumProofBytesPerRole ||
        value > graph.allocation.capacityLimitBytes) ||
      row.maximumOperationCost !== Math.max(...row.profileOperationCosts) ||
      row.requiredProofBytes !== Math.max(...row.profileRequiredProofBytes) ||
      row.capacityProofBytes !== Math.min(...row.profileCapacityProofBytes) ||
      canonicalV17Json(row) !== canonicalV17Json(canonicalDensityRow(row))) {
      throw new Error(`v17 density row ${index}:${row.roleId}`);
    }
  });
  return rows;
}

export function createV17DensityClosure(
  rows: readonly V17DensityFeasibilityRow[],
  graph: V17ConstructionGraph = V17_CONSTRUCTION_GRAPH,
): V17DensityClosure {
  validateV17DensityRows(rows, graph);
  const minimumProofBytes = rows.reduce((sum, row) => sum + row.requiredProofBytes, 0);
  const maximumProofBytes = graph.allocation.maximumProofBytes;
  const infeasible = rows.filter((row) => row.requiredProofBytes > row.capacityProofBytes);
  if (infeasible.length > 0 || !Number.isSafeInteger(minimumProofBytes) ||
    minimumProofBytes < 1 || minimumProofBytes >= maximumProofBytes) {
    throw new Error(`v17 density closure infeasible ${infeasible.map((row) =>
      `${row.roleId}:${row.requiredProofBytes}/${row.capacityProofBytes}`).join(",")}`);
  }
  const core = {
    schema: V17_DENSITY_CLOSURE_SCHEMA,
    status: "monotone-conservative-envelope" as const,
    minimumProofBytes,
    maximumProofBytes,
    rows: rows.map(canonicalDensityRow),
  };
  return {
    ...core,
    closureSha256Hex: digest("ShieldKit/V17DensityClosure/v1", closureCore(core)),
  };
}

export function validateV17DensityClosure(
  closure: V17DensityClosure,
  graph: V17ConstructionGraph = V17_CONSTRUCTION_GRAPH,
): V17DensityClosure {
  if (closure.schema !== V17_DENSITY_CLOSURE_SCHEMA ||
    closure.status !== "monotone-conservative-envelope") {
    throw new Error("v17 density closure envelope");
  }
  const replay = createV17DensityClosure(closure.rows, graph);
  if (canonicalV17Json(replay) !== canonicalV17Json(closure)) {
    throw new Error("v17 density closure digest");
  }
  return closure;
}

export function joinV17DensityClosure(
  prior: V17DensityClosure | null,
  measuredRows: readonly V17DensityFeasibilityRow[],
  graph: V17ConstructionGraph = V17_CONSTRUCTION_GRAPH,
): V17DensityClosure {
  validateV17DensityRows(measuredRows, graph);
  if (prior === null) return createV17DensityClosure(measuredRows, graph);
  validateV17DensityClosure(prior, graph);
  const joined = measuredRows.map((measured, index): V17DensityFeasibilityRow => {
    const retained = prior.rows[index]!;
    if (measured.roleId !== retained.roleId) throw new Error("v17 density closure role order");
    const profileOperationCosts = measured.profileOperationCosts.map((value, profile) =>
      Math.max(value, retained.profileOperationCosts[profile]!)) as unknown as
      readonly [number, number, number];
    const profileRequiredProofBytes = measured.profileRequiredProofBytes.map((value, profile) =>
      Math.max(value, retained.profileRequiredProofBytes[profile]!)) as unknown as
      readonly [number, number, number];
    const profileCapacityProofBytes = measured.profileCapacityProofBytes.map((value, profile) =>
      Math.min(value, retained.profileCapacityProofBytes[profile]!)) as unknown as
      readonly [number, number, number];
    return {
      roleId: measured.roleId,
      profileOperationCosts,
      profileRequiredProofBytes,
      profileCapacityProofBytes,
      maximumOperationCost: Math.max(...profileOperationCosts),
      requiredProofBytes: Math.max(...profileRequiredProofBytes),
      capacityProofBytes: Math.min(...profileCapacityProofBytes),
    };
  });
  return createV17DensityClosure(joined, graph);
}

export function v17DensityClosureDominates(
  closure: V17DensityClosure,
  measuredRows: readonly V17DensityFeasibilityRow[],
  graph: V17ConstructionGraph = V17_CONSTRUCTION_GRAPH,
): boolean {
  validateV17DensityClosure(closure, graph);
  validateV17DensityRows(measuredRows, graph);
  return closure.rows.every((retained, index) => {
    const measured = measuredRows[index]!;
    return retained.roleId === measured.roleId && [0, 1, 2].every((profile) =>
      retained.profileOperationCosts[profile]! >= measured.profileOperationCosts[profile]! &&
      retained.profileRequiredProofBytes[profile]! >= measured.profileRequiredProofBytes[profile]! &&
      retained.profileCapacityProofBytes[profile]! <= measured.profileCapacityProofBytes[profile]!);
  });
}

/** The one q=1 Hamilton allocation law over exact or conservatively joined rows. */
export function allocateV17DensityRows(
  graph: V17ConstructionGraph,
  rows: readonly V17DensityFeasibilityRow[],
): readonly V17DensityAssignment[] {
  const closure = createV17DensityClosure(rows, graph);
  const { minimumProofBytes, maximumProofBytes } = closure;
  const elasticProofBytes = maximumProofBytes - minimumProofBytes;
  const scale = graph.allocation.elasticScaleUnits;
  const elasticCapacities = closure.rows.map((row) => Math.floor(
    (row.capacityProofBytes - row.requiredProofBytes) * scale / elasticProofBytes,
  ));
  const totalElasticCapacity = elasticCapacities.reduce((sum, value) => sum + value, 0);
  if (totalElasticCapacity < scale) {
    throw new Error(`v17 density elastic capacity ${totalElasticCapacity}/${scale}`);
  }
  const elasticUnits = apportionV17Units(elasticCapacities, scale);
  if (elasticUnits.some((units, index) => units > elasticCapacities[index]!)) {
    throw new Error("v17 density Hamilton capacity");
  }
  let basePrefix = 0;
  let elasticPrefix = 0;
  const assignments = closure.rows.map((row, index): V17DensityAssignment => {
    const basePrefixStart = basePrefix;
    const elasticPrefixStart = elasticPrefix;
    basePrefix += row.requiredProofBytes;
    elasticPrefix += elasticUnits[index]!;
    const maximumExtra = Math.ceil(elasticProofBytes * elasticUnits[index]! / scale);
    if (maximumExtra > row.capacityProofBytes - row.requiredProofBytes) {
      throw new Error(`v17 density elastic overflow ${row.roleId}`);
    }
    return {
      ...row,
      basePrefixStart,
      basePrefixEnd: basePrefix,
      elasticPrefixStart,
      elasticPrefixEnd: elasticPrefix,
    };
  });
  if (assignments[0]?.basePrefixStart !== 0 || assignments[0]?.elasticPrefixStart !== 0 ||
    assignments.at(-1)?.basePrefixEnd !== minimumProofBytes ||
    assignments.at(-1)?.elasticPrefixEnd !== scale ||
    assignments.slice(0, -1).some((assignment) => assignment.elasticPrefixEnd >= scale)) {
    throw new Error("v17 density prefix union");
  }
  return assignments;
}

export function allocateV17DensityClosure(
  closure: V17DensityClosure,
  graph: V17ConstructionGraph = V17_CONSTRUCTION_GRAPH,
): readonly V17DensityAssignment[] {
  validateV17DensityClosure(closure, graph);
  return allocateV17DensityRows(graph, closure.rows);
}

export function createV17DensityClosureTrace(): V17DensityClosureTrace {
  const bootstrapAllocation = validateV17AffineAllocation(V17_BOOTSTRAP_AFFINE_ALLOCATION);
  const bootstrapReader = compileV17AffineReaderConstruction(bootstrapAllocation).evidence;
  const core = {
    schema: "ShieldKit/V17DensityClosureTraceGenesis/v1" as const,
    protocolIdHex: v17ProtocolIdHex(),
    graphAllocation: V17_CONSTRUCTION_GRAPH.allocation,
    bootstrapAllocation,
    bootstrapAllocationSha256Hex: v17DensityAllocationDigestHex(bootstrapAllocation),
    bootstrapReader,
  };
  return {
    schema: V17_DENSITY_TRACE_SCHEMA,
    genesis: {
      ...core,
      genesisSha256Hex: digest("ShieldKit/V17DensityClosureTraceGenesis/v1", core),
    },
    entries: [],
  };
}

function same(left: unknown, right: unknown): boolean {
  return canonicalV17Json(left) === canonicalV17Json(right);
}

export function replayV17DensityClosureTrace(trace: V17DensityClosureTrace): V17DensityTraceHead {
  const canonical = createV17DensityClosureTrace();
  if (trace.schema !== V17_DENSITY_TRACE_SCHEMA || !same(trace.genesis, canonical.genesis)) {
    throw new Error("v17 density trace genesis");
  }
  if (!same(trace, { schema: trace.schema, genesis: trace.genesis, entries: trace.entries })) {
    throw new Error("v17 density trace envelope");
  }
  let allocation = canonical.genesis.bootstrapAllocation;
  let closure: V17DensityClosure | null = null;
  let traceRootSha256Hex = canonical.genesis.genesisSha256Hex;
  let terminalNoChange = false;
  let terminalPhase: V17DensityTracePhase | null = null;
  trace.entries.forEach((entry, index) => {
    if (!["local-sizing", "post-link-bchn", "final-bchn"].includes(entry.phase)) {
      throw new Error(`v17 density trace phase ${index + 1}`);
    }
    const currentReader = compileV17AffineReaderConstruction(allocation).evidence;
    const joinedClosure = joinV17DensityClosure(closure, entry.measuredRows);
    const nextAllocation = measuredV17AffineAllocation(allocateV17DensityClosure(joinedClosure));
    const nextReader = compileV17AffineReaderConstruction(nextAllocation).evidence;
    const closureChanged = closure === null ||
      closure.closureSha256Hex !== joinedClosure.closureSha256Hex;
    const allocationChanged = v17DensityAllocationDigestHex(allocation) !==
      v17DensityAllocationDigestHex(nextAllocation);
    const readerChanged = currentReader.planSha256Hex !== nextReader.planSha256Hex ||
      currentReader.readerBytecodeSha256Hex !== nextReader.readerBytecodeSha256Hex;
    const noChange = closure !== null && !closureChanged && !allocationChanged && !readerChanged;
    const changedRoleIds = joinedClosure.rows.flatMap((row, roleIndex) =>
      closure === null || canonicalV17Json(closure.rows[roleIndex]) !== canonicalV17Json(row)
        ? [row.roleId]
        : []);
    const core = {
      schema: "ShieldKit/V17DensityClosureTraceEntry/v1" as const,
      ordinal: index + 1,
      phase: entry.phase,
      priorTraceRootSha256Hex: traceRootSha256Hex,
      currentAllocationSha256Hex: v17DensityAllocationDigestHex(allocation),
      currentReaderPlanSha256Hex: currentReader.planSha256Hex,
      currentReaderBytecodeSha256Hex: currentReader.readerBytecodeSha256Hex,
      romPreviewIdHex: entry.romPreviewIdHex,
      measurementEvidenceSha256Hex: entry.measurementEvidenceSha256Hex,
      measuredRowsSha256Hex: digest("ShieldKit/V17DensityMeasuredRows/v1", entry.measuredRows),
      measuredRows: entry.measuredRows,
      priorClosureSha256Hex: closure?.closureSha256Hex ?? null,
      joinedClosure,
      nextAllocation,
      nextAllocationSha256Hex: v17DensityAllocationDigestHex(nextAllocation),
      nextReaderPlanSha256Hex: nextReader.planSha256Hex,
      nextReaderBytecodeSha256Hex: nextReader.readerBytecodeSha256Hex,
      changedRoleIds,
      closureChanged,
      allocationChanged,
      readerChanged,
      noChange,
    };
    const replayed = {
      ...core,
      entrySha256Hex: digest("ShieldKit/V17DensityClosureTraceEntry/v1", core),
    };
    [entry.romPreviewIdHex, entry.measurementEvidenceSha256Hex].forEach((value, field) =>
      assertHex32(`trace entry ${index}:${field}`, value));
    if (!same(entry, replayed)) throw new Error(`v17 density trace entry ${index + 1}`);
    allocation = nextAllocation;
    closure = joinedClosure;
    traceRootSha256Hex = replayed.entrySha256Hex;
    terminalNoChange = noChange;
    terminalPhase = entry.phase;
  });
  return { allocation, closure, traceRootSha256Hex, terminalNoChange, terminalPhase };
}

export function appendV17DensityClosureTrace(args: {
  readonly trace: V17DensityClosureTrace;
  readonly phase: V17DensityTracePhase;
  readonly currentAllocation: V17AffineAllocation;
  readonly currentReader: V17AffineReaderConstructionEvidence;
  readonly romPreviewIdHex: string;
  readonly measurementEvidenceSha256Hex: string;
  readonly measuredRows: readonly V17DensityFeasibilityRow[];
}): V17DensityClosureTrace {
  const head = replayV17DensityClosureTrace(args.trace);
  if (!same(allocationGeometry(args.currentAllocation), allocationGeometry(head.allocation)) ||
    !same(compileV17AffineReaderConstruction(head.allocation).evidence, args.currentReader)) {
    throw new Error("v17 density trace caller state");
  }
  [args.romPreviewIdHex, args.measurementEvidenceSha256Hex].forEach((value, index) =>
    assertHex32(`trace append ${index}`, value));
  validateV17DensityRows(args.measuredRows);
  const joinedClosure = joinV17DensityClosure(head.closure, args.measuredRows);
  const nextAllocation = measuredV17AffineAllocation(allocateV17DensityClosure(joinedClosure));
  const nextReader = compileV17AffineReaderConstruction(nextAllocation).evidence;
  const closureChanged = head.closure === null ||
    head.closure.closureSha256Hex !== joinedClosure.closureSha256Hex;
  const allocationChanged = v17DensityAllocationDigestHex(head.allocation) !==
    v17DensityAllocationDigestHex(nextAllocation);
  const readerChanged = args.currentReader.planSha256Hex !== nextReader.planSha256Hex ||
    args.currentReader.readerBytecodeSha256Hex !== nextReader.readerBytecodeSha256Hex;
  const noChange = head.closure !== null && !closureChanged && !allocationChanged && !readerChanged;
  const changedRoleIds = joinedClosure.rows.flatMap((row, roleIndex) =>
    head.closure === null ||
      canonicalV17Json(head.closure.rows[roleIndex]) !== canonicalV17Json(row)
      ? [row.roleId]
      : []);
  const core = {
    schema: "ShieldKit/V17DensityClosureTraceEntry/v1" as const,
    ordinal: args.trace.entries.length + 1,
    phase: args.phase,
    priorTraceRootSha256Hex: head.traceRootSha256Hex,
    currentAllocationSha256Hex: v17DensityAllocationDigestHex(head.allocation),
    currentReaderPlanSha256Hex: args.currentReader.planSha256Hex,
    currentReaderBytecodeSha256Hex: args.currentReader.readerBytecodeSha256Hex,
    romPreviewIdHex: args.romPreviewIdHex,
    measurementEvidenceSha256Hex: args.measurementEvidenceSha256Hex,
    measuredRowsSha256Hex: digest("ShieldKit/V17DensityMeasuredRows/v1", args.measuredRows),
    measuredRows: args.measuredRows.map((row) => ({ ...row })),
    priorClosureSha256Hex: head.closure?.closureSha256Hex ?? null,
    joinedClosure,
    nextAllocation,
    nextAllocationSha256Hex: v17DensityAllocationDigestHex(nextAllocation),
    nextReaderPlanSha256Hex: nextReader.planSha256Hex,
    nextReaderBytecodeSha256Hex: nextReader.readerBytecodeSha256Hex,
    changedRoleIds,
    closureChanged,
    allocationChanged,
    readerChanged,
    noChange,
  };
  const entry: V17DensityTraceEntry = {
    ...core,
    entrySha256Hex: digest("ShieldKit/V17DensityClosureTraceEntry/v1", core),
  };
  const next = { ...args.trace, entries: [...args.trace.entries, entry] };
  replayV17DensityClosureTrace(next);
  return next;
}

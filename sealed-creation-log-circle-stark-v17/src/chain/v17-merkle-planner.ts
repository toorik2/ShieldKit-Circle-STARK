import {
  maximumV17MerkleOpening,
  v17ProductionMerkleDescriptors,
  type V17MaximumOpening,
  type V17MaximumOpeningRequest,
  type V17MerkleDescriptor,
} from "../backends/circle/v17-merkle.ts";
import { V17_CONSTRUCTION_GRAPH } from "../construction/v17-graph.ts";

const FRONTIER_NODE_BYTES = 4 + 32;

export type V17MerklePlannerWeights = {
  readonly leafHash: number;
  readonly binaryParent: number;
  readonly quartetParent: number;
  /** Fixed loop/control charge for crossing one authenticated tree level. */
  readonly levelOverhead?: number;
};

export type V17MerklePlannerLimits = {
  readonly maxWork: number;
  /** Maximum serialized input or output frontier owned by one stage. */
  readonly maxHandoffBytes: number;
};

export type V17MerklePlannerInput = {
  readonly descriptor: V17MerkleDescriptor;
  readonly opening: V17MaximumOpeningRequest;
  readonly weights: V17MerklePlannerWeights;
  readonly limits: V17MerklePlannerLimits;
};

export type V17MerkleStage = {
  readonly startLevel: number;
  readonly endLevel: number;
  readonly startBits: number;
  readonly endBits: number;
  readonly work: number;
  readonly inputFrontierBytes: number;
  readonly outputFrontierBytes: number;
};

export type V17MerklePlannerEdge = V17MerkleStage & {
  readonly valid: boolean;
  readonly rejectedBy: readonly ("work" | "input-frontier" | "output-frontier" | "mixed-arity")[];
};

export type V17MerklePlanCertificate = {
  readonly version: 1;
  readonly input: V17MerklePlannerInput;
  readonly maximum: V17MaximumOpening;
  /** Every possible contiguous stage, including every rejected coarsening. */
  readonly edges: readonly V17MerklePlannerEdge[];
  /** Exact minimum stage count to each level boundary; null means unreachable. */
  readonly minimumStagesToBoundary: readonly (number | null)[];
  readonly selectedCuts: readonly number[];
  readonly selectedStageCount: number;
  readonly serializedCutBytes: number;
};

export type V17MerklePlan = {
  readonly cuts: readonly number[];
  readonly stages: readonly V17MerkleStage[];
  readonly serializedCutBytes: number;
  readonly certificate: V17MerklePlanCertificate;
};

function positiveSafeInteger(value: number, label: string): number {
  if (!Number.isSafeInteger(value) || value < 1) throw new Error(`v17 Merkle planner ${label}`);
  return value;
}

function validateInput(input: V17MerklePlannerInput): void {
  if (!Number.isSafeInteger(input.weights.leafHash) || input.weights.leafHash < 0) {
    throw new Error("v17 Merkle planner leaf weight");
  }
  positiveSafeInteger(input.weights.binaryParent, "binary weight");
  positiveSafeInteger(input.weights.quartetParent, "quartet weight");
  if (input.weights.levelOverhead !== undefined) {
    positiveSafeInteger(input.weights.levelOverhead, "level overhead");
  }
  positiveSafeInteger(input.limits.maxWork, "work limit");
  positiveSafeInteger(input.limits.maxHandoffBytes, "handoff limit");
}

function boundaryBits(maximum: V17MaximumOpening): readonly number[] {
  return [0, ...maximum.levels.map((level) => level.nextConsumedBits)];
}

function stageEdge(
  input: V17MerklePlannerInput,
  maximum: V17MaximumOpening,
  startLevel: number,
  endLevel: number,
): V17MerklePlannerEdge {
  const bits = boundaryBits(maximum);
  const levelCount = maximum.levels.length;
  let work = startLevel === 0
    ? maximum.openedLeafCount * input.weights.leafHash
    : 0;
  for (let level = startLevel; level < endLevel; level += 1) {
    const geometry = maximum.levels[level]!;
    work += (input.weights.levelOverhead ?? 0) + geometry.parentNodes * (
      geometry.arity === 2 ? input.weights.binaryParent : input.weights.quartetParent
    );
  }
  if (!Number.isSafeInteger(work)) throw new Error("v17 Merkle planner work overflow");
  const inputFrontierBytes = startLevel === 0
    ? 0
    : maximum.frontierNodes[startLevel]! * FRONTIER_NODE_BYTES;
  const outputFrontierBytes = endLevel === levelCount
    ? 0
    : maximum.frontierNodes[endLevel]! * FRONTIER_NODE_BYTES;
  const rejectedBy: ("work" | "input-frontier" | "output-frontier" | "mixed-arity")[] = [];
  if (new Set(maximum.levels.slice(startLevel, endLevel).map(({ arity }) => arity)).size > 1) {
    rejectedBy.push("mixed-arity");
  }
  if (work > input.limits.maxWork) rejectedBy.push("work");
  if (inputFrontierBytes > input.limits.maxHandoffBytes) rejectedBy.push("input-frontier");
  if (outputFrontierBytes > input.limits.maxHandoffBytes) rejectedBy.push("output-frontier");
  return {
    startLevel,
    endLevel,
    startBits: bits[startLevel]!,
    endBits: bits[endLevel]!,
    work,
    inputFrontierBytes,
    outputFrontierBytes,
    valid: rejectedBy.length === 0,
    rejectedBy,
  };
}

export const V17_PRODUCTION_MERKLE_WORK_MODEL = {
  /**
   * One unit is an intentionally abstract verifier-work atom. The generated
   * plan is subsequently gated by exact BCH script bytes and operation cost;
   * this model exists only to choose deterministic candidates without
   * smuggling handwritten cut positions back into the construction.
   */
  binaryParent: 1,
  quartetParent: 2,
  levelOverhead: 100,
  /** Leaf work is owned by the mandatory level-zero binding roles. */
  friLeaf: 0,
  maxWork: 854,
  maxHandoffBytes: 4_096,
} as const;

export type V17ProductionMerklePlan = {
  readonly id: string;
  readonly kind: "matrix" | "fri";
  readonly descriptor: V17MerkleDescriptor;
  readonly opening: V17MaximumOpeningRequest;
  readonly plan: V17MerklePlan;
};

export type V17ProductionMerklePlanSet = {
  readonly matrices: Readonly<Record<string, V17ProductionMerklePlan>>;
  readonly fri: readonly V17ProductionMerklePlan[];
  readonly matrixRoleCount: number;
  readonly friRoleCount: number;
};

/**
 * Committed output of the exhaustive q44 BCH measurement certificate. The
 * source test evaluates every homogeneous contiguous span (including
 * consensus hashing-density rejection), feeds those measurements back into
 * `planV17MerkleStagesFromMeasurements`, and locks this minimal cut vector.
 * Cuts are consumed tree bits, never handwritten VM stage numbers.
 */
export const V17_Q44_MEASURED_MERKLE_CUTS: Readonly<Record<string, readonly number[]>> =
  Object.freeze(Object.fromEntries(V17_CONSTRUCTION_GRAPH.commitments.map((commitment) => [
    commitment.hashLabel,
    Object.freeze([...commitment.verifierCuts]),
  ])));

export function v17Q44MeasuredMerkleCuts(descriptor: V17MerkleDescriptor): readonly number[] {
  const production = v17ProductionMerkleDescriptors();
  const expected = [
    ...Object.values(production.matrices),
    ...production.fri,
  ].find(({ label }) => label === descriptor.label);
  const cuts = V17_Q44_MEASURED_MERKLE_CUTS[descriptor.label];
  if (expected === undefined || cuts === undefined ||
    expected.shape !== descriptor.shape || expected.logRows !== descriptor.logRows ||
    expected.rowWidth !== descriptor.rowWidth || cuts.some((bits, item) =>
      !Number.isInteger(bits) || bits <= 0 || bits >= descriptor.logRows ||
      (item > 0 && cuts[item - 1]! >= bits))) {
    throw new Error("v17 q44 measured Merkle descriptor");
  }
  return cuts;
}

export function planV17ProtocolMerkleStages(args: {
  readonly descriptor: V17MerkleDescriptor;
  readonly opening: V17MaximumOpeningRequest;
  readonly kind: "matrix" | "fri";
}): V17MerklePlan {
  const model = V17_PRODUCTION_MERKLE_WORK_MODEL;
  return planV17MerkleStages({
    descriptor: args.descriptor,
    opening: args.opening,
    weights: {
      leafHash: 0,
      binaryParent: model.binaryParent,
      quartetParent: model.quartetParent,
      levelOverhead: model.levelOverhead,
    },
    limits: {
      maxWork: model.maxWork,
      maxHandoffBytes: model.maxHandoffBytes,
    },
  });
}

/**
 * Generate verifier-key cuts from the graph inventory and the tight
 * all-schedule recurrence. `evalLog`, `friLogs`, and `queries` exist only for
 * reduced test geometries; production callers use the no-argument form.
 */
export function planV17ProductionMerkleStages(overrides: {
  readonly evalLog?: number;
  readonly friLogs?: readonly number[];
  readonly queries?: number;
} = {}): V17ProductionMerklePlanSet {
  const production = v17ProductionMerkleDescriptors();
  const queries = overrides.queries ?? V17_CONSTRUCTION_GRAPH.foundation.queries;
  const evalLog = overrides.evalLog ?? production.matrices.preprocessed.logRows;
  const friLogs = overrides.friLogs ?? production.fri.map(({ logRows }) => logRows);
  if (!Number.isSafeInteger(queries) || queries < 1 ||
    !Number.isSafeInteger(evalLog) || evalLog < 2 ||
    friLogs.length !== production.fri.length ||
    friLogs.some((log) => !Number.isSafeInteger(log) || log < 2)) {
    throw new Error("v17 production Merkle plan geometry");
  }
  const matrixEntries = Object.entries(production.matrices).map(([name, base]) => {
    const descriptor = { ...base, logRows: evalLog };
    const opening = { openedLeaves: name === "interactionGlobal" ? queries * 2 : queries } as const;
    const plan = planV17ProtocolMerkleStages({ descriptor, opening, kind: "matrix" });
    return [name, { id: `matrix:${name}`, kind: "matrix", descriptor, opening, plan }] as const;
  });
  const matrices = Object.fromEntries(matrixEntries) as Record<string, V17ProductionMerklePlan>;
  const fri = production.fri.map((base, layer): V17ProductionMerklePlan => {
    const descriptor = { ...base, logRows: friLogs[layer]! };
    const opening = { completeFirstGroups: queries } as const;
    const plan = planV17ProtocolMerkleStages({ descriptor, opening, kind: "fri" });
    return { id: `fri:${layer}`, kind: "fri", descriptor, opening, plan };
  });
  return {
    matrices,
    fri,
    matrixRoleCount: Object.values(matrices).reduce((sum, item) => sum + item.plan.stages.length, 0),
    friRoleCount: fri.reduce((sum, item) => sum + item.plan.stages.length, 0),
  };
}

type Candidate = {
  readonly stages: readonly V17MerkleStage[];
  readonly cuts: readonly number[];
  readonly serializedCutBytes: number;
};

function lexicographicallyLess(left: readonly number[], right: readonly number[]): boolean {
  for (let index = 0; index < Math.min(left.length, right.length); index += 1) {
    if (left[index] !== right[index]) return left[index]! < right[index]!;
  }
  return left.length < right.length;
}

function better(left: Candidate, right: Candidate | undefined): boolean {
  if (right === undefined) return true;
  if (left.stages.length !== right.stages.length) return left.stages.length < right.stages.length;
  if (left.serializedCutBytes !== right.serializedCutBytes) {
    return left.serializedCutBytes < right.serializedCutBytes;
  }
  return lexicographicallyLess(left.cuts, right.cuts);
}

function publicStage(edge: V17MerklePlannerEdge): V17MerkleStage {
  const { valid: _valid, rejectedBy: _rejectedBy, ...stage } = edge;
  return stage;
}

/**
 * Dynamic programming selects the fewest valid stages, then the fewest
 * serialized handoff bytes, then the lexicographically earliest cut vector.
 * The certificate contains all rejected coarsenings and is independently
 * reproducible from the verifier-key input.
 */
export function planV17MerkleStages(input: V17MerklePlannerInput): V17MerklePlan {
  validateInput(input);
  const maximum = maximumV17MerkleOpening(input.descriptor, input.opening);
  const levelCount = maximum.levels.length;
  const edges: V17MerklePlannerEdge[] = [];
  const edgeBySpan = new Map<string, V17MerklePlannerEdge>();
  for (let start = 0; start < levelCount; start += 1) {
    for (let end = start + 1; end <= levelCount; end += 1) {
      const edge = stageEdge(input, maximum, start, end);
      edges.push(edge);
      edgeBySpan.set(`${start}:${end}`, edge);
    }
  }

  const best: (Candidate | undefined)[] = Array.from({ length: levelCount + 1 });
  best[0] = { stages: [], cuts: [], serializedCutBytes: 0 };
  for (let end = 1; end <= levelCount; end += 1) {
    for (let start = 0; start < end; start += 1) {
      const prefix = best[start];
      const edge = edgeBySpan.get(`${start}:${end}`)!;
      if (prefix === undefined || !edge.valid) continue;
      const internalCut = end < levelCount;
      const candidate: Candidate = {
        stages: [...prefix.stages, publicStage(edge)],
        cuts: internalCut ? [...prefix.cuts, edge.endBits] : prefix.cuts,
        serializedCutBytes: prefix.serializedCutBytes +
          (internalCut ? edge.outputFrontierBytes : 0),
      };
      if (better(candidate, best[end])) best[end] = candidate;
    }
  }
  const selected = best[levelCount];
  if (selected === undefined) throw new Error("v17 Merkle planner infeasible");
  const minimumStagesToBoundary = best.map((candidate) => candidate?.stages.length ?? null);
  const certificate: V17MerklePlanCertificate = {
    version: 1,
    input: {
      descriptor: { ...input.descriptor },
      opening: { ...input.opening },
      weights: { ...input.weights },
      limits: { ...input.limits },
    },
    maximum,
    edges,
    minimumStagesToBoundary,
    selectedCuts: [...selected.cuts],
    selectedStageCount: selected.stages.length,
    serializedCutBytes: selected.serializedCutBytes,
  };
  return {
    cuts: [...selected.cuts],
    stages: [...selected.stages],
    serializedCutBytes: selected.serializedCutBytes,
    certificate,
  };
}

/** A certificate is valid only when full deterministic regeneration matches. */
export function verifyV17MerklePlanCertificate(
  certificate: V17MerklePlanCertificate,
): boolean {
  try {
    if (certificate.version !== 1) return false;
    const regenerated = planV17MerkleStages(certificate.input).certificate;
    return JSON.stringify(regenerated) === JSON.stringify(certificate);
  } catch {
    return false;
  }
}

export type V17MerkleStageMeasurement = {
  readonly startLevel: number;
  readonly endLevel: number;
  readonly lockingBytes: number;
  readonly operationCost: number;
  /** False when consensus evaluation rejects before the numeric limits apply. */
  readonly consensusValid?: boolean;
};

export type V17MeasuredMerklePlannerInput = {
  readonly descriptor: V17MerkleDescriptor;
  readonly opening: V17MaximumOpeningRequest;
  /** One exact measurement for every homogeneous-arity contiguous stage. */
  readonly measurements: readonly V17MerkleStageMeasurement[];
  readonly limits: {
    readonly maxLockingBytes: number;
    readonly maxOperationCost: number;
    readonly maxHandoffBytes: number;
  };
};

export type V17MeasuredMerkleStage = V17MerkleStageMeasurement & {
  readonly startBits: number;
  readonly endBits: number;
  readonly inputFrontierBytes: number;
  readonly outputFrontierBytes: number;
};

export type V17MeasuredMerklePlanCertificate = {
  readonly version: 1;
  readonly input: V17MeasuredMerklePlannerInput;
  readonly selectedCuts: readonly number[];
  readonly selectedSpans: readonly { readonly startLevel: number; readonly endLevel: number }[];
  readonly serializedCutBytes: number;
};

export type V17MeasuredMerklePlan = {
  readonly cuts: readonly number[];
  readonly stages: readonly V17MeasuredMerkleStage[];
  readonly serializedCutBytes: number;
  readonly certificate: V17MeasuredMerklePlanCertificate;
};

/**
 * Final planner boundary: candidate selection is driven only by measured BCH
 * byte/opcost evidence. Missing spans, duplicate spans, and optimistic
 * handoff sizes fail closed, so no role count is an input or invariant.
 */
export function planV17MerkleStagesFromMeasurements(
  input: V17MeasuredMerklePlannerInput,
): V17MeasuredMerklePlan {
  positiveSafeInteger(input.limits.maxLockingBytes, "measured locking limit");
  positiveSafeInteger(input.limits.maxOperationCost, "measured opcost limit");
  positiveSafeInteger(input.limits.maxHandoffBytes, "measured handoff limit");
  const maximum = maximumV17MerkleOpening(input.descriptor, input.opening);
  const bits = boundaryBits(maximum);
  const levelCount = maximum.levels.length;
  const candidateSpans = new Set<string>();
  for (let start = 0; start < levelCount; start += 1) {
    for (let end = start + 1; end <= levelCount; end += 1) {
      if (new Set(maximum.levels.slice(start, end).map(({ arity }) => arity)).size === 1) {
        candidateSpans.add(`${start}:${end}`);
      }
    }
  }
  const expectedCount = candidateSpans.size;
  const bySpan = new Map<string, V17MeasuredMerkleStage>();
  for (const measurement of input.measurements) {
    if (!Number.isInteger(measurement.startLevel) || !Number.isInteger(measurement.endLevel) ||
      measurement.startLevel < 0 || measurement.startLevel >= measurement.endLevel ||
      measurement.endLevel > levelCount || !Number.isSafeInteger(measurement.lockingBytes) ||
      measurement.lockingBytes < 1 || !Number.isSafeInteger(measurement.operationCost) ||
      measurement.operationCost < 1 ||
      (measurement.consensusValid !== undefined && typeof measurement.consensusValid !== "boolean")) {
      throw new Error("v17 measured Merkle stage");
    }
    const key = `${measurement.startLevel}:${measurement.endLevel}`;
    if (!candidateSpans.has(key)) throw new Error("non-candidate v17 measured Merkle stage");
    if (bySpan.has(key)) throw new Error("duplicate v17 measured Merkle stage");
    const inputFrontierBytes = measurement.startLevel === 0
      ? 0
      : maximum.frontierNodes[measurement.startLevel]! * FRONTIER_NODE_BYTES;
    const outputFrontierBytes = measurement.endLevel === levelCount
      ? 0
      : maximum.frontierNodes[measurement.endLevel]! * FRONTIER_NODE_BYTES;
    bySpan.set(key, {
      ...measurement,
      startBits: bits[measurement.startLevel]!,
      endBits: bits[measurement.endLevel]!,
      inputFrontierBytes,
      outputFrontierBytes,
    });
  }
  if (input.measurements.length !== expectedCount || bySpan.size !== expectedCount) {
    throw new Error("incomplete v17 measured Merkle stages");
  }
  const best: ({ readonly stages: readonly V17MeasuredMerkleStage[];
    readonly cuts: readonly number[]; readonly serializedCutBytes: number } | undefined)[] =
    Array.from({ length: levelCount + 1 });
  best[0] = { stages: [], cuts: [], serializedCutBytes: 0 };
  for (let end = 1; end <= levelCount; end += 1) {
    for (let start = 0; start < end; start += 1) {
      const prefix = best[start];
      const stage = bySpan.get(`${start}:${end}`);
      if (prefix === undefined || stage === undefined ||
        stage.consensusValid === false ||
        stage.lockingBytes > input.limits.maxLockingBytes ||
        stage.operationCost > input.limits.maxOperationCost ||
        stage.inputFrontierBytes > input.limits.maxHandoffBytes ||
        stage.outputFrontierBytes > input.limits.maxHandoffBytes) continue;
      const internalCut = end < levelCount;
      const candidate = {
        stages: [...prefix.stages, stage],
        cuts: internalCut ? [...prefix.cuts, stage.endBits] : prefix.cuts,
        serializedCutBytes: prefix.serializedCutBytes +
          (internalCut ? stage.outputFrontierBytes : 0),
      };
      const current = best[end];
      if (current === undefined || candidate.stages.length < current.stages.length ||
        (candidate.stages.length === current.stages.length &&
          (candidate.serializedCutBytes < current.serializedCutBytes ||
            (candidate.serializedCutBytes === current.serializedCutBytes &&
              lexicographicallyLess(candidate.cuts, current.cuts))))) {
        best[end] = candidate;
      }
    }
  }
  const selected = best[levelCount];
  if (selected === undefined) throw new Error("v17 measured Merkle planner infeasible");
  const certificate: V17MeasuredMerklePlanCertificate = {
    version: 1,
    input: {
      descriptor: { ...input.descriptor },
      opening: { ...input.opening },
      measurements: input.measurements.map((measurement) => ({ ...measurement })),
      limits: { ...input.limits },
    },
    selectedCuts: [...selected.cuts],
    selectedSpans: selected.stages.map(({ startLevel, endLevel }) => ({ startLevel, endLevel })),
    serializedCutBytes: selected.serializedCutBytes,
  };
  return { ...selected, certificate };
}

export function verifyV17MeasuredMerklePlanCertificate(
  certificate: V17MeasuredMerklePlanCertificate,
): boolean {
  try {
    if (certificate.version !== 1) return false;
    return JSON.stringify(planV17MerkleStagesFromMeasurements(certificate.input).certificate) ===
      JSON.stringify(certificate);
  } catch {
    return false;
  }
}

import {
  concatBytes,
  eq32,
  readU32BE,
  sha256,
  writeU16BE,
  writeU32BE,
} from "../../pool/bytes.ts";
import {
  V17_CONSTRUCTION_GRAPH,
  type V17CommitmentSpec,
} from "../../construction/v17-graph.ts";

const DOMAIN = new TextEncoder().encode("ShieldKit/Merkle/v17");
const LEAF_TAG = Uint8Array.of(0);
const BINARY_TAG = Uint8Array.of(1);
const QUARTET_TAG = Uint8Array.of(2);

export type V17MerkleShape = "binary" | "quartet-first";

export const V17_PRODUCTION_MATRIX_NAMES = [
  "preprocessed",
  "original",
  "interaction",
  "interactionGlobal",
  "quotientAndFriMask",
] as const;

export type V17ProductionMatrixName = typeof V17_PRODUCTION_MATRIX_NAMES[number];

/** A verifier-key value. No descriptor field is selected by proof bytes. */
export type V17MerkleDescriptor = {
  readonly shape: V17MerkleShape;
  readonly label: string;
  readonly logRows: number;
  readonly rowWidth: number;
};

export type V17MerkleLevel = {
  readonly level: number;
  readonly arity: 2 | 4;
  readonly consumedBits: number;
  readonly nextConsumedBits: number;
};

export type V17MerkleScheduleLevel = V17MerkleLevel & {
  readonly frontierIndices: readonly number[];
  readonly parentIndices: readonly number[];
  readonly siblingIndices: readonly number[];
};

export type V17MerkleSchedule = {
  readonly indices: readonly number[];
  readonly levels: readonly V17MerkleScheduleLevel[];
  readonly siblingCount: number;
};

export type V17MerkleRow = {
  readonly index: number;
  readonly raw: Uint8Array;
};

export type V17MerkleFrontierNode = {
  readonly index: number;
  readonly hash: Uint8Array;
};

export type V17MerkleCutFrontier = {
  readonly consumedBits: number;
  readonly nodes: readonly V17MerkleFrontierNode[];
};

export type V17MerkleOpening = {
  readonly rows: readonly V17MerkleRow[];
  readonly siblings: readonly Uint8Array[];
  readonly cuts: readonly V17MerkleCutFrontier[];
  readonly root: Uint8Array;
};

export type V17MaximumOpeningRequest =
  | { readonly openedLeaves: number }
  | { readonly completeFirstGroups: number };

export type V17MaximumOpeningLevel = V17MerkleLevel & {
  readonly frontierNodes: number;
  readonly parentNodes: number;
  readonly siblingNodes: number;
};

export type V17MaximumOpening = {
  readonly descriptor: V17MerkleDescriptor;
  readonly request: V17MaximumOpeningRequest;
  readonly openedLeafCount: number;
  /** Frontier cardinality at level boundaries, including leaves and root. */
  readonly frontierNodes: readonly number[];
  readonly levels: readonly V17MaximumOpeningLevel[];
  readonly siblingCount: number;
  readonly parentHashCount: number;
};

export type V17ProductionMerkleDescriptors = {
  readonly matrices: Readonly<Record<V17ProductionMatrixName, V17MerkleDescriptor>>;
  readonly fri: readonly V17MerkleDescriptor[];
};

function descriptorFromCommitment(commitment: V17CommitmentSpec): V17MerkleDescriptor {
  const consumedBits = commitment.arities.reduce(
    (sum, arity) => sum + (arity === 4 ? 2 : 1),
    0,
  );
  if (consumedBits !== commitment.domainLog || commitment.arities.length < 1) {
    throw new Error(`v17 Merkle graph arities ${commitment.id}`);
  }
  const shape: V17MerkleShape = commitment.arities[0] === 4
    ? "quartet-first"
    : "binary";
  if (commitment.arities.some((arity, level) =>
    arity !== 2 && !(level === 0 && shape === "quartet-first" && arity === 4))) {
    throw new Error(`v17 Merkle graph shape ${commitment.id}`);
  }
  const widthMatch = /:(\d+)-bytes$/.exec(commitment.leafCodec);
  const codecWidth = commitment.leafCodec === "qm31-value"
    ? 16
    : Number(widthMatch?.[1]);
  if (!Number.isSafeInteger(codecWidth) || codecWidth !== commitment.rowBytes) {
    throw new Error(`v17 Merkle graph leaf codec ${commitment.id}`);
  }
  return validateV17MerkleDescriptor({
    shape,
    label: commitment.hashLabel,
    logRows: commitment.domainLog,
    rowWidth: commitment.rowBytes,
  });
}

/**
 * Convert the typed construction graph into the only accepted production
 * descriptor inventory. Unknown, duplicate, missing, or non-minimal tree
 * languages fail closed instead of silently selecting another hash grammar.
 */
export function v17MerkleDescriptorsFromCommitments(
  commitments: readonly V17CommitmentSpec[],
): V17ProductionMerkleDescriptors {
  const byId = new Map<string, V17CommitmentSpec>();
  for (const commitment of commitments) {
    if (byId.has(commitment.id)) throw new Error(`duplicate v17 Merkle commitment ${commitment.id}`);
    byId.set(commitment.id, commitment);
  }
  const expectedIds = [
    ...V17_PRODUCTION_MATRIX_NAMES.map((name) => `matrix:${name}`),
    ...Array.from({ length: 9 }, (_, layer) => `fri:${layer}`),
  ];
  if (commitments.length !== expectedIds.length ||
    expectedIds.some((id) => !byId.has(id)) ||
    commitments.some(({ id }) => !expectedIds.includes(id))) {
    throw new Error("v17 Merkle graph inventory");
  }
  const matrices = Object.fromEntries(V17_PRODUCTION_MATRIX_NAMES.map((name) => [
    name,
    descriptorFromCommitment(byId.get(`matrix:${name}`)!),
  ])) as Record<V17ProductionMatrixName, V17MerkleDescriptor>;
  const fri = Array.from({ length: 9 }, (_, layer) =>
    descriptorFromCommitment(byId.get(`fri:${layer}`)!));
  return { matrices, fri };
}

/** The construction graph is the sole production commitment inventory. */
export function v17ProductionMerkleDescriptors(): V17ProductionMerkleDescriptors {
  return v17MerkleDescriptorsFromCommitments(V17_CONSTRUCTION_GRAPH.commitments);
}

function descriptorRowCount(descriptor: V17MerkleDescriptor): number {
  return 2 ** descriptor.logRows;
}

function shapeCode(shape: V17MerkleShape): number {
  if (shape === "binary") return 0;
  if (shape === "quartet-first") return 1;
  throw new Error("v17 Merkle shape");
}

function labelBytes(descriptor: V17MerkleDescriptor): Uint8Array {
  if (!/^[A-Za-z0-9:_-]+$/.test(descriptor.label)) {
    throw new Error("v17 Merkle label");
  }
  const bytes = new TextEncoder().encode(descriptor.label);
  if (bytes.length < 1 || bytes.length > 96) throw new Error("v17 Merkle label");
  return bytes;
}

export function validateV17MerkleDescriptor(
  descriptor: V17MerkleDescriptor,
): V17MerkleDescriptor {
  shapeCode(descriptor.shape);
  labelBytes(descriptor);
  if (!Number.isInteger(descriptor.logRows) || descriptor.logRows < 1 ||
    descriptor.logRows > 30 ||
    (descriptor.shape === "quartet-first" && descriptor.logRows < 2)) {
    throw new Error("v17 Merkle row geometry");
  }
  if (!Number.isInteger(descriptor.rowWidth) || descriptor.rowWidth < 1 ||
    descriptor.rowWidth > 0xffff) {
    throw new Error("v17 Merkle row width");
  }
  return descriptor;
}

export function v17MerkleTreeKey(descriptor: V17MerkleDescriptor): Uint8Array {
  validateV17MerkleDescriptor(descriptor);
  const label = labelBytes(descriptor);
  return sha256(concatBytes(
    DOMAIN,
    Uint8Array.of(shapeCode(descriptor.shape), descriptor.logRows),
    writeU16BE(descriptor.rowWidth),
    Uint8Array.of(label.length),
    label,
  ));
}

export function v17MerkleLevels(
  descriptor: V17MerkleDescriptor,
): readonly V17MerkleLevel[] {
  validateV17MerkleDescriptor(descriptor);
  const levels: V17MerkleLevel[] = [];
  let consumedBits = 0;
  if (descriptor.shape === "quartet-first") {
    levels.push({ level: 0, arity: 4, consumedBits: 0, nextConsumedBits: 2 });
    consumedBits = 2;
  }
  while (consumedBits < descriptor.logRows) {
    levels.push({
      level: levels.length,
      arity: 2,
      consumedBits,
      nextConsumedBits: consumedBits + 1,
    });
    consumedBits += 1;
  }
  return levels;
}

function hashLeaf(
  treeKey: Uint8Array,
  index: number,
  raw: Uint8Array,
): Uint8Array {
  return sha256(concatBytes(LEAF_TAG, treeKey, writeU32BE(index), raw));
}

function hashParent(
  treeKey: Uint8Array,
  level: V17MerkleLevel,
  children: readonly Uint8Array[],
): Uint8Array {
  if (children.length !== level.arity || children.some((child) => child.length !== 32)) {
    throw new Error("v17 Merkle parent width");
  }
  return sha256(concatBytes(
    level.arity === 2 ? BINARY_TAG : QUARTET_TAG,
    treeKey,
    Uint8Array.of(level.consumedBits),
    ...children,
  ));
}

export function v17MerkleLeaf(
  descriptor: V17MerkleDescriptor,
  index: number,
  raw: Uint8Array,
): Uint8Array {
  validateV17MerkleDescriptor(descriptor);
  if (!Number.isSafeInteger(index) || index < 0 || index >= descriptorRowCount(descriptor) ||
    raw.length !== descriptor.rowWidth) {
    throw new Error("v17 Merkle leaf");
  }
  return hashLeaf(v17MerkleTreeKey(descriptor), index, raw);
}

function validateIndices(
  descriptor: V17MerkleDescriptor,
  indices: readonly number[],
): readonly number[] {
  validateV17MerkleDescriptor(descriptor);
  const rowCount = descriptorRowCount(descriptor);
  if (indices.length < 1 || indices.some((index) => !Number.isSafeInteger(index) ||
    index < 0 || index >= rowCount) ||
    indices.some((index, position) => position > 0 && indices[position - 1]! >= index)) {
    throw new Error("v17 Merkle indices");
  }
  return indices;
}

function uniqueParents(indices: readonly number[], arity: 2 | 4): number[] {
  const parents: number[] = [];
  let previous = -1;
  for (const index of indices) {
    const parent = Math.floor(index / arity);
    if (parent !== previous) parents.push(parent);
    previous = parent;
  }
  return parents;
}

/** The sole index-only traversal used by prover, codec, planner, and verifier. */
export function v17MerkleSchedule(
  descriptor: V17MerkleDescriptor,
  indices: readonly number[],
): V17MerkleSchedule {
  validateIndices(descriptor, indices);
  let frontier = [...indices];
  let siblingCount = 0;
  const levels = v17MerkleLevels(descriptor).map((level): V17MerkleScheduleLevel => {
    const present = new Set(frontier);
    const parents = uniqueParents(frontier, level.arity);
    const siblings: number[] = [];
    for (const parent of parents) {
      for (let child = 0; child < level.arity; child += 1) {
        const index = parent * level.arity + child;
        if (!present.has(index)) siblings.push(index);
      }
    }
    const result = {
      ...level,
      frontierIndices: frontier,
      parentIndices: parents,
      siblingIndices: siblings,
    };
    siblingCount += siblings.length;
    frontier = parents;
    return result;
  });
  if (frontier.length !== 1 || frontier[0] !== 0) {
    throw new Error("v17 Merkle root schedule");
  }
  return { indices: [...indices], levels, siblingCount };
}

function validateRows(
  descriptor: V17MerkleDescriptor,
  rows: readonly V17MerkleRow[],
): readonly number[] {
  const indices = rows.map(({ index }) => index);
  validateIndices(descriptor, indices);
  if (rows.some(({ raw }) => raw.length !== descriptor.rowWidth)) {
    throw new Error("v17 Merkle row width");
  }
  return indices;
}

function validateCutBits(
  descriptor: V17MerkleDescriptor,
  cutBits: readonly number[],
): readonly number[] {
  const allowed = new Set<number>([0]);
  for (const level of v17MerkleLevels(descriptor)) {
    if (level.nextConsumedBits < descriptor.logRows) allowed.add(level.nextConsumedBits);
  }
  if (cutBits.some((bits) => !Number.isInteger(bits) || !allowed.has(bits)) ||
    cutBits.some((bits, position) => position > 0 && cutBits[position - 1]! >= bits)) {
    throw new Error("v17 Merkle cuts");
  }
  return cutBits;
}

function copyFrontier(
  consumedBits: number,
  frontier: ReadonlyMap<number, Uint8Array>,
): V17MerkleCutFrontier {
  return {
    consumedBits,
    nodes: [...frontier.entries()].map(([index, hash]) => ({
      index,
      hash: hash.slice(),
    })),
  };
}

function traverseOpening(
  descriptor: V17MerkleDescriptor,
  rows: readonly V17MerkleRow[],
  siblings: readonly Uint8Array[],
  cutBits: readonly number[],
): { readonly root: Uint8Array; readonly cuts: readonly V17MerkleCutFrontier[] } {
  const indices = validateRows(descriptor, rows);
  const schedule = v17MerkleSchedule(descriptor, indices);
  validateCutBits(descriptor, cutBits);
  if (siblings.length !== schedule.siblingCount || siblings.some((node) => node.length !== 32)) {
    throw new Error("v17 Merkle siblings");
  }
  const treeKey = v17MerkleTreeKey(descriptor);
  let frontier = new Map<number, Uint8Array>(
    rows.map(({ index, raw }) => [index, hashLeaf(treeKey, index, raw)]),
  );
  const wantedCuts = new Set(cutBits);
  const cuts = new Map<number, V17MerkleCutFrontier>();
  if (wantedCuts.has(0)) cuts.set(0, copyFrontier(0, frontier));
  let siblingCursor = 0;
  for (const level of schedule.levels) {
    const next = new Map<number, Uint8Array>();
    for (const parent of level.parentIndices) {
      const children: Uint8Array[] = [];
      for (let child = 0; child < level.arity; child += 1) {
        const index = parent * level.arity + child;
        const value = frontier.get(index) ?? siblings[siblingCursor++];
        if (!value || value.length !== 32) throw new Error("v17 Merkle sibling traversal");
        children.push(value);
      }
      next.set(parent, hashParent(treeKey, level, children));
    }
    frontier = next;
    if (wantedCuts.has(level.nextConsumedBits)) {
      cuts.set(level.nextConsumedBits, copyFrontier(level.nextConsumedBits, frontier));
    }
  }
  if (siblingCursor !== siblings.length || frontier.size !== 1 || !frontier.has(0)) {
    throw new Error("v17 Merkle traversal");
  }
  return {
    root: frontier.get(0)!.slice(),
    cuts: cutBits.map((bits) => cuts.get(bits)!),
  };
}

function encodeCut(cut: V17MerkleCutFrontier): Uint8Array {
  return concatBytes(...cut.nodes.map(({ index, hash }) => {
    if (hash.length !== 32) throw new Error("v17 Merkle cut hash");
    return concatBytes(writeU32BE(index), hash);
  }));
}

/** The canonical derived handoff material for verifier-key cut boundaries. */
export function v17MerkleCutFrontiers(args: {
  readonly descriptor: V17MerkleDescriptor;
  readonly rows: readonly V17MerkleRow[];
  readonly siblings: readonly Uint8Array[];
  readonly cutBits: readonly number[];
}): readonly V17MerkleCutFrontier[] {
  return traverseOpening(args.descriptor, args.rows, args.siblings, args.cutBits).cuts;
}

export function v17MerkleOpeningRoot(args: {
  readonly descriptor: V17MerkleDescriptor;
  readonly rows: readonly V17MerkleRow[];
  readonly siblings: readonly Uint8Array[];
}): Uint8Array {
  return traverseOpening(args.descriptor, args.rows, args.siblings, []).root;
}

export function encodeV17MerkleCutFrontiers(
  cuts: readonly V17MerkleCutFrontier[],
): Uint8Array {
  return concatBytes(...cuts.map(encodeCut));
}

/**
 * Canonical opening body: rows, siblings, then derived cut frontiers. Indices,
 * counts, arities, labels, and merge programs are verifier-key data and are
 * deliberately absent.
 */
export function encodeV17MerkleOpening(args: {
  readonly descriptor: V17MerkleDescriptor;
  readonly rows: readonly V17MerkleRow[];
  readonly siblings: readonly Uint8Array[];
  readonly cutBits?: readonly number[];
}): Uint8Array {
  const cutBits = args.cutBits ?? [];
  const traversal = traverseOpening(args.descriptor, args.rows, args.siblings, cutBits);
  return concatBytes(
    ...args.rows.map(({ raw }) => raw),
    ...args.siblings,
    ...traversal.cuts.map(encodeCut),
  );
}

function frontierIndicesAtCuts(
  schedule: V17MerkleSchedule,
  cutBits: readonly number[],
): readonly (readonly number[])[] {
  const byBits = new Map<number, readonly number[]>([[0, schedule.indices]]);
  for (const level of schedule.levels) {
    byBits.set(level.nextConsumedBits, level.parentIndices);
  }
  return cutBits.map((bits) => byBits.get(bits)!);
}

/** Strict decoding requires the transcript-derived indices and verifier-key cuts. */
export function decodeV17MerkleOpening(
  bytes: Uint8Array,
  args: {
    readonly descriptor: V17MerkleDescriptor;
    readonly indices: readonly number[];
    readonly cutBits?: readonly number[];
    readonly expectedRoot?: Uint8Array;
  },
): V17MerkleOpening {
  const cutBits = args.cutBits ?? [];
  validateIndices(args.descriptor, args.indices);
  validateCutBits(args.descriptor, cutBits);
  if (args.expectedRoot !== undefined && args.expectedRoot.length !== 32) {
    throw new Error("v17 Merkle expected root");
  }
  const schedule = v17MerkleSchedule(args.descriptor, args.indices);
  const cutIndices = frontierIndicesAtCuts(schedule, cutBits);
  const expectedLength = args.indices.length * args.descriptor.rowWidth +
    schedule.siblingCount * 32 +
    cutIndices.reduce((sum, indices) => sum + indices.length * 36, 0);
  if (bytes.length !== expectedLength) throw new Error("v17 Merkle opening length");

  let cursor = 0;
  const take = (count: number): Uint8Array => {
    const value = bytes.slice(cursor, cursor + count);
    cursor += count;
    return value;
  };
  const rows = args.indices.map((index): V17MerkleRow => ({
    index,
    raw: take(args.descriptor.rowWidth),
  }));
  const siblings = Array.from({ length: schedule.siblingCount }, () => take(32));
  const traversal = traverseOpening(args.descriptor, rows, siblings, cutBits);
  for (let cut = 0; cut < cutBits.length; cut += 1) {
    const expected = traversal.cuts[cut]!;
    for (const node of expected.nodes) {
      const index = readU32BE(bytes, cursor);
      cursor += 4;
      const hash = take(32);
      if (index !== node.index || !eq32(hash, node.hash)) {
        throw new Error("v17 Merkle cut frontier");
      }
    }
  }
  if (cursor !== bytes.length) throw new Error("trailing v17 Merkle opening bytes");
  if (args.expectedRoot !== undefined && !eq32(traversal.root, args.expectedRoot)) {
    throw new Error("v17 Merkle root");
  }
  return { rows, siblings, cuts: traversal.cuts, root: traversal.root };
}

export function verifyV17MerkleOpening(
  bytes: Uint8Array,
  args: Parameters<typeof decodeV17MerkleOpening>[1] & { readonly expectedRoot: Uint8Array },
): boolean {
  try {
    decodeV17MerkleOpening(bytes, args);
    return true;
  } catch {
    return false;
  }
}

/** Small in-memory reference tree. Production provers may stream the same traversal. */
export class V17MerkleTree {
  readonly descriptor: V17MerkleDescriptor;
  readonly rows: readonly Uint8Array[];
  readonly layers: readonly (readonly Uint8Array[])[];

  constructor(descriptor: V17MerkleDescriptor, rows: readonly Uint8Array[]) {
    validateV17MerkleDescriptor(descriptor);
    const rowCount = descriptorRowCount(descriptor);
    if (rows.length !== rowCount || rows.some((row) => row.length !== descriptor.rowWidth)) {
      throw new Error("v17 Merkle tree rows");
    }
    this.descriptor = { ...descriptor };
    this.rows = rows.map((row) => row.slice());
    const treeKey = v17MerkleTreeKey(descriptor);
    const layers: Uint8Array[][] = [
      this.rows.map((raw, index) => hashLeaf(treeKey, index, raw)),
    ];
    for (const level of v17MerkleLevels(descriptor)) {
      const current = layers.at(-1)!;
      const next: Uint8Array[] = [];
      for (let start = 0; start < current.length; start += level.arity) {
        next.push(hashParent(treeKey, level, current.slice(start, start + level.arity)));
      }
      layers.push(next);
    }
    this.layers = layers;
  }

  get root(): Uint8Array {
    return this.layers.at(-1)![0]!.slice();
  }

  multiproof(indices: readonly number[]): readonly Uint8Array[] {
    const schedule = v17MerkleSchedule(this.descriptor, indices);
    return schedule.levels.flatMap((level, levelIndex) =>
      level.siblingIndices.map((index) => this.layers[levelIndex]![index]!.slice()));
  }

  opening(indices: readonly number[]): {
    readonly rows: readonly V17MerkleRow[];
    readonly siblings: readonly Uint8Array[];
    readonly root: Uint8Array;
  } {
    validateIndices(this.descriptor, indices);
    return {
      rows: indices.map((index) => ({ index, raw: this.rows[index]!.slice() })),
      siblings: this.multiproof(indices),
      root: this.root,
    };
  }
}

/**
 * Tight schedule-independent recurrence. `completeFirstGroups` models FRI
 * cosets which open every child of the first level, so that level has no
 * authentication siblings.
 */
export function maximumV17MerkleOpening(
  descriptor: V17MerkleDescriptor,
  request: V17MaximumOpeningRequest,
): V17MaximumOpening {
  validateV17MerkleDescriptor(descriptor);
  const specs = v17MerkleLevels(descriptor);
  const rowCount = descriptorRowCount(descriptor);
  const completeGroups = "completeFirstGroups" in request;
  let frontier: number;
  let openedLeafCount: number;
  let startLevel = 0;
  const levels: V17MaximumOpeningLevel[] = [];
  const frontierNodes: number[] = [];

  if (completeGroups) {
    const groups = request.completeFirstGroups;
    const first = specs[0]!;
    if (!Number.isSafeInteger(groups) || groups < 1 || groups > rowCount / first.arity) {
      throw new Error("v17 Merkle complete groups");
    }
    openedLeafCount = groups * first.arity;
    frontierNodes.push(openedLeafCount);
    levels.push({
      ...first,
      frontierNodes: openedLeafCount,
      parentNodes: groups,
      siblingNodes: 0,
    });
    frontier = groups;
    frontierNodes.push(frontier);
    startLevel = 1;
  } else {
    const leaves = request.openedLeaves;
    if (!Number.isSafeInteger(leaves) || leaves < 1 || leaves > rowCount) {
      throw new Error("v17 Merkle opened leaves");
    }
    openedLeafCount = leaves;
    frontier = leaves;
    frontierNodes.push(frontier);
  }

  for (let index = startLevel; index < specs.length; index += 1) {
    const level = specs[index]!;
    const nodesAtLevel = 2 ** (descriptor.logRows - level.consumedBits);
    const parentCapacity = nodesAtLevel / level.arity;
    const parents = Math.min(frontier, parentCapacity);
    const siblings = level.arity * parents - frontier;
    levels.push({
      ...level,
      frontierNodes: frontier,
      parentNodes: parents,
      siblingNodes: siblings,
    });
    frontier = parents;
    frontierNodes.push(frontier);
  }
  if (frontier !== 1 || levels.length !== specs.length ||
    frontierNodes.length !== specs.length + 1) {
    throw new Error("v17 Merkle maximum recurrence");
  }
  return {
    descriptor: { ...descriptor },
    request: { ...request },
    openedLeafCount,
    frontierNodes,
    levels,
    siblingCount: levels.reduce((sum, level) => sum + level.siblingNodes, 0),
    parentHashCount: levels.reduce((sum, level) => sum + level.parentNodes, 0),
  };
}

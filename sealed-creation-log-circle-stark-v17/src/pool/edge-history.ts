import { concatBytes, eq32, sha256, writeU64BE, ZERO32 } from "./bytes.ts";
import { commitNote, type Note } from "./notes.ts";

const utf8 = (value: string): Uint8Array => new TextEncoder().encode(value);

/**
 * Fixed relation context, independent of the eventual artifact manifest hash.
 * This avoids a circular construction ID while keeping every v16 hash scoped.
 */
export const CREATION_LOG_CONTEXT = sha256(
  utf8("shieldkit.cash/labs/sealed-creation-log/v16/relation-context/1"),
);
export const CREATION_LINK_DOMAIN = sha256(
  utf8("shieldkit.cash/labs/sealed-creation-log/v16/creation-link/1"),
);
export const CREATION_EDGE_DOMAIN = sha256(
  utf8("shieldkit.cash/labs/sealed-creation-log/v16/creation-edge/1"),
);
export const EDGE_NULLIFIER_DOMAIN = sha256(
  utf8("shieldkit.cash/labs/sealed-creation-log/v16/edge-nullifier/1"),
);

export const EDGE_HISTORY_DEPTH = 32;
export const EDGE_HISTORY_CAPACITY = 1n << BigInt(EDGE_HISTORY_DEPTH);

export type CreatedNoteRecord = {
  readonly note: Note;
  readonly creationIndex: bigint;
  readonly previousHead: Uint8Array;
};

export type CreatedNoteContext = {
  readonly noteCommitment: Uint8Array;
  readonly creationHead: Uint8Array;
  readonly edge: Uint8Array;
};

export type EdgeMembershipWitness = {
  readonly index: bigint;
  readonly edge: Uint8Array;
  readonly path: readonly Uint8Array[];
  readonly root: Uint8Array;
};

export type EdgeAppendWitness = {
  readonly index: bigint;
  readonly edge: Uint8Array;
  readonly path: readonly Uint8Array[];
  readonly oldRoot: Uint8Array;
  readonly newRoot: Uint8Array;
};

function assert32(value: Uint8Array, name: string): Uint8Array {
  if (value.length !== 32) throw new Error(`${name} must be 32 bytes`);
  return value;
}

function assertCreationIndex(index: bigint): bigint {
  if (index < 0n || index >= EDGE_HISTORY_CAPACITY) {
    throw new Error("creation index out of range");
  }
  return index;
}

function assertPath(path: readonly Uint8Array[]): void {
  if (path.length !== EDGE_HISTORY_DEPTH) {
    throw new Error(`edge path must contain ${EDGE_HISTORY_DEPTH} siblings`);
  }
  for (let i = 0; i < path.length; i += 1) assert32(path[i]!, `edge path ${i}`);
}

function pairHash(left: Uint8Array, right: Uint8Array): Uint8Array {
  return sha256(concatBytes(assert32(left, "left child"), assert32(right, "right child")));
}

const ZERO_HASHES: readonly Uint8Array[] = (() => {
  const zeros: Uint8Array[] = [new Uint8Array(ZERO32)];
  for (let level = 0; level < EDGE_HISTORY_DEPTH; level += 1) {
    zeros.push(pairHash(zeros[level]!, zeros[level]!));
  }
  return zeros;
})();

/** Deterministic empty subtree root at `level` (level 0 is the empty leaf). */
export function edgeHistoryZero(level: number): Uint8Array {
  if (!Number.isInteger(level) || level < 0 || level > EDGE_HISTORY_DEPTH) {
    throw new Error("edge zero level out of range");
  }
  return ZERO_HASHES[level]!.slice();
}

export function emptyEdgeHistoryRoot(): Uint8Array {
  return edgeHistoryZero(EDGE_HISTORY_DEPTH);
}

/** Fixed 168-byte preimage for the next creation-chain head. */
export function encodeCreationLinkMessage(args: {
  readonly poolCategory: Uint8Array;
  readonly creationIndex: bigint;
  readonly previousHead: Uint8Array;
  readonly noteCommitment: Uint8Array;
}): Uint8Array {
  return concatBytes(
    CREATION_LINK_DOMAIN,
    CREATION_LOG_CONTEXT,
    assert32(args.poolCategory, "poolCategory"),
    writeU64BE(assertCreationIndex(args.creationIndex)),
    assert32(args.previousHead, "previousHead"),
    assert32(args.noteCommitment, "noteCommitment"),
  );
}

export function creationLink(args: {
  readonly poolCategory: Uint8Array;
  readonly creationIndex: bigint;
  readonly previousHead: Uint8Array;
  readonly noteCommitment: Uint8Array;
}): Uint8Array {
  return sha256(encodeCreationLinkMessage(args));
}

/** Fixed 168-byte preimage for the public unlinkable creation handle. */
export function encodeCreationEdgeMessage(args: {
  readonly poolCategory: Uint8Array;
  readonly creationIndex: bigint;
  readonly previousHead: Uint8Array;
  readonly creationHead: Uint8Array;
}): Uint8Array {
  return concatBytes(
    CREATION_EDGE_DOMAIN,
    CREATION_LOG_CONTEXT,
    assert32(args.poolCategory, "poolCategory"),
    writeU64BE(assertCreationIndex(args.creationIndex)),
    assert32(args.previousHead, "previousHead"),
    assert32(args.creationHead, "creationHead"),
  );
}

export function creationEdge(args: {
  readonly poolCategory: Uint8Array;
  readonly creationIndex: bigint;
  readonly previousHead: Uint8Array;
  readonly creationHead: Uint8Array;
}): Uint8Array {
  const edge = sha256(encodeCreationEdgeMessage(args));
  if (edge.every((byte) => byte === 0)) {
    throw new Error("creation edge collides with the empty-leaf sentinel");
  }
  return edge;
}

/** Fixed 192-byte preimage for an edge-bound nullifier. */
export function encodeEdgeNullifierMessage(args: {
  readonly poolCategory: Uint8Array;
  readonly edge: Uint8Array;
  readonly ownerSecret: Uint8Array;
  readonly rho: Uint8Array;
}): Uint8Array {
  return concatBytes(
    EDGE_NULLIFIER_DOMAIN,
    CREATION_LOG_CONTEXT,
    assert32(args.poolCategory, "poolCategory"),
    assert32(args.edge, "edge"),
    assert32(args.ownerSecret, "ownerSecret"),
    assert32(args.rho, "rho"),
  );
}

export function edgeNullifier(
  note: Note,
  poolCategory: Uint8Array,
  edge: Uint8Array,
): Uint8Array {
  return sha256(encodeEdgeNullifierMessage({
    poolCategory,
    edge,
    ownerSecret: note.ownerSecret,
    rho: note.rho,
  }));
}

/** Minimal durable wallet record; its path is disposable public cache data. */
export function createdNoteRecord(
  note: Note,
  creationIndex: bigint,
  previousHead: Uint8Array,
): CreatedNoteRecord {
  assertCreationIndex(creationIndex);
  if (note.amountSats < 0n) throw new Error("negative note amount");
  assert32(note.rho, "rho");
  assert32(note.ownerSecret, "ownerSecret");
  assert32(previousHead, "previousHead");
  return {
    note: {
      amountSats: note.amountSats,
      rho: note.rho.slice(),
      ownerSecret: note.ownerSecret.slice(),
    },
    creationIndex,
    previousHead: previousHead.slice(),
  };
}

/** Derive every redundant creation value from the durable wallet record. */
export function createdNoteContext(
  record: CreatedNoteRecord,
  poolCategory: Uint8Array,
): CreatedNoteContext {
  const noteCommitment = commitNote(record.note);
  const creationHead = creationLink({
    poolCategory,
    creationIndex: record.creationIndex,
    previousHead: record.previousHead,
    noteCommitment,
  });
  const edge = creationEdge({
    poolCategory,
    creationIndex: record.creationIndex,
    previousHead: record.previousHead,
    creationHead,
  });
  return { noteCommitment, creationHead, edge };
}

export function edgeRootFromPath(
  edge: Uint8Array,
  index: bigint,
  path: readonly Uint8Array[],
): Uint8Array {
  assert32(edge, "edge");
  assertCreationIndex(index);
  assertPath(path);
  let node = edge;
  let cursor = index;
  for (const sibling of path) {
    node = (cursor & 1n) === 0n ? pairHash(node, sibling) : pairHash(sibling, node);
    cursor >>= 1n;
  }
  return node;
}

export function verifyEdgeMembership(witness: EdgeMembershipWitness): boolean {
  if (witness.edge.every((byte) => byte === 0)) return false;
  return eq32(
    edgeRootFromPath(witness.edge, witness.index, witness.path),
    assert32(witness.root, "edge root"),
  );
}

export function verifyEdgeAppend(witness: EdgeAppendWitness): boolean {
  if (witness.edge.every((byte) => byte === 0)) return false;
  const oldRoot = edgeRootFromPath(ZERO32, witness.index, witness.path);
  const newRoot = edgeRootFromPath(witness.edge, witness.index, witness.path);
  return eq32(oldRoot, assert32(witness.oldRoot, "old edge root"))
    && eq32(newRoot, assert32(witness.newRoot, "new edge root"));
}

function nextLayer(layer: readonly Uint8Array[], level: number): Uint8Array[] {
  const next: Uint8Array[] = [];
  for (let i = 0; i < layer.length; i += 2) {
    next.push(pairHash(layer[i]!, layer[i + 1] ?? ZERO_HASHES[level]!));
  }
  return next;
}

function rootForEdges(edges: readonly Uint8Array[]): Uint8Array {
  if (edges.length === 0) return emptyEdgeHistoryRoot();
  let layer = edges.map((edge) => assert32(edge, "edge").slice());
  for (let level = 0; level < EDGE_HISTORY_DEPTH; level += 1) {
    layer = nextLayer(layer, level);
  }
  return layer[0]!;
}

function pathForEdges(edges: readonly Uint8Array[], index: bigint): Uint8Array[] {
  assertCreationIndex(index);
  let cursor = Number(index);
  let layer = edges.map((edge) => edge.slice());
  const path: Uint8Array[] = [];
  for (let level = 0; level < EDGE_HISTORY_DEPTH; level += 1) {
    const sibling = cursor % 2 === 0 ? cursor + 1 : cursor - 1;
    path.push((layer[sibling] ?? ZERO_HASHES[level]!).slice());
    layer = nextLayer(layer, level);
    cursor = Math.floor(cursor / 2);
  }
  return path;
}

/** Disposable cache rebuilt solely from public creation edges. */
export class EdgeHistory {
  readonly #edges: Uint8Array[];

  constructor(publicEdges: readonly Uint8Array[] = []) {
    if (BigInt(publicEdges.length) > EDGE_HISTORY_CAPACITY) {
      throw new Error("edge history exceeds depth-32 capacity");
    }
    this.#edges = publicEdges.map((edge) => {
      assert32(edge, "edge");
      if (edge.every((byte) => byte === 0)) throw new Error("zero edge is reserved");
      return edge.slice();
    });
  }

  static rebuild(publicEdges: readonly Uint8Array[]): EdgeHistory {
    return new EdgeHistory(publicEdges);
  }

  get count(): bigint {
    return BigInt(this.#edges.length);
  }

  get root(): Uint8Array {
    return rootForEdges(this.#edges);
  }

  publicEdges(): readonly Uint8Array[] {
    return this.#edges.map((edge) => edge.slice());
  }

  append(edge: Uint8Array): EdgeAppendWitness {
    if (this.count >= EDGE_HISTORY_CAPACITY) throw new Error("edge history full");
    assert32(edge, "edge");
    if (edge.every((byte) => byte === 0)) throw new Error("zero edge is reserved");
    const index = this.count;
    const path = pathForEdges(this.#edges, index);
    const oldRoot = this.root;
    this.#edges.push(edge.slice());
    return { index, edge: edge.slice(), path, oldRoot, newRoot: this.root };
  }

  membership(index: bigint): EdgeMembershipWitness {
    assertCreationIndex(index);
    if (index >= this.count) throw new Error("edge index has not been created");
    const edge = this.#edges[Number(index)]!.slice();
    return { index, edge, path: pathForEdges(this.#edges, index), root: this.root };
  }
}

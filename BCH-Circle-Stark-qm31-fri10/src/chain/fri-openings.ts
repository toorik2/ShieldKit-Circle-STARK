import { encodeLe, M31 } from "../backends/circle/m31.ts";
import { encodeQm31 } from "../backends/circle/qm31.ts";
import { isQm31, type FriLayerFelt } from "../backends/circle/fri.ts";

function encodeLayerLeaf(v: FriLayerFelt): Uint8Array {
  return isQm31(v) ? encodeQm31(v) : encodeLe(v);
}
import { decodeFriProof, type FriProof } from "../backends/circle/fri.ts";
import { MerkleTree } from "../backends/circle/merkle.ts";
import { COMMITTED_LAYERS, FRI_N, FRI_QUERIES } from "../backends/circle/params.ts";
import {
  compileFriQueryKernel,
  FRI_KERNEL_INPUTS,
  FRI_LAYER_UNBOUND,
  FRI_PAIR_BYTES_L0,
  FRI_PAIR_BYTES_QM,
} from "./fri-kernel.ts";
import { actualLayer, buildLayerProofs, encodeLayerUnlocking } from "./merkle-multiproof.ts";
import { encodeSteps, parentIndexOf } from "./vm-steps.ts";
import { AIR_PACKED_SIZE, AIR_OFF_ROOTS } from "./air-cqz.ts";

export { FRI_KERNEL_INPUTS };
export const UNLOCKING_LIMIT = 10_000;

function pushData(data: Uint8Array): Uint8Array {
  if (data.length <= 75) return Uint8Array.of(data.length, ...data);
  if (data.length <= 255) return Uint8Array.of(0x4c, data.length, ...data);
  if (data.length <= 0xffff) {
    return Uint8Array.of(0x4d, data.length & 0xff, (data.length >> 8) & 0xff, ...data);
  }
  throw new Error("push too large");
}

function pushScriptNumber(n: number): Uint8Array {
  if (n === 0) return Uint8Array.of(0x00);
  if (n >= 1 && n <= 16) return Uint8Array.of(0x50 + n);
  if (n < 0 || n > 127) throw new Error(`script number ${n}`);
  return Uint8Array.of(1, n);
}
const SHARD_BUDGET = 9_000;

export type FriOpening = {
  left: Uint8Array;
  right: Uint8Array;
  parentPath: Uint8Array[];
  parentIndex: number;
  root: Uint8Array;
  layerIndex: number;
  /** Fiat–Shamir domain index for this query (same on all 7 layers). */
  queryIndex: number;
  /** Packed qTable slot 0..FRI_QUERIES-1. */
  slot: number;
};

/** One PUSHDATA2 of the 1200-byte AIR packed blob (roots at offset 0). */
export function encodeLayerRootsPrefix(layerRoots: Uint8Array[]): Uint8Array {
  const packed = new Uint8Array(AIR_PACKED_SIZE);
  const roots = layerRoots.slice(0, COMMITTED_LAYERS);
  while (roots.length < COMMITTED_LAYERS) roots.push(new Uint8Array(32));
  for (let i = 0; i < COMMITTED_LAYERS; i += 1) packed.set(roots[i]!, AIR_OFF_ROOTS + i * 32);
  return pushData(packed);
}

export function collectFriOpenings(proof: Uint8Array | FriProof): FriOpening[] {
  const p = proof instanceof Uint8Array ? decodeFriProof(proof) : proof;
  const out: FriOpening[] = [];
  let boundQ = false;
  for (let slot = 0; slot < p.queries.length; slot += 1) {
    const q = p.queries[slot]!;
    for (let r = 0; r < q.layers.length; r += 1) {
      const layer = q.layers[r]!;
      const n = FRI_N >> r;
      const i = q.index % n;
      const lo = i < n / 2;
      let layerIndex = r;
      if (r === 0) {
        if (boundQ) layerIndex = FRI_LAYER_UNBOUND;
        else boundQ = true;
      }
      out.push({
        left: encodeLayerLeaf(lo ? layer.value : layer.partner),
        right: encodeLayerLeaf(lo ? layer.partner : layer.value),
        parentPath: layer.path,
        parentIndex: parentIndexOf(i, n),
        root: p.layerRoots[r]!,
        layerIndex,
        queryIndex: q.index,
        slot,
      });
    }
  }
  return out;
}

function openingPushBytes(o: FriOpening): number {
  const steps = encodeSteps(o.parentIndex, o.parentPath);
  return pushData(o.left).length + pushData(o.right).length + pushData(steps).length + 2;
}

/** Split openings into one layer-major group per committed layer. */
export function shardFriOpenings(openings: FriOpening[]): FriOpening[][] {
  if (openings.length === 0) throw new Error("no FRI openings");
  const shards: FriOpening[][] = Array.from({ length: FRI_KERNEL_INPUTS }, () => []);
  for (const o of openings) shards[actualLayer(o.layerIndex)]!.push(o);
  for (let s = 0; s < shards.length; s += 1) {
    if (shards[s]!.length === 0) {
      throw new Error(`FRI layer ${s} has no openings`);
    }
  }
  return shards;
}

/**
 * packed AIR || leftover pairs. Leftover is [L6][L5]…[L1][L0], each layer
 * query-major (slot 0..35) left||right. Layer 0 is 8 B; later layers 32 B.
 * Each Merkle kernel trims the suffix it does not consume, then LIFO-binds.
 */
export function packedWithPairs(packed: Uint8Array, proof?: Uint8Array | FriProof): Uint8Array {
  const head = packed.length >= AIR_PACKED_SIZE ? packed.subarray(0, AIR_PACKED_SIZE) : packed;
  if (!proof) {
    const out = new Uint8Array(AIR_PACKED_SIZE);
    out.set(head.subarray(0, Math.min(head.length, AIR_PACKED_SIZE)), 0);
    return out;
  }
  const openings = collectFriOpenings(proof);
  const byLayer: FriOpening[][] = Array.from({ length: COMMITTED_LAYERS }, () => []);
  for (const o of openings) byLayer[actualLayer(o.layerIndex)]!.push(o);
  const parts: Uint8Array[] = [];
  for (let r = COMMITTED_LAYERS - 1; r >= 0; r -= 1) {
    const group = byLayer[r]!.slice().sort((a, b) => a.slot - b.slot);
    const stride = r === 0 ? FRI_PAIR_BYTES_L0 : FRI_PAIR_BYTES_QM;
    for (const o of group) {
      if (o.left.length + o.right.length !== stride) {
        throw new Error(`leftover layer ${r} pair ${o.left.length}+${o.right.length}`);
      }
      parts.push(o.left, o.right);
    }
  }
  let n = 0;
  for (const p of parts) n += p.length;
  const pairs = new Uint8Array(n);
  let off = 0;
  for (const p of parts) {
    pairs.set(p, off);
    off += p.length;
  }
  const out = new Uint8Array(AIR_PACKED_SIZE + pairs.length);
  out.set(head.subarray(0, AIR_PACKED_SIZE), 0);
  out.set(pairs, AIR_PACKED_SIZE);
  return out;
}

export function queryPairShard(proof: Uint8Array | FriProof, queryIndex: number, nFold: number): Uint8Array {
  const blob = openingPairsBlob(collectFriOpenings(proof));
  const stride = blob.length / FRI_QUERIES;
  const out = new Uint8Array(nFold * stride);
  out.set(blob.subarray(queryIndex * stride, (queryIndex + nFold) * stride));
  return out;
}

/** Concatenate (left||right) for every opening, query-major. Layer 0 is 8 B; later 32 B. */
export function openingPairsBlob(openings: FriOpening[]): Uint8Array {
  const parts: Uint8Array[] = [];
  let n = 0;
  for (const o of openings) {
    n += o.left.length + o.right.length;
    parts.push(o.left, o.right);
  }
  const out = new Uint8Array(n);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

export function encodeFriBatchUnlocking(
  openings: FriOpening[],
  opts?: { allPairGroups?: boolean; layer?: number },
): Uint8Array {
  if (openings.length === 0) throw new Error("empty FRI shard");
  void opts?.allPairGroups;
  const layer = opts?.layer ?? actualLayer(openings[0]!.layerIndex);
  const proofs = buildLayerProofs(openings);
  const proof = proofs[layer] ?? proofs.find((p) => p.openings.length > 0);
  if (!proof) throw new Error(`no layer proof for ${layer}`);
  return encodeLayerUnlocking(proof, compileFriQueryKernel(proof.layer));
}

export function shardUnlockingBytes(openings: FriOpening[], opts?: { allPairGroups?: boolean; layer?: number }): number {
  return encodeFriBatchUnlocking(openings, opts).length;
}

export function friShardUnlockings(
  proof: Uint8Array | FriProof,
  opts?: { allPairGroups?: boolean },
): Uint8Array[] {
  void opts?.allPairGroups;
  return buildLayerProofs(collectFriOpenings(proof)).map((p) =>
    encodeLayerUnlocking(p, compileFriQueryKernel(p.layer)),
  );
}

/**
 * 8-leaf dummy Q-tree openings. Merkle-valid against the dummy root, not this
 * statement's layerRoots. Used to prove kernels cannot spend a dummy tree
 * while the pool unlocking still carries the honest proof roots.
 */
export function dummyFriOpenings(count = FRI_KERNEL_INPUTS): FriOpening[] {
  const values = Array.from({ length: 8 }, (_, i) => BigInt(i + 1));
  const tree = new MerkleTree(values);
  const out: FriOpening[] = [];
  for (let k = 0; k < count; k += 1) {
    const i = (k % 4) * 2;
    out.push({
      left: encodeLe(values[i]!),
      right: encodeLe(values[i + 1]!),
      parentPath: tree.path(i).slice(1),
      parentIndex: Math.floor(i / 2),
      root: tree.root,
      layerIndex: k % COMMITTED_LAYERS,
      queryIndex: 0,
      slot: k % FRI_QUERIES,
    });
  }
  return out;
}

export function dummyFriShardUnlockings(): Uint8Array[] {
  return buildLayerProofs(dummyFriOpenings(FRI_KERNEL_INPUTS * 2)).map((p) =>
    encodeLayerUnlocking(p, compileFriQueryKernel(p.layer)),
  );
}

/** Same dummy 8-leaf tree, but every opening uses layerIndex 16+k so a skip-bind kernel would walk without a Q check. */
export function dummyFriOpeningsUnbound(count = FRI_KERNEL_INPUTS): FriOpening[] {
  return dummyFriOpenings(count).map((o) => ({
    ...o,
    layerIndex: FRI_LAYER_UNBOUND + (o.layerIndex % COMMITTED_LAYERS),
  }));
}

export function dummyFriShardUnlockingsUnbound(): Uint8Array[] {
  return buildLayerProofs(dummyFriOpeningsUnbound(FRI_KERNEL_INPUTS * 2)).map((p) =>
    encodeLayerUnlocking(p, compileFriQueryKernel(p.layer)),
  );
}

/** Dummy 8-leaf openings that never use actual layer 0 (only 17–22). */
export function dummyFriOpeningsNoL0(count = FRI_KERNEL_INPUTS): FriOpening[] {
  return dummyFriOpenings(count).map((o, k) => ({
    ...o,
    layerIndex: FRI_LAYER_UNBOUND + 1 + (k % (COMMITTED_LAYERS - 1)),
  }));
}

export function dummyFriShardUnlockingsNoL0(): Uint8Array[] {
  return buildLayerProofs(dummyFriOpeningsNoL0(FRI_KERNEL_INPUTS * 2)).map((p) =>
    encodeLayerUnlocking(p, compileFriQueryKernel(p.layer)),
  );
}

/** FRI_N-wide dummy tree (honest path depth) so isolated walk tests can pass the depth gate. */
export function dummyFriOpeningsWide(count = 1): FriOpening[] {
  const values = Array.from({ length: FRI_N }, (_, i) => BigInt((i % Number(M31 - 1n)) + 1));
  const tree = new MerkleTree(values);
  const out: FriOpening[] = [];
  for (let k = 0; k < count; k += 1) {
    const i = (k % (FRI_N / 2)) * 2;
    out.push({
      left: encodeLe(values[i]!),
      right: encodeLe(values[i + 1]!),
      parentPath: tree.path(i).slice(1),
      parentIndex: Math.floor(i / 2),
      root: tree.root,
      layerIndex: 0,
      queryIndex: 0,
      slot: 0,
    });
  }
  return out;
}

export function proofShardReport(proof: Uint8Array | FriProof): {
  openings: number;
  shards: number;
  unlockingMax: number;
  unlockingSum: number;
  shardsFit10k: boolean;
  txEst: number;
  txFit100k: boolean;
} {
  const shards = friShardUnlockings(proof);
  const unlockingMax = Math.max(...shards.map((s) => s.length));
  const unlockingSum = shards.reduce((n, s) => n + s.length, 0);
  const txEst = unlockingSum + 1_200 + shards.length * 150;
  return {
    openings: collectFriOpenings(proof).length,
    shards: shards.length,
    unlockingMax,
    unlockingSum,
    shardsFit10k: unlockingMax <= UNLOCKING_LIMIT,
    txEst,
    txFit100k: txEst <= 100_000,
  };
}

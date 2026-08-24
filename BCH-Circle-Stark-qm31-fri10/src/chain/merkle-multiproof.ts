/**
 * Unique-sibling Merkle encoding for Circle FRI openings.
 * Paths become (bit || u16le table-index) instead of (bit || 32-byte hash).
 * Completeness is unchanged: same SHA-256 parent hashes, same depth gate.
 */
import { sha256 } from "../pool/bytes.ts";
import { COMMITTED_LAYERS, FRI_LOG_N } from "../backends/circle/params.ts";
import type { FriOpening } from "./fri-openings.ts";
import { COMPACT_PATH_STRIDE, FRI_LAYER_UNBOUND } from "./fri-kernel.ts";

export function pathLen(layer: number): number {
  const r = layer >= FRI_LAYER_UNBOUND ? layer - FRI_LAYER_UNBOUND : layer;
  return FRI_LOG_N - 1 - r;
}

export function actualLayer(layerIndex: number): number {
  return layerIndex >= FRI_LAYER_UNBOUND ? layerIndex - FRI_LAYER_UNBOUND : layerIndex;
}

export function uniqueTableAndIndex(hashes: Uint8Array[]): { table: Uint8Array; indexOf: Map<string, number> } {
  const indexOf = new Map<string, number>();
  const parts: Uint8Array[] = [];
  for (const h of hashes) {
    const k = Buffer.from(h).toString("hex");
    if (!indexOf.has(k)) {
      indexOf.set(k, parts.length);
      parts.push(h);
    }
  }
  const table = new Uint8Array(parts.length * 32);
  for (let i = 0; i < parts.length; i += 1) table.set(parts[i]!, i * 32);
  return { table, indexOf };
}

export function compactStride(_layer: number): number {
  return COMPACT_PATH_STRIDE;
}

export function compactPath(parentIndex: number, parentPath: Uint8Array[], indexOf: Map<string, number>, stride = COMPACT_PATH_STRIDE): Uint8Array {
  const n = parentPath.length;
  const out = new Uint8Array(n * stride);
  let i = parentIndex;
  for (let s = 0; s < n; s += 1) {
    const sib = parentPath[s]!;
    const idx = indexOf.get(Buffer.from(sib).toString("hex"));
    if (idx === undefined) throw new Error("sibling missing from unique table");
    out[s * stride] = i & 1;
    out[s * stride + 1] = idx & 0xff;
    out[s * stride + 2] = (idx >> 8) & 0xff;
    i >>= 1;
  }
  return out;
}

export function lookupTable(table: Uint8Array, index: number): Uint8Array {
  const o = index * 32;
  if (o + 32 > table.length) throw new Error(`table index ${index}`);
  return table.subarray(o, o + 32);
}

export function walkCompact(
  left: Uint8Array,
  right: Uint8Array,
  compact: Uint8Array,
  table: Uint8Array,
  root: Uint8Array,
): boolean {
  const l = sha256(left);
  const r = sha256(right);
  let acc = sha256(new Uint8Array([...l, ...r]));
  const stride =
    compact.length % COMPACT_PATH_STRIDE === 0
      ? COMPACT_PATH_STRIDE
      : compact.length % 8 === 0
        ? 8
        : 3;
  if (compact.length % stride !== 0) return false;
  for (let s = 0; s < compact.length; s += stride) {
    const bit = compact[s]!;
    const idx = compact[s + 1]! | (compact[s + 2]! << 8);
    const sib = lookupTable(table, idx);
    acc =
      bit === 0
        ? sha256(new Uint8Array([...acc, ...sib]))
        : sha256(new Uint8Array([...sib, ...acc]));
  }
  return Buffer.from(acc).equals(Buffer.from(root));
}

export type LayerProof = {
  layer: number;
  table: Uint8Array;
  openings: Array<{
    left: Uint8Array;
    right: Uint8Array;
    parentIndex: number;
    compactPath: Uint8Array;
    slot: number;
    layerIndex: number;
  }>;
};

export function buildLayerProofs(openings: FriOpening[]): LayerProof[] {
  const byLayer: FriOpening[][] = Array.from({ length: COMMITTED_LAYERS }, () => []);
  for (const o of openings) {
    byLayer[actualLayer(o.layerIndex)]!.push(o);
  }
  return byLayer.map((group, layer) => {
    const hashes: Uint8Array[] = [];
    for (const o of group) hashes.push(...o.parentPath);
    const { table, indexOf } = uniqueTableAndIndex(hashes);
    return {
      layer,
      table,
      openings: group.map((o) => ({
        left: o.left,
        right: o.right,
        parentIndex: o.parentIndex,
        compactPath: compactPath(o.parentIndex, o.parentPath, indexOf, compactStride(layer)),
        slot: o.slot,
        layerIndex: o.layerIndex,
      })),
    };
  });
}

function pushData(data: Uint8Array): Uint8Array {
  if (data.length <= 75) return Uint8Array.of(data.length, ...data);
  if (data.length <= 255) return Uint8Array.of(0x4c, data.length, ...data);
  return Uint8Array.of(0x4d, data.length & 0xff, (data.length >> 8) & 0xff, ...data);
}

function pushScriptNumber(n: number): Uint8Array {
  if (n === 0) return Uint8Array.of(0x00);
  if (n >= 1 && n <= 16) return Uint8Array.of(0x50 + n);
  if (n < 0 || n > 127) throw new Error(`script number ${n}`);
  return Uint8Array.of(1, n);
}

export function encodeLayerUnlocking(p: LayerProof, redeem: Uint8Array): Uint8Array {
  const tableParts: Uint8Array[] = [];
  for (let i = 0; i < p.table.length; i += 32) tableParts.push(pushData(p.table.subarray(i, i + 32)));
  const openingParts: Uint8Array[] = [];
  for (const o of p.openings) {
    openingParts.push(pushData(o.left), pushData(o.right), pushData(o.compactPath), pushScriptNumber(o.slot));
  }
  openingParts.push(pushScriptNumber(p.openings.length));
  const redeemPush = pushData(redeem);
  const parts: Uint8Array[] = [
    ...tableParts,
    ...openingParts,
    redeemPush,
  ];
  const n = parts.reduce((s, x) => s + x.length, 0);
  if (n > 10_000) throw new Error(`layer ${p.layer} unlocking ${n} > 10000`);
  const out = new Uint8Array(n);
  let o = 0;
  for (const x of parts) {
    out.set(x, o);
    o += x.length;
  }
  return out;
}

export function layerProofBytes(p: LayerProof): {
  table: number;
  compact: number;
  leftRight: number;
  totalPayload: number;
} {
  const compact = p.openings.reduce((n, o) => n + o.compactPath.length, 0);
  const leftRight = p.openings.length * 8;
  return {
    table: p.table.length,
    compact,
    leftRight,
    totalPayload: p.table.length + compact + leftRight + p.openings.length * 3,
  };
}

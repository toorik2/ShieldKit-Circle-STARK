/**
 * Density prototype: layer-major compact Merkle with
 *   (a) 32-byte table items + bottom-relative PICK, pad BETWEEN table and openings
 *   (b) concatenated table + PICK-bottom then SPLIT idx*32, pad INSIDE the blob
 * Pair blob lives on input 0 as packed||pairs so fold need not read merkle shards.
 */
import { cashAssemblyToBin, createVirtualMachineBch2026, encodeLockingBytecodeP2sh32, hash256 } from "@bitauth/libauth";
import { applyDeposit } from "../src/pool/transition.ts";
import { IncrementalMerkle, NullifierSet, type Note } from "../src/pool/notes.ts";
import { emptyState } from "../src/pool/state.ts";
import { encodeFriProof, proveFri, wDeposit } from "../src/backends/circle/fri.ts";
import { COMMITTED_LAYERS, FRI_LOG_N } from "../src/backends/circle/params.ts";
import { collectFriOpenings, openingPairsBlob } from "../src/chain/fri-openings.ts";
import { buildLayerProofs, layerProofBytes, walkCompact } from "../src/chain/merkle-multiproof.ts";
import { AIR_OFF_QTABLE, AIR_PACKED_SIZE, encodeAirPacked } from "../src/chain/air-cqz.ts";
import { FIRST_PUSH_BODY } from "../src/chain/fri-kernel.ts";
import { pushData } from "../src/chain/covenant-p2s.ts";

const PAIR_BYTES = 8 * COMMITTED_LAYERS;
const STRIDE = 3;

function num(v: unknown): number {
  if (typeof v === "number") return v;
  if (typeof v === "bigint") return Number(v);
  return 0;
}

function pushScriptNumber(n: number): Uint8Array {
  if (n === 0) return Uint8Array.of(0x00);
  if (n >= 1 && n <= 16) return Uint8Array.of(0x50 + n);
  if (n < 0 || n > 127) throw new Error(`script number ${n}`);
  return Uint8Array.of(1, n);
}

function concatBytes(parts: Uint8Array[]): Uint8Array {
  const n = parts.reduce((s, p) => s + p.length, 0);
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

function qBindAsm(): string {
  return `
OP_FROMALTSTACK
<4>
OP_MUL
<${AIR_OFF_QTABLE}>
OP_ADD
<0> OP_INPUTBYTECODE
${FIRST_PUSH_BODY}
OP_SWAP
OP_SPLIT
OP_NIP
<4>
OP_SPLIT
OP_DROP
<0x00>
OP_CAT
OP_BIN2NUM
OP_TOALTSTACK
<0x00>
OP_CAT
OP_BIN2NUM
OP_SWAP
<0x00>
OP_CAT
OP_BIN2NUM
OP_FROMALTSTACK
OP_DUP
OP_3 OP_PICK
OP_NUMEQUAL
OP_SWAP
OP_2 OP_PICK
OP_NUMEQUAL
OP_BOOLOR
OP_VERIFY
OP_2DROP
`;
}

function pairBindAsm(layer: number): string {
  return `
OP_DUP
OP_TOALTSTACK
<${PAIR_BYTES}>
OP_MUL
<${layer * 8}>
OP_ADD
OP_TOALTSTACK
OP_2DUP
OP_CAT
<0> OP_INPUTBYTECODE
${FIRST_PUSH_BODY}
<${AIR_PACKED_SIZE}>
OP_SPLIT
OP_NIP
OP_FROMALTSTACK
OP_SPLIT
OP_NIP
<8>
OP_SPLIT
OP_DROP
OP_EQUALVERIFY
`;
}

function rootBindAsm(layer: number): string {
  return `
<${layer * 32}>
<0> OP_INPUTBYTECODE
${FIRST_PUSH_BODY}
OP_SWAP
OP_SPLIT
OP_NIP
<32>
OP_SPLIT
OP_DROP
OP_EQUALVERIFY
`;
}

function itemLookupAsm(): string {
  return `
<${STRIDE}> OP_SPLIT
OP_TOALTSTACK
<1> OP_SPLIT
<0x00>
OP_CAT
OP_BIN2NUM
OP_DEPTH
<2>
OP_SUB
OP_SWAP
OP_SUB
OP_PICK
OP_ROT
OP_SWAP
OP_ROT
OP_IF
  OP_SWAP
OP_ENDIF
OP_CAT
OP_SHA256
OP_FROMALTSTACK
`;
}

function concatLookupAsm(): string {
  return `
<${STRIDE}> OP_SPLIT
OP_TOALTSTACK
<1> OP_SPLIT
<0x00>
OP_CAT
OP_BIN2NUM
OP_TOALTSTACK
OP_DEPTH
<1>
OP_SUB
OP_PICK
OP_FROMALTSTACK
<32>
OP_MUL
OP_SPLIT
OP_NIP
<32>
OP_SPLIT
OP_DROP
OP_ROT
OP_SWAP
OP_ROT
OP_IF
  OP_SWAP
OP_ENDIF
OP_CAT
OP_SHA256
OP_FROMALTSTACK
`;
}

function kernelAsm(layer: number, lookup: "item" | "concat"): string {
  const pathBytes = (FRI_LOG_N - 1 - layer) * STRIDE;
  const lookupAsm = lookup === "item" ? itemLookupAsm() : concatLookupAsm();
  const qBind = layer === 0 ? qBindAsm() : "OP_FROMALTSTACK\nOP_DROP\nOP_2DROP\n";
  return `
OP_BEGIN
  OP_DUP
  OP_0 OP_GREATERTHAN
  OP_IF
    OP_1SUB
    OP_TOALTSTACK
    OP_TOALTSTACK
    OP_SIZE
    <${pathBytes}>
    OP_NUMEQUALVERIFY
    OP_FROMALTSTACK
    OP_SWAP
    OP_TOALTSTACK
    ${pairBindAsm(layer)}
    OP_2DUP
    OP_SHA256
    OP_SWAP
    OP_SHA256
    OP_SWAP
    OP_CAT
    OP_SHA256
    OP_FROMALTSTACK
    OP_FROMALTSTACK
    OP_SWAP
    OP_TOALTSTACK
    OP_BEGIN
      OP_SIZE
      OP_0 OP_GREATERTHAN
      OP_IF
        ${lookupAsm}
        OP_0
      OP_ELSE
        OP_DROP
        OP_1
      OP_ENDIF
    OP_UNTIL
    ${rootBindAsm(layer)}
    ${qBind}
    OP_FROMALTSTACK
    OP_0
  OP_ELSE
    OP_DROP
    OP_BEGIN
      OP_DEPTH
      OP_IF
        OP_DROP
        OP_0
      OP_ELSE
        OP_1
      OP_ENDIF
    OP_UNTIL
    OP_1
  OP_ENDIF
OP_UNTIL
OP_1
`;
}

function padTable(table: Uint8Array, extraHashes: number): Uint8Array {
  if (extraHashes <= 0 || table.length < 32) return table;
  const out = new Uint8Array(table.length + extraHashes * 32);
  out.set(table);
  const first = table.subarray(0, 32);
  for (let i = 0; i < extraHashes; i += 1) out.set(first, table.length + i * 32);
  return out;
}

function encodeUnlocking(args: {
  table: Uint8Array;
  openings: Array<{ left: Uint8Array; right: Uint8Array; compactPath: Uint8Array; slot: number }>;
  redeem: Uint8Array;
  mode: "item" | "concat";
  extraHashes: number;
}): Uint8Array {
  const table = padTable(args.table, args.extraHashes);
  const parts: Uint8Array[] = [];
  if (args.mode === "concat") {
    parts.push(pushData(table));
  } else {
    for (let i = 0; i < table.length; i += 32) parts.push(pushData(table.subarray(i, i + 32)));
  }
  for (const o of args.openings) {
    parts.push(pushData(o.left), pushData(o.right), pushData(o.compactPath), pushScriptNumber(o.slot));
  }
  parts.push(pushScriptNumber(args.openings.length));
  parts.push(pushData(args.redeem));
  return concatBytes(parts);
}

function evalKernel(args: {
  redeem: Uint8Array;
  unlocking: Uint8Array;
  carrier: Uint8Array;
}): { accepted: boolean; error: string | null; op: number; opMax: number; hash: number; hashMax: number; opPct: number } {
  const lock = encodeLockingBytecodeP2sh32(hash256(args.redeem));
  const vm = createVirtualMachineBch2026(true);
  const sourceOutputs = [
    { lockingBytecode: Uint8Array.of(0x75, 0x51), valueSatoshis: 1000n },
    { lockingBytecode: lock, valueSatoshis: 1000n },
  ];
  const transaction = {
    version: 2,
    locktime: 0,
    inputs: [
      {
        outpointTransactionHash: new Uint8Array(32).fill(0x22),
        outpointIndex: 0,
        sequenceNumber: 0xffffffff,
        unlockingBytecode: pushData(args.carrier),
      },
      {
        outpointTransactionHash: new Uint8Array(32).fill(0x44),
        outpointIndex: 0,
        sequenceNumber: 0xffffffff,
        unlockingBytecode: args.unlocking,
      },
    ],
    outputs: [{ lockingBytecode: Uint8Array.of(0x75, 0x51), valueSatoshis: 1000n }],
  };
  const state = vm.evaluate({ inputIndex: 1, sourceOutputs, transaction } as never);
  const ok = vm.stateSuccess(state);
  const m = (state as { metrics?: Record<string, number | bigint> }).metrics ?? {};
  const op = num(m.operationCost);
  const opMax = num(m.maximumOperationCost);
  return {
    accepted: ok === true,
    error: ok === true ? null : String(ok).slice(0, 280),
    op,
    opMax,
    hash: num(m.hashDigestIterations),
    hashMax: num(m.maximumHashDigestIterations),
    opPct: opMax ? +(100 * op / opMax).toFixed(2) : 0,
  };
}

const note: Note = {
  amountSats: 8_000n,
  rho: crypto.getRandomValues(new Uint8Array(32)),
  ownerSecret: crypto.getRandomValues(new Uint8Array(32)),
};
const d = applyDeposit(
  { state: emptyState(crypto.getRandomValues(new Uint8Array(32))), notes: new IncrementalMerkle(), nullifiers: new NullifierSet() },
  note,
);
const proved = proveFri(d.statement, wDeposit(note, d.index, d.path));
const proof = encodeFriProof(proved);
const packed = encodeAirPacked(d.statement, proof);
const openings = collectFriOpenings(proved);
const pairs = openingPairsBlob(openings);
const carrier = concatBytes([packed, pairs]);
const layers = buildLayerProofs(openings);

const only = process.argv.includes("--one") ? 1 : undefined;
const wantLayer = process.argv.find((a) => a.startsWith("--layer="));
const layerFilter = wantLayer ? Number(wantLayer.slice("--layer=".length)) : undefined;
const modes = (process.argv.find((a) => a.startsWith("--mode="))?.slice("--mode=".length) ?? "item,concat").split(",") as Array<"item" | "concat">;

const rows: unknown[] = [];
let merkleSum = 0;

for (const layer of layers) {
  if (layerFilter !== undefined && layer.layer !== layerFilter) continue;
  const root = proved.layerRoots[layer.layer]!;
  const used = only ? { ...layer, openings: layer.openings.slice(0, only) } : layer;
  for (const o of used.openings) {
    if (!walkCompact(o.left, o.right, o.compactPath, used.table, root)) {
      throw new Error(`JS walk fail layer ${layer.layer} slot ${o.slot}`);
    }
  }
  const sizes = layerProofBytes(layer);
  for (const mode of modes) {
    const asm = kernelAsm(layer.layer, mode);
    const redeem = cashAssemblyToBin(asm);
    if (typeof redeem === "string") throw new Error(`layer ${layer.layer} ${mode}: ${redeem}`);
    const openings3 = used.openings.map((o) => ({
      left: o.left,
      right: o.right,
      compactPath: stride3(o.compactPath),
      slot: o.slot,
    }));
    let extra = 0;
    let best: ReturnType<typeof evalKernel> & { extra: number; unlocking: number; redeem: number } | undefined;
    for (;;) {
      const unlocking = encodeUnlocking({
        table: used.table,
        openings: openings3,
        redeem,
        mode,
        extraHashes: extra,
      });
      const ev = evalKernel({ redeem, unlocking, carrier });
      best = { ...ev, extra, unlocking: unlocking.length, redeem: redeem.length };
      if (ev.accepted && ev.opPct <= 99.5) break;
      if (extra >= 80) break;
      const deficit = ev.op - Math.floor(ev.opMax * 0.995);
      extra += Math.max(1, Math.ceil(deficit / (800 * 33)));
    }
    if (best) {
      merkleSum += best.unlocking;
      rows.push({
        layer: layer.layer,
        mode,
        unique: used.table.length / 32,
        openings: openings3.length,
        path: (FRI_LOG_N - 1 - layer.layer),
        payload: sizes.totalPayload,
        extra: best.extra,
        unlocking: best.unlocking,
        redeem: best.redeem,
        accepted: best.accepted,
        opPct: best.opPct,
        op: best.op,
        opMax: best.opMax,
        hash: best.hash,
        hashMax: best.hashMax,
        error: best.accepted ? null : best.error,
      });
    }
  }
}

function pathLenBytes(layer: number): number {
  return (FRI_LOG_N - 1 - layer) * STRIDE;
}

function stride3(compact: Uint8Array): Uint8Array {
  if (compact.length % STRIDE === 0 && compact.length % 8 !== 0) return compact;
  const steps = compact.length % 8 === 0 ? compact.length / 8 : compact.length / STRIDE;
  const out = new Uint8Array(steps * STRIDE);
  const srcStride = compact.length === steps * 8 ? 8 : STRIDE;
  for (let s = 0; s < steps; s += 1) {
    out[s * STRIDE] = compact[s * srcStride]!;
    out[s * STRIDE + 1] = compact[s * srcStride + 1]!;
    out[s * STRIDE + 2] = compact[s * srcStride + 2]!;
  }
  return out;
}

console.log(JSON.stringify({
  carrier: carrier.length,
  packed: packed.length,
  pairs: pairs.length,
  merkleSum,
  rows,
}, null, 2));

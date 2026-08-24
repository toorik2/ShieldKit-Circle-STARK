/**
 * Dedicated Circle-FRI fold kernel. First push of each grouped FRI unlocking
 * is (left||right)×7×queriesInShard. Kernel q reads shard (q % 10) and slices
 * pair group floor(q/10). One query per redeem (density).
 * Packed idx is bound to recomputed FS; an even layer-0 pair cannot hide a cooked index.
 */
import { cashAssemblyToBin, encodeLockingBytecodeP2sh32, hash256 } from "@bitauth/libauth";
import { addPoints, scalarMul } from "../backends/circle/group.ts";
import { encodeLe, inv, neg } from "../backends/circle/m31.ts";
import { COMMITTED_LAYERS, FRI_N, FRI_QUERIES, FRI_VERSION, RULES_SHA256, SECURE_FIELD_BIT_LENGTH } from "../backends/circle/params.ts";
import { AIR_OFF_IDX, AIR_PACKED_SIZE, G1024, SLOT_KERNEL_COUNT } from "./air-cqz.ts";

import {
  FRI_KERNEL_INPUTS,
  FIRST_PUSH_BODY,
  FRI_PAIR_BYTES,
  FRI_PAIR_BYTES_L0,
  FRI_PAIR_BYTES_QM,
  FRI_LEFTOVER_LATER_BYTES,
} from "./fri-kernel.ts";
import { foldDefinesAsm, foldQueriesAsm } from "./fold-asm.ts";
import { fusedRPrepAsm } from "./r-kernel.ts";

export const FOLD_KERNEL_INPUTS = 1;
export const FOLD_KERNEL_INDEX = 14;
/** Standard 100 KB path: one fold input (density + remaining bytes). */
export const FOLD_QUERY_COUNT_STANDARD = 1;
export const FOLD_KERNEL_COUNT_STANDARD = 1;
/** Consensus path: 6 unique-orbit folds with inv witnesses. Isolated 6-fold is 95.6% of standard op-cost. */
export const FOLD_QUERIES_PER_KERNEL = 6;
export const FOLD_KERNEL_COUNT_CONSENSUS = FRI_QUERIES / FOLD_QUERIES_PER_KERNEL;

const FOLD_VK_PIN = Buffer.concat([
  Buffer.from(RULES_SHA256, "hex"),
  Buffer.from([FRI_VERSION, 20, 36, 16, 64, 10, 2, 128, 10, 7, 8, SECURE_FIELD_BIT_LENGTH]),
]);

export function foldQueriesPerKernel(slotKernels: number): number {
  return slotKernels > SLOT_KERNEL_COUNT ? FOLD_QUERIES_PER_KERNEL : FOLD_QUERY_COUNT_STANDARD;
}

export function foldKernelCount(slotKernels: number): number {
  return slotKernels > SLOT_KERNEL_COUNT ? FOLD_KERNEL_COUNT_CONSENSUS : FOLD_KERNEL_COUNT_STANDARD;
}

/** Consensus B fuses 6 R-slots into each 6-query fold input (shared unlocking budget). */
export function foldRFused(slotKernels: number): boolean {
  return slotKernels > SLOT_KERNEL_COUNT;
}

/** Separate R-slot input count. Zero when R runs inside the fold redeem. */
export function slotInputsCount(slotKernels: number): number {
  return foldRFused(slotKernels) ? 0 : slotKernels;
}

export function foldQueryShardInput(queryIndex: number): number {
  return 1 + (queryIndex % FRI_KERNEL_INPUTS);
}

export function foldQueryPairIndex(queryIndex: number): number {
  return Math.floor(queryIndex / FRI_KERNEL_INPUTS);
}

const PAIR_BYTES = FRI_PAIR_BYTES;
const INV_GROUP_BYTES = COMMITTED_LAYERS * 4;

/** Per-query inverses of (px==0 ? py : px), matching chained fold domain points. */
export function foldInvsBlob(packed: Uint8Array, queryIndex: number, nFold: number): Uint8Array {
  const out = new Uint8Array(nFold * INV_GROUP_BYTES);
  for (let q = 0; q < nFold; q += 1) {
    const off = AIR_OFF_IDX + (queryIndex + q) * 2;
    const idx = (packed[off]! << 8) | packed[off + 1]!;
    let p = scalarMul(G1024, BigInt(idx % (FRI_N >> 1)));
    for (let r = 0; r < COMMITTED_LAYERS; r += 1) {
      const denom = p.x !== 0n ? p.x : p.y;
      out.set(encodeLe(inv(denom)), q * INV_GROUP_BYTES + r * 4);
      if (r + 1 < COMMITTED_LAYERS) {
        p = addPoints(p, p);
        if (idx % (FRI_N >> (r + 1)) >= FRI_N >> (r + 2)) {
          p = { x: neg(p.x), y: neg(p.y) };
        }
      }
    }
  }
  return out;
}

function queryPairsFromBodyAsm(pairIndex = 0): string {
  const l0 = 8;
  return `
<${AIR_PACKED_SIZE}>
OP_SPLIT
OP_NIP
<${pairIndex * l0}>
OP_SPLIT
OP_NIP
<${l0}>
OP_SPLIT
OP_DROP
`;
}

function queryPairsAsm(pairIndex = 0): string {
  return `
${FIRST_PUSH_BODY}
${queryPairsFromBodyAsm(pairIndex)}
`;
}

function extractQueryPairsAsm(inputIndex: number, pairIndex = 0): string {
  return `
<${inputIndex}> OP_INPUTBYTECODE
${queryPairsAsm(pairIndex)}
`;
}

/**
 * Stack: leftover pairs → pairs.
 * Rebuilds query-major (L0||L1||…||L6)×nFold from layer-major leftover and
 * EQUALVERIFYs the fold unlocking shard. Miner binds fold L||R to Merkle leftover.
 */
export function bindFoldPairsLeftoverAsm(nFold: number, queryIndex: number): string {
  const later = FRI_LEFTOVER_LATER_BYTES;
  const splitLater = Array.from({ length: COMMITTED_LAYERS - 1 }, () => `<${later}>\nOP_SPLIT`).join("\n");
  const sliceOntoAcc = (layer: number): string => {
    const stride = layer === 0 ? FRI_PAIR_BYTES_L0 : FRI_PAIR_BYTES_QM;
    const base = queryIndex * stride;
    const park =
      layer === 0
        ? `
OP_1 OP_PICK
OP_0
OP_NUMEQUAL
OP_IF
  OP_TOALTSTACK
OP_ELSE
  OP_FROMALTSTACK
  OP_SWAP
  OP_CAT
  OP_TOALTSTACK
OP_ENDIF
`
        : `
OP_FROMALTSTACK
OP_SWAP
OP_CAT
OP_TOALTSTACK
`;
    return `
OP_DUP
<${stride}>
OP_MUL
${base === 0 ? "" : `<${base}>\nOP_ADD\n`}
<${layer + 2}>
OP_PICK
OP_SWAP
OP_SPLIT
OP_NIP
<${stride}>
OP_SPLIT
OP_DROP
${park}
`;
  };
  const layers = Array.from({ length: COMMITTED_LAYERS }, (_, r) => sliceOntoAcc(r)).join("\n");
  return `
OP_DUP
${splitLater}
<0>
OP_BEGIN
  OP_DUP
  <${nFold}>
  OP_LESSTHAN
  OP_IF
    ${layers}
    OP_1ADD
    OP_0
  OP_ELSE
    OP_DROP
    OP_1
  OP_ENDIF
OP_UNTIL
OP_FROMALTSTACK
OP_9 OP_PICK
OP_EQUALVERIFY
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
`;
}

function fusedRAsm(nFold: number, queryIndex: number): string {
  if (nFold !== FOLD_QUERIES_PER_KERNEL) return "OP_DROP\nOP_DROP\nOP_DROP\n";
  const one = (local: number): string => `<${local}>\n<8> OP_INVOKE\n`;
  void queryIndex;
  return `
${fusedRPrepAsm()}
${Array.from({ length: nFold }, (_, i) => one(i)).join("\n")}
OP_2DROP
OP_DROP
`;
}

export function foldKernelAsm(nFold = 1, queryIndex = 0): string {
  return `
${foldDefinesAsm()}
<${nFold * PAIR_BYTES}>
OP_SPLIT
OP_SWAP
<0> OP_INPUTBYTECODE
${FIRST_PUSH_BODY}
<${AIR_PACKED_SIZE}>
OP_SPLIT
OP_TOALTSTACK
OP_SWAP
OP_FROMALTSTACK
${bindFoldPairsLeftoverAsm(nFold, queryIndex)}
OP_SWAP
${foldQueriesAsm(nFold, queryIndex)}
${fusedRAsm(nFold, queryIndex)}
<0x${FOLD_VK_PIN.toString("hex")}>
OP_SIZE
<${FOLD_VK_PIN.length}>
OP_NUMEQUALVERIFY
OP_DROP
OP_1
`;
}

export function compileInput1PairsLock(): Uint8Array {
  const bin = cashAssemblyToBin(`
<1> OP_INPUTBYTECODE
${queryPairsAsm(0)}
OP_SIZE
<8>
OP_NUMEQUAL
OP_NIP
`);
  if (typeof bin === "string") throw new Error(`input1-pairs: ${bin}`);
  return bin;
}

export function compileFirstQueryPairsLock(): Uint8Array {
  const bin = cashAssemblyToBin(`
${queryPairsFromBodyAsm(0)}
OP_SIZE
<8>
OP_NUMEQUAL
OP_NIP
`);
  if (typeof bin === "string") throw new Error(`first-pairs: ${bin}`);
  return bin;
}

const FOLD_REDEEM_PAD = 0;

export function compileFoldKernel(nFold = 1, queryIndex = 0): Uint8Array {
  const bin = cashAssemblyToBin(foldKernelAsm(nFold, queryIndex));
  if (typeof bin === "string") throw new Error(`fold-kernel: ${bin}`);
  if (bin.length >= FOLD_REDEEM_PAD) return bin;
  const pairs = Math.ceil((FOLD_REDEEM_PAD - bin.length) / 2);
  const pad = new Uint8Array(pairs * 2);
  for (let i = 0; i < pairs; i += 1) {
    pad[i * 2] = 0x00;
    pad[i * 2 + 1] = 0x75;
  }
  const out = new Uint8Array(pad.length + bin.length);
  out.set(pad, 0);
  out.set(bin, pad.length);
  return out;
}

export function compileFoldLockP2sh32(nFold = 1, queryIndex = 0): Uint8Array {
  return encodeLockingBytecodeP2sh32(hash256(compileFoldKernel(nFold, queryIndex)));
}

function pushRedeem(data: Uint8Array): Uint8Array {
  if (data.length <= 75) return Uint8Array.of(data.length, ...data);
  if (data.length <= 255) return Uint8Array.of(0x4c, data.length, ...data);
  return Uint8Array.of(0x4d, data.length & 0xff, (data.length >> 8) & 0xff, ...data);
}

export function foldKernelUnlocking(
  nFold = 1,
  queryIndex = 0,
  packed?: Uint8Array,
  pairShard?: Uint8Array,
): Uint8Array {
  const redeem = pushRedeem(compileFoldKernel(nFold, queryIndex));
  if (!packed || packed.length < AIR_PACKED_SIZE) return redeem;
  const invs = foldInvsBlob(packed, queryIndex, nFold);
  const pairs = pairShard ?? new Uint8Array(nFold * PAIR_BYTES);
  const body = new Uint8Array(pairs.length + invs.length);
  body.set(pairs, 0);
  body.set(invs, pairs.length);
  const push = body.length <= 75
    ? Uint8Array.of(body.length, ...body)
    : body.length <= 255
      ? Uint8Array.of(0x4c, body.length, ...body)
      : Uint8Array.of(0x4d, body.length & 0xff, (body.length >> 8) & 0xff, ...body);
  const out = new Uint8Array(push.length + redeem.length);
  out.set(push, 0);
  out.set(redeem, push.length);
  return out;
}

/**
 * On-chain Circle FRI fold (2024/278 foldPair) for the 2026 VM.
 * Function indices used by the production fold kernel:
 *   0 CIRCLE_ADD  1 SMUL  2 FOLD_SECURE  3 LAMBDA
 *   4 FOLD_QM31   5 BE8_MOD_P   6 CM31_MUL  7 VANISH  8 RSLOT  9 LAMAT
 */
import { cashAssemblyToBin } from "@bitauth/libauth";
import { COMMITTED_LAYERS, FRI_FINAL, FRI_N } from "../backends/circle/params.ts";
import { CIRCLE_ONE } from "../backends/circle/group.ts";
import {
  AIR_OFF_DIGEST,
  AIR_OFF_FINAL,
  AIR_OFF_IDX,
  AIR_OFF_OPEN_MASK,
  AIR_OFF_QTABLE,
  AIR_OFF_ROOTS,
  BE16_UNSIGNED,
  CIRCLE_ADD,
  G1024,
  SCALAR_MUL_FAST,
  VANISH_XS,
  vanishingUnrolledAsm,
} from "./air-cqz.ts";
import { M31_ADD, M31_INV, M31_MUL, M31_P, M31_SUB, M31_TWO_INV } from "./m31-asm.ts";
import {
  BLOB_TO_QM31_ASM,
  CM31_MUL_ASM,
  QM31_ADD_ASM,
  QM31_EVEN_ODD_ASM,
  QM31_MUL_ASM,
  QM31_MUL_M31_ASM,
  QM31_TO_BLOB_ASM,
} from "./qm31-asm.ts";
import { slotRCqzBodyBlobAsm } from "./r-kernel.ts";

function hexPush(data: Uint8Array): string {
  return `<0x${Buffer.from(data).toString("hex")}>`;
}

function defineFn(asm: string, index: number, name: string): string {
  const body = cashAssemblyToBin(asm);
  if (typeof body === "string") throw new Error(`${name}: ${body}`);
  return `${hexPush(body)}\n<${index}>\nOP_DEFINE`;
}

function pushFelt(n: bigint): string {
  return `<${n.toString()}>`;
}

/** 4-byte big-endian → unsigned integer (trailing 0x00 keeps BIN2NUM unsigned). */
function be4UnsignedAsm(): string {
  return `
OP_1 OP_SPLIT
OP_1 OP_SPLIT
OP_1 OP_SPLIT
OP_SWAP
OP_CAT
OP_SWAP
OP_CAT
OP_SWAP
OP_CAT
<0x00>
OP_CAT
OP_BIN2NUM
`;
}

/** 8-byte big-endian → integer, then mod M31 (hashToM31). Same value as the byte-loop. */
export const BE8_MOD_P = `
<4> OP_SPLIT
OP_SWAP
${be4UnsignedAsm()}
<4294967296>
OP_MUL
OP_SWAP
${be4UnsignedAsm()}
OP_ADD
<${M31_P}> OP_MOD
`;

/** Stack: packed r → λ0 λ1 λ2 λ3 (λ3 on top). Full SHA-256 as four BE-u64 mod p. Consumes packed. */
export function lambdaFromPackedAsm(): string {
  return `
OP_TOALTSTACK
OP_DUP
<${AIR_OFF_DIGEST}> OP_SPLIT OP_NIP
<32> OP_SPLIT OP_DROP
OP_FROMALTSTACK
OP_DUP
OP_TOALTSTACK
<1> OP_NUM2BIN
OP_CAT
OP_OVER
OP_FROMALTSTACK
<32> OP_MUL
<${AIR_OFF_ROOTS}> OP_ADD
OP_SPLIT OP_NIP
<32> OP_SPLIT OP_DROP
OP_CAT
<0x6c616d626461> OP_CAT
OP_SHA256
<8> OP_SPLIT
OP_SWAP
${BE8_MOD_P}
OP_SWAP
<8> OP_SPLIT
OP_SWAP
${BE8_MOD_P}
OP_SWAP
<8> OP_SPLIT
OP_SWAP
${BE8_MOD_P}
OP_SWAP
${BE8_MOD_P}
OP_4 OP_ROLL
OP_DROP
`;
}

/**
 * Stack: px py fP fConj λ inv → folded.
 * Witness inv must satisfy inv · (px==0 ? py : px) ≡ 1 (mod M31).
 * foldPair: (fP+fConj)/2 + λ · (fP−fConj)/2 · inv.
 */
export const FOLD_PAIR_ASM = `
OP_5 OP_PICK
OP_0 OP_NUMEQUAL
OP_IF
  OP_4 OP_PICK
OP_ELSE
  OP_5 OP_PICK
OP_ENDIF
OP_OVER
${M31_MUL}
<1>
OP_NUMEQUALVERIFY
OP_TOALTSTACK
OP_2 OP_PICK
OP_2 OP_PICK
${M31_ADD}
<${M31_TWO_INV}>
${M31_MUL}
OP_3 OP_PICK
OP_3 OP_PICK
${M31_SUB}
<${M31_TWO_INV}>
${M31_MUL}
OP_FROMALTSTACK
${M31_MUL}
OP_2 OP_PICK
${M31_MUL}
${M31_ADD}
OP_NIP
OP_NIP
OP_NIP
OP_NIP
OP_NIP
`;

function smul9InvokeAsm(): string {
  const bit = `
OP_DUP
OP_2 OP_MOD
OP_IF
  OP_TOALTSTACK
  OP_3 OP_PICK
  OP_3 OP_PICK
  OP_3 OP_PICK
  OP_3 OP_PICK
  <0> OP_INVOKE
  OP_TOALTSTACK
  OP_TOALTSTACK
  OP_2SWAP
  OP_2DROP
  OP_FROMALTSTACK
  OP_FROMALTSTACK
  OP_2SWAP
  OP_FROMALTSTACK
OP_ENDIF
OP_TOALTSTACK
OP_2DUP
<0> OP_INVOKE
OP_FROMALTSTACK
OP_2 OP_DIV
`;
  return `
OP_TOALTSTACK
OP_TOALTSTACK
${pushFelt(CIRCLE_ONE.x)}
${pushFelt(CIRCLE_ONE.y)}
OP_FROMALTSTACK
OP_FROMALTSTACK
OP_4 OP_ROLL
${Array.from({ length: 9 }, () => bit).join("\n")}
OP_DROP
OP_2DROP
`;
}

function lambdaFromPackedKernelAsm(): string {
  return lambdaFromPackedAsm().split(BE8_MOD_P).join("<5> OP_INVOKE");
}

/** Stack: digest root32 r → λ0 λ1 λ2 λ3. SHA-256(digest || r || root32 || "lambda"). */
function lambdaFromDigestRootsAsm(): string {
  return `
OP_2 OP_PICK
OP_OVER
<1>
OP_NUM2BIN
OP_CAT
OP_2 OP_PICK
OP_CAT
<0x6c616d626461>
OP_CAT
OP_SHA256
<8> OP_SPLIT
OP_SWAP
<5> OP_INVOKE
OP_SWAP
<8> OP_SPLIT
OP_SWAP
<5> OP_INVOKE
OP_SWAP
<8> OP_SPLIT
OP_SWAP
<5> OP_INVOKE
OP_SWAP
<5> OP_INVOKE
OP_6 OP_ROLL
OP_DROP
OP_5 OP_ROLL
OP_DROP
OP_4 OP_ROLL
OP_DROP
`;
}

/** Stack: 16-byte λ_r → λ0 λ1 λ2 λ3 (λ3 on top). */
function lambdaFromBlobAsm(): string {
  return BLOB_TO_QM31_ASM;
}

function splitDropPrefixAsm(n: number): string {
  if (n < 0) throw new Error(`peel skip ${n}`);
  if (n === 0) return "";
  return `<${n}>\nOP_SPLIT\nOP_NIP\n`;
}

/**
 * Consume packed once. No 1704-byte DUP/PICK.
 * Stack: packed → commit q24 idx final digest roots.
 */
export function peelPackedFoldRAsm(nFold: number, queryIndex: number): string {
  const rootsLen = COMMITTED_LAYERS * 32;
  const qOff = AIR_OFF_QTABLE - (AIR_OFF_OPEN_MASK + 32) + queryIndex * 4;
  const idxOff = AIR_OFF_IDX + queryIndex * 2 - (AIR_OFF_QTABLE + queryIndex * 4 + nFold * 4);
  const finalOff = AIR_OFF_FINAL - (AIR_OFF_IDX + queryIndex * 2 + nFold * 2);
  return `
<${rootsLen}>
OP_SPLIT
OP_SWAP
OP_TOALTSTACK
${splitDropPrefixAsm(AIR_OFF_DIGEST - rootsLen)}
<32>
OP_SPLIT
OP_SWAP
OP_TOALTSTACK
${splitDropPrefixAsm(AIR_OFF_OPEN_MASK - (AIR_OFF_DIGEST + 32))}
<32>
OP_SPLIT
${splitDropPrefixAsm(qOff)}
<${nFold * 4}>
OP_SPLIT
${splitDropPrefixAsm(idxOff)}
<${nFold * 2}>
OP_SPLIT
${splitDropPrefixAsm(finalOff)}
<128>
OP_SPLIT
OP_DROP
OP_FROMALTSTACK
OP_FROMALTSTACK
`;
}

/** Stack: digest roots224 → λblob. Splits roots into 7×32 so λ never copies 224. */
function lambdaBlobFromDigestRootsAsm(): string {
  const splitRoots = Array.from({ length: COMMITTED_LAYERS - 1 }, () => `<32>\nOP_SPLIT`).join("\n");
  const one = (r: number): string => `
<${7 - r}>
OP_PICK
OP_9
OP_PICK
OP_SWAP
<${r}>
<3> OP_INVOKE
${QM31_TO_BLOB_ASM}
OP_SIZE
<16>
OP_NUMEQUALVERIFY
OP_CAT
`;
  return `
OP_SIZE
<224>
OP_NUMEQUALVERIFY
OP_SWAP
OP_SIZE
<32>
OP_NUMEQUALVERIFY
OP_SWAP
${splitRoots}
OP_0
${Array.from({ length: COMMITTED_LAYERS }, (_, r) => one(r)).join("\n")}
OP_TOALTSTACK
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_FROMALTSTACK
`;
}

/** Stack: packed → commit q24 idx final λblob. */
export function lambdaBlobFromPackedAsm(nFold: number, queryIndex: number): string {
  return `
${peelPackedFoldRAsm(nFold, queryIndex)}
${lambdaBlobFromDigestRootsAsm()}
`;
}

export function foldDefinesAsm(): string {
  const foldQm31 = FOLD_PAIR_QM31_ASM.split(CM31_MUL_ASM).join("<6> OP_INVOKE");
  return [
    defineFn(CIRCLE_ADD, 0, "cadd"),
    defineFn(SCALAR_MUL_FAST.split(CIRCLE_ADD).join("<0> OP_INVOKE"), 1, "smul"),
    defineFn(FOLD_PAIR_SECURE_ASM, 2, "fold0"),
    defineFn(lambdaFromDigestRootsAsm(), 3, "lambda"),
    defineFn(foldQm31, 4, "foldq"),
    defineFn(BE8_MOD_P, 5, "be8"),
    defineFn(CM31_MUL_ASM, 6, "cmmul"),
    defineFn(vanishingUnrolledAsm(VANISH_XS), 7, "vanish"),
    defineFn(slotRCqzBodyBlobAsm(1, 7), 8, "rslot"),
    defineFn(lambdaFromBlobAsm(), 9, "lamat"),
  ].join("\n");
}

/** Stack: a → −a (mod M31). */
function m31NegAsm(): string {
  return `OP_0 OP_SWAP\n${M31_SUB}`;
}

/**
 * Layer-0 domain point: [idx % (FRI_N/2)] · G1024.
 * Stack in: packed built idxBlob q. Stack out: … Px Py.
 */
function layer0PointAsm(): string {
  return `
OP_1 OP_PICK
OP_1 OP_PICK
<2> OP_MUL
OP_SPLIT OP_NIP
<2> OP_SPLIT OP_DROP
${BE16_UNSIGNED}
<${FRI_N >> 1}>
OP_MOD
${pushFelt(G1024.x)}
${pushFelt(G1024.y)}
<1> OP_INVOKE
`;
}

/**
 * P_r → P_{r+1} by doubling, then (−x,−y) when the next lo bit is set.
 * Matches [idx % (FRI_N>>(r+1))] · 2^r G without a fresh 10-bit scalar mul.
 * Stack in: packed built idxBlob q Px Py (P_{r-1}). Stack out: … P_r x y.
 * `r` is the layer being entered (r ≥ 1).
 */
function advancePointAsm(r: number): string {
  return `
OP_2DUP
<0> OP_INVOKE
OP_3 OP_PICK
OP_3 OP_PICK
<2> OP_MUL
OP_SPLIT OP_NIP
<2> OP_SPLIT OP_DROP
${BE16_UNSIGNED}
<${FRI_N >> r}>
OP_MOD
<${FRI_N >> (r + 1)}>
OP_GREATERTHANOREQUAL
OP_IF
  ${m31NegAsm()}
  OP_SWAP
  ${m31NegAsm()}
  OP_SWAP
OP_ENDIF
`;
}

const PAIR_GROUP_BYTES = 8 + 32 * (COMMITTED_LAYERS - 1);
const INV_GROUP_BYTES = COMMITTED_LAYERS * 4;
const PIECE_COUNT = COMMITTED_LAYERS * 2;

/**
 * After pre-split: p0..p6 i0..i6 idx q (q on top). extraOnTop sits above q.
 * p0 at extra+15, p6 at extra+9; i0 at extra+8, i6 at extra+2.
 */
function pairDepth(layer: number, extraOnTop: number): number {
  return extraOnTop + 15 - layer;
}

function invDepth(layer: number, extraOnTop: number): number {
  return extraOnTop + 8 - layer;
}

/** extraOnTop: items above `p0..p6 i0..i6 idx q`. */
function extractPairAsm(layer: number, extraOnTop = 0): string {
  const d = pairDepth(layer, extraOnTop);
  if (layer === 0) {
    return `
<${d}>
OP_PICK
<4> OP_SPLIT
OP_TOALTSTACK
OP_BIN2NUM
OP_FROMALTSTACK
<4> OP_SPLIT OP_DROP
OP_BIN2NUM
`;
  }
  return `
<${d}>
OP_PICK
<16> OP_SPLIT
OP_SWAP
OP_TOALTSTACK
<16> OP_SPLIT
OP_DROP
OP_FROMALTSTACK
OP_SWAP
`;
}

/** extraOnTop: items above `p0..p6 i0..i6 idx q`. */
function extractInvAsm(layer: number, extraOnTop = 0): string {
  return `
<${invDepth(layer, extraOnTop)}>
OP_PICK
OP_BIN2NUM
`;
}

function nextPairCheckAsm(r: number): string {
  return `
${QM31_TO_BLOB_ASM}
${extractPairAsm(r + 1, 1)}
OP_2 OP_PICK
OP_EQUAL
OP_TOALTSTACK
OP_EQUAL
OP_FROMALTSTACK
OP_BOOLOR
OP_VERIFY
`;
}

function finalCheckAsm(): string {
  return `
${QM31_TO_BLOB_ASM}
OP_2 OP_PICK
OP_2 OP_PICK
<2> OP_MUL
OP_SPLIT OP_NIP
<2> OP_SPLIT OP_DROP
${BE16_UNSIGNED}
<${FRI_FINAL}> OP_MOD
OP_TOALTSTACK
<17>
OP_PICK
OP_FROMALTSTACK
<16> OP_MUL
OP_SPLIT OP_NIP
<16> OP_SPLIT OP_DROP
OP_EQUALVERIFY
`;
}

function layerFoldAsm(r: number): string {
  const restore = r === 0 ? "" : "OP_FROMALTSTACK\nOP_FROMALTSTACK";
  const point = r === 0 ? layer0PointAsm() : advancePointAsm(r);
  const save =
    r + 1 < COMMITTED_LAYERS ? "OP_2DUP\nOP_TOALTSTACK\nOP_TOALTSTACK" : "";
  const check = r + 1 < COMMITTED_LAYERS ? nextPairCheckAsm(r) : finalCheckAsm();
  if (r === 0) {
    return `
${point}
${save}
${extractPairAsm(0, 2)}
${extractInvAsm(0, 4)}
<${5 + 23 - r}>
OP_PICK
<9> OP_INVOKE
<2> OP_INVOKE
${check}
`;
  }
  return `
${restore}
${point}
${save}
${extractPairAsm(r, 2)}
OP_TOALTSTACK
${BLOB_TO_QM31_ASM}
OP_FROMALTSTACK
${BLOB_TO_QM31_ASM}
${extractInvAsm(r, 10)}
<${11 + 23 - r}>
OP_PICK
<9> OP_INVOKE
<4> OP_INVOKE
${check}
`;
}

/**
 * Stack in: invs pairs packed. Packed is consumed once (no 1704-byte copy).
 * Loop stack: commit q24 invs pairs λblob final128 p0..p6 i0..i6 idx q.
 * Pair/inv groups are split once per query so layer PICKs copy 8/32/4 bytes.
 * Leaves commit q24 idx for fused R (or three DROPs when R is not fused).
 */
export function foldQueriesAsm(nFold: number, queryIndex = 0): string {
  const pairBytes = PAIR_GROUP_BYTES;
  const invBytes = INV_GROUP_BYTES;
  const layers = Array.from({ length: COMMITTED_LAYERS }, (_, r) => layerFoldAsm(r)).join("\n");
  return `
${lambdaBlobFromPackedAsm(nFold, queryIndex)}
OP_SWAP
OP_ROT
OP_TOALTSTACK
OP_TOALTSTACK
OP_TOALTSTACK
OP_2SWAP
OP_FROMALTSTACK
OP_FROMALTSTACK
OP_FROMALTSTACK
OP_ROT
<16>
OP_SPLIT
<16>
OP_SPLIT
<16>
OP_SPLIT
<16>
OP_SPLIT
<16>
OP_SPLIT
<16>
OP_SPLIT
OP_8 OP_ROLL
OP_8 OP_ROLL
<0>
OP_BEGIN
  OP_DUP
  <${nFold}>
  OP_LESSTHAN
  OP_IF
    OP_10 OP_PICK
    OP_OVER
    <${pairBytes}>
    OP_MUL
    OP_SPLIT
    OP_NIP
    <${pairBytes}>
    OP_SPLIT
    OP_DROP
    <12>
    OP_PICK
    OP_2 OP_PICK
    <${invBytes}>
    OP_MUL
    OP_SPLIT
    OP_NIP
    <${invBytes}>
    OP_SPLIT
    OP_DROP
    OP_SWAP
    <8>
    OP_SPLIT
    <32>
    OP_SPLIT
    <32>
    OP_SPLIT
    <32>
    OP_SPLIT
    <32>
    OP_SPLIT
    <32>
    OP_SPLIT
    OP_7 OP_ROLL
    <4>
    OP_SPLIT
    <4>
    OP_SPLIT
    <4>
    OP_SPLIT
    <4>
    OP_SPLIT
    <4>
    OP_SPLIT
    <4>
    OP_SPLIT
    OP_15 OP_ROLL
    OP_15 OP_ROLL
    ${layers}
    OP_TOALTSTACK
    OP_TOALTSTACK
    OP_2DROP
    OP_2DROP
    OP_2DROP
    OP_2DROP
    OP_2DROP
    OP_2DROP
    OP_2DROP
    OP_FROMALTSTACK
    OP_FROMALTSTACK
    OP_1ADD
    OP_0
  OP_ELSE
    OP_DROP
    OP_1
  OP_ENDIF
OP_UNTIL
OP_TOALTSTACK
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_FROMALTSTACK
OP_SIZE
<${nFold * 2}>
OP_NUMEQUALVERIFY
OP_SWAP
OP_SIZE
<${nFold * 4}>
OP_NUMEQUALVERIFY
OP_ROT
OP_SIZE
<32>
OP_NUMEQUALVERIFY
OP_SWAP
OP_ROT
`;
}

export function compileM31InvLock(expected: bigint): Uint8Array {
  const bin = cashAssemblyToBin(`${M31_INV}\n${pushFelt(expected)}\nOP_NUMEQUAL`);
  if (typeof bin === "string") throw new Error(`m31-inv: ${bin}`);
  return bin;
}

/**
 * Later-layer occupancy. Unlocking: px py a0-3 b0-3 inv λ0-3 (λ3 on top).
 * Result: even + λ · oddOver in QM31. Stack out r0 r1 r2 r3.
 */
export const FOLD_PAIR_QM31_ASM = `
OP_TOALTSTACK
OP_TOALTSTACK
OP_TOALTSTACK
OP_TOALTSTACK
OP_TOALTSTACK
OP_9 OP_ROLL
OP_TOALTSTACK
OP_8 OP_ROLL
OP_TOALTSTACK
${QM31_EVEN_ODD_ASM}
OP_FROMALTSTACK
OP_FROMALTSTACK
OP_DUP
OP_0
OP_NUMEQUAL
OP_IF
  OP_OVER
OP_ELSE
  OP_DUP
OP_ENDIF
OP_FROMALTSTACK
OP_2DUP
${M31_MUL}
<1>
OP_NUMEQUALVERIFY
OP_TOALTSTACK
OP_DROP
OP_2DROP
OP_FROMALTSTACK
${QM31_MUL_M31_ASM}
OP_FROMALTSTACK
OP_FROMALTSTACK
OP_FROMALTSTACK
OP_FROMALTSTACK
${QM31_MUL_ASM}
${QM31_ADD_ASM}
`;

/**
 * First-fold occupancy. Unlocking: px py fP fConj inv λ0 λ1 λ2 λ3.
 * Result: QM31 = lift(even) + λ · oddOver. Stack out r0 r1 r2 r3.
 */
export const FOLD_PAIR_SECURE_ASM = `
OP_TOALTSTACK
OP_TOALTSTACK
OP_TOALTSTACK
OP_TOALTSTACK
OP_4 OP_PICK
OP_0 OP_NUMEQUAL
OP_IF
  OP_3 OP_PICK
OP_ELSE
  OP_4 OP_PICK
OP_ENDIF
OP_OVER
${M31_MUL}
<1>
OP_NUMEQUALVERIFY
OP_2 OP_PICK
OP_2 OP_PICK
${M31_ADD}
<${M31_TWO_INV}>
${M31_MUL}
OP_TOALTSTACK
OP_2 OP_PICK
OP_2 OP_PICK
${M31_SUB}
<${M31_TWO_INV}>
${M31_MUL}
OP_OVER
${M31_MUL}
OP_TOALTSTACK
OP_DROP
OP_2DROP
OP_2DROP
OP_FROMALTSTACK
OP_FROMALTSTACK
OP_SWAP
OP_FROMALTSTACK
OP_OVER
${M31_MUL}
OP_ROT
${M31_ADD}
OP_SWAP
OP_FROMALTSTACK
OP_OVER
${M31_MUL}
OP_ROT
OP_ROT
OP_SWAP
OP_ROT
OP_ROT
OP_FROMALTSTACK
OP_OVER
${M31_MUL}
OP_SWAP
OP_FROMALTSTACK
OP_OVER
${M31_MUL}
OP_NIP
`;

export function compileFoldPairSecureLock(expected: readonly [bigint, bigint, bigint, bigint]): Uint8Array {
  const asm = `
${FOLD_PAIR_SECURE_ASM}
${pushFelt(expected[3]!)}
OP_EQUALVERIFY
${pushFelt(expected[2]!)}
OP_EQUALVERIFY
${pushFelt(expected[1]!)}
OP_EQUALVERIFY
${pushFelt(expected[0]!)}
OP_NUMEQUAL
`;
  const bin = cashAssemblyToBin(asm);
  if (typeof bin === "string") throw new Error(`fold-pair-secure: ${bin}`);
  return bin;
}

export function compileFoldPairQm31Lock(expected: readonly [bigint, bigint, bigint, bigint]): Uint8Array {
  const asm = `
${FOLD_PAIR_QM31_ASM}
${pushFelt(expected[3]!)}
OP_EQUALVERIFY
${pushFelt(expected[2]!)}
OP_EQUALVERIFY
${pushFelt(expected[1]!)}
OP_EQUALVERIFY
${pushFelt(expected[0]!)}
OP_NUMEQUAL
`;
  const bin = cashAssemblyToBin(asm);
  if (typeof bin === "string") throw new Error(`fold-pair-qm31: ${bin}`);
  return bin;
}

export function compileFoldPairLock(expected: bigint): Uint8Array {
  const asm = `
${FOLD_PAIR_ASM}
${pushFelt(expected)}
OP_NUMEQUAL
`;
  const bin = cashAssemblyToBin(asm);
  if (typeof bin === "string") throw new Error(`fold-pair: ${bin}`);
  return bin;
}

export function compileLambdaLock(expected: bigint): Uint8Array {
  const asm = `
${lambdaFromPackedAsm()}
${pushFelt(expected)}
OP_NUMEQUAL
`;
  const bin = cashAssemblyToBin(asm);
  if (typeof bin === "string") throw new Error(`lambda: ${bin}`);
  return bin;
}

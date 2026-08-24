/**
 * Stwo CM31 / QM31 snippets for the 2026 VM.
 * Stack numbers are M31 limbs. QM31 = (a0,a1,a2,a3) with a3 on top.
 */
import { cashAssemblyToBin } from "@bitauth/libauth";
import { M31_ADD, M31_MUL, M31_P, M31_SUB, M31_TWO_INV } from "./m31-asm.ts";

function pushFelt(n: bigint): string {
  return `<${n.toString()}>`;
}

/** Copy four limbs at the given depths onto the top (ar, ai, br, bi). */
export function copy4(ar: number, ai: number, br: number, bi: number): string {
  return `
<${ar}> OP_PICK
<${ai + 1}> OP_PICK
<${br + 2}> OP_PICK
<${bi + 3}> OP_PICK
`;
}

/**
 * CM31 mul. Stack: a0 a1 b0 b1 → re im.
 * (a+bi)(c+di) = (ac−bd)+(ad+bc)i
 */
export const CM31_MUL_ASM = `
OP_3 OP_PICK
OP_1 OP_PICK
${M31_MUL}
OP_3 OP_PICK
OP_3 OP_PICK
${M31_MUL}
${M31_ADD}
OP_TOALTSTACK
OP_3 OP_PICK
OP_2 OP_PICK
${M31_MUL}
OP_TOALTSTACK
OP_2 OP_PICK
OP_1 OP_PICK
${M31_MUL}
OP_FROMALTSTACK
OP_SWAP
${M31_SUB}
OP_TOALTSTACK
OP_2DROP
OP_2DROP
OP_FROMALTSTACK
OP_FROMALTSTACK
`;

/**
 * Multiply by R = 2+i. Stack: d0 d1 → re im.
 * re = 2 d0 − d1, im = 2 d1 + d0.
 */
export const CM31_MUL_R_ASM = `
OP_OVER
<2>
${M31_MUL}
OP_OVER
${M31_SUB}
OP_TOALTSTACK
OP_DUP
<2>
${M31_MUL}
OP_ROT
${M31_ADD}
OP_NIP
OP_FROMALTSTACK
OP_SWAP
`;

/** CM31 add. Stack: x0 x1 y0 y1 → re im. */
export const CM31_ADD_ASM = `
OP_2 OP_PICK
OP_1 OP_PICK
${M31_ADD}
OP_TOALTSTACK
OP_3 OP_PICK
OP_2 OP_PICK
${M31_ADD}
OP_TOALTSTACK
OP_2DROP
OP_2DROP
OP_FROMALTSTACK
OP_FROMALTSTACK
`;

/**
 * QM31 mul. Stack: a0 a1 a2 a3 b0 b1 b2 b3 → r0 r1 r2 r3.
 * (a+bu)(c+du) = (ac + R bd) + (ad+bc)u, R=2+i.
 * Im half is parked first so FROMALT yields re||im without OP_2SWAP.
 */
export const QM31_MUL_ASM = `
${copy4(7, 6, 1, 0)}
${CM31_MUL_ASM}
OP_TOALTSTACK
OP_TOALTSTACK
${copy4(5, 4, 3, 2)}
${CM31_MUL_ASM}
OP_FROMALTSTACK
OP_FROMALTSTACK
${CM31_ADD_ASM}
OP_TOALTSTACK
OP_TOALTSTACK
${copy4(5, 4, 1, 0)}
${CM31_MUL_ASM}
${CM31_MUL_R_ASM}
OP_TOALTSTACK
OP_TOALTSTACK
${copy4(7, 6, 3, 2)}
${CM31_MUL_ASM}
OP_FROMALTSTACK
OP_FROMALTSTACK
${CM31_ADD_ASM}
OP_TOALTSTACK
OP_TOALTSTACK
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_FROMALTSTACK
OP_FROMALTSTACK
OP_FROMALTSTACK
OP_FROMALTSTACK
`;

/** QM31 add. Stack: a0 a1 a2 a3 b0 b1 b2 b3 → s0 s1 s2 s3. */
export const QM31_ADD_ASM = `
<4> OP_PICK
OP_1 OP_PICK
${M31_ADD}
OP_TOALTSTACK
<5> OP_PICK
<2> OP_PICK
${M31_ADD}
OP_TOALTSTACK
<6> OP_PICK
<3> OP_PICK
${M31_ADD}
OP_TOALTSTACK
<7> OP_PICK
<4> OP_PICK
${M31_ADD}
OP_TOALTSTACK
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_FROMALTSTACK
OP_FROMALTSTACK
OP_FROMALTSTACK
OP_FROMALTSTACK
`;

/** QM31 * M31. Stack: a0 a1 a2 a3 m → r0 r1 r2 r3. */
export const QM31_MUL_M31_ASM = `
OP_DUP
OP_2 OP_PICK
${M31_MUL}
OP_TOALTSTACK
OP_DUP
OP_3 OP_PICK
${M31_MUL}
OP_TOALTSTACK
OP_DUP
OP_4 OP_PICK
${M31_MUL}
OP_TOALTSTACK
OP_DUP
OP_5 OP_PICK
${M31_MUL}
OP_TOALTSTACK
OP_DROP
OP_2DROP
OP_2DROP
OP_FROMALTSTACK
OP_FROMALTSTACK
OP_FROMALTSTACK
OP_FROMALTSTACK
`;

/**
 * even = (a+b)/2, odd = (a-b)/2. Consumes a and b (8 limbs).
 * Stack: a0 a1 a2 a3 b0 b1 b2 b3 → e0 e1 e2 e3 o0 o1 o2 o3.
 */
export const QM31_EVEN_ODD_ASM = `
<4> OP_PICK
OP_1 OP_PICK
${M31_SUB}
<${M31_TWO_INV}>
${M31_MUL}
OP_TOALTSTACK
<5> OP_PICK
<2> OP_PICK
${M31_SUB}
<${M31_TWO_INV}>
${M31_MUL}
OP_TOALTSTACK
<6> OP_PICK
<3> OP_PICK
${M31_SUB}
<${M31_TWO_INV}>
${M31_MUL}
OP_TOALTSTACK
<7> OP_PICK
<4> OP_PICK
${M31_SUB}
<${M31_TWO_INV}>
${M31_MUL}
OP_TOALTSTACK
<4> OP_PICK
OP_1 OP_PICK
${M31_ADD}
<${M31_TWO_INV}>
${M31_MUL}
OP_TOALTSTACK
<5> OP_PICK
<2> OP_PICK
${M31_ADD}
<${M31_TWO_INV}>
${M31_MUL}
OP_TOALTSTACK
<6> OP_PICK
<3> OP_PICK
${M31_ADD}
<${M31_TWO_INV}>
${M31_MUL}
OP_TOALTSTACK
<7> OP_PICK
<4> OP_PICK
${M31_ADD}
<${M31_TWO_INV}>
${M31_MUL}
OP_TOALTSTACK
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_FROMALTSTACK
OP_FROMALTSTACK
OP_FROMALTSTACK
OP_FROMALTSTACK
OP_FROMALTSTACK
OP_FROMALTSTACK
OP_FROMALTSTACK
OP_FROMALTSTACK
`;

/** Four limbs (a3 on top) → 16-byte LE blob matching encodeQm31. */
export const QM31_TO_BLOB_ASM = `
<4> OP_NUM2BIN
OP_TOALTSTACK
<4> OP_NUM2BIN
OP_TOALTSTACK
<4> OP_NUM2BIN
OP_TOALTSTACK
<4> OP_NUM2BIN
OP_FROMALTSTACK
OP_CAT
OP_FROMALTSTACK
OP_CAT
OP_FROMALTSTACK
OP_CAT
`;

/** 16-byte LE blob → a0 a1 a2 a3 (a3 on top). */
export const BLOB_TO_QM31_ASM = `
<4> OP_SPLIT
OP_SWAP
OP_BIN2NUM
OP_SWAP
<4> OP_SPLIT
OP_SWAP
OP_BIN2NUM
OP_SWAP
<4> OP_SPLIT
OP_SWAP
OP_BIN2NUM
OP_SWAP
OP_BIN2NUM
`;

function expectQm31Asm(body: string, expected: readonly [bigint, bigint, bigint, bigint]): string {
  return `
${body}
${pushFelt(expected[3]!)}
OP_EQUALVERIFY
${pushFelt(expected[2]!)}
OP_EQUALVERIFY
${pushFelt(expected[1]!)}
OP_EQUALVERIFY
${pushFelt(expected[0]!)}
OP_NUMEQUAL
`;
}

export function compileCm31MulLock(expected: readonly [bigint, bigint]): Uint8Array {
  const asm = `
${CM31_MUL_ASM}
${pushFelt(expected[1]!)}
OP_EQUALVERIFY
${pushFelt(expected[0]!)}
OP_NUMEQUAL
`;
  const bin = cashAssemblyToBin(asm);
  if (typeof bin === "string") throw new Error(`cm31-mul: ${bin}`);
  return bin;
}

export function compileCm31AddLock(expected: readonly [bigint, bigint]): Uint8Array {
  const asm = `
${CM31_ADD_ASM}
${pushFelt(expected[1]!)}
OP_EQUALVERIFY
${pushFelt(expected[0]!)}
OP_NUMEQUAL
`;
  const bin = cashAssemblyToBin(asm);
  if (typeof bin === "string") throw new Error(`cm31-add: ${bin}`);
  return bin;
}

export function compileCm31MulRLock(expected: readonly [bigint, bigint]): Uint8Array {
  const asm = `
${CM31_MUL_R_ASM}
${pushFelt(expected[1]!)}
OP_EQUALVERIFY
${pushFelt(expected[0]!)}
OP_NUMEQUAL
`;
  const bin = cashAssemblyToBin(asm);
  if (typeof bin === "string") throw new Error(`cm31-mul-r: ${bin}`);
  return bin;
}

export function compileQm31MulLock(expected: readonly [bigint, bigint, bigint, bigint]): Uint8Array {
  const bin = cashAssemblyToBin(expectQm31Asm(QM31_MUL_ASM, expected));
  if (typeof bin === "string") throw new Error(`qm31-mul: ${bin}`);
  return bin;
}

export function compileQm31AddLock(expected: readonly [bigint, bigint, bigint, bigint]): Uint8Array {
  const bin = cashAssemblyToBin(expectQm31Asm(QM31_ADD_ASM, expected));
  if (typeof bin === "string") throw new Error(`qm31-add: ${bin}`);
  return bin;
}

export function compileQm31MulM31Lock(expected: readonly [bigint, bigint, bigint, bigint]): Uint8Array {
  const bin = cashAssemblyToBin(expectQm31Asm(QM31_MUL_M31_ASM, expected));
  if (typeof bin === "string") throw new Error(`qm31-mul-m31: ${bin}`);
  return bin;
}

export function compileQm31EvenOddLock(
  even: readonly [bigint, bigint, bigint, bigint],
  odd: readonly [bigint, bigint, bigint, bigint],
): Uint8Array {
  const asm = `
${QM31_EVEN_ODD_ASM}
${pushFelt(odd[3]!)} OP_EQUALVERIFY
${pushFelt(odd[2]!)} OP_EQUALVERIFY
${pushFelt(odd[1]!)} OP_EQUALVERIFY
${pushFelt(odd[0]!)} OP_EQUALVERIFY
${pushFelt(even[3]!)} OP_EQUALVERIFY
${pushFelt(even[2]!)} OP_EQUALVERIFY
${pushFelt(even[1]!)} OP_EQUALVERIFY
${pushFelt(even[0]!)} OP_NUMEQUAL
`;
  const bin = cashAssemblyToBin(asm);
  if (typeof bin === "string") throw new Error(`qm31-even-odd: ${bin}`);
  return bin;
}

void M31_P;

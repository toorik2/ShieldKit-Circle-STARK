/**
 * On-chain R_on(i) + Z(i)·R_off(i). Fused slots check (qTable−R)·Z against
 * leftover L0 C(z): N = (opened − R) · Z. Honest occupancy+SHA ⇒ Q=0 ⇒ N=0.
 * Packed interpolant/openings are cargo. Not parked `<0>`.
 */
import { cashAssemblyToBin } from "@bitauth/libauth";
import {
  FRI_OPEN_MASK_TAG,
  OPEN_MASK_DEGREE,
  OPEN_MASK_OFF_DEGREE,
  VIEWING_TAG,
} from "../backends/circle/witness-mask.ts";
import { M31_ADD, M31_MUL, M31_SUB } from "./m31-asm.ts";
import { FRI_N } from "../backends/circle/params.ts";
import {
  AIR_OFF_CELLS,
  AIR_OFF_IDX,
  AIR_OFF_OPEN_MASK,
  AIR_OFF_QTABLE,
  AIR_OFF_SHA_C,
  BE16_UNSIGNED,
  G1024,
  SCALAR_MUL_FAST,
  VANISH_XS,
  fsIndexSlotAsm,
  packedMagicAsm,
  vanishingUnrolledAsm,
} from "./air-cqz.ts";

function hexPush(data: Uint8Array): string {
  return `<0x${Buffer.from(data).toString("hex")}>`;
}

function pushFelt(n: bigint): string {
  return `<${n.toString()}>`;
}

function defineFn(asm: string, index: number, name: string): string {
  const body = cashAssemblyToBin(asm);
  if (typeof body === "string") throw new Error(`${name}: ${body}`);
  return `${hexPush(body)}\n<${index}>\nOP_DEFINE`;
}

/** SHA256 blob → M31 felt (first 4 bytes, high bit cleared). */
export const FELT_FROM_SHA256 = `
OP_SHA256
<4> OP_SPLIT OP_DROP
<3> OP_SPLIT
<0x7f> OP_AND
OP_CAT
OP_BIN2NUM
<2147483647> OP_MOD
`;

/**
 * Horner eval of the PRF mask poly. Stack: prefix x → R.
 * Unrolled PRF of (stream,k) SHA-256 coeffs — same as JS `openingMaskCoeffs`.
 */
export function evalMaskPolyUnrolledAsm(stream: 0 | 1, degree: number): string {
  const lines: string[] = [`<0>`, `<1>`];
  for (let k = 0; k <= degree; k += 1) {
    lines.push(
      `OP_3 OP_PICK`,
      hexPush(Uint8Array.of(stream, k)),
      `OP_CAT`,
      FELT_FROM_SHA256,
      `OP_OVER`,
      M31_MUL,
      `OP_ROT`,
      M31_ADD,
      `OP_SWAP`,
    );
    if (k < degree) lines.push(`OP_2 OP_PICK`, M31_MUL);
  }
  lines.push(`OP_DROP`, `OP_NIP`, `OP_NIP`);
  return lines.join("\n");
}

/**
 * Same poly as `evalMaskPolyUnrolledAsm`, one Horner step in a loop.
 */
export function evalMaskPolyAsm(stream: 0 | 1, degree: number): string {
  const sk = hexPush(Uint8Array.of(stream));
  return `
<0>
<1>
<0>
OP_TOALTSTACK
OP_BEGIN
  OP_FROMALTSTACK
  OP_DUP
  <${degree}>
  OP_GREATERTHAN
  OP_IF
    OP_DROP
    OP_1
  OP_ELSE
    OP_DUP
    OP_TOALTSTACK
    OP_DROP
    OP_3 OP_PICK
    ${sk}
    OP_CAT
    OP_FROMALTSTACK
    OP_DUP
    OP_TOALTSTACK
    <1>
    OP_NUM2BIN
    OP_CAT
    ${FELT_FROM_SHA256}
    OP_OVER
    ${M31_MUL}
    OP_ROT
    ${M31_ADD}
    OP_SWAP
    OP_FROMALTSTACK
    OP_DUP
    <${degree}>
    OP_NUMEQUAL
    OP_IF
      OP_1ADD
      OP_TOALTSTACK
    OP_ELSE
      OP_1ADD
      OP_TOALTSTACK
      OP_2 OP_PICK
      ${M31_MUL}
    OP_ENDIF
    OP_0
  OP_ENDIF
OP_UNTIL
OP_DROP
OP_NIP
OP_NIP
`;
}

/**
 * Peel `n` 4-byte M31 encodings from a SHA-256 digest (high bit of each word cleared).
 * Stack: prefix acc hash → prefix acc' rest.
 */
function peelFeltsFromHashAsm(n: number): string {
  const peel = `
<4> OP_SPLIT
OP_SWAP
<3> OP_SPLIT
<0x7f> OP_AND
OP_CAT
OP_ROT
OP_SWAP
OP_CAT
OP_SWAP
`;
  return Array.from({ length: n }, () => peel).join("\n");
}

/**
 * SHA-256 mask coeffs once, squeezed: one digest → 8 felts.
 * On-stream: 1 block (8). Off-stream: 5 blocks, keep 36.
 * Stack: prefix → 176-byte blob.
 */
export function maskCoeffBlobAsm(): string {
  const block = (stream: 0 | 1, b: number, nFelts: number): string => `
OP_OVER
${hexPush(Uint8Array.of(stream, b))}
OP_CAT
OP_SHA256
${peelFeltsFromHashAsm(nFelts)}
OP_DROP
`;
  return `
OP_0
${block(0, 0, 8)}
${block(1, 0, 8)}
${block(1, 1, 8)}
${block(1, 2, 8)}
${block(1, 3, 8)}
${block(1, 4, 4)}
OP_NIP
`;
}

/** Stack: packed → packed blob. */
export function maskCoeffBlobFromPackedAsm(): string {
  return `
OP_DUP
<${AIR_OFF_OPEN_MASK}> OP_SPLIT OP_NIP
<32> OP_SPLIT OP_DROP
${hexPush(VIEWING_TAG)} OP_SWAP OP_CAT
${hexPush(FRI_OPEN_MASK_TAG)} OP_CAT
${maskCoeffBlobAsm()}
`;
}

/**
 * Horner over a coeff blob that is already the stream (no 32-byte slice).
 * Stack: blob x → R (consumes blob and x). Unrolled: x, acc, pow, rest.
 * No altstack (loop k lived there and stole x from OP_3 PICK).
 */
export function evalMaskPolyWholeBlobAsm(degree: number): string {
  const step = (k: number): string => `
<4>
OP_SPLIT
OP_SWAP
OP_BIN2NUM
OP_2 OP_PICK
${M31_MUL}
OP_3 OP_ROLL
${M31_ADD}
OP_SWAP
OP_ROT
OP_SWAP
${k < degree
    ? `
OP_SWAP
OP_3 OP_PICK
${M31_MUL}
OP_SWAP
`
    : ""}
`;
  return `
<0>
<1>
OP_3 OP_ROLL
${Array.from({ length: degree + 1 }, (_, k) => step(k)).join("\n")}
OP_DROP
OP_DROP
OP_NIP
`;
}

/**
 * Same power-sum as `evalMaskPolyAsm`, coeffs from a 4-byte-felt blob.
 * Stack: blob x → R (consumes blob and x).
 * Each Horner step peels 4 bytes from the remainder (no PICK of the 32/144-byte blob).
 */
export function evalMaskPolyFromBlobAsm(offset: number, degree: number): string {
  const slice = offset === 0
    ? `
OP_SWAP
<32>
OP_SPLIT
OP_DROP
OP_SWAP
`
    : `
OP_SWAP
<${offset}>
OP_SPLIT
OP_NIP
OP_SWAP
`;
  return `
${slice}
${evalMaskPolyWholeBlobAsm(degree)}
`;
}

/**
 * Stack: blob i Z → R (consumes blob).
 * R = R_on(i) + Z · R_off(i), x = i+1.
 * Split on/off once. Horner must see exactly (blob, x) — one extra item
 * under the loop makes OP_3 PICK steal x.
 */
export function openingMaskAtBlobAsm(): string {
  return `
OP_TOALTSTACK
<1> OP_ADD
OP_SWAP
<32> OP_SPLIT
OP_TOALTSTACK
OP_SWAP
OP_DUP
OP_TOALTSTACK
${evalMaskPolyWholeBlobAsm(OPEN_MASK_DEGREE)}
OP_FROMALTSTACK
OP_FROMALTSTACK
OP_SWAP
OP_ROT
OP_TOALTSTACK
${evalMaskPolyWholeBlobAsm(OPEN_MASK_OFF_DEGREE)}
OP_FROMALTSTACK
OP_FROMALTSTACK
OP_ROT
${M31_MUL}
${M31_ADD}
`;
}

/**
 * Stack: packed i Z → packed R.
 * R = R_on(i) + Z · R_off(i), x = i+1.
 */
export function openingMaskAtPackedAsm(): string {
  return `
OP_TOALTSTACK
OP_SWAP
OP_DUP
<${AIR_OFF_OPEN_MASK}> OP_SPLIT OP_NIP
<32> OP_SPLIT OP_DROP
${hexPush(VIEWING_TAG)} OP_SWAP OP_CAT
${hexPush(FRI_OPEN_MASK_TAG)} OP_CAT
${maskCoeffBlobAsm()}
OP_ROT
<1> OP_ADD
OP_2DUP
${evalMaskPolyFromBlobAsm(0, OPEN_MASK_DEGREE)}
OP_TOALTSTACK
${evalMaskPolyFromBlobAsm((OPEN_MASK_DEGREE + 1) * 4, OPEN_MASK_OFF_DEGREE)}
OP_FROMALTSTACK
OP_FROMALTSTACK
OP_ROT
${M31_MUL}
${M31_ADD}
`;
}

/** Stack: blob96 → acc of 48 u16 LE limbs mod M31. Alt-free (Z may already sit on alt). */
export function shaPubsAccFrom96Asm(): string {
  return `
<0>
OP_SWAP
OP_BEGIN
  OP_SIZE
  OP_IF
    <2> OP_SPLIT
    OP_ROT
    OP_SWAP
    OP_ROT
    <0x00>
    OP_CAT
    OP_BIN2NUM
    OP_ROT
    OP_SWAP
    ${M31_ADD}
    OP_SWAP
    OP_0
  OP_ELSE
    OP_DROP
    OP_1
  OP_ENDIF
OP_UNTIL
`;
}

/** Stack: packed → packed N. N = shaPubsAcc(cells 32–55) − opening[0]. */
export function shaNFromPackedAsm(): string {
  return `
OP_DUP
<${AIR_OFF_CELLS + 32 * 4}> OP_SPLIT OP_NIP
<96> OP_SPLIT OP_DROP
${shaPubsAccFrom96Asm()}
OP_OVER
<${AIR_OFF_SHA_C}> OP_SPLIT OP_NIP
<4> OP_SPLIT OP_DROP
<0x00>
OP_CAT
OP_BIN2NUM
${M31_SUB}
`;
}

/**
 * Requires OP_DEFINE smulDef=fast, vanishDef=vanish.
 * Stack: packed i → packed i N Z
 * N = leftover SHA-in-C C(z). Honest occupancy+SHA vanish ⇒ N = 0.
 */
export function nAndZFromPackedIAsm(smulDef = 2, vanishDef = 3): string {
  return `
OP_DUP
${pushFelt(G1024.x)}
${pushFelt(G1024.y)}
<${smulDef}> OP_INVOKE
OP_OVER
<${vanishDef}> OP_INVOKE
OP_TOALTSTACK
OP_2DROP
<0>
OP_FROMALTSTACK
`;
}

function slotDefines(): string {
  return `
${defineFn(SCALAR_MUL_FAST, 2, "fast")}
${defineFn(vanishingUnrolledAsm(VANISH_XS), 3, "vanish")}
`;
}

/**
 * One FS slot: (qTable[slot] − R(i)) · Z([i]G) equals leftover SHA-in-C C(z).
 * Honest occupancy+SHA vanish ⇒ N = 0. Independent of nTable.
 */
export function slotRCqzBodyAsm(slot = 0, smulDef = 2, vanishDef = 3): string {
  const qOff = AIR_OFF_QTABLE + slot * 4;
  return `
${fsIndexSlotAsm(slot)}
${nAndZFromPackedIAsm(smulDef, vanishDef)}
OP_DUP
OP_TOALTSTACK
OP_SWAP
OP_TOALTSTACK
${openingMaskAtPackedAsm()}
OP_FROMALTSTACK
OP_FROMALTSTACK
OP_3 OP_PICK
<${qOff}> OP_SPLIT OP_NIP
<4> OP_SPLIT OP_DROP
OP_BIN2NUM
OP_3 OP_PICK
${M31_SUB}
OP_1 OP_PICK
OP_0
OP_NUMEQUAL
OP_IF
  OP_0
  OP_NUMEQUALVERIFY
  OP_1 OP_PICK
  OP_0
  OP_NUMEQUALVERIFY
  OP_2DROP
  OP_2DROP
OP_ELSE
  OP_1 OP_PICK
  ${M31_MUL}
  OP_2 OP_PICK
  OP_NUMEQUALVERIFY
  OP_2DROP
  OP_2DROP
OP_ENDIF
`;
}

/**
 * Mask blob from peeled pieces. Packed is already consumed by the fold peel.
 * Stack: commit q24 idx12 → blob q24 idx12.
 */
export function fusedRPrepAsm(): string {
  return `
OP_ROT
OP_SIZE
<32>
OP_NUMEQUALVERIFY
${hexPush(VIEWING_TAG)}
OP_SWAP
OP_CAT
${hexPush(FRI_OPEN_MASK_TAG)}
OP_CAT
${maskCoeffBlobAsm()}
OP_ROT
OP_ROT
`;
}

/**
 * Stack: i → i Z. Vanishing at [i]G. Leftover L0 opened stays on the main stack.
 */
function zFromIAsm(smulDef = 2, vanishDef = 3): string {
  return `
OP_DUP
${pushFelt(G1024.x)}
${pushFelt(G1024.y)}
<${smulDef}> OP_INVOKE
OP_OVER
<${vanishDef}> OP_INVOKE
OP_TOALTSTACK
OP_2DROP
OP_FROMALTSTACK
`;
}

/**
 * Fused R: pairs idx q24 blob sha24 slot → pairs idx q24 blob sha24.
 * leftover C = (opened − R) · Z. Independent C_SHA = sha24[slot].
 * N = leftover C + C_SHA. Honest both 0. Not parked `<0>`.
 */
export function slotRCqzBodyBlobAsm(smulDef = 2, vanishDef = 3): string {
  return `
OP_DUP
<4>
OP_MUL
OP_2 OP_PICK
OP_SWAP
OP_SPLIT
OP_NIP
<4>
OP_SPLIT
OP_DROP
<0x00>
OP_CAT
OP_BIN2NUM
OP_SWAP
OP_DUP
<8>
OP_MUL
OP_7 OP_PICK
OP_SWAP
OP_SPLIT
OP_NIP
<8>
OP_SPLIT
OP_DROP
OP_OVER
<2>
OP_MUL
OP_7 OP_PICK
OP_SWAP
OP_SPLIT
OP_NIP
<2>
OP_SPLIT
OP_DROP
${BE16_UNSIGNED}
OP_DUP
<${FRI_N >> 1}>
OP_GREATERTHANOREQUAL
OP_IF
  OP_SWAP
  <4> OP_SPLIT OP_NIP
  <4> OP_SPLIT OP_DROP
OP_ELSE
  OP_SWAP
  <4> OP_SPLIT OP_DROP
OP_ENDIF
<0x00>
OP_CAT
OP_BIN2NUM
OP_2 OP_PICK
<4>
OP_MUL
OP_7 OP_PICK
OP_SWAP
OP_SPLIT
OP_NIP
<4>
OP_SPLIT
OP_DROP
OP_BIN2NUM
OP_3 OP_ROLL
OP_DROP
OP_2 OP_ROLL
${zFromIAsm(smulDef, vanishDef)}
OP_2DUP
OP_8 OP_PICK
OP_SWAP
OP_ROT
OP_SWAP
${openingMaskAtBlobAsm()}
OP_DUP
OP_4 OP_PICK
OP_SWAP
${M31_SUB}
OP_2 OP_PICK
${M31_MUL}
OP_6 OP_PICK
${M31_ADD}
OP_TOALTSTACK
OP_4 OP_PICK
OP_OVER
${M31_SUB}
OP_2 OP_PICK
${M31_MUL}
OP_FROMALTSTACK
OP_NUMEQUALVERIFY
OP_2DROP
OP_DROP
OP_NUMEQUALVERIFY
OP_DROP
`;
}

/**
 * Stack: packed slot → packed. Slot stays off the alt stack so mask Horner can use it.
 */
export function slotRCqzBodyStackAsm(smulDef = 2, vanishDef = 3): string {
  return `
OP_SWAP
OP_OVER
<4>
OP_MUL
<${AIR_OFF_QTABLE}>
OP_ADD
OP_ROT
OP_ROT
OP_SWAP
OP_OVER
<${AIR_OFF_IDX}>
OP_2 OP_PICK
<2>
OP_MUL
OP_ADD
OP_SPLIT
OP_NIP
<2>
OP_SPLIT
OP_DROP
${BE16_UNSIGNED}
OP_NIP
${nAndZFromPackedIAsm(smulDef, vanishDef)}
OP_DUP
OP_TOALTSTACK
OP_SWAP
OP_TOALTSTACK
${openingMaskAtPackedAsm()}
OP_FROMALTSTACK
OP_FROMALTSTACK
OP_3 OP_PICK
OP_5 OP_PICK
OP_SPLIT
OP_NIP
<4>
OP_SPLIT
OP_DROP
OP_BIN2NUM
OP_3 OP_PICK
${M31_SUB}
OP_1 OP_PICK
OP_0
OP_NUMEQUAL
OP_IF
  OP_0
  OP_NUMEQUALVERIFY
  OP_1 OP_PICK
  OP_0
  OP_NUMEQUALVERIFY
  OP_2DROP
  OP_2DROP
OP_ELSE
  OP_1 OP_PICK
  ${M31_MUL}
  OP_2 OP_PICK
  OP_NUMEQUALVERIFY
  OP_2DROP
  OP_2DROP
OP_ENDIF
OP_NIP
`;
}

export function slotRCqzAsm(slot = 0): string {
  return `
${slotDefines()}
${packedMagicAsm()}
${slotRCqzBodyAsm(slot)}
`;
}

function compileOrThrow(asm: string, name: string): Uint8Array {
  const bin = cashAssemblyToBin(asm);
  if (typeof bin === "string") throw new Error(`${name}: ${bin}`);
  return bin;
}

/** Isolated R at FS slot 0. Unlocking: packed. Leaves true iff R matches `expected`. */
export function compileRAtSlot0Lock(expected: bigint): Uint8Array {
  return compileOrThrow(
    `
${slotDefines()}
${packedMagicAsm()}
${fsIndexSlotAsm(0)}
OP_DUP
${pushFelt(G1024.x)}
${pushFelt(G1024.y)}
<2> OP_INVOKE
OP_OVER
<3> OP_INVOKE
OP_TOALTSTACK
OP_2DROP
OP_FROMALTSTACK
${openingMaskAtPackedAsm()}
OP_NIP
${pushFelt(expected)}
OP_NUMEQUAL
`,
    "r-slot0",
  );
}

/** Isolated N = leftover SHA-in-C vanish at FS slot 0. Unlocking: packed. Honest N = 0. */
export function compileNFromTSlot0Lock(expected: bigint): Uint8Array {
  return compileOrThrow(
    `
${slotDefines()}
${packedMagicAsm()}
${fsIndexSlotAsm(0)}
${nAndZFromPackedIAsm()}
OP_DROP
OP_NIP
OP_NIP
${pushFelt(expected)}
OP_NUMEQUAL
`,
    "n-slot0",
  );
}

export function compileSlotRCqzLock(slot = 0): Uint8Array {
  return compileOrThrow(`${slotRCqzAsm(slot)}\nOP_1`, `slot-${slot}-r-cqz`);
}

/**
 * Isolated fused leftover-L0 C + independent SHA_OPEN. Unlocking:
 * commit q24 idx pairs sha24 (sha24 on top).
 */
export function compileFusedLeftoverCLock(nSlots = 6): Uint8Array {
  const slots = Array.from({ length: nSlots }, (_, i) => `<${i}>\n<8> OP_INVOKE`).join("\n");
  return compileOrThrow(
    `
${slotDefines()}
${defineFn(slotRCqzBodyBlobAsm(2, 3), 8, "rslot")}
OP_TOALTSTACK
OP_TOALTSTACK
${fusedRPrepAsm()}
OP_FROMALTSTACK
OP_SWAP
OP_2SWAP
OP_SWAP
OP_FROMALTSTACK
${slots}
OP_DROP
OP_2DROP
OP_2DROP
OP_1
`,
    "fused-leftover-c",
  );
}

import { cashAssemblyToBin } from "@bitauth/libauth";
import { ZERO32 } from "../pool/bytes.ts";

/**
 * IncrementalMerkle pair: SHA-256(left || right), bit = index&1.
 * Stack in: acc, steps=(bit||sib)*. Stack out: root.
 * Uses altstack only for the current step's remainder (LIFO-safe).
 */
export const NOTE_MERKLE_WALK = `
OP_BEGIN
  OP_SIZE
  OP_0 OP_GREATERTHAN
  OP_IF
    <33> OP_SPLIT
    OP_SWAP
    <1> OP_SPLIT
    OP_2SWAP
    OP_TOALTSTACK
    OP_ROT
    OP_NOTIF
      OP_SWAP
    OP_ENDIF
    OP_CAT
    OP_SHA256
    OP_FROMALTSTACK
    OP_0
  OP_ELSE
    OP_DROP
    OP_1
  OP_ENDIF
OP_UNTIL
`;

export const ZERO32_ASM = `<0x${Buffer.from(ZERO32).toString("hex")}>`;

export const EXTRACT_INSTANCE = `<32> OP_SPLIT OP_NIP <32> OP_SPLIT OP_DROP`;
export const EXTRACT_NOTE_ROOT = `<64> OP_SPLIT OP_NIP <32> OP_SPLIT OP_DROP`;
export const EXTRACT_NF_ROOT = `<96> OP_SPLIT OP_NIP`;

/** High 4 bytes of a u64-BE field must be 0; low 4 → script number. */
const U64BE_FIELD_TO_NUM = `
<4> OP_SPLIT
OP_SWAP
<0x00000000> OP_EQUALVERIFY
<4> OP_SPLIT
OP_DROP
OP_REVERSEBYTES
OP_BIN2NUM
`;

export const EXTRACT_SEQ_NUM = `<8> OP_SPLIT OP_NIP\n${U64BE_FIELD_TO_NUM}`;
export const EXTRACT_RESERVE_NUM = `<16> OP_SPLIT OP_NIP\n${U64BE_FIELD_TO_NUM}`;
/** PAA1 withdrawalCount at offset 28, u32-BE. */
export const EXTRACT_WD_NUM = `<28> OP_SPLIT OP_NIP <4> OP_SPLIT OP_DROP OP_REVERSEBYTES OP_BIN2NUM`;

export function encodeWalkSteps(index: number, path: Uint8Array[]): Uint8Array {
  const parts: Uint8Array[] = [];
  let i = index;
  for (const sib of path) {
    parts.push(Uint8Array.of(i & 1), sib);
    i >>= 1;
  }
  const n = parts.reduce((s, p) => s + p.length, 0);
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

/** Stack: nf instance owner rho amountCommit spentLeaf spentSteps oldNoteRoot */
export const SPENT_NOTE_PREIMAGE = `
OP_TOALTSTACK
OP_TOALTSTACK
OP_TOALTSTACK
OP_TOALTSTACK
OP_2DUP
OP_TOALTSTACK
OP_TOALTSTACK
OP_CAT
OP_CAT
OP_SHA256
OP_EQUALVERIFY
OP_FROMALTSTACK
OP_FROMALTSTACK
OP_FROMALTSTACK
OP_TOALTSTACK
OP_SWAP
OP_FROMALTSTACK
OP_ROT
OP_ROT
OP_CAT
OP_CAT
OP_SHA256
OP_FROMALTSTACK
OP_TUCK
OP_EQUALVERIFY
OP_FROMALTSTACK
OP_FROMALTSTACK
OP_TOALTSTACK
${NOTE_MERKLE_WALK}
OP_FROMALTSTACK
OP_EQUALVERIFY
`;

export function compileNoteMerkleWalk(): Uint8Array {
  const bin = cashAssemblyToBin(NOTE_MERKLE_WALK);
  if (typeof bin === "string") throw new Error(`note merkle walk: ${bin}`);
  return bin;
}

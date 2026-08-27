/**
 * On-chain algebraicC occupancy pins (digest / seq / action / reserve).
 * Honest leftover-z C_SHA openings are zeros: hashBitRoot must be the
 * zero-column merkle (grind-bound). Nonzero openings are fused N on input 12.
 * Not 36 compact walks. HASH_BIT_CHECK_ASM stays dead.
 */
import { cashAssemblyToBin, encodeLockingBytecodeP2sh32, hash256 } from "@bitauth/libauth";
import {
  AIR_OFF_DIGEST,
  AIR_OFF_HASHBIT,
  AIR_OFF_SHA_OPEN,
  AIR_SHA_OPEN_BYTES,
  extractCellAsm,
  LOAD_AIR_PACKED,
  packedMagicAsm,
} from "./air-cqz.ts";
import { zerosCShaMerkleRoot } from "./sha-lde.ts";
import { M31_ADD, M31_P, M31_SUB } from "./m31-asm.ts";
import { sha256 } from "../pool/bytes.ts";
import { STATE_BASE_SATS } from "../pool/state.ts";
import { FRI_N, FRI_QUERIES, TRACE_LEN } from "../backends/circle/params.ts";
import { circleDomain, decodeFriProof, type FriProof } from "../backends/circle/fri.ts";
import { shaCLdeColumn } from "../backends/circle/air.ts";
import { defaultInternalHash } from "../backends/circle/internal-hash.ts";
import {
  encodeShaCLdeCargo,
  leavesFromLdeColumn,
  openShaLde,
  SHA_LDE_COMPACT,
  SHA_LDE_VALUE_BYTES,
} from "./sha-lde.ts";
import { explodeTableFnAsm, shaWalkFnAsm } from "./note-auth-kernel.ts";
import type { PoolStatement } from "../pool/statement.ts";

export { ALGEBRAIC_C_INPUT } from "./air-cqz.ts";

const SHA_LDE_COMPACT_LEN = FRI_QUERIES * SHA_LDE_COMPACT;

const U8_FROM_FRONT = `
<1> OP_SPLIT
OP_SWAP
OP_BIN2NUM
`;

function shaCMerkleAsm(): string {
  const walkLoop = `
<0>
OP_BEGIN
  OP_DUP
  <${FRI_QUERIES}>
  OP_LESSTHAN
  OP_IF
    OP_2 OP_PICK
    OP_4 OP_PICK
    OP_2 OP_PICK
    <${SHA_LDE_COMPACT}>
    OP_MUL
    <2> OP_NUM2BIN
    OP_BIN2NUM
    OP_SPLIT OP_NIP
    <${SHA_LDE_COMPACT}> OP_SPLIT OP_DROP
    OP_6 OP_PICK
    OP_3 OP_PICK
    OP_SPLIT OP_NIP
    <1> OP_SPLIT OP_DROP
    <0x00> OP_CAT
    OP_BIN2NUM
    <${SHA_LDE_VALUE_BYTES}> OP_MUL
    <2> OP_NUM2BIN
    OP_BIN2NUM
    OP_8 OP_PICK
    OP_SWAP
    OP_SPLIT OP_NIP
    <${SHA_LDE_VALUE_BYTES}> OP_SPLIT OP_DROP
    OP_4 OP_PICK
    <2> OP_INVOKE
    OP_1ADD
    OP_0
  OP_ELSE
    OP_DROP
    OP_1
  OP_ENDIF
OP_UNTIL
`;
  return `
${shaWalkFnAsm()}
${explodeTableFnAsm()}
${U8_FROM_FRONT}
OP_TOALTSTACK
${U8_FROM_FRONT}
OP_TOALTSTACK
OP_FROMALTSTACK
OP_SWAP
OP_FROMALTSTACK
<${SHA_LDE_VALUE_BYTES}>
OP_MUL
<2> OP_NUM2BIN
OP_BIN2NUM
OP_TOALTSTACK
OP_SWAP
OP_FROMALTSTACK
OP_SWAP
OP_TOALTSTACK
OP_SPLIT
<${FRI_QUERIES}>
OP_SPLIT
<${SHA_LDE_COMPACT_LEN}>
OP_SPLIT
OP_FROMALTSTACK
<3> OP_INVOKE
${LOAD_AIR_PACKED}
<${AIR_OFF_HASHBIT}> OP_SPLIT OP_NIP
<32> OP_SPLIT OP_DROP
OP_SIZE
<32>
OP_NUMEQUALVERIFY
OP_DUP
OP_0NOTEQUAL
OP_VERIFY
${walkLoop}
OP_2DROP
OP_2DROP
OP_DROP
`;
}

const ZEROS_C_SHA_ROOT = zerosCShaMerkleRoot();
const ZEROS_SHA_OPEN_HASH = sha256(new Uint8Array(AIR_SHA_OPEN_BYTES));

export const ALGEBRAIC_C_KERNEL_ASM = `
${LOAD_AIR_PACKED}
${packedMagicAsm()}
OP_DUP
<${AIR_OFF_SHA_OPEN}> OP_SPLIT OP_NIP
<${AIR_SHA_OPEN_BYTES}> OP_SPLIT OP_DROP
OP_SHA256
<0x${Buffer.from(ZEROS_SHA_OPEN_HASH).toString("hex")}>
OP_EQUAL
OP_IF
  OP_DUP
  <${AIR_OFF_HASHBIT}> OP_SPLIT OP_NIP
  <32> OP_SPLIT OP_DROP
  <0x${Buffer.from(ZEROS_C_SHA_ROOT).toString("hex")}>
  OP_EQUALVERIFY
OP_ENDIF
OP_DUP
<${AIR_OFF_DIGEST}> OP_SPLIT OP_NIP
<32> OP_SPLIT OP_DROP
<4> OP_SPLIT OP_DROP
<0x00> OP_CAT
OP_BIN2NUM
<${M31_P}> OP_MOD
OP_OVER
${extractCellAsm(18)}
OP_NUMEQUALVERIFY
OP_DUP
${extractCellAsm(23)}
OP_OVER
${extractCellAsm(24)}
OP_SWAP
<1> OP_ADD
OP_NUMEQUALVERIFY
OP_DUP
${extractCellAsm(3)}
OP_DUP
<1> OP_NUMEQUAL
OP_OVER
<2> OP_NUMEQUAL
OP_BOOLOR
OP_VERIFY
OP_OVER
${extractCellAsm(5)}
OP_TOALTSTACK
OP_TOALTSTACK
<0> OP_UTXOVALUE
<${Number(STATE_BASE_SATS)}>
OP_SUB
<${M31_P}>
OP_MOD
<0> OP_OUTPUTVALUE
<${Number(STATE_BASE_SATS)}>
OP_SUB
<${M31_P}>
OP_MOD
OP_FROMALTSTACK
OP_DUP
<1>
OP_NUMEQUAL
OP_IF
  OP_DROP
  OP_FROMALTSTACK
  OP_ROT
  ${M31_ADD}
  OP_NUMEQUALVERIFY
OP_ELSE
  OP_DROP
  OP_FROMALTSTACK
  OP_ROT
  OP_SWAP
  ${M31_SUB}
  OP_NUMEQUALVERIFY
OP_ENDIF
OP_DROP
OP_1
`;

export function compileAlgebraicCKernel(): Uint8Array {
  const bin = cashAssemblyToBin(ALGEBRAIC_C_KERNEL_ASM);
  if (typeof bin === "string") throw new Error(`algebraic-c: ${bin}`);
  return bin;
}

export function compileAlgebraicCLockP2sh32(): Uint8Array {
  return encodeLockingBytecodeP2sh32(hash256(compileAlgebraicCKernel()));
}

function pushRedeem(data: Uint8Array): Uint8Array {
  if (data.length <= 75) return Uint8Array.of(data.length, ...data);
  if (data.length <= 255) return Uint8Array.of(0x4c, data.length, ...data);
  return Uint8Array.of(0x4d, data.length & 0xff, (data.length >> 8) & 0xff, ...data);
}

export function shaCLdeUnlockingCargo(
  statement: PoolStatement,
  proof: Uint8Array | FriProof,
  hash = defaultInternalHash(),
): Uint8Array {
  const p = proof instanceof Uint8Array ? decodeFriProof(proof) : proof;
  if (p.hashBitLde) return encodeShaCLdeCargo(p.hashBitLde);
  const small = circleDomain(TRACE_LEN);
  const big = circleDomain(FRI_N);
  const mixes = shaCLdeColumn(statement, small, big, p.authMasked ? undefined : p.auth, p.shaTrace);
  const leaves = leavesFromLdeColumn(mixes);
  const qIdx = p.queries.map((q) => q.index);
  return encodeShaCLdeCargo(openShaLde(leaves, qIdx, hash));
}

export function algebraicCKernelUnlocking(_packed?: Uint8Array, cargo?: Uint8Array): Uint8Array {
  const redeem = pushRedeem(compileAlgebraicCKernel());
  if (!cargo || cargo.length === 0) return redeem;
  const push =
    cargo.length <= 75
      ? Uint8Array.of(cargo.length, ...cargo)
      : cargo.length <= 255
        ? Uint8Array.of(0x4c, cargo.length, ...cargo)
        : Uint8Array.of(0x4d, cargo.length & 0xff, (cargo.length >> 8) & 0xff, ...cargo);
  const out = new Uint8Array(push.length + redeem.length);
  out.set(push, 0);
  out.set(redeem, push.length);
  return out;
}

export function algebraicCUnlockingFromProof(
  statement: PoolStatement,
  proof: Uint8Array | FriProof,
  packed?: Uint8Array,
): Uint8Array {
  return algebraicCKernelUnlocking(packed, shaCLdeUnlockingCargo(statement, proof));
}

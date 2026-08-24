/**
 * On-chain algebraicC point checks from packed cells + pool UTXO values.
 * Reserve felts come from (UTXO value − STATE_BASE) mod M31 (TVL is public).
 * Does not evaluate R. Note Merkle / nullifier are a separate B kernel.
 */
import { cashAssemblyToBin, encodeLockingBytecodeP2sh32, hash256 } from "@bitauth/libauth";
import { AIR_OFF_DIGEST, AIR_PACKED_SIZE, extractCellAsm, packedMagicAsm } from "./air-cqz.ts";
import { M31_ADD, M31_P, M31_SUB } from "./m31-asm.ts";
import { STATE_BASE_SATS } from "../pool/state.ts";


export const ALGEBRAIC_C_KERNEL_ASM = `
<0> OP_INPUTBYTECODE
<1> OP_SPLIT OP_NIP
<2> OP_SPLIT OP_NIP
${packedMagicAsm()}
<${AIR_PACKED_SIZE}>
OP_SPLIT
OP_DROP
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
  if (typeof bin === "string") throw new Error(`algebraic-c-kernel: ${bin}`);
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

export function algebraicCKernelUnlocking(): Uint8Array {
  return pushRedeem(compileAlgebraicCKernel());
}

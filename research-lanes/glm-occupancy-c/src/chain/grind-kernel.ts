/**
 * On-chain 20-bit grind. SHA256(grindSeed || nonce || "grind") must have
 * GRIND_BITS leading zero bits. Query FS uses the same grindSeed.
 */
import { cashAssemblyToBin, encodeLockingBytecodeP2sh32, hash256 } from "@bitauth/libauth";
import { GRIND_BITS } from "../backends/circle/params.ts";
import { AIR_OFF_DIGEST, AIR_OFF_NONCE, LOAD_AIR_PACKED, grindSeedFromPackedAsm } from "./air-cqz.ts";


const extraBits = GRIND_BITS - 16;
if (extraBits < 1 || extraBits > 8) throw new Error("grind kernel expects 17..24 bits");
const thirdByteMax = 1 << (8 - extraBits);

export const GRIND_KERNEL_ASM = `
OP_TOALTSTACK
${LOAD_AIR_PACKED}
OP_DUP
<${AIR_OFF_DIGEST}> OP_SPLIT OP_NIP
<32> OP_SPLIT OP_DROP
OP_FROMALTSTACK
OP_EQUALVERIFY
${grindSeedFromPackedAsm()}
OP_OVER
<${AIR_OFF_NONCE}> OP_SPLIT OP_NIP
<4> OP_SPLIT OP_DROP
OP_CAT
<0x6772696e64>
OP_CAT
OP_SHA256
<2> OP_SPLIT
OP_SWAP
OP_SIZE
<2>
OP_EQUALVERIFY
OP_BIN2NUM
<0>
OP_NUMEQUALVERIFY
<1> OP_SPLIT
OP_DROP
<0x00>
OP_CAT
OP_BIN2NUM
<${thirdByteMax}>
OP_LESSTHAN
OP_VERIFY
OP_DROP
OP_1
`;

export function compileGrindKernel(): Uint8Array {
  const bin = cashAssemblyToBin(GRIND_KERNEL_ASM);
  if (typeof bin === "string") throw new Error(`grind-kernel: ${bin}`);
  return bin;
}

export function compileGrindLockP2sh32(): Uint8Array {
  return encodeLockingBytecodeP2sh32(hash256(compileGrindKernel()));
}

function pushRedeem(data: Uint8Array): Uint8Array {
  if (data.length <= 75) return Uint8Array.of(data.length, ...data);
  if (data.length <= 255) return Uint8Array.of(0x4c, data.length, ...data);
  return Uint8Array.of(0x4d, data.length & 0xff, (data.length >> 8) & 0xff, ...data);
}

export function grindKernelUnlocking(packed?: Uint8Array): Uint8Array {
  const redeem = pushRedeem(compileGrindKernel());
  if (!packed) return redeem;
  const digest = packed.subarray(AIR_OFF_DIGEST, AIR_OFF_DIGEST + 32);
  const push = Uint8Array.of(digest.length, ...digest);
  const out = new Uint8Array(push.length + redeem.length);
  out.set(push, 0);
  out.set(redeem, push.length);
  return out;
}

import { compileFoldKernel, foldKernelAsm } from "../src/chain/fold-kernel.ts";

const asm = foldKernelAsm(6, 0);
const k = compileFoldKernel(6, 0);
console.log(JSON.stringify({
  asmChars: asm.length,
  redeem: k.length,
  hasPaa1: asm.includes("50414131"),
  hasVanish: asm.includes("<7>"),
  hasSmul10: asm.includes("<8>"),
  tail: asm.slice(-500).replace(/\s+/g, " "),
}));

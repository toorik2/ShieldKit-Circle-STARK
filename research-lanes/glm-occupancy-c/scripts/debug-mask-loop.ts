import { cashAssemblyToBin } from "@bitauth/libauth";
import { openingMaskCoeffs, VIEWING_TAG, FRI_OPEN_MASK_TAG } from "../src/backends/circle/witness-mask.ts";
import { FELT_FROM_SHA256 } from "../src/chain/r-kernel.ts";
import { M31_MUL, M31_ADD } from "../src/chain/m31-asm.ts";
import { evaluateBch2026 } from "../src/chain/vm-verifier.ts";
import { pushData } from "../src/chain/covenant-p2s.ts";
import { concatBytes } from "../src/pool/bytes.ts";
import { add, mul } from "../src/backends/circle/m31.ts";

const commit = new Uint8Array(32).fill(7);
const prefix = concatBytes(VIEWING_TAG, commit, FRI_OPEN_MASK_TAG);
const coeffs = openingMaskCoeffs(commit, undefined, "on");
const x = 4n;
let acc = 0n;
let xp = 1n;
for (const c of coeffs) {
  acc = add(acc, mul(c, xp));
  xp = mul(xp, x);
}

const drop = cashAssemblyToBin("OP_DROP") as Uint8Array;
function run(asm: string) {
  const body = cashAssemblyToBin(asm);
  if (typeof body === "string") throw new Error(body);
  const locking = new Uint8Array(drop.length + body.length);
  locking.set(drop, 0);
  locking.set(body, drop.length);
  const dummy = new Uint8Array(3000).fill(0x11);
  const suffix = pushData(dummy);
  const inner = pushData(prefix);
  const unl = new Uint8Array(inner.length + suffix.length);
  unl.set(inner, 0);
  unl.set(suffix, inner.length);
  return evaluateBch2026(locking, unl);
}

const step0 = `
<4>
<0>
<1>
<0>
OP_4 OP_PICK
<0x00>
OP_CAT
OP_OVER
<1>
OP_NUM2BIN
OP_CAT
${FELT_FROM_SHA256}
<${coeffs[0]!.toString()}>
OP_NUMEQUALVERIFY
OP_DROP
OP_DROP
OP_DROP
OP_DROP
OP_1
`;
console.log("felt0", run(step0), "js", coeffs[0]!.toString());
console.log("poly", acc.toString(), "ncoeffs", coeffs.length);

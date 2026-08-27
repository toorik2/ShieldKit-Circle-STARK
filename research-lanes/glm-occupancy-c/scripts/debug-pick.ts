import { cashAssemblyToBin } from "@bitauth/libauth";
import { evaluateBch2026 } from "../src/chain/vm-verifier.ts";
import { pushData } from "../src/chain/covenant-p2s.ts";

const h0 = new Uint8Array(32).fill(0x11);
const h1 = new Uint8Array(32).fill(0x22);
const h2 = new Uint8Array(32).fill(0x33);

function run(name: string, asm: string, unlocking: Uint8Array) {
  const lock = cashAssemblyToBin(asm);
  if (typeof lock === "string") throw new Error(`${name} ${lock}`);
  const ev = evaluateBch2026(lock, unlocking);
  console.log(name, ev.accepted ? "ok" : ev.error);
}

const unlock = Uint8Array.of(...pushData(h0), ...pushData(h1), ...pushData(h2), 1, 0); // idx 0 as OP_0? last is idx
// unlocking: h0 h1 h2 idx=0  — idx as empty OP_0 we need a push. Use OP_0 in script instead.

run("pick0", `
OP_0
OP_DEPTH <2> OP_SUB OP_SWAP OP_SUB OP_PICK
<0x${Buffer.from(h0).toString("hex")}>
OP_EQUAL
OP_NIP OP_NIP OP_NIP
`, Uint8Array.of(...pushData(h0), ...pushData(h1), ...pushData(h2)));

run("pick1", `
<1>
OP_DEPTH <2> OP_SUB OP_SWAP OP_SUB OP_PICK
<0x${Buffer.from(h1).toString("hex")}>
OP_EQUAL
OP_NIP OP_NIP OP_NIP
`, Uint8Array.of(...pushData(h0), ...pushData(h1), ...pushData(h2)));

run("pick2", `
<2>
OP_DEPTH <2> OP_SUB OP_SWAP OP_SUB OP_PICK
<0x${Buffer.from(h2).toString("hex")}>
OP_EQUAL
OP_NIP OP_NIP OP_NIP
`, Uint8Array.of(...pushData(h0), ...pushData(h1), ...pushData(h2)));

import { cashAssemblyToBin } from "@bitauth/libauth";
import { sha256 } from "../src/pool/bytes.ts";
import { applyDeposit } from "../src/pool/transition.ts";
import { IncrementalMerkle, NullifierSet, type Note } from "../src/pool/notes.ts";
import { emptyState } from "../src/pool/state.ts";
import { proveFri, wDeposit } from "../src/backends/circle/fri.ts";
import { collectFriOpenings } from "../src/chain/fri-openings.ts";
import { buildLayerProofs, lookupTable } from "../src/chain/merkle-multiproof.ts";
import { evaluateBch2026 } from "../src/chain/vm-verifier.ts";
import { pushData } from "../src/chain/covenant-p2s.ts";

const note: Note = {
  amountSats: 8_000n,
  rho: crypto.getRandomValues(new Uint8Array(32)),
  ownerSecret: crypto.getRandomValues(new Uint8Array(32)),
};
const d = applyDeposit(
  { state: emptyState(crypto.getRandomValues(new Uint8Array(32))), notes: new IncrementalMerkle(), nullifiers: new NullifierSet() },
  note,
);
const proved = proveFri(d.statement, wDeposit(note, d.index, d.path));
const layer = buildLayerProofs(collectFriOpenings(proved))[0]!;
const o0 = layer.openings[0]!;
const bit = o0.compactPath[0]!;
const idx = o0.compactPath[1]! | (o0.compactPath[2]! << 8);
const sib = lookupTable(layer.table, idx);
const parent = sha256(new Uint8Array([...sha256(o0.left), ...sha256(o0.right)]));
function afterK(k: number): Uint8Array {
  let acc = parent;
  for (let s = 0; s < k; s += 1) {
    const b = o0.compactPath[s * 3]!;
    const i = o0.compactPath[s * 3 + 1]! | (o0.compactPath[s * 3 + 2]! << 8);
    const h = lookupTable(layer.table, i);
    acc = b === 0 ? sha256(new Uint8Array([...acc, ...h])) : sha256(new Uint8Array([...h, ...acc]));
  }
  return acc;
}
const after1 = afterK(1);

function run(name: string, asm: string, unlocking: Uint8Array) {
  const lock = cashAssemblyToBin(asm);
  if (typeof lock === "string") throw new Error(lock);
  const ev = evaluateBch2026(lock, unlocking);
  console.log(name, ev.accepted ? "ok" : ev.error);
}

const exp = `<0x${Buffer.from(after1).toString("hex")}>`;
const step33 = new Uint8Array(33);
step33[0] = bit;
step33.set(sib, 1);

run("A-33byte", `
OP_TOALTSTACK
OP_2DUP OP_SHA256 OP_SWAP OP_SHA256 OP_SWAP OP_CAT OP_SHA256
OP_FROMALTSTACK
<1> OP_SPLIT
OP_ROT OP_SWAP OP_ROT
OP_IF OP_SWAP OP_ENDIF
OP_CAT OP_SHA256
${exp}
OP_EQUAL
OP_NIP OP_NIP
`, Uint8Array.of(
  ...pushData(o0.left),
  ...pushData(o0.right),
  ...pushData(step33),
));

run("B-table-pick", `
OP_TOALTSTACK
OP_2DUP OP_SHA256 OP_SWAP OP_SHA256 OP_SWAP OP_CAT OP_SHA256
OP_FROMALTSTACK
<1> OP_SPLIT
OP_TOALTSTACK
<0x00> OP_CAT OP_BIN2NUM
<32> OP_MUL
OP_DEPTH OP_1SUB OP_PICK
OP_SWAP OP_SPLIT OP_NIP
<32> OP_SPLIT OP_DROP
OP_FROMALTSTACK
OP_IF OP_SWAP OP_ENDIF
OP_CAT OP_SHA256
${exp}
OP_EQUAL
OP_NIP OP_NIP OP_NIP
`, Uint8Array.of(
  ...pushData(layer.table),
  ...pushData(o0.left),
  ...pushData(o0.right),
  ...pushData(o0.compactPath.subarray(0, 3)),
));

run("F-bit-on-stack", `
OP_TOALTSTACK
OP_2DUP OP_SHA256 OP_SWAP OP_SHA256 OP_SWAP OP_CAT OP_SHA256
OP_FROMALTSTACK
<1> OP_SPLIT
<0x00> OP_CAT OP_BIN2NUM
<32> OP_MUL
OP_DEPTH OP_1SUB OP_PICK
OP_SWAP OP_SPLIT OP_NIP
<32> OP_SPLIT OP_DROP
OP_ROT OP_SWAP OP_ROT
OP_IF OP_SWAP OP_ENDIF
OP_CAT OP_SHA256
${exp}
OP_EQUAL
OP_NIP OP_NIP OP_NIP
`, Uint8Array.of(
  ...pushData(layer.table),
  ...pushData(o0.left),
  ...pushData(o0.right),
  ...pushData(o0.compactPath.subarray(0, 3)),
));

run("C-full-walk-pushed-root", `
OP_TOALTSTACK
OP_2DUP OP_SHA256 OP_SWAP OP_SHA256 OP_SWAP OP_CAT OP_SHA256
OP_FROMALTSTACK
OP_BEGIN
  OP_SIZE OP_0 OP_GREATERTHAN
  OP_IF
    <3> OP_SPLIT
    OP_TOALTSTACK
    <1> OP_SPLIT
    OP_TOALTSTACK
    <0x00> OP_CAT OP_BIN2NUM
    <32> OP_MUL
    OP_DEPTH OP_1SUB OP_PICK
    OP_SWAP OP_SPLIT OP_NIP
    <32> OP_SPLIT OP_DROP
    OP_FROMALTSTACK
    OP_IF OP_SWAP OP_ENDIF
    OP_CAT OP_SHA256
    OP_FROMALTSTACK
    OP_0
  OP_ELSE
    OP_DROP
    OP_1
  OP_ENDIF
OP_UNTIL
<0x${Buffer.from(proved.layerRoots[0]!).toString("hex")}>
OP_EQUAL
OP_NIP OP_NIP OP_NIP
`, Uint8Array.of(
  ...pushData(layer.table),
  ...pushData(o0.left),
  ...pushData(o0.right),
  ...pushData(o0.compactPath),
));

const stepBody = `
<3> OP_SPLIT
OP_TOALTSTACK
<1> OP_SPLIT
<0x00> OP_CAT OP_BIN2NUM
<32> OP_MUL
OP_DEPTH OP_1SUB OP_PICK
OP_SWAP OP_SPLIT OP_NIP
<32> OP_SPLIT OP_DROP
OP_ROT OP_SWAP OP_ROT
OP_IF OP_SWAP OP_ENDIF
OP_CAT OP_SHA256
OP_FROMALTSTACK
`;

run("D-unrolled-9", `
OP_TOALTSTACK
OP_2DUP OP_SHA256 OP_SWAP OP_SHA256 OP_SWAP OP_CAT OP_SHA256
OP_FROMALTSTACK
${Array.from({ length: 9 }, () => stepBody).join("\n")}
OP_DROP
<0x${Buffer.from(proved.layerRoots[0]!).toString("hex")}>
OP_EQUAL
OP_NIP OP_NIP OP_NIP
`, Uint8Array.of(
  ...pushData(layer.table),
  ...pushData(o0.left),
  ...pushData(o0.right),
  ...pushData(o0.compactPath),
));

run("E-unrolled-1", `
OP_TOALTSTACK
OP_2DUP OP_SHA256 OP_SWAP OP_SHA256 OP_SWAP OP_CAT OP_SHA256
OP_FROMALTSTACK
${stepBody}
OP_DROP
<0x${Buffer.from(after1).toString("hex")}>
OP_EQUAL
OP_NIP OP_NIP OP_NIP
`, Uint8Array.of(
  ...pushData(layer.table),
  ...pushData(o0.left),
  ...pushData(o0.right),
  ...pushData(o0.compactPath),
));

function unrolledK(k: number, expected: Uint8Array) {
  run(`U-${k}`, `
OP_TOALTSTACK
OP_2DUP OP_SHA256 OP_SWAP OP_SHA256 OP_SWAP OP_CAT OP_SHA256
OP_FROMALTSTACK
${Array.from({ length: k }, () => stepBody).join("\n")}
OP_DROP
<0x${Buffer.from(expected).toString("hex")}>
OP_EQUAL
OP_NIP OP_NIP OP_NIP
`, Uint8Array.of(
    ...pushData(layer.table),
    ...pushData(o0.left),
    ...pushData(o0.right),
    ...pushData(o0.compactPath),
  ));
}
unrolledK(1, afterK(1));
unrolledK(2, afterK(2));
unrolledK(3, afterK(3));
unrolledK(9, afterK(9));
console.log({
  bit, idx, tableLen: layer.table.length, compact: o0.compactPath.length,
  bits: [...o0.compactPath].filter((_, i) => i % 3 === 0),
  idxs: Array.from({ length: 9 }, (_, s) => o0.compactPath[s * 3 + 1]! | (o0.compactPath[s * 3 + 2]! << 8)),
});

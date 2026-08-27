/**
 * Density/size prototype: one layer-0 compact unique-table merkle kernel.
 */
import { cashAssemblyToBin, createVirtualMachineBch2026, encodeLockingBytecodeP2sh32, hash256 } from "@bitauth/libauth";
import { applyDeposit } from "../src/pool/transition.ts";
import { IncrementalMerkle, NullifierSet, type Note } from "../src/pool/notes.ts";
import { emptyState } from "../src/pool/state.ts";
import { encodeFriProof, proveFri, wDeposit } from "../src/backends/circle/fri.ts";
import { FRI_LOG_N } from "../src/backends/circle/params.ts";
import { collectFriOpenings } from "../src/chain/fri-openings.ts";
import { buildLayerProofs, layerProofBytes, walkCompact } from "../src/chain/merkle-multiproof.ts";
import { encodeAirPacked } from "../src/chain/air-cqz.ts";
import { pushData } from "../src/chain/covenant-p2s.ts";

function num(v: unknown): number {
  if (typeof v === "number") return v;
  if (typeof v === "bigint") return Number(v);
  return 0;
}

function pushScriptNumber(n: number): Uint8Array {
  if (n === 0) return Uint8Array.of(0x00);
  if (n >= 1 && n <= 16) return Uint8Array.of(0x50 + n);
  if (n < 0 || n > 127) throw new Error(`script number ${n}`);
  return Uint8Array.of(1, n);
}

const COMPACT_OPENING = `
OP_DUP
<16>
OP_GREATERTHANOREQUAL
OP_IF
  <16>
  OP_SUB
OP_ENDIF
OP_DUP
OP_0
OP_EQUAL
OP_TOALTSTACK
OP_DUP
<${FRI_LOG_N - 1}>
OP_SWAP
OP_SUB
<3>
OP_MUL
OP_2 OP_PICK
OP_SIZE
OP_NIP
OP_NUMEQUALVERIFY
OP_DUP
OP_TOALTSTACK
<32> OP_MUL
<0> OP_INPUTBYTECODE
<1> OP_SPLIT
OP_NIP
<2> OP_SPLIT
OP_NIP
OP_SWAP
OP_SPLIT
OP_NIP
<32> OP_SPLIT
OP_DROP
OP_TOALTSTACK
OP_TOALTSTACK
OP_2DUP
OP_SHA256
OP_SWAP
OP_SHA256
OP_SWAP
OP_CAT
OP_SHA256
OP_FROMALTSTACK
OP_BEGIN
  OP_SIZE
  OP_0 OP_GREATERTHAN
  OP_IF
    <3> OP_SPLIT
    OP_TOALTSTACK
    <1> OP_SPLIT
    <0x00>
    OP_CAT
    OP_BIN2NUM
    OP_DEPTH
    <2>
    OP_SUB
    OP_SWAP
    OP_SUB
    OP_PICK
    OP_ROT
    OP_SWAP
    OP_ROT
    OP_IF
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
OP_FROMALTSTACK
OP_EQUALVERIFY
OP_FROMALTSTACK
OP_DROP
OP_FROMALTSTACK
OP_DROP
OP_2DROP
`;

const KERNEL = `
OP_BEGIN
  OP_DUP
  OP_0 OP_GREATERTHAN
  OP_IF
    OP_1SUB
    OP_TOALTSTACK
    OP_TOALTSTACK
    ${COMPACT_OPENING}
    OP_FROMALTSTACK
    OP_DROP
    OP_FROMALTSTACK
    OP_0
  OP_ELSE
    OP_DROP
    OP_BEGIN
      OP_DEPTH
      OP_IF
        OP_DROP
        OP_0
      OP_ELSE
        OP_1
      OP_ENDIF
    OP_UNTIL
    OP_1
  OP_ENDIF
OP_UNTIL
OP_1
`;

const bin = cashAssemblyToBin(KERNEL);
if (typeof bin === "string") throw new Error(bin);
const lock = encodeLockingBytecodeP2sh32(hash256(bin));

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
const proof = encodeFriProof(proved);
const packed = encodeAirPacked(d.statement, proof);
const layer = buildLayerProofs(collectFriOpenings(proved))[0]!;
const sizes = layerProofBytes(layer);

const one = process.argv.includes("--one");
const parts: Uint8Array[] = [];
for (let i = 0; i < layer.table.length; i += 32) parts.push(pushData(layer.table.subarray(i, i + 32)));
const openingList = one ? layer.openings.slice(0, 1) : layer.openings;
for (const op of openingList) {
  parts.push(pushData(op.left), pushData(op.right), pushData(op.compactPath), pushScriptNumber(op.layerIndex), pushScriptNumber(op.slot));
}
parts.push(pushScriptNumber(one ? 1 : layer.openings.length));
parts.push(pushData(bin));
const unlocking = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
let o = 0;
for (const p of parts) {
  unlocking.set(p, o);
  o += p.length;
}

const vm = createVirtualMachineBch2026(true);
const sourceOutputs = [
  { lockingBytecode: Uint8Array.of(0x75, 0x51), valueSatoshis: 1000n },
  { lockingBytecode: lock, valueSatoshis: 1000n },
];
const transaction = {
  version: 2,
  locktime: 0,
  inputs: [
    {
      outpointTransactionHash: new Uint8Array(32).fill(0x22),
      outpointIndex: 0,
      sequenceNumber: 0xffffffff,
      unlockingBytecode: pushData(packed),
    },
    {
      outpointTransactionHash: new Uint8Array(32).fill(0x44),
      outpointIndex: 0,
      sequenceNumber: 0xffffffff,
      unlockingBytecode: unlocking,
    },
  ],
  outputs: [{ lockingBytecode: Uint8Array.of(0x75, 0x51), valueSatoshis: 1000n }],
};
const state = vm.evaluate({ inputIndex: 1, sourceOutputs, transaction } as never);
const ok = vm.stateSuccess(state);
const m = (state as { metrics?: Record<string, number | bigint> }).metrics ?? {};
const o0 = layer.openings[0]!;
const idx0 = o0.compactPath[1]! | (o0.compactPath[2]! << 8);
console.log(JSON.stringify({
  debug: {
    compact0: Buffer.from(o0.compactPath).toString("hex"),
    bit0: o0.compactPath[0],
    idx0,
    table0: Buffer.from(layer.table.subarray(0, 32)).toString("hex"),
    sib0: Buffer.from(layer.table.subarray(idx0 * 32, idx0 * 32 + 32)).toString("hex"),
    left: Buffer.from(o0.left).toString("hex"),
    layerIndex: o0.layerIndex,
    parentIndex: o0.parentIndex,
    walk: walkCompact(o0.left, o0.right, o0.compactPath, layer.table, proved.layerRoots[0]!),
    root: Buffer.from(proved.layerRoots[0]!).toString("hex"),
    packedRoot: Buffer.from(packed.subarray(0, 32)).toString("hex"),
    packedLen: packed.length,
  },
  layer0: sizes,
  tableHashes: layer.table.length / 32,
  openings: layer.openings.length,
  unlocking: unlocking.length,
  redeem: bin.length,
  accepted: ok === true,
  error: ok === true ? null : String(ok).slice(0, 240),
  op: num(m.operationCost),
  opMax: num(m.maximumOperationCost),
  hash: num(m.hashDigestIterations),
  hashMax: num(m.maximumHashDigestIterations),
  opPct: num(m.maximumOperationCost) ? +(100 * num(m.operationCost) / num(m.maximumOperationCost)).toFixed(1) : 0,
}, null, 2));

import { encodeFriProof, proveFri, wDeposit } from "../src/backends/circle/fri.ts";
import { applyDeposit } from "../src/pool/transition.ts";
import { IncrementalMerkle, NullifierSet, type Note } from "../src/pool/notes.ts";
import { emptyState } from "../src/pool/state.ts";
import { encodeAirPacked } from "../src/chain/air-cqz.ts";
import { collectFriOpenings, packedWithPairs } from "../src/chain/fri-openings.ts";
import { actualLayer, buildLayerProofs, encodeLayerUnlocking, pathLen, walkCompact } from "../src/chain/merkle-multiproof.ts";
import { MerkleTree } from "../src/backends/circle/merkle.ts";
import { compileFriQueryKernel, compileFriQueryLockP2sh32 } from "../src/chain/fri-kernel.ts";
import { createVirtualMachineBch2026, createTestAuthenticationProgramBch } from "@bitauth/libauth";
import { pushData } from "../src/chain/covenant-p2s.ts";

const rnd32 = () => crypto.getRandomValues(new Uint8Array(32));
const note: Note = { amountSats: 10_000n, rho: rnd32(), ownerSecret: rnd32() };
const d = applyDeposit(
  { state: emptyState(rnd32()), notes: new IncrementalMerkle(), nullifiers: new NullifierSet() },
  note,
);
const proof = proveFri(d.statement, wDeposit(note, d.index, d.path));
const openings = collectFriOpenings(proof);
const proofs = buildLayerProofs(openings);
const p1 = proofs[1]!;
function pushSizes(u: Uint8Array): number[] {
  const sizes: number[] = [];
  let i = 0;
  while (i < u.length) {
    const op = u[i]!;
    if (op === 0) {
      sizes.push(0);
      i += 1;
    } else if (op <= 75) {
      sizes.push(op);
      i += 1 + op;
    } else if (op === 0x4c) {
      const n = u[i + 1]!;
      sizes.push(n);
      i += 2 + n;
    } else if (op === 0x4d) {
      const n = u[i + 1]! | (u[i + 2]! << 8);
      sizes.push(n);
      i += 3 + n;
    } else if (op >= 0x51 && op <= 0x60) {
      sizes.push(-1);
      i += 1;
    } else {
      sizes.push(-(op));
      i += 1;
    }
  }
  return sizes;
}
console.log(JSON.stringify({
  layer: 1,
  nOpen: p1.openings.length,
  pathLen: pathLen(1),
  compact0: p1.openings[0]!.compactPath.length,
  compactLast: p1.openings[p1.openings.length - 1]!.compactPath.length,
  left0: p1.openings[0]!.left.length,
  right0: p1.openings[0]!.right.length,
  table: p1.table.length,
  redeem: compileFriQueryKernel(1).length,
}));
const packed = packedWithPairs(encodeAirPacked(d.statement, proof), proof);
const unlocking = encodeLayerUnlocking(p1, compileFriQueryKernel(1));
const sizes = pushSizes(unlocking);
console.log(JSON.stringify({
  nPushes: sizes.length,
  tail: sizes.slice(-12),
  head: sizes.slice(0, 5),
  n24: sizes.filter((s) => s === 24).length,
  n16: sizes.filter((s) => s === 16).length,
  n32: sizes.filter((s) => s === 32).length,
}));
const locking = compileFriQueryLockP2sh32(1);
const vm = createVirtualMachineBch2026(true);
const program = createTestAuthenticationProgramBch({
  lockingBytecode: locking,
  unlockingBytecode: unlocking,
  valueSatoshis: 1000n,
});
// Need input 0 packed as well — use verify with two inputs like evaluateFriQueryOpening.
const { decodeTransaction } = await import("@bitauth/libauth");
void decodeTransaction;
void packed;
void pushData;
const sourceOutputs = [
  { lockingBytecode: Uint8Array.of(0x75, 0x51), valueSatoshis: 1000n },
  { lockingBytecode: locking, valueSatoshis: 1000n },
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
const result = vm.verify({ sourceOutputs, transaction } as never);
const o0 = p1.openings[0]!;
const jsWalk = walkCompact(o0.left, o0.right, o0.compactPath, p1.table, proof.layerRoots[1]!);
const i = proof.queries[0]!.index % (1024 >> 1);
const raw = MerkleTree.verifyPairedRaw(
  o0.left,
  o0.right,
  proof.queries[0]!.index % 512,
  512,
  collectFriOpenings(proof).find((x) => actualLayer(x.layerIndex) === 1 && x.slot === 0)!.parentPath,
  proof.layerRoots[1]!,
);
let maxIdx = 0;
for (const o of p1.openings) {
  for (let s = 0; s < o.compactPath.length; s += 3) {
    const idx = o.compactPath[s + 1]! | (o.compactPath[s + 2]! << 8);
    if (idx > maxIdx) maxIdx = idx;
  }
}
console.log(JSON.stringify({
  jsWalk,
  verifyPairedRaw: raw,
  maxIdx,
  tableN: p1.table.length / 32,
  err: String(result).slice(0, 240),
}));

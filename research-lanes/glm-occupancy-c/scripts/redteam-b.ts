/**
 * Adversarial red team of the sub-100 KB envelope-B successor.
 * Every attack must be rejected by createVirtualMachineBch2026(true)
 * on the 36-orbit consensus lock. Honest control must accept.
 */
import { createVirtualMachineBch2026 } from "@bitauth/libauth";
import { applyDeposit, applyWithdraw } from "../src/pool/transition.ts";
import { IncrementalMerkle, NullifierSet, type Note } from "../src/pool/notes.ts";
import { emptyState, encodePublicPaa1, utxoValueFor } from "../src/pool/state.ts";
import { decodeFriProof, encodeFriProof, mutateTraceAndProve, proveFri, verifyFri, wWithdraw } from "../src/backends/circle/fri.ts";
import { LAB_PAYOUT_DIGEST } from "../src/chain/payout.ts";
import { compileCovenantSuccessor } from "../src/chain/covenant-spend.ts";
import { createLabWallet } from "../src/chain/wallet.ts";
import {
  AIR_OFF_NONCE,
  AIR_PACKED_SIZE,
  SLOT_KERNEL_COUNT_CONSENSUS,
  encodeAirPacked,
} from "../src/chain/air-cqz.ts";
import {
  buildPoolSuccessorTx,
  evaluateCookedT,
  evaluateCrossPacked,
  evaluateDummyKernels,
  evaluateDummyShortPath,
  evaluatePoolSuccessorVm,
  evaluateWrongFoldIndex,
} from "../src/chain/vm-verifier.ts";
import { collectFriOpenings, friShardUnlockings } from "../src/chain/fri-openings.ts";
import { buildLayerProofs, encodeLayerUnlocking } from "../src/chain/merkle-multiproof.ts";
import { compileFriQueryKernel, FRI_KERNEL_INPUTS } from "../src/chain/fri-kernel.ts";
import { foldInvsBlob, foldKernelCount, foldKernelUnlocking, foldQueriesPerKernel } from "../src/chain/fold-kernel.ts";
import { FRI_QUERIES, FRI_VERSION, GRIND_BITS, CONJECTURAL_BITS } from "../src/backends/circle/params.ts";
import { DEFAULT_INTERNAL_HASH_ID } from "../src/backends/circle/internal-hash.ts";

type Row = { name: string; want: boolean; got: boolean; error: string | null; txBytes?: number };

function firstPushBody(u: Uint8Array): { off: number; body: Uint8Array } {
  const op = u[0]!;
  if (op > 0 && op <= 75) return { off: 1, body: u.subarray(1, 1 + op) };
  if (op === 0x4c) return { off: 2, body: u.subarray(2, 2 + u[1]!) };
  if (op === 0x4d) {
    const n = u[1]! | (u[2]! << 8);
    return { off: 3, body: u.subarray(3, 3 + n) };
  }
  throw new Error(`not a push ${op}`);
}

const note: Note = {
  amountSats: 10_000n,
  rho: crypto.getRandomValues(new Uint8Array(32)),
  ownerSecret: crypto.getRandomValues(new Uint8Array(32)),
};
const d = applyDeposit(
  { state: emptyState(crypto.getRandomValues(new Uint8Array(32))), notes: new IncrementalMerkle(), nullifiers: new NullifierSet() },
  note,
);
const w = applyWithdraw(d.machine, note, d.index, LAB_PAYOUT_DIGEST, 3_000n);
const proved = proveFri(w.statement, wWithdraw(note, d.index, w.path, w.created));
const proof = encodeFriProof(proved);
const js = verifyFri(w.statement, proved);
const base = {
  oldState: w.statement.oldState,
  newState: w.statement.newState,
  proof,
  statement: w.statement,
  slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
  standard: true as const,
  note,
  change: w.created?.note,
};

const B = compileCovenantSuccessor({
  wallet: createLabWallet(),
  pool: {
    tx_hash: "11".repeat(32),
    tx_pos: 0,
    value: utxoValueFor(w.statement.oldState),
    category: new Uint8Array(32).fill(0x11),
    commitment: encodePublicPaa1(w.statement.oldState),
  },
  newState: w.statement.newState,
  proof,
  statement: w.statement,
  lockKind: "p2sh32",
  envelope: "consensus",
  slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
  note,
  change: w.created?.note,
});

const honest = evaluatePoolSuccessorVm(base);
const rows: Row[] = [
  {
    name: "honest 36-orbit B standard=true",
    want: true,
    got: honest.accepted,
    error: honest.error,
    txBytes: B.txBytes,
  },
];

function add(name: string, want: boolean, ev: { accepted: boolean; error: string | null }) {
  rows.push({ name, want, got: ev.accepted, error: ev.error });
}

add("wrong FS index (packed idx flip)", false, evaluateWrongFoldIndex(base));
add("dummy 8-leaf kernels vs honest roots", false, evaluateDummyKernels(base));
add("dummy short Merkle path", false, evaluateDummyShortPath(base));
add("cooked Newton T", false, evaluateCookedT(base));

const oneOpening = (() => {
  const proofs = buildLayerProofs(collectFriOpenings(proof));
  const shards = proofs.map((p) => {
    const thin = { ...p, openings: p.openings.slice(0, 1) };
    return encodeLayerUnlocking(thin, compileFriQueryKernel(p.layer));
  });
  return evaluatePoolSuccessorVm({ ...base, kernelUnlockings: shards });
})();
add("omit 35/36 Merkle openings (N=1 first opening)", false, oneOpening);

const oneOpeningLifo = (() => {
  const proofs = buildLayerProofs(collectFriOpenings(proof));
  const shards = proofs.map((p) => {
    const last = p.openings[p.openings.length - 1]!;
    const thin = { ...p, openings: [last] };
    return encodeLayerUnlocking(thin, compileFriQueryKernel(p.layer));
  });
  return evaluatePoolSuccessorVm({ ...base, kernelUnlockings: shards });
})();
add("omit 35/36 Merkle openings (N=1 LIFO-last / slot of last push)", false, oneOpeningLifo);

const omitSlot0 = (() => {
  const proofs = buildLayerProofs(collectFriOpenings(proof));
  const shards = proofs.map((p) => {
    const rest = p.openings.filter((o) => o.slot !== 0);
    const thin = { ...p, openings: rest.length ? rest : p.openings.slice(1) };
    return encodeLayerUnlocking(thin, compileFriQueryKernel(p.layer));
  });
  return evaluatePoolSuccessorVm({ ...base, kernelUnlockings: shards });
})();
add("omit slot-0 Merkle opening only (35 remain)", false, omitSlot0);

const cookedLeaf = (() => {
  const proofs = buildLayerProofs(collectFriOpenings(proof));
  const p0 = proofs[0]!;
  const o0 = { ...p0.openings[0]!, left: new Uint8Array(p0.openings[0]!.left) };
  o0.left[0] ^= 0xff;
  const bad = { ...p0, openings: [o0, ...p0.openings.slice(1)] };
  const shards = proofs.map((p, i) =>
    encodeLayerUnlocking(i === 0 ? bad : p, compileFriQueryKernel(p.layer)),
  );
  return evaluatePoolSuccessorVm({ ...base, kernelUnlockings: shards });
})();
add("flip L0 opened left felt (Merkle)", false, cookedLeaf);

const cookedPath = (() => {
  const proofs = buildLayerProofs(collectFriOpenings(proof));
  const p6 = proofs[6]!;
  const o0 = { ...p6.openings[0]!, compactPath: new Uint8Array(p6.openings[0]!.compactPath) };
  o0.compactPath[0] ^= 0x01;
  const bad = { ...p6, openings: [o0, ...p6.openings.slice(1)] };
  const shards = proofs.map((p, i) =>
    encodeLayerUnlocking(i === 6 ? bad : p, compileFriQueryKernel(p.layer)),
  );
  return evaluatePoolSuccessorVm({ ...base, kernelUnlockings: shards });
})();
add("flip L6 compact-path bit", false, cookedPath);

const dup36 = (() => {
  const proofs = buildLayerProofs(collectFriOpenings(proof));
  const shards = proofs.map((p) => {
    const last = p.openings[p.openings.length - 1]!;
    return encodeLayerUnlocking(
      { ...p, openings: Array.from({ length: FRI_QUERIES }, () => last) },
      compileFriQueryKernel(p.layer),
    );
  });
  return evaluatePoolSuccessorVm({ ...base, kernelUnlockings: shards });
})();
add("duplicate one opening ×36 vs 36 distinct pair groups", false, dup36);

const tableSwap = (() => {
  const proofs = buildLayerProofs(collectFriOpenings(proof));
  const p0 = proofs[0]!;
  if (p0.table.length < 64) return { accepted: true, error: "table too small to swap" };
  const table = new Uint8Array(p0.table);
  const a = table.slice(0, 32);
  table.set(table.subarray(32, 64), 0);
  table.set(a, 32);
  const shards = proofs.map((p, i) =>
    encodeLayerUnlocking(i === 0 ? { ...p, table } : p, compileFriQueryKernel(p.layer)),
  );
  return evaluatePoolSuccessorVm({ ...base, kernelUnlockings: shards });
})();
add("swap unique-table slots 0 and 1 (table-index confusion)", false, tableSwap);

const idxFfff = (() => {
  const proofs = buildLayerProofs(collectFriOpenings(proof));
  const p0 = proofs[0]!;
  const o0 = { ...p0.openings[0]!, compactPath: new Uint8Array(p0.openings[0]!.compactPath) };
  o0.compactPath[1] = 0xff;
  o0.compactPath[2] = 0xff;
  const bad = { ...p0, openings: [o0, ...p0.openings.slice(1)] };
  const shards = proofs.map((p, i) =>
    encodeLayerUnlocking(i === 0 ? bad : p, compileFriQueryKernel(p.layer)),
  );
  return evaluatePoolSuccessorVm({ ...base, kernelUnlockings: shards });
})();
add("compact-path table index 0xFFFF (PICK confusion)", false, idxFfff);

const idxZero = (() => {
  const proofs = buildLayerProofs(collectFriOpenings(proof));
  const p6 = proofs[6]!;
  const openings = p6.openings.map((o) => {
    const compactPath = new Uint8Array(o.compactPath);
    for (let s = 0; s < compactPath.length; s += 3) {
      compactPath[s + 1] = 0;
      compactPath[s + 2] = 0;
    }
    return { ...o, compactPath };
  });
  const shards = proofs.map((p, i) =>
    encodeLayerUnlocking(i === 6 ? { ...p, openings } : p, compileFriQueryKernel(p.layer)),
  );
  return evaluatePoolSuccessorVm({ ...base, kernelUnlockings: shards });
})();
add("all L6 path indices forced to table[0]", false, idxZero);

const nZero = (() => {
  const proofs = buildLayerProofs(collectFriOpenings(proof));
  const shards = proofs.map((p) =>
    encodeLayerUnlocking({ ...p, openings: [] }, compileFriQueryKernel(p.layer)),
  );
  return evaluatePoolSuccessorVm({ ...base, kernelUnlockings: shards });
})();
add("N=0 openings, full pair blob leftover", false, nZero);

const grindNonce = (() => {
  const packed = encodeAirPacked(w.statement, proof);
  packed[AIR_OFF_NONCE + 3] ^= 0x01;
  return evaluatePoolSuccessorVm({ ...base, airPacked: packed });
})();
add("grind nonce flipped (20-bit grind / FS seed)", false, grindNonce);

const crossLayer = (() => {
  const proofs = buildLayerProofs(collectFriOpenings(proof));
  const shards = proofs.map((p, i) =>
    encodeLayerUnlocking(
      i === 6 ? proofs[0]! : p,
      compileFriQueryKernel(i === 6 ? 6 : p.layer),
    ),
  );
  return evaluatePoolSuccessorVm({ ...base, kernelUnlockings: shards });
})();
add("L0 openings + L0 paths on L6 kernel (wrong depth)", false, crossLayer);

const crossPacked = (() => {
  const other = encodeAirPacked(w.statement, proof);
  other[0] ^= 0xff;
  return evaluateCrossPacked({ ...base, otherPacked: other });
})();
add("packed layerRoot[0] cooked vs honest Merkle openings", false, crossPacked);

const junkInvReal = (() => {
  const packed = encodeAirPacked(w.statement, proof);
  const nFold = foldQueriesPerKernel(SLOT_KERNEL_COUNT_CONSENSUS);
  const built = buildPoolSuccessorTx(base);
  const vm = createVirtualMachineBch2026(true);
  const foldIdx = 1 + FRI_KERNEL_INPUTS + 4;
  const honestUnlock = built.transaction.inputs[foldIdx]!.unlockingBytecode;
  const { off } = firstPushBody(honestUnlock);
  const flipped = new Uint8Array(honestUnlock);
  flipped[off + AIR_PACKED_SIZE] ^= 0xff;
  built.transaction.inputs[foldIdx] = { ...built.transaction.inputs[foldIdx]!, unlockingBytecode: flipped };
  const result = vm.verify({ sourceOutputs: built.sourceOutputs, transaction: built.transaction } as never);
  return { accepted: result === true, error: result === true ? null : String(result).slice(0, 200) };
})();
add("junk inv witness on fold kernel 0", false, junkInvReal);

const zeroInv = (() => {
  const packed = encodeAirPacked(w.statement, proof);
  const built = buildPoolSuccessorTx(base);
  const vm = createVirtualMachineBch2026(true);
  const foldIdx = 1 + FRI_KERNEL_INPUTS + 4;
  const honestUnlock = built.transaction.inputs[foldIdx]!.unlockingBytecode;
  const { off } = firstPushBody(honestUnlock);
  const zeroed = new Uint8Array(honestUnlock);
  zeroed.fill(0, off + AIR_PACKED_SIZE, off + AIR_PACKED_SIZE + 4);
  built.transaction.inputs[foldIdx] = { ...built.transaction.inputs[foldIdx]!, unlockingBytecode: zeroed };
  const result = vm.verify({ sourceOutputs: built.sourceOutputs, transaction: built.transaction } as never);
  return { accepted: result === true, error: result === true ? null : String(result).slice(0, 200) };
})();
add("zero inv witness", false, zeroInv);

const aLock = evaluatePoolSuccessorVm({ ...base, slotKernels: 4, standard: true });
rows.push({
  name: "A lock (4 slots / 1 fold) is a different object — must not be counted as B",
  want: true,
  got: aLock.accepted && foldKernelCount(4) === 1 && foldKernelCount(SLOT_KERNEL_COUNT_CONSENSUS) === 6,
  error: aLock.error,
});

const falseAir = (() => {
  const wit = wWithdraw(note, d.index, w.path, w.created);
  const bad = mutateTraceAndProve(w.statement, 0, wit);
  const raw = encodeFriProof(bad);
  const v = verifyFri(w.statement, bad, wit);
  const ev = evaluatePoolSuccessorVm({ ...base, proof: raw });
  return { js: v.ok, onchain: ev.accepted, error: ev.error };
})();
rows.push({
  name: "false AIR rejected by verifyFri AND on-chain",
  want: true,
  got: falseAir.js === false && falseAir.onchain === false,
  error: falseAir.error,
});

const pins = {
  friVersion: FRI_VERSION,
  queries: FRI_QUERIES,
  grind: GRIND_BITS,
  bits: CONJECTURAL_BITS,
  hash: DEFAULT_INTERNAL_HASH_ID,
  folds: foldKernelCount(SLOT_KERNEL_COUNT_CONSENSUS) * foldQueriesPerKernel(SLOT_KERNEL_COUNT_CONSENSUS),
  txBytes: B.txBytes,
  jsVerifyFri: js.ok,
  honestStd: honest.accepted,
};

const fails = rows.filter((r) => r.got !== r.want);
console.log(JSON.stringify({ pins, rows, failCount: fails.length, fails }, null, 2));
if (fails.length) process.exitCode = 1;
void foldInvsBlob;
void decodeFriProof;
void friShardUnlockings;
void foldKernelUnlocking;

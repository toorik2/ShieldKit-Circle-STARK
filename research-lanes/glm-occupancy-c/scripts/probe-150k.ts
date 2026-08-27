/**
 * Size/density probe for the next B construction (150k checkpoint).
 * Does not change kernels.
 */
import { createVirtualMachineBch2026, decodeAuthenticationInstructions, decodeTransaction } from "@bitauth/libauth";
import { applyDeposit, applyWithdraw } from "../src/pool/transition.ts";
import { IncrementalMerkle, NullifierSet, type Note } from "../src/pool/notes.ts";
import { emptyState, encodePublicPaa1, utxoValueFor } from "../src/pool/state.ts";
import { LAB_PAYOUT_DIGEST } from "../src/chain/payout.ts";
import { encodeFriProof, proveFri, wWithdraw } from "../src/backends/circle/fri.ts";
import { COMMITTED_LAYERS, FRI_N, FRI_QUERIES } from "../src/backends/circle/params.ts";
import { compileCovenantSuccessor } from "../src/chain/covenant-spend.ts";
import { createLabWallet } from "../src/chain/wallet.ts";
import { buildPoolSuccessorTx, evaluateFoldKernelOnly, evaluatePoolSuccessorVm } from "../src/chain/vm-verifier.ts";
import {
  SLOT_KERNEL_COUNT_CONSENSUS,
  SLOTS_PER_KERNEL,
  compileSlotsKernel,
  encodeAirPacked,
} from "../src/chain/air-cqz.ts";
import { compileFoldKernel, foldKernelCount, foldKernelUnlocking, FOLD_QUERIES_PER_KERNEL } from "../src/chain/fold-kernel.ts";
import { FRI_KERNEL_INPUTS } from "../src/chain/fri-kernel.ts";
import { collectFriOpenings } from "../src/chain/fri-openings.ts";
import { encodeSteps, parentIndexOf } from "../src/chain/vm-steps.ts";
import { compileFriQueryKernel } from "../src/chain/fri-kernel.ts";
import { lambdaFromPackedAsm, foldDefinesAsm, foldQueriesAsm } from "../src/chain/fold-asm.ts";
import { cashAssemblyToBin } from "@bitauth/libauth";

function mix() {
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
  return { note, d, w, proof, change: w.created?.note };
}

function isPush(ix: { data?: Uint8Array }): ix is { data: Uint8Array; opcode: number } {
  return ix.data instanceof Uint8Array;
}

function splitUnlocking(unlocking: Uint8Array) {
  const decoded = decodeAuthenticationInstructions(unlocking);
  const pushes = decoded.filter(isPush);
  const last = pushes.at(-1);
  const redeemBytes = last ? last.data.length : 0;
  const redeemEncoded = last
    ? last.data.length <= 75
      ? 1 + last.data.length
      : last.data.length <= 255
        ? 2 + last.data.length
        : 3 + last.data.length
    : 0;
  return { redeemBytes, otherBytes: unlocking.length - redeemEncoded, unlockingBytes: unlocking.length, nPushes: pushes.length };
}

function num(v: unknown): number {
  if (typeof v === "number") return v;
  if (typeof v === "bigint") return Number(v);
  return 0;
}

function familyOf(i: number, foldN: number, slotN: number): string {
  if (i === 0) return "pool";
  if (i >= 1 && i <= FRI_KERNEL_INPUTS) return "fri-merkle";
  const extra0 = 1 + FRI_KERNEL_INPUTS;
  if (i === extra0) return "bind-T";
  if (i === extra0 + 1) return "grind";
  if (i === extra0 + 2) return "algebraicC";
  if (i === extra0 + 3) return "note-auth";
  const fold0 = extra0 + 4;
  if (i >= fold0 && i < fold0 + foldN) return "fold";
  const slot0 = fold0 + foldN;
  if (i >= slot0 && i < slot0 + slotN) return "r-slot";
  return "other";
}

const { note, w, proof, change } = mix();
const foldN = foldKernelCount(SLOT_KERNEL_COUNT_CONSENSUS);
const slotN = SLOT_KERNEL_COUNT_CONSENSUS;

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
  change,
});

const tx = decodeTransaction(B.raw);
if (typeof tx === "string") throw new Error(tx);

const families: Record<string, { count: number; unlocking: number; redeem: number; other: number }> = {};
const rows: Array<Record<string, unknown>> = [];
for (let i = 0; i < tx.inputs.length; i += 1) {
  const u = tx.inputs[i]!.unlockingBytecode;
  const s = splitUnlocking(u);
  const fam = familyOf(i, foldN, slotN);
  const rec = (families[fam] ??= { count: 0, unlocking: 0, redeem: 0, other: 0 });
  rec.count += 1;
  rec.unlocking += s.unlockingBytes;
  rec.redeem += s.redeemBytes;
  rec.other += s.otherBytes;
  rows.push({ i, fam, ...s });
}

const packed = encodeAirPacked(w.statement, proof);
const built = buildPoolSuccessorTx({
  oldState: w.statement.oldState,
  newState: w.statement.newState,
  proof,
  statement: w.statement,
  slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
  note,
  change,
  standard: false,
});

function meter(inputIndex: number, standard: boolean) {
  const vm = createVirtualMachineBch2026(standard);
  const unlocking = built.transaction.inputs[inputIndex]!.unlockingBytecode;
  const state = vm.evaluate({
    inputIndex,
    sourceOutputs: built.sourceOutputs,
    transaction: built.transaction,
  } as never);
  const ok = vm.stateSuccess(state);
  const m = (state as { metrics?: Record<string, number | bigint> }).metrics ?? {};
  return {
    accepted: ok === true,
    error: ok === true ? null : String(ok).slice(0, 180),
    op: num(m.operationCost),
    opMax: num(m.maximumOperationCost),
    hash: num(m.hashDigestIterations),
    hashMax: num(m.maximumHashDigestIterations),
    density: num(m.densityControlLength),
    unlocking: unlocking.length,
    opPct: num(m.maximumOperationCost) ? +(100 * num(m.operationCost) / num(m.maximumOperationCost)).toFixed(1) : 0,
    hashPct: num(m.maximumHashDigestIterations) ? +(100 * num(m.hashDigestIterations) / num(m.maximumHashDigestIterations)).toFixed(1) : 0,
  };
}

const fold0 = 1 + FRI_KERNEL_INPUTS + 4;
const slot0 = fold0 + foldN;
const meters = {
  fold0: { std: meter(fold0, true), cons: meter(fold0, false) },
  foldLast: { std: meter(fold0 + foldN - 1, true), cons: meter(fold0 + foldN - 1, false) },
  slot0: { std: meter(slot0, true), cons: meter(slot0, false) },
  merkle0: { std: meter(1, true), cons: meter(1, false) },
  merkleLast: { std: meter(FRI_KERNEL_INPUTS, true), cons: meter(FRI_KERNEL_INPUTS, false) },
};

function binLen(asm: string, name: string): number {
  const b = cashAssemblyToBin(asm);
  if (typeof b === "string") throw new Error(`${name}: ${b}`);
  return b.length;
}

const openings = collectFriOpenings(proof);
const pathBytes = openings.reduce((n, o) => n + encodeSteps(parentIndexOf(o.queryIndex % (FRI_N >> o.layerIndex), FRI_N >> o.layerIndex) === o.parentIndex ? o.parentIndex : o.parentIndex, o.parentPath).length, 0);
const uniqueByLayer: number[] = [];
let uniqueSibBytes = 0;
for (let r = 0; r < COMMITTED_LAYERS; r += 1) {
  const keys = new Set<string>();
  let bytes = 0;
  for (const o of openings.filter((x) => (x.layerIndex === r || x.layerIndex === 16 + r))) {
    let idx = o.parentIndex;
    for (const sib of o.parentPath) {
      const k = `${r}:${idx}:${Buffer.from(sib).toString("hex")}`;
      if (!keys.has(k)) {
        keys.add(k);
        bytes += 33;
      }
      idx >>= 1;
    }
  }
  uniqueByLayer.push(keys.size);
  uniqueSibBytes += bytes;
}

const foldSizes = [1, 2, 3, 4, 6].map((n) => ({
  n,
  redeem: compileFoldKernel(n, 0).length,
  unlockPacked: foldKernelUnlocking(n, 0, packed).length,
  unlockBare: foldKernelUnlocking(n, 0).length,
}));

const isolated: Array<Record<string, unknown>> = [];
for (const n of [1, 2, 3, 4, 6, 9]) {
  const ev = evaluateFoldKernelOnly({
    statement: w.statement,
    proof,
    nFold: n,
    queryIndex: 0,
  });
  isolated.push({ n, accepted: ev.accepted, error: ev.error?.slice(0, 200) ?? null, unlocking: ev.unlockingBytes });
}

console.log(JSON.stringify({
  txBytes: B.txBytes,
  inputs: tx.inputs.length,
  foldN,
  slotN,
  FOLD_QUERIES_PER_KERNEL,
  SLOTS_PER_KERNEL,
  families,
  foldSizes,
  slotRedeem6: compileSlotsKernel(0, 6).length,
  friRedeem: compileFriQueryKernel().length,
  asm: {
    lambda: binLen(lambdaFromPackedAsm(), "lambda"),
    defines: binLen(foldDefinesAsm(), "defines"),
    queries1: binLen(foldQueriesAsm(1), "q1"),
    queries2: binLen(foldQueriesAsm(2), "q2"),
    queries3: binLen(foldQueriesAsm(3), "q3"),
  },
  merkle: {
    openings: openings.length,
    pathBytes,
    uniqueSibBytes,
    uniqueByLayer,
    naiveSteps: openings.reduce((n, o) => n + o.parentPath.length * 33, 0),
  },
  meters,
  isolated,
  sampleRows: rows.filter((r) => r.fam !== "fold" && r.fam !== "r-slot" || r.i === fold0 || r.i === fold0 + foldN - 1 || r.i === slot0),
}, null, 2));

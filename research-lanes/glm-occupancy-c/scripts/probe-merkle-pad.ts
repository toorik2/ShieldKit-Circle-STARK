import { createVirtualMachineBch2026, decodeTransaction } from "@bitauth/libauth";
import { applyDeposit, applyWithdraw } from "../src/pool/transition.ts";
import { IncrementalMerkle, NullifierSet, type Note } from "../src/pool/notes.ts";
import { emptyState, encodePublicPaa1, utxoValueFor } from "../src/pool/state.ts";
import { encodeFriProof, proveFri, verifyFri, wWithdraw } from "../src/backends/circle/fri.ts";
import { LAB_PAYOUT_DIGEST } from "../src/chain/payout.ts";
import { compileCovenantSuccessor } from "../src/chain/covenant-spend.ts";
import { createLabWallet } from "../src/chain/wallet.ts";
import { SLOT_KERNEL_COUNT_CONSENSUS } from "../src/chain/air-cqz.ts";
import { evaluatePoolSuccessorVm, buildPoolSuccessorTx } from "../src/chain/vm-verifier.ts";
import { FRI_KERNEL_INPUTS } from "../src/chain/fri-kernel.ts";
import { collectFriOpenings } from "../src/chain/fri-openings.ts";
import { buildLayerProofs, encodeLayerUnlocking } from "../src/chain/merkle-multiproof.ts";
import { compileFriQueryKernel } from "../src/chain/fri-kernel.ts";

function num(x: number | bigint | undefined): number {
  if (x === undefined) return 0;
  return typeof x === "bigint" ? Number(x) : x;
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
const tx = decodeTransaction(B.raw);
if (typeof tx === "string") throw new Error(tx);

const std = evaluatePoolSuccessorVm({
  oldState: w.statement.oldState,
  newState: w.statement.newState,
  proof,
  statement: w.statement,
  slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
  standard: true,
  note,
  change: w.created?.note,
});
const cons = evaluatePoolSuccessorVm({
  oldState: w.statement.oldState,
  newState: w.statement.newState,
  proof,
  statement: w.statement,
  slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
  standard: false,
  note,
  change: w.created?.note,
});

const built = buildPoolSuccessorTx({
  oldState: w.statement.oldState,
  newState: w.statement.newState,
  proof,
  statement: w.statement,
  slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
  standard: true,
  note,
  change: w.created?.note,
});
const vm = createVirtualMachineBch2026(true);
const meters = built.transaction.inputs.map((inp, i) => {
  const state = vm.evaluate({
    inputIndex: i,
    sourceOutputs: built.sourceOutputs,
    transaction: built.transaction,
  } as never);
  const ok = vm.stateSuccess(state);
  const m = (state as { metrics?: Record<string, number | bigint> }).metrics ?? {};
  return {
    i,
    unlocking: inp.unlockingBytecode.length,
    accepted: ok === true,
    error: ok === true ? null : String(ok).slice(0, 180),
    op: num(m.operationCost),
    opMax: num(m.maximumOperationCost),
    slack: num(m.maximumOperationCost) - num(m.operationCost),
    opPct: num(m.maximumOperationCost) ? +(100 * num(m.operationCost) / num(m.maximumOperationCost)).toFixed(2) : 0,
  };
});

const proofs = buildLayerProofs(collectFriOpenings(proof));
const layers = proofs.map((p, layer) => {
  const redeem = compileFriQueryKernel(layer);
  const unlocking = encodeLayerUnlocking(p, redeem);
  return {
    layer,
    table: p.table.length,
    openings: p.openings.length,
    redeem: redeem.length,
    unlocking: unlocking.length,
  };
});

console.log(JSON.stringify({
  verifyFri: verifyFri(w.statement, proved),
  txBytes: B.txBytes,
  inputCount: tx.inputs.length,
  std: { accepted: std.accepted, error: std.error?.slice(0, 280) ?? null },
  cons: { accepted: cons.accepted, error: cons.error?.slice(0, 180) ?? null },
  layers,
  meters,
}, null, 2));

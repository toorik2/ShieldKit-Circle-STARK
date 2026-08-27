import { createVirtualMachineBch2026, decodeTransaction } from "@bitauth/libauth";
import { applyDeposit, applyWithdraw } from "../src/pool/transition.ts";
import { IncrementalMerkle, NullifierSet, type Note } from "../src/pool/notes.ts";
import { emptyState, encodePublicPaa1, utxoValueFor } from "../src/pool/state.ts";
import { encodeFriProof, proveFri, wWithdraw } from "../src/backends/circle/fri.ts";
import { LAB_PAYOUT_DIGEST } from "../src/chain/payout.ts";
import { compileCovenantSuccessor } from "../src/chain/covenant-spend.ts";
import { createLabWallet } from "../src/chain/wallet.ts";
import { SLOT_KERNEL_COUNT_CONSENSUS } from "../src/chain/air-cqz.ts";
import { buildPoolSuccessorTx } from "../src/chain/vm-verifier.ts";
import { FRI_KERNEL_INPUTS } from "../src/chain/fri-kernel.ts";

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
const proof = encodeFriProof(proveFri(w.statement, wWithdraw(note, d.index, w.path, w.created)));
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
const built = buildPoolSuccessorTx({
  oldState: w.statement.oldState,
  newState: w.statement.newState,
  proof,
  statement: w.statement,
  slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
  standard: false,
  note,
  change: w.created?.note,
});
const vmFalse = createVirtualMachineBch2026(false);
const vmTrue = createVirtualMachineBch2026(true);
const merkle = Array.from({ length: FRI_KERNEL_INPUTS }, (_, i) => i + 1).map((i) => {
  const st = vmFalse.evaluate({
    inputIndex: i,
    sourceOutputs: built.sourceOutputs,
    transaction: built.transaction,
  } as never);
  const okF = vmFalse.stateSuccess(st);
  const m = (st as { metrics?: Record<string, number | bigint> }).metrics ?? {};
  const stT = vmTrue.evaluate({
    inputIndex: i,
    sourceOutputs: built.sourceOutputs,
    transaction: built.transaction,
  } as never);
  const okT = vmTrue.stateSuccess(stT);
  const mT = (stT as { metrics?: Record<string, number | bigint> }).metrics ?? {};
  const unlocking = built.transaction.inputs[i]!.unlockingBytecode.length;
  const opMaxStd = 800 * (41 + unlocking);
  return {
    i,
    unlocking,
    consOk: okF === true,
    stdOk: okT === true,
    stdErr: okT === true ? null : String(okT).slice(0, 160),
    op: num(m.operationCost),
    opMaxStd,
    slack: opMaxStd - num(m.operationCost),
    opPct: +(100 * num(m.operationCost) / opMaxStd).toFixed(2),
    hash: num(m.hashDigestIterations),
    hashMaxStd: num(mT.maximumHashDigestIterations) || Math.floor((41 + unlocking) / 2),
  };
});
console.log(JSON.stringify({
  txBytes: B.txBytes,
  merkle,
}, null, 2));

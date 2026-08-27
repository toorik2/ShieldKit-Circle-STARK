import { createVirtualMachineBch2026, decodeTransaction } from "@bitauth/libauth";
import { applyDeposit, applyWithdraw } from "../src/pool/transition.ts";
import { IncrementalMerkle, NullifierSet, type Note } from "../src/pool/notes.ts";
import { emptyState, encodePublicPaa1, utxoValueFor } from "../src/pool/state.ts";
import { encodeFriProof, proveFri, verifyFri, wWithdraw } from "../src/backends/circle/fri.ts";
import { LAB_PAYOUT_DIGEST } from "../src/chain/payout.ts";
import { compileCovenantSuccessor } from "../src/chain/covenant-spend.ts";
import { createLabWallet } from "../src/chain/wallet.ts";
import { encodeAirPacked, SLOT_KERNEL_COUNT_CONSENSUS, compileSlotsLockP2sh32, slotsKernelUnlocking, compileSlotsKernel } from "../src/chain/air-cqz.ts";
import { evaluatePoolSuccessorVm } from "../src/chain/vm-verifier.ts";
import { FOLD_QUERIES_PER_KERNEL } from "../src/chain/fold-kernel.ts";
import { FRI_KERNEL_INPUTS } from "../src/chain/fri-kernel.ts";
import { packedWithPairs } from "../src/chain/fri-openings.ts";
import { AIR_PACKED_SIZE } from "../src/chain/air-cqz.ts";

function num(x: number | bigint | undefined): number {
  if (x === undefined) return 0;
  return typeof x === "bigint" ? Number(x) : x;
}

function pushData(data: Uint8Array): Uint8Array {
  if (data.length <= 75) return Uint8Array.of(data.length, ...data);
  if (data.length <= 255) return Uint8Array.of(0x4c, data.length, ...data);
  return Uint8Array.of(0x4d, data.length & 0xff, (data.length >> 8) & 0xff, ...data);
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
const packed = encodeAirPacked(w.statement, proof);

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

function slotEval(n: number, withPacked: boolean) {
  const vm = createVirtualMachineBch2026(true);
  const lock = compileSlotsLockP2sh32(0, n);
  let unlock = slotsKernelUnlocking(0, n, packed);
  if (withPacked) {
    const body = packed.subarray(0, AIR_PACKED_SIZE);
    const push = pushData(body);
    const out = new Uint8Array(push.length + unlock.length);
    out.set(push, 0);
    out.set(unlock, push.length);
    unlock = out;
  }
  const carrier = packedWithPairs(packed, proof);
  const carrierLock = Uint8Array.of(0x75, 0x51);
  const sourceOutputs = [
    { lockingBytecode: carrierLock, valueSatoshis: 1000n },
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
        unlockingBytecode: pushData(carrier),
      },
      {
        outpointTransactionHash: new Uint8Array(32).fill(0x87),
        outpointIndex: 0,
        sequenceNumber: 0xffffffff,
        unlockingBytecode: unlock,
      },
    ],
    outputs: [{ lockingBytecode: carrierLock, valueSatoshis: 1000n }],
  };
  const state = vm.evaluate({
    inputIndex: 1,
    sourceOutputs,
    transaction,
  } as never);
  const ok = vm.stateSuccess(state);
  const m = (state as { metrics?: Record<string, number | bigint> }).metrics ?? {};
  return {
    n,
    withPacked,
    accepted: ok === true,
    error: ok === true ? null : String(ok).slice(0, 220),
    unlocking: unlock.length,
    redeem: compileSlotsKernel(0, n).length,
    op: num(m.operationCost),
    opMax: num(m.maximumOperationCost),
    slack: num(m.maximumOperationCost) - num(m.operationCost),
    opPct: num(m.maximumOperationCost) ? +(100 * num(m.operationCost) / num(m.maximumOperationCost)).toFixed(3) : 0,
  };
}

const inputs = tx.inputs.map((i, n) => ({ i: n, unlocking: i.unlockingBytecode.length }));
console.log(JSON.stringify({
  verifyFri: verifyFri(w.statement, proved),
  FOLD_QUERIES_PER_KERNEL,
  FRI_KERNEL_INPUTS,
  txBytes: B.txBytes,
  inputCount: inputs.length,
  inputs,
  std: { accepted: std.accepted, error: std.error?.slice(0, 280) ?? null },
  cons: { accepted: cons.accepted, error: cons.error?.slice(0, 280) ?? null },
  slots: [6, 9, 12].flatMap((n) => [slotEval(n, false), slotEval(n, true)]),
}, null, 2));

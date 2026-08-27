/** Measure shipped standard vs consensus successors. No keys. */
import { writeFileSync } from "node:fs";
import { applyDeposit, applyWithdraw } from "../src/pool/transition.ts";
import { IncrementalMerkle, NullifierSet, type Note } from "../src/pool/notes.ts";
import { emptyState, encodePublicPaa1, utxoValueFor } from "../src/pool/state.ts";
import { LAB_PAYOUT_DIGEST } from "../src/chain/payout.ts";
import { encodeFriProof, proveFri, wWithdraw } from "../src/backends/circle/fri.ts";
import { compileCovenantSuccessor } from "../src/chain/covenant-spend.ts";
import { createLabWallet } from "../src/chain/wallet.ts";
import {
  compileSlotsKernel,
  SLOT_KERNEL_COUNT,
  SLOT_KERNEL_COUNT_CONSENSUS,
  slotsKernelUnlocking,
} from "../src/chain/air-cqz.ts";
import { compileFoldKernel, foldKernelCount } from "../src/chain/fold-kernel.ts";
import { RELAY_STANDARD_TX_BYTES, CONSENSUS_TX_BYTES, UNLOCKING_MAX_BYTES } from "../src/chain/envelope.ts";

const outPath = process.argv[2];
if (!outPath) throw new Error("usage: measure-envelopes <out.txt>");

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
const wallet = createLabWallet();
const pool = {
  tx_hash: "11".repeat(32),
  tx_pos: 0,
  value: utxoValueFor(w.statement.oldState),
  category: new Uint8Array(32).fill(0x11),
  commitment: encodePublicPaa1(w.statement.oldState),
};

function measure(slotKernels: number) {
  return compileCovenantSuccessor({
    wallet,
    feeUtxo: { tx_hash: "33".repeat(32), tx_pos: 0, value: 250_000 },
    pool,
    newState: w.statement.newState,
    proof,
    statement: w.statement,
    lockKind: "p2sh32",
    slotKernels,
    note,
    change: w.created?.note,
  });
}

const std = measure(SLOT_KERNEL_COUNT);
const cons = measure(SLOT_KERNEL_COUNT_CONSENSUS);
const k0 = compileSlotsKernel(0);
const u0 = slotsKernelUnlocking(0);
const fold1 = compileFoldKernel(1);
const sweep: string[] = [];
for (const n of [1, 2, 3, 4, 5, 6, 8, 12, 18, 36]) {
  const m = measure(n);
  const maxUnlock = Math.max(
    m.unlockingBytes,
    ...Array.from({ length: n }, (_, i) => slotsKernelUnlocking(i).length),
  );
  sweep.push(
    `slots=${n} txBytes=${m.txBytes} poolUnlock=${m.unlockingBytes} maxSlotUnlock=${maxUnlock} stdFit=${m.txBytes <= RELAY_STANDARD_TX_BYTES} consFit=${m.txBytes <= CONSENSUS_TX_BYTES}`,
  );
}

const text = [
  `SLOT_KERNEL_COUNT=${SLOT_KERNEL_COUNT}`,
  `SLOT_KERNEL_COUNT_CONSENSUS=${SLOT_KERNEL_COUNT_CONSENSUS}`,
  `standard txBytes=${std.txBytes} unlocking=${std.unlockingBytes} limit=${RELAY_STANDARD_TX_BYTES} ok=${std.txBytes <= RELAY_STANDARD_TX_BYTES && std.unlockingBytes <= UNLOCKING_MAX_BYTES}`,
  `consensus txBytes=${cons.txBytes} unlocking=${cons.unlockingBytes} limit=${CONSENSUS_TX_BYTES} ok=${cons.txBytes <= CONSENSUS_TX_BYTES && cons.unlockingBytes <= UNLOCKING_MAX_BYTES}`,
  `slot0 redeem=${k0.length} unlocking=${u0.length} unlockingMax=${UNLOCKING_MAX_BYTES}`,
  `fold1 redeem=${fold1.length} unlockingMax=${UNLOCKING_MAX_BYTES} under10k=${fold1.length <= UNLOCKING_MAX_BYTES}`,
  `foldKernels standard=${foldKernelCount(SLOT_KERNEL_COUNT)} consensus=${foldKernelCount(SLOT_KERNEL_COUNT_CONSENSUS)}`,
  ...sweep,
].join("\n");

writeFileSync(outPath, text + "\n");
process.stdout.write(text + "\n");

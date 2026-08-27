/**
 * Write VM-measured per-input standard=true meters into checkpoint packs.
 * First-cross snapshot unlocking tables stay in inputs.json; this file records
 * createVirtualMachineBch2026(true).evaluate rows for the live successor
 * (size-gate failure does not block per-input evaluate).
 */
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { applyDeposit, applyWithdraw } from "../src/pool/transition.ts";
import { IncrementalMerkle, NullifierSet, type Note } from "../src/pool/notes.ts";
import { emptyState, encodePublicPaa1, utxoValueFor } from "../src/pool/state.ts";
import { encodeFriProof, proveFri, verifyFri, wWithdraw } from "../src/backends/circle/fri.ts";
import { LAB_PAYOUT_DIGEST } from "../src/chain/payout.ts";
import { compileCovenantSuccessor } from "../src/chain/covenant-spend.ts";
import { createLabWallet } from "../src/chain/wallet.ts";
import { SLOT_KERNEL_COUNT_CONSENSUS } from "../src/chain/air-cqz.ts";
import { evaluateSuccessorInputMeters } from "../src/chain/vm-verifier.ts";
import { FRI_VERSION, FRI_QUERIES } from "../src/backends/circle/params.ts";
import { DEFAULT_INTERNAL_HASH_ID } from "../src/backends/circle/internal-hash.ts";

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
const live = evaluateSuccessorInputMeters({
  oldState: w.statement.oldState,
  newState: w.statement.newState,
  proof,
  statement: w.statement,
  slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
  standard: true,
  note,
  change: w.created?.note,
});
const v = verifyFri(w.statement, proved);

for (const mark of [400000, 300000, 200000, 150000]) {
  const dir = join("survey/artifacts", `${mark}b`);
  const meta = JSON.parse(readFileSync(join(dir, "meta.json"), "utf8"));
  const snapInputs = JSON.parse(readFileSync(join(dir, "inputs.json"), "utf8"));
  const meters = {
    mark,
    firstCross: {
      txBytes: meta.txBytes,
      standardAccepted: meta.standardAccepted,
      standardError: meta.standardError,
      consensusAccepted: meta.consensusAccepted,
      inputs: (snapInputs.inputs as Array<{ i: number; unlocking: number }>).map((r) => ({
        i: r.i,
        unlocking: r.unlocking,
        maximumOperationCost: 800 * (41 + r.unlocking),
        maximumHashDigestIterations: Math.floor((41 + r.unlocking) / 2),
      })),
    },
    liveSuccessor: {
      txBytes: B.txBytes,
      standardTxAccepted: live.standardTxAccepted,
      standardTxError: live.standardTxError,
      verifyFri: v.ok,
      friVersion: FRI_VERSION,
      queries: FRI_QUERIES,
      hash: DEFAULT_INTERNAL_HASH_ID,
      inputs: live.inputs,
    },
  };
  writeFileSync(join(dir, "meters.json"), `${JSON.stringify(meters, null, 2)}\n`);
  console.log(JSON.stringify({
    mark,
    firstCrossTx: meta.txBytes,
    liveTx: B.txBytes,
    liveStd: live.standardTxAccepted,
    liveInputs: live.inputs.length,
    liveAllAccepted: live.inputs.every((r) => r.accepted),
  }));
}

import { applyDeposit, applyWithdraw } from "../src/pool/transition.ts";
import { IncrementalMerkle, NullifierSet, type Note } from "../src/pool/notes.ts";
import { emptyState, encodePublicPaa1, utxoValueFor } from "../src/pool/state.ts";
import { encodeFriProof, proveFri, verifyFri, wWithdraw } from "../src/backends/circle/fri.ts";
import { LAB_PAYOUT_DIGEST } from "../src/chain/payout.ts";
import { compileCovenantSuccessor } from "../src/chain/covenant-spend.ts";
import { createLabWallet } from "../src/chain/wallet.ts";
import { SLOT_KERNEL_COUNT_CONSENSUS } from "../src/chain/air-cqz.ts";
import { evaluatePoolSuccessorVm } from "../src/chain/vm-verifier.ts";
import { FRI_VERSION, FRI_QUERIES } from "../src/backends/circle/params.ts";
import { DEFAULT_INTERNAL_HASH_ID } from "../src/backends/circle/internal-hash.ts";

function one(i: number) {
  const note: Note = {
    amountSats: 10_000n + BigInt(i),
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
  const std = i === 0
    ? evaluatePoolSuccessorVm({
        oldState: w.statement.oldState,
        newState: w.statement.newState,
        proof,
        statement: w.statement,
        slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
        standard: true,
        note,
        change: w.created?.note,
      })
    : null;
  return {
    i,
    txBytes: B.txBytes,
    unlocking: B.unlockingBytes,
    verifyFri: verifyFri(w.statement, proved).ok,
    friVersion: FRI_VERSION,
    queries: FRI_QUERIES,
    hash: DEFAULT_INTERNAL_HASH_ID,
    std: std ? { accepted: std.accepted, error: std.error?.slice(0, 280) ?? null } : null,
  };
}

const rows = [0, 1, 2, 3, 4].map(one);
const sizes = rows.map((r) => r.txBytes);
console.log(JSON.stringify({
  rows,
  min: Math.min(...sizes),
  max: Math.max(...sizes),
  over: sizes.filter((s) => s > 100000).length,
}, null, 2));

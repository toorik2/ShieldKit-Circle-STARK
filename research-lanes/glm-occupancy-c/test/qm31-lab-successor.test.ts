import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { createVirtualMachineBch2026, decodeTransaction } from "@bitauth/libauth";
import { encodeFriProof, proveFri, verifyFri, wDeposit } from "../src/backends/circle/fri.ts";
import { applyDeposit } from "../src/pool/transition.ts";
import { IncrementalMerkle, NullifierSet, type Note } from "../src/pool/notes.ts";
import { emptyState, encodePublicPaa1, utxoValueFor } from "../src/pool/state.ts";
import { compileCovenantSuccessor } from "../src/chain/covenant-spend.ts";
import { SLOT_KERNEL_COUNT_CONSENSUS } from "../src/chain/air-cqz.ts";
import { createLabWallet } from "../src/chain/wallet.ts";
import { evaluatePoolSuccessorVm } from "../src/chain/vm-verifier.ts";
import { BLOWUP, FRI_QUERIES, GRIND_BITS, TRACE_LEN, VK_ID } from "../src/backends/circle/params.ts";

const rnd32 = () => crypto.getRandomValues(new Uint8Array(32));
const SLOTS = SLOT_KERNEL_COUNT_CONSENSUS;

describe("QM31 24-input B skeleton", () => {
  it(
    "honest 1-note successor: verifyFri + createVirtualMachineBch2026(true), standard bars",
    { timeout: 180_000 },
    () => {
      assert.equal(VK_ID.includes("qm31"), true);
      assert.equal(FRI_QUERIES, 36);
      assert.equal(GRIND_BITS, 20);
      assert.equal(TRACE_LEN, 64);
      assert.equal(BLOWUP, 16);
      const note: Note = { amountSats: 10_000n, rho: rnd32(), ownerSecret: rnd32() };
      const d = applyDeposit(
        { state: emptyState(rnd32()), notes: new IncrementalMerkle(), nullifiers: new NullifierSet() },
        note,
      );
      const proved = proveFri(d.statement, wDeposit(note, d.index, d.path));
      const fri = verifyFri(d.statement, proved, wDeposit(note, d.index, d.path));
      assert.equal(fri.ok, true, fri.reason ?? "verifyFri");
      const raw = encodeFriProof(proved);
      const measured = compileCovenantSuccessor({
        wallet: createLabWallet(),
        feeUtxo: { tx_hash: "33".repeat(32), tx_pos: 0, value: 1_000_000 },
        pool: {
          tx_hash: "11".repeat(32),
          tx_pos: 0,
          value: utxoValueFor(d.statement.oldState),
          category: new Uint8Array(32).fill(0x11),
          commitment: encodePublicPaa1(d.statement.oldState),
        },
        newState: d.statement.newState,
        proof: raw,
        statement: d.statement,
        lockKind: "p2sh32",
        envelope: "consensus",
        slotKernels: SLOTS,
        note,
      });
      console.log(
        `qm31 successor txBytes=${measured.txBytes} unlocking=${measured.unlockingBytes} txid=${measured.txid}`,
      );
      assert.ok(measured.txBytes <= 100000, String(measured.txBytes));
      assert.ok(measured.unlockingBytes <= 10000, String(measured.unlockingBytes));
      const tx = decodeTransaction(measured.raw);
      if (typeof tx === "string") throw new Error(tx);
      const maxUnlock = Math.max(...tx.inputs.map((i) => i.unlockingBytecode.length));
      assert.ok(maxUnlock <= 10000, String(maxUnlock));
      const vm = evaluatePoolSuccessorVm({
        oldState: d.statement.oldState,
        newState: d.statement.newState,
        proof: raw,
        statement: d.statement,
        slotKernels: SLOTS,
        standard: true,
        note,
      });
      console.log(`qm31 VM accepted=${vm.accepted} err=${vm.error}`);
      assert.equal(vm.accepted, true, vm.error ?? "vm");
      void createVirtualMachineBch2026;
    },
  );
});

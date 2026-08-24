import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { decodeTransaction } from "@bitauth/libauth";
import { SLOT_KERNEL_COUNT_CONSENSUS } from "../src/chain/air-cqz.ts";
import { compileCovenantSuccessor } from "../src/chain/covenant-spend.ts";
import { createLabWallet } from "../src/chain/wallet.ts";
import { evaluatePoolSuccessorVm } from "../src/chain/vm-verifier.ts";
import { BLOWUP, FRI_QUERIES, GRIND_BITS, TRACE_LEN, VK_ID } from "../src/backends/circle/params.ts";
import { circleFriPlugin } from "../src/backends/circle/plugin.ts";
import { runMixSuccessor } from "../src/pool/mix-successor.ts";
import { encodePublicPaa1, utxoValueFor } from "../src/pool/state.ts";

const SLOTS = SLOT_KERNEL_COUNT_CONSENSUS;

describe("QM31 18-input occupancy successor", () => {
  it(
    "mix successor: verifyFri + standard VM, tx ≤ 100000",
    { timeout: 180_000 },
    () => {
      assert.equal(VK_ID.includes("qm31"), true);
      assert.equal(FRI_QUERIES, 36);
      assert.equal(GRIND_BITS, 20);
      assert.equal(TRACE_LEN, 64);
      assert.equal(BLOWUP, 16);
      const mix = runMixSuccessor({ depositCount: 6, withdrawSats: 1_000n });
      const fri = circleFriPlugin.verify(mix.statement, mix.proof);
      assert.equal(fri.ok, true, fri.ok ? "verifyFri" : fri.reason);
      const measured = compileCovenantSuccessor({
        wallet: createLabWallet(),
        pool: {
          tx_hash: "11".repeat(32),
          tx_pos: 0,
          value: utxoValueFor(mix.oldState),
          category: new Uint8Array(32).fill(0x11),
          commitment: encodePublicPaa1(mix.oldState),
        },
        newState: mix.newState,
        proof: mix.proof,
        statement: mix.statement,
        lockKind: "p2sh32",
        envelope: "consensus",
        slotKernels: SLOTS,
        note: mix.spent.note,
        change: mix.witness.created?.note,
      });
      console.log(`qm31 mix txBytes=${measured.txBytes} unlocking=${measured.unlockingBytes}`);
      assert.ok(measured.txBytes <= 100000, String(measured.txBytes));
      const tx = decodeTransaction(measured.raw);
      if (typeof tx === "string") throw new Error(tx);
      assert.equal(tx.inputs.length, 18);
      const maxUnlock = Math.max(...tx.inputs.map((i) => i.unlockingBytecode.length));
      assert.ok(maxUnlock <= 10000, String(maxUnlock));
      const vm = evaluatePoolSuccessorVm({
        oldState: mix.oldState,
        newState: mix.newState,
        proof: mix.proof,
        statement: mix.statement,
        slotKernels: SLOTS,
        standard: true,
        note: mix.spent.note,
        change: mix.witness.created?.note,
      });
      console.log(`qm31 VM accepted=${vm.accepted} err=${vm.error}`);
      assert.equal(vm.accepted, true, vm.error ?? "vm");
    },
  );
});

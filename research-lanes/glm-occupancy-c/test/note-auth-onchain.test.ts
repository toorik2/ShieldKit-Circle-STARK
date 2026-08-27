import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { applyDeposit, applyWithdraw } from "../src/pool/transition.ts";
import { IncrementalMerkle, NullifierSet, type Note } from "../src/pool/notes.ts";
import { emptyState } from "../src/pool/state.ts";
import { LAB_PAYOUT_DIGEST } from "../src/chain/payout.ts";
import {
  compileNoteAuthKernel,
  includeNoteAuth,
  noteAuthKernelUnlocking,
  prefixExtraKernelCount,
} from "../src/chain/note-auth-kernel.ts";
import { SLOT_KERNEL_COUNT, SLOT_KERNEL_COUNT_CONSENSUS } from "../src/chain/air-cqz.ts";
import { UNLOCKING_MAX_BYTES } from "../src/chain/envelope.ts";
import { evaluateNoteAuthKernel } from "../src/chain/vm-verifier.ts";

function rnd32(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}

describe("on-chain note Merkle + nullifier + amount/auth", () => {
  it("redeem and unlocking stay under 10 KB; B-only extra kernel", () => {
    const redeem = compileNoteAuthKernel();
    assert.ok(redeem.length > 80);
    assert.ok(redeem.length <= UNLOCKING_MAX_BYTES, `note-auth redeem ${redeem.length}`);
    assert.equal(includeNoteAuth(SLOT_KERNEL_COUNT), false);
    assert.equal(includeNoteAuth(SLOT_KERNEL_COUNT_CONSENSUS), true);
    assert.equal(prefixExtraKernelCount(SLOT_KERNEL_COUNT), 3);
    assert.equal(prefixExtraKernelCount(SLOT_KERNEL_COUNT_CONSENSUS), 4);
    assert.equal(prefixExtraKernelCount(2, false), 1);
  });

  it("honest deposit append + equal nfRoots accept", () => {
    const note: Note = { amountSats: 8_000n, rho: rnd32(), ownerSecret: rnd32() };
    const d = applyDeposit(
      { state: emptyState(rnd32()), notes: new IncrementalMerkle(), nullifiers: new NullifierSet() },
      note,
    );
    const ev = evaluateNoteAuthKernel({
      oldState: d.statement.oldState,
      newState: d.statement.newState,
      action: 1n,
      note,
      spentIndex: d.index,
      spentPath: d.path,
      createdIndex: d.index,
      createdPath: d.path,
    });
    assert.equal(ev.accepted, true, ev.error ?? "honest deposit");
    assert.ok(ev.unlockingBytes <= UNLOCKING_MAX_BYTES, `unlocking ${ev.unlockingBytes}`);
  });

  it("honest withdraw spent-walk + nf chain + change append accept", () => {
    const note: Note = { amountSats: 20_000n, rho: rnd32(), ownerSecret: rnd32() };
    const d = applyDeposit(
      { state: emptyState(rnd32()), notes: new IncrementalMerkle(), nullifiers: new NullifierSet() },
      note,
    );
    const w = applyWithdraw(d.machine, note, d.index, LAB_PAYOUT_DIGEST, 7_777n);
    assert.ok(w.created);
    const ev = evaluateNoteAuthKernel({
      oldState: w.statement.oldState,
      newState: w.statement.newState,
      action: 2n,
      note,
      change: w.created.note,
      spentIndex: d.index,
      spentPath: w.path,
      createdIndex: w.created.index,
      createdPath: w.created.path,
    });
    assert.equal(ev.accepted, true, ev.error ?? "honest withdraw");
  });

  it("full withdraw (no change) accepts when noteRoots stay equal", () => {
    const note: Note = { amountSats: 5_000n, rho: rnd32(), ownerSecret: rnd32() };
    const d = applyDeposit(
      { state: emptyState(rnd32()), notes: new IncrementalMerkle(), nullifiers: new NullifierSet() },
      note,
    );
    const w = applyWithdraw(d.machine, note, d.index, LAB_PAYOUT_DIGEST, 5_000n);
    assert.equal(w.created, undefined);
    const ev = evaluateNoteAuthKernel({
      oldState: w.statement.oldState,
      newState: w.statement.newState,
      action: 2n,
      note,
      spentIndex: d.index,
      spentPath: w.path,
      createdIndex: 0,
      createdPath: [],
    });
    assert.equal(ev.accepted, true, ev.error ?? "full withdraw");
  });

  it("fake rho (wrong leaf) is rejected", () => {
    const note: Note = { amountSats: 8_000n, rho: rnd32(), ownerSecret: rnd32() };
    const d = applyDeposit(
      { state: emptyState(rnd32()), notes: new IncrementalMerkle(), nullifiers: new NullifierSet() },
      note,
    );
    const fake: Note = { ...note, rho: rnd32() };
    const ev = evaluateNoteAuthKernel({
      oldState: d.statement.oldState,
      newState: d.statement.newState,
      action: 1n,
      note: fake,
      spentIndex: d.index,
      spentPath: d.path,
      createdIndex: d.index,
      createdPath: d.path,
    });
    assert.equal(ev.accepted, false, "fake note preimage must fail the Merkle walk");
  });

  it("cooked created path is rejected", () => {
    const note: Note = { amountSats: 8_000n, rho: rnd32(), ownerSecret: rnd32() };
    const d = applyDeposit(
      { state: emptyState(rnd32()), notes: new IncrementalMerkle(), nullifiers: new NullifierSet() },
      note,
    );
    const cooked = d.path.map((p) => new Uint8Array(p));
    cooked[0]![0] ^= 0xff;
    const ev = evaluateNoteAuthKernel({
      oldState: d.statement.oldState,
      newState: d.statement.newState,
      action: 1n,
      note,
      spentIndex: d.index,
      spentPath: cooked,
      createdIndex: d.index,
      createdPath: cooked,
    });
    assert.equal(ev.accepted, false, "cooked Merkle path must fail");
  });

  it("wrong nullifier root (output NFT) is rejected", () => {
    const note: Note = { amountSats: 20_000n, rho: rnd32(), ownerSecret: rnd32() };
    const d = applyDeposit(
      { state: emptyState(rnd32()), notes: new IncrementalMerkle(), nullifiers: new NullifierSet() },
      note,
    );
    const w = applyWithdraw(d.machine, note, d.index, LAB_PAYOUT_DIGEST, 7_777n);
    const cookedNew = {
      ...w.statement.newState,
      nullifierRoot: rnd32(),
    };
    const ev = evaluateNoteAuthKernel({
      oldState: w.statement.oldState,
      newState: cookedNew,
      action: 2n,
      note,
      change: w.created?.note,
      spentIndex: d.index,
      spentPath: w.path,
      createdIndex: w.created!.index,
      createdPath: w.created!.path,
    });
    assert.equal(ev.accepted, false, "cooked nfRoot must fail the SHA-256 chain");
  });

  it("unlocking is payload + redeem, not leftover-fill cargo", () => {
    const note: Note = { amountSats: 8_000n, rho: rnd32(), ownerSecret: rnd32() };
    const d = applyDeposit(
      { state: emptyState(rnd32()), notes: new IncrementalMerkle(), nullifiers: new NullifierSet() },
      note,
    );
    const unlocking = noteAuthKernelUnlocking({
      note,
      spentIndex: d.index,
      spentPath: d.path,
      createdIndex: d.index,
      createdPath: d.path,
      poolInstanceId: d.statement.oldState.poolInstanceId,
      action: "DEPOSIT",
    });
    assert.ok(unlocking.length < 3_000, `note-auth unlocking ${unlocking.length} looks like leftover-fill`);
  });
});

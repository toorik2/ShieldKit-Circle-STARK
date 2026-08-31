import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  EDGE_HISTORY_CAPACITY,
  EdgeHistory,
  createdNoteContext,
  createdNoteRecord,
  edgeNullifier,
} from "../src/pool/edge-history.ts";
import type { Note } from "../src/pool/notes.ts";
import { SparseNullifierTree } from "../src/pool/sparse-nullifiers.ts";
import { emptyState } from "../src/pool/state.ts";
import { applyDeposit, applyWithdraw, type PoolMachine } from "../src/pool/transition.ts";
import { eq32, isZero32 } from "../src/pool/bytes.ts";

const category = new Uint8Array(32).fill(0x42);

function note(amountSats: bigint, rho: number, owner = 0x77): Note {
  return {
    amountSats,
    rho: new Uint8Array(32).fill(rho),
    ownerSecret: new Uint8Array(32).fill(owner),
  };
}

function machine(): PoolMachine {
  return {
    state: emptyState(),
    poolCategory: category,
    history: new EdgeHistory(),
    nullifiers: new SparseNullifierTree(),
  };
}

describe("v16 sealed creation log transitions", () => {
  it("creates one public edge without retaining a private tree frontier", () => {
    const deposited = applyDeposit(machine(), note(20_041n, 0x41));
    assert.equal(deposited.created.creationIndex, 0n);
    assert.equal(deposited.created.previousHead.every((byte) => byte === 0), true);
    assert.equal(deposited.machine.state.creationCount, 1n);
    assert.equal(eq32(deposited.machine.state.creationHead,
      createdNoteContext(deposited.created, category).creationHead), true);
    assert.equal(eq32(deposited.statement.createdEdge, deposited.append.edge), true);
    assert.equal(eq32(deposited.machine.state.edgeHistoryRoot, deposited.append.newRoot), true);
    assert.equal("path" in deposited.created, false, "durable note record must not own public cache data");
  });

  it("rebuilds a spend witness from public handles after deleting the cache", () => {
    let current = machine();
    const first = applyDeposit(current, note(11_000n, 0x11));
    current = first.machine;
    current = applyDeposit(current, note(12_000n, 0x12)).machine;
    current = applyDeposit(current, note(13_000n, 0x13)).machine;

    const publicEdges = current.history.publicEdges();
    const rebuilt = EdgeHistory.rebuild(publicEdges);
    const witness = rebuilt.membership(first.created.creationIndex);
    assert.equal(eq32(rebuilt.root, current.state.edgeHistoryRoot), true);
    assert.equal(eq32(witness.edge, createdNoteContext(first.created, category).edge), true);
  });

  it("full withdrawal creates no edge and partial withdrawal creates exactly one change edge", () => {
    const fullDeposit = applyDeposit(machine(), note(9_000n, 0x21));
    const full = applyWithdraw(fullDeposit.machine, fullDeposit.created, new Uint8Array(32).fill(0x70), 9_000n);
    assert.equal(full.change, undefined);
    assert.equal(full.append, undefined);
    assert.equal(isZero32(full.statement.createdEdge), true);
    assert.equal(full.machine.state.creationCount, fullDeposit.machine.state.creationCount);
    assert.equal(eq32(full.machine.state.edgeHistoryRoot, fullDeposit.machine.state.edgeHistoryRoot), true);

    const partialDeposit = applyDeposit(machine(), note(20_041n, 0x31));
    assert.throws(
      () => applyWithdraw(
        partialDeposit.machine,
        partialDeposit.created,
        new Uint8Array(32).fill(0x70),
        7_777n,
      ),
      /wallet-supplied change rho/,
    );
    const partial = applyWithdraw(
      partialDeposit.machine,
      partialDeposit.created,
      new Uint8Array(32).fill(0x70),
      7_777n,
      { changeRho: new Uint8Array(32).fill(0x43) },
    );
    assert.ok(partial.change);
    assert.ok(partial.append);
    assert.equal(partial.change.note.amountSats, 12_264n);
    assert.deepEqual(partial.change.note.ownerSecret, partialDeposit.created.note.ownerSecret);
    assert.equal(partial.machine.state.creationCount, partialDeposit.machine.state.creationCount + 1n);
    assert.equal(isZero32(partial.statement.createdEdge), false);
    assert.throws(
      () => applyWithdraw(
        partial.machine,
        partialDeposit.created,
        new Uint8Array(32).fill(0x70),
        1n,
        { changeRho: new Uint8Array(32).fill(0x44) },
      ),
      /nullifier already used/,
    );
  });

  it("gives identical note preimages distinct edges and distinct spend nullifiers", () => {
    const repeated = note(10_000n, 0x51, 0x61);
    const first = applyDeposit(machine(), repeated);
    const second = applyDeposit(first.machine, repeated);
    const firstContext = createdNoteContext(first.created, category);
    const secondContext = createdNoteContext(second.created, category);
    assert.equal(eq32(firstContext.noteCommitment, secondContext.noteCommitment), true);
    assert.equal(eq32(firstContext.edge, secondContext.edge), false);
    assert.equal(eq32(
      edgeNullifier(repeated, category, firstContext.edge),
      edgeNullifier(repeated, category, secondContext.edge),
    ), false);

    const spentFirst = applyWithdraw(second.machine, first.created, new Uint8Array(32).fill(0x70), 10_000n);
    const spentSecond = applyWithdraw(spentFirst.machine, second.created, new Uint8Array(32).fill(0x70), 10_000n);
    assert.equal(spentSecond.machine.state.reserveSats, 0n);
  });

  it("stops new creation at 2^32 while preserving the exit-only design", () => {
    assert.throws(
      () => createdNoteRecord(note(1n, 0x01), EDGE_HISTORY_CAPACITY, new Uint8Array(32)),
      /creation index out of range/,
    );
  });
});

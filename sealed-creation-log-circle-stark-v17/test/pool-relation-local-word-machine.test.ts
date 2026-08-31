import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { compilePoolLocalShaGraph, type PoolLocalShaGraph } from "../src/chain/pool-relation-local-word-machine.ts";
import {
  executeLocalShaProgram,
  localShaGeometry,
  localShaWordsFromBytes,
  verifyLocalShaExplicitAliases,
} from "../src/chain/sha256-local-word-machine.ts";
import { writeI64LE, ZERO32 } from "../src/pool/bytes.ts";
import {
  createdNoteContext,
  createdNoteRecord,
  edgeNullifier,
  EdgeHistory,
  type CreatedNoteRecord,
} from "../src/pool/edge-history.ts";
import type { Note } from "../src/pool/notes.ts";
import { wDeposit, wWithdraw } from "../src/pool/relation-witness.ts";
import { emptyState, type AnyAmountState } from "../src/pool/state.ts";
import type { PoolStatement } from "../src/pool/statement.ts";
import { SparseNullifierTree } from "../src/pool/sparse-nullifiers.ts";
import { applyDeposit, applyWithdraw } from "../src/pool/transition.ts";

const CATEGORY = new Uint8Array(32).fill(0x31);

function note(amountSats: bigint, byte: number): Note {
  return {
    amountSats,
    rho: new Uint8Array(32).fill(byte),
    ownerSecret: new Uint8Array(32).fill(byte ^ 0xff),
  };
}

function boundaryMismatches(graph: PoolLocalShaGraph, inputs = graph.inputs): readonly string[] {
  const execution = executeLocalShaProgram(graph.program, inputs);
  return graph.boundaries.flatMap((boundary) =>
    boundary.computedWires.every((wire, index) =>
      execution.wireValues[wire] === execution.wireValues[boundary.publicWires[index]!])
      ? []
      : [boundary.label]);
}

function aliasViolation(graph: PoolLocalShaGraph, inputs = graph.inputs): string | undefined {
  return verifyLocalShaExplicitAliases(
    graph.program,
    executeLocalShaProgram(graph.program, inputs),
  )?.constraint;
}

type DepositFixture = {
  readonly statement: PoolStatement;
  readonly state: AnyAmountState;
  readonly record: CreatedNoteRecord;
  readonly history: EdgeHistory;
};

function depositFixture(created: Note): DepositFixture {
  const oldState = emptyState();
  const history = new EdgeHistory();
  const record = createdNoteRecord(created, oldState.creationCount, oldState.creationHead);
  const context = createdNoteContext(record, CATEGORY);
  const append = history.append(context.edge);
  const state: AnyAmountState = {
    ...oldState,
    sequence: oldState.sequence + 1n,
    reserveSats: oldState.reserveSats + created.amountSats,
    creationCount: oldState.creationCount + 1n,
    creationHead: context.creationHead,
    edgeHistoryRoot: append.newRoot,
  };
  return {
    state,
    record,
    history,
    statement: {
      profile: "sealed-creation-log-v1",
      action: "DEPOSIT",
      publicAmountSats: created.amountSats,
      poolCategory: CATEGORY,
      oldState,
      newState: state,
      createdEdge: context.edge,
      nullifier: new Uint8Array(ZERO32),
      payoutLockingDigest: new Uint8Array(ZERO32),
    },
  };
}

function withdrawalFixture(
  deposited: DepositFixture,
  spent: Note,
  withdrawal: bigint,
  change?: Note,
): { readonly statement: PoolStatement; readonly witness: ReturnType<typeof wWithdraw> } {
  const oldState = deposited.state;
  const membership = deposited.history.membership(deposited.record.creationIndex);
  const spentContext = createdNoteContext(deposited.record, CATEGORY);
  let creationHead = oldState.creationHead;
  let edgeHistoryRoot = oldState.edgeHistoryRoot;
  let creationCount = oldState.creationCount;
  let createdEdge = new Uint8Array(ZERO32);
  if (change !== undefined) {
    const changeRecord = createdNoteRecord(change, oldState.creationCount, oldState.creationHead);
    const changeContext = createdNoteContext(changeRecord, CATEGORY);
    const append = deposited.history.append(changeContext.edge);
    creationHead = changeContext.creationHead;
    edgeHistoryRoot = append.newRoot;
    creationCount += 1n;
    createdEdge = changeContext.edge;
  }
  const newState: AnyAmountState = {
    ...oldState,
    sequence: oldState.sequence + 1n,
    reserveSats: oldState.reserveSats - withdrawal,
    creationCount,
    creationHead,
    edgeHistoryRoot,
  };
  return {
    statement: {
      profile: "sealed-creation-log-v1",
      action: "WITHDRAW",
      publicAmountSats: -withdrawal,
      poolCategory: CATEGORY,
      oldState,
      newState,
      createdEdge,
      nullifier: edgeNullifier(spent, CATEGORY, spentContext.edge),
      payoutLockingDigest: new Uint8Array(32).fill(0x70),
    },
    witness: wWithdraw({
      note: spent,
      creationIndex: deposited.record.creationIndex,
      previousHead: deposited.record.previousHead,
      path: membership.path,
    }, change),
  };
}

describe("sealed-creation-log pool graph on the local SHA word machine", () => {
  it("matches the v16 transition model end to end", () => {
    const spent = note(20_000n, 0x52);
    const deposited = applyDeposit({
      state: emptyState(),
      poolCategory: CATEGORY,
      history: new EdgeHistory(),
      nullifiers: new SparseNullifierTree(),
    }, spent);
    const depositGraph = compilePoolLocalShaGraph(deposited.statement, wDeposit(deposited.created.note));
    assert.deepEqual(boundaryMismatches(depositGraph), []);
    assert.equal(aliasViolation(depositGraph), undefined);

    const withdrawn = applyWithdraw(
      deposited.machine,
      deposited.created,
      new Uint8Array(32).fill(0x70),
      7_777n,
      { changeRho: new Uint8Array(32).fill(0x43) },
    );
    const withdrawGraph = compilePoolLocalShaGraph(withdrawn.statement, wWithdraw({
      note: withdrawn.spent.note,
      creationIndex: withdrawn.spent.creationIndex,
      previousHead: withdrawn.spent.previousHead,
      path: withdrawn.membership.path,
    }, withdrawn.change?.note));
    assert.deepEqual(boundaryMismatches(withdrawGraph), []);
    assert.equal(aliasViolation(withdrawGraph), undefined);
  });

  it("creates a deposit edge without a private append path", () => {
    const created = note(20_000n, 0x52);
    const deposited = depositFixture(created);
    const graph = compilePoolLocalShaGraph(deposited.statement, wDeposit(created));

    assert.equal(graph.compressions, 17);
    assert.equal(graph.hasChange, false);
    assert.equal(graph.amountWires.relation, "deposit-public-equality");
    assert.deepEqual(boundaryMismatches(graph), []);
    assert.equal(aliasViolation(graph), undefined);
    assert.equal(localShaGeometry(graph.program).relationRows, 65_536);
    assert.equal(graph.inputLayout.some((input) =>
      input.label.includes("sibling") || input.label.includes("direction")), false);
    assert.deepEqual(
      graph.inputLayout.filter((input) => input.visibility === "public")
        .map((input) => input.publicField),
      Array(8).fill("statement-digest"),
    );
  });

  it("binds a spend edge to one private depth-32 history path and to its nullifier", () => {
    const spent = note(20_000n, 0x52);
    const deposited = depositFixture(spent);
    const withdrawn = withdrawalFixture(deposited, spent, spent.amountSats);
    const graph = compilePoolLocalShaGraph(withdrawn.statement, withdrawn.witness);

    assert.equal(graph.compressions, 85);
    assert.equal(graph.hasChange, false);
    assert.equal(graph.amountWires.relation, "full-withdraw-public-equality");
    assert.deepEqual(boundaryMismatches(graph), []);
    assert.equal(aliasViolation(graph), undefined);
    assert.equal(graph.inputLayout.filter((input) => input.label.includes(":sibling:")).length, 32 * 8);
    assert.equal(graph.inputLayout.some((input) => input.label.includes(":direction:")), false);

    const changed = [...graph.inputs];
    const previousHead = graph.inputLayout.find((input) => input.label === "spent-creation:previous-head:word:0")!;
    changed[previousHead.input] ^= 1;
    assert.deepEqual(boundaryMismatches(graph, changed), []);
    assert.equal(aliasViolation(graph, changed), "explicit-word-alias");
  });

  it("derives Merkle directions from the same private index hashed into the edge", () => {
    const spent = note(20_000n, 0x52);
    const deposited = depositFixture(spent);
    const withdrawn = withdrawalFixture(deposited, spent, spent.amountSats);
    const graph = compilePoolLocalShaGraph(withdrawn.statement, withdrawn.witness);
    const changed = [...graph.inputs];
    const lowIndex = graph.inputLayout.find((input) => input.label === "spent-creation:index:word:1")!;
    changed[lowIndex.input] = 1;

    assert.deepEqual(boundaryMismatches(graph, changed), []);
    assert.equal(aliasViolation(graph, changed), "explicit-word-alias");
  });

  it("authenticates an honest edge at a non-zero history index", () => {
    const history = new EdgeHistory();
    let state = emptyState();
    let spent!: Note;
    let spentRecord!: CreatedNoteRecord;
    let spentEdge!: Uint8Array;
    for (let index = 0; index < 6; index += 1) {
      const created = note(20_000n + BigInt(index), 0x30 + index);
      const record = createdNoteRecord(created, state.creationCount, state.creationHead);
      const context = createdNoteContext(record, CATEGORY);
      const append = history.append(context.edge);
      state = {
        ...state,
        sequence: state.sequence + 1n,
        reserveSats: state.reserveSats + created.amountSats,
        creationCount: state.creationCount + 1n,
        creationHead: context.creationHead,
        edgeHistoryRoot: append.newRoot,
      };
      if (index === 5) {
        spent = created;
        spentRecord = record;
        spentEdge = context.edge;
      }
    }
    const membership = history.membership(spentRecord.creationIndex);
    const statement: PoolStatement = {
      profile: "sealed-creation-log-v1",
      action: "WITHDRAW",
      publicAmountSats: -spent.amountSats,
      poolCategory: CATEGORY,
      oldState: state,
      newState: {
        ...state,
        sequence: state.sequence + 1n,
        reserveSats: state.reserveSats - spent.amountSats,
      },
      createdEdge: new Uint8Array(ZERO32),
      nullifier: edgeNullifier(spent, CATEGORY, spentEdge),
      payoutLockingDigest: new Uint8Array(32).fill(0x77),
    };
    const graph = compilePoolLocalShaGraph(statement, wWithdraw({
      note: spent,
      creationIndex: spentRecord.creationIndex,
      previousHead: spentRecord.previousHead,
      path: membership.path,
    }));
    assert.deepEqual(boundaryMismatches(graph), []);
    assert.equal(aliasViolation(graph), undefined);
  });

  it("creates one change edge, reuses the owner, and conserves private amounts", () => {
    const spent = note(20_000n, 0x52);
    const deposited = depositFixture(spent);
    const withdrawal = 7_777n;
    const change = { ...note(spent.amountSats - withdrawal, 0x70), ownerSecret: spent.ownerSecret };
    const withdrawn = withdrawalFixture(deposited, spent, withdrawal, change);
    const graph = compilePoolLocalShaGraph(withdrawn.statement, withdrawn.witness);

    assert.equal(graph.compressions, 95);
    assert.equal(graph.hasChange, true);
    assert.equal(graph.amountWires.relation, "withdraw-change-sum");
    assert.deepEqual(boundaryMismatches(graph), []);
    assert.equal(aliasViolation(graph), undefined);
    assert.equal(graph.inputLayout.some((input) => input.label.startsWith("change-note:owner")), false);

    const changed = [...graph.inputs];
    const spentAmount = graph.inputLayout.find((input) => input.label === "spent-note:amount:word:0")!;
    changed[spentAmount.input] ^= 1;
    assert.deepEqual(boundaryMismatches(graph, changed), []);
    assert.equal(aliasViolation(graph, changed), "explicit-word-alias");
  });

  it("charges the public miner fee inside the withdrawal amount", () => {
    const spent = note(20_000n, 0x52);
    const deposited = depositFixture(spent);
    const payout = 7_777n;
    const minerFee = 1_234n;
    const withdrawal = payout + minerFee;
    const change = { ...note(spent.amountSats - withdrawal, 0x70), ownerSecret: spent.ownerSecret };
    const withdrawn = withdrawalFixture(deposited, spent, withdrawal, change);
    const graph = compilePoolLocalShaGraph(withdrawn.statement, withdrawn.witness, minerFee);

    assert.equal(graph.minerFeeSats, minerFee);
    assert.deepEqual(graph.inputLayout.filter((input) =>
      input.label === "relation-statement:word:3" || input.label === "relation-statement:word:4")
      .map((input) => input.value), localShaWordsFromBytes(writeI64LE(withdrawal)));
    assert.deepEqual(boundaryMismatches(graph), []);
    assert.equal(aliasViolation(graph), undefined);
  });
});

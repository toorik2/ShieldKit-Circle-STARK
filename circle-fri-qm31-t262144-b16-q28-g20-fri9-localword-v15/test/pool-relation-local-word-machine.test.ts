import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { wDeposit, wWithdraw } from "../src/pool/relation-witness.ts";
import { compilePoolLocalShaGraph, type PoolLocalShaGraph } from "../src/chain/pool-relation-local-word-machine.ts";
import {
  executeLocalShaProgram,
  localShaGeometry,
  localShaWordsFromBytes,
  verifyLocalShaExplicitAliases,
} from "../src/chain/sha256-local-word-machine.ts";
import { writeI64LE } from "../src/pool/bytes.ts";
import { IncrementalMerkle, NullifierSet, type Note } from "../src/pool/notes.ts";
import { emptyState } from "../src/pool/state.ts";
import { applyDeposit, applyWithdraw } from "../src/pool/transition.ts";

function note(amountSats: bigint, byte: number): Note {
  return {
    amountSats,
    rho: new Uint8Array(32).fill(byte),
    ownerSecret: new Uint8Array(32).fill(byte ^ 0xff),
  };
}

function machine() {
  return {
    state: emptyState(new Uint8Array(32).fill(0x31)),
    notes: new IncrementalMerkle(),
    nullifiers: new NullifierSet(),
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

describe("complete pool graph on the local SHA word machine", () => {
  it("compiles an honest deposit into one static 68-compression graph", () => {
    const n = note(20_000n, 0x52);
    const deposited = applyDeposit(machine(), n);
    const graph = compilePoolLocalShaGraph(
      deposited.statement,
      wDeposit(n, deposited.index, deposited.path),
    );

    assert.equal(graph.compressions, 68);
    assert.equal(graph.hasChange, false);
    assert.equal(graph.amountWires.relation, "deposit-public-equality");
    assert.deepEqual(boundaryMismatches(graph), []);
    assert.equal(aliasViolation(graph), undefined);
    assert.deepEqual(
      { activeRows: localShaGeometry(graph.program).activeRows, relationRows: localShaGeometry(graph.program).relationRows },
      { activeRows: 155_751, relationRows: 262_144 },
    );
    assert.equal(graph.inputLayout.filter((input) => input.visibility === "public").some((input) =>
      input.label.includes("sibling") || input.label.includes("direction")), false);
    assert.equal(graph.inputLayout.some((input) => input.label.startsWith("public:note-commitment") ||
      input.label.startsWith("public:amount-commit")), false);
  });

  it("uses the same program for different deposit witnesses and catches a changed private path", () => {
    const left = applyDeposit(machine(), note(20_000n, 0x52));
    const rightNote = note(30_000n, 0x23);
    const right = applyDeposit(machine(), rightNote);
    const leftGraph = compilePoolLocalShaGraph(left.statement, wDeposit(
      note(20_000n, 0x52),
      left.index,
      left.path,
    ));
    const rightGraph = compilePoolLocalShaGraph(right.statement, wDeposit(rightNote, right.index, right.path));
    assert.deepEqual(leftGraph.program.rows, rightGraph.program.rows);
    assert.deepEqual(leftGraph.program.copyAliases, rightGraph.program.copyAliases);
    assert.deepEqual(leftGraph.program.wordAliases, rightGraph.program.wordAliases);

    const changed = [...leftGraph.inputs];
    const sibling = leftGraph.inputLayout.find((input) => input.label === "deposit-append:sibling:0:word:0")!;
    changed[sibling.input] = (changed[sibling.input]! ^ 1) >>> 0;
    assert.notDeepEqual(boundaryMismatches(leftGraph, changed), []);
    assert.equal(aliasViolation(leftGraph, changed), "explicit-word-alias");
  });

  it("compiles withdraw-with-change into one 106-compression no-transfer graph", () => {
    const n = note(20_000n, 0x52);
    const deposited = applyDeposit(machine(), n);
    const withdrawn = applyWithdraw(
      deposited.machine,
      n,
      deposited.index,
      new Uint8Array(32).fill(0x70),
      7_777n,
    );
    const graph = compilePoolLocalShaGraph(
      withdrawn.statement,
      wWithdraw(n, deposited.index, withdrawn.path, withdrawn.created),
    );

    assert.equal(graph.compressions, 106);
    assert.equal(graph.hasChange, true);
    assert.equal(graph.amountWires.relation, "withdraw-change-sum");
    assert.deepEqual(boundaryMismatches(graph), []);
    assert.equal(aliasViolation(graph), undefined);
    assert.deepEqual(
      { activeRows: localShaGeometry(graph.program).activeRows, relationRows: localShaGeometry(graph.program).relationRows },
      { activeRows: 243_015, relationRows: 262_144 },
    );
    assert.equal(graph.inputLayout.some((input) => input.label.startsWith("change-note:owner")), false);
    assert.equal(graph.inputLayout.some((input) => input.label.startsWith("public:note-commitment") ||
      input.label.startsWith("public:amount-commit")), false);

    assert.equal(graph.inputLayout.some((input) => input.label.endsWith(":view")), false);
    const changed = [...graph.inputs];
    const spentAmount = graph.inputLayout.find((input) => input.label === "spent-note:amount:word:0")!;
    changed[spentAmount.input] ^= 1;
    assert.notDeepEqual(boundaryMismatches(graph, changed), []);
    assert.equal(aliasViolation(graph, changed), "explicit-word-alias");
  });

  it("compiles a full withdrawal into 38 compressions and binds its private amount to payout", () => {
    const n = note(20_000n, 0x52);
    const deposited = applyDeposit(machine(), n);
    const withdrawn = applyWithdraw(
      deposited.machine,
      n,
      deposited.index,
      new Uint8Array(32).fill(0x70),
      n.amountSats,
    );
    const graph = compilePoolLocalShaGraph(
      withdrawn.statement,
      wWithdraw(n, deposited.index, withdrawn.path),
    );

    assert.equal(graph.compressions, 38);
    assert.equal(graph.hasChange, false);
    assert.equal(graph.amountWires.relation, "full-withdraw-public-equality");
    assert.deepEqual(boundaryMismatches(graph), []);
    assert.equal(aliasViolation(graph), undefined);
  });

  it("charges the public miner fee to a withdrawal note, never to its payout", () => {
    const n = note(20_000n, 0x52);
    const deposited = applyDeposit(machine(), n);
    const payout = 7_777n;
    const minerFee = 1_234n;
    const withdrawal = payout + minerFee;
    const withdrawn = applyWithdraw(
      deposited.machine,
      n,
      deposited.index,
      new Uint8Array(32).fill(0x70),
      withdrawal,
    );
    const graph = compilePoolLocalShaGraph(
      withdrawn.statement,
      wWithdraw(n, deposited.index, withdrawn.path, withdrawn.created),
      minerFee,
    );
    assert.equal(graph.minerFeeSats, minerFee);
    assert.deepEqual(graph.inputLayout.filter((input) => input.publicField === "withdraw-amount")
      .map((input) => input.value), localShaWordsFromBytes(writeI64LE(withdrawal)));
    assert.deepEqual(boundaryMismatches(graph), []);
    assert.equal(aliasViolation(graph), undefined);
  });
});

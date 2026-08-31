import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { qm31, qmAdd } from "../src/backends/circle/qm31.ts";
import {
  buildPoolLocalBoundaryTrace,
  executePoolLocalShaGraph,
  poolLocalShaGeometry,
  poolLocalBoundaryPreprocessedAt,
  poolLocalShaSoundnessProjection,
  verifyPoolLocalBoundaryTrace,
} from "../src/chain/pool-relation-local-word-boundary.ts";
import { compilePoolLocalShaGraph } from "../src/chain/pool-relation-local-word-machine.ts";
import {
  createdNoteContext,
  createdNoteRecord,
  edgeNullifier,
  EdgeHistory,
} from "../src/pool/edge-history.ts";
import type { Note } from "../src/pool/notes.ts";
import { wWithdraw } from "../src/pool/relation-witness.ts";
import { emptyState, type AnyAmountState } from "../src/pool/state.ts";
import type { PoolStatement } from "../src/pool/statement.ts";

const CHALLENGES = {
  gamma: qm31(11n, 13n, 17n, 19n),
  identity: qm31(23n, 29n, 31n, 37n),
  limbs: Array.from({ length: 8 }, (_, limb) =>
    qm31(BigInt(41 + 18 * limb), BigInt(43 + 18 * limb), BigInt(47 + 18 * limb), BigInt(53 + 18 * limb))),
};

function fixture() {
  const category = new Uint8Array(32).fill(0x51);
  const spent: Note = {
    amountSats: 20_000n,
    rho: new Uint8Array(32).fill(0x52),
    ownerSecret: new Uint8Array(32).fill(0x53),
  };
  const oldEmpty = emptyState();
  const history = new EdgeHistory();
  const spentRecord = createdNoteRecord(spent, oldEmpty.creationCount, oldEmpty.creationHead);
  const spentContext = createdNoteContext(spentRecord, category);
  const depositedAppend = history.append(spentContext.edge);
  const depositedState: AnyAmountState = {
    ...oldEmpty,
    sequence: 1n,
    reserveSats: spent.amountSats,
    creationCount: 1n,
    creationHead: spentContext.creationHead,
    edgeHistoryRoot: depositedAppend.newRoot,
  };
  const membership = history.membership(spentRecord.creationIndex);
  const withdrawal = 7_777n;
  const change: Note = {
    amountSats: spent.amountSats - withdrawal,
    rho: new Uint8Array(32).fill(0x70),
    ownerSecret: spent.ownerSecret,
  };
  const changeRecord = createdNoteRecord(change, depositedState.creationCount, depositedState.creationHead);
  const changeContext = createdNoteContext(changeRecord, category);
  const changeAppend = history.append(changeContext.edge);
  const newState: AnyAmountState = {
    ...depositedState,
    sequence: 2n,
    reserveSats: depositedState.reserveSats - withdrawal,
    creationCount: 2n,
    creationHead: changeContext.creationHead,
    edgeHistoryRoot: changeAppend.newRoot,
  };
  const statement: PoolStatement = {
    profile: "sealed-creation-log-v1",
    action: "WITHDRAW",
    publicAmountSats: -withdrawal,
    poolCategory: category,
    oldState: depositedState,
    newState,
    createdEdge: changeContext.edge,
    nullifier: edgeNullifier(spent, category, spentContext.edge),
    payoutLockingDigest: new Uint8Array(32).fill(0x71),
  };
  return compilePoolLocalShaGraph(statement, wWithdraw({
    note: spent,
    creationIndex: spentRecord.creationIndex,
    previousHead: spentRecord.previousHead,
    path: membership.path,
  }, change));
}

describe("sealed-creation-log public statement boundary", () => {
  it("binds one eight-word statement digest with two quadratic LogUp columns", () => {
    const graph = fixture();
    const execution = executePoolLocalShaGraph(graph);
    const trace = buildPoolLocalBoundaryTrace(graph, execution, CHALLENGES);
    assert.equal(trace.words.length, 8);
    assert.equal(verifyPoolLocalBoundaryTrace(graph, execution, trace, CHALLENGES), undefined);
    assert.deepEqual(poolLocalShaGeometry(graph), {
      activeRows: 218165,
      relationRows: 262144,
      sealedDegreeBound: 524288,
      quotientDegreeBound: 1048576,
      ldeRows: 16777216,
      openedM31ValuesPerQuery: 537,
      directValueBytes: 62292,
      publicBoundaryPreprocessedColumns: 3,
      publicBoundaryInteractionQm31Columns: 2,
    });
    const first = trace.words[0]!;
    assert.deepEqual(poolLocalBoundaryPreprocessedAt(graph, first.row).slice(0, 2), [1n, 1n]);
    assert.equal(poolLocalBoundaryPreprocessedAt(graph, first.row).length, 3);
    assert.deepEqual(poolLocalBoundaryPreprocessedAt(graph, 0), [0n, 0n, 1n]);
    const soundness = poolLocalShaSoundnessProjection(graph, 102.41184856965779);
    assert.equal(soundness.boundaryTerms, 2_359_296);
    assert.equal(soundness.boundaryBits > 102, true);
    assert.equal(soundness.conservativeUnionBits > 101, true);
    assert.equal(soundness.meetsFloor, true);
  });

  it("rejects a changed accumulator and a changed statement-owned word", () => {
    const graph = fixture();
    const execution = executePoolLocalShaGraph(graph);
    const trace = buildPoolLocalBoundaryTrace(graph, execution, CHALLENGES);
    const global = [...trace.columns[1]];
    global[17] = qmAdd(global[17]!, qm31(1n, 0n, 0n, 0n));
    assert.equal(verifyPoolLocalBoundaryTrace(
      graph,
      execution,
      { ...trace, columns: [trace.columns[0], global] },
      CHALLENGES,
    )?.constraint, "public-boundary-global");

    const inverses = [...trace.publicInverses];
    inverses[0] = qmAdd(inverses[0]!, qm31(1n, 0n, 0n, 0n));
    assert.equal(verifyPoolLocalBoundaryTrace(
      graph,
      execution,
      { ...trace, publicInverses: inverses },
      CHALLENGES,
    )?.constraint, "public-boundary-inverse:0");

    const changedInputs = [...graph.inputs];
    const publicInput = graph.inputLayout.find((input) => input.visibility === "public")!;
    changedInputs[publicInput.input] ^= 1;
    const changedExecution = executePoolLocalShaGraph({ ...graph, inputs: changedInputs });
    assert.equal(verifyPoolLocalBoundaryTrace(
      graph,
      changedExecution,
      trace,
      CHALLENGES,
    )?.constraint, "public-boundary-access");
  });
});

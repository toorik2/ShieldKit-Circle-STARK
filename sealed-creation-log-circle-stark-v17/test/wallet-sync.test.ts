import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { EdgeHistory } from "../src/pool/edge-history.ts";
import type { Note } from "../src/pool/notes.ts";
import { SparseNullifierTree } from "../src/pool/sparse-nullifiers.ts";
import { emptyState } from "../src/pool/state.ts";
import { applyDeposit, applyWithdraw, type PoolMachine } from "../src/pool/transition.ts";
import { rebuildPublicPoolCaches, spendMembershipFromPublicHistory } from "../src/pool/wallet-sync.ts";
import { eq32 } from "../src/pool/bytes.ts";

const category = new Uint8Array(32).fill(0x42);
const owned: Note = {
  amountSats: 20_041n,
  rho: new Uint8Array(32).fill(0x41),
  ownerSecret: new Uint8Array(32).fill(0xbe),
};

function machine(): PoolMachine {
  return {
    state: emptyState(),
    poolCategory: category,
    history: new EdgeHistory(),
    nullifiers: new SparseNullifierTree(),
  };
}

describe("permissionless wallet reconstruction", () => {
  it("reconstructs current spend and nullifier witnesses from canonical public transitions", () => {
    const genesis = emptyState();
    const deposit = applyDeposit(machine(), owned);
    const withdrawal = applyWithdraw(
      deposit.machine,
      deposit.created,
      new Uint8Array(32).fill(0x70),
      7_777n,
      { changeRho: new Uint8Array(32).fill(0x43) },
    );

    const rebuilt = rebuildPublicPoolCaches(genesis, [deposit.statement, withdrawal.statement]);
    assert.equal(eq32(rebuilt.state.edgeHistoryRoot, withdrawal.machine.state.edgeHistoryRoot), true);
    assert.equal(eq32(rebuilt.state.nullifierRoot, withdrawal.machine.state.nullifierRoot), true);

    const changeWitness = spendMembershipFromPublicHistory(
      withdrawal.change!,
      category,
      rebuilt.history,
    );
    assert.equal(changeWitness.path.length, 32);
    assert.equal(changeWitness.creationIndex, withdrawal.change!.creationIndex);
  });

  it("rejects reordering and a forged public creation handle", () => {
    const genesis = emptyState();
    const first = applyDeposit(machine(), owned);
    const second = applyDeposit(first.machine, {
      ...owned,
      rho: new Uint8Array(32).fill(0x52),
    });
    assert.throws(
      () => rebuildPublicPoolCaches(genesis, [second.statement, first.statement]),
      /non-contiguous/,
    );
    const forged = {
      ...first.statement,
      createdEdge: new Uint8Array(first.statement.createdEdge).fill(0x99),
    };
    assert.throws(
      () => rebuildPublicPoolCaches(genesis, [forged]),
      /does not reconstruct PAA2/,
    );
  });
});

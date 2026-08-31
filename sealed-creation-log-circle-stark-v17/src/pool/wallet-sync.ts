import { EdgeHistory, createdNoteContext, type CreatedNoteRecord } from "./edge-history.ts";
import { SparseNullifierTree } from "./sparse-nullifiers.ts";
import type { AnyAmountState } from "./state.ts";
import type { PoolStatement } from "./statement.ts";
import type { RelationMembership } from "./relation-witness.ts";
import { eq32, isZero32 } from "./bytes.ts";

export type PublicPoolCaches = {
  readonly state: AnyAmountState;
  readonly history: EdgeHistory;
  readonly nullifiers: SparseNullifierTree;
};

function sameState(left: AnyAmountState, right: AnyAmountState): boolean {
  return left.sequence === right.sequence && left.reserveSats === right.reserveSats &&
    left.creationCount === right.creationCount && eq32(left.creationHead, right.creationHead) &&
    eq32(left.edgeHistoryRoot, right.edgeHistoryRoot) && eq32(left.nullifierRoot, right.nullifierRoot);
}

/**
 * Rebuild both disposable wallet caches from canonical, already-validated BCH
 * transitions. No note secret or private append frontier is consumed here.
 */
export function rebuildPublicPoolCaches(
  genesis: AnyAmountState,
  canonicalStatements: readonly PoolStatement[],
): PublicPoolCaches {
  const history = new EdgeHistory();
  const nullifiers = new SparseNullifierTree();
  if (genesis.creationCount !== 0n || !eq32(genesis.edgeHistoryRoot, history.root) ||
    !eq32(genesis.nullifierRoot, nullifiers.root)) {
    throw new Error("public cache rebuild requires canonical empty genesis");
  }
  let state = genesis;
  let category: Uint8Array | undefined;
  for (const statement of canonicalStatements) {
    if (!sameState(statement.oldState, state)) throw new Error("non-contiguous public transition history");
    if (category === undefined) category = statement.poolCategory;
    else if (!eq32(category, statement.poolCategory)) throw new Error("pool category changed in public history");

    if (!isZero32(statement.createdEdge)) {
      const appended = history.append(statement.createdEdge);
      if (appended.index !== statement.oldState.creationCount ||
        !eq32(appended.oldRoot, statement.oldState.edgeHistoryRoot) ||
        !eq32(appended.newRoot, statement.newState.edgeHistoryRoot)) {
        throw new Error("public creation edge does not reconstruct PAA2");
      }
    } else if (!eq32(history.root, statement.newState.edgeHistoryRoot)) {
      throw new Error("edge history changed without a public creation edge");
    }

    if (!isZero32(statement.nullifier)) {
      const inserted = nullifiers.insert(statement.nullifier);
      if (!eq32(inserted.oldRoot, statement.oldState.nullifierRoot) ||
        !eq32(inserted.newRoot, statement.newState.nullifierRoot)) {
        throw new Error("public nullifier does not reconstruct PAA2");
      }
    } else if (!eq32(nullifiers.root, statement.newState.nullifierRoot)) {
      throw new Error("nullifier root changed without a public nullifier");
    }
    state = statement.newState;
  }
  return { state, history, nullifiers };
}

/** Build the complete private spend witness from one durable note plus public cache. */
export function spendMembershipFromPublicHistory(
  owned: CreatedNoteRecord,
  poolCategory: Uint8Array,
  history: EdgeHistory,
): RelationMembership {
  const derived = createdNoteContext(owned, poolCategory);
  const membership = history.membership(owned.creationIndex);
  if (!eq32(derived.edge, membership.edge)) {
    throw new Error("owned note does not open the public edge at its creation index");
  }
  return {
    note: owned.note,
    creationIndex: owned.creationIndex,
    previousHead: owned.previousHead,
    path: membership.path,
  };
}

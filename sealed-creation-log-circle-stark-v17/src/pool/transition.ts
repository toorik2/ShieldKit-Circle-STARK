import {
  EdgeHistory,
  createdNoteContext,
  createdNoteRecord,
  edgeNullifier,
  verifyEdgeMembership,
  type CreatedNoteRecord,
  type EdgeAppendWitness,
  type EdgeMembershipWitness,
} from "./edge-history.ts";
import type { Note } from "./notes.ts";
import { SparseNullifierTree } from "./sparse-nullifiers.ts";
import { type AnyAmountState } from "./state.ts";
import type { ActionKind, PoolStatement } from "./statement.ts";
import { eq32, isZero32, ZERO32 } from "./bytes.ts";
import { hashPayoutSet, type PayoutPair } from "../chain/payout.ts";
import { splitIntoBuckets } from "./payout-buckets.ts";

/** Mutable reference model only; consensus trusts neither cache. */
export type PoolMachine = {
  state: AnyAmountState;
  /** UI-order immutable state-NFT category. */
  poolCategory: Uint8Array;
  /** Disposable cache rebuilt from public edge outputs. */
  history: EdgeHistory;
  /** Disposable cache rebuilt from public withdrawal nullifiers. */
  nullifiers: SparseNullifierTree;
};

export type DepositTransition = {
  machine: PoolMachine;
  statement: PoolStatement;
  created: CreatedNoteRecord;
  append: EdgeAppendWitness;
};

export type WithdrawTransition = {
  machine: PoolMachine;
  statement: PoolStatement;
  spent: CreatedNoteRecord;
  membership: EdgeMembershipWitness;
  nullifierPath: readonly Uint8Array[];
  change?: CreatedNoteRecord;
  append?: EdgeAppendWitness;
};

export type WithdrawOptions = {
  /** Wallet-supplied entropy. Required exactly when this withdrawal creates change. */
  readonly changeRho?: Uint8Array;
};

function assertMachine(machine: PoolMachine): void {
  if (machine.poolCategory.length !== 32) throw new Error("pool category width");
  if (machine.state.creationCount !== machine.history.count ||
    !eq32(machine.state.edgeHistoryRoot, machine.history.root)) {
    throw new Error("public edge cache does not match PAA2");
  }
  if (!eq32(machine.state.nullifierRoot, machine.nullifiers.root)) {
    throw new Error("public nullifier cache does not match PAA2");
  }
}

export function applyDeposit(machine: PoolMachine, note: Note): DepositTransition {
  assertMachine(machine);
  if (note.amountSats <= 0n) throw new Error("deposit amount must be > 0");
  const oldState = machine.state;
  const created = createdNoteRecord(note, oldState.creationCount, oldState.creationHead);
  const context = createdNoteContext(created, machine.poolCategory);
  const history = EdgeHistory.rebuild(machine.history.publicEdges());
  const append = history.append(context.edge);
  if (append.index !== oldState.creationCount || !eq32(append.oldRoot, oldState.edgeHistoryRoot)) {
    throw new Error("deposit edge append does not continue PAA2");
  }
  const newState: AnyAmountState = {
    ...oldState,
    sequence: oldState.sequence + 1n,
    reserveSats: oldState.reserveSats + note.amountSats,
    creationCount: oldState.creationCount + 1n,
    creationHead: context.creationHead,
    edgeHistoryRoot: append.newRoot,
  };
  const statement: PoolStatement = {
    profile: "sealed-creation-log-v1",
    action: "DEPOSIT",
    publicAmountSats: note.amountSats,
    poolCategory: machine.poolCategory,
    oldState,
    newState,
    createdEdge: context.edge,
    nullifier: new Uint8Array(ZERO32),
    payoutLockingDigest: new Uint8Array(ZERO32),
  };
  checkPublicTransition(statement);
  return { machine: { ...machine, state: newState, history }, statement, created, append };
}

export function applyWithdraw(
  machine: PoolMachine,
  spent: CreatedNoteRecord,
  payoutLockingDigest: Uint8Array,
  withdrawSats: bigint,
  options: WithdrawOptions = {},
): WithdrawTransition {
  assertMachine(machine);
  if (payoutLockingDigest.length !== 32) throw new Error("payout digest width");
  if (withdrawSats <= 0n) throw new Error("withdraw amount must be > 0");
  if (withdrawSats > spent.note.amountSats) throw new Error("withdraw exceeds note");
  if (withdrawSats > machine.state.reserveSats) throw new Error("withdraw exceeds pool reserve");

  const changeSats = spent.note.amountSats - withdrawSats;
  if (changeSats > 0n && options.changeRho?.length !== 32) {
    throw new Error("partial withdrawal requires a 32-byte wallet-supplied change rho");
  }
  if (changeSats === 0n && options.changeRho !== undefined) {
    throw new Error("full withdrawal must not supply change rho");
  }

  const oldState = machine.state;
  const spentContext = createdNoteContext(spent, machine.poolCategory);
  const membership = machine.history.membership(spent.creationIndex);
  if (!eq32(membership.edge, spentContext.edge) ||
    !eq32(membership.root, oldState.edgeHistoryRoot) || !verifyEdgeMembership(membership)) {
    throw new Error("note edge is not in current public history");
  }

  const nullifier = edgeNullifier(spent.note, machine.poolCategory, spentContext.edge);
  const nullifiers = machine.nullifiers.clone();
  const nullifierInsertion = nullifiers.insert(nullifier);
  if (!eq32(nullifierInsertion.oldRoot, oldState.nullifierRoot)) {
    throw new Error("nullifier insertion does not continue PAA2");
  }

  let creationCount = oldState.creationCount;
  let creationHead = oldState.creationHead;
  let edgeHistoryRoot = oldState.edgeHistoryRoot;
  let createdEdge = new Uint8Array(ZERO32);
  let change: CreatedNoteRecord | undefined;
  let append: EdgeAppendWitness | undefined;
  const history = EdgeHistory.rebuild(machine.history.publicEdges());
  if (changeSats > 0n) {
    const changeNote: Note = {
      amountSats: changeSats,
      rho: options.changeRho!,
      ownerSecret: spent.note.ownerSecret,
    };
    change = createdNoteRecord(changeNote, creationCount, creationHead);
    const context = createdNoteContext(change, machine.poolCategory);
    append = history.append(context.edge);
    if (append.index !== creationCount || !eq32(append.oldRoot, edgeHistoryRoot)) {
      throw new Error("change edge append does not continue PAA2");
    }
    creationCount += 1n;
    creationHead = context.creationHead;
    edgeHistoryRoot = append.newRoot;
    createdEdge = context.edge;
  }

  const newState: AnyAmountState = {
    ...oldState,
    sequence: oldState.sequence + 1n,
    reserveSats: oldState.reserveSats - withdrawSats,
    creationCount,
    creationHead,
    edgeHistoryRoot,
    nullifierRoot: nullifierInsertion.newRoot,
  };
  const statement: PoolStatement = {
    profile: "sealed-creation-log-v1",
    action: "WITHDRAW",
    publicAmountSats: -withdrawSats,
    poolCategory: machine.poolCategory,
    oldState,
    newState,
    createdEdge,
    nullifier,
    payoutLockingDigest,
  };
  checkPublicTransition(statement);
  return {
    machine: { ...machine, state: newState, history, nullifiers },
    statement,
    spent,
    membership,
    nullifierPath: nullifierInsertion.path,
    change,
    append,
  };
}

/** Fast withdraw snaps the public reserve decrease to the existing BCH buckets. */
export function applyWithdrawBucketed(
  machine: PoolMachine,
  spent: CreatedNoteRecord,
  payouts: PayoutPair[],
  requested: bigint,
  options: WithdrawOptions = {},
): WithdrawTransition & { slices: bigint[]; publicSats: bigint } {
  const split = splitIntoBuckets(requested > spent.note.amountSats ? spent.note.amountSats : requested);
  if (split.publicSats <= 0n) throw new Error(`withdraw ${requested} is below the smallest payout bucket`);
  const paySum = payouts.reduce((sum, payout) => sum + payout.sats, 0n);
  if (paySum !== split.publicSats || payouts.length !== split.slices.length) {
    throw new Error("bucket payout shape");
  }
  const seenLocks = new Set<string>();
  for (let index = 0; index < payouts.length; index += 1) {
    if (payouts[index]!.sats !== split.slices[index]!) throw new Error("bucket slice order");
    const key = Buffer.from(payouts[index]!.lockingBytecode).toString("hex");
    if (seenLocks.has(key)) throw new Error("payout address reuse forbidden");
    seenLocks.add(key);
  }
  return {
    ...applyWithdraw(machine, spent, hashPayoutSet(payouts), split.publicSats, options),
    slices: split.slices,
    publicSats: split.publicSats,
  };
}

export function checkPublicTransition(statement: PoolStatement): void {
  const { oldState, newState } = statement;
  if (statement.profile !== "sealed-creation-log-v1" || statement.poolCategory.length !== 32 ||
    statement.createdEdge.length !== 32 || statement.nullifier.length !== 32 ||
    statement.payoutLockingDigest.length !== 32) {
    throw new Error("v16 profile/category");
  }
  if (newState.sequence !== oldState.sequence + 1n) throw new Error("sequence");
  if (newState.reserveSats !== oldState.reserveSats + statement.publicAmountSats ||
    newState.reserveSats < 0n) {
    throw new Error("reserve");
  }
  if (statement.action === "DEPOSIT") {
    if (statement.publicAmountSats <= 0n || isZero32(statement.createdEdge) ||
      !isZero32(statement.nullifier) || !isZero32(statement.payoutLockingDigest) ||
      newState.creationCount !== oldState.creationCount + 1n ||
      !eq32(newState.nullifierRoot, oldState.nullifierRoot)) {
      throw new Error("deposit transition");
    }
  } else {
    if (statement.publicAmountSats >= 0n || isZero32(statement.nullifier) ||
      eq32(newState.nullifierRoot, oldState.nullifierRoot)) {
      throw new Error("withdraw transition");
    }
    if (isZero32(statement.createdEdge)) {
      if (newState.creationCount !== oldState.creationCount ||
        !eq32(newState.creationHead, oldState.creationHead) ||
        !eq32(newState.edgeHistoryRoot, oldState.edgeHistoryRoot)) {
        throw new Error("full withdrawal created history");
      }
    } else if (newState.creationCount !== oldState.creationCount + 1n) {
      throw new Error("change creation count");
    }
  }
}

export function actionOf(delta: bigint): ActionKind {
  if (delta === 0n) throw new Error("zero pool action");
  return delta > 0n ? "DEPOSIT" : "WITHDRAW";
}

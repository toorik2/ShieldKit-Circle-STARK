import { IncrementalMerkle, NullifierSet, commitNote, freshRho, nullifierOf, type Note } from "./notes.ts";
import { type AnyAmountState } from "./state.ts";
import type { ActionKind, PoolStatement } from "./statement.ts";
import { commitAmount, freshNetBlind } from "../amounts/hash-commit.ts";
import { isZero32, ZERO32 } from "./bytes.ts";
import { hashPayoutSet, type PayoutPair } from "../chain/payout.ts";
import { splitIntoBuckets } from "./payout-buckets.ts";

export type PoolMachine = {
  state: AnyAmountState;
  notes: IncrementalMerkle;
  nullifiers: NullifierSet;
};

export function applyDeposit(
  machine: PoolMachine,
  note: Note,
): { machine: PoolMachine; statement: PoolStatement; index: number; path: Uint8Array[] } {
  if (note.amountSats <= 0n) throw new Error("deposit amount must be > 0");
  const hash = machine.notes.hash;
  const leaf = commitNote(note, hash);
  const oldState = machine.state;
  const { index, root, path } = machine.notes.append(leaf);
  const newState: AnyAmountState = {
    ...oldState,
    sequence: oldState.sequence + 1n,
    reserveSats: oldState.reserveSats + note.amountSats,
    depositCount: oldState.depositCount + 1n,
    noteRoot: root,
  };
  const statement: PoolStatement = {
    profile: "any-amount-v0",
    action: "DEPOSIT",
    publicAmountSats: note.amountSats,
    netBlind: freshNetBlind(),
    oldState,
    newState,
    noteCommitment: leaf,
    nullifier: new Uint8Array(32),
    payoutLockingDigest: new Uint8Array(32),
    amountCommitIn: new Uint8Array(ZERO32),
    amountCommitOut: commitAmount(note.amountSats, note.rho, hash),
  };
  checkPublicTransition(statement);
  return { machine: { ...machine, state: newState }, statement, index, path };
}

export function applyWithdraw(
  machine: PoolMachine,
  note: Note,
  index: number,
  payoutLockingDigest: Uint8Array,
  withdrawSats: bigint,
): {
  machine: PoolMachine;
  statement: PoolStatement;
  change?: Note;
  changeIndex?: number;
  path: Uint8Array[];
  created?: { note: Note; index: number; path: Uint8Array[] };
} {
  if (withdrawSats <= 0n) throw new Error("withdraw amount must be > 0");
  if (withdrawSats > note.amountSats) throw new Error("withdraw exceeds note");
  const hash = machine.notes.hash;
  const leaf = commitNote(note, hash);
  const path = machine.notes.authPath(index);
  if (!IncrementalMerkle.verify(leaf, index, path, machine.state.noteRoot, hash)) {
    throw new Error("note not in tree");
  }
  const nf = nullifierOf(note, machine.state.poolInstanceId, hash);
  const oldState = machine.state;
  const nullifierRoot = machine.nullifiers.add(nf);

  let change: Note | undefined;
  let changeIndex: number | undefined;
  let created: { note: Note; index: number; path: Uint8Array[] } | undefined;
  const leftover = note.amountSats - withdrawSats;
  let noteRoot = oldState.noteRoot;
  if (leftover > 0n) {
    change = {
      amountSats: leftover,
      rho: freshRho(),
      ownerSecret: note.ownerSecret,
    };
    const inserted = machine.notes.append(commitNote(change, hash));
    noteRoot = inserted.root;
    changeIndex = inserted.index;
    created = { note: change, index: inserted.index, path: inserted.path };
  }

  const newState: AnyAmountState = {
    ...oldState,
    sequence: oldState.sequence + 1n,
    reserveSats: oldState.reserveSats - withdrawSats,
    withdrawalCount: oldState.withdrawalCount + 1n,
    noteRoot,
    nullifierRoot,
  };
  const statement: PoolStatement = {
    profile: "any-amount-v0",
    action: "WITHDRAW",
    publicAmountSats: -withdrawSats,
    netBlind: freshNetBlind(),
    oldState,
    newState,
    noteCommitment: leftover > 0n ? commitNote(change!, hash) : new Uint8Array(32),
    nullifier: nf,
    payoutLockingDigest,
    amountCommitIn: commitAmount(note.amountSats, note.rho, hash),
    amountCommitOut:
      leftover > 0n && change
        ? commitAmount(change.amountSats, change.rho, hash)
        : new Uint8Array(ZERO32),
  };
  checkPublicTransition(statement);
  return { machine: { ...machine, state: newState }, statement, change, changeIndex, path, created };
}

/**
 * Fast withdraw: snap `requested` down to payout buckets. Unbucketed dust and
 * unspent note remainder stay as one change note in the same tree.
 */
export function applyWithdrawBucketed(
  machine: PoolMachine,
  note: Note,
  index: number,
  payouts: PayoutPair[],
  requested: bigint,
): ReturnType<typeof applyWithdraw> & { slices: bigint[]; publicSats: bigint } {
  const split = splitIntoBuckets(requested > note.amountSats ? note.amountSats : requested);
  if (split.publicSats <= 0n) {
    throw new Error(`withdraw ${requested} is below the smallest payout bucket`);
  }
  const paySum = payouts.reduce((n, p) => n + p.sats, 0n);
  if (paySum !== split.publicSats) {
    throw new Error(`bucket payouts ${paySum} != snapped public ${split.publicSats}`);
  }
  if (payouts.length !== split.slices.length) {
    throw new Error("one HD/P2PKH lock per bucket slice (no address reuse)");
  }
  const seenLock = new Set<string>();
  for (let i = 0; i < payouts.length; i += 1) {
    if (payouts[i]!.sats !== split.slices[i]!) throw new Error("bucket slice order");
    const key = Buffer.from(payouts[i]!.lockingBytecode).toString("hex");
    if (seenLock.has(key)) throw new Error("payout address reuse forbidden (HD/P2PKH)");
    seenLock.add(key);
  }
  const digest = hashPayoutSet(payouts);
  const inner = applyWithdraw(machine, note, index, digest, split.publicSats);
  return { ...inner, slices: split.slices, publicSats: split.publicSats };
}

export function checkPublicTransition(s: PoolStatement): void {
  if (s.oldState.poolInstanceId.some((b, i) => b !== s.newState.poolInstanceId[i])) {
    throw new Error("poolInstanceId mutated");
  }
  if (s.newState.sequence !== s.oldState.sequence + 1n) throw new Error("sequence");
  const expectedReserve = s.oldState.reserveSats + s.publicAmountSats;
  if (s.newState.reserveSats !== expectedReserve) throw new Error("reserve");
  if (s.action === "DEPOSIT") {
    if (s.publicAmountSats <= 0n) throw new Error("deposit delta");
    if (s.newState.depositCount !== s.oldState.depositCount + 1n) throw new Error("depositCount");
  } else {
    if (s.publicAmountSats >= 0n) throw new Error("withdraw delta");
    if (s.newState.withdrawalCount !== s.oldState.withdrawalCount + 1n) {
      throw new Error("withdrawalCount");
    }
  }
  if (s.newState.reserveSats < 0n) throw new Error("over-withdraw");
  if (s.netBlind.length !== 32) throw new Error("net blind width");
  if (s.amountCommitIn.length !== 32 || s.amountCommitOut.length !== 32) {
    throw new Error("amount commit width");
  }
  if (s.action === "DEPOSIT" && isZero32(s.amountCommitOut)) {
    throw new Error("deposit amount commit");
  }
  if (s.action === "WITHDRAW" && isZero32(s.amountCommitIn)) {
    throw new Error("withdraw amount commit");
  }
}

export type BatchExitPayout = {
  sats: bigint;
  lockingBytecode: Uint8Array;
};

export type BatchExitItem = {
  note: Note;
  index: number;
  /** Must equal the note (full exit) so noteRoot stays put and one-auth FRI still type-checks. */
  withdrawSats: bigint;
  payoutLocking: Uint8Array;
};

/**
 * One successor, many notes. Sequence +1 once. Each payout ≤ that note.
 * Sum(payouts) = −publicAmount = pool UTXO drop. Cannot spend another's note
 * or more than the reserve.
 */
export function applyBatchExit(
  machine: PoolMachine,
  items: BatchExitItem[],
): {
  machine: PoolMachine;
  statement: PoolStatement;
  payouts: BatchExitPayout[];
  spent: Array<{ note: Note; index: number; path: Uint8Array[]; nullifier: Uint8Array }>;
} {
  if (items.length < 1) throw new Error("batch-exit needs at least one note");
  const hash = machine.notes.hash;
  const oldState = machine.state;
  const spent: Array<{ note: Note; index: number; path: Uint8Array[]; nullifier: Uint8Array }> = [];
  const payouts: BatchExitPayout[] = [];
  let reserve = oldState.reserveSats;
  for (const item of items) {
    if (item.withdrawSats <= 0n) throw new Error("batch-exit amount must be > 0");
    if (item.withdrawSats !== item.note.amountSats) {
      throw new Error("batch-exit is full-note only (partial would mint change)");
    }
    if (item.payoutLocking.length === 0) throw new Error("batch-exit payout locking required");
    const leaf = commitNote(item.note, hash);
    const path = machine.notes.authPath(item.index);
    if (!IncrementalMerkle.verify(leaf, item.index, path, machine.state.noteRoot, hash)) {
      throw new Error("note not in tree");
    }
    const nf = nullifierOf(item.note, oldState.poolInstanceId, hash);
    machine.nullifiers.add(nf);
    reserve -= item.withdrawSats;
    if (reserve < 0n) throw new Error("over-withdraw");
    spent.push({ note: item.note, index: item.index, path, nullifier: nf });
    payouts.push({ sats: item.withdrawSats, lockingBytecode: item.payoutLocking });
  }
  const sum = payouts.reduce((n, p) => n + p.sats, 0n);
  const first = spent[0]!;
  const newState: AnyAmountState = {
    ...oldState,
    sequence: oldState.sequence + 1n,
    reserveSats: reserve,
    withdrawalCount: oldState.withdrawalCount + BigInt(items.length),
    noteRoot: oldState.noteRoot,
    nullifierRoot: machine.nullifiers.root,
  };
  const statement: PoolStatement = {
    profile: "any-amount-v0",
    action: "WITHDRAW",
    publicAmountSats: -sum,
    netBlind: freshNetBlind(),
    oldState,
    newState,
    noteCommitment: new Uint8Array(32),
    nullifier: first.nullifier,
    payoutLockingDigest: hashPayoutSet(payouts),
    amountCommitIn: commitAmount(first.note.amountSats, first.note.rho, hash),
    amountCommitOut: new Uint8Array(ZERO32),
  };
  if (newState.sequence !== oldState.sequence + 1n) throw new Error("sequence");
  if (newState.reserveSats !== oldState.reserveSats - sum) throw new Error("reserve");
  if (sum !== items.reduce((n, i) => n + i.withdrawSats, 0n)) throw new Error("payout sum");
  return { machine: { ...machine, state: newState }, statement, payouts, spent };
}

export function actionOf(delta: bigint): ActionKind {
  return delta > 0n ? "DEPOSIT" : "WITHDRAW";
}

/**
 * One-set mix: many notes in, many notes out, one public net delta.
 * Individual amounts stay in hash-committed leaves — only the net hits the UTXO.
 */
export function applyAggregate(
  machine: PoolMachine,
  deposits: Note[],
  withdraws: Array<{ note: Note; index: number; amount: bigint }>,
): {
  machine: PoolMachine;
  statement: PoolStatement;
  deposited: Array<{ note: Note; index: number }>;
  change: Array<{ note: Note; index: number }>;
} {
  let next = machine;
  const deposited: Array<{ note: Note; index: number }> = [];
  for (const note of deposits) {
    const d = applyDeposit(next, note);
    next = d.machine;
    deposited.push({ note, index: d.index });
  }
  const change: Array<{ note: Note; index: number }> = [];
  let last = undefined as ReturnType<typeof applyWithdraw> | undefined;
  for (const w of withdraws) {
    last = applyWithdraw(next, w.note, w.index, new Uint8Array(32), w.amount);
    next = last.machine;
    if (last.change && last.changeIndex !== undefined) {
      change.push({ note: last.change, index: last.changeIndex });
    }
  }
  const net = next.state.reserveSats - machine.state.reserveSats;
  const statement: PoolStatement = {
    profile: "any-amount-v0",
    action: net >= 0n ? "DEPOSIT" : "WITHDRAW",
    publicAmountSats: net,
    netBlind: freshNetBlind(),
    oldState: machine.state,
    newState: next.state,
    noteCommitment: next.state.noteRoot,
    nullifier: last?.statement.nullifier ?? new Uint8Array(32),
    payoutLockingDigest: new Uint8Array(32),
    amountCommitIn: last?.statement.amountCommitIn ?? new Uint8Array(ZERO32),
    amountCommitOut: deposited[0]
      ? commitAmount(deposited[0].note.amountSats, deposited[0].note.rho, next.notes.hash)
      : new Uint8Array(ZERO32),
  };
  return { machine: next, statement, deposited, change };
}

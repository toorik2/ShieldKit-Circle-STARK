/**
 * One on-chain successor after a local mix: several deposits, then one
 * partial withdraw. Public PAA1 carries roots + reserve only — not note amounts.
 */
import { encodeFriProof, proveFri, wWithdraw, type FriWitness } from "../backends/circle/fri.ts";
import { wBatchExit } from "../backends/circle/air.ts";
import { encodePublicPaa1, emptyState, type AnyAmountState } from "./state.ts";
import { writeU64BE } from "./bytes.ts";
import { IncrementalMerkle, NullifierSet, nullifierOf, type Note } from "./notes.ts";
import { cmpUnsignedLe } from "../chain/note-auth-step-kernel.ts";
import { applyBatchExit, applyDeposit, applyWithdraw, type PoolMachine } from "./transition.ts";
import type { PoolStatement } from "./statement.ts";
import { LAB_PAYOUT_DIGEST, LAB_PAYOUT_LOCKING } from "../chain/payout.ts";
import { defaultInternalHash } from "../backends/circle/internal-hash.ts";
import { concatBytes } from "./bytes.ts";

export type PublicPoolView = {
  sequence: string;
  reserveSats: string;
  depositCount: string;
  withdrawalCount: string;
  noteRoot: string;
  nullifierRoot: string;
  anonSet: number;
};

export function publicPoolView(state: AnyAmountState, anonSet: number): PublicPoolView {
  return {
    sequence: state.sequence.toString(),
    reserveSats: state.reserveSats.toString(),
    depositCount: state.depositCount.toString(),
    withdrawalCount: state.withdrawalCount.toString(),
    noteRoot: Buffer.from(state.noteRoot).toString("hex"),
    nullifierRoot: Buffer.from(state.nullifierRoot).toString("hex"),
    anonSet,
  };
}

export type MixSuccessor = {
  machine: PoolMachine;
  oldState: AnyAmountState;
  newState: AnyAmountState;
  statement: PoolStatement;
  witness: FriWitness;
  proof: Uint8Array;
  spent: { note: Note; index: number };
  publicBefore: PublicPoolView;
  publicAfter: PublicPoolView;
};

function rnd32(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}

export function runMixSuccessor(args?: {
  instance?: Uint8Array;
  depositCount?: number;
  withdrawSats?: bigint;
}): MixSuccessor {
  const n = args?.depositCount ?? 6;
  const withdrawSats = args?.withdrawSats ?? 1_000n;
  let machine: PoolMachine = {
    state: emptyState(args?.instance ?? rnd32()),
    notes: new IncrementalMerkle(),
    nullifiers: new NullifierSet(),
  };
  const notes: Array<{ note: Note; index: number; path: Uint8Array[] }> = [];
  for (let i = 0; i < n; i += 1) {
    const note: Note = {
      amountSats: 2_000n * BigInt(i + 1),
      rho: rnd32(),
      ownerSecret: rnd32(),
    };
    const d = applyDeposit(machine, note);
    machine = d.machine;
    notes.push({ note, index: d.index, path: d.path });
  }
  const leavesBefore = machine.notes.leaves.length;
  const oldState = structuredCloneState(machine.state);
  const spent = notes[0]!;
  const w = applyWithdraw(machine, spent.note, spent.index, LAB_PAYOUT_DIGEST, withdrawSats);
  const witness = wWithdraw(spent.note, spent.index, w.path, w.created);
  const proof = encodeFriProof(proveFri(w.statement, witness));
  const newState = w.machine.state;
  return {
    machine: w.machine,
    oldState,
    newState,
    statement: w.statement,
    witness,
    proof,
    spent: { note: spent.note, index: spent.index },
    publicBefore: publicPoolView(oldState, leavesBefore),
    publicAfter: publicPoolView(newState, w.machine.notes.leaves.length),
  };
}

function structuredCloneState(s: AnyAmountState): AnyAmountState {
  return {
    ...s,
    poolInstanceId: new Uint8Array(s.poolInstanceId),
    noteRoot: new Uint8Array(s.noteRoot),
    nullifierRoot: new Uint8Array(s.nullifierRoot),
  };
}

export function publicStateHasNoNoteAmounts(state: AnyAmountState, noteAmounts: bigint[] = []): boolean {
  const bin = encodePublicPaa1(state);
  if (bin.length !== 128 || bin[0] !== 0x50 || bin[1] !== 0x41 || bin[2] !== 0x41 || bin[3] !== 0x31) {
    return false;
  }
  if (!bin.subarray(16, 24).every((b) => b === 0)) return false;
  for (const amt of noteAmounts) {
    if (amt === state.reserveSats) continue;
    if (amt <= 0n) continue;
    const needle = writeU64BE(amt);
    for (let i = 0; i <= bin.length - 8; i += 1) {
      if (needle.every((b, k) => bin[i + k] === b)) return false;
    }
  }
  return true;
}

export function mixChangedRootsAndReserve(mix: MixSuccessor): boolean {
  const before = mix.oldState;
  const after = mix.newState;
  const rootChanged = !eq32(before.noteRoot, after.noteRoot);
  const nfChanged = !eq32(before.nullifierRoot, after.nullifierRoot);
  const reserveChanged = before.reserveSats !== after.reserveSats;
  const seqChanged = after.sequence > before.sequence;
  return rootChanged && nfChanged && reserveChanged && seqChanged;
}

function eq32(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((x, i) => x === b[i]);
}

/**
 * Option A' (FRI10-BATCH-EXIT.md): the batch equivalent of `runMixSuccessor`.
 *
 * Deposits `depositCount` notes, then exits `noteCount` of them in ONE batch, and
 * returns the intermediate nullifier roots the tape hops walk through. The proof
 * is a plain FRI9 proof over the batch statement - FRI9 already validates N notes
 * via `checkBatchSpends` when the witness carries them, so no FRI_VERSION bump is
 * involved. Its single published `auth` covers only the first note, which is why
 * each hop supplies its own walk.
 *
 * `roots` is R_0..R_noteCount: R_0 is the old root, R_i = SHA256(R_{i-1} || nf_i),
 * and R_noteCount is the new state's root. Callers pad it out to the hop count.
 */
export function runBatchSuccessor(args?: {
  depositCount?: number;
  noteCount?: number;
  instance?: Uint8Array;
}): {
  oldState: AnyAmountState;
  newState: AnyAmountState;
  statement: PoolStatement;
  proof: Uint8Array;
  spends: Array<{ note: Note; index: number; path: Uint8Array[] }>;
  roots: Uint8Array[];
  /** One per spent note. BIND_PAA1 requires outputCount - 2 == withdrawalCount
   *  delta, so a batch needs N payout outputs AND a change output. */
  payouts: Array<{ sats: bigint; lockingBytecode: Uint8Array }>;
} {
  const deposits = args?.depositCount ?? 6;
  const noteCount = args?.noteCount ?? 3;
  if (noteCount < 1 || noteCount > deposits) {
    throw new Error(`noteCount ${noteCount} must be in 1..${deposits}`);
  }
  let machine: PoolMachine = {
    state: emptyState(args?.instance ?? rnd32()),
    notes: new IncrementalMerkle(),
    nullifiers: new NullifierSet(),
  };
  const held: Array<{ note: Note; index: number }> = [];
  for (let i = 0; i < deposits; i += 1) {
    const note: Note = { amountSats: 2_000n * BigInt(i + 1), rho: rnd32(), ownerSecret: rnd32() };
    const d = applyDeposit(machine, note);
    machine = d.machine;
    held.push({ note, index: d.index });
  }
  const oldState = structuredCloneState(machine.state);
  // Sort by nullifier BEFORE applying. The pool folds nullifiers in insertion
  // order, and the on-chain step kernels require strictly increasing nullifier
  // order (that ordering is what makes a duplicate unsatisfiable). Sorting here
  // makes the two agree, so newState.nullifierRoot == the step plan's last root.
  const hashForSort = defaultInternalHash();
  const ordered = held.slice(0, noteCount).sort((x, y) =>
    cmpUnsignedLe(
      nullifierOf(x.note, oldState.poolInstanceId, hashForSort),
      nullifierOf(y.note, oldState.poolInstanceId, hashForSort),
    ),
  );
  const b = applyBatchExit(
    machine,
    ordered.map((h) => ({
      note: h.note,
      index: h.index,
      withdrawSats: h.note.amountSats,
      payoutLocking: LAB_PAYOUT_LOCKING,
    })),
  );
  const spends = b.spent.map((s) => ({ note: s.note, index: s.index, path: s.path }));
  const proof = encodeFriProof(proveFri(b.statement, wBatchExit(spends)));
  const hash = defaultInternalHash();
  const roots: Uint8Array[] = [new Uint8Array(oldState.nullifierRoot)];
  for (const s of b.spent) roots.push(hash.digest(concatBytes(roots[roots.length - 1]!, s.nullifier)));
  return {
    oldState,
    newState: b.machine.state,
    statement: b.statement,
    proof,
    spends,
    roots,
    payouts: b.payouts,
  };
}

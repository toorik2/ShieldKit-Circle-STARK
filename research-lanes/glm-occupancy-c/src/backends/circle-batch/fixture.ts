/**
 * Multi-note fixtures for the FRI10 invariant tests.
 *
 * Everything here composes existing machinery rather than reimplementing it:
 * `applyBatchExit` (transition.ts:200) already produces one successor spending N
 * notes and moves `withdrawalCount` by exactly N, and `wBatchExit` (air.ts:36)
 * already builds the N-note witness. FRI10's contribution is carrying those auths
 * in the PUBLISHED proof so a verifier without the witness can check them.
 */
import { emptyState, type AnyAmountState } from "../../pool/state.ts";
import { applyDeposit, applyBatchExit, type PoolMachine } from "../../pool/transition.ts";
import { wBatchExit, type FriAuth } from "../circle/air.ts";
import { IncrementalMerkle, NullifierSet, type Note } from "../../pool/notes.ts";
import type { PoolStatement } from "../../pool/statement.ts";
import {
  decodeFriBatchProof,
  encodeFriBatchProof,
  proveFriBatch,
  type FriProof,
} from "./fri-batch.ts";

const rnd32 = () => crypto.getRandomValues(new Uint8Array(32));
const LOCK = Uint8Array.of(0x76, 0xa9, 0x14, ...new Uint8Array(20), 0x88, 0xac);

export type BatchFixture = {
  statement: PoolStatement;
  oldState: AnyAmountState;
  proof: FriProof;
  encoded: Uint8Array;
  authCount: number;
  /** Break auth i so it no longer opens to its leaf. */
  corruptAuth(i: number): FriProof;
  /** Remove the last auth — the list must no longer match withdrawalCount. */
  dropAuth(): FriProof;
  /** Repeat an auth — same count only if one is dropped, so this pads to N+1. */
  duplicateAuth(): FriProof;
  /** Swap two auths, so their per-auth pads no longer line up. */
  swapAuths(a: number, b: number): FriProof;
};

export function makeBatchFixture(opts: { notes: number }): BatchFixture {
  const n = opts.notes;
  if (n < 1) throw new Error("need at least one note");
  let machine: PoolMachine = {
    state: emptyState(rnd32()),
    notes: new IncrementalMerkle(),
    nullifiers: new NullifierSet(),
  };
  const deposited: Array<{ note: Note; index: number }> = [];
  for (let i = 0; i < n; i += 1) {
    const note: Note = { amountSats: 2_000n * BigInt(i + 1), rho: rnd32(), ownerSecret: rnd32() };
    const d = applyDeposit(machine, note);
    machine = d.machine;
    deposited.push({ note, index: d.index });
  }
  const oldState = { ...machine.state };
  const b = applyBatchExit(
    machine,
    deposited.map((d) => ({
      note: d.note,
      index: d.index,
      withdrawSats: d.note.amountSats,
      payoutLocking: LOCK,
    })),
  );
  const witness = wBatchExit(b.spent.map((s) => ({ note: s.note, index: s.index, path: s.path })));
  const proof = proveFriBatch(b.statement, witness);
  const encoded = encodeFriBatchProof(proof);

  const clone = (p: FriProof, auths: FriAuth[]): FriProof => ({ ...p, auths });
  const open = () => decodeFriBatchProof(encodeFriBatchProof(proof));

  return {
    statement: b.statement,
    oldState,
    proof,
    encoded,
    authCount: proof.auths.length,
    corruptAuth(i) {
      const auths = proof.auths.map((a, k) =>
        k === i ? { ...a, rho: rnd32() } : a,
      );
      return clone(proof, auths);
    },
    dropAuth() {
      return clone(proof, proof.auths.slice(0, -1));
    },
    duplicateAuth() {
      return clone(proof, [...proof.auths, proof.auths[0]!]);
    },
    swapAuths(a, b2) {
      const auths = [...proof.auths];
      const t = auths[a]!;
      auths[a] = auths[b2]!;
      auths[b2] = t;
      return clone(proof, auths);
    },
  };
}

export { decodeFriBatchProof, encodeFriBatchProof };

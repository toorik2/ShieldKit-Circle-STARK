/**
 * Walked-note unlocking must not publish rho, owner, or amount8.
 * Leaf↔nf↔amountCommit is miner-bound without those preimages.
 * Tagged SHA-256 commits are not Maxwell. TVL may stay public.
 */
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { decodeTransaction } from "@bitauth/libauth";
import { noteAuthKernelUnlocking, noteAuthPublicOpens } from "../src/chain/note-auth-kernel.ts";
import { noteAuthStepUnlocking, stepPlan } from "../src/chain/note-auth-step-kernel.ts";
import { emptyState, encodePublicPaa1, utxoValueFor } from "../src/pool/state.ts";
import { applyDeposit, applyWithdraw } from "../src/pool/transition.ts";
import { IncrementalMerkle, NullifierSet, commitNote, type Note } from "../src/pool/notes.ts";
import { defaultInternalHash } from "../src/backends/circle/internal-hash.ts";
import { writeI64LE } from "../src/pool/bytes.ts";
import { encodeFriProof, proveFri, verifyFri, wWithdraw } from "../src/backends/circle/fri.ts";
import { compileCovenantSuccessor } from "../src/chain/covenant-spend.ts";
import { SLOT_KERNEL_COUNT_CONSENSUS } from "../src/chain/air-cqz.ts";
import { createLabWallet } from "../src/chain/wallet.ts";
import { LAB_PAYOUT_DIGEST } from "../src/chain/payout.ts";
import { commitAmount } from "../src/amounts/hash-commit.ts";
import {
  decodeHashBitRows,
  HASH_BIT_SHARD_COUNT,
  HASH_BIT_SHARD_BYTES,
  messagesFromHashBitRows,
} from "../src/chain/note-auth-air.ts";
import { concatBytes, sha256 } from "../src/pool/bytes.ts";

const rnd32 = () => crypto.getRandomValues(new Uint8Array(32));
const H = defaultInternalHash();
const hex = (u: Uint8Array) => Buffer.from(u).toString("hex");

function containsPreimage(unlocking: Uint8Array, note: Note): boolean {
  const h = hex(unlocking);
  return (
    h.includes(hex(note.rho)) ||
    h.includes(hex(note.ownerSecret)) ||
    h.includes(hex(writeI64LE(note.amountSats)))
  );
}

function firstPush(u: Uint8Array): Uint8Array {
  const op = u[0]!;
  if (op > 0 && op <= 75) return u.subarray(1, 1 + op);
  if (op === 0x4c) return u.subarray(2, 2 + u[1]!);
  if (op === 0x4d) {
    const n = u[1]! | (u[2]! << 8);
    return u.subarray(3, 3 + n);
  }
  return new Uint8Array();
}

function xorRepeat(data: Uint8Array, key: Uint8Array): Uint8Array {
  const out = new Uint8Array(data.length);
  for (let i = 0; i < data.length; i += 1) out[i] = data[i]! ^ key[i % key.length]!;
  return out;
}

/** Spec-aware: viewing-commit XOR and TRACE-w unpack must not yield the note. */
function specAwareRecoversNote(unlockings: Uint8Array[], note: Note, viewingCommit: Uint8Array): boolean {
  const amount8 = writeI64LE(note.amountSats);
  for (const u of unlockings) {
    const xored = xorRepeat(u, viewingCommit);
    if (containsPreimage(xored, note)) return true;
    const body = firstPush(u);
    if (body.length >= 32 && containsPreimage(xorRepeat(body, viewingCommit), note)) return true;
  }
  const rebuiltLeaf = hex(commitNote(note, H));
  for (const u of unlockings) {
    const xored = xorRepeat(u, viewingCommit);
    if (hex(xored).includes(rebuiltLeaf) && containsPreimage(xored, note)) return true;
  }
  const fold = unlockings
    .map(firstPush)
    .filter((b) => b.length >= HASH_BIT_SHARD_BYTES && b.length <= HASH_BIT_SHARD_BYTES + 256)
    .map((b) => b.subarray(0, HASH_BIT_SHARD_BYTES));
  const leftover = unlockings.map(firstPush).find((b) => b.length === 7200);
  const rowSources: Uint8Array[][] = [];
  if (fold.length === HASH_BIT_SHARD_COUNT) rowSources.push(fold);
  if (leftover) {
    rowSources.push(Array.from({ length: HASH_BIT_SHARD_COUNT }, (_, s) => leftover.subarray(s * HASH_BIT_SHARD_BYTES, (s + 1) * HASH_BIT_SHARD_BYTES)));
  }
  for (const shards of rowSources) {
    try {
      const rows = decodeHashBitRows(shards);
      const msgs = messagesFromHashBitRows(rows);
      const blob = hex(concatBytes(msgs.amountCommitMsg, msgs.leafMsg, msgs.nfMsg));
      if (blob.includes(hex(note.rho)) || blob.includes(hex(note.ownerSecret)) || blob.includes(hex(amount8))) {
        return true;
      }
    } catch {
      /* leftover pair-bind / LDE as TRACE w is garbage */
    }
  }
  return false;
}

describe("walked note unlocking does not publish the preimage", () => {
  it("the audited kernel unlocking has no amount8, rho, or owner", () => {
    const note: Note = { amountSats: 8_000n, rho: rnd32(), ownerSecret: rnd32() };
    const d = applyDeposit(
      { state: emptyState(rnd32()), notes: new IncrementalMerkle(), nullifiers: new NullifierSet() },
      note,
    );
    const w = applyWithdraw(d.machine, note, d.index, LAB_PAYOUT_DIGEST, 3_000n);
    const u = noteAuthKernelUnlocking({
      note,
      change: w.created?.note,
      spentIndex: d.index,
      spentPath: w.path,
      createdIndex: w.created!.index,
      createdPath: w.created!.path,
      poolInstanceId: w.statement.oldState.poolInstanceId,
      action: "WITHDRAW",
    });
    assert.equal(containsPreimage(u, note), false);
    if (w.created) assert.equal(containsPreimage(u, w.created.note), false);
    const opens = noteAuthPublicOpens({
      note,
      change: w.created?.note,
      action: "WITHDRAW",
      poolInstanceId: w.statement.oldState.poolInstanceId,
    });
    assert.equal(hex(u).includes(hex(opens.leaf)), true, "leaf commitment may be walked");
  });

  it("the STEP kernel unlocking has no amount8, rho, or owner", () => {
    const note: Note = { amountSats: 4_000n, rho: rnd32(), ownerSecret: rnd32() };
    const d = applyDeposit(
      { state: emptyState(rnd32()), notes: new IncrementalMerkle(), nullifiers: new NullifierSet() },
      note,
    );
    const w = applyWithdraw(d.machine, note, d.index, LAB_PAYOUT_DIGEST, note.amountSats);
    const plan = stepPlan({
      oldNfRoot: w.statement.oldState.nullifierRoot,
      poolInstanceId: w.statement.oldState.poolInstanceId,
      spends: [{ note, index: d.index, path: w.path }],
    });
    const u = noteAuthStepUnlocking(plan.spends[0]!);
    assert.equal(containsPreimage(u, note), false);
  });

  it("an observer with only the unlocking cannot recompute the deposit leaf from preimages", () => {
    const note: Note = { amountSats: 9_000n, rho: rnd32(), ownerSecret: rnd32() };
    const d = applyDeposit(
      { state: emptyState(rnd32()), notes: new IncrementalMerkle(), nullifiers: new NullifierSet() },
      note,
    );
    const w = applyWithdraw(d.machine, note, d.index, LAB_PAYOUT_DIGEST, 1_000n);
    const u = hex(
      noteAuthKernelUnlocking({
        note,
        change: w.created?.note,
        spentIndex: d.index,
        spentPath: w.path,
        createdIndex: w.created!.index,
        createdPath: w.created!.path,
        poolInstanceId: w.statement.oldState.poolInstanceId,
        action: "WITHDRAW",
      }),
    );
    assert.equal(u.includes(hex(note.rho)), false);
    assert.equal(u.includes(hex(note.ownerSecret)), false);
    assert.equal(u.includes(hex(writeI64LE(note.amountSats))), false);
    const leaf = hex(commitNote(note, H));
    assert.equal(
      u.includes(hex(note.rho)) && u.includes(hex(note.ownerSecret)),
      false,
      "cannot rebuild SHA256(amountCommit||rho||owner) from unlocking preimages",
    );
    void leaf;
  });

  it(
    "honest envelope-B successor unlockings omit spent and change preimages",
    { timeout: 180_000 },
    () => {
      const note: Note = { amountSats: 20_000n, rho: rnd32(), ownerSecret: rnd32() };
      const d = applyDeposit(
        { state: emptyState(rnd32()), notes: new IncrementalMerkle(), nullifiers: new NullifierSet() },
        note,
      );
      const w = applyWithdraw(d.machine, note, d.index, LAB_PAYOUT_DIGEST, 7_777n);
      const proved = proveFri(w.statement, wWithdraw(note, d.index, w.path, w.created));
      const fri = verifyFri(w.statement, proved, wWithdraw(note, d.index, w.path, w.created));
      assert.equal(fri.ok, true, fri.ok ? "ok" : fri.reason);
      const raw = encodeFriProof(proved);
      const measured = compileCovenantSuccessor({
        wallet: createLabWallet(),
        pool: {
          tx_hash: "11".repeat(32),
          tx_pos: 0,
          value: utxoValueFor(w.statement.oldState),
          category: new Uint8Array(32).fill(0x11),
          commitment: encodePublicPaa1(w.statement.oldState),
        },
        newState: w.statement.newState,
        proof: raw,
        statement: w.statement,
        lockKind: "p2s",
        envelope: "consensus",
        slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
        note,
        change: w.created?.note,
      });
      const tx = decodeTransaction(measured.raw);
      if (typeof tx === "string") throw new Error(tx);
      const unlockings = tx.inputs.map((i) => i.unlockingBytecode);
      for (const u of unlockings) {
        assert.equal(containsPreimage(u, note), false);
        if (w.created) assert.equal(containsPreimage(u, w.created.note), false);
      }
      const commit = proved.viewingCommit ?? new Uint8Array(32);
      assert.equal(
        specAwareRecoversNote(unlockings, note, commit),
        false,
        "spec-aware XOR / TRACE-w unpack must not recover the spent note",
      );
      if (w.created) {
        assert.equal(specAwareRecoversNote(unlockings, w.created.note, commit), false);
      }
    },
  );
});

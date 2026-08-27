import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { decodeTransaction } from "@bitauth/libauth";
import { encodeFriProof, proveFri, verifyFri, wDeposit, wWithdraw } from "../src/backends/circle/fri.ts";
import { commitAmount, commitPublicNet, commitReserve } from "../src/amounts/hash-commit.ts";
import { encodeStatement } from "../src/pool/statement.ts";
import { applyDeposit, applyWithdraw } from "../src/pool/transition.ts";
import { IncrementalMerkle, NullifierSet, commitNote, type Note } from "../src/pool/notes.ts";
import { emptyState, encodePublicPaa1, utxoValueFor } from "../src/pool/state.ts";
import { LAB_PAYOUT_DIGEST } from "../src/chain/payout.ts";
import { writeI64BE, writeI64LE, writeU64BE, writeU64LE } from "../src/pool/bytes.ts";
import { compileCovenantSuccessor } from "../src/chain/covenant-spend.ts";
import { createLabWallet } from "../src/chain/wallet.ts";
import { describePlugins } from "../src/plugins/registry.ts";
import { circleFriPlugin } from "../src/backends/circle/plugin.ts";

const AMT_A = 0x0a1b2c3d4e5f6071n;
const AMT_B = 0x1122334455667788n;

function rnd32(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}

function machine() {
  return {
    state: emptyState(rnd32()),
    notes: new IncrementalMerkle(),
    nullifiers: new NullifierSet(),
  };
}

function containsBytes(hay: Uint8Array, needle: Uint8Array): boolean {
  if (needle.length === 0) return false;
  outer: for (let i = 0; i + needle.length <= hay.length; i += 1) {
    for (let j = 0; j < needle.length; j += 1) {
      if (hay[i + j] !== needle[j]) continue outer;
    }
    return true;
  }
  return false;
}

function amountEncodings(v: bigint): Uint8Array[] {
  const abs = v < 0n ? -v : v;
  return [
    writeI64BE(v),
    writeI64LE(v),
    writeU64BE(abs),
    writeU64LE(abs),
    writeI64BE(abs),
    writeI64LE(abs),
    new TextEncoder().encode(abs.toString()),
    new TextEncoder().encode(v.toString()),
  ];
}

function successorHex(note: Note) {
  const d = applyDeposit(machine(), note);
  const w = applyWithdraw(d.machine, note, d.index, LAB_PAYOUT_DIGEST, note.amountSats / 4n);
  const raw = encodeFriProof(proveFri(w.statement, wWithdraw(note, d.index, w.path, w.created)));
  const measured = compileCovenantSuccessor({
    wallet: createLabWallet(),
    feeUtxo: { tx_hash: "33".repeat(32), tx_pos: 0, value: 250_000 },
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
    lockKind: "p2sh32",
  });
  return { measured, statement: w.statement, note, d, w, raw };
}

describe("hash/PQ note-amount commit", () => {
  it("production commit is tagged SHA-256, not a Pedersen scalar", () => {
    const rho = rnd32();
    const a = commitAmount(AMT_A, rho);
    const b = commitAmount(AMT_B, rho);
    assert.equal(a.length, 32);
    assert.notDeepEqual(a, b);
    assert.notDeepEqual(a, new Uint8Array(32));
    const note: Note = { amountSats: AMT_A, rho, ownerSecret: rnd32() };
    const d = applyDeposit(machine(), note);
    assert.deepEqual(d.statement.amountCommitOut, a);
    assert.deepEqual(commitNote(note), d.statement.noteCommitment);
  });

  it("two different amounts are absent from public successor fields", () => {
    const a = successorHex({ amountSats: AMT_A, rho: rnd32(), ownerSecret: rnd32() });
    const b = successorHex({ amountSats: AMT_B, rho: rnd32(), ownerSecret: rnd32() });
    for (const built of [a, b]) {
      const unlocking = decodeTransaction(built.measured.raw);
      if (typeof unlocking === "string") throw new Error(unlocking);
      const unlock0 = unlocking.inputs[0]!.unlockingBytecode;
      for (const amt of [AMT_A, AMT_B]) {
        for (const enc of amountEncodings(amt)) {
          assert.equal(containsBytes(unlock0, enc), false, `unlocking must not publish note amount ${amt}`);
        }
      }
      const pub = encodePublicPaa1(built.statement.newState);
      assert.deepEqual(pub.subarray(16, 24), new Uint8Array(8));
    }
  });

  it("public net and reserve are hiding commits; blind stays off encodeStatement", () => {
    const note: Note = { amountSats: AMT_A, rho: rnd32(), ownerSecret: rnd32() };
    const d = applyDeposit(machine(), note);
    const enc = encodeStatement(d.statement);
    assert.equal(containsBytes(enc, d.statement.netBlind), false, "net blind is not in the encoding");
    for (const amt of [AMT_A, d.statement.oldState.reserveSats, d.statement.newState.reserveSats]) {
      if (amt === 0n) continue;
      for (const raw of amountEncodings(amt)) {
        assert.equal(containsBytes(enc, raw), false, `encodeStatement must not carry ${amt}`);
      }
    }
    const netCommit = enc.slice(9, 41);
    assert.deepEqual(
      netCommit,
      commitPublicNet(d.statement.publicAmountSats, d.statement.payoutLockingDigest, d.statement.netBlind),
    );
    assert.notDeepEqual(
      netCommit,
      commitPublicNet(d.statement.publicAmountSats, d.statement.payoutLockingDigest, new Uint8Array(32)),
      "zero-blind net commit would be brute-forceable from payout",
    );
    const rsvOff = 9 + 32 + 128 + 128;
    assert.deepEqual(enc.slice(rsvOff, rsvOff + 32), commitReserve(d.statement.oldState.reserveSats, d.statement.netBlind));
    assert.deepEqual(
      enc.slice(rsvOff + 32, rsvOff + 64),
      commitReserve(d.statement.newState.reserveSats, d.statement.netBlind),
    );
    const other = applyDeposit(machine(), note);
    assert.notDeepEqual(
      encodeStatement(d.statement).slice(9, 41),
      encodeStatement(other.statement).slice(9, 41),
      "fresh netBlind must rerandomize the public-net commit",
    );
  });

  it("forged amount commit rejects verifyFri; honest accepts", () => {
    const note: Note = { amountSats: AMT_A, rho: rnd32(), ownerSecret: rnd32() };
    const d = applyDeposit(machine(), note);
    const proof = proveFri(d.statement, wDeposit(note, d.index, d.path));
    assert.equal(verifyFri(d.statement, proof).ok, true);
    const forged = {
      ...d.statement,
      amountCommitOut: commitAmount(AMT_B, note.rho),
    };
    const v = verifyFri(forged, proof);
    assert.equal(v.ok, false);
    assert.match(v.ok ? "" : v.reason, /amount commit/);
  });

  it("unlocking has no amount preimage", () => {
    const built = successorHex({ amountSats: AMT_A, rho: rnd32(), ownerSecret: rnd32() });
    const tx = decodeTransaction(built.measured.raw);
    if (typeof tx === "string") throw new Error(tx);
    const unlocking = tx.inputs[0]!.unlockingBytecode;
    for (const enc of amountEncodings(AMT_A)) {
      assert.equal(containsBytes(unlocking, enc), false, "unlocking amount preimage");
    }
    assert.equal(containsBytes(unlocking, built.note.rho), false);
    assert.equal(containsBytes(unlocking, built.note.ownerSecret), false);
  });

  it("shipped path is Circle FRI, not Groth16 / pairing", () => {
    assert.equal(circleFriPlugin.family, "circle-fri-m31");
    const d = describePlugins() as { zkp: Array<{ family: string }>; side: Array<{ family: string }> };
    assert.ok(d.side.some((s) => s.family === "sha256-tagged-amount"));
    assert.ok(!d.zkp.some((z) => /groth|pairing|bn254|bls12/i.test(z.family)));
    const here = dirname(fileURLToPath(import.meta.url));
    const srcRoot = join(here, "..", "src");
    const scanned = [
      readFileSync(join(srcRoot, "pool", "notes.ts"), "utf8"),
      readFileSync(join(srcRoot, "pool", "transition.ts"), "utf8"),
      readFileSync(join(srcRoot, "pool", "statement.ts"), "utf8"),
      readFileSync(join(srcRoot, "backends", "circle", "air.ts"), "utf8"),
    ].join("\n");
    assert.equal(/groth16|pairing.?snark|bn254/i.test(scanned), false);
    assert.match(scanned, /hash-commit/);
    assert.equal(/from ["'].*pedersen/.test(scanned), false);
  });
});

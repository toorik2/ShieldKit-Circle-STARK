import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { circleFriPlugin } from "../src/backends/circle/plugin.ts";
import {
  airQuotientLde,
  algebraicC,
  algebraicCQuotientLde,
  circleDomain,
  decodeFriProof,
  encodeFriProof,
  proveFri,
  proveFromTLde,
  publicCells,
  publicEvals,
  statementToEvals,
  verifyFri,
  wDeposit,
  wWithdraw,
} from "../src/backends/circle/fri.ts";
import { FRI_VERSION, TRACE_LEN } from "../src/backends/circle/params.ts";
import { onCircle } from "../src/backends/circle/group.ts";
import { applyDeposit, applyWithdraw } from "../src/pool/transition.ts";
import { IncrementalMerkle, NullifierSet, commitNote, nullifierOf, type Note } from "../src/pool/notes.ts";
import { emptyState } from "../src/pool/state.ts";
import { commitAmount } from "../src/amounts/hash-commit.ts";
import { encodeStatement } from "../src/pool/statement.ts";


function rnd32(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}

function freshMachine() {
  return {
    state: emptyState(rnd32()),
    notes: new IncrementalMerkle(),
    nullifiers: new NullifierSet(),
  };
}

function depositNote(amount = 12_345n) {
  const note: Note = { amountSats: amount, rho: rnd32(), ownerSecret: rnd32() };
  const d = applyDeposit(freshMachine(), note);
  const w = wDeposit(note, d.index, d.path);
  return { statement: d.statement, machine: d.machine, note, index: d.index, path: d.path, witness: w };
}

describe("Circle FRI prove/verify", () => {
  it("domain points lie on the circle", () => {
    for (const p of circleDomain()) assert.ok(onCircle(p));
  });

  it("accepts an honest deposit statement via shipped plugin", async () => {
    const { statement, witness } = depositNote();
    const proof = await circleFriPlugin.prove(statement, witness);
    const v = circleFriPlugin.verify(statement, proof);
    assert.equal(v.ok, true, v.ok ? "" : v.reason);
    assert.ok(proof.length > 100);
  });

  it("accepts honest withdraw with change via shipped plugin", async () => {
    const { machine, note, index, path } = depositNote(20_000n);
    const w = applyWithdraw(machine, note, index, rnd32(), 5_000n);
    const proof = await circleFriPlugin.prove(w.statement, wWithdraw(note, index, path, w.created));
    const v = circleFriPlugin.verify(w.statement, proof);
    assert.equal(v.ok, true, v.ok ? "" : v.reason);
    assert.ok(w.change);
    assert.equal(typeof w.changeIndex, "number");
    assert.notDeepEqual(w.change.rho, note.rho);
    assert.equal(w.change.amountSats, 15_000n);
  });

  it("deposit → partial withdraw → spend-change via shipped plugin", async () => {
    const { machine, note, index, path } = depositNote(20_000n);
    const instance = machine.state.poolInstanceId;
    const partial = applyWithdraw(machine, note, index, rnd32(), 5_000n);
    const p1 = await circleFriPlugin.prove(partial.statement, wWithdraw(note, index, path, partial.created));
    const v1 = circleFriPlugin.verify(partial.statement, p1);
    assert.equal(v1.ok, true, v1.ok ? "" : v1.reason);
    assert.ok(partial.change);
    assert.equal(typeof partial.changeIndex, "number");
    assert.notDeepEqual(partial.change.rho, note.rho);
    assert.notDeepEqual(nullifierOf(partial.change, instance), partial.statement.nullifier);
    assert.throws(() => applyWithdraw(partial.machine, note, index, rnd32(), 1n));

    const spent = applyWithdraw(
      partial.machine,
      partial.change,
      partial.changeIndex!,
      rnd32(),
      partial.change.amountSats,
    );
    const changePath = partial.machine.notes.authPath(partial.changeIndex!);
    const p2 = await circleFriPlugin.prove(
      spent.statement,
      wWithdraw(partial.change, partial.changeIndex!, changePath),
    );
    const v2 = circleFriPlugin.verify(spent.statement, p2);
    assert.equal(v2.ok, true, v2.ok ? "" : v2.reason);
    assert.equal(spent.machine.state.reserveSats, 0n);
    assert.equal(spent.change, undefined);
  });

  it("refuses to prove a false reserve from scratch", () => {
    const { statement, witness } = depositNote();
    statement.newState.reserveSats += 1n;
    assert.throws(() => proveFri(statement, witness), /unsatisfiable|reserve/i);
  });

  it("rejects a false statement (tampered reserve)", () => {
    const { statement, witness } = depositNote();
    const proof = proveFri(statement, witness);
    statement.newState.reserveSats += 1n;
    const v = verifyFri(statement, proof, witness);
    assert.equal(v.ok, false);
  });

  it("from-scratch fake noteCommitment: prove throws and a forced proof fails verify", () => {
    const { statement, witness, note, index, path } = depositNote();
    const fake = { ...statement, noteCommitment: rnd32() };
    assert.throws(() => proveFri(fake, wDeposit(note, index, path)), /unsatisfiable|membership/i);
    const small = circleDomain(TRACE_LEN);
    const big = circleDomain();
    const forced = proveFromTLde(fake, publicEvals(fake, small, big), {
      leaf: fake.noteCommitment,
      index,
      path,
      root: fake.newState.noteRoot,
      nullifier: new Uint8Array(32),
      rho: new Uint8Array(32),
      owner: new Uint8Array(32),
      amountSats: 0n,
      publicDeltaSats: 0n,
      amountCommit: new Uint8Array(32),
      createdLeaf: fake.noteCommitment,
      createdIndex: index,
      createdPath: path,
    }, { occupancyOnly: true });
    const v = verifyFri(fake, forced);
    assert.equal(v.ok, false, "forced fake-membership proof must not verify");
    assert.match(v.ok ? "" : v.reason, /membership|auth|path|leaf|sha-in-c/i);
  });

  it("from-scratch fake nullifier: prove throws and a forced proof fails verify", () => {
    const { machine, note, index, path } = depositNote(9_000n);
    const w = applyWithdraw(machine, note, index, rnd32(), 9_000n);
    const wit = wWithdraw(note, index, path);
    const fake = { ...w.statement, nullifier: rnd32() };
    assert.throws(() => proveFri(fake, wit), /unsatisfiable|nullifier/i);
    const small = circleDomain(TRACE_LEN);
    const big = circleDomain();
    const forced = proveFromTLde(fake, publicEvals(fake, small, big), {
      leaf: commitNote(note),
      index,
      path,
      root: fake.oldState.noteRoot,
      nullifier: fake.nullifier,
      rho: note.rho,
      owner: note.ownerSecret,
      amountSats: note.amountSats,
      publicDeltaSats: 9_000n,
      amountCommit: commitAmount(note.amountSats, note.rho),
      createdLeaf: new Uint8Array(32),
      createdIndex: 0,
      createdPath: [],
    }, { occupancyOnly: true });
    const v = verifyFri(fake, forced);
    assert.equal(v.ok, false);
    assert.match(v.ok ? "" : v.reason, /nullifier|membership|auth|preimage|sha-in-c/i);
    const opened = verifyFri(fake, decodeFriProof(encodeFriProof(forced)), {}, { viewingKey: forced.viewingKey });
    assert.equal(opened.ok, false, "viewing-key verify must still reject fake nullifier");
    assert.match(opened.ok ? "" : opened.reason, /nullifier|membership|auth|preimage/i);
  });

  it("algebraicC is zero on honest cells and nonzero on a false reserve", () => {
    const { statement, witness } = depositNote(4_000n);
    const honest = algebraicC(publicCells(statement), statement);
    assert.ok(honest.every((r) => r === 0n));
    const lied = {
      ...statement,
      newState: { ...statement.newState, reserveSats: statement.newState.reserveSats + 1n },
    };
    const bad = algebraicC(publicCells(lied), lied);
    assert.ok(bad.some((r) => r !== 0n));
    const v = verifyFri(lied, proveFri(statement, witness));
    assert.equal(v.ok, false);
    const v8Air = airQuotientLde(statement, circleDomain(TRACE_LEN), circleDomain());
    assert.ok(v8Air.qLde.some((x) => x !== 0n), "FRI_VERSION 8 airNumerator quotient is not the zero polynomial");
    const v9 = algebraicCQuotientLde(statement, circleDomain(TRACE_LEN), circleDomain());
    assert.ok(v9.nLde.every((x) => x === 0n), "honest algebraicC interpolant is the zero polynomial");
    assert.ok(v9.qLde.every((x) => x === 0n), "honest Q = C/Z is 0");
  });

  it("FRI_VERSION 9; a version-8 proof is rejected", () => {
    const { statement, witness } = depositNote();
    const proof = proveFri(statement, witness);
    assert.equal(proof.version, FRI_VERSION);
    assert.equal(FRI_VERSION, 9);
    assert.equal(verifyFri(statement, proof).ok, true);
    const v8 = { ...proof, version: 8 };
    const rejected = verifyFri(statement, v8);
    assert.equal(rejected.ok, false, "old FRI_VERSION 8 must not verify as 9");
  });

  it("statement polynomial moves when reserve, note, or nullifier change", () => {
    const { statement } = depositNote(4_000n);
    const domain = circleDomain();
    const honest = statementToEvals(statement, domain);
    const tamperedReserve = { ...statement, newState: { ...statement.newState, reserveSats: statement.newState.reserveSats + 1n } };
    const tamperedNote = { ...statement, noteCommitment: rnd32() };
    const tamperedNf = { ...statement, nullifier: rnd32() };
    assert.notDeepEqual(statementToEvals(tamperedReserve, domain), honest);
    assert.notDeepEqual(statementToEvals(tamperedNote, domain), honest);
    assert.notDeepEqual(statementToEvals(tamperedNf, domain), honest);
    assert.equal(encodeStatement(statement).length, encodeStatement(tamperedReserve).length);
  });
});

describe("hash amount commit binds the note", () => {
  it("deposit commit is the tagged SHA-256 of (amount, rho)", () => {
    const { statement, note } = depositNote(777n);
    assert.notDeepEqual(statement.amountCommitOut, new Uint8Array(32));
    assert.deepEqual(statement.amountCommitOut, commitAmount(777n, note.rho));
  });

  it("withdraw openings conserve note = public + change amounts", () => {
    const { machine, note, index } = depositNote(20_000n);
    const w = applyWithdraw(machine, note, index, rnd32(), 5_000n);
    assert.ok(w.change);
    assert.equal(note.amountSats, 5_000n + w.change.amountSats);
    let rIn = 0n;
    let rOut = 0n;
    for (const b of note.rho) rIn = (rIn << 8n) | BigInt(b);
    for (const b of w.change.rho) rOut = (rOut << 8n) | BigInt(b);
    assert.notEqual(rIn, rOut);
    assert.notDeepEqual(w.statement.amountCommitIn, new Uint8Array(32));
    assert.notDeepEqual(w.statement.amountCommitOut, new Uint8Array(32));
  });
});

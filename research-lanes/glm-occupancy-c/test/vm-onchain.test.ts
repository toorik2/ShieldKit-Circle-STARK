import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { applyDeposit, applyWithdraw } from "../src/pool/transition.ts";
import { mixChangedRootsAndReserve, runMixSuccessor } from "../src/pool/mix-successor.ts";
import { IncrementalMerkle, NullifierSet, commitNote, type Note } from "../src/pool/notes.ts";
import { concatBytes, sha256 } from "../src/pool/bytes.ts";
import { emptyState } from "../src/pool/state.ts";
import {
  encodeFriProof,
  mutateTraceAndProve,
  proveFri,
  proveFromTLde,
  publicEvals,
  verifyFri,
  wDeposit,
  wWithdraw,
  circleDomain,
} from "../src/backends/circle/fri.ts";
import { TRACE_LEN } from "../src/backends/circle/params.ts";
import {
  evaluateBch2026,
  evaluateDigestOnlyPool,
  evaluateDummyKernels,
  evaluateDummyConsistent,
  evaluateDummyNoL0,
  evaluateDummyShortPath,
  evaluateCrossPacked,
  evaluateDummyUnbound,
  evaluateCookedLaterSlot,
  evaluateCookedNTable,
  evaluateCookedT,
  evaluateSwappedDummyKernels,
  evaluateFriQueryOpening,
  evaluateMissingProofPool,
  evaluateOnChainVerify,
  evaluatePoolSuccessorVm,
  evaluateWrongFoldIndex,
  proofFitsEnvelope,
} from "../src/chain/vm-verifier.ts";
import { collectFriOpenings, dummyFriOpenings, dummyFriOpeningsWide } from "../src/chain/fri-openings.ts";
import { AIR_OFF_QTABLE, AIR_PACKED_SIZE, encodeAirPacked } from "../src/chain/air-cqz.ts";
import { NOTE_MERKLE_WALK, encodeWalkSteps } from "../src/chain/note-merkle.ts";
import { cashAssemblyToBin } from "@bitauth/libauth";
import { pushData } from "../src/chain/covenant-p2s.ts";
import { compilePoolCovenant } from "../src/chain/covenant-p2s.ts";
import { LAB_PAYOUT_DIGEST } from "../src/chain/payout.ts";

function deposit() {
  const note: Note = {
    amountSats: 8_000n,
    rho: crypto.getRandomValues(new Uint8Array(32)),
    ownerSecret: crypto.getRandomValues(new Uint8Array(32)),
  };
  const d = applyDeposit(
    { state: emptyState(crypto.getRandomValues(new Uint8Array(32))), notes: new IncrementalMerkle(), nullifiers: new NullifierSet() },
    note,
  );
  return { ...d, note, witness: wDeposit(note, d.index, d.path) };
}

describe("2026 VM runs pool covenant + STARK verify", () => {
  it("native SHA-256 note-tree walk matches IncrementalMerkle", () => {
    const tree = new IncrementalMerkle();
    const leaf = crypto.getRandomValues(new Uint8Array(32));
    const { index, path, root } = tree.append(leaf);
    const steps = encodeWalkSteps(index, path);
    const unlocking = Uint8Array.of(
      ...pushData(leaf),
      ...pushData(steps),
      ...pushData(root),
    );
    // unlocking: leaf, steps, root — lock walks then EQUAL. Need root under walk.
    const lock2 = cashAssemblyToBin(`OP_TOALTSTACK\n${NOTE_MERKLE_WALK}\nOP_FROMALTSTACK\nOP_EQUAL`);
    if (typeof lock2 === "string") throw new Error(lock2);
    const ev = evaluateBch2026(lock2, unlocking);
    assert.equal(ev.accepted, true, ev.error ?? "note merkle walk");
  });

  it("mix withdraw successor updates roots and VM-accepts; digest-only fails", () => {
    const mix = runMixSuccessor({ depositCount: 5, withdrawSats: 1_000n });
    const on = evaluateOnChainVerify(mix.statement, mix.proof);
    assert.ok(mixChangedRootsAndReserve(mix));
    assert.equal(on.stark.ok, true, on.stark.ok ? "" : on.stark.reason);
    assert.equal(on.pool.accepted, true, on.pool.error ?? "pool vm");
    assert.equal(evaluateDigestOnlyPool(mix.oldState).accepted, false);
    assert.equal(evaluateMissingProofPool(mix.oldState).accepted, false);
  });

  it("honest successor accepts; digest-only, missing, and fake-membership fail", () => {
    const d = deposit();
    const w = applyWithdraw(d.machine, d.note, d.index, LAB_PAYOUT_DIGEST, 3_000n);
    const wit = wWithdraw(d.note, d.index, w.path, w.created);
    const proof = proveFri(w.statement, wit);
    const raw = encodeFriProof(proof);
    const env = proofFitsEnvelope(raw);
    assert.ok(env.txFit100k, `tx estimate over 100KB (${raw.length})`);
    assert.ok(raw.length > 200);
    assert.equal(env.shards, 7);
    assert.ok(env.shardsFit10k);
    assert.ok(env.openings >= 200);
    assert.ok(env.unlockingMax <= 10_000);

    const on = evaluateOnChainVerify(w.statement, raw);
    assert.equal(on.stark.ok, true, on.stark.ok ? "" : on.stark.reason);
    assert.equal(on.pool.accepted, true, on.pool.error ?? "pool vm");
    assert.equal(on.accepted, true);
    assert.ok(on.pool.unlockingBytes <= 10_000);

    assert.equal(evaluateDigestOnlyPool(w.statement.oldState).accepted, false);
    assert.equal(evaluateMissingProofPool(w.statement.oldState).accepted, false);

    const fakeLeaf = crypto.getRandomValues(new Uint8Array(32));
    const fake = { ...w.statement, noteCommitment: fakeLeaf };
    const forced = proveFromTLde(fake, publicEvals(fake, circleDomain(TRACE_LEN), circleDomain()), {
      leaf: fakeLeaf,
      index: d.index,
      path: w.path,
      root: fake.oldState.noteRoot,
      nullifier: w.statement.nullifier,
      rho: d.note.rho,
      owner: d.note.ownerSecret,
      amountSats: d.note.amountSats,
      publicDeltaSats: 3_000n,
      amountCommit: new Uint8Array(32),
      createdLeaf: fakeLeaf,
      createdIndex: w.created?.index ?? 0,
      createdPath: w.created?.path ?? [],
    }, { occupancyOnly: true });
    const badPool = evaluatePoolSuccessorVm({
      oldState: w.statement.oldState,
      newState: w.statement.newState,
      proof: encodeFriProof(forced),
    });
    assert.equal(badPool.accepted, false, badPool.error ?? "fake membership must fail pool lock");
    const bad = evaluateOnChainVerify(fake, encodeFriProof(forced));
    assert.equal(bad.stark.ok, false);
    assert.equal(bad.pool.accepted, false);
    assert.equal(bad.accepted, false);

    const rewritten = {
      ...w.statement.newState,
      noteRoot: crypto.getRandomValues(new Uint8Array(32)),
    };
    const rewriteVm = evaluatePoolSuccessorVm({
      oldState: w.statement.oldState,
      newState: rewritten,
      proof: raw,
    });
    assert.equal(rewriteVm.accepted, false, rewriteVm.error ?? "rewritten noteRoot must fail pool lock");

    const drainVm = evaluatePoolSuccessorVm({
      oldState: w.statement.oldState,
      newState: w.statement.newState,
      proof: raw,
      outputValueSats: 0n,
    });
    assert.equal(drainVm.accepted, false, drainVm.error ?? "drain pool value must fail pool lock");

    const seqVm = evaluatePoolSuccessorVm({
      oldState: w.statement.oldState,
      newState: { ...w.statement.newState, sequence: 99n },
      proof: raw,
    });
    assert.equal(seqVm.accepted, false, seqVm.error ?? "sequence=99 must fail pool lock");

    const fakeNf = crypto.getRandomValues(new Uint8Array(32));
    const nfTampered = {
      ...w.statement.newState,
      nullifierRoot: sha256(concatBytes(w.statement.oldState.nullifierRoot, fakeNf)),
    };
    const fakeNfProof = encodeFriProof({
      ...proof,
      auth: { ...proof.auth, nullifier: fakeNf },
    });
    const fakeNfVm = evaluatePoolSuccessorVm({
      oldState: w.statement.oldState,
      newState: nfTampered,
      proof: fakeNfProof,
    });
    assert.equal(fakeNfVm.accepted, false, fakeNfVm.error ?? "fake nullifier must fail pool lock");

    const dummy = dummyFriOpenings(1)[0]!;
    const wide = dummyFriOpeningsWide(1)[0]!;
    const walkPacked = new Uint8Array(AIR_PACKED_SIZE);
    walkPacked.set(wide.root, 0);
    walkPacked.set(wide.left, AIR_OFF_QTABLE);
    const dummyOk = evaluateFriQueryOpening({
      left: wide.left,
      right: wide.right,
      root: wide.root,
      parentPath: wide.parentPath,
      parentIndex: wide.parentIndex,
      layerIndex: 0,
      packed: walkPacked,
    });
    assert.equal(dummyOk.accepted, true, dummyOk.error ?? "wide dummy tree must walk its own root");
    const dummyVsHonest = evaluateFriQueryOpening({
      left: dummy.left,
      right: dummy.right,
      root: proof.layerRoots[dummy.layerIndex] ?? proof.layerRoots[0]!,
      parentPath: dummy.parentPath,
      parentIndex: dummy.parentIndex,
      layerIndex: dummy.layerIndex,
    });
    assert.equal(dummyVsHonest.accepted, false, dummyVsHonest.error ?? "dummy vs honest root must fail");

    const honestPacked = encodeAirPacked(w.statement, raw);
    const dummyPacked = new Uint8Array(honestPacked);
    for (let r = 0; r < 7; r += 1) dummyPacked.set(dummy.root, r * 32);
    const dummyVsQ = evaluateFriQueryOpening({
      left: dummy.left,
      right: dummy.right,
      root: dummy.root,
      parentPath: dummy.parentPath,
      parentIndex: dummy.parentIndex,
      layerIndex: 0,
      packed: dummyPacked,
    });
    assert.equal(dummyVsQ.accepted, false, dummyVsQ.error ?? "dummy leaf vs honest qTable must fail");
    const firstL0 = collectFriOpenings(proof).find((o) => o.layerIndex === 0);
    assert.ok(firstL0, "need a layer-0 opening");
    const honestOpen = evaluateFriQueryOpening({
      left: firstL0!.left,
      right: firstL0!.right,
      root: firstL0!.root,
      parentPath: firstL0!.parentPath,
      parentIndex: firstL0!.parentIndex,
      layerIndex: 0,
      slot: firstL0!.slot,
      packed: honestPacked,
    });
    assert.equal(honestOpen.accepted, true, honestOpen.error ?? "honest leaf must be in qTable");

    const dummyShort = evaluateDummyShortPath({
      oldState: w.statement.oldState,
      newState: w.statement.newState,
      proof: raw,
      statement: w.statement,
    });
    assert.equal(dummyShort.accepted, false, dummyShort.error ?? "short dummy path must fail");
    const other = deposit();
    const otherPacked = encodeAirPacked(other.statement, encodeFriProof(proveFri(other.statement, other.witness)));
    const cross = evaluateCrossPacked({
      oldState: w.statement.oldState,
      newState: w.statement.newState,
      proof: raw,
      statement: w.statement,
      otherPacked,
    });
    assert.equal(cross.accepted, false, cross.error ?? "cross-statement packed must fail");
    const dummyNoL0 = evaluateDummyNoL0({
      oldState: w.statement.oldState,
      newState: w.statement.newState,
      proof: raw,
      statement: w.statement,
    });
    assert.equal(dummyNoL0.accepted, false, dummyNoL0.error ?? "dummy-no-L0 17-22 must fail");
    const dummyUnbound = evaluateDummyUnbound({
      oldState: w.statement.oldState,
      newState: w.statement.newState,
      proof: raw,
      statement: w.statement,
    });
    assert.equal(dummyUnbound.accepted, false, dummyUnbound.error ?? "dummy-unbound 16+ must fail");
    const dummyConsistent = evaluateDummyConsistent({
      oldState: w.statement.oldState,
      newState: w.statement.newState,
      proof: raw,
      statement: w.statement,
    });
    assert.equal(dummyConsistent.accepted, false, dummyConsistent.error ?? "dummy-consistent must fail");
    const dummyKernels = evaluateDummyKernels({
      oldState: w.statement.oldState,
      newState: w.statement.newState,
      proof: raw,
      statement: w.statement,
    });
    assert.equal(dummyKernels.accepted, false, dummyKernels.error ?? "dummy kernels must fail pool lock");
    const swapped = evaluateSwappedDummyKernels({
      oldState: w.statement.oldState,
      newState: w.statement.newState,
      proof: raw,
      statement: w.statement,
    });
    assert.equal(swapped.accepted, false, swapped.error ?? "swapped dummy roots/qTable must fail C=QZ");
    const cooked = evaluateCookedNTable({
      oldState: w.statement.oldState,
      newState: w.statement.newState,
      proof: raw,
      statement: w.statement,
    });
    assert.equal(cooked.accepted, true, "nTable is not the RHS; independent N from T");
    const cookedT = evaluateCookedT({
      oldState: w.statement.oldState,
      newState: w.statement.newState,
      proof: raw,
      statement: w.statement,
    });
    assert.equal(cookedT.accepted, false, cookedT.error ?? "cooked T must fail bind");
    const unfolded = evaluateWrongFoldIndex({
      oldState: w.statement.oldState,
      newState: w.statement.newState,
      proof: raw,
      statement: w.statement,
    });
    assert.equal(unfolded.accepted, false, "wrong fold index must fail");
    void evaluateCookedLaterSlot;

    const redeem = compilePoolCovenant();
    assert.ok(redeem.length > 40);
    assert.ok(redeem.length <= 10_000);
  });

  it("rejects a trace[i]+=1 proof on the shipped verify path", () => {
    const d = deposit();
    const bad = mutateTraceAndProve(d.statement, 0, d.witness);
    const v = verifyFri(d.statement, bad, d.witness);
    assert.equal(v.ok, false);
  });
});

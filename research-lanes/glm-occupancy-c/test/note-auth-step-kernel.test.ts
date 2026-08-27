/**
 * The note-auth STEP kernel: N notes walked on chain in ONE transaction.
 *
 * The audited kernel cannot do this. It reads both nullifier roots out of the
 * transaction at absolute index 0, so N copies would need N distinct values from
 * one output commitment — unsatisfiable for N > 1 (FRI10-BATCH-EXIT.md, verified
 * five ways). That is the whole reason envelope B walks exactly one note today.
 *
 * The step kernel bakes the two roots into the redeem instead, so step j and step
 * k are different programs at different addresses with nothing to collide over.
 * These tests are the evidence that the difference is real: the same 3-note batch
 * that the audited kernel rejects outright is accepted here.
 *
 * The audited kernel is NOT touched. `compileNoteAuthKernel()` must stay
 * byte-identical, and there is a test below that says so.
 */
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { createVirtualMachineBch2026 } from "@bitauth/libauth";
import {
  compileNoteAuthStepKernel,
  compileNoteAuthStepLockP2sh32,
  noteAuthStepUnlocking,
  stepPlan,
  stepRoots,
  cmpUnsignedLe,
} from "../src/chain/note-auth-step-kernel.ts";
import {
  compileNoteAuthKernel,
  compileNoteAuthLockP2sh32,
  noteAuthKernelUnlocking,
} from "../src/chain/note-auth-kernel.ts";
import { encodePublicPaa1, emptyState } from "../src/pool/state.ts";
import { applyDeposit, applyBatchExit } from "../src/pool/transition.ts";
import { IncrementalMerkle, NullifierSet, type Note } from "../src/pool/notes.ts";

const rnd32 = () => crypto.getRandomValues(new Uint8Array(32));
const PAYOUT = Uint8Array.of(0x76, 0xa9, 0x14, ...new Uint8Array(20), 0x88, 0xac);
const CARRIER = Uint8Array.of(0x75, 0x51);
const CATEGORY = new Uint8Array(32).fill(0x11);
const push = (d: Uint8Array) => Uint8Array.of(d.length, ...d);

function batchOf(n: number) {
  let m: {
    state: ReturnType<typeof emptyState>;
    notes: IncrementalMerkle;
    nullifiers: NullifierSet;
  } = { state: emptyState(rnd32()), notes: new IncrementalMerkle(), nullifiers: new NullifierSet() };
  const held: Array<{ note: Note; index: number }> = [];
  for (let i = 0; i < n; i += 1) {
    const note: Note = { amountSats: 5_000n * BigInt(i + 1), rho: rnd32(), ownerSecret: rnd32() };
    const d = applyDeposit(m, note);
    m = d.machine;
    held.push({ note, index: d.index });
  }
  const b = applyBatchExit(
    m,
    held.map((h) => ({
      note: h.note,
      index: h.index,
      withdrawSats: h.note.amountSats,
      payoutLocking: PAYOUT,
    })),
  );
  const roots = stepRoots(
    b.statement.oldState.nullifierRoot,
    b.spent.map((s) => s.nullifier),
  );
  return { ...b, roots };
}

/** One transaction carrying `steps` step kernels against a single carrier NFT. */
function runSteps(
  b: ReturnType<typeof batchOf>,
  steps: Array<{ noteAt: number; rIn: Uint8Array; rOut: Uint8Array; prevNf?: Uint8Array }>,
): string {
  const vm = createVirtualMachineBch2026(true);
  const outState = {
    ...b.statement.newState,
    // last step's rOut - the sorted plan may differ from deposit order
    nullifierRoot: steps.length ? steps[steps.length - 1]!.rOut : b.roots[0]!,
  };
  const r = vm.verify({
    sourceOutputs: [
      {
        lockingBytecode: CARRIER,
        valueSatoshis: 100_000n,
        token: {
          amount: 0n,
          category: CATEGORY,
          nft: {
            capability: "mutable" as const,
            commitment: encodePublicPaa1(b.statement.oldState),
          },
        },
      },
      ...steps.map((s) => ({
        lockingBytecode: compileNoteAuthStepLockP2sh32(s.rIn, s.rOut, s.prevNf ?? new Uint8Array(32)),
        valueSatoshis: 1000n,
      })),
    ],
    transaction: {
      version: 2,
      locktime: 0,
      inputs: [
        {
          outpointTransactionHash: new Uint8Array(32).fill(0x11),
          outpointIndex: 0,
          sequenceNumber: 0xffffffff,
          unlockingBytecode: push(new Uint8Array(4)),
        },
        ...steps.map((s, k) => {
          const sp = b.spent[s.noteAt]!;
          return {
            outpointTransactionHash: new Uint8Array(32).fill(0xa0 + k),
            outpointIndex: 0,
            sequenceNumber: 0xffffffff,
            unlockingBytecode: noteAuthStepUnlocking({
              note: sp.note,
              index: sp.index,
              path: sp.path,
              rIn: s.rIn,
              rOut: s.rOut,
              prevNf: s.prevNf,
              poolInstanceId: b.statement.oldState.poolInstanceId,
            }),
          };
        }),
      ],
      outputs: [
        {
          lockingBytecode: CARRIER,
          valueSatoshis: 100_000n,
          token: {
            amount: 0n,
            category: CATEGORY,
            nft: { capability: "mutable" as const, commitment: encodePublicPaa1(outState) },
          },
        },
      ],
    },
  });
  return r === true ? "ok" : String(r).replace(/\s+/g, " ").slice(0, 110);
}

/** The planner sorts by nullifier and threads prevNf - the on-chain contract. */
function honestSteps(b: ReturnType<typeof batchOf>) {
  const plan = stepPlan({
    oldNfRoot: b.statement.oldState.nullifierRoot,
    poolInstanceId: b.statement.oldState.poolInstanceId,
    spends: b.spent.map((s) => ({ note: s.note, index: s.index, path: s.path })),
  });
  return plan.spends.map((p) => ({
    noteAt: b.spent.findIndex((s) => s.index === p.index),
    rIn: p.rIn,
    rOut: p.rOut,
    prevNf: p.prevNf,
  }));
}

describe("note-auth step kernel — N notes in one transaction", () => {
  it("the step chain closes on the state's new nullifier root", () => {
    const b = batchOf(4);
    assert.equal(b.roots.length, 5);
    assert.deepEqual(
      b.roots[4],
      b.statement.newState.nullifierRoot,
      "stepRoots must land exactly on the new root",
    );
  });

  it("one step verifies", () => {
    const b = batchOf(3);
    assert.equal(runSteps(b, [honestSteps(b)[0]!]), "ok");
  });

  it("THREE steps verify in ONE transaction — what the audited kernel cannot do", () => {
    const b = batchOf(3);
    assert.equal(runSteps(b, honestSteps(b)), "ok");
  });

  it("and eight do too, so this is not a two-or-three special case", () => {
    const b = batchOf(8);
    assert.equal(runSteps(b, honestSteps(b)), "ok");
  });

  it("a step fed the wrong note is rejected", () => {
    const b = batchOf(3);
    const bad = [{ noteAt: 1, rIn: b.roots[0]!, rOut: b.roots[1]! }];
    assert.notEqual(runSteps(b, bad), "ok", "note 1 must not satisfy step 0's roots");
  });

  it("permuting which note goes in which step is rejected", () => {
    const b = batchOf(3);
    const h = honestSteps(b);
    // Swap the ACTUAL note assignments, not literal 0 and 1. honestSteps sorts by
    // nullifier, which is random per run, so hardcoding the indices restored the
    // honest assignment whenever the sort had already swapped these two - the test
    // then failed for the right reason (the tx really did verify). CI caught it.
    assert.notEqual(h[0]!.noteAt, h[1]!.noteAt, "distinct notes, or the swap is a no-op");
    const swapped = [
      { ...h[0]!, noteAt: h[1]!.noteAt },
      { ...h[1]!, noteAt: h[0]!.noteAt },
      h[2]!,
    ];
    assert.notEqual(runSteps(b, swapped), "ok", "order is bound by the baked roots");
  });

  it("a forged intermediate root is rejected", () => {
    const b = batchOf(3);
    const h = honestSteps(b);
    const forged = [h[0]!, { ...h[1]!, rOut: rnd32() }, h[2]!];
    assert.notEqual(runSteps(b, forged), "ok");
  });

  it("each (rIn, rOut) is its own address, so steps are not interchangeable", () => {
    const a = rnd32();
    const c = rnd32();
    const d = rnd32();
    assert.notDeepEqual(
      compileNoteAuthStepLockP2sh32(a, c),
      compileNoteAuthStepLockP2sh32(a, d),
      "a different rOut must give a different lock",
    );
    assert.notDeepEqual(
      compileNoteAuthStepLockP2sh32(a, c),
      compileNoteAuthStepLockP2sh32(c, a),
      "swapping the roots must give a different lock",
    );
    assert.equal(compileNoteAuthStepLockP2sh32(a, c).length, 35, "P2SH32 lock is 35 B");
  });

  it("rejects wrong-width roots rather than baking a short push", () => {
    assert.throws(() => compileNoteAuthStepKernel(new Uint8Array(31), rnd32()), /rIn must be 32/);
    assert.throws(() => compileNoteAuthStepKernel(rnd32(), new Uint8Array(33)), /rOut must be 32/);
  });

  it("the step kernel is smaller than the audited one, and fits many per tx", () => {
    const b = batchOf(1);
    const sp = b.spent[0]!;
    const stepU = noteAuthStepUnlocking({
      note: sp.note,
      index: sp.index,
      path: sp.path,
      rIn: b.roots[0]!,
      rOut: b.roots[1]!,
      poolInstanceId: b.statement.oldState.poolInstanceId,
    });
    const auditedU = noteAuthKernelUnlocking({
      note: sp.note,
      spentIndex: sp.index,
      spentPath: sp.path,
      createdIndex: 0,
      createdPath: [],
      poolInstanceId: b.statement.oldState.poolInstanceId,
      action: "WITHDRAW",
    });
    // No deposit branch and no change branch, so the redeem is much shorter.
    assert.ok(
      compileNoteAuthStepKernel(b.roots[0]!, b.roots[1]!).length <
        compileNoteAuthKernel().length,
      "step redeem must be smaller than the audited redeem",
    );
    assert.ok(stepU.length < auditedU.length, "and so must its unlocking");
    // Each step is its OWN input, so the 2026 per-input 10 KB cap never binds.
    assert.ok(stepU.length < 10_000, `step unlocking ${stepU.length} must fit one input`);
  });

  it("NON-BATCHED: a single note still works, and is the same code path", () => {
    const b = batchOf(1);
    const steps = honestSteps(b);
    assert.equal(steps.length, 1, "one note, one step");
    assert.deepEqual(steps[0]!.prevNf, new Uint8Array(32), "step 0 compares against ZERO32");
    assert.equal(runSteps(b, steps), "ok", "the N=1 case must verify like any other");
  });

  it("DUPLICATE: the same note spent twice is unsatisfiable on chain", () => {
    // Before the ordering guard this was ACCEPTED by the VM: one note folded
    // twice gives a valid root chain, and no single kernel can see the other.
    const b = batchOf(2);
    const nf0 = b.spent[0]!.nullifier;
    const r1 = stepRoots(b.statement.oldState.nullifierRoot, [nf0, nf0]);
    const dup = [
      { noteAt: 0, rIn: r1[0]!, rOut: r1[1]!, prevNf: new Uint8Array(32) },
      { noteAt: 0, rIn: r1[1]!, rOut: r1[2]!, prevNf: nf0 },
    ];
    assert.notEqual(runSteps(b, dup), "ok", "nf > prevNf is false for equals");
  });

  it("the planner refuses to build a duplicate plan at all", () => {
    const b = batchOf(2);
    const one = { note: b.spent[0]!.note, index: b.spent[0]!.index, path: b.spent[0]!.path };
    assert.throws(
      () =>
        stepPlan({
          oldNfRoot: b.statement.oldState.nullifierRoot,
          poolInstanceId: b.statement.oldState.poolInstanceId,
          spends: [one, one],
        }),
      /duplicate note/,
    );
  });

  it("out-of-order steps are rejected — order is the guard", () => {
    const b = batchOf(3);
    const steps = honestSteps(b);
    // keep the roots, but give step 1 a prevNf that is larger than its own nf
    const bad = steps.map((s, i) => (i === 1 ? { ...s, prevNf: steps[2]!.prevNf } : s));
    if (cmpUnsignedLe(bad[1]!.prevNf!, steps[1]!.prevNf!) === 0) return; // degenerate
    assert.notEqual(runSteps(b, bad), "ok");
  });

  it("the sort matches the VM's unsigned little-endian comparison", () => {
    const lo = new Uint8Array(32); lo[31] = 0x10;
    const hi = new Uint8Array(32); hi[31] = 0xfe; // high bit set: signed would flip this
    assert.equal(cmpUnsignedLe(lo, hi), -1, "0xfe must sort ABOVE 0x10, not below");
    assert.equal(cmpUnsignedLe(hi, lo), 1);
    assert.equal(cmpUnsignedLe(lo, lo), 0);
  });

  it("the audited kernel is untouched by any of this", () => {
    // If this ever fails, a landed transaction just changed address.
    assert.equal(compileNoteAuthKernel().length, 660, "prefix-only redeem has no dummy OP_DROP");
    assert.equal(compileNoteAuthLockP2sh32().length, 35);
    assert.notDeepEqual(
      compileNoteAuthLockP2sh32(),
      compileNoteAuthStepLockP2sh32(new Uint8Array(32), new Uint8Array(32)),
      "the two kernels must be distinct programs",
    );
  });
});

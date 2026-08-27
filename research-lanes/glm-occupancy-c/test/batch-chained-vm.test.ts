/**
 * Option A' end to end: a real N-note batch across envelope C's tape hops, run
 * through the 2026 VM with full transaction context.
 *
 * This is the test that says the wiring works, as opposed to the pieces working.
 * `batch-root-binding.test.ts` proves the three primitives in isolation; this one
 * builds the actual chained withdraw with `compileChainedWithdraw({ batch })` and
 * verifies each hop the way BCHN would.
 *
 * The proof here is a plain FRI9 proof over a batch statement. That is deliberate
 * and is what makes A' land without a FRI_VERSION bump: FRI9 already validates N
 * notes through `checkBatchSpends` when the witness carries them, and its single
 * published `auth` covers only the first note - which is exactly why each hop past
 * the first supplies its own walk through `noteSpent`.
 */
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { createVirtualMachineBch2026, decodeTransaction, hash256 } from "@bitauth/libauth";
import { compileChainedWithdraw, QUERIES_PER_TAPE_HOP } from "../src/chain/chained.ts";
import { createLabWallet, p2pkhLockingOf } from "../src/chain/wallet.ts";
import { emptyState, encodePublicPaa1, utxoValueFor } from "../src/pool/state.ts";
import { applyDeposit, applyBatchExit } from "../src/pool/transition.ts";
import { IncrementalMerkle, NullifierSet, type Note } from "../src/pool/notes.ts";
import { defaultInternalHash } from "../src/backends/circle/internal-hash.ts";
import { concatBytes } from "../src/pool/bytes.ts";
import { FRI_QUERIES } from "../src/backends/circle/params.ts";
import { compileFriQueryLockP2sh32 } from "../src/chain/fri-kernel.ts";
import { compileCqzLockP2sh32, compileSlotsLockP2sh32 } from "../src/chain/air-cqz.ts";
import { compileFoldLockP2sh32 } from "../src/chain/fold-kernel.ts";
import { compileNoteAuthLockP2sh32 } from "../src/chain/note-auth-kernel.ts";
import { proofCargoLock } from "../src/chain/proof-cargo.ts";
import { tapeTipLockChainWithRoots } from "../src/chain/tape-tip.ts";
import { TAPE_HOP_OUT_SATS } from "../src/chain/envelope.ts";
import { circleFriPlugin } from "../src/backends/circle/plugin.ts";
import { wBatchExit } from "../src/backends/circle/air.ts";

const CAT = new Uint8Array(32).fill(0x33);
const FUNDER = "ab".repeat(32);
const GEN = "dd".repeat(32);
const POOL = "33".repeat(32);
const TAPE_VALUE = 300_000;
const KERNEL_SATS = 1000n;
const PAYOUT = Uint8Array.of(0x76, 0xa9, 0x14, ...new Uint8Array(20), 0x88, 0xac);
const H = defaultInternalHash();
const rnd32 = () => crypto.getRandomValues(new Uint8Array(32));

/** N full-note exits, a FRI9 proof over the batch statement, and R_0..R_tapeN. */
async function buildBatch(noteCount: number) {
  let m: {
    state: ReturnType<typeof emptyState>;
    notes: IncrementalMerkle;
    nullifiers: NullifierSet;
  } = { state: emptyState(rnd32()), notes: new IncrementalMerkle(), nullifiers: new NullifierSet() };
  const held: Array<{ note: Note; index: number }> = [];
  for (let i = 0; i < noteCount; i += 1) {
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
  const proof = await circleFriPlugin.prove(
    b.statement,
    wBatchExit(b.spent.map((s) => ({ note: s.note, index: s.index, path: s.path }))),
  );
  const v = circleFriPlugin.verify(b.statement, proof);
  assert.equal(v.ok, true, `FRI9 must verify the batch statement: ${v.ok ? "" : v.reason}`);

  const tapeHops = Math.ceil(FRI_QUERIES / QUERIES_PER_TAPE_HOP);
  // R_0 = old root; hop i writes R_{i+1}. Hops past the notes hold the root still.
  const roots: Uint8Array[] = [b.statement.oldState.nullifierRoot];
  for (const s of b.spent) roots.push(H.digest(concatBytes(roots[roots.length - 1]!, s.nullifier)));
  while (roots.length < tapeHops + 1) roots.push(roots[roots.length - 1]!);

  return { batch: b, proof, roots, tapeHops };
}

function buildChain(built: Awaited<ReturnType<typeof buildBatch>>) {
  const { batch, proof, roots, tapeHops } = built;
  const wallet = createLabWallet();
  const spends = batch.spent.map((s) => ({ note: s.note, index: s.index, path: s.path }));
  const groups = Array.from({ length: tapeHops }, (_, g) => {
    // hops with a note carry 6 extras (cqz, note, 2 fold, 2 slot), others 5
    const extras = 5 + (g < spends.length ? 1 : 0);
    let base = 0;
    for (let i = 0; i < g; i += 1) base += 10 + 5 + (i < spends.length ? 1 : 0);
    const at = (i: number) => ({ tx_hash: FUNDER, tx_pos: base + i, value: Number(KERNEL_SATS) });
    return {
      fri: Array.from({ length: 10 }, (_, i) => at(i)),
      extra: Array.from({ length: extras }, (_, i) => at(10 + i)),
      carrier: { tx_hash: GEN, tx_pos: 2 + g, value: Number(TAPE_HOP_OUT_SATS) },
    };
  });
  const chain = compileChainedWithdraw({
    wallet,
    tapeKernels: groups,
    tapeUtxo: { tx_hash: "11".repeat(32), tx_pos: 0, value: TAPE_VALUE },
    hops: tapeHops + 1,
    digest: hash256(proof),
    proof,
    pool: {
      tx_hash: POOL,
      tx_pos: 0,
      value: utxoValueFor(batch.statement.oldState),
      category: CAT,
      commitment: encodePublicPaa1(batch.statement.oldState),
    },
    newState: batch.statement.newState,
    statement: batch.statement,
    kernelUtxos: Array.from({ length: 10 }, (_, i) => ({ tx_hash: "cc".repeat(32), tx_pos: i, value: 1000 })),
    extraKernels: Array.from({ length: 8 }, (_, i) => ({ tx_hash: "cc".repeat(32), tx_pos: 10 + i, value: 1000 })),
    batch: { spends, roots },
  });
  return { chain, wallet, spends, tips: tapeTipLockChainWithRoots(hash256(proof), roots.slice(1)) };
}

/** Source outputs for a batch tape hop, in the order the successor consumes them. */
function hopSourceOutputs(args: {
  q0: number;
  inRoot: Uint8Array;
  oldState: ReturnType<typeof emptyState>;
  wallet: ReturnType<typeof createLabWallet>;
  prevTape: bigint;
  tipLock: Uint8Array;
  hasNote: boolean;
}) {
  return [
    {
      lockingBytecode: proofCargoLock(),
      valueSatoshis: TAPE_HOP_OUT_SATS,
      token: {
        amount: 0n,
        category: CAT,
        nft: {
          capability: "mutable" as const,
          commitment: encodePublicPaa1({ ...args.oldState, nullifierRoot: args.inRoot }),
        },
      },
    },
    ...Array.from({ length: 10 }, () => ({
      lockingBytecode: compileFriQueryLockP2sh32(),
      valueSatoshis: KERNEL_SATS,
    })),
    { lockingBytecode: compileCqzLockP2sh32(), valueSatoshis: KERNEL_SATS },
    ...(args.hasNote
      ? [{ lockingBytecode: compileNoteAuthLockP2sh32(), valueSatoshis: KERNEL_SATS }]
      : []),
    { lockingBytecode: compileFoldLockP2sh32(1, args.q0), valueSatoshis: KERNEL_SATS },
    { lockingBytecode: compileFoldLockP2sh32(1, args.q0 + 1), valueSatoshis: KERNEL_SATS },
    { lockingBytecode: compileSlotsLockP2sh32(args.q0), valueSatoshis: KERNEL_SATS },
    { lockingBytecode: compileSlotsLockP2sh32(args.q0 + 1), valueSatoshis: KERNEL_SATS },
    { lockingBytecode: args.tipLock, valueSatoshis: args.prevTape },
  ];
}

describe("option A' end to end: an N-note batch across envelope C", () => {
  it("every hop verifies, and the note-carrying ones walk their own note", async () => {
    const built = await buildBatch(3);
    const { chain, wallet, spends, tips } = buildChain(built);
    const vm = createVirtualMachineBch2026(true);
    let withNote = 0;
    let checked = 0;
    for (const hop of chain.hops) {
      if (hop.role !== "tape") continue;
      const tx = decodeTransaction(hop.raw);
      if (typeof tx === "string") throw new Error(tx);
      const hasNote = hop.index < spends.length;
      const sourceOutputs = hopSourceOutputs({
        q0: hop.index * QUERIES_PER_TAPE_HOP,
        inRoot: built.roots[hop.index]!,
        oldState: built.batch.statement.oldState,
        wallet,
        prevTape: hop.index === 0 ? BigInt(TAPE_VALUE) : TAPE_HOP_OUT_SATS,
        tipLock: tips[hop.index]!,
        hasNote,
      });
      assert.equal(tx.inputs.length, sourceOutputs.length, `hop ${hop.index} input count`);
      assert.equal(
        vm.verify({ transaction: tx, sourceOutputs }),
        true,
        `tape hop ${hop.index} must verify (hasNote=${hasNote})`,
      );
      if (hasNote) withNote += 1;
      checked += 1;
    }
    assert.equal(checked, built.tapeHops, "every tape hop checked");
    assert.equal(withNote, 3, "three hops carry a note-auth kernel");
  });

  it("the batch really does advance the root N steps, ending on the new state", async () => {
    const built = await buildBatch(3);
    assert.deepEqual(
      built.roots[3],
      built.batch.statement.newState.nullifierRoot,
      "R_3 must be the state's new nullifier root",
    );
    assert.notDeepEqual(built.roots[0], built.roots[3], "the root must actually move");
    // hops past the notes hold it still, so the terminal root is still R_3
    assert.deepEqual(
      built.roots[built.tapeHops],
      built.batch.statement.newState.nullifierRoot,
      "idle hops must not move the root",
    );
  });

  it("a hop cannot publish a root its kernel did not produce", async () => {
    const built = await buildBatch(2);
    const bad = { ...built, roots: [...built.roots] };
    bad.roots[1] = rnd32(); // hop 0 now claims a root its note does not give
    const { chain, wallet, spends } = buildChain(bad);
    const tips = tapeTipLockChainWithRoots(hash256(bad.proof), bad.roots.slice(1));
    const hop = chain.hops.find((h) => h.role === "tape" && h.index === 0)!;
    const tx = decodeTransaction(hop.raw);
    if (typeof tx === "string") throw new Error(tx);
    const sourceOutputs = hopSourceOutputs({
      q0: 0,
      inRoot: bad.roots[0]!,
      oldState: bad.batch.statement.oldState,
      wallet,
      prevTape: BigInt(TAPE_VALUE),
      tipLock: tips[0]!,
      hasNote: spends.length > 0,
    });
    assert.notEqual(
      createVirtualMachineBch2026(true).verify({ transaction: tx, sourceOutputs }),
      true,
      "a forged intermediate root must be rejected",
    );
  });

  it("FRI9 single-note chaining is untouched when no batch is passed", async () => {
    // The same builder without `batch` must produce the unrooted tip chain and
    // 5-extra hops, exactly as before option A' existed.
    const { runMixSuccessor } = await import("../src/pool/mix-successor.ts");
    const mix = runMixSuccessor({ depositCount: 4, withdrawSats: 1_000n });
    const tapeHops = Math.ceil(FRI_QUERIES / QUERIES_PER_TAPE_HOP);
    const groups = Array.from({ length: tapeHops }, (_, g) => {
      const base = g * 15;
      const at = (i: number) => ({ tx_hash: FUNDER, tx_pos: base + i, value: Number(KERNEL_SATS) });
      return {
        fri: Array.from({ length: 10 }, (_, i) => at(i)),
        extra: Array.from({ length: 5 }, (_, i) => at(10 + i)),
        carrier: { tx_hash: GEN, tx_pos: 2 + g, value: Number(TAPE_HOP_OUT_SATS) },
      };
    });
    const chain = compileChainedWithdraw({
      wallet: createLabWallet(),
      tapeKernels: groups,
      tapeUtxo: { tx_hash: "11".repeat(32), tx_pos: 0, value: TAPE_VALUE },
      hops: tapeHops + 1,
      digest: hash256(mix.proof),
      proof: mix.proof,
      pool: {
        tx_hash: POOL,
        tx_pos: 0,
        value: utxoValueFor(mix.oldState),
        category: CAT,
        commitment: encodePublicPaa1(mix.oldState),
      },
      newState: mix.newState,
      statement: mix.statement,
      kernelUtxos: Array.from({ length: 10 }, (_, i) => ({ tx_hash: "cc".repeat(32), tx_pos: i, value: 1000 })),
      extraKernels: Array.from({ length: 9 }, (_, i) => ({ tx_hash: "cc".repeat(32), tx_pos: 10 + i, value: 1000 })),
      note: mix.spent.note,
      change: mix.witness.created?.note,
    });
    assert.equal(chain.hops.filter((h) => h.role === "tape").length, tapeHops);
    assert.ok(chain.payIndex >= 0, "the pay hop is still built");
  });
});

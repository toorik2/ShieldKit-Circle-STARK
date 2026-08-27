/**
 * Envelope C on the 2026 VM, with full transaction context.
 *
 * These exist because the tape-hop path had no VM coverage and shipped seven
 * separate defects that only surfaced on chain: missing per-hop kernels, a bare
 * OP_DROP OP_1 carrier lock (CLEANSTACK), no NFT for cqz to read (OP_SPLIT on an
 * empty item), dust-valued token outputs, a token-carrying tape tip (NULLFAIL),
 * and a pool covenant that did not expect note-auth at 4 slots (OP_EQUALVERIFY).
 *
 * `evaluateBch2026` cannot catch any of them: it uses
 * createTestAuthenticationProgramBch, which has no transaction, so every
 * introspection kernel fails there regardless. These tests run the real VM over a
 * whole transaction with real source outputs.
 */
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { createVirtualMachineBch2026, decodeTransaction, hash256 } from "@bitauth/libauth";
import { compileChainedWithdraw, QUERIES_PER_TAPE_HOP } from "../src/chain/chained.ts";
import { runMixSuccessor } from "../src/pool/mix-successor.ts";
import { createLabWallet, p2pkhLockingOf } from "../src/chain/wallet.ts";
import { encodePublicPaa1, utxoValueFor } from "../src/pool/state.ts";
import { FRI_QUERIES } from "../src/backends/circle/params.ts";
import { compileFriQueryLockP2sh32 } from "../src/chain/fri-kernel.ts";
import { compileCqzLockP2sh32, compileSlotsLockP2sh32, SLOT_KERNEL_COUNT } from "../src/chain/air-cqz.ts";
import { compileFoldLockP2sh32 } from "../src/chain/fold-kernel.ts";
import { compileGrindLockP2sh32 } from "../src/chain/grind-kernel.ts";
import { compileAlgebraicCLockP2sh32 } from "../src/chain/algebraic-c-kernel.ts";
import { compileNoteAuthLockP2sh32 } from "../src/chain/note-auth-kernel.ts";
import { proofCargoLock } from "../src/chain/proof-cargo.ts";
import { poolLockP2sh32 } from "../src/chain/covenant-p2s.ts";
import { tapeTipLockChain, tapeTipRedeemChain } from "../src/chain/tape-tip.ts";
import { TAPE_HOP_OUT_SATS } from "../src/chain/envelope.ts";

const CAT = new Uint8Array(32).fill(0x33);
const FUNDER = "ab".repeat(32);
const GEN = "dd".repeat(32);
const POOL = "33".repeat(32);
const TAPE_VALUE = 300_000;
const KERNEL_SATS = 1000n;

function buildChain() {
  const mix = runMixSuccessor({ depositCount: 6, withdrawSats: 1_000n });
  const wallet = createLabWallet();
  const tapeHops = Math.ceil(FRI_QUERIES / QUERIES_PER_TAPE_HOP);
  const old = encodePublicPaa1(mix.oldState);
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
    wallet,
    tapeKernels: groups,
    tapeUtxo: { tx_hash: "11".repeat(32), tx_pos: 0, value: TAPE_VALUE },
    hops: tapeHops + 1,
    digest: hash256(mix.proof),
    proof: mix.proof,
    pool: { tx_hash: POOL, tx_pos: 0, value: utxoValueFor(mix.oldState), category: CAT, commitment: old },
    newState: mix.newState,
    statement: mix.statement,
    kernelUtxos: Array.from({ length: 10 }, (_, i) => ({ tx_hash: "cc".repeat(32), tx_pos: i, value: 1000 })),
    extraKernels: Array.from({ length: 9 }, (_, i) => ({ tx_hash: "cc".repeat(32), tx_pos: 10 + i, value: 1000 })),
    note: mix.spent.note,
    change: mix.witness.created?.note,
  });
  return { chain, mix, wallet, old, tapeHops, tips: tapeTipLockChain(hash256(mix.proof), tapeHops) };
}

/** Source outputs for a tape hop: sibling NFT, 10 FRI, cqz, 2 fold, 2 slot, tape tip. */
function tapeSourceOutputs(args: {
  q0: number;
  old: Uint8Array;
  wallet: ReturnType<typeof createLabWallet>;
  prevTape: bigint;
  carrierToken?: boolean;
  tipLock?: Uint8Array;
}) {
  const carrier = {
    lockingBytecode: proofCargoLock(),
    valueSatoshis: TAPE_HOP_OUT_SATS,
    ...(args.carrierToken === false
      ? {}
      : { token: { amount: 0n, category: CAT, nft: { capability: "mutable" as const, commitment: args.old } } }),
  };
  return [
    carrier,
    ...Array.from({ length: 10 }, () => ({ lockingBytecode: compileFriQueryLockP2sh32(), valueSatoshis: KERNEL_SATS })),
    { lockingBytecode: compileCqzLockP2sh32(), valueSatoshis: KERNEL_SATS },
    { lockingBytecode: compileFoldLockP2sh32(1, args.q0), valueSatoshis: KERNEL_SATS },
    { lockingBytecode: compileFoldLockP2sh32(1, args.q0 + 1), valueSatoshis: KERNEL_SATS },
    { lockingBytecode: compileSlotsLockP2sh32(args.q0), valueSatoshis: KERNEL_SATS },
    { lockingBytecode: compileSlotsLockP2sh32(args.q0 + 1), valueSatoshis: KERNEL_SATS },
    { lockingBytecode: args.tipLock ?? p2pkhLockingOf(args.wallet), valueSatoshis: args.prevTape },
  ];
}

describe("envelope C on the 2026 VM (full transaction context)", () => {
  it("every tape hop verifies with its sibling NFT and absolute-index fold/slot locks", () => {
    const { chain, wallet, old, tips } = buildChain();
    const vm = createVirtualMachineBch2026(true);
    let checked = 0;
    for (const hop of chain.hops) {
      if (hop.role !== "tape") continue;
      const tx = decodeTransaction(hop.raw);
      if (typeof tx === "string") throw new Error(tx);
      const sourceOutputs = tapeSourceOutputs({
        q0: hop.index * QUERIES_PER_TAPE_HOP,
        old,
        wallet,
        prevTape: hop.index === 0 ? BigInt(TAPE_VALUE) : TAPE_HOP_OUT_SATS,
        tipLock: tips[hop.index],
      });
      assert.equal(tx.inputs.length, sourceOutputs.length, `hop ${hop.index} input count`);
      assert.equal(vm.verify({ transaction: tx, sourceOutputs }), true, `tape hop ${hop.index} must verify`);
      checked += 1;
    }
    assert.equal(checked, 18, "18 tape hops carry the 36 unique-orbit queries");
  });

  it("a tokenless carrier breaks cqz: it has no PAA1 commitment to bind against", () => {
    const { chain, wallet, old } = buildChain();
    const hop = chain.hops.find((h) => h.role === "tape" && h.index === 0)!;
    const tx = decodeTransaction(hop.raw);
    if (typeof tx === "string") throw new Error(tx);
    // Same hop, but input 0 carries no token — the shape that shipped before the
    // sibling NFTs and drew "Invalid OP_SPLIT range (code 16)" from BCHN.
    const { tips: t2 } = buildChain();
    const sourceOutputs = tapeSourceOutputs({ q0: 0, old, wallet, prevTape: BigInt(TAPE_VALUE), carrierToken: false, tipLock: t2[0] });
    const r = createVirtualMachineBch2026(true).verify({ transaction: tx, sourceOutputs });
    assert.notEqual(r, true, "cqz must reject a carrier with no token commitment");
  });

  it("the pay hop verifies against a pool lock that expects note-auth at 4 slots", () => {
    const { chain, mix, wallet, old, tips, tapeHops } = buildChain();
    const pay = chain.hops[chain.payIndex]!;
    const tx = decodeTransaction(pay.raw);
    if (typeof tx === "string") throw new Error(tx);
    const sourceOutputs = [
      {
        lockingBytecode: poolLockP2sh32({ slotKernels: SLOT_KERNEL_COUNT, forceNoteAuth: true, tapeTipLock: tips[tapeHops] }),
        valueSatoshis: BigInt(utxoValueFor(mix.oldState)),
        token: { amount: 0n, category: CAT, nft: { capability: "mutable" as const, commitment: old } },
      },
      ...Array.from({ length: 10 }, () => ({ lockingBytecode: compileFriQueryLockP2sh32(), valueSatoshis: KERNEL_SATS })),
      { lockingBytecode: compileCqzLockP2sh32(), valueSatoshis: KERNEL_SATS },
      { lockingBytecode: compileGrindLockP2sh32(), valueSatoshis: KERNEL_SATS },
      { lockingBytecode: compileAlgebraicCLockP2sh32(), valueSatoshis: KERNEL_SATS },
      { lockingBytecode: compileNoteAuthLockP2sh32(), valueSatoshis: KERNEL_SATS },
      { lockingBytecode: compileFoldLockP2sh32(1, 0), valueSatoshis: KERNEL_SATS },
      ...Array.from({ length: SLOT_KERNEL_COUNT }, (_, i) => ({
        lockingBytecode: compileSlotsLockP2sh32(i),
        valueSatoshis: KERNEL_SATS,
      })),
      { lockingBytecode: tips[tapeHops]!, valueSatoshis: TAPE_HOP_OUT_SATS },
    ];
    assert.equal(tx.inputs.length, sourceOutputs.length, "pay hop input count");
    assert.equal(createVirtualMachineBch2026(true).verify({ transaction: tx, sourceOutputs }), true);
  });

  it("the note-auth pool lock differs from the plain one, and A/B locks are unchanged", () => {
    const plain = poolLockP2sh32({ slotKernels: SLOT_KERNEL_COUNT });
    const forced = poolLockP2sh32({ slotKernels: SLOT_KERNEL_COUNT, forceNoteAuth: true });
    assert.notDeepEqual(plain, forced, "forceNoteAuth must change the covenant, not be silently dropped");
    // Regression: forceNoteAuth once compiled to the same bytes because
    // compilePoolCovenant did not declare the option and TS allowed the extra
    // property through a variable. A typecheck cannot catch that; this can.
    assert.deepEqual(poolLockP2sh32({ slotKernels: SLOT_KERNEL_COUNT, forceNoteAuth: false }), plain);
  });

  it("the tip lock chain is counted, so hops cannot be skipped or re-digested", () => {
    const d1 = new Uint8Array(32).fill(0xaa);
    const d2 = new Uint8Array(32).fill(0xbb);
    const N = 18;
    const c1 = tapeTipLockChain(d1, N);
    const c2 = tapeTipLockChain(d2, N);
    assert.equal(c1.length, N + 1);
    // every link distinct: the pay hop demands L(d,N), so it cannot reach back to
    // the funder's L(d,0) and skip the tape
    const seen = new Set(c1.map((l) => Buffer.from(l).toString("hex")));
    assert.equal(seen.size, c1.length, "each hop must have its own tip lock");
    assert.notDeepEqual(c1[0], c1[N], "funder tip must differ from the terminal tip");
    assert.notDeepEqual(c1[0], c2[0], "a different digest must give a different chain");
    // terminal link carries no propagation clause, so it is the shorter redeem
    const r1 = tapeTipRedeemChain(d1, N);
    assert.ok(r1[N]!.length < r1[0]!.length, "terminal redeem has no output-1 obligation");
  });

  it("the pool covenant pins the terminal tip lock", () => {
    const d = new Uint8Array(32).fill(0xaa);
    const tip = tapeTipLockChain(d, 18)[18]!;
    const other = tapeTipLockChain(new Uint8Array(32).fill(0xbb), 18)[18]!;
    const base = poolLockP2sh32({ slotKernels: SLOT_KERNEL_COUNT, forceNoteAuth: true });
    const pinned = poolLockP2sh32({ slotKernels: SLOT_KERNEL_COUNT, forceNoteAuth: true, tapeTipLock: tip });
    const pinnedOther = poolLockP2sh32({ slotKernels: SLOT_KERNEL_COUNT, forceNoteAuth: true, tapeTipLock: other });
    assert.notDeepEqual(base, pinned, "pinning must change the covenant");
    assert.notDeepEqual(pinned, pinnedOther, "a different digest must give a different pool lock");
  });

  it("a tape hop that does not recreate the next tip lock is rejected", () => {
    const { chain, wallet, old } = buildChain();
    const hop = chain.hops.find((h) => h.role === "tape" && h.index === 0)!;
    const tx = decodeTransaction(hop.raw);
    if (typeof tx === "string") throw new Error(tx);
    // Model the tip as some other link in the chain. The covenant compares output 1
    // against the successor of whatever lock is actually being spent, so this must
    // fail - that is what stops the digest being swapped mid-tape.
    const wrong = tapeTipLockChain(new Uint8Array(32).fill(0x77), 18)[0]!;
    const sourceOutputs = tapeSourceOutputs({ q0: 0, old, wallet, prevTape: BigInt(TAPE_VALUE), tipLock: wrong });
    sourceOutputs[sourceOutputs.length - 1] = { lockingBytecode: wrong, valueSatoshis: BigInt(TAPE_VALUE) };
    const r = createVirtualMachineBch2026(true).verify({ transaction: tx, sourceOutputs });
    assert.notEqual(r, true, "spending a foreign tip lock must not verify");
  });
});

/**
 * Envelope A and B batching: N notes walked on chain in ONE transaction.
 *
 * Until now B could walk exactly one note, because the audited kernel reads both
 * nullifier roots at absolute index 0 and a transaction has one such pair. The
 * step kernel bakes the roots in instead, so N of them coexist — and the covenant
 * pins each one by index, which is what stops a prover from simply omitting them.
 * That pinning is the difference between "the kernels can be there" and "the
 * kernels must be there"; plain option A taught that lesson the hard way.
 *
 * These run the real 2026 VM over a whole transaction built by
 * `compileCovenantSuccessor`, not a hand-assembled one.
 */
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { createVirtualMachineBch2026, decodeTransaction } from "@bitauth/libauth";
import { compileCovenantSuccessor } from "../src/chain/covenant-spend.ts";
import { poolLockP2sh32 } from "../src/chain/covenant-p2s.ts";
import { runBatchSuccessor } from "../src/pool/mix-successor.ts";
import { stepPlan, compileNoteAuthStepLockP2sh32 } from "../src/chain/note-auth-step-kernel.ts";
import { compileNoteAuthLockP2sh32 } from "../src/chain/note-auth-kernel.ts";
import { encodePublicPaa1, utxoValueFor } from "../src/pool/state.ts";
import { compileFriQueryLockP2sh32, FRI_KERNEL_INPUTS } from "../src/chain/fri-kernel.ts";
import {
  compileCqzLockP2sh32,
  compileSlotsLockP2sh32,
  SLOT_KERNEL_COUNT,
  SLOT_KERNEL_COUNT_CONSENSUS,
  SLOTS_PER_KERNEL,
} from "../src/chain/air-cqz.ts";
import { compileFoldLockP2sh32, foldKernelCount, foldQueriesPerKernel } from "../src/chain/fold-kernel.ts";
import { compileGrindLockP2sh32 } from "../src/chain/grind-kernel.ts";
import { compileAlgebraicCLockP2sh32 } from "../src/chain/algebraic-c-kernel.ts";
import { createLabWallet, p2pkhLockingOf } from "../src/chain/wallet.ts";

/**
 * Envelope B is the 36-orbit completeness object. The 1-note successor is a
 * standard-size tx; an 8-note batch currently is too. Negative tests still use
 * standard=false so a size reject cannot masquerade as a script fail.
 * vm-verifier.ts uses standard iff slots <= 4.
 */
/** true only when the VM accepted; otherwise the reason, for asserting on it. */
function verdict(
  transaction: unknown,
  sourceOutputs: unknown,
  standard = false,
): true | string {
  const r = createVirtualMachineBch2026(standard).verify({ transaction, sourceOutputs } as never);
  if (r === true) return true;
  const msg = String(r);
  if (/maximum standard byte length/.test(msg)) {
    throw new Error(`verified in the wrong mode - B is non-standard: ${msg}`);
  }
  return msg;
}

const CAT = new Uint8Array(32).fill(0x33);
const POOL = "33".repeat(32);
const KERNEL = "cc".repeat(32);
const FEE = "ee".repeat(32);
// createLabWallet() makes a RANDOM key per call, so the funder input must be
// signed by and paid back to the SAME wallet object, or the P2PKH check fails.
const WALLET = createLabWallet();
const KERNEL_SATS = 1000n;
const SLOTS = SLOT_KERNEL_COUNT_CONSENSUS;
const FOLDS = foldKernelCount(SLOTS);

/**
 * Envelope A is standard-size with 4 R-slots; B is consensus with 36. Both take
 * the same step kernels - only the slot count, the envelope and therefore the VM
 * mode differ. vm-verifier.ts:257: standard iff slots <= SLOT_KERNEL_COUNT.
 */
type Env = { slots: number; envelope: "standard" | "consensus"; standard: boolean };
const ENV_A: Env = { slots: SLOT_KERNEL_COUNT, envelope: "standard", standard: true };
const ENV_B: Env = { slots: SLOTS, envelope: "consensus", standard: false };

function buildFor(env: Env, noteCount: number) {
  const folds = foldKernelCount(env.slots);
  const b = runBatchSuccessor({ depositCount: Math.max(6, noteCount), noteCount });
  // stepPlan sorts by nullifier and threads prevNf; runBatchSuccessor sorts the
  // same way, so newState.nullifierRoot equals the plan's last root.
  const plan = stepPlan({
    oldNfRoot: b.oldState.nullifierRoot,
    poolInstanceId: b.oldState.poolInstanceId,
    spends: b.spends,
  });
  const roots = plan.roots;
  const stepSpends = plan.spends;
  const stepLocks = stepSpends.map((s) =>
    compileNoteAuthStepLockP2sh32(s.rIn, s.rOut, s.prevNf),
  );
  const finalNfRoot = roots[noteCount]!;
  const nExtras = 3 + folds + env.slots + noteCount;
  const tx = compileCovenantSuccessor({
    pool: {
      tx_hash: POOL,
      tx_pos: 0,
      value: utxoValueFor(b.oldState),
      category: CAT,
      commitment: encodePublicPaa1(b.oldState),
    },
    newState: b.newState,
    statement: b.statement,
    proof: b.proof,
    lockKind: "p2sh32",
    envelope: env.envelope,
    slotKernels: env.slots,
    stepSpends,
    finalNfRoot,
    // BIND_PAA1 checks withdrawalCount delta == outputCount - 2, so a batch of N
    // needs N payout outputs plus a change output - hence the fee utxo.
    extraPayouts: b.payouts.map((p) => ({ lockingBytecode: p.lockingBytecode, sats: p.sats })),
    wallet: WALLET,
    feeUtxo: { tx_hash: FEE, tx_pos: 0, value: 1_000_000 },
    kernelUtxos: Array.from({ length: FRI_KERNEL_INPUTS }, (_, i) => ({ tx_hash: KERNEL, tx_pos: i, value: 1000 })),
    extraKernels: Array.from({ length: nExtras }, (_, i) => ({
      tx_hash: KERNEL,
      tx_pos: FRI_KERNEL_INPUTS + i,
      value: 1000,
    })),
  });
  return { b, roots, stepSpends, stepLocks, finalNfRoot, tx, noteCount, env, folds };
}

function sourceOutputsFor(built: ReturnType<typeof buildFor>, stepLocks: Uint8Array[]) {
  return [
    {
      lockingBytecode: poolLockP2sh32({
        slotKernels: built.env.slots,
        finalNfRoot: built.finalNfRoot,
        stepLocks,
      }),
      valueSatoshis: BigInt(utxoValueFor(built.b.oldState)),
      token: {
        amount: 0n,
        category: CAT,
        nft: {
          capability: "mutable" as const,
          commitment: encodePublicPaa1(built.b.oldState),
        },
      },
    },
    ...Array.from({ length: FRI_KERNEL_INPUTS }, (_, i) => ({
      lockingBytecode: compileFriQueryLockP2sh32(i),
      valueSatoshis: KERNEL_SATS,
    })),
    { lockingBytecode: compileCqzLockP2sh32(), valueSatoshis: KERNEL_SATS },
    { lockingBytecode: compileGrindLockP2sh32(), valueSatoshis: KERNEL_SATS },
    { lockingBytecode: compileAlgebraicCLockP2sh32(), valueSatoshis: KERNEL_SATS },
    ...Array.from({ length: built.folds }, (_, f) => {
      const nFold = foldQueriesPerKernel(built.env.slots);
      return {
        lockingBytecode: compileFoldLockP2sh32(nFold, f * nFold),
        valueSatoshis: KERNEL_SATS,
      };
    }),
    ...Array.from({ length: built.env.slots }, (_, i) => {
      const n = built.env.slots > SLOT_KERNEL_COUNT ? SLOTS_PER_KERNEL : 1;
      return {
        lockingBytecode: compileSlotsLockP2sh32(i * n, n),
        valueSatoshis: KERNEL_SATS,
      };
    }),
    ...stepLocks.map((l) => ({ lockingBytecode: l, valueSatoshis: KERNEL_SATS })),
    // the funder input that pays the fee and receives the change output
    {
      lockingBytecode: p2pkhLockingOf(WALLET),
      valueSatoshis: 1_000_000n,
    },
  ];
}

describe("envelope B: N notes walked on chain in one consensus transaction", () => {
  it("the step roots close on the batch's new nullifier root", () => {
    const built = buildFor(ENV_B, 3);
    assert.deepEqual(
      built.roots[3],
      built.b.newState.nullifierRoot,
      "R_3 must be the state's new root",
    );
  });

  it("a 3-note batch verifies on the 2026 VM", () => {
    const built = buildFor(ENV_B, 3);
    const tx = decodeTransaction(built.tx.raw);
    if (typeof tx === "string") throw new Error(tx);
    const sourceOutputs = sourceOutputsFor(built, built.stepLocks);
    assert.equal(tx.inputs.length, sourceOutputs.length, "input count must line up");
    assert.equal(verdict(tx, sourceOutputs, built.env.standard), true, "the batched consensus transaction must verify");
  });

  it("the covenant REQUIRES the step kernels — dropping one is rejected", () => {
    const built = buildFor(ENV_B, 3);
    const tx = decodeTransaction(built.tx.raw);
    if (typeof tx === "string") throw new Error(tx);
    // Same transaction, but the pool is locked to a covenant that pins only two
    // steps. The input count check and the per-index pins must both object.
    const short = sourceOutputsFor(built, built.stepLocks.slice(0, 2));
    assert.notEqual(
      verdict(tx, short, built.env.standard),
      true,
      "a covenant pinning fewer steps must not accept this transaction",
    );
  });

  it("swapping two step locks is rejected — order is pinned by index", () => {
    const built = buildFor(ENV_B, 3);
    const tx = decodeTransaction(built.tx.raw);
    if (typeof tx === "string") throw new Error(tx);
    const swapped = [built.stepLocks[1]!, built.stepLocks[0]!, built.stepLocks[2]!];
    assert.notEqual(
      verdict(tx, sourceOutputsFor(built, swapped), built.env.standard),
      true,
      "the covenant pins each step at its own index",
    );
  });

  it("a batched B drops the audited single-note kernel", () => {
    const built = buildFor(ENV_B, 3);
    const withSteps = poolLockP2sh32({
      slotKernels: SLOTS,
      finalNfRoot: built.finalNfRoot,
      stepLocks: built.stepLocks,
    });
    const plain = poolLockP2sh32({ slotKernels: SLOTS });
    assert.notDeepEqual(withSteps, plain, "a batched covenant must differ from FRI9's");
    // and the transaction must not be carrying the audited lock anywhere
    const noteLock = Buffer.from(compileNoteAuthLockP2sh32()).toString("hex");
    const outs = sourceOutputsFor(built, built.stepLocks);
    assert.equal(
      outs.some((o) => Buffer.from(o.lockingBytecode).toString("hex") === noteLock),
      false,
      "the audited kernel must be absent from a batched B",
    );
  });

  it("eight notes also fit and verify, well inside the 1 MB envelope", () => {
    const built = buildFor(ENV_B, 8);
    const tx = decodeTransaction(built.tx.raw);
    if (typeof tx === "string") throw new Error(tx);
    assert.equal(
      verdict(tx, sourceOutputsFor(built, built.stepLocks), true),
      true,
      "8 notes in one standard transaction must verify",
    );
    assert.ok(built.tx.txBytes <= 100_000, `8-note B must fit one standard tx (${built.tx.txBytes})`);
    assert.ok(built.tx.txBytes < 1_000_000, `B stays under 1 MB (${built.tx.txBytes})`);
  });

  it("NON-BATCHED: a 1-note batch is the same path and still verifies", () => {
    const built = buildFor(ENV_B, 1);
    const tx = decodeTransaction(built.tx.raw);
    if (typeof tx === "string") throw new Error(tx);
    assert.equal(built.stepSpends.length, 1);
    assert.deepEqual(built.stepSpends[0]!.prevNf, new Uint8Array(32));
    assert.equal(
      verdict(tx, sourceOutputsFor(built, built.stepLocks), built.env.standard),
      true,
      "N=1 must verify through the batch path too",
    );
  });

  it("the plan's final root is the state's new nullifier root", () => {
    for (const n of [1, 3]) {
      const built = buildFor(ENV_B, n);
      assert.deepEqual(
        built.roots[n],
        built.b.newState.nullifierRoot,
        `N=${n}: sorted plan must land on the state's root`,
      );
    }
  });

  it("FRI9's unbatched covenant is untouched", () => {
    // No stepLocks, no finalNfRoot: must be exactly the lock that is landed today.
    assert.deepEqual(
      poolLockP2sh32({ slotKernels: SLOTS }),
      poolLockP2sh32({ slotKernels: SLOTS, stepLocks: [] }),
      "an empty step list must change nothing",
    );
  });
});

describe("envelope A: the same step kernels in a standard 100 KB transaction", () => {
  it("a 3-note batch verifies in STANDARD mode", () => {
    const built = buildFor(ENV_A, 3);
    const tx = decodeTransaction(built.tx.raw);
    if (typeof tx === "string") throw new Error(tx);
    const outs = sourceOutputsFor(built, built.stepLocks);
    assert.equal(tx.inputs.length, outs.length, "input count must line up");
    assert.ok(built.tx.txBytes <= 100_000, `A must stay standard-size (${built.tx.txBytes})`);
    assert.equal(
      verdict(tx, outs, built.env.standard),
      true,
      "a batched standard transaction must verify",
    );
  });

  it("the covenant pins A's steps too — dropping one is rejected", () => {
    const built = buildFor(ENV_A, 3);
    const tx = decodeTransaction(built.tx.raw);
    if (typeof tx === "string") throw new Error(tx);
    assert.notEqual(
      verdict(tx, sourceOutputsFor(built, built.stepLocks.slice(0, 2)), built.env.standard),
      true,
      "a covenant pinning fewer steps must not accept this transaction",
    );
  });

  it("so A is no longer the envelope that cannot walk a note", () => {
    const one = buildFor(ENV_A, 1);
    const built = buildFor(ENV_A, 3);
    assert.ok(built.tx.txBytes > one.tx.txBytes, "a batched A is larger than the unbatched one");
    assert.ok(built.tx.txBytes <= 100_000, "and still standard");
  });
});

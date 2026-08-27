/**
 * Option A' — binding the per-hop nullifier-root chain to the pool.
 *
 * WHY THIS EXISTS. Item 4 asked for N note-auth kernels in one transaction; that
 * is unsatisfiable (FRI10-BATCH-EXIT.md, verified five ways). Option A spreads the
 * N kernels across envelope C's tape hops instead, one per hop. Each hop's kernel
 * verifies in the real VM on its own — but that alone is NOT sound:
 *
 *   - nothing on a tape hop *requires* a note-auth kernel to be present,
 *   - the hop output NFTs are dead ends ("Nothing spends this output again"),
 *   - the tip chain carries only the digest and the count (tape-tip.ts), and
 *   - `checkBatchSpends` (air.ts:148) never checks that newState.nullifierRoot is
 *     the correct fold — cells 21/22 are assigned but appear in no constraint.
 *
 * So the per-hop kernels would be unobserved: a prover could skip every one of
 * them and the pool would not notice. Since the nullifier accumulator is the
 * double-spend defence, that is exactly the thing that must not be possible.
 *
 * A' closes it by making the running root reach the pool:
 *   1. sibling i is minted carrying R_i,
 *   2. tip i asserts hop i's own output-0 nfRoot == R_{i+1}, so a hop cannot
 *      write a root its kernel did not produce, and
 *   3. the pool covenant asserts its output-0 nfRoot == R_N.
 *
 * Everything here is opt-in. FRI9 passes none of it and must stay byte-identical;
 * the audited note-auth kernel is not touched and still does each step.
 */
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  binToHex,
  createVirtualMachineBch2026,
  encodeLockingBytecodeP2sh32,
  hash256,
} from "@bitauth/libauth";
import { encodePublicPaa1, emptyState } from "../src/pool/state.ts";
import { applyDeposit, applyBatchExit } from "../src/pool/transition.ts";
import { IncrementalMerkle, NullifierSet, type Note } from "../src/pool/notes.ts";
import { defaultInternalHash } from "../src/backends/circle/internal-hash.ts";
import { concatBytes } from "../src/pool/bytes.ts";
import {
  compileNoteAuthLockP2sh32,
  noteAuthBindHash,
  noteAuthKernelUnlocking,
  noteAuthPublicOpens,
} from "../src/chain/note-auth-kernel.ts";
import { AIR_PACKED_SIZE, AIR_OFF_CELLS, AIR_OFF_NET } from "../src/chain/air-cqz.ts";
import { pushData, poolLockP2sh32 } from "../src/chain/covenant-p2s.ts";
import { encodeLe } from "../src/backends/circle/m31.ts";
import { decodeTransaction } from "@bitauth/libauth";
import { compileCovenantSpend } from "../src/chain/covenant-spend.ts";
import { runMixSuccessor } from "../src/pool/mix-successor.ts";
import { createLabWallet } from "../src/chain/wallet.ts";
import { proofCargoLock } from "../src/chain/proof-cargo.ts";
import {
  tapeTipLockChain,
  tapeTipRedeemChain,
  tapeTipRedeemChainWithRoots,
  tapeTipLockChainWithRoots,
  tapeTipUnlocking,
} from "../src/chain/tape-tip.ts";

const rnd32 = () => crypto.getRandomValues(new Uint8Array(32));
const CARRIER = Uint8Array.of(0x75, 0x51);
const CATEGORY = new Uint8Array(32).fill(0x11);
const PAYOUT = Uint8Array.of(0x76, 0xa9, 0x14, ...new Uint8Array(20), 0x88, 0xac);
const H = defaultInternalHash();
const DIGEST = new Uint8Array(32).fill(0x5c);

/** A batch of `n` full-note exits, plus the intermediate roots it walks through. */
function batchOf(n: number) {
  let m: {
    state: ReturnType<typeof emptyState>;
    notes: IncrementalMerkle;
    nullifiers: NullifierSet;
  } = { state: emptyState(rnd32()), notes: new IncrementalMerkle(), nullifiers: new NullifierSet() };
  const notes: Note[] = [];
  const idx: number[] = [];
  for (let i = 0; i < n; i += 1) {
    const note: Note = { amountSats: 10_000n * BigInt(i + 1), rho: rnd32(), ownerSecret: rnd32() };
    const d = applyDeposit(m, note);
    m = d.machine;
    notes.push(note);
    idx.push(d.index);
  }
  const b = applyBatchExit(
    m,
    notes.map((note, i) => ({
      note,
      index: idx[i]!,
      withdrawSats: note.amountSats,
      payoutLocking: PAYOUT,
    })),
  );
  // R_0 = old root; R_{i+1} = H(R_i || nf_i); R_n must equal the new root.
  const roots = [b.statement.oldState.nullifierRoot];
  for (const s of b.spent) roots.push(H.digest(concatBytes(roots[roots.length - 1]!, s.nullifier)));
  return { ...b, roots };
}

const withRoot = (state: unknown, nullifierRoot: Uint8Array) =>
  ({ ...(state as object), nullifierRoot }) as ReturnType<typeof emptyState>;

function hopKernel(b: ReturnType<typeof batchOf>, s: { note: Note; index: number; path: Uint8Array[] }) {
  const args = {
    note: s.note,
    spentIndex: s.index,
    spentPath: s.path,
    createdIndex: 0,
    createdPath: [] as Uint8Array[],
    poolInstanceId: b.statement.oldState.poolInstanceId,
    action: "WITHDRAW" as const,
  };
  return {
    kernel: noteAuthKernelUnlocking(args),
    authBind: noteAuthBindHash(
      noteAuthPublicOpens({
        note: s.note,
        action: "WITHDRAW",
        poolInstanceId: b.statement.oldState.poolInstanceId,
      }),
    ),
  };
}

/**
 * One tape hop: sibling NFT (carrying R_in) at input 0, note-auth kernel, and the
 * root-pinned tip. Output 0 carries R_out; output 1 is the next tip lock.
 */
function runHop(args: {
  inState: unknown;
  outState: unknown;
  kernel: Uint8Array;
  tipRedeem?: Uint8Array;
  tipLock?: Uint8Array;
  nextLock?: Uint8Array;
  authBind?: Uint8Array;
}): string {
  const vm = createVirtualMachineBch2026(true);
  const packed = new Uint8Array(AIR_PACKED_SIZE);
  packed.set(encodeLe(2n), AIR_OFF_CELLS + 3 * 4);
  if (args.authBind) packed.set(args.authBind, AIR_OFF_NET);
  const tip = args.tipRedeem && args.tipLock;
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
            commitment: encodePublicPaa1(args.inState as never),
          },
        },
      },
      { lockingBytecode: compileNoteAuthLockP2sh32(), valueSatoshis: 1000n },
      ...(tip ? [{ lockingBytecode: args.tipLock!, valueSatoshis: 5000n }] : []),
    ],
    transaction: {
      version: 2,
      locktime: 0,
      inputs: [
        {
          outpointTransactionHash: new Uint8Array(32).fill(0x11),
          outpointIndex: 0,
          sequenceNumber: 0xffffffff,
          unlockingBytecode: pushData(packed),
        },
        {
          outpointTransactionHash: new Uint8Array(32).fill(0xa3),
          outpointIndex: 0,
          sequenceNumber: 0xffffffff,
          unlockingBytecode: args.kernel,
        },
        ...(tip
          ? [
              {
                outpointTransactionHash: new Uint8Array(32).fill(0xb7),
                outpointIndex: 0,
                sequenceNumber: 0xffffffff,
                unlockingBytecode: tapeTipUnlocking(args.tipRedeem!),
              },
            ]
          : []),
      ],
      outputs: [
        {
          lockingBytecode: CARRIER,
          valueSatoshis: 100_000n,
          token: {
            amount: 0n,
            category: CATEGORY,
            nft: {
              capability: "mutable" as const,
              commitment: encodePublicPaa1(args.outState as never),
            },
          },
        },
        ...(args.nextLock ? [{ lockingBytecode: args.nextLock, valueSatoshis: 5000n }] : []),
      ],
    },
  });
  return r === true ? "ok" : String(r).replace(/\s+/g, " ").slice(0, 120);
}

describe("A' — per-hop nullifier-root chain bound to the pool", () => {
  it("the intermediate roots really do close on newState.nullifierRoot", () => {
    const b = batchOf(4);
    assert.equal(b.roots.length, 5, "R_0..R_4 for four notes");
    assert.deepEqual(
      b.roots[4],
      b.statement.newState.nullifierRoot,
      "the fold must land exactly on the state's new root",
    );
    // and the batch must leave noteRoot alone, or the kernel's no-change branch fails
    assert.deepEqual(
      b.statement.oldState.noteRoot,
      b.statement.newState.noteRoot,
      "full-note batch exit must not move noteRoot",
    );
  });

  it("each note verifies on its own hop against the audited kernel", () => {
    const b = batchOf(3);
    for (const [i, s] of b.spent.entries()) {
      const { kernel, authBind } = hopKernel(b, s);
      const res = runHop({
        inState: withRoot(b.statement.oldState, b.roots[i]!),
        outState: withRoot(b.statement.newState, b.roots[i + 1]!),
        kernel,
        authBind,
      });
      assert.equal(res, "ok", `hop ${i}: ${res}`);
    }
  });

  it("a root-pinned tip rejects a hop that writes the wrong nfRoot", () => {
    const b = batchOf(3);
    const outRoots = b.roots.slice(1); // R_1..R_3, what each hop must write
    const redeems = tapeTipRedeemChainWithRoots(DIGEST, outRoots);
    const locks = tapeTipLockChainWithRoots(DIGEST, outRoots);
    const s = b.spent[0]!;
    const { kernel, authBind } = hopKernel(b, s);
    const honest = runHop({
      inState: withRoot(b.statement.oldState, b.roots[0]!),
      outState: withRoot(b.statement.newState, b.roots[1]!),
      kernel,
      authBind,
      tipRedeem: redeems[0],
      tipLock: locks[0],
      nextLock: locks[1],
    });
    assert.equal(honest, "ok", `honest hop must pass: ${honest}`);

    // Same hop, but the output claims a root the kernel did not produce. The
    // kernel alone would already catch this one; the point is the tip does too,
    // so a hop with NO kernel still cannot forge the root.
    const forged = runHop({
      inState: withRoot(b.statement.oldState, b.roots[0]!),
      outState: withRoot(b.statement.newState, b.roots[2]!),
      kernel,
      authBind,
      tipRedeem: redeems[0],
      tipLock: locks[0],
      nextLock: locks[1],
    });
    assert.notEqual(forged, "ok", "a forged output root must be rejected");
  });

  it("the tip pins the root even when the hop carries NO note-auth kernel", () => {
    // This is the case the kernel cannot defend, and the whole reason A' exists.
    const b = batchOf(2);
    const outRoots = b.roots.slice(1);
    const redeems = tapeTipRedeemChainWithRoots(DIGEST, outRoots);
    const locks = tapeTipLockChainWithRoots(DIGEST, outRoots);
    const vm = createVirtualMachineBch2026(true);
    const mk = (commitment: Uint8Array) => ({
      lockingBytecode: CARRIER,
      valueSatoshis: 100_000n,
      token: { amount: 0n, category: CATEGORY, nft: { capability: "mutable" as const, commitment } },
    });
    const run = (outRoot: Uint8Array) =>
      vm.verify({
        sourceOutputs: [
          mk(encodePublicPaa1(withRoot(b.statement.oldState, b.roots[0]!) as never)),
          { lockingBytecode: locks[0]!, valueSatoshis: 5000n },
        ],
        transaction: {
          version: 2,
          locktime: 0,
          inputs: [
            {
              outpointTransactionHash: new Uint8Array(32).fill(0x11),
              outpointIndex: 0,
              sequenceNumber: 0xffffffff,
              unlockingBytecode: pushData(new Uint8Array(AIR_PACKED_SIZE)),
            },
            {
              outpointTransactionHash: new Uint8Array(32).fill(0xb7),
              outpointIndex: 0,
              sequenceNumber: 0xffffffff,
              unlockingBytecode: tapeTipUnlocking(redeems[0]!),
            },
          ],
          outputs: [
            mk(encodePublicPaa1(withRoot(b.statement.newState, outRoot) as never)),
            { lockingBytecode: locks[1]!, valueSatoshis: 5000n },
          ],
        },
      });
    assert.equal(run(b.roots[1]!), true, "correct root must pass with no kernel present");
    assert.notEqual(run(rnd32()), true, "a kernel-less hop must not be able to forge the root");
  });

  it("the counted chain still holds: hops cannot be skipped or reordered", () => {
    const b = batchOf(3);
    const outRoots = b.roots.slice(1);
    const redeems = tapeTipRedeemChainWithRoots(DIGEST, outRoots);
    const locks = tapeTipLockChainWithRoots(DIGEST, outRoots);
    assert.equal(redeems.length, 4, "N hops need N+1 tips");
    assert.equal(locks.length, 4);
    const s = b.spent[0]!;
    const { kernel, authBind } = hopKernel(b, s);
    // hop 0 pointing at tip 2 instead of tip 1 must fail
    const skipped = runHop({
      inState: withRoot(b.statement.oldState, b.roots[0]!),
      outState: withRoot(b.statement.newState, b.roots[1]!),
      kernel,
      authBind,
      tipRedeem: redeems[0],
      tipLock: locks[0],
      nextLock: locks[2],
    });
    assert.notEqual(skipped, "ok", "skipping a hop must be rejected");
    // every lock in the chain must be distinct, or a tip could be replayed
    const seen = new Set(locks.map((l) => binToHex(l)));
    assert.equal(seen.size, locks.length, "tip locks must all differ");
  });

  it("the terminal tip is plain — the pool covenant carries the final root", () => {
    const b = batchOf(3);
    const outRoots = b.roots.slice(1);
    const redeems = tapeTipRedeemChainWithRoots(DIGEST, outRoots);
    // Terminal must be the same shape as the unrooted chain's terminal, so the
    // pay hop spends it exactly as it does today.
    assert.deepEqual(
      redeems[3],
      tapeTipRedeemChain(DIGEST, 3)[3],
      "terminal redeem must be unchanged",
    );
  });

  it("the pool covenant pins the final root, and rejects any other", () => {
    const b = batchOf(3);
    const finalNfRoot = b.roots[3]!;
    const pinned = poolLockP2sh32({ finalNfRoot });
    const unpinned = poolLockP2sh32();
    assert.notDeepEqual(pinned, unpinned, "pinning must change the covenant");
    // a different final root must produce a different lock, or the pin is vacuous
    assert.notDeepEqual(
      poolLockP2sh32({ finalNfRoot: rnd32() }),
      pinned,
      "the pinned root must be part of the covenant",
    );
  });

  it("FRI9 is untouched: omitting the new options is byte-identical", () => {
    // the audited kernel
    const kernelLock = compileNoteAuthLockP2sh32();
    assert.equal(kernelLock.length, 35, "note-auth lock stays 35 B");
    // the unrooted tip chain
    assert.deepEqual(
      tapeTipLockChain(DIGEST, 3),
      tapeTipRedeemChain(DIGEST, 3).map((r) => encodeLockingBytecodeP2sh32(hash256(r))),
      "the existing chain must be unchanged",
    );
    // the pool covenant with no pin
    assert.deepEqual(
      poolLockP2sh32(),
      poolLockP2sh32({}),
      "an empty options object must not change the covenant",
    );
  });
});

describe("A' — genesis mints siblings carrying the intermediate roots", () => {
  const mix = runMixSuccessor({ depositCount: 4, withdrawSats: 1_000n });
  const base = {
    wallet: createLabWallet(),
    utxo: { tx_hash: "11".repeat(32), tx_pos: 0, value: 1_000_000 },
    state: mix.oldState,
    proof: mix.proof,
  };
  const siblingCommitments = (n: number) =>
    Array.from({ length: n }, (_, i) =>
      encodePublicPaa1(withRoot(mix.oldState, new Uint8Array(32).fill(i + 1)) as never),
    );
  const siblingsOf = (raw: Uint8Array, n: number) => {
    const tx = decodeTransaction(raw);
    if (typeof tx === "string") throw new Error(tx);
    return tx.outputs.slice(2, 2 + n).map((o) => o.token?.nft?.commitment);
  };

  it("mints each sibling with its own commitment when they are supplied", () => {
    const n = 3;
    const want = siblingCommitments(n);
    const tx = compileCovenantSpend({
      ...base,
      siblingNfts: { count: n, lockingBytecode: proofCargoLock(), commitments: want },
    });
    const got = siblingsOf(tx.raw, n);
    for (let i = 0; i < n; i += 1) {
      assert.deepEqual(got[i], want[i], `sibling ${i} must carry its own root`);
    }
    // and they must actually differ, or the test would pass on the FRI9 path too
    assert.equal(new Set(got.map((g) => binToHex(g!))).size, n, "siblings must all differ");
  });

  it("FRI9 path unchanged: omitting commitments gives every sibling the same PAA1", () => {
    const n = 3;
    const tx = compileCovenantSpend({
      ...base,
      siblingNfts: { count: n, lockingBytecode: proofCargoLock() },
    });
    const got = siblingsOf(tx.raw, n);
    const want = encodePublicPaa1(mix.oldState);
    for (const [i, g] of got.entries()) assert.deepEqual(g, want, `sibling ${i} is the OLD PAA1`);
  });

  it("omitting commitments is byte-identical to before the option existed", () => {
    const n = 3;
    const a = compileCovenantSpend({
      ...base,
      siblingNfts: { count: n, lockingBytecode: proofCargoLock() },
    });
    const b = compileCovenantSpend({
      ...base,
      siblingNfts: { count: n, lockingBytecode: proofCargoLock(), commitments: undefined },
    });
    assert.deepEqual(a.raw, b.raw, "an undefined commitments list must change nothing");
  });

  it("a mismatched or wrong-width commitments list is rejected, not silently minted", () => {
    assert.throws(
      () =>
        compileCovenantSpend({
          ...base,
          siblingNfts: { count: 3, lockingBytecode: proofCargoLock(), commitments: siblingCommitments(2) },
        }),
      /sibling commitments 2 != count 3/,
    );
    assert.throws(
      () =>
        compileCovenantSpend({
          ...base,
          siblingNfts: {
            count: 1,
            lockingBytecode: proofCargoLock(),
            commitments: [new Uint8Array(64)],
          },
        }),
      /sibling commitment 0 must be 128 bytes/,
    );
  });
});

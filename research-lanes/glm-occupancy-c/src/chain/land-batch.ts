/**
 * Land an N-note batch exit on envelope B, walked on chain by step kernels.
 *
 * Separate from `land-envelopes.ts` on purpose: that file lands the FRI9
 * single-note path that is already on chain, and it stays byte-identical. This is
 * the batch path and it is opt-in.
 *
 * Shape, and why each piece is where it is:
 *
 *   genesis   commits the pool covenant, so the step locks and the landing root
 *             R_N have to be known HERE - the successor cannot spend what genesis
 *             did not commit to.
 *   kernels   one carrier per step, funded after the slots, in the order
 *             `requireFriInputsAsm` pins them.
 *   successor spends the pool + 10 FRI + cqz/grind/algC + folds + slots + N steps
 *             + a funder input. The funder is not optional: BIND_PAA1 requires
 *             `withdrawalCount delta == outputCount - 2`, so a batch of N needs N
 *             payout outputs AND a change output.
 *
 * The audited note-auth kernel is absent from a batched B - its single
 * SHA256(oldRoot || nf) == newRoot step is exactly what N insertions cannot
 * satisfy - and `requireFriInputsAsm` drops it when step locks are present.
 *
 * `dryRun` compiles and validates everything without broadcasting. Use it first:
 * a failed run halfway through leaves genesis on chain and the funds spent.
 */
import { binToHex, hexToBin } from "@bitauth/libauth";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { runBatchSuccessor } from "../pool/mix-successor.ts";
import { circleFriPlugin } from "../backends/circle/plugin.ts";
import { encodePublicPaa1, utxoValueFor } from "../pool/state.ts";
import { loadLabWallet } from "./wallet.ts";
import { connectChipnet, listUnspent } from "./electrum.ts";
import { broadcastRetry, waitForTxid } from "./land-envelopes.ts";
import {
  compileCovenantSpend,
  compileCovenantSuccessor,
  compileFundVerifierKernels,
} from "./covenant-spend.ts";
import { compileTapeFunder } from "./chained.ts";
import { stepPlan, compileNoteAuthStepLockP2sh32 } from "./note-auth-step-kernel.ts";
import {
  compileCqzLockP2sh32,
  compileSlotsLockP2sh32,
  SLOT_KERNEL_COUNT,
  SLOT_KERNEL_COUNT_CONSENSUS,
  SLOTS_PER_KERNEL,
} from "./air-cqz.ts";
import { successorFeeCoinSats } from "./envelope.ts";
import { createVirtualMachineBch2026, decodeTransaction } from "@bitauth/libauth";
import { poolLockP2sh32 } from "./covenant-p2s.ts";
import { compileFriQueryLockP2sh32, FRI_KERNEL_INPUTS } from "./fri-kernel.ts";
import { compileFoldLockP2sh32, foldKernelCount, foldQueriesPerKernel } from "./fold-kernel.ts";
import { compileGrindLockP2sh32 } from "./grind-kernel.ts";
import { compileAlgebraicCLockP2sh32 } from "./algebraic-c-kernel.ts";
import { p2pkhLockingOf } from "./wallet.ts";

const FEE_NEED = 200_000;

/**
 * Envelope A and B both fit standard size now; Electrum relays both.
 */
export async function landBatch(args: {
  envelope: "standard" | "consensus";
  notes: number;
  scratch: string;
  dryRun?: boolean;
}): Promise<Record<string, unknown>> {
  const noteCount = args.notes;
  const consensus = args.envelope === "consensus";
  const slots = consensus ? SLOT_KERNEL_COUNT_CONSENSUS : SLOT_KERNEL_COUNT;
  const GENESIS_NEED = 400_000;
  if (noteCount < 1) throw new Error("need at least one note");

  const b = runBatchSuccessor({ depositCount: Math.max(6, noteCount), noteCount });
  const v = circleFriPlugin.verify(b.statement, b.proof);
  if (!v.ok) throw new Error(`proof does not verify off chain: ${v.reason}`);

  const plan = stepPlan({
    oldNfRoot: b.oldState.nullifierRoot,
    poolInstanceId: b.oldState.poolInstanceId,
    spends: b.spends,
  });
  const stepLocks = plan.spends.map((s) =>
    compileNoteAuthStepLockP2sh32(s.rIn, s.rOut, s.prevNf),
  );
  const finalNfRoot = plan.roots[noteCount]!;
  // If these disagree the successor cannot satisfy the covenant's pin, and the
  // failure would only show up after genesis is already on chain.
  if (binToHex(finalNfRoot) !== binToHex(b.newState.nullifierRoot)) {
    throw new Error("step plan root != state root (insertion order mismatch)");
  }

  const wallet = await loadLabWallet();
  const client = await connectChipnet();
  let step = "listunspent";
  const out: Record<string, unknown> = { envelope: `${args.envelope}-batch`, notes: noteCount };
  try {
    const utxos = await listUnspent(client, wallet.address);
    const sorted = [...utxos].sort((x, y) => y.value - x.value);
    const forGenesis = sorted.find((u) => u.value >= GENESIS_NEED);
    const forFee = sorted.find((u) => u !== forGenesis && u.value >= FEE_NEED);
    if (!forGenesis || !forFee) {
      return {
        ...out,
        ok: false,
        error: `need one utxo >= ${GENESIS_NEED} and another >= ${FEE_NEED}; have ${utxos.length}`,
        address: wallet.address,
      };
    }

    // Genesis wants a vout-0 input of a known size, same as landAB.
    step = "split";
    let picked = forGenesis;
    let prepTxid: string | undefined;
    if (picked.tx_pos !== 0 || picked.value > GENESIS_NEED + 50_000) {
      const split = compileTapeFunder({ wallet, utxo: picked, tapeSats: BigInt(GENESIS_NEED) });
      if (!args.dryRun) {
        prepTxid = (await broadcastRetry(client, split.raw, split.txid)).txid;
        await waitForTxid(client, split.txid);
      }
      picked = { tx_hash: split.txid, tx_pos: 0, value: GENESIS_NEED, height: 0 };
    }

    step = "genesis";
    const genesis = compileCovenantSpend({
      wallet,
      utxo: picked,
      state: b.oldState,
      proof: b.proof,
      lockKind: "p2sh32",
      envelope: args.envelope,
      slotKernels: slots,
      stepLocks,
      finalNfRoot,
    });
    out.genesisBytes = genesis.raw.length;
    if (!args.dryRun) {
      const id = (await broadcastRetry(client, genesis.raw, genesis.txid)).txid;
      await waitForTxid(client, id);
      out.genesis = id;
    }
    const genesisTxid = (out.genesis as string) ?? genesis.txid;

    step = "kernels";
    const funded = compileFundVerifierKernels(
      wallet,
      { tx_hash: genesisTxid, tx_pos: 1, value: genesis.changeValue ?? 0 },
      1_000,
      slots,
      successorFeeCoinSats(args.envelope),
      false,
      stepLocks,
    );
    out.kernelBytes = funded.raw.length;
    if (!args.dryRun) {
      const id = (await broadcastRetry(client, funded.raw, funded.txid)).txid;
      await waitForTxid(client, id);
      out.kernels = id;
    }

    step = "successor";
    const successor = compileCovenantSuccessor({
      wallet,
      pool: {
        tx_hash: genesisTxid,
        tx_pos: 0,
        value: utxoValueFor(b.oldState),
        category: hexToBin(picked.tx_hash),
        commitment: encodePublicPaa1(b.oldState),
      },
      newState: b.newState,
      statement: b.statement,
      proof: b.proof,
      lockKind: "p2sh32",
      envelope: args.envelope,
      slotKernels: slots,
      stepSpends: plan.spends,
      finalNfRoot,
      kernelUtxos: funded.fri,
      extraKernels: funded.extra,
      // N payouts + a change output, or BIND_PAA1's outputCount-2 rule fails.
      extraPayouts: b.payouts.map((p) => ({ lockingBytecode: p.lockingBytecode, sats: p.sats })),
      feeUtxo: { tx_hash: forFee.tx_hash, tx_pos: forFee.tx_pos, value: forFee.value },
    });
    out.successorBytes = successor.txBytes;
    out.stepInputs = stepLocks.length;

    // PRE-FLIGHT. Run the real 2026 VM over the compiled successor before any
    // broadcast. If the genesis covenant and the successor's redeem disagree,
    // this catches it here instead of after genesis is on chain and spent.
    const tx = decodeTransaction(successor.raw);
    if (typeof tx === "string") throw new Error(`decode successor: ${tx}`);
    const kSats = 1000n;
    const nFold = foldQueriesPerKernel(slots);
    const sourceOutputs = [
      {
        lockingBytecode: poolLockP2sh32({ slotKernels: slots, finalNfRoot, stepLocks }),
        valueSatoshis: BigInt(utxoValueFor(b.oldState)),
        token: {
          amount: 0n,
          category: hexToBin(picked.tx_hash),
          nft: { capability: "mutable" as const, commitment: encodePublicPaa1(b.oldState) },
        },
      },
      { lockingBytecode: compileFriQueryLockP2sh32(0), valueSatoshis: kSats + successorFeeCoinSats(args.envelope) },
      ...Array.from({ length: FRI_KERNEL_INPUTS - 1 }, (_, i) => ({
        lockingBytecode: compileFriQueryLockP2sh32(i + 1),
        valueSatoshis: kSats,
      })),
      { lockingBytecode: compileCqzLockP2sh32(), valueSatoshis: kSats },
      { lockingBytecode: compileGrindLockP2sh32(), valueSatoshis: kSats },
      { lockingBytecode: compileAlgebraicCLockP2sh32(), valueSatoshis: kSats },
      ...Array.from({ length: foldKernelCount(slots) }, (_, f) => ({
        lockingBytecode: compileFoldLockP2sh32(nFold, f * nFold),
        valueSatoshis: kSats,
      })),
      ...Array.from({ length: slots }, (_, i) => {
        const n = slots > SLOT_KERNEL_COUNT ? SLOTS_PER_KERNEL : 1;
        return { lockingBytecode: compileSlotsLockP2sh32(i * n, n), valueSatoshis: kSats };
      }),
      ...stepLocks.map((lock) => ({ lockingBytecode: lock, valueSatoshis: kSats })),
      { lockingBytecode: p2pkhLockingOf(wallet), valueSatoshis: BigInt(forFee.value) },
    ];
    if (tx.inputs.length !== sourceOutputs.length) {
      throw new Error(`pre-flight: ${tx.inputs.length} inputs vs ${sourceOutputs.length} source outputs`);
    }
    const vm = createVirtualMachineBch2026(true).verify({ transaction: tx, sourceOutputs });
    if (vm !== true) throw new Error(`pre-flight VM rejected the successor: ${String(vm).slice(0, 200)}`);
    out.preflight = "vm ok";
    mkdirSync(args.scratch, { recursive: true });
    writeFileSync(join(args.scratch, `batch-${args.envelope}-${noteCount}.hex`), binToHex(successor.raw));
    if (!args.dryRun) {
      const id = (await broadcastRetry(client, successor.raw, successor.txid)).txid;
      out.successor = id;
    }
    return { ...out, ok: true, dryRun: Boolean(args.dryRun) };
  } catch (e) {
    return { ...out, ok: false, step, error: e instanceof Error ? e.message : String(e) };
  } finally {
    client.close();
  }
}

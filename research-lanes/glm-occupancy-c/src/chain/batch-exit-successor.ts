/**
 * Lab compile of a batch-exit successor with on-chain step kernels.
 * Dummy UTXOs (same pattern as envelope-batch.test.ts). Not a Chipnet land.
 */
import { createVirtualMachineBch2026, decodeTransaction } from "@bitauth/libauth";
import { compileCovenantSuccessor } from "./covenant-spend.ts";
import { poolLockP2sh32 } from "./covenant-p2s.ts";
import { stepPlan, compileNoteAuthStepLockP2sh32 } from "./note-auth-step-kernel.ts";
import { compileFriQueryLockP2sh32, FRI_KERNEL_INPUTS } from "./fri-kernel.ts";
import {
  compileCqzLockP2sh32,
  compileSlotsLockP2sh32,
  SLOT_KERNEL_COUNT,
  SLOT_KERNEL_COUNT_CONSENSUS,
  SLOTS_PER_KERNEL,
} from "./air-cqz.ts";
import { compileFoldLockP2sh32, foldKernelCount, foldQueriesPerKernel } from "./fold-kernel.ts";
import { compileGrindLockP2sh32 } from "./grind-kernel.ts";
import { compileAlgebraicCLockP2sh32 } from "./algebraic-c-kernel.ts";
import { createLabWallet, p2pkhLockingOf } from "./wallet.ts";
import { encodePublicPaa1, utxoValueFor, type AnyAmountState } from "../pool/state.ts";
import type { Note } from "../pool/notes.ts";
import type { PoolStatement } from "../pool/statement.ts";
import type { TxEnvelope } from "./envelope.ts";
import { RELAY_STANDARD_TX_BYTES } from "./envelope.ts";

const POOL = "11".repeat(32);
const FEE = "22".repeat(32);
const KERNEL = "33".repeat(32);
const CAT = new Uint8Array(32).fill(0x11);
const KERNEL_SATS = 1000n;
const WALLET = createLabWallet();

export function slotsForEnvelope(envelope: TxEnvelope): number {
  return envelope === "standard" ? SLOT_KERNEL_COUNT : SLOT_KERNEL_COUNT_CONSENSUS;
}

export function compileBatchExitSuccessor(args: {
  envelope: TxEnvelope;
  oldState: AnyAmountState;
  newState: AnyAmountState;
  statement: PoolStatement;
  proof: Uint8Array;
  spends: ReadonlyArray<{ note: Note; index: number; path: Uint8Array[] }>;
  payouts: ReadonlyArray<{ lockingBytecode: Uint8Array; sats: bigint }>;
}): {
  envelope: TxEnvelope;
  slotKernels: number;
  stepN: number;
  txBytes: number;
  unlockingBytes: number;
  txid: string;
  standardAccepted: boolean;
  standardError: string | null;
} {
  const envelope: TxEnvelope = args.envelope === "chained" ? "consensus" : args.envelope;
  const slotKernels = slotsForEnvelope(envelope);
  const folds = foldKernelCount(slotKernels);
  const plan = stepPlan({
    oldNfRoot: args.oldState.nullifierRoot,
    poolInstanceId: args.oldState.poolInstanceId,
    spends: args.spends,
  });
  const stepSpends = plan.spends;
  const stepLocks = stepSpends.map((s) =>
    compileNoteAuthStepLockP2sh32(s.rIn, s.rOut, s.prevNf),
  );
  const finalNfRoot = plan.roots[stepSpends.length]!;
  const nExtras = 3 + folds + slotKernels + stepSpends.length;
  const measured = compileCovenantSuccessor({
    pool: {
      tx_hash: POOL,
      tx_pos: 0,
      value: utxoValueFor(args.oldState),
      category: CAT,
      commitment: encodePublicPaa1(args.oldState),
    },
    newState: args.newState,
    statement: args.statement,
    proof: args.proof,
    lockKind: "p2sh32",
    envelope,
    slotKernels,
    stepSpends,
    finalNfRoot,
    extraPayouts: args.payouts.map((p) => ({ lockingBytecode: p.lockingBytecode, sats: p.sats })),
    wallet: WALLET,
    feeUtxo: { tx_hash: FEE, tx_pos: 0, value: 1_000_000 },
    kernelUtxos: Array.from({ length: FRI_KERNEL_INPUTS }, (_, i) => ({
      tx_hash: KERNEL,
      tx_pos: i,
      value: 1000,
    })),
    extraKernels: Array.from({ length: nExtras }, (_, i) => ({
      tx_hash: KERNEL,
      tx_pos: FRI_KERNEL_INPUTS + i,
      value: 1000,
    })),
  });
  const tx = decodeTransaction(measured.raw);
  if (typeof tx === "string") throw new Error(tx);
  const nFold = foldQueriesPerKernel(slotKernels);
  const sourceOutputs = [
    {
      lockingBytecode: poolLockP2sh32({ slotKernels, finalNfRoot, stepLocks }),
      valueSatoshis: BigInt(utxoValueFor(args.oldState)),
      token: {
        amount: 0n,
        category: CAT,
        nft: { capability: "mutable" as const, commitment: encodePublicPaa1(args.oldState) },
      },
    },
    ...Array.from({ length: FRI_KERNEL_INPUTS }, (_, i) => ({
      lockingBytecode: compileFriQueryLockP2sh32(i),
      valueSatoshis: KERNEL_SATS,
    })),
    { lockingBytecode: compileCqzLockP2sh32(), valueSatoshis: KERNEL_SATS },
    { lockingBytecode: compileGrindLockP2sh32(), valueSatoshis: KERNEL_SATS },
    { lockingBytecode: compileAlgebraicCLockP2sh32(), valueSatoshis: KERNEL_SATS },
    ...Array.from({ length: folds }, (_, f) => ({
      lockingBytecode: compileFoldLockP2sh32(nFold, f * nFold),
      valueSatoshis: KERNEL_SATS,
    })),
    ...Array.from({ length: slotKernels }, (_, i) => {
      const n = slotKernels > SLOT_KERNEL_COUNT ? SLOTS_PER_KERNEL : 1;
      return { lockingBytecode: compileSlotsLockP2sh32(i * n, n), valueSatoshis: KERNEL_SATS };
    }),
    ...stepLocks.map((l) => ({ lockingBytecode: l, valueSatoshis: KERNEL_SATS })),
    { lockingBytecode: p2pkhLockingOf(WALLET), valueSatoshis: 1_000_000n },
  ];
  const std = createVirtualMachineBch2026(true).verify({ transaction: tx, sourceOutputs } as never);
  return {
    envelope,
    slotKernels,
    stepN: stepSpends.length,
    txBytes: measured.txBytes,
    unlockingBytes: measured.unlockingBytes,
    txid: measured.txid,
    standardAccepted: std === true,
    standardError: std === true ? null : String(std).slice(0, 240),
  };
}

export function assertBatchExitFitsStandard(shape: { txBytes: number; standardAccepted: boolean }): void {
  if (shape.txBytes > RELAY_STANDARD_TX_BYTES) {
    throw new Error(`batch-exit successor ${shape.txBytes} B exceeds standard ${RELAY_STANDARD_TX_BYTES}`);
  }
  if (!shape.standardAccepted) {
    throw new Error(`batch-exit successor standard=true rejected`);
  }
}

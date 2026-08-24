import {
  binToHex,
  encodeTransaction,
  generateTransaction,
  hashTransaction,
  hexToBin,
  walletTemplateP2pkhNonHd,
  walletTemplateToCompilerBCH,
} from "@bitauth/libauth";
import { encodePublicPaa1, encodeState, STATE_BASE_SATS, utxoValueFor, type AnyAmountState } from "../pool/state.ts";
import { concatBytes, isZero32 } from "../pool/bytes.ts";
import { LAB_PAYOUT_LOCKING } from "./payout.ts";
import { createLabWallet, p2pkhLockingOf, privateKeyOf, type LabWallet } from "./wallet.ts";
import { broadcast, connectChipnet, getTx, listUnspent } from "./electrum.ts";

async function sleep(ms: number): Promise<void> {
  await new Promise((r) => setTimeout(r, ms));
}

async function broadcastWithRetry(client: Awaited<ReturnType<typeof connectChipnet>>, rawHex: string): Promise<string> {
  let last: Error | undefined;
  for (let i = 0; i < 5; i += 1) {
    try {
      return await broadcast(client, rawHex);
    } catch (e) {
      last = e instanceof Error ? e : new Error(String(e));
      const msg = last.message.toLowerCase();
      if (!msg.includes("missing") && !msg.includes("orphan") && !msg.includes("bad-txns-inputs")) {
        throw last;
      }
      await sleep(1500 * (i + 1));
    }
  }
  throw last ?? new Error("broadcast retry exhausted");
}

async function waitForTx(client: Awaited<ReturnType<typeof connectChipnet>>, txid: string): Promise<void> {
  for (let i = 0; i < 8; i += 1) {
    try {
      await getTx(client, txid);
      return;
    } catch {
      await sleep(1000);
    }
  }
}
import {
  compilePoolCovenant,
  p2sUnlocking,
  p2sh32Unlocking,
  poolLockP2s,
  poolLockP2sFor,
  poolLockP2sh32,
} from "./covenant-p2s.ts";
import { decodeFriProof } from "../backends/circle/fri.ts";
import { decodeState } from "../pool/state.ts";
import { compileFriQueryLockP2sh32, FRI_KERNEL_INPUTS } from "./fri-kernel.ts";
import {
  DUST_SATS,
  successorFeeCoinSats,
  successorFeeSats,
  TAPE_HOP_OUT_SATS,
  type TxEnvelope,
} from "./envelope.ts";
import { packedAirCarrierUnlocking } from "./proof-cargo.ts";
import { tapeTipUnlocking } from "./tape-tip.ts";
import { collectFriOpenings, friShardUnlockings, openingPairsBlob, packedWithPairs, queryPairShard } from "./fri-openings.ts";
import {
  compileCqzLockP2sh32,
  compileSlotsLockP2sh32,
  cqzKernelUnlocking,
  AIR_PACKED_SIZE,
  encodeAirPacked,
  SLOT_KERNEL_COUNT,
  SLOT_KERNEL_COUNT_CONSENSUS,
  SLOTS_PER_KERNEL,
  slotsKernelUnlocking,
} from "./air-cqz.ts";
import { compileFoldLockP2sh32, foldKernelCount, foldKernelUnlocking, foldQueriesPerKernel, slotInputsCount } from "./fold-kernel.ts";
import { compileGrindLockP2sh32, grindKernelUnlocking } from "./grind-kernel.ts";
import { compileAlgebraicCLockP2sh32, algebraicCKernelUnlocking } from "./algebraic-c-kernel.ts";
import { compileNoteAuthStepLockP2sh32, noteAuthStepUnlocking } from "./note-auth-step-kernel.ts";
import {
  compileNoteAuthLockP2sh32,
  includeNoteAuth,
  noteAuthKernelUnlocking,
  noteAuthUnlockingFromProof,
  prefixExtraKernelCount,
} from "./note-auth-kernel.ts";
import type { PoolStatement } from "../pool/statement.ts";
import type { Note } from "../pool/notes.ts";

export type LockKind = "p2s" | "p2sh32";

export type MeasuredTx = {
  raw: Uint8Array;
  txid: string;
  txBytes: number;
  unlockingBytes: number;
  lockP2sBytes: number;
  lockP2sh32Bytes: number;
  proofBytes: number;
  proofSlotBytes: number;
  lockKind: LockKind;
  changeValue?: number;
};

export function proofSlot(proof: Uint8Array): Uint8Array {
  return proof;
}

function compiler() {
  return walletTemplateToCompilerBCH(walletTemplateP2pkhNonHd);
}

function lockOf(
  kind: LockKind,
  slotKernels = SLOT_KERNEL_COUNT,
  forceNoteAuth = false,
  tapeTipLock?: Uint8Array,
  finalNfRoot?: Uint8Array,
  stepLocks: readonly Uint8Array[] = [],
): Uint8Array {
  return kind === "p2s"
    ? poolLockP2sFor({ slotKernels, forceNoteAuth, tapeTipLock, finalNfRoot, stepLocks })
    : poolLockP2sh32({ slotKernels, forceNoteAuth, tapeTipLock, finalNfRoot, stepLocks });
}

function measureOf(
  raw: Uint8Array,
  unlockingBytes: number,
  proof: Uint8Array,
  lockKind: LockKind,
): MeasuredTx {
  return {
    raw,
    txid: hashTransaction(raw),
    txBytes: raw.length,
    unlockingBytes,
    lockP2sBytes: poolLockP2s().length,
    lockP2sh32Bytes: poolLockP2sh32().length,
    proofBytes: proof.length,
    proofSlotBytes: 0,
    lockKind,
  };
}

/**
 * Genesis: P2PKH funds a P2S / P2SH32 five-point cell.
 * NFT commitment is the 128-byte PAA1 state (Layla). Verify is the FRI-kernel
 * input on the successor — genesis only creates the cell.
 */
export function compileCovenantSpend(args: {
  wallet: LabWallet;
  utxo: { tx_hash: string; tx_pos: number; value: number };
  state: AnyAmountState;
  proof: Uint8Array;
  lockKind?: LockKind;
  slotKernels?: number;
  envelope?: TxEnvelope;
  /**
   * Envelope C: mint N sibling NFTs in the same (genesis) category, each holding
   * the OLD PAA1. Each tape hop spends one as input 0 so cqz's
   * bindPackedStmtToPaa1Asm finds a commitment there, and mutates it to NEW on
   * its own output 0. They land at vout 2..2+count-1; change stays at vout 1.
   */
  siblingNfts?: {
    count: number;
    lockingBytecode: Uint8Array;
    satsEach?: bigint;
    /**
     * Option A' (FRI10-BATCH-EXIT.md): mint sibling i carrying the intermediate
     * nullifier root R_i instead of the shared OLD PAA1, so hop i can advance
     * R_i -> R_{i+1} with its own note-auth kernel. Omit for FRI9, where every
     * sibling carries the same commitment and the tape moves no root.
     */
    commitments?: readonly Uint8Array[];
  };
  /**
   * Envelope C's pay hop runs 4 slots but still carries a note-auth kernel, so its
   * pool lock must expect one. Genesis commits the lock, so it has to be set here
   * too or the successor cannot spend what genesis created.
   */
  forceNoteAuth?: boolean;
  /** Envelope C: pin the terminal tape tip lock into the pool covenant here, at
   * genesis, so the pay hop cannot spend a tip committed to another digest. */
  tapeTipLock?: Uint8Array;
  /**
   * Option A' (FRI10-BATCH-EXIT.md): pin the batch's landing root R_N into the
   * pool covenant. Genesis is the only place this can be committed, since the
   * covenant is what the pool NFT is locked to.
   */
  finalNfRoot?: Uint8Array;
  /**
   * Option B: the per-note step-kernel locks the successor will carry. Genesis
   * commits the covenant, so the same list has to be known here or the
   * successor cannot spend what genesis created.
   */
  stepLocks?: readonly Uint8Array[];
}): MeasuredTx {
  const lockKind = args.lockKind ?? "p2sh32";
  const slotKernels =
    args.slotKernels ??
    (args.envelope === "consensus" ? SLOT_KERNEL_COUNT_CONSENSUS : SLOT_KERNEL_COUNT);
  const c = compiler();
  const data = { keys: { privateKeys: { key: privateKeyOf(args.wallet) } } };
  const siblingCount = args.siblingNfts?.count ?? 0;
  // A token output with a 128-byte commitment is ~210 B, so BCH dust is
  // ~3*(210+148) = ~1074 sats. 1000 drew "dust (code 64)" at genesis.
  const siblingSats = args.siblingNfts?.satsEach ?? 3_000n;
  const siblingCommitments = args.siblingNfts?.commitments;
  if (siblingCommitments) {
    if (siblingCommitments.length !== siblingCount) {
      throw new Error(
        `sibling commitments ${siblingCommitments.length} != count ${siblingCount}`,
      );
    }
    for (const [i, sc] of siblingCommitments.entries()) {
      if (sc.length !== 128) throw new Error(`sibling commitment ${i} must be 128 bytes`);
    }
  }
  // A 128-byte-commitment token output is ~170 B; 1200 only covers the base tx.
  const fee = 1_200n + BigInt(siblingCount) * 200n;
  const value = utxoValueFor(args.state);
  const change = BigInt(args.utxo.value) - value - fee - BigInt(siblingCount) * siblingSats;
  if (change < 546n) throw new Error("utxo too small for covenant spend");

  const commitment = encodePublicPaa1(args.state);
  if (commitment.length !== 128) throw new Error("PAA1 must be 128 bytes");

  const generated = generateTransaction({
    version: 2,
    locktime: 0,
    inputs: [
      {
        outpointIndex: args.utxo.tx_pos,
        outpointTransactionHash: hexToBin(args.utxo.tx_hash),
        sequenceNumber: 0xffffffff,
        unlockingBytecode: {
          compiler: c,
          script: "unlock",
          data,
          valueSatoshis: BigInt(args.utxo.value),
        },
      },
    ],
    outputs: [
      {
        lockingBytecode: lockOf(
          lockKind,
          slotKernels,
          args.forceNoteAuth ?? false,
          args.tapeTipLock,
          args.finalNfRoot,
          args.stepLocks ?? [],
        ),
        valueSatoshis: value,
        token: {
          amount: 0n,
          category: hexToBin(args.utxo.tx_hash),
          nft: { capability: "mutable", commitment },
        },
      },
      {
        lockingBytecode: { compiler: c, script: "lock", data },
        valueSatoshis: change,
      },
      ...Array.from({ length: siblingCount }, (_, i) => ({
        lockingBytecode: args.siblingNfts!.lockingBytecode,
        valueSatoshis: siblingSats,
        token: {
          amount: 0n,
          category: hexToBin(args.utxo.tx_hash),
          nft: {
            capability: "mutable" as const,
            commitment: args.siblingNfts!.commitments?.[i] ?? commitment,
          },
        },
      })),
    ],
  });
  if (!generated.success) {
    throw new Error(`covenant spend: ${JSON.stringify(generated.errors).slice(0, 500)}`);
  }
  const raw = encodeTransaction(generated.transaction);
  const measured = measureOf(raw, generated.transaction.inputs[0]!.unlockingBytecode.length, args.proof, lockKind);
  measured.changeValue = Number(change);
  return measured;
}

/**
 * Five-point successor: pool input 0 + FRI/fold/slot kernels.
 * Withdraws do **not** take a user P2PKH fee input (no relayer). Miner fee
 * comes from kernel-carrier sats. Deposits still need a funder for the net.
 */
export function compileCovenantSuccessor(args: {
  wallet?: LabWallet;
  feeUtxo?: { tx_hash: string; tx_pos: number; value: number };
  pool: {
    tx_hash: string;
    tx_pos: number;
    value: number | bigint;
    category: Uint8Array;
    commitment: Uint8Array;
  };
  newState: AnyAmountState;
  proof: Uint8Array;
  statement?: PoolStatement;
  lockKind?: LockKind;
  kernelUtxo?: { tx_hash: string; tx_pos: number; value: number };
  kernelUtxos?: Array<{ tx_hash: string; tx_pos: number; value: number }>;
  extraKernels?: Array<{ tx_hash: string; tx_pos: number; value: number }>;
  envelope?: TxEnvelope;
  slotKernels?: number;
  feeSats?: bigint;
  payoutLockingBytecode?: Uint8Array;
  extraPayouts?: Array<{ lockingBytecode: Uint8Array; sats: bigint }>;
  /** Last output (fee change). Default is a fresh P2PKH, not the funder. */
  changeLockingBytecode?: Uint8Array;
  /** Envelope C: spend the tape tip so a missing/wrong hop rejects the pay tx. */
  tapeUtxo?: { tx_hash: string; tx_pos: number; value: number };
  /** When false, input 0 is an AIR carrier (tape hop), not the pool. */
  includePool?: boolean;
  /** Real AIR-carrier UTXO for tape hops (tests may omit and use a dummy prevout). */
  carrierUtxo?: { tx_hash: string; tx_pos: number; value: number };
  /** First FRI query index for fold/slot kernels on this hop. */
  queryStart?: number;
  /** How many foldPair kernels to run (default from slotKernels). */
  foldQueries?: number;
  /** Opened note for the B note-auth kernel (required when slotKernels > 4). */
  note?: Note;
  /** Change note when the withdraw appends. */
  change?: Note;
  /** Match a genesis locked with forceNoteAuth (envelope C pay hop). */
  forceNoteAuth?: boolean;
  /**
   * Option A' (FRI10-BATCH-EXIT.md): this hop's own note walk. A batch spreads N
   * notes across N tape hops, and the published proof's single `auth` describes
   * only the first, so each hop past the first must supply its own index+path.
   * Omit for FRI9, which reads the walk out of the proof.
   */
  noteSpent?: { index: number; path: Uint8Array[] };
  /** Option A': must equal what genesis pinned, or the pool lock will not match. */
  finalNfRoot?: Uint8Array;
  /**
   * Option B (note-auth-step-kernel.ts): walk N notes in THIS transaction, one
   * step kernel per note, appended after the slots. The audited single-note
   * kernel is dropped when these are present - its one root step is exactly
   * what a batch cannot satisfy. The covenant pins each step lock by index, so
   * genesis must have been compiled with the same list.
   */
  stepSpends?: ReadonlyArray<{
    note: Note;
    index: number;
    path: Uint8Array[];
    rIn: Uint8Array;
    rOut: Uint8Array;
    /** Previous step's nullifier. Steps run in strictly increasing nullifier
     *  order, which is what makes a duplicate note unsatisfiable on chain.
     *  Build these with `stepPlan`, which sorts and rejects duplicates. */
    prevNf?: Uint8Array;
  }>;
  /**
   * Tape tip lock chain (C-BINDING). When present the tape tip is a P2SH32
   * covenant rather than a P2PKH: spend it with `tapeTipRedeem`, and a tape hop
   * must recreate `tapeTipNextLock` at output 1. The chain is counted, so hops
   * cannot be skipped and the digest cannot be swapped.
   */
  tapeTipRedeem?: Uint8Array;
  tapeTipNextLock?: Uint8Array;
  /** Terminal tip lock the pool covenant pins (pay hop only). */
  tapeTipLock?: Uint8Array;
}): MeasuredTx {
  const lockKind = args.lockKind ?? "p2sh32";
  const slotKernels =
    args.slotKernels ??
    (args.envelope === "consensus" ? SLOT_KERNEL_COUNT_CONSENSUS : SLOT_KERNEL_COUNT);
  const fee = args.feeSats ?? successorFeeSats(args.envelope ?? "standard");
  const value = utxoValueFor(args.newState);
  const poolIn = BigInt(args.pool.value);
  const net = value - poolIn;
  const depositNeed = net > 0n ? net : 0n;
  const userFee = Boolean(args.feeUtxo);
  const tape = Boolean(args.tapeUtxo);
  // Option A': a tape hop may carry its own note-auth kernel when a note is
  // supplied. FRI9 tape hops pass none, so this stays false for them.
  const stepSpends = args.stepSpends ?? [];
  const stepN = stepSpends.length;
  if (args.statement) {
    const spentNotes = Number(
      args.statement.newState.withdrawalCount - args.statement.oldState.withdrawalCount,
    );
    if (spentNotes > 1 && stepN !== spentNotes) {
      throw new Error(
        `H1: ${spentNotes}-note withdraw requires ${spentNotes} step kernels (got ${stepN}); extras in verifyFri are not a B successor`,
      );
    }
  }
  const stepLocks = stepSpends.map((sp) =>
    compileNoteAuthStepLockP2sh32(sp.rIn, sp.rOut, sp.prevNf ?? new Uint8Array(32)),
  );
  // A batch drops the audited kernel: one SHA256(old || nf) == new step cannot
  // express N insertions, and the step kernels do that job instead.
  const wantNote =
    stepN > 0
      ? false
      : args.includePool !== false
        ? includeNoteAuth(slotKernels) || Boolean(args.note)
        : Boolean(args.note);
  if (depositNeed > 0n && !args.feeUtxo) {
    throw new Error("deposit successor needs a funder utxo for the net");
  }
  if (userFee && !args.wallet) throw new Error("fee utxo needs a wallet to sign");
  if (tape && !args.tapeTipRedeem && !args.wallet) {
    throw new Error("tape utxo needs a wallet to sign (or a tapeTipRedeem covenant)");
  }
  const signP2pkh = userFee || (tape && !args.tapeTipRedeem);
  const c = signP2pkh ? compiler() : undefined;
  const data = signP2pkh ? { keys: { privateKeys: { key: privateKeyOf(args.wallet!) } } } : undefined;
  const change =
    userFee && args.feeUtxo
      ? BigInt(args.feeUtxo.value) - fee - depositNeed
      : 0n;
  if (userFee && change < DUST_SATS) throw new Error("fee utxo too small for successor");
  const withdrawSats = net < 0n ? -net : 0n;
  const payoutLock = args.payoutLockingBytecode ?? LAB_PAYOUT_LOCKING;
  const extraPayouts = args.extraPayouts ?? [];
  if (extraPayouts.length > 0) {
    const paySum = extraPayouts.reduce((n, p) => n + p.sats, 0n);
    if (paySum !== withdrawSats) {
      throw new Error(`extraPayouts sum ${paySum} != pool net ${withdrawSats} (would steal or leak reserve)`);
    }
  }
  const wantPayout =
    Boolean(args.statement) &&
    args.statement!.publicAmountSats < 0n &&
    !isZero32(args.statement!.payoutLockingDigest);
  const payoutOutputs =
    extraPayouts.length > 0
      ? extraPayouts.map((p) => ({ lockingBytecode: p.lockingBytecode, valueSatoshis: p.sats }))
      : wantPayout
        ? [{ lockingBytecode: payoutLock, valueSatoshis: withdrawSats }]
        : [];
  const commitment = encodePublicPaa1(args.newState);
  const oldState = decodeState(args.pool.commitment);
  const decoded = decodeFriProof(args.proof);
  const packed = args.statement ? encodeAirPacked(args.statement, decoded) : decoded.layerRoots;
  const carrierPacked =
    packed instanceof Uint8Array && packed.length >= AIR_PACKED_SIZE
      ? packed.length === AIR_PACKED_SIZE
        ? packedWithPairs(packed, args.proof)
        : packed
      : packed;
  const includePool = args.includePool !== false;
  const queryStart = args.queryStart ?? 0;
  const foldN = args.foldQueries ?? foldKernelCount(slotKernels);
  const slotN = args.foldQueries !== undefined ? args.foldQueries : slotInputsCount(slotKernels);
  const unlocking = includePool
    ? lockKind === "p2s"
      ? p2sUnlocking(undefined, carrierPacked)
      : p2sh32Unlocking(undefined, carrierPacked, {
          slotKernels,
          forceNoteAuth: args.forceNoteAuth ?? false,
          tapeTipLock: args.tapeTipLock,
          finalNfRoot: args.finalNfRoot,
          stepLocks,
        })
    : packedAirCarrierUnlocking(packed instanceof Uint8Array ? packed : encodeAirPacked(args.statement!, decoded));
  const shards = friShardUnlockings(args.proof, { allPairGroups: foldN > 1 });
  const dummy = "44".repeat(32);
  const kernels = args.kernelUtxos ??
    (args.kernelUtxo
      ? [args.kernelUtxo]
      : shards.map((_, i) => ({ tx_hash: dummy, tx_pos: i, value: 1000 })));
  if (kernels.length !== FRI_KERNEL_INPUTS) {
    throw new Error(`need ${FRI_KERNEL_INPUTS} FRI kernel UTXOs, got ${kernels.length}`);
  }
  // A batch drops the audited kernel, so the prefix is cqz+grind+algC = 3 even at
  // 36 slots, where includeNoteAuth would otherwise say 4. The covenant computes
  // the same 3 (requireFriInputsAsm), and a mismatch here would shift every fold
  // and slot index by one.
  const prefixN =
    stepN > 0 ? 3 : prefixExtraKernelCount(slotKernels, includePool, wantNote);
  const extras = args.extraKernels ?? [
    { tx_hash: dummy, tx_pos: 10, value: 1000 },
    ...(includePool
      ? [
          { tx_hash: dummy, tx_pos: 11, value: 1000 },
          { tx_hash: dummy, tx_pos: 12, value: 1000 },
        ]
      : []),
    ...(wantNote ? [{ tx_hash: dummy, tx_pos: includePool ? 13 : 11, value: 1000 }] : []),
    ...Array.from({ length: foldN }, (_, f) => ({ tx_hash: dummy, tx_pos: 10 + prefixN + f, value: 1000 })),
    ...Array.from({ length: slotN }, (_, i) => ({ tx_hash: dummy, tx_pos: 10 + prefixN + foldN + i, value: 1000 })),
    ...Array.from({ length: stepN }, (_, i) => ({ tx_hash: dummy, tx_pos: 10 + prefixN + foldN + slotN + i, value: 1000 })),
  ];
  if (extras.length !== prefixN + foldN + slotN + stepN) {
    throw new Error(
      `need ${prefixN + foldN + slotN + stepN} extra kernel UTXOs, got ${extras.length}`,
    );
  }
  if (wantNote) {
    if (!args.note) throw new Error("note-auth kernel needs the opened note (not the OTP-masked proof field)");
    if (!args.noteSpent && !args.statement) {
      throw new Error("note-auth kernel needs the statement (or an explicit noteSpent walk)");
    }
  }

  const airPacked =
    packed instanceof Uint8Array && packed.length >= AIR_PACKED_SIZE
      ? packed.subarray(0, AIR_PACKED_SIZE)
      : args.statement
        ? encodeAirPacked(args.statement, decoded)
        : undefined;
  const in0 = includePool
    ? {
        outpointIndex: args.pool.tx_pos,
        outpointTransactionHash: hexToBin(args.pool.tx_hash),
        sequenceNumber: 0xffffffff,
        unlockingBytecode: unlocking,
      }
    : {
        outpointIndex: args.carrierUtxo?.tx_pos ?? 0,
        outpointTransactionHash: hexToBin(args.carrierUtxo?.tx_hash ?? "aa".repeat(32)),
        sequenceNumber: 0xffffffff,
        unlockingBytecode: packedAirCarrierUnlocking(airPacked ?? new Uint8Array(AIR_PACKED_SIZE)),
      };
  const baseInputs = [
      in0,
      ...shards.map((friUnlock, i) => ({
        outpointIndex: kernels[i]!.tx_pos,
        outpointTransactionHash: hexToBin(kernels[i]!.tx_hash),
        sequenceNumber: 0xffffffff,
        unlockingBytecode: friUnlock,
      })),
      {
        outpointIndex: extras[0]!.tx_pos,
        outpointTransactionHash: hexToBin(extras[0]!.tx_hash),
        sequenceNumber: 0xffffffff,
        unlockingBytecode: cqzKernelUnlocking(carrierPacked),
      },
      ...(includePool
        ? [
            {
              outpointIndex: extras[1]!.tx_pos,
              outpointTransactionHash: hexToBin(extras[1]!.tx_hash),
              sequenceNumber: 0xffffffff,
              unlockingBytecode: grindKernelUnlocking(airPacked),
            },
            {
              outpointIndex: extras[2]!.tx_pos,
              outpointTransactionHash: hexToBin(extras[2]!.tx_hash),
              sequenceNumber: 0xffffffff,
              unlockingBytecode: algebraicCKernelUnlocking(),
            },
          ]
        : []),
      ...(wantNote
        ? [
            {
              outpointIndex: extras[includePool ? 3 : 1]!.tx_pos,
              outpointTransactionHash: hexToBin(extras[includePool ? 3 : 1]!.tx_hash),
              sequenceNumber: 0xffffffff,
              // Option A': a batch hop supplies its own note's walk, since the
              // published proof's single `auth` covers only the first spent note.
              unlockingBytecode: args.noteSpent
                ? noteAuthKernelUnlocking({
                    note: args.note!,
                    change: args.change,
                    spentIndex: args.noteSpent.index,
                    spentPath: args.noteSpent.path,
                    createdIndex: 0,
                    createdPath: [],
                  })
                : noteAuthUnlockingFromProof({
                    note: args.note!,
                    change: args.change,
                    proof: args.proof,
                    statement: args.statement!,
                  }),
            },
          ]
        : []),
      ...Array.from({ length: foldN }, (_, f) => ({
        outpointIndex: extras[prefixN + f]!.tx_pos,
        outpointTransactionHash: hexToBin(extras[prefixN + f]!.tx_hash),
        sequenceNumber: 0xffffffff,
        unlockingBytecode: foldKernelUnlocking(
          foldQueriesPerKernel(slotKernels),
          queryStart + f * foldQueriesPerKernel(slotKernels),
          airPacked,
          queryPairShard(args.proof, queryStart + f * foldQueriesPerKernel(slotKernels), foldQueriesPerKernel(slotKernels)),
        ),
      })),
      ...Array.from({ length: slotN }, (_, i) => ({
        outpointIndex: extras[prefixN + foldN + i]!.tx_pos,
        outpointTransactionHash: hexToBin(extras[prefixN + foldN + i]!.tx_hash),
        sequenceNumber: 0xffffffff,
        unlockingBytecode: slotsKernelUnlocking(
          (queryStart + i) * (slotKernels > SLOT_KERNEL_COUNT ? SLOTS_PER_KERNEL : 1),
          slotKernels > SLOT_KERNEL_COUNT ? SLOTS_PER_KERNEL : 1,
          airPacked,
        ),
      })),
      ...stepSpends.map((sp, i) => ({
        outpointIndex: extras[prefixN + foldN + slotN + i]!.tx_pos,
        outpointTransactionHash: hexToBin(extras[prefixN + foldN + slotN + i]!.tx_hash),
        sequenceNumber: 0xffffffff,
        unlockingBytecode: noteAuthStepUnlocking(sp),
      })),
      ...(userFee && args.feeUtxo && c && data
        ? [
            {
              outpointIndex: args.feeUtxo.tx_pos,
              outpointTransactionHash: hexToBin(args.feeUtxo.tx_hash),
              sequenceNumber: 0xffffffff,
              unlockingBytecode: {
                compiler: c,
                script: "unlock",
                data,
                valueSatoshis: BigInt(args.feeUtxo.value),
              },
            },
          ]
        : []),
      ...(tape && args.tapeUtxo && args.tapeTipRedeem
        ? [
            {
              outpointIndex: args.tapeUtxo.tx_pos,
              outpointTransactionHash: hexToBin(args.tapeUtxo.tx_hash),
              sequenceNumber: 0xffffffff,
              // P2SH32 covenant spend: the redeem is the whole unlocking. No
              // signature, so the tip must stay tokenless (a token-carrying tip
              // changes the sighash and broke P2PKH signing with NULLFAIL).
              unlockingBytecode: tapeTipUnlocking(args.tapeTipRedeem),
            },
          ]
        : tape && args.tapeUtxo && c && data
        ? [
            {
              outpointIndex: args.tapeUtxo.tx_pos,
              outpointTransactionHash: hexToBin(args.tapeUtxo.tx_hash),
              sequenceNumber: 0xffffffff,
              unlockingBytecode: {
                compiler: c,
                script: "unlock",
                data,
                valueSatoshis: BigInt(args.tapeUtxo.value),
              },
            },
          ]
        : []),
  ];
  const outputs = includePool
    ? [
      {
        lockingBytecode: lockOf(
          lockKind,
          slotKernels,
          args.forceNoteAuth ?? false,
          args.tapeTipLock,
          args.finalNfRoot,
          stepLocks,
        ),
        valueSatoshis: value,
        token: {
          amount: 0n,
          category: args.pool.category,
          nft: { capability: "mutable" as const, commitment },
        },
      },
      ...payoutOutputs,
      ...(userFee
        ? [
            {
              lockingBytecode: args.changeLockingBytecode ?? p2pkhLockingOf(createLabWallet()),
              valueSatoshis: change,
            },
          ]
        : []),
    ]
    : [
        {
          // Output 0 carries the pool category with the NEW commitment: cqz's
          // bindPackedStmtToPaa1Asm reads OP_OUTPUTTOKENCOMMITMENT <0>, and a
          // tokenless output makes that an empty item so OP_SPLIT <64> fails.
          // Input 0 is a mutable sibling holding OLD, so mutating it to NEW is a
          // legal CashTokens move and needs no minting capability. Nothing spends
          // this output again; each sibling is consumed once.
          lockingBytecode: p2pkhLockingOf(args.wallet ?? createLabWallet()),
          valueSatoshis: TAPE_HOP_OUT_SATS,
          token: {
            amount: 0n,
            category: args.pool.category,
            nft: { capability: "mutable" as const, commitment },
          },
        },
        {
          // Output 1 is the tape tip the next hop spends, deliberately tokenless.
          // A token-carrying UTXO changes the sighash preimage and breaks the
          // P2PKH path with NULLFAIL. With the binding covenant in use this is
          // the next lock in the counted chain, so the digest propagates.
          lockingBytecode:
            args.tapeTipNextLock ?? p2pkhLockingOf(args.wallet ?? createLabWallet()),
          valueSatoshis: TAPE_HOP_OUT_SATS,
        },
      ];
  const generated = generateTransaction({ version: 2, locktime: 0, inputs: baseInputs, outputs });
  if (!generated.success) {
    throw new Error(`covenant successor: ${JSON.stringify(generated.errors).slice(0, 500)}`);
  }
  const raw = encodeTransaction(generated.transaction);
  const poolUnlock = generated.transaction.inputs[0]!.unlockingBytecode.length;
  return measureOf(raw, poolUnlock, args.proof, lockKind);
}

export function measureCovenantSpend(state: AnyAmountState, proof: Uint8Array, lockKind: LockKind = "p2sh32"): MeasuredTx {
  return compileCovenantSpend({
    wallet: createLabWallet(),
    utxo: { tx_hash: "11".repeat(32), tx_pos: 0, value: 1_000_000 },
    state,
    proof,
    lockKind,
  });
}

export function measureGenesisAndSuccessor(state: AnyAmountState, next: AnyAmountState, proof: Uint8Array): {
  genesisP2sh32: MeasuredTx;
  genesisP2s: MeasuredTx;
  successorP2sh32: MeasuredTx;
} {
  const wallet = createLabWallet();
  const genesisP2sh32 = compileCovenantSpend({
    wallet,
    utxo: { tx_hash: "11".repeat(32), tx_pos: 0, value: 2_000_000 },
    state,
    proof,
    lockKind: "p2sh32",
  });
  const genesisP2s = compileCovenantSpend({
    wallet,
    utxo: { tx_hash: "22".repeat(32), tx_pos: 0, value: 2_000_000 },
    state,
    proof,
    lockKind: "p2s",
  });
  const successorP2sh32 = compileCovenantSuccessor({
    wallet,
    feeUtxo: { tx_hash: "33".repeat(32), tx_pos: 0, value: 250_000 },
    pool: {
      tx_hash: genesisP2sh32.txid,
      tx_pos: 0,
      value: utxoValueFor(state),
      category: hexToBin("11".repeat(32)),
      commitment: encodePublicPaa1(state),
    },
    newState: next,
    proof,
    lockKind: "p2sh32",
  });
  return { genesisP2sh32, genesisP2s, successorP2sh32 };
}

/** CashTokens genesis is only legal from a parent vout=0. */
export function compileSelfSendVout0(
  wallet: LabWallet,
  utxo: { tx_hash: string; tx_pos: number; value: number },
): { raw: Uint8Array; txid: string; value: number } {
  const c = compiler();
  const data = { keys: { privateKeys: { key: privateKeyOf(wallet) } } };
  const fee = 400n;
  const value = BigInt(utxo.value) - fee;
  if (value < 546n) throw new Error("utxo too small to prep genesis vout0");
  const generated = generateTransaction({
    version: 2,
    locktime: 0,
    inputs: [
      {
        outpointIndex: utxo.tx_pos,
        outpointTransactionHash: hexToBin(utxo.tx_hash),
        sequenceNumber: 0xffffffff,
        unlockingBytecode: {
          compiler: c,
          script: "unlock",
          data,
          valueSatoshis: BigInt(utxo.value),
        },
      },
    ],
    outputs: [
      {
        lockingBytecode: { compiler: c, script: "lock", data },
        valueSatoshis: value,
      },
    ],
  });
  if (!generated.success) {
    throw new Error(`self-send: ${JSON.stringify(generated.errors).slice(0, 400)}`);
  }
  const raw = encodeTransaction(generated.transaction);
  return { raw, txid: hashTransaction(raw), value: Number(value) };
}

/** 10 FRI + bind-T + slot C=QZ carriers. Fat leftover is a fresh treasury, not the successor. */
export function compileFundVerifierKernels(
  wallet: LabWallet,
  utxo: { tx_hash: string; tx_pos: number; value: number },
  kernelSats = 1_000,
  slotKernels = SLOT_KERNEL_COUNT,
  feeCoinSats: bigint = successorFeeCoinSats("standard"),
  forceNoteAuth = false,
  /** Option B: one carrier per step kernel, funded after the slots. When these
   *  are present the audited note-auth carrier is NOT funded, matching what the
   *  covenant expects (requireFriInputsAsm drops it for a batch). */
  stepLocks: readonly Uint8Array[] = [],
): {
  raw: Uint8Array;
  txid: string;
  fri: Array<{ tx_hash: string; tx_pos: number; value: number }>;
  extra: Array<{ tx_hash: string; tx_pos: number; value: number }>;
  cargo: Array<{ tx_hash: string; tx_pos: number; value: number }>;
  changeValue: number;
  changePos: number;
  treasuryValue?: number;
  treasuryPos?: number;
  treasuryAddress?: string;
} {
  const c = compiler();
  const data = { keys: { privateKeys: { key: privateKeyOf(wallet) } } };
  const foldN = foldKernelCount(slotKernels);
  const batched = stepLocks.length > 0;
  const extraCount =
    (batched ? 3 : prefixExtraKernelCount(slotKernels, true, forceNoteAuth)) +
    foldN +
    slotInputsCount(slotKernels) +
    stepLocks.length;
  const count = FRI_KERNEL_INPUTS + extraCount;
  // 10 FRI + bind-T + N slots is ~50 B/out; 1000 sats was under 1 sat/byte at N=36 (code 66).
  const fee = 2_000n + BigInt(count) * 80n;
  const minerPad = feeCoinSats;
  const leftover = BigInt(utxo.value) - BigInt(kernelSats) * BigInt(count) - minerPad - fee;
  if (leftover < DUST_SATS) throw new Error("utxo too small to fund verifier kernels");
  const treasuryWallet = createLabWallet();
  const fatFri = BigInt(kernelSats) + minerPad;
  const tail = [{ lockingBytecode: p2pkhLockingOf(treasuryWallet), valueSatoshis: leftover }];
  const generated = generateTransaction({
    version: 2,
    locktime: 0,
    inputs: [
      {
        outpointIndex: utxo.tx_pos,
        outpointTransactionHash: hexToBin(utxo.tx_hash),
        sequenceNumber: 0xffffffff,
        unlockingBytecode: {
          compiler: c,
          script: "unlock",
          data,
          valueSatoshis: BigInt(utxo.value),
        },
      },
    ],
    outputs: [
      { lockingBytecode: compileFriQueryLockP2sh32(0), valueSatoshis: fatFri },
      ...Array.from({ length: FRI_KERNEL_INPUTS - 1 }, (_, i) => ({
        lockingBytecode: compileFriQueryLockP2sh32(i + 1),
        valueSatoshis: BigInt(kernelSats),
      })),
      { lockingBytecode: compileCqzLockP2sh32(), valueSatoshis: BigInt(kernelSats) },
      { lockingBytecode: compileGrindLockP2sh32(), valueSatoshis: BigInt(kernelSats) },
      { lockingBytecode: compileAlgebraicCLockP2sh32(), valueSatoshis: BigInt(kernelSats) },
      ...(!batched && includeNoteAuth(slotKernels, forceNoteAuth)
        ? [{ lockingBytecode: compileNoteAuthLockP2sh32(), valueSatoshis: BigInt(kernelSats) }]
        : []),
      ...Array.from({ length: foldN }, (_, f) => ({
        lockingBytecode: compileFoldLockP2sh32(
          foldQueriesPerKernel(slotKernels),
          f * foldQueriesPerKernel(slotKernels),
        ),
        valueSatoshis: BigInt(kernelSats),
      })),
      ...Array.from({ length: slotInputsCount(slotKernels) }, (_, i) => ({
        lockingBytecode: compileSlotsLockP2sh32(
          i * (slotKernels > SLOT_KERNEL_COUNT ? SLOTS_PER_KERNEL : 1),
          slotKernels > SLOT_KERNEL_COUNT ? SLOTS_PER_KERNEL : 1,
        ),
        valueSatoshis: BigInt(kernelSats),
      })),
      ...stepLocks.map((lock) => ({
        lockingBytecode: lock,
        valueSatoshis: BigInt(kernelSats),
      })),
      ...tail,
    ],
  });
  if (!generated.success) {
    throw new Error(`fund verifier kernels: ${JSON.stringify(generated.errors).slice(0, 400)}`);
  }
  const raw = encodeTransaction(generated.transaction);
  const txid = hashTransaction(raw);
  return {
    raw,
    txid,
    fri: [
      { tx_hash: txid, tx_pos: 0, value: Number(fatFri) },
      ...Array.from({ length: FRI_KERNEL_INPUTS - 1 }, (_, i) => ({
        tx_hash: txid,
        tx_pos: i + 1,
        value: kernelSats,
      })),
    ],
    extra: Array.from({ length: extraCount }, (_, i) => ({
      tx_hash: txid,
      tx_pos: FRI_KERNEL_INPUTS + i,
      value: kernelSats,
    })),
    cargo: [],
    changeValue: Number(leftover),
    changePos: count,
    treasuryValue: Number(leftover),
    treasuryPos: count,
    treasuryAddress: treasuryWallet.address,
  };
}

/** Fund FRI-kernel P2SH32 carriers (one per proof shard) so the successor can spend them. */
export function compileFundFriKernels(
  wallet: LabWallet,
  utxo: { tx_hash: string; tx_pos: number; value: number },
  count = FRI_KERNEL_INPUTS,
  kernelSats = 1_000,
): {
  raw: Uint8Array;
  txid: string;
  kernels: Array<{ tx_hash: string; tx_pos: number; value: number }>;
  changeValue: number;
} {
  const c = compiler();
  const data = { keys: { privateKeys: { key: privateKeyOf(wallet) } } };
  const fee = 800n;
  const change = BigInt(utxo.value) - BigInt(kernelSats) * BigInt(count) - fee;
  if (change < 546n) throw new Error("utxo too small to fund FRI kernels");
  const generated = generateTransaction({
    version: 2,
    locktime: 0,
    inputs: [
      {
        outpointIndex: utxo.tx_pos,
        outpointTransactionHash: hexToBin(utxo.tx_hash),
        sequenceNumber: 0xffffffff,
        unlockingBytecode: {
          compiler: c,
          script: "unlock",
          data,
          valueSatoshis: BigInt(utxo.value),
        },
      },
    ],
    outputs: [
      ...Array.from({ length: count }, (_, i) => ({
        lockingBytecode: compileFriQueryLockP2sh32(i),
        valueSatoshis: BigInt(kernelSats),
      })),
      { lockingBytecode: { compiler: c, script: "lock", data }, valueSatoshis: change },
    ],
  });
  if (!generated.success) {
    throw new Error(`fund kernels: ${JSON.stringify(generated.errors).slice(0, 400)}`);
  }
  const raw = encodeTransaction(generated.transaction);
  const txid = hashTransaction(raw);
  return {
    raw,
    txid,
    kernels: Array.from({ length: count }, (_, i) => ({ tx_hash: txid, tx_pos: i, value: kernelSats })),
    changeValue: Number(change),
  };
}

/** @deprecated use compileFundFriKernels */
export function compileFundFriKernel(
  wallet: LabWallet,
  utxo: { tx_hash: string; tx_pos: number; value: number },
  kernelSats = 1_000,
): { raw: Uint8Array; txid: string; kernel: { tx_hash: string; tx_pos: number; value: number }; changeValue: number } {
  const funded = compileFundFriKernels(wallet, utxo, 1, kernelSats);
  return { raw: funded.raw, txid: funded.txid, kernel: funded.kernels[0]!, changeValue: funded.changeValue };
}

export async function broadcastCovenantGenesis(
  wallet: LabWallet,
  state: AnyAmountState,
  proof: Uint8Array,
  lockKind: LockKind = "p2sh32",
): Promise<MeasuredTx & { broadcast: string; prepTxid?: string; categoryHex: string }> {
  const client = await connectChipnet();
  try {
    const utxos = await listUnspent(client, wallet.address);
    if (utxos.length === 0) throw new Error("no Chipnet coins — fund the lab address");
    let picked = utxos.reduce((a, b) => (a.value >= b.value ? a : b));
    let prepTxid: string | undefined;
    if (picked.tx_pos !== 0) {
      const prep = compileSelfSendVout0(wallet, picked);
      prepTxid = await broadcastWithRetry(client, binToHex(prep.raw));
      picked = { tx_hash: prep.txid, tx_pos: 0, value: prep.value, height: 0 };
      await waitForTx(client, prep.txid);
    }
    const measured = compileCovenantSpend({
      wallet,
      utxo: picked,
      state,
      proof,
      lockKind,
    });
    const txid = await broadcastWithRetry(client, binToHex(measured.raw));
    return { ...measured, broadcast: txid, prepTxid, categoryHex: picked.tx_hash };
  } finally {
    client.close();
  }
}

export { compilePoolCovenant, STATE_BASE_SATS };

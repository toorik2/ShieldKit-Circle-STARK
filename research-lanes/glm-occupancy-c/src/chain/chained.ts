import {
  tapeTipLockChain,
  tapeTipLockChainWithRoots,
  tapeTipRedeemChain,
  tapeTipRedeemChainWithRoots,
  tapeTipUnlocking,
} from "./tape-tip.ts";
/**
 * Envelope C: pre-signed unconfirmed chain. Tape hops commit digest+i+N
 * and never pay. The last hop spends the pool and the tape tip.
 * BCHN still takes one tx at a time (not Core 1p1c). A missing tape hop
 * makes the pay hop invalid (missing inputs). Notes stay unspent until pay lands.
 */
import {
  binToHex,
  cashAssemblyToBin,
  encodeLockingBytecodeP2sh32,
  encodeTransaction,
  generateTransaction,
  hash256,
  hashTransaction,
  hexToBin,
  walletTemplateP2pkhNonHd,
  walletTemplateToCompilerBCH,
} from "@bitauth/libauth";
import { concatBytes } from "../pool/bytes.ts";
import { compileCovenantSuccessor, type MeasuredTx } from "./covenant-spend.ts";
import { compileCqzLockP2sh32, compileSlotsLockP2sh32 } from "./air-cqz.ts";
import { compileNoteAuthLockP2sh32 } from "./note-auth-kernel.ts";
import { compileFoldLockP2sh32 } from "./fold-kernel.ts";
import { compileFriQueryLockP2sh32, FRI_KERNEL_INPUTS } from "./fri-kernel.ts";
import { successorFeeCoinSats, TAPE_HOP_OUT_SATS } from "./envelope.ts";
import { FRI_QUERIES } from "../backends/circle/params.ts";
import { SLOT_KERNEL_COUNT } from "./air-cqz.ts";

import { broadcastSized, type BroadcastPath } from "./broadcast-tx.ts";
import type { BchnRpcConfig } from "./bchn-rpc.ts";
import {
  CHAINED_HOPS_DEFAULT,
  CHAINED_TX_BYTES,
  DUST_SATS,
  parseChainedHops,
  RELAY_STANDARD_TX_BYTES,
  STANDARD_SUCCESSOR_FEE_SATS,
  TAPE_TIMEOUT_CSV,
} from "./envelope.ts";
import { proofCargoLock, type CargoUtxo } from "./proof-cargo.ts";
import { p2pkhLockingOf, privateKeyOf, type LabWallet } from "./wallet.ts";
import type { AnyAmountState } from "../pool/state.ts";
import type { PoolStatement } from "../pool/statement.ts";

/** FS queries carried per tape hop. 36 queries / 2 = 18 tape hops. */
export const QUERIES_PER_TAPE_HOP = 2;

export const TAPE_MAGIC = new Uint8Array([0x54, 0x41, 0x50, 0x45, 0x31]); // TAPE1
const TIMEOUT_FEE_SATS = 400n;

export type ChainUtxo = { tx_hash: string; tx_pos: number; value: number };

export type ChainedHop = {
  role: "tape" | "pay";
  index: number;
  raw: Uint8Array;
  txid: string;
  txBytes: number;
  payoutCount: number;
  commitHex?: string;
};

export type ChainedWithdraw = {
  envelope: "chained";
  hops: ChainedHop[];
  totalBytes: number;
  payIndex: number;
  timeout: { raw: Uint8Array; txid: string; sequence: number };
};

function compiler() {
  return walletTemplateToCompilerBCH(walletTemplateP2pkhNonHd);
}

function opReturnLocking(payload: Uint8Array): Uint8Array {
  if (payload.length <= 75) return Uint8Array.of(0x6a, payload.length, ...payload);
  if (payload.length <= 255) return Uint8Array.of(0x6a, 0x4c, payload.length, ...payload);
  throw new Error("tape OP_RETURN too large");
}

export function tapeCommit(digest: Uint8Array, index: number, hopCount: number, chunkHash: Uint8Array): Uint8Array {
  return concatBytes(TAPE_MAGIC, digest, Uint8Array.of(index & 0xff, hopCount & 0xff), chunkHash);
}

export function compileTapeHop(args: {
  wallet: LabWallet;
  utxo: ChainUtxo;
  digest: Uint8Array;
  index: number;
  hopCount: number;
  chunkHash: Uint8Array;
  proof?: Uint8Array;
  feeSats?: bigint;
}): { raw: Uint8Array; txid: string; nextUtxo: ChainUtxo; commit: Uint8Array; cargoCount: number } {
  const fee = args.feeSats ?? STANDARD_SUCCESSOR_FEE_SATS;
  const nextValue = BigInt(args.utxo.value) - fee;
  if (nextValue < DUST_SATS) throw new Error("tape utxo too small");
  const c = compiler();
  const data = { keys: { privateKeys: { key: privateKeyOf(args.wallet) } } };
  const commit = tapeCommit(args.digest, args.index, args.hopCount, args.chunkHash);
  const carrier = {
    outpointIndex: args.utxo.tx_pos,
    outpointTransactionHash: hexToBin(args.utxo.tx_hash),
    sequenceNumber: 0xffffffff,
    unlockingBytecode: {
      compiler: c,
      script: "unlock" as const,
      data,
      valueSatoshis: BigInt(args.utxo.value),
    },
  };
  const outputs = [
    { lockingBytecode: p2pkhLockingOf(args.wallet), valueSatoshis: nextValue },
    { lockingBytecode: opReturnLocking(commit), valueSatoshis: 0n },
  ];
  const generated = generateTransaction({
    version: 2,
    locktime: 0,
    inputs: [carrier],
    outputs,
  });
  if (!generated.success) throw new Error(`tape hop: ${JSON.stringify(generated.errors).slice(0, 400)}`);
  const raw = encodeTransaction(generated.transaction);
  if (raw.length > RELAY_STANDARD_TX_BYTES) {
    throw new Error(`tape hop ${raw.length} > ${RELAY_STANDARD_TX_BYTES}`);
  }
  const txid = hashTransaction(raw);
  return {
    raw,
    txid,
    commit,
    cargoCount: 0,
    nextUtxo: { tx_hash: txid, tx_pos: 0, value: Number(nextValue) },
  };
}

export function compileTapeTimeout(args: {
  wallet: LabWallet;
  tapeUtxo: ChainUtxo;
}): { raw: Uint8Array; txid: string; sequence: number } {
  const nextValue = BigInt(args.tapeUtxo.value) - TIMEOUT_FEE_SATS;
  if (nextValue < DUST_SATS) throw new Error("tape timeout utxo too small");
  const c = compiler();
  const data = { keys: { privateKeys: { key: privateKeyOf(args.wallet) } } };
  const generated = generateTransaction({
    version: 2,
    locktime: 0,
    inputs: [
      {
        outpointIndex: args.tapeUtxo.tx_pos,
        outpointTransactionHash: hexToBin(args.tapeUtxo.tx_hash),
        sequenceNumber: TAPE_TIMEOUT_CSV,
        unlockingBytecode: {
          compiler: c,
          script: "unlock",
          data,
          valueSatoshis: BigInt(args.tapeUtxo.value),
        },
      },
    ],
    outputs: [{ lockingBytecode: p2pkhLockingOf(args.wallet), valueSatoshis: nextValue }],
  });
  if (!generated.success) {
    throw new Error(`tape timeout: ${JSON.stringify(generated.errors).slice(0, 400)}`);
  }
  const raw = encodeTransaction(generated.transaction);
  return { raw, txid: hashTransaction(raw), sequence: TAPE_TIMEOUT_CSV };
}

/** Split genesis-change into a tape carrier and kernel funder. No leftover-fill cargo. */
export function compileTapeFunder(args: {
  wallet: LabWallet;
  utxo: ChainUtxo;
  tapeSats?: bigint;
  feeSats?: bigint;
  /** C-BINDING: lock the tape output to L(digest, 0) instead of a bare P2PKH. */
  tapeLockingBytecode?: Uint8Array;
}): { raw: Uint8Array; txid: string; tapeUtxo: ChainUtxo; funderUtxo: ChainUtxo; cargo: CargoUtxo[] } {
  const tapeSats = args.tapeSats ?? 300_000n;
  const fee = args.feeSats ?? 2_000n;
  const rest = BigInt(args.utxo.value) - tapeSats - fee;
  if (rest < DUST_SATS) throw new Error("change too small to fund tape + kernels");
  const c = compiler();
  const data = { keys: { privateKeys: { key: privateKeyOf(args.wallet) } } };
  const lock = p2pkhLockingOf(args.wallet);
  const tapeLock = args.tapeLockingBytecode ?? lock;
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
      // output 0 is the tape head: L(digest, 0) when the binding covenant is used
      { lockingBytecode: tapeLock, valueSatoshis: tapeSats },
      { lockingBytecode: lock, valueSatoshis: rest },
    ],
  });
  if (!generated.success) {
    throw new Error(`tape funder: ${JSON.stringify(generated.errors).slice(0, 400)}`);
  }
  const raw = encodeTransaction(generated.transaction);
  const txid = hashTransaction(raw);
  return {
    raw,
    txid,
    tapeUtxo: { tx_hash: txid, tx_pos: 0, value: Number(tapeSats) },
    cargo: [],
    funderUtxo: { tx_hash: txid, tx_pos: 1, value: Number(rest) },
  };
}

export function compileChainedWithdraw(args: {
  wallet: LabWallet;
  tapeUtxo: ChainUtxo;
  hops?: number;
  digest: Uint8Array;
  proof: Uint8Array;
  pool: {
    tx_hash: string;
    tx_pos: number;
    value: number | bigint;
    category: Uint8Array;
    commitment: Uint8Array;
  };
  newState: AnyAmountState;
  statement?: PoolStatement;
  kernelUtxos?: Array<ChainUtxo>;
  extraKernels?: Array<ChainUtxo>;
  extraPayouts?: Array<{ lockingBytecode: Uint8Array; sats: bigint }>;
  payoutLockingBytecode?: Uint8Array;
  note?: import("../pool/notes.ts").Note;
  change?: import("../pool/notes.ts").Note;
  /** Per tape hop: AIR carrier + FRI + extras. Tests omit (dummy prevouts). */
  tapeKernels?: Array<{
    carrier?: ChainUtxo;
    fri: ChainUtxo[];
    extra: ChainUtxo[];
  }>;
  /**
   * Option A' (FRI10-BATCH-EXIT.md): spend N notes by giving hop i its own
   * note-auth kernel, advancing the nullifier root one step per hop.
   *
   * `spends[i]` is the note hop i walks; hops past the end carry no kernel and
   * leave the root where it is. `roots` is R_0..R_tapeN inclusive, so hop i reads
   * R_i from its sibling and writes R_{i+1}; R_tapeN is what the pool covenant
   * pins with `finalNfRoot`.
   *
   * The pay hop carries NO note-auth kernel in this mode: its single step
   * SHA256(R_0 || nf) == R_N is precisely what is unsatisfiable for N > 1. The
   * hops do the walking; the covenant pin validates where they landed.
   */
  batch?: {
    spends: ReadonlyArray<{ note: import("../pool/notes.ts").Note; index: number; path: Uint8Array[] }>;
    roots: readonly Uint8Array[];
  };
}): ChainedWithdraw {
  const digest = args.digest.length === 32 ? args.digest : hash256(args.digest);
  const hops: ChainedHop[] = [];
  let utxo = args.tapeUtxo;
  const qn = QUERIES_PER_TAPE_HOP;
  const tapeN = Math.ceil(FRI_QUERIES / qn);
  const hopCount = parseChainedHops(args.hops ?? tapeN + 1);
  // Counted tip lock chain: L(d,i) requires output 1 to be L(d,i+1); L(d,tapeN)
  // is terminal and is what the pay hop spends. Binds every hop to one digest and
  // makes skipping impossible - see C-BINDING.md.
  // Option A' pins each hop's output root into its tip, so a hop cannot publish a
  // root its kernel did not produce - and a hop with no kernel cannot forge one.
  const batch = args.batch;
  if (batch) {
    if (batch.roots.length !== tapeN + 1) {
      throw new Error(`batch roots ${batch.roots.length} != tapeN + 1 (${tapeN + 1})`);
    }
    if (batch.spends.length > tapeN) {
      throw new Error(`batch of ${batch.spends.length} exceeds ${tapeN} tape hops`);
    }
  }
  const tipRedeems = batch
    ? tapeTipRedeemChainWithRoots(digest, batch.roots.slice(1))
    : tapeTipRedeemChain(digest, tapeN);
  const tipLocks = batch
    ? tapeTipLockChainWithRoots(digest, batch.roots.slice(1))
    : tapeTipLockChain(digest, tapeN);
  if (hopCount < tapeN + 1) {
    throw new Error(`chained needs ${tapeN + 1} hops for ${FRI_QUERIES} unique-orbit slices (got ${hopCount})`);
  }
  for (let i = 0; i < tapeN; i += 1) {
    const q0 = i * qn;
    const thisN = Math.min(qn, FRI_QUERIES - q0);
    const group = args.tapeKernels?.[i];
    const spend = batch?.spends[i];
    const sliceTx = compileCovenantSuccessor({
      wallet: args.wallet,
      includePool: false,
      tapeUtxo: utxo,
      carrierUtxo: group?.carrier,
      queryStart: q0,
      foldQueries: thisN,
      slotKernels: thisN,
      tapeTipRedeem: tipRedeems[i],
      tapeTipNextLock: tipLocks[i + 1],
      kernelUtxos: group?.fri,
      extraKernels: group?.extra,
      pool: args.pool,
      // Output 0 carries this hop's intermediate root; cqz binds only noteRoot
      // and seq, both unchanged across a full-note batch, so this is legal.
      newState: batch ? { ...args.newState, nullifierRoot: batch.roots[i + 1]! } : args.newState,
      ...(spend
        ? { note: spend.note, noteSpent: { index: spend.index, path: spend.path } }
        : {}),
      proof: args.proof,
      statement: args.statement,
      lockKind: "p2sh32",
      envelope: "standard",
    });
    if (sliceTx.txBytes > RELAY_STANDARD_TX_BYTES) {
      throw new Error(`tape hop ${i} ${sliceTx.txBytes} > ${RELAY_STANDARD_TX_BYTES} (chunk queries across hops)`);
    }
    hops.push({
      role: "tape",
      index: i,
      raw: sliceTx.raw,
      txid: sliceTx.txid,
      txBytes: sliceTx.txBytes,
      payoutCount: 0,
      commitHex: Buffer.from(digest).toString("hex"),
    });
    // tape tip is output 1; output 0 holds the NEW-commitment NFT for cqz
    utxo = { tx_hash: sliceTx.txid, tx_pos: 1, value: Number(TAPE_HOP_OUT_SATS) };
  }
  const timeout = compileTapeTimeout({ wallet: args.wallet, tapeUtxo: utxo });
  const successor: MeasuredTx = compileCovenantSuccessor({
    wallet: args.wallet,
    tapeUtxo: utxo,
    pool: args.pool,
    newState: args.newState,
    proof: args.proof,
    statement: args.statement,
    lockKind: "p2sh32",
    envelope: "standard",
    slotKernels: SLOT_KERNEL_COUNT,
    // 4 slots but a note-auth kernel is present, so the pool lock must expect it.
    // Genesis commits the matching lock (landC passes the same flag). Under a
    // batch the pay hop carries no note-auth kernel at all - see `batch` above -
    // so the flag flips and genesis must match.
    forceNoteAuth: !batch,
    // The landing root the hops walked to. Genesis pinned this into the covenant,
    // so the pay hop must present a redeem carrying the same value.
    finalNfRoot: batch ? batch.roots[tapeN] : undefined,
    // Terminal link: only L(digest, tapeN) can be spent here, so the pay hop
    // cannot reach past the tape to the funder's tip.
    tapeTipRedeem: tipRedeems[tapeN],
    tapeTipLock: tipLocks[tapeN],
    kernelUtxos: args.kernelUtxos,
    extraKernels: args.extraKernels,
    extraPayouts: args.extraPayouts,
    payoutLockingBytecode: args.payoutLockingBytecode,
    // Under a batch the hops carry the kernels; the pay hop carries none.
    note: batch ? undefined : args.note,
    change: args.change,
  });
  if (successor.txBytes > RELAY_STANDARD_TX_BYTES) {
    throw new Error(`C pay hop ${successor.txBytes} > ${RELAY_STANDARD_TX_BYTES}`);
  }
  const payoutCount =
    args.extraPayouts && args.extraPayouts.length > 0
      ? args.extraPayouts.length
      : args.statement && args.statement.publicAmountSats < 0n
        ? 1
        : 0;
  hops.push({
    role: "pay",
    index: tapeN,
    raw: successor.raw,
    txid: successor.txid,
    txBytes: successor.txBytes,
    payoutCount,
  });
  const totalBytes = hops.reduce((n, h) => n + h.txBytes, 0);
  if (totalBytes > CHAINED_TX_BYTES) throw new Error(`chained ${totalBytes} > ${CHAINED_TX_BYTES}`);
  return {
    envelope: "chained",
    hops,
    totalBytes,
    payIndex: tapeN,
    timeout,
  };
}

/**
 * Fund every tape hop's kernels in one tx.
 *
 * compileChainedWithdraw takes per-hop kernels via `tapeKernels`; without it each
 * hop compiles against dummy prevouts (44../aa..) and any node answers
 * "Missing inputs". Each hop needs 10 FRI + 5 extras (1 cqz + 2 fold + 2 slot)
 * + 1 AIR carrier = 16 outputs.
 *
 * Fold and slot unlockings use ABSOLUTE query indices (covenant-spend passes
 * `queryStart + f`), so hop g gets fold/slot locks for q0 = g*QUERIES_PER_TAPE_HOP,
 * not locks 0..1. Identical groups would be unspendable.
 */
export function compileTapeKernelGroups(args: {
  wallet: LabWallet;
  utxo: { tx_hash: string; tx_pos: number; value: number };
  tapeHops: number;
  kernelSats?: number;
  feeSats?: bigint;
  /** Genesis sibling NFTs (vout 2+g), one per hop, each holding the OLD PAA1. */
  carriers: ChainUtxo[];
  /**
   * Option A' (FRI10-BATCH-EXIT.md): which hops carry their own note-auth kernel.
   * A batch of N notes sets the first N true, so hop g advances the nullifier root
   * by one step. Those hops get a 6th extra (the note lock, right after cqz) and
   * the group offsets stop being uniform. Omit for FRI9: every hop keeps 5 extras
   * and the layout is byte-identical.
   */
  noteAuthHops?: readonly boolean[];
}): {
  raw: Uint8Array;
  txid: string;
  groups: Array<{ carrier: ChainUtxo; fri: ChainUtxo[]; extra: ChainUtxo[] }>;
  changeValue: number;
} {
  if (args.carriers.length !== args.tapeHops) {
    throw new Error(`need ${args.tapeHops} sibling carriers, got ${args.carriers.length}`);
  }
  const kernelSats = BigInt(args.kernelSats ?? 1_000);
  const feeCoin = successorFeeCoinSats("standard");
  const noteAt = (g: number) => args.noteAuthHops?.[g] === true;
  if (args.noteAuthHops && args.noteAuthHops.length !== args.tapeHops) {
    throw new Error(
      `noteAuthHops ${args.noteAuthHops.length} != tapeHops ${args.tapeHops}`,
    );
  }
  // 5 extras per hop (cqz + 2 fold + 2 slots), plus the note lock on hops that
  // carry one. Offsets are cumulative because that count varies per hop.
  const extrasAt = (g: number) => 5 + (noteAt(g) ? 1 : 0);
  const baseAt = (g: number) => {
    let off = 0;
    for (let i = 0; i < g; i += 1) off += FRI_KERNEL_INPUTS + extrasAt(i);
    return off;
  };
  const c = compiler();
  const data = { keys: { privateKeys: { key: privateKeyOf(args.wallet) } } };
  const outputs: Array<{ lockingBytecode: Uint8Array; valueSatoshis: bigint }> = [];
  for (let g = 0; g < args.tapeHops; g += 1) {
    const q0 = g * QUERIES_PER_TAPE_HOP;
    outputs.push({ lockingBytecode: compileFriQueryLockP2sh32(0), valueSatoshis: kernelSats + feeCoin });
    for (let i = 1; i < FRI_KERNEL_INPUTS; i += 1) {
      outputs.push({ lockingBytecode: compileFriQueryLockP2sh32(i), valueSatoshis: kernelSats });
    }
    // extras, in the order compileCovenantSuccessor consumes them
    outputs.push({ lockingBytecode: compileCqzLockP2sh32(), valueSatoshis: kernelSats });
    // Must sit directly after cqz: compileCovenantSuccessor reads extras as
    // [cqz, note?, folds, slots] on a tape hop.
    if (noteAt(g)) {
      outputs.push({ lockingBytecode: compileNoteAuthLockP2sh32(), valueSatoshis: kernelSats });
    }
    for (let f = 0; f < QUERIES_PER_TAPE_HOP; f += 1) {
      outputs.push({ lockingBytecode: compileFoldLockP2sh32(1, q0 + f), valueSatoshis: kernelSats });
    }
    for (let i = 0; i < QUERIES_PER_TAPE_HOP; i += 1) {
      outputs.push({ lockingBytecode: compileSlotsLockP2sh32(q0 + i), valueSatoshis: kernelSats });
    }
  }

  const spend = outputs.reduce((n, o) => n + o.valueSatoshis, 0n);
  const fee = args.feeSats ?? 2_000n + BigInt(outputs.length) * 80n;
  const change = BigInt(args.utxo.value) - spend - fee;
  if (change < DUST_SATS) {
    throw new Error(
      `tape kernel groups need ${spend + fee + DUST_SATS}, utxo has ${args.utxo.value}`,
    );
  }
  outputs.push({ lockingBytecode: p2pkhLockingOf(args.wallet), valueSatoshis: change });

  const generated = generateTransaction({
    version: 2,
    locktime: 0,
    inputs: [
      {
        outpointIndex: args.utxo.tx_pos,
        outpointTransactionHash: hexToBin(args.utxo.tx_hash),
        sequenceNumber: 0xffffffff,
        unlockingBytecode: { compiler: c, script: "unlock", data, valueSatoshis: BigInt(args.utxo.value) },
      },
    ],
    outputs,
  });
  if (!generated.success) {
    throw new Error(`tape kernel groups: ${JSON.stringify(generated.errors).slice(0, 400)}`);
  }
  const raw = encodeTransaction(generated.transaction);
  const txid = hashTransaction(raw);

  const groups = Array.from({ length: args.tapeHops }, (_, g) => {
    const base = baseAt(g);
    const at = (i: number, v: bigint) => ({ tx_hash: txid, tx_pos: base + i, value: Number(v) });
    return {
      fri: [
        at(0, kernelSats + feeCoin),
        ...Array.from({ length: FRI_KERNEL_INPUTS - 1 }, (_, i) => at(i + 1, kernelSats)),
      ],
      extra: Array.from({ length: extrasAt(g) }, (_, i) => at(FRI_KERNEL_INPUTS + i, kernelSats)),
      carrier: args.carriers[g]!,
    };
  });
  return { raw, txid, groups, changeValue: Number(change) };
}

export async function broadcastChained(args: {
  hops: ChainedHop[];
  electrum?: (rawHex: string) => Promise<string>;
  rpc?: BchnRpcConfig;
}): Promise<Array<{ txid: string; path: BroadcastPath; index: number; role: "tape" | "pay" }>> {
  const sent: Array<{ txid: string; path: BroadcastPath; index: number; role: "tape" | "pay" }> = [];
  for (const hop of args.hops) {
    try {
      const r = await broadcastSized({ raw: hop.raw, electrum: args.electrum, rpc: args.rpc });
      sent.push({ txid: r.txid, path: r.path, index: hop.index, role: hop.role });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      throw new Error(`chained hop ${hop.index} ${hop.role}: ${msg}`);
    }
  }
  return sent;
}

export function chainedShape(chain: ChainedWithdraw): Record<string, unknown> {
  return {
    envelope: "chained",
    hops: chain.hops.map((h) => ({
      index: h.index,
      role: h.role,
      txid: h.txid,
      txBytes: h.txBytes,
      payoutCount: h.payoutCount,
      commitHex: h.commitHex ?? null,
    })),
    payIndex: chain.payIndex,
    totalBytes: chain.totalBytes,
    timeoutCsv: chain.timeout.sequence,
    timeoutTxid: chain.timeout.txid,
    note: "tape hops run fold/C=QZ slices and never pay; last hop is the 36-query consensus verifier (same as envelope B)",
  };
}

/**
 * BCH 2026 VM verifier for Circle FRI paired Merkle openings.
 * Standard P2S lock is 201 bytes — this kernel is a P2SH32 redeem
 * (OP_SHA256 + OP_BEGIN/OP_UNTIL). A digest / OP_RETURN is not Verify.
 */
import { createTestAuthenticationProgramBch, createVirtualMachineBch2026 } from "@bitauth/libauth";
import { add, encodeLe, mul } from "../backends/circle/m31.ts";
import { decodeFriProof, verifyFri, type FriProof } from "../backends/circle/fri.ts";
import { FRI_N, FRI_QUERIES } from "../backends/circle/params.ts";
import {
  compileFriMerkleOnlyKernel,
  compileFriMerkleOnlyLockP2sh32,
  compileFriQueryKernel,
  compileFriQueryLockP2sh32,
  FRI_KERNEL_INPUTS,
  FRI_PAIR_BYTES,
  FRI_QUERY_KERNEL,
} from "./fri-kernel.ts";
import {
  compileCqzLockP2sh32,
  compileSlotsLockP2sh32,
  cqzKernelUnlocking,
  SLOT_KERNEL_COUNT,
  SLOTS_PER_KERNEL,
  slotsKernelUnlocking,
} from "./air-cqz.ts";
import {
  compileFoldLockP2sh32,
  foldKernelCount,
  foldKernelUnlocking,
  foldQueriesPerKernel,
  foldQueryShardInput,
  slotInputsCount,
} from "./fold-kernel.ts";
import { compileGrindLockP2sh32, grindKernelUnlocking } from "./grind-kernel.ts";
import { compileAlgebraicCLockP2sh32, algebraicCKernelUnlocking } from "./algebraic-c-kernel.ts";
import {
  compileNoteAuthLockP2sh32,
  includeNoteAuth,
  noteAuthKernelUnlocking,
  noteAuthUnlockingFromProof,
} from "./note-auth-kernel.ts";
import type { Note } from "../pool/notes.ts";
import { uniqueTableAndIndex, compactPath, encodeLayerUnlocking, actualLayer } from "./merkle-multiproof.ts";
import { encodeSteps, parentIndexOf } from "./vm-steps.ts";
import {
  collectFriOpenings,
  dummyFriOpenings,
  dummyFriOpeningsWide,
  dummyFriShardUnlockings,
  dummyFriShardUnlockingsNoL0,
  dummyFriShardUnlockingsUnbound,
  encodeLayerRootsPrefix,
  friShardUnlockings,
  openingPairsBlob,
  packedWithPairs,
  proofShardReport,
  queryPairShard,
} from "./fri-openings.ts";
import {
  AIR_OFF_CELLS,
  AIR_OFF_EVEN,
  AIR_OFF_IDX,
  AIR_OFF_NTABLE,
  AIR_OFF_QTABLE,
  AIR_PACKED_SIZE,
  encodeAirPacked,
  fiatShamirQueryIndices,
  nqzAt,
} from "./air-cqz.ts";
import { statementDigest, type PoolStatement } from "../pool/statement.ts";
import { COMMITTED_LAYERS } from "../backends/circle/params.ts";
import {
  compilePoolCovenant,
  FIVE_POINT_PAA1,
  p2sh32Unlocking,
  poolLockP2sh32,
  pushData,
} from "./covenant-p2s.ts";
import { encodePublicPaa1, STATE_BASE_SATS, utxoValueFor, type AnyAmountState } from "../pool/state.ts";
import { concatBytes, isZero32 } from "../pool/bytes.ts";
import { LAB_PAYOUT_LOCKING } from "./payout.ts";

export { compileFriQueryKernel, compileFriQueryLockP2sh32, FRI_QUERY_KERNEL };

export function poolLockRedeem(): Uint8Array {
  return compilePoolCovenant();
}



function dummyPrevout(tag: number, i: number): Uint8Array {
  const h = new Uint8Array(32).fill(tag);
  h[30] = (i >> 8) & 0xff;
  h[31] = i & 0xff;
  return h;
}

function concat(parts: Uint8Array[]): Uint8Array {
  const n = parts.reduce((s, p) => s + p.length, 0);
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

function push(data: Uint8Array): Uint8Array {
  return pushData(data);
}

export { encodeSteps, parentIndexOf };

export function encodeFriQueryUnlocking(args: {
  left: Uint8Array;
  right: Uint8Array;
  root: Uint8Array;
  parentPath: Uint8Array[];
  parentIndex: number;
  layerIndex?: number;
  slot?: number;
}): Uint8Array {
  const layer = actualLayer(args.layerIndex ?? 0);
  const { table, indexOf } = uniqueTableAndIndex(args.parentPath);
  const compact = compactPath(args.parentIndex, args.parentPath, indexOf);
  return encodeLayerUnlocking(
    {
      layer,
      table,
      openings: [
        {
          left: args.left,
          right: args.right,
          parentIndex: args.parentIndex,
          compactPath: compact,
          slot: args.slot ?? 0,
          layerIndex: args.layerIndex ?? layer,
        },
      ],
    },
    compileFriQueryKernel(layer),
  );
}

export type VmEval = {
  accepted: boolean;
  error: string | null;
  unlockingBytes: number;
  lockingBytes: number;
};

export function evaluateBch2026(locking: Uint8Array, unlocking: Uint8Array): VmEval {
  const vm = createVirtualMachineBch2026(true);
  const program = createTestAuthenticationProgramBch({
    lockingBytecode: locking,
    unlockingBytecode: unlocking,
    valueSatoshis: 1000n,
  });
  const state = vm.evaluate(program);
  const ok = vm.stateSuccess(state);
  return {
    accepted: ok === true,
    error: ok === true ? null : String(ok),
    unlockingBytes: unlocking.length,
    lockingBytes: locking.length,
  };
}

/** Roots + qTable so an isolated kernel can membership-check layer-0 leaves. */
function packedForOpening(p: FriProof, layerRoots?: Uint8Array[]): Uint8Array {
  const packed = new Uint8Array(AIR_PACKED_SIZE);
  const roots = layerRoots ?? p.layerRoots;
  for (let r = 0; r < COMMITTED_LAYERS; r += 1) {
    packed.set(roots[r] ?? new Uint8Array(32), r * 32);
  }
  for (let s = 0; s < p.queries.length && s < FRI_QUERIES; s += 1) {
    packed.set(encodeLe(p.queries[s]!.layers[0]!.value), AIR_OFF_QTABLE + s * 4);
  }
  return packed;
}

export function evaluateFriQueryOpening(args: {
  left: Uint8Array;
  right: Uint8Array;
  root: Uint8Array;
  parentPath: Uint8Array[];
  parentIndex: number;
  layerIndex?: number;
  /** Forwarded to encodeFriQueryUnlocking, which binds the L0 felt to qTable[slot]. */
  slot?: number;
  packed?: Uint8Array;
}): VmEval {
  const vm = createVirtualMachineBch2026(true);
  const layer = actualLayer(args.layerIndex ?? 0);
  const roots = Array.from({ length: 7 }, (_, i) => (i === layer ? args.root : new Uint8Array(32)));
  const packed = args.packed ? args.packed : (() => {
    const p = new Uint8Array(AIR_PACKED_SIZE);
    for (let r = 0; r < COMMITTED_LAYERS; r += 1) p.set(roots[r]!, r * 32);
    return p;
  })();
  // N=1 unlocking consumes the last remaining pair group. Isolated openings
  // carry one 56-byte group; qTable still keys off `slot`.
  const pairs = new Uint8Array(FRI_PAIR_BYTES);
  pairs.set(args.left, layer * 8);
  pairs.set(args.right, layer * 8 + 4);
  const carrierBody = packed.length >= AIR_PACKED_SIZE
    ? packed.length === AIR_PACKED_SIZE
      ? concatBytes(packed.subarray(0, AIR_PACKED_SIZE), pairs)
      : packed
    : concatBytes(packed, pairs);
  const carrierUnlock = pushData(carrierBody.length >= AIR_PACKED_SIZE ? carrierBody : concatBytes(packed, pairs));
  const carrierLock = Uint8Array.of(0x75, 0x51);
  const sourceOutputs = [
    { lockingBytecode: carrierLock, valueSatoshis: 1000n },
    { lockingBytecode: compileFriQueryLockP2sh32(layer), valueSatoshis: 1000n },
  ];
  const transaction = {
    version: 2,
    locktime: 0,
    inputs: [
      {
        outpointTransactionHash: new Uint8Array(32).fill(0x22),
        outpointIndex: 0,
        sequenceNumber: 0xffffffff,
        unlockingBytecode: carrierUnlock,
      },
      {
        outpointTransactionHash: new Uint8Array(32).fill(0x44),
        outpointIndex: 0,
        sequenceNumber: 0xffffffff,
        unlockingBytecode: encodeFriQueryUnlocking(args),
      },
    ],
    outputs: [{ lockingBytecode: carrierLock, valueSatoshis: 1000n }],
  };
  const result = vm.verify({ sourceOutputs, transaction });
  return {
    accepted: result === true,
    error: result === true ? null : String(result),
    unlockingBytes: encodeFriQueryUnlocking(args).length,
    lockingBytes: compileFriQueryLockP2sh32(layer).length,
  };
}

export function evaluateDigestOnly(): VmEval {
  const digest = new Uint8Array(40);
  digest.set(new TextEncoder().encode("PAA1PROF"));
  const unlocking = concat([push(digest), push(compileFriQueryKernel())]);
  return evaluateBch2026(compileFriQueryLockP2sh32(), unlocking);
}

export function evaluateMissingProof(): VmEval {
  return evaluateBch2026(compileFriQueryLockP2sh32(), push(compileFriQueryKernel()));
}

export function firstFriQueryUnlocking(proof: Uint8Array | FriProof): Uint8Array {
  return friShardUnlockings(proof)[0]!;
}

/** Full pool successor: five-point + FRI-kernel input, no OP_RETURN digest. */
export function buildPoolSuccessorTx(args: {
  oldState: AnyAmountState;
  newState: AnyAmountState;
  proof: Uint8Array;
  category?: Uint8Array;
  kernelUnlockings?: Uint8Array[];
  statement?: PoolStatement;
  airPacked?: Uint8Array;
  /** Override fold-kernel pair shards (default queryPairShard of the proof). */
  foldPairShards?: Uint8Array[];
  outputValueSats?: bigint;
  payoutLockingBytecode?: Uint8Array;
  payoutValueSats?: bigint;
  extraPayouts?: Array<{ lockingBytecode: Uint8Array; sats: bigint }>;
  /** Override output PAA1 (default encodePublicPaa1(newState)). */
  outputCommitment?: Uint8Array;
  slotKernels?: number;
  /** false = consensus/nonstandard (tx may exceed 100 KB). Default: standard iff slotKernels is the 100 KB count. */
  standard?: boolean;
  /** Opened note for the B note-auth kernel. */
  note?: Note;
  change?: Note;
}): {
  transaction: {
    version: number;
    locktime: number;
    inputs: Array<{
      outpointTransactionHash: Uint8Array;
      outpointIndex: number;
      sequenceNumber: number;
      unlockingBytecode: Uint8Array;
    }>;
    outputs: Array<{ lockingBytecode: Uint8Array; valueSatoshis: bigint; token?: unknown }>;
  };
  sourceOutputs: Array<{ lockingBytecode: Uint8Array; valueSatoshis: bigint; token?: unknown }>;
  poolLock: Uint8Array;
  standard: boolean;
} {
  const slotKernels = args.slotKernels ?? SLOT_KERNEL_COUNT;
  const standard = args.standard ?? slotKernels <= SLOT_KERNEL_COUNT;
  const poolLock = poolLockP2sh32({ slotKernels });
  const category = args.category ?? new Uint8Array(32).fill(0x11);
  const poolValue = utxoValueFor(args.oldState);
  const newValue = args.outputValueSats ?? utxoValueFor(args.newState);
  const net = newValue - poolValue;
  const payoutLock = args.payoutLockingBytecode ?? LAB_PAYOUT_LOCKING;
  const wantPayout =
    Boolean(args.statement) &&
    args.statement!.publicAmountSats < 0n &&
    !isZero32(args.statement!.payoutLockingDigest);
  const payoutValue = args.payoutValueSats ?? (net < 0n ? -net : 0n);
  const funderNeed = net > 0n ? net : 0n;
  const funderLock = Uint8Array.of(0x51);
  const foldN = foldKernelCount(slotKernels);
  const decodedEarly = decodeFriProof(args.proof);
  const packedEarly =
    args.airPacked ??
    (args.statement ? encodeAirPacked(args.statement, decodedEarly) : undefined);
  const cqzLock = compileCqzLockP2sh32();
  const airOnly =
    packedEarly instanceof Uint8Array && packedEarly.length >= AIR_PACKED_SIZE
      ? packedEarly.subarray(0, AIR_PACKED_SIZE)
      : packedEarly instanceof Uint8Array
        ? packedEarly
        : undefined;
  const cqzCarrier =
    packedEarly instanceof Uint8Array && packedEarly.length >= AIR_PACKED_SIZE + 8
      ? packedEarly
      : packedEarly instanceof Uint8Array && args.proof
        ? packedWithPairs(airOnly ?? packedEarly, args.proof)
        : packedEarly;
  const shards = args.kernelUnlockings ?? friShardUnlockings(args.proof, { allPairGroups: foldN > 1 });
  const cqzUnlock = cqzKernelUnlocking(cqzCarrier);
  const foldQ = foldQueriesPerKernel(slotKernels);
  const foldLocks = Array.from({ length: foldN }, (_, f) => compileFoldLockP2sh32(foldQ, f * foldQ));
  const foldUnlocks = Array.from({ length: foldN }, (_, f) =>
    foldKernelUnlocking(
      foldQ,
      f * foldQ,
      airOnly,
      args.foldPairShards?.[f] ?? queryPairShard(args.proof, f * foldQ, foldQ),
    ),
  );
  const slotN = slotInputsCount(slotKernels);
  const slotUnlocks = Array.from({ length: slotN }, (_, i) =>
    slotsKernelUnlocking(
      i * (slotKernels > SLOT_KERNEL_COUNT ? SLOTS_PER_KERNEL : 1),
      slotKernels > SLOT_KERNEL_COUNT ? SLOTS_PER_KERNEL : 1,
      airOnly,
    ),
  );
  const sourceOutputs = [
    {
      lockingBytecode: poolLock,
      valueSatoshis: poolValue,
      token: {
        amount: 0n,
        category,
        nft: { capability: "mutable" as const, commitment: encodePublicPaa1(args.oldState) },
      },
    },
    ...shards.map((_, i) => ({ lockingBytecode: compileFriQueryLockP2sh32(i), valueSatoshis: 1000n })),
    { lockingBytecode: cqzLock, valueSatoshis: 1000n },
    { lockingBytecode: compileGrindLockP2sh32(), valueSatoshis: 1000n },
    { lockingBytecode: compileAlgebraicCLockP2sh32(), valueSatoshis: 1000n },
    ...(includeNoteAuth(slotKernels) ? [{ lockingBytecode: compileNoteAuthLockP2sh32(), valueSatoshis: 1000n }] : []),
    ...foldLocks.map((lockingBytecode) => ({ lockingBytecode, valueSatoshis: 1000n })),
    ...slotUnlocks.map((_, i) => ({
      lockingBytecode: compileSlotsLockP2sh32(
        i * (slotKernels > SLOT_KERNEL_COUNT ? SLOTS_PER_KERNEL : 1),
        slotKernels > SLOT_KERNEL_COUNT ? SLOTS_PER_KERNEL : 1,
      ),
      valueSatoshis: 1000n,
    })),
    ...(funderNeed > 0n ? [{ lockingBytecode: funderLock, valueSatoshis: funderNeed }] : []),
  ];
  const decoded = decodeFriProof(args.proof);
  const prefix = args.airPacked
    ?? (args.statement ? encodeAirPacked(args.statement, decoded) : decoded.layerRoots);
  const carrier =
    prefix instanceof Uint8Array && prefix.length >= AIR_PACKED_SIZE
      ? prefix.length === AIR_PACKED_SIZE
        ? packedWithPairs(prefix, args.proof)
        : prefix
      : prefix;
  const poolUnlock = p2sh32Unlocking(undefined, carrier, { slotKernels });
  const transaction = {
    version: 2,
    locktime: 0,
    inputs: [
      {
        outpointTransactionHash: new Uint8Array(32).fill(0x11),
        outpointIndex: 0,
        sequenceNumber: 0xffffffff,
        unlockingBytecode: poolUnlock,
      },
      ...shards.map((unlocking, i) => ({
        outpointTransactionHash: new Uint8Array(32).fill(0x44 + i),
        outpointIndex: 0,
        sequenceNumber: 0xffffffff,
        unlockingBytecode: unlocking,
      })),
      {
        outpointTransactionHash: new Uint8Array(32).fill(0xa0),
        outpointIndex: 0,
        sequenceNumber: 0xffffffff,
        unlockingBytecode: cqzUnlock,
      },
      {
        outpointTransactionHash: new Uint8Array(32).fill(0xa1),
        outpointIndex: 0,
        sequenceNumber: 0xffffffff,
        unlockingBytecode: grindKernelUnlocking(packedEarly instanceof Uint8Array ? packedEarly : undefined),
      },
      {
        outpointTransactionHash: new Uint8Array(32).fill(0xa2),
        outpointIndex: 0,
        sequenceNumber: 0xffffffff,
        unlockingBytecode: algebraicCKernelUnlocking(),
      },
      ...(includeNoteAuth(slotKernels)
        ? [
            {
              outpointTransactionHash: new Uint8Array(32).fill(0xa3),
              outpointIndex: 0,
              sequenceNumber: 0xffffffff,
              unlockingBytecode: (() => {
                if (!args.note) throw new Error("B note-auth kernel needs the opened note");
                if (!args.statement) throw new Error("B note-auth kernel needs the statement");
                return noteAuthUnlockingFromProof({
                  note: args.note,
                  change: args.change,
                  proof: args.proof,
                  statement: args.statement,
                });
              })(),
            },
          ]
        : []),
      ...foldUnlocks.map((unlocking, i) => ({
        outpointTransactionHash: dummyPrevout(0xb0, i),
        outpointIndex: 0,
        sequenceNumber: 0xffffffff,
        unlockingBytecode: unlocking,
      })),
      ...slotUnlocks.map((unlocking, i) => ({
        outpointTransactionHash: dummyPrevout(0xc0, i),
        outpointIndex: 0,
        sequenceNumber: 0xffffffff,
        unlockingBytecode: unlocking,
      })),
      ...(funderNeed > 0n
        ? [
            {
              outpointTransactionHash: dummyPrevout(0xd0, 0),
              outpointIndex: 0,
              sequenceNumber: 0xffffffff,
              unlockingBytecode: new Uint8Array(),
            },
          ]
        : []),
    ],
    outputs: [
      {
        lockingBytecode: poolLock,
        valueSatoshis: newValue,
        token: {
          amount: 0n,
          category,
          nft: { capability: "mutable" as const, commitment: args.outputCommitment ?? encodePublicPaa1(args.newState) },
        },
      },
      ...(args.extraPayouts && args.extraPayouts.length > 0
        ? [
            ...args.extraPayouts.map((p) => ({
              lockingBytecode: p.lockingBytecode,
              valueSatoshis: p.sats,
            })),
            { lockingBytecode: Uint8Array.of(0x51), valueSatoshis: 546n },
          ]
        : wantPayout
          ? [{ lockingBytecode: payoutLock, valueSatoshis: payoutValue }]
          : []),
    ],
  };
  return { transaction, sourceOutputs, poolLock, standard };
}

export type InputMeter = {
  i: number;
  unlocking: number;
  accepted: boolean;
  error: string | null;
  operationCost: number;
  maximumOperationCost: number;
  hashDigestIterations: number;
  maximumHashDigestIterations: number;
  opPct: number;
  hashPct: number;
};

function numMeter(x: number | bigint | undefined): number {
  if (x === undefined) return 0;
  return typeof x === "bigint" ? Number(x) : x;
}

/** Per-input standard=true evaluate. Tx-size failure does not block a single input. */
export function evaluateSuccessorInputMeters(
  args: Parameters<typeof buildPoolSuccessorTx>[0],
): { standardTxAccepted: boolean; standardTxError: string | null; inputs: InputMeter[] } {
  const built = buildPoolSuccessorTx({ ...args, standard: true });
  const vm = createVirtualMachineBch2026(true);
  const full = vm.verify({
    sourceOutputs: built.sourceOutputs,
    transaction: built.transaction,
  } as never);
  const inputs = built.transaction.inputs.map((inp, i) => {
    const state = vm.evaluate({
      inputIndex: i,
      sourceOutputs: built.sourceOutputs,
      transaction: built.transaction,
    } as never);
    const ok = vm.stateSuccess(state);
    const m = (state as { metrics?: Record<string, number | bigint> }).metrics ?? {};
    const operationCost = numMeter(m.operationCost);
    const maximumOperationCost = numMeter(m.maximumOperationCost);
    const hashDigestIterations = numMeter(m.hashDigestIterations);
    const maximumHashDigestIterations = numMeter(m.maximumHashDigestIterations);
    return {
      i,
      unlocking: inp.unlockingBytecode.length,
      accepted: ok === true,
      error: ok === true ? null : String(ok).slice(0, 200),
      operationCost,
      maximumOperationCost,
      hashDigestIterations,
      maximumHashDigestIterations,
      opPct: maximumOperationCost ? +(100 * operationCost / maximumOperationCost).toFixed(2) : 0,
      hashPct: maximumHashDigestIterations ? +(100 * hashDigestIterations / maximumHashDigestIterations).toFixed(2) : 0,
    };
  });
  return {
    standardTxAccepted: full === true,
    standardTxError: full === true ? null : String(full).slice(0, 240),
    inputs,
  };
}

export function evaluatePoolSuccessorVm(
  args: Parameters<typeof buildPoolSuccessorTx>[0],
): VmEval {
  const built = buildPoolSuccessorTx(args);
  const vm = createVirtualMachineBch2026(built.standard);
  const result = vm.verify({
    sourceOutputs: built.sourceOutputs,
    transaction: built.transaction,
  } as never);
  return {
    accepted: result === true,
    error: result === true ? null : String(result),
    unlockingBytes: built.transaction.inputs[0]!.unlockingBytecode.length,
    lockingBytes: built.poolLock.length,
  };
}

/** Isolated note-auth kernel against a pool NFT pair. No FRI kernels. */
export function evaluateNoteAuthKernel(args: {
  oldState: AnyAmountState;
  newState: AnyAmountState;
  action: 1n | 2n;
  note: Note;
  spentIndex: number;
  spentPath: Uint8Array[];
  createdIndex: number;
  createdPath: Uint8Array[];
  change?: Note;
}): VmEval {
  const vm = createVirtualMachineBch2026(true);
  const carrierLock = Uint8Array.of(0x75, 0x51);
  const category = new Uint8Array(32).fill(0x11);
  const packed = new Uint8Array(AIR_PACKED_SIZE);
  packed.set(encodeLe(args.action), AIR_OFF_CELLS + 3 * 4);
  const unlocking = noteAuthKernelUnlocking(args);
  const value = 100_000n;
  const sourceOutputs = [
    {
      lockingBytecode: carrierLock,
      valueSatoshis: value,
      token: {
        amount: 0n,
        category,
        nft: { capability: "mutable" as const, commitment: encodePublicPaa1(args.oldState) },
      },
    },
    { lockingBytecode: compileNoteAuthLockP2sh32(), valueSatoshis: 1000n },
  ];
  const transaction = {
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
        unlockingBytecode: unlocking,
      },
    ],
    outputs: [
      {
        lockingBytecode: carrierLock,
        valueSatoshis: value,
        token: {
          amount: 0n,
          category,
          nft: { capability: "mutable" as const, commitment: encodePublicPaa1(args.newState) },
        },
      },
    ],
  };
  const result = vm.verify({ sourceOutputs, transaction });
  return {
    accepted: result === true,
    error: result === true ? null : String(result),
    unlockingBytes: unlocking.length,
    lockingBytes: compileNoteAuthLockP2sh32().length,
  };
}

export function evaluateDigestOnlyPool(oldState: AnyAmountState): VmEval {
  const vm = createVirtualMachineBch2026(true);
  const poolLock = poolLockP2sh32();
  const digest = new Uint8Array(40);
  digest.set(new TextEncoder().encode("PAA1PROF"));
  const sourceOutputs = [
    {
      lockingBytecode: poolLock,
      valueSatoshis: STATE_BASE_SATS,
      token: {
        amount: 0n,
        category: new Uint8Array(32).fill(0x11),
        nft: { capability: "mutable" as const, commitment: encodePublicPaa1(oldState) },
      },
    },
  ];
  const transaction = {
    version: 2,
    locktime: 0,
    inputs: [
      {
        outpointTransactionHash: new Uint8Array(32).fill(0x11),
        outpointIndex: 0,
        sequenceNumber: 0xffffffff,
        unlockingBytecode: concat([push(digest), p2sh32Unlocking()]),
      },
    ],
    outputs: [
      {
        lockingBytecode: poolLock,
        valueSatoshis: STATE_BASE_SATS,
        token: {
          amount: 0n,
          category: new Uint8Array(32).fill(0x11),
          nft: { capability: "mutable" as const, commitment: encodePublicPaa1(oldState) },
        },
      },
    ],
  };
  const result = vm.verify({ sourceOutputs, transaction });
  return {
    accepted: result === true,
    error: result === true ? null : String(result),
    unlockingBytes: transaction.inputs[0]!.unlockingBytecode.length,
    lockingBytes: poolLock.length,
  };
}

export function evaluateMissingProofPool(oldState: AnyAmountState): VmEval {
  const vm = createVirtualMachineBch2026(true);
  const poolLock = poolLockP2sh32();
  const sourceOutputs = [
    {
      lockingBytecode: poolLock,
      valueSatoshis: STATE_BASE_SATS,
      token: {
        amount: 0n,
        category: new Uint8Array(32).fill(0x11),
        nft: { capability: "mutable" as const, commitment: encodePublicPaa1(oldState) },
      },
    },
  ];
  const transaction = {
    version: 2,
    locktime: 0,
    inputs: [
      {
        outpointTransactionHash: new Uint8Array(32).fill(0x11),
        outpointIndex: 0,
        sequenceNumber: 0xffffffff,
        unlockingBytecode: p2sh32Unlocking(),
      },
    ],
    outputs: sourceOutputs,
  };
  const result = vm.verify({ sourceOutputs, transaction });
  return {
    accepted: result === true,
    error: result === true ? null : String(result),
    unlockingBytes: p2sh32Unlocking().length,
    lockingBytes: poolLock.length,
  };
}

/**
 * Lab bar = 2026 lock AND JS verifyFri. A does not walk notes/nullifiers.
 * B adds a note-auth kernel; batch-exit extra notes still stay in verifyFri.
 */
export function evaluateOnChainVerify(
  statement: PoolStatement,
  proof: Uint8Array,
): { accepted: boolean; pool: VmEval; stark: ReturnType<typeof verifyFri> } {
  const pool = evaluatePoolSuccessorVm({
    oldState: statement.oldState,
    newState: statement.newState,
    proof,
    statement,
  });
  const stark = verifyFri(statement, decodeFriProof(proof));
  return { accepted: pool.accepted && stark.ok, pool, stark };
}

export function evaluateProofOnVm(proof: FriProof | Uint8Array): {
  accepted: boolean;
  failed: string | null;
  queryEvals: number;
  unlockingMax: number;
} {
  const p = proof instanceof Uint8Array ? decodeFriProof(proof) : proof;
  const packed = packedWithPairs(packedForOpening(p), p);
  const shards = friShardUnlockings(p);
  let unlockingMax = 0;
  for (let s = 0; s < shards.length; s += 1) {
    const ev = evaluateFriShard(packed, shards[s]!, s);
    unlockingMax = Math.max(unlockingMax, ev.unlockingBytes);
    if (!ev.accepted) {
      return {
        accepted: false,
        failed: ev.error ?? `shard ${s}`,
        queryEvals: collectFriOpenings(p).length,
        unlockingMax,
      };
    }
  }
  return { accepted: true, failed: null, queryEvals: collectFriOpenings(p).length, unlockingMax };
}

function evaluateFriShard(packed: Uint8Array, unlocking: Uint8Array, layer = 0): VmEval {
  const vm = createVirtualMachineBch2026(true);
  const carrierUnlock = pushData(packed.length === AIR_PACKED_SIZE ? packed : packed);
  const carrierLock = Uint8Array.of(0x75, 0x51);
  const sourceOutputs = [
    { lockingBytecode: carrierLock, valueSatoshis: 1000n },
    { lockingBytecode: compileFriQueryLockP2sh32(layer), valueSatoshis: 1000n },
  ];
  const transaction = {
    version: 2,
    locktime: 0,
    inputs: [
      {
        outpointTransactionHash: new Uint8Array(32).fill(0x22),
        outpointIndex: 0,
        sequenceNumber: 0xffffffff,
        unlockingBytecode: carrierUnlock,
      },
      {
        outpointTransactionHash: new Uint8Array(32).fill(0x44),
        outpointIndex: 0,
        sequenceNumber: 0xffffffff,
        unlockingBytecode: unlocking,
      },
    ],
    outputs: [{ lockingBytecode: carrierLock, valueSatoshis: 1000n }],
  };
  const result = vm.verify({ sourceOutputs, transaction });
  return {
    accepted: result === true,
    error: result === true ? null : String(result),
    unlockingBytes: unlocking.length,
    lockingBytes: compileFriQueryLockP2sh32().length,
  };
}

export function evaluateFalseRoot(proof: FriProof | Uint8Array): VmEval {
  const p = proof instanceof Uint8Array ? decodeFriProof(proof) : proof;
  const q = p.queries[0]!;
  const layer = q.layers[0]!;
  const n = FRI_N;
  const i = q.index % n;
  const lo = i < n / 2;
  const bad = new Uint8Array(p.layerRoots[0]!);
  bad[0] ^= 1;
  const packed = packedForOpening(p);
  packed.set(bad, 0);
  return evaluateFriQueryOpening({
    left: encodeLe(lo ? layer.value : layer.partner),
    right: encodeLe(lo ? layer.partner : layer.value),
    root: bad,
    parentPath: layer.path,
    parentIndex: parentIndexOf(i, n),
    layerIndex: 0,
    packed,
  });
}

/** Honest PAA1 walk + dummy 8-leaf kernel openings against this statement's roots. */
export function evaluateDummyKernels(args: {
  oldState: AnyAmountState;
  newState: AnyAmountState;
  proof: Uint8Array;
  statement?: PoolStatement;
}): VmEval {
  return evaluatePoolSuccessorVm({
    ...args,
    kernelUnlockings: dummyFriShardUnlockings(),
  });
}

/** Honest Merkle kernels; nTable[0] flipped so slot-0 Q·Z ≠ nTable (Newton T is not the interpolant). */
export function evaluateCookedNTable(args: {
  oldState: AnyAmountState;
  newState: AnyAmountState;
  proof: Uint8Array;
  statement: PoolStatement;
}): VmEval {
  const honest = encodeAirPacked(args.statement, args.proof);
  const cooked = new Uint8Array(honest);
  cooked[AIR_OFF_NTABLE] ^= 1;
  return evaluatePoolSuccessorVm({
    ...args,
    airPacked: cooked,
    statement: args.statement,
  });
}

/** Honest kernels; seq cell 23 flipped so PAA1 bind fails. */
export function evaluateCookedT(args: {
  oldState: AnyAmountState;
  newState: AnyAmountState;
  proof: Uint8Array;
  statement: PoolStatement;
}): VmEval {
  const honest = encodeAirPacked(args.statement, args.proof);
  const cooked = new Uint8Array(honest);
  cooked[AIR_OFF_CELLS + 23 * 4] ^= 1;
  return evaluatePoolSuccessorVm({
    ...args,
    airPacked: cooked,
    statement: args.statement,
  });
}

/** Honest slot 0; a later off-trace slot has q'·Z cooked into nTable. */
export function evaluateCookedLaterSlot(args: {
  oldState: AnyAmountState;
  newState: AnyAmountState;
  proof: Uint8Array;
  statement: PoolStatement;
}): VmEval {
  const cooked = new Uint8Array(encodeAirPacked(args.statement, args.proof));
  for (let s = 1; s < FRI_QUERIES; s += 1) {
    const i = (cooked[AIR_OFF_IDX + s * 2]! << 8) | cooked[AIR_OFF_IDX + s * 2 + 1]!;
    const { z, q } = nqzAt(args.statement, i);
    if (z === 0n) continue;
    const q2 = add(q, 1n);
    cooked.set(encodeLe(q2), AIR_OFF_QTABLE + s * 4);
    cooked.set(encodeLe(mul(q2, z)), AIR_OFF_NTABLE + s * 4);
    break;
  }
  return evaluatePoolSuccessorVm({
    ...args,
    airPacked: cooked,
    statement: args.statement,
  });
}

/**
 * 8-leaf dummy openings (short Merkle path) with qTable planted so membership
 * would pass. Must fail the FRI_N path-depth gate (issue #2: synthetic tree).
 */
export function evaluateDummyShortPath(args: {
  oldState: AnyAmountState;
  newState: AnyAmountState;
  proof: Uint8Array;
  statement: PoolStatement;
}): VmEval {
  const honest = encodeAirPacked(args.statement, args.proof);
  const dummy = dummyFriOpenings(8);
  const packed = new Uint8Array(honest);
  for (let r = 0; r < COMMITTED_LAYERS; r += 1) packed.set(dummy[0]!.root, r * 32);
  for (let s = 0; s < FRI_QUERIES; s += 1) {
    packed.set(dummy[s % dummy.length]!.left, AIR_OFF_QTABLE + s * 4);
  }
  return evaluatePoolSuccessorVm({
    ...args,
    airPacked: packed,
    kernelUnlockings: dummyFriShardUnlockings(),
  });
}

/**
 * Honest openings of proof A against packed AIR of a different statement.
 * Independent fixtures must not assemble into one accept (issue #2).
 */
export function evaluateCrossPacked(args: {
  oldState: AnyAmountState;
  newState: AnyAmountState;
  proof: Uint8Array;
  statement: PoolStatement;
  otherPacked: Uint8Array;
}): VmEval {
  return evaluatePoolSuccessorVm({
    ...args,
    airPacked: args.otherPacked,
  });
}

/**
 * Dummy 8-leaf openings with only layerIndex 17–22 (no actual layer 0),
 * dummy roots, honest T, qTable[0]=nTable[0]=N/Z at FS(dummy roots).
 */
export function evaluateDummyNoL0(args: {
  oldState: AnyAmountState;
  newState: AnyAmountState;
  proof: Uint8Array;
  statement: PoolStatement;
}): VmEval {
  const honest = encodeAirPacked(args.statement, args.proof);
  const dummy = dummyFriOpenings(8);
  const packed = new Uint8Array(honest);
  for (let r = 0; r < COMMITTED_LAYERS; r += 1) packed.set(dummy[0]!.root, r * 32);
  const decoded = decodeFriProof(args.proof);
  const dummyRoots = Array.from({ length: COMMITTED_LAYERS }, () => dummy[0]!.root);
  const i0 = fiatShamirQueryIndices(statementDigest(args.statement), {
    ...decoded,
    layerRoots: dummyRoots,
  })[0]!;
  const slot = nqzAt(args.statement, i0);
  packed.set(encodeLe(slot.q), AIR_OFF_QTABLE);
  packed.set(encodeLe(slot.n), AIR_OFF_NTABLE);
  return evaluatePoolSuccessorVm({
    ...args,
    airPacked: packed,
    kernelUnlockings: dummyFriShardUnlockingsNoL0(),
  });
}

/**
 * Dummy 8-leaf openings with layerIndex 16+k, dummy roots, honest T,
 * qTable[0]=nTable[0]=N/Z at FS(dummy roots). A kernel that skips the Q bind
 * on 16+ would accept this.
 */
export function evaluateDummyUnbound(args: {
  oldState: AnyAmountState;
  newState: AnyAmountState;
  proof: Uint8Array;
  statement: PoolStatement;
}): VmEval {
  const honest = encodeAirPacked(args.statement, args.proof);
  const dummy = dummyFriOpenings(8);
  const packed = new Uint8Array(honest);
  for (let r = 0; r < COMMITTED_LAYERS; r += 1) packed.set(dummy[0]!.root, r * 32);
  const decoded = decodeFriProof(args.proof);
  const dummyRoots = Array.from({ length: COMMITTED_LAYERS }, () => dummy[0]!.root);
  const i0 = fiatShamirQueryIndices(statementDigest(args.statement), {
    ...decoded,
    layerRoots: dummyRoots,
  })[0]!;
  const slot = nqzAt(args.statement, i0);
  packed.set(encodeLe(slot.q), AIR_OFF_QTABLE);
  packed.set(encodeLe(slot.n), AIR_OFF_NTABLE);
  return evaluatePoolSuccessorVm({
    ...args,
    airPacked: packed,
    kernelUnlockings: dummyFriShardUnlockingsUnbound(),
  });
}

/**
 * Dummy 8-leaf openings + dummy layerRoots, honest T / qTable = N/Z.
 * Skeptic dummy-consistent spend: Merkle walks the dummy tree; C=QZ sees honest Q.
 */
export function evaluateDummyConsistent(args: {
  oldState: AnyAmountState;
  newState: AnyAmountState;
  proof: Uint8Array;
  statement: PoolStatement;
}): VmEval {
  const honest = encodeAirPacked(args.statement, args.proof);
  const dummy = dummyFriOpenings(8);
  const packed = new Uint8Array(honest);
  for (let r = 0; r < COMMITTED_LAYERS; r += 1) packed.set(dummy[0]!.root, r * 32);
  return evaluatePoolSuccessorVm({
    ...args,
    airPacked: packed,
    kernelUnlockings: dummyFriShardUnlockings(),
  });
}

/** Dummy 8-leaf kernels AND dummy layerRoots/qTable in the pool unlocking. */
export function evaluateSwappedDummyKernels(args: {
  oldState: AnyAmountState;
  newState: AnyAmountState;
  proof: Uint8Array;
  statement: PoolStatement;
}): VmEval {
  const dummy = dummyFriOpenings(8);
  const honest = encodeAirPacked(args.statement, args.proof);
  const swapped = new Uint8Array(honest);
  for (let r = 0; r < 7; r += 1) swapped.set(dummy[0]!.root, r * 32);
  for (let s = 0; s < FRI_QUERIES && AIR_OFF_QTABLE + (s + 1) * 4 <= swapped.length; s += 1) {
    swapped.set(dummy[s % dummy.length]!.left, AIR_OFF_QTABLE + s * 4);
  }
  swapped.set(encodeLe(1n), AIR_OFF_NTABLE);
  return evaluatePoolSuccessorVm({
    ...args,
    kernelUnlockings: dummyFriShardUnlockings(),
    airPacked: swapped,
    statement: args.statement,
  });
}

/** Packed + first nFold FRI shards + fold kernel only (no pool five-point). */
export function evaluateFoldKernelOnly(args: {
  statement: PoolStatement;
  proof: Uint8Array;
  nFold?: number;
  sourceInput?: number;
  queryIndex?: number;
}): VmEval {
  const nFold = args.nFold ?? 1;
  const queryIndex =
    args.queryIndex ?? (args.sourceInput !== undefined ? args.sourceInput - 1 : 0);
  const vm = createVirtualMachineBch2026(true);
  const packed = encodeAirPacked(args.statement, args.proof);
  const carrier = packedWithPairs(packed, args.proof);
  const foldLock = compileFoldLockP2sh32(nFold, queryIndex);
  const foldUnlock = foldKernelUnlocking(
    nFold,
    queryIndex,
    packed,
    queryPairShard(args.proof, queryIndex, nFold),
  );
  const carrierLock = Uint8Array.of(0x75, 0x51);
  const sourceOutputs = [
    { lockingBytecode: carrierLock, valueSatoshis: 1000n },
    { lockingBytecode: foldLock, valueSatoshis: 1000n },
  ];
  const transaction = {
    version: 2,
    locktime: 0,
    inputs: [
      {
        outpointTransactionHash: new Uint8Array(32).fill(0x22),
        outpointIndex: 0,
        sequenceNumber: 0xffffffff,
        unlockingBytecode: pushData(carrier),
      },
      {
        outpointTransactionHash: new Uint8Array(32).fill(0x87),
        outpointIndex: 0,
        sequenceNumber: 0xffffffff,
        unlockingBytecode: foldUnlock,
      },
    ],
    outputs: [{ lockingBytecode: carrierLock, valueSatoshis: 1000n }],
  };
  const result = vm.verify({ sourceOutputs, transaction });
  return {
    accepted: result === true,
    error: result === true ? null : String(result),
    unlockingBytes: foldUnlock.length,
    lockingBytes: foldLock.length,
  };
}

/** Packed FS index flipped so foldPair uses the wrong domain point. */
export function evaluateWrongFoldIndex(args: {
  oldState: AnyAmountState;
  newState: AnyAmountState;
  proof: Uint8Array;
  statement: PoolStatement;
  queryIndex?: number;
  slotKernels?: number;
  standard?: boolean;
  note?: Note;
  change?: Note;
}): VmEval {
  const packed = encodeAirPacked(args.statement, args.proof);
  const q = args.queryIndex ?? 0;
  packed[AIR_OFF_IDX + q * 2] ^= 1;
  return evaluatePoolSuccessorVm({
    ...args,
    airPacked: packed,
    statement: args.statement,
  });
}

export function proofFitsEnvelope(proof: Uint8Array): {
  proofBytes: number;
  shards: number;
  unlockingLimit: number;
  txLimit: number;
  shardsFit10k: boolean;
  txFit100k: boolean;
  unlockingMax: number;
  openings: number;
} {
  const report = proofShardReport(proof);
  return {
    proofBytes: proof.length,
    shards: report.shards,
    unlockingLimit: 10_000,
    txLimit: 100_000,
    shardsFit10k: report.shardsFit10k,
    txFit100k: report.txFit100k,
    unlockingMax: report.unlockingMax,
    openings: report.openings,
  };
}

export { FIVE_POINT_PAA1, FRI_QUERIES };

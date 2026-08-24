import { binToHex, cashAssemblyToBin, encodeLockingBytecodeP2sh32, hash256 } from "@bitauth/libauth";
import { compileFriQueryLockP2sh32, FRI_KERNEL_INPUTS } from "./fri-kernel.ts";
import { encodeLayerRootsPrefix } from "./fri-openings.ts";
import { AIR_PACKED_SIZE, compileCqzLockP2sh32, compileSlotsLockP2sh32, SLOT_KERNEL_COUNT, SLOTS_PER_KERNEL } from "./air-cqz.ts";
import { compileFoldLockP2sh32, foldKernelCount, foldQueriesPerKernel, slotInputsCount } from "./fold-kernel.ts";
import { compileGrindLockP2sh32 } from "./grind-kernel.ts";
import { compileAlgebraicCLockP2sh32 } from "./algebraic-c-kernel.ts";
import { compileNoteAuthLockP2sh32, includeNoteAuth, prefixExtraKernelCount } from "./note-auth-kernel.ts";
import {
  EXTRACT_INSTANCE,
  EXTRACT_RESERVE_NUM,
  EXTRACT_SEQ_NUM,
  EXTRACT_WD_NUM,
  encodeWalkSteps,
} from "./note-merkle.ts";
import { STATE_BASE_SATS } from "../pool/state.ts";
import { AIR_OFF_PAYOUT, extractCellAsm } from "./air-cqz.ts";

/**
 * Pool lock = covenant, not P2PKH.
 * P2S: locking bytecode is this program.
 * P2SH32: hash256(program) in the lock (ShieldKit P1 shell).
 *
 * OP_SIZE leaves the commitment on the stack — OP_DROP it or the successor
 * fails with "Extra items left on stack" (seen on Chipnet against 0adce2ca…).
 *
 * Output-0's 128-byte PAA1 is bound: instance id, noteRoot (equal or
 * incremental append), nullifierRoot (equal or SHA-256(old||nf)).
 * Unlocking: <packed AIR 1704> [<redeem>]. Envelope B (and C pay hop) adds a
 * note-auth kernel that walks leaf+path to noteRoot, chains the nullifier
 * into nfRoot, and SHA-256-binds amount/rho/owner. A has no room for that
 * kernel. Batch-exit extra notes stay in verifyFri. Withdraw binds every
 * payout lock+value (not only output 1) and withdrawalCount delta = payout count.
 */
export const FIVE_POINT_PAA1 = `
OP_0 OP_OUTPUTBYTECODE
OP_INPUTINDEX OP_UTXOBYTECODE
OP_EQUALVERIFY
OP_0 OP_OUTPUTTOKENCATEGORY
OP_INPUTINDEX OP_UTXOTOKENCATEGORY
OP_EQUALVERIFY
OP_0 OP_OUTPUTTOKENAMOUNT
OP_INPUTINDEX OP_UTXOTOKENAMOUNT
OP_NUMEQUALVERIFY
OP_0 OP_OUTPUTTOKENCOMMITMENT
OP_SIZE <128> OP_EQUALVERIFY
OP_DROP
OP_0 OP_OUTPUTTOKENCOMMITMENT
<4> OP_SPLIT OP_DROP
<0x50414131> OP_EQUALVERIFY
`;

/**
 * `forceNoteAuth` is envelope C's pay hop: it runs 4 slots (so
 * `includeNoteAuth(4)` is false) but still carries a note-auth kernel because an
 * opened note is supplied. Without this the covenant checks index 14 for the fold
 * lock, finds note-auth, and OP_EQUALVERIFY fails - every later index is shifted
 * by one too. Default false keeps A and B byte-identical.
 */
function requireFriInputsAsm(
  slotKernels = SLOT_KERNEL_COUNT,
  forceNoteAuth = false,
  /**
   * Option B (note-auth-step-kernel.ts): one lock per note, pinned by index
   * after the slots. Unpinned they would be unobserved - a prover could simply
   * omit them - which is the trap plain option A fell into. When steps are
   * present the audited single-note kernel is NOT included: its one
   * SHA256(oldRoot || nf) == newRoot step is exactly what a batch cannot
   * satisfy. Empty for FRI9, which keeps the layout byte-identical.
   */
  stepLocks: readonly Uint8Array[] = [],
): string {
  const cqzHex = binToHex(compileCqzLockP2sh32());
  const grindHex = binToHex(compileGrindLockP2sh32());
  const algHex = binToHex(compileAlgebraicCLockP2sh32());
  const foldN = foldKernelCount(slotKernels);
  const foldQ = foldQueriesPerKernel(slotKernels);
  const slotN = slotInputsCount(slotKernels);
  const prefix = 1 + FRI_KERNEL_INPUTS;
  const batched = stepLocks.length > 0;
  const extraN = batched ? 3 : prefixExtraKernelCount(slotKernels, true, forceNoteAuth);
  const lines = [
    "OP_TXINPUTCOUNT",
    `<${prefix + extraN + foldN + slotN + stepLocks.length}>`,
    "OP_GREATERTHANOREQUAL",
    "OP_VERIFY",
  ];
  for (let i = 1; i <= FRI_KERNEL_INPUTS; i += 1) {
    const lockHex = binToHex(compileFriQueryLockP2sh32(i - 1));
    lines.push(`<${i}>`, "OP_UTXOBYTECODE", `<0x${lockHex}>`, "OP_EQUALVERIFY");
  }
  lines.push(`<${prefix}>`, "OP_UTXOBYTECODE", `<0x${cqzHex}>`, "OP_EQUALVERIFY");
  lines.push(`<${prefix + 1}>`, "OP_UTXOBYTECODE", `<0x${grindHex}>`, "OP_EQUALVERIFY");
  lines.push(`<${prefix + 2}>`, "OP_UTXOBYTECODE", `<0x${algHex}>`, "OP_EQUALVERIFY");
  if (!batched && includeNoteAuth(slotKernels, forceNoteAuth)) {
    const noteHex = binToHex(compileNoteAuthLockP2sh32());
    lines.push(`<${prefix + 3}>`, "OP_UTXOBYTECODE", `<0x${noteHex}>`, "OP_EQUALVERIFY");
  }
  for (let f = 0; f < foldN; f += 1) {
    const foldHex = binToHex(compileFoldLockP2sh32(foldQ, f * foldQ));
    lines.push(
      `<${prefix + extraN + f}>`,
      "OP_UTXOBYTECODE",
      `<0x${foldHex}>`,
      "OP_EQUALVERIFY",
    );
  }
  for (let i = 0; i < slotN; i += 1) {
    const slotsHex = binToHex(compileSlotsLockP2sh32(i * (slotKernels > SLOT_KERNEL_COUNT ? SLOTS_PER_KERNEL : 1), slotKernels > SLOT_KERNEL_COUNT ? SLOTS_PER_KERNEL : 1));
    lines.push(
      `<${prefix + extraN + foldN + i}>`,
      "OP_UTXOBYTECODE",
      `<0x${slotsHex}>`,
      "OP_EQUALVERIFY",
    );
  }
  // Step kernels last, one per note, each pinned to its own (R_in, R_out)
  // address so neither the order nor the count can be altered.
  for (const [j, lock] of stepLocks.entries()) {
    lines.push(
      `<${prefix + extraN + foldN + slotN + j}>`,
      "OP_UTXOBYTECODE",
      `<0x${binToHex(lock)}>`,
      "OP_EQUALVERIFY",
    );
  }
  return lines.join("\n");
}

/** Inputs 1..FRI_KERNEL_INPUTS must be the batch FRI kernel. Extra fee inputs may follow. */
export const REQUIRE_FRI_INPUTS = requireFriInputsAsm();

/** Bind new PAA1 cell. B note-auth kernel walks membership/nullifier; A does not. */
export const BIND_PAA1 = `
OP_INPUTINDEX OP_UTXOTOKENCOMMITMENT
OP_SIZE <128> OP_EQUALVERIFY
OP_DROP
OP_INPUTINDEX OP_UTXOTOKENCOMMITMENT
${EXTRACT_INSTANCE}
OP_0 OP_OUTPUTTOKENCOMMITMENT
${EXTRACT_INSTANCE}
OP_EQUALVERIFY
OP_INPUTINDEX OP_UTXOTOKENCOMMITMENT
${EXTRACT_SEQ_NUM}
<1> OP_ADD
OP_0 OP_OUTPUTTOKENCOMMITMENT
${EXTRACT_SEQ_NUM}
OP_NUMEQUALVERIFY
OP_INPUTINDEX OP_UTXOTOKENCOMMITMENT
${EXTRACT_RESERVE_NUM}
OP_0
OP_NUMEQUALVERIFY
OP_0 OP_OUTPUTTOKENCOMMITMENT
${EXTRACT_RESERVE_NUM}
OP_0
OP_NUMEQUALVERIFY
OP_INPUTINDEX OP_UTXOVALUE
<${Number(STATE_BASE_SATS)}>
OP_GREATERTHANOREQUAL
OP_VERIFY
OP_0 OP_OUTPUTVALUE
<${Number(STATE_BASE_SATS)}>
OP_GREATERTHANOREQUAL
OP_VERIFY
OP_DUP
${extractCellAsm(5)}
OP_OVER
${extractCellAsm(3)}
<2>
OP_NUMEQUAL
OP_IF
  OP_NEGATE
OP_ENDIF
OP_INPUTINDEX OP_UTXOVALUE
OP_ADD
OP_0 OP_OUTPUTVALUE
OP_NUMEQUALVERIFY
OP_DUP
${extractCellAsm(3)}
<2>
OP_NUMEQUAL
OP_IF
  OP_DUP
  ${extractCellAsm(5)}
  OP_TXOUTPUTCOUNT
  <3>
  OP_LESSTHAN
  OP_IF
    OP_1 OP_OUTPUTVALUE
  OP_ELSE
    OP_0
    <1>
    OP_BEGIN
      OP_DUP
      OP_OUTPUTVALUE
      OP_ROT
      OP_ADD
      OP_SWAP
      OP_1ADD
      OP_DUP
      OP_TXOUTPUTCOUNT
      OP_1SUB
      OP_GREATERTHANOREQUAL
    OP_UNTIL
    OP_DROP
  OP_ENDIF
  OP_NUMEQUALVERIFY
  OP_DUP
  <${AIR_OFF_PAYOUT}>
  OP_SPLIT
  OP_NIP
  <32>
  OP_SPLIT
  OP_DROP
  OP_TXOUTPUTCOUNT
  <4>
  OP_LESSTHAN
  OP_IF
    OP_1 OP_OUTPUTBYTECODE
    OP_HASH256
  OP_ELSE
    OP_1 OP_OUTPUTBYTECODE
    OP_HASH256
    OP_1 OP_OUTPUTVALUE
    <8> OP_NUM2BIN
    OP_CAT
    <2>
    OP_BEGIN
      OP_DUP
      OP_OUTPUTBYTECODE
      OP_HASH256
      OP_OVER
      OP_OUTPUTVALUE
      <8> OP_NUM2BIN
      OP_CAT
      OP_ROT
      OP_SWAP
      OP_CAT
      OP_SWAP
      OP_1ADD
      OP_DUP
      OP_TXOUTPUTCOUNT
      OP_1SUB
      OP_GREATERTHANOREQUAL
    OP_UNTIL
    OP_DROP
    OP_HASH256
  OP_ENDIF
  OP_EQUALVERIFY
  OP_INPUTINDEX OP_UTXOTOKENCOMMITMENT
  ${EXTRACT_WD_NUM}
  OP_0 OP_OUTPUTTOKENCOMMITMENT
  ${EXTRACT_WD_NUM}
  OP_SWAP
  OP_SUB
  OP_TXOUTPUTCOUNT
  <3>
  OP_LESSTHAN
  OP_IF
    <1>
  OP_ELSE
    OP_TXOUTPUTCOUNT
    <2>
    OP_SUB
  OP_ENDIF
  OP_NUMEQUALVERIFY
  OP_DUP
  <${AIR_OFF_PAYOUT}>
  OP_SPLIT
  OP_NIP
  <32>
  OP_SPLIT
  OP_DROP
  <4>
  OP_SPLIT
  OP_DROP
  <0x00>
  OP_CAT
  OP_BIN2NUM
  <2147483647>
  OP_MOD
  OP_OVER
  ${extractCellAsm(6)}
  OP_NUMEQUALVERIFY
OP_ENDIF
OP_1
`;

/** Packed AIR blob sits under the witness; drop it after BIND so only OP_1 remains. */
export const DROP_LAYER_ROOTS = `
OP_TOALTSTACK
OP_DROP
OP_FROMALTSTACK
`;

export function compilePoolCovenant(opts?: {
  slotKernels?: number;
  forceNoteAuth?: boolean;
  /**
   * Envelope C: require the last input (the tape tip) to carry exactly this
   * locking bytecode - the terminal link L(digest, tapeN). Without it the pay hop
   * could spend a tip committed to another digest and the tape would bind nothing
   * to this statement. Depends only on the digest, so no cycle with the tip
   * covenant. See C-BINDING.md.
   */
  tapeTipLock?: Uint8Array;
  /**
   * Option A' (FRI10-BATCH-EXIT.md): require output-0's nullifierRoot to be
   * exactly this. Closes the batch chain — the tape hops each prove one honest
   * step R_i -> R_{i+1} under their own root-pinned tip
   * (`tapeTipRedeemChainWithRoots`), and this pins the pool's landing point R_N.
   *
   * Needed because the note-auth kernel advances the root by exactly one step, so
   * a single kernel cannot express an N-note batch, and nothing else constrains
   * the root: `checkBatchSpends` (air.ts:148) does not check the fold, and AIR
   * cells 21/22 are assigned but appear in no constraint.
   *
   * nullifierRoot is bytes 96..128 of the 128-byte PAA1 (state.ts:77).
   */
  finalNfRoot?: Uint8Array;
  /**
   * Option B: the per-note step-kernel locks this transaction must carry, in
   * order. Pair with `finalNfRoot` so the chain they walk is anchored at both
   * ends. Omit for FRI9.
   */
  stepLocks?: readonly Uint8Array[];
}): Uint8Array {
  const slots = opts?.slotKernels ?? SLOT_KERNEL_COUNT;
  const requireTape = opts?.tapeTipLock
    ? `
OP_TXINPUTCOUNT OP_1SUB OP_UTXOBYTECODE <0x${binToHex(opts.tapeTipLock)}> OP_EQUALVERIFY`
    : "";
  if (opts?.finalNfRoot && opts.finalNfRoot.length !== 32) {
    throw new Error(`finalNfRoot must be 32 bytes, got ${opts.finalNfRoot.length}`);
  }
  const requireFinalRoot = opts?.finalNfRoot
    ? `
<0> OP_OUTPUTTOKENCOMMITMENT <96> OP_SPLIT OP_NIP <0x${binToHex(opts.finalNfRoot)}> OP_EQUALVERIFY`
    : "";
  const bin = cashAssemblyToBin(
    `${FIVE_POINT_PAA1}\n${requireFriInputsAsm(slots, opts?.forceNoteAuth ?? false, opts?.stepLocks ?? [])}${requireTape}${requireFinalRoot}\n${BIND_PAA1}\n${DROP_LAYER_ROOTS}`,
  );
  if (typeof bin === "string") throw new Error(`covenant compile: ${bin}`);
  return bin;
}

export function poolLockP2s(): Uint8Array {
  return compilePoolCovenant();
}

export function poolLockP2sh32(opts?: {
  slotKernels?: number;
  forceNoteAuth?: boolean;
  tapeTipLock?: Uint8Array;
  /** Option A': pin output-0 nullifierRoot. See compilePoolCovenant. */
  finalNfRoot?: Uint8Array;
  /** Option B: per-note step-kernel locks. See compilePoolCovenant. */
  stepLocks?: readonly Uint8Array[];
}): Uint8Array {
  return encodeLockingBytecodeP2sh32(hash256(compilePoolCovenant(opts)));
}

export function poolLockP2sFor(opts?: {
  slotKernels?: number;
  forceNoteAuth?: boolean;
  tapeTipLock?: Uint8Array;
  /** Option A': pin output-0 nullifierRoot. See compilePoolCovenant. */
  finalNfRoot?: Uint8Array;
  /** Option B: per-note step-kernel locks. See compilePoolCovenant. */
  stepLocks?: readonly Uint8Array[];
}): Uint8Array {
  return compilePoolCovenant(opts);
}

function concatPrefix(packed: Uint8Array, pairs: Uint8Array): Uint8Array {
  const out = new Uint8Array(packed.length + pairs.length);
  out.set(packed, 0);
  out.set(pairs, packed.length);
  return out;
}

/** Bitcoin script push of `data` (redeem / unlocking payload). */
export function pushData(data: Uint8Array): Uint8Array {
  if (data.length <= 75) return Uint8Array.of(data.length, ...data);
  if (data.length <= 255) return Uint8Array.of(0x4c, data.length, ...data);
  if (data.length <= 0xffff) {
    return Uint8Array.of(0x4d, data.length & 0xff, (data.length >> 8) & 0xff, ...data);
  }
  throw new Error("push too large");
}

export type PoolUnlockWitness = {
  walkLeaf: Uint8Array;
  walkPath: Uint8Array[];
  walkIndex: number;
  nullifier: Uint8Array;
  amountSats: bigint;
  rho: Uint8Array;
  owner: Uint8Array;
  amountCommit: Uint8Array;
  spentLeaf: Uint8Array;
  spentPath: Uint8Array[];
  spentIndex: number;
};

function pushScriptNumber(n: bigint): Uint8Array {
  if (n === 0n) return Uint8Array.of(0x00);
  if (n >= 1n && n <= 16n) return Uint8Array.of(0x50 + Number(n));
  if (n < 0n || n > 0x7fffffffn) throw new Error(`script number ${n}`);
  const bytes: number[] = [];
  let v = n;
  while (v > 0n) {
    bytes.push(Number(v & 0xffn));
    v >>= 8n;
  }
  if ((bytes[bytes.length - 1]! & 0x80) !== 0) bytes.push(0);
  return pushData(Uint8Array.from(bytes));
}

export function poolWitnessPushes(w: PoolUnlockWitness): Uint8Array {
  const steps = encodeWalkSteps(w.walkIndex, w.walkPath);
  const spentSteps = encodeWalkSteps(w.spentIndex, w.spentPath);
  const parts = [
    pushData(w.walkLeaf),
    pushData(steps),
    pushData(w.nullifier),
    pushScriptNumber(w.amountSats),
    pushData(w.rho),
    pushData(w.owner),
    pushData(w.amountCommit),
    pushData(w.spentLeaf),
    pushData(spentSteps),
  ];
  const n = parts.reduce((s, p) => s + p.length, 0);
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

export function p2sh32Unlocking(
  w?: PoolUnlockWitness,
  layerRoots?: Uint8Array[] | Uint8Array,
  opts?: {
    slotKernels?: number;
    forceNoteAuth?: boolean;
    tapeTipLock?: Uint8Array;
    /** Option A': must match the lock's pin or the redeem will not hash to it. */
    finalNfRoot?: Uint8Array;
    /** Option B: must match the lock's step pins, for the same reason. */
    stepLocks?: readonly Uint8Array[];
  },
): Uint8Array {
  const redeem = pushData(compilePoolCovenant(opts));
  const prefix =
    layerRoots instanceof Uint8Array && layerRoots.length >= AIR_PACKED_SIZE
      ? pushData(layerRoots)
      : encodeLayerRootsPrefix(Array.isArray(layerRoots) ? layerRoots : []);
  if (!w) {
    const out = new Uint8Array(prefix.length + redeem.length);
    out.set(prefix, 0);
    out.set(redeem, prefix.length);
    return out;
  }
  const wit = poolWitnessPushes(w);
  const out = new Uint8Array(prefix.length + wit.length + redeem.length);
  out.set(prefix, 0);
  out.set(wit, prefix.length);
  out.set(redeem, prefix.length + wit.length);
  return out;
}

export function p2sUnlocking(w?: PoolUnlockWitness, layerRoots?: Uint8Array[] | Uint8Array): Uint8Array {
  const prefix =
    layerRoots instanceof Uint8Array && layerRoots.length >= AIR_PACKED_SIZE
      ? pushData(layerRoots)
      : encodeLayerRootsPrefix(Array.isArray(layerRoots) ? layerRoots : []);
  if (!w) return prefix;
  const wit = poolWitnessPushes(w);
  const out = new Uint8Array(prefix.length + wit.length);
  out.set(prefix, 0);
  out.set(wit, prefix.length);
  return out;
}

export function walkWitnessFromAuth(
  auth: {
    leaf: Uint8Array;
    index: number;
    path: Uint8Array[];
    nullifier: Uint8Array;
    createdLeaf: Uint8Array;
    createdIndex: number;
    createdPath: Uint8Array[];
    amountSats: bigint;
    publicDeltaSats: bigint;
    amountCommit: Uint8Array;
    rho: Uint8Array;
    owner: Uint8Array;
  },
  oldNoteRoot: Uint8Array,
  newNoteRoot: Uint8Array,
): PoolUnlockWitness {
  const same =
    oldNoteRoot.length === newNoteRoot.length && oldNoteRoot.every((b, i) => b === newNoteRoot[i]);
  const amountSats = auth.publicDeltaSats;
  return {
    walkLeaf: same ? auth.leaf : auth.createdLeaf,
    walkPath: same ? auth.path : auth.createdPath,
    walkIndex: same ? auth.index : auth.createdIndex,
    nullifier: auth.nullifier,
    amountSats,
    rho: auth.rho,
    owner: auth.owner,
    amountCommit: auth.amountCommit,
    spentLeaf: auth.leaf,
    spentPath: auth.path,
    spentIndex: auth.index,
  };
}

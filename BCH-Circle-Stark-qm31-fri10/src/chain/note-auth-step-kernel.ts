/**
 * Note-auth STEP kernel — a NEW kernel beside the audited one, never an edit to it.
 *
 * WHY IT EXISTS. The audited `note-auth-kernel.ts` reads its old and new nullifier
 * roots from the transaction itself:
 *
 *     SHA256(<0> OP_UTXOTOKENCOMMITMENT.nfRoot || nf) == <0> OP_OUTPUTTOKENCOMMITMENT.nfRoot
 *
 * Both indices are absolute `0`, so every copy in a transaction reads the SAME
 * pair. N copies would need N distinct values out of one output commitment, which
 * is unsatisfiable for N > 1 — verified five ways in FRI10-BATCH-EXIT.md. That is
 * why envelope B, a single transaction, can walk exactly one note today.
 *
 * This kernel takes the two roots as BAKED CONSTANTS instead of reading the output:
 *
 *     SHA256(R_IN || nf) == R_OUT          (both baked into the redeem)
 *
 * So step j and step k are different programs at different P2SH32 addresses, and N
 * of them coexist in one transaction with nothing to collide over. It is the same
 * position-indexing the codebase already uses for `compileFoldLockP2sh32(nFold,
 * queryIndex)` and `compileSlotsLockP2sh32(slot)`.
 *
 * WHAT ANCHORS THE CHAIN. Nothing here ties R_0 to the pool's old root or R_N to
 * its new one — deliberately, so every step is the same shape. That is the
 * covenant's job: genesis mints the pool NFT with R_0 and pins R_N through
 * `finalNfRoot` (covenant-p2s.ts), and the covenant pins each step's lock by
 * index. A step kernel on its own proves only "this note's nullifier carries R_IN
 * to R_OUT", which is exactly what it should prove.
 *
 * WHAT IT DROPS. Batch exit is full-note only (`transition.ts` rejects partials:
 * "batch-exit is full-note only (partial would mint change)"), so there is no
 * change note and no deposit branch. That is why this is a straight line where the
 * audited kernel has two nested branches — not a simplification of its rules, but
 * the absence of the cases those branches handle. noteRoot is asserted unchanged.
 *
 * SIZE. Separate inputs, so each gets its own 10 KB unlocking budget — unlike
 * unrolling N notes into one kernel, which would cap at 8. The ceiling here is the
 * transaction size, so envelope B's 1 MB is the real limit.
 *
 * FRI_VERSION is untouched. Nothing here is wired into a default path; adopting it
 * is an audit call.
 */
import { cashAssemblyToBin, encodeLockingBytecodeP2sh32, hash256 } from "@bitauth/libauth";
import { HASH_AMOUNT_TAG } from "../amounts/hash-commit.ts";
import { writeI64LE, concatBytes, sha256 } from "../pool/bytes.ts";
import { nullifierOf, type Note } from "../pool/notes.ts";
import { defaultInternalHash, type InternalHash } from "../backends/circle/internal-hash.ts";
import {
  EXTRACT_INSTANCE,
  EXTRACT_NOTE_ROOT,
  NOTE_MERKLE_WALK,
  encodeWalkSteps,
} from "./note-merkle.ts";

function hexPush(data: Uint8Array): string {
  return `<0x${Buffer.from(data).toString("hex")}>`;
}

function pushData(data: Uint8Array): Uint8Array {
  if (data.length <= 75) return Uint8Array.of(data.length, ...data);
  if (data.length <= 255) return Uint8Array.of(0x4c, data.length, ...data);
  return Uint8Array.of(0x4d, data.length & 0xff, (data.length >> 8) & 0xff, ...data);
}

const TAG = hexPush(HASH_AMOUNT_TAG);

/**
 * Unlocking (bottom→top): steps, amount8, rho, owner — so the script starts with
 * `owner` on top and `steps` at the bottom, where the Merkle walk wants it.
 * `noteAuthStepUnlocking` below is the authority on that order.
 *
 * amountCommit = SHA256(tag || amount8 || rho)
 * leaf         = SHA256(amountCommit || rho || owner)
 * nf           = SHA256(instance || owner || rho)
 *
 * Identical to the audited kernel's three formulas; only the root handling differs.
 *
 * ORDERING GUARD. Each step also asserts its nullifier is strictly greater than
 * the previous step's, compared UNSIGNED (`<0x00> OP_CAT OP_BIN2NUM` - a 32-byte
 * value with its top byte >= 0x80 would otherwise read as negative, the same
 * idiom BIND_PAA1 uses). Strictly increasing implies all distinct, so spending
 * one note twice in a batch becomes unsatisfiable on chain rather than merely
 * caught by the proof. Step 0 uses ZERO32, which every real nullifier exceeds.
 */
export function noteAuthStepKernelAsm(
  rIn: Uint8Array,
  rOut: Uint8Array,
  prevNf: Uint8Array = new Uint8Array(32),
): string {
  if (rIn.length !== 32) throw new Error(`rIn must be 32 bytes, got ${rIn.length}`);
  if (rOut.length !== 32) throw new Error(`rOut must be 32 bytes, got ${rOut.length}`);
  if (prevNf.length !== 32) throw new Error(`prevNf must be 32 bytes, got ${prevNf.length}`);
  return `
OP_DUP OP_TOALTSTACK
OP_SWAP
OP_DUP OP_TOALTSTACK
<0> OP_UTXOTOKENCOMMITMENT
${EXTRACT_INSTANCE}
OP_ROT
OP_CAT
OP_SWAP
OP_CAT
OP_SHA256
OP_DUP
<0x00> OP_CAT OP_BIN2NUM
${hexPush(concatBytes(prevNf, Uint8Array.of(0)))} OP_BIN2NUM
OP_GREATERTHAN
OP_VERIFY
${hexPush(rIn)}
OP_SWAP
OP_CAT
OP_SHA256
${hexPush(rOut)}
OP_EQUALVERIFY
OP_FROMALTSTACK
OP_DUP OP_TOALTSTACK
OP_SWAP
${TAG}
OP_SWAP
OP_CAT
OP_SWAP
OP_CAT
OP_SHA256
OP_FROMALTSTACK
OP_CAT
OP_FROMALTSTACK
OP_CAT
OP_SHA256
OP_SWAP
${NOTE_MERKLE_WALK}
<0> OP_UTXOTOKENCOMMITMENT
${EXTRACT_NOTE_ROOT}
OP_EQUALVERIFY
<0> OP_UTXOTOKENCOMMITMENT
${EXTRACT_NOTE_ROOT}
<0> OP_OUTPUTTOKENCOMMITMENT
${EXTRACT_NOTE_ROOT}
OP_EQUALVERIFY
OP_1
`;
}

export function compileNoteAuthStepKernel(
  rIn: Uint8Array,
  rOut: Uint8Array,
  prevNf: Uint8Array = new Uint8Array(32),
): Uint8Array {
  const bin = cashAssemblyToBin(noteAuthStepKernelAsm(rIn, rOut, prevNf));
  if (typeof bin === "string") throw new Error(`note-auth-step-kernel: ${bin}`);
  return bin;
}

/** One address per (R_IN, R_OUT), so step j and step k cannot be swapped. */
export function compileNoteAuthStepLockP2sh32(
  rIn: Uint8Array,
  rOut: Uint8Array,
  prevNf: Uint8Array = new Uint8Array(32),
): Uint8Array {
  return encodeLockingBytecodeP2sh32(hash256(compileNoteAuthStepKernel(rIn, rOut, prevNf)));
}

/**
 * Unlocking payload. Push order is steps, amount8, rho, owner — so the script
 * starts with `owner` on top and `steps` at the bottom, where the Merkle walk
 * wants it.
 */
export function noteAuthStepUnlocking(args: {
  note: Note;
  index: number;
  path: Uint8Array[];
  rIn: Uint8Array;
  rOut: Uint8Array;
  /** The previous step's nullifier. Steps must run in strictly increasing
   *  nullifier order, which is what makes a duplicate note unsatisfiable. */
  prevNf?: Uint8Array;
}): Uint8Array {
  const payload = concatBytes(
    pushData(encodeWalkSteps(args.index, args.path)),
    pushData(writeI64LE(args.note.amountSats)),
    pushData(args.note.rho),
    pushData(args.note.ownerSecret),
  );
  const redeem = pushData(
    compileNoteAuthStepKernel(args.rIn, args.rOut, args.prevNf ?? new Uint8Array(32)),
  );
  return concatBytes(payload, redeem);
}

/**
 * The running roots a batch walks through: R_0 = old root, R_i = SHA256(R_{i-1} ||
 * nf_i), R_N = new root. Returned inclusive, so `roots.length === nullifiers.length + 1`.
 */
export function stepRoots(oldNfRoot: Uint8Array, nullifiers: readonly Uint8Array[]): Uint8Array[] {
  const out = [new Uint8Array(oldNfRoot)];
  // Plain SHA-256: this must match the VM's OP_SHA256, not whichever InternalHash
  // knob the prover happens to be using.
  for (const nf of nullifiers) out.push(sha256(concatBytes(out[out.length - 1]!, nf)));
  return out;
}

/**
 * Order N spends the way the on-chain guard compares them, and derive every
 * step's (rIn, rOut, prevNf).
 *
 * The kernel reads its nullifier with `OP_BIN2NUM` after appending 0x00, so the
 * comparison is UNSIGNED LITTLE-ENDIAN: byte 31 is the most significant. Sorting
 * any other way produces a plan the VM rejects, so this comparator is part of the
 * contract, not a convenience.
 *
 * Strictly increasing order is what makes a duplicate note unsatisfiable: two
 * copies of one note share a nullifier, and `nf > prevNf` is false for equals.
 */
export function stepPlan(args: {
  oldNfRoot: Uint8Array;
  poolInstanceId: Uint8Array;
  spends: ReadonlyArray<{ note: Note; index: number; path: Uint8Array[] }>;
  hash?: InternalHash;
}): {
  spends: Array<{
    note: Note;
    index: number;
    path: Uint8Array[];
    rIn: Uint8Array;
    rOut: Uint8Array;
    prevNf: Uint8Array;
  }>;
  roots: Uint8Array[];
} {
  const hash = args.hash ?? defaultInternalHash();
  const withNf = args.spends.map((s) => ({
    ...s,
    nf: nullifierOf(s.note, args.poolInstanceId, hash),
  }));
  withNf.sort((a, b) => cmpUnsignedLe(a.nf, b.nf));
  for (let i = 1; i < withNf.length; i += 1) {
    if (cmpUnsignedLe(withNf[i - 1]!.nf, withNf[i]!.nf) === 0) {
      throw new Error(`duplicate note at position ${i}: the same note cannot be spent twice`);
    }
  }
  const roots = stepRoots(args.oldNfRoot, withNf.map((s) => s.nf));
  return {
    spends: withNf.map((s, i) => ({
      note: s.note,
      index: s.index,
      path: s.path,
      rIn: roots[i]!,
      rOut: roots[i + 1]!,
      prevNf: i === 0 ? new Uint8Array(32) : withNf[i - 1]!.nf,
    })),
    roots,
  };
}

/** Matches OP_BIN2NUM on a 0x00-extended 32-byte push: little-endian, unsigned. */
export function cmpUnsignedLe(a: Uint8Array, b: Uint8Array): number {
  for (let i = a.length - 1; i >= 0; i -= 1) {
    if (a[i]! !== b[i]!) return a[i]! < b[i]! ? -1 : 1;
  }
  return 0;
}

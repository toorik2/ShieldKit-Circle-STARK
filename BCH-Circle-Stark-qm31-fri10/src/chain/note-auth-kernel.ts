/**
 * On-chain note Merkle + nullifier-root chain + amount/auth preimage.
 * B (and C pay hop) only — A does not carry this kernel by default. That is about
 * THIS kernel: the step kernel (note-auth-step-kernel.ts, 182 B) does fit A.
 * Spender unlocking carries the note; CashVM SHA-256 matches default InternalHash.
 * Dummy leftover-fill cargo is not this kernel.
 */
import { cashAssemblyToBin, encodeLockingBytecodeP2sh32, hash256 } from "@bitauth/libauth";
import { HASH_AMOUNT_TAG } from "../amounts/hash-commit.ts";
import { writeI64LE, ZERO32, concatBytes } from "../pool/bytes.ts";
import { type Note } from "../pool/notes.ts";
import { extractCellAsm, SLOT_KERNEL_COUNT } from "./air-cqz.ts";
import {
  EXTRACT_INSTANCE,
  EXTRACT_NF_ROOT,
  EXTRACT_NOTE_ROOT,
  NOTE_MERKLE_WALK,
  encodeWalkSteps,
} from "./note-merkle.ts";
import { decodeFriProof } from "../backends/circle/fri.ts";
import type { PoolStatement } from "../pool/statement.ts";


function hexPush(data: Uint8Array): string {
  return `<0x${Buffer.from(data).toString("hex")}>`;
}

function pushData(data: Uint8Array): Uint8Array {
  if (data.length <= 75) return Uint8Array.of(data.length, ...data);
  if (data.length <= 255) return Uint8Array.of(0x4c, data.length, ...data);
  return Uint8Array.of(0x4d, data.length & 0xff, (data.length >> 8) & 0xff, ...data);
}

const TAG = hexPush(HASH_AMOUNT_TAG);
const ZERO32_PUSH = hexPush(ZERO32);

/**
 * Unlocking (bottom→top): amount8 rho owner spentSteps createdSteps
 * changeAmount8 changeRho changeOwner redeem.
 *
 * amountCommit = SHA256(tag || amount8 || rho)
 * leaf         = SHA256(amountCommit || rho || owner)
 * nf           = SHA256(instance || owner || rho)
 *
 * Deposit: walk(ZERO32) then walk(leaf) with createdSteps; nfRoots equal.
 * Withdraw: walk(leaf) with spentSteps; SHA256(oldNfRoot||nf)==newNfRoot;
 * empty createdSteps ⇒ noteRoots equal; else change-note append.
 */
export const NOTE_AUTH_KERNEL_ASM = `
OP_TOALTSTACK
OP_TOALTSTACK
OP_TOALTSTACK
OP_TOALTSTACK
OP_TOALTSTACK
OP_TOALTSTACK
OP_TOALTSTACK
${TAG}
OP_SWAP
OP_CAT
OP_FROMALTSTACK
OP_DUP
OP_TOALTSTACK
OP_CAT
OP_SHA256
OP_FROMALTSTACK
OP_FROMALTSTACK
OP_2DUP
OP_TOALTSTACK
OP_TOALTSTACK
OP_TOALTSTACK
OP_CAT
OP_FROMALTSTACK
OP_CAT
OP_SHA256
<0> OP_UTXOTOKENCOMMITMENT
${EXTRACT_INSTANCE}
OP_FROMALTSTACK
OP_FROMALTSTACK
OP_SWAP
OP_CAT
OP_CAT
OP_SHA256
OP_TOALTSTACK
OP_TOALTSTACK
<0> OP_INPUTBYTECODE
<1> OP_SPLIT OP_NIP
<2> OP_SPLIT OP_NIP
${extractCellAsm(3)}
OP_DUP
<1>
OP_NUMEQUAL
OP_IF
  OP_DROP
  OP_FROMALTSTACK
  OP_FROMALTSTACK
  OP_DROP
  OP_FROMALTSTACK
  OP_DROP
  OP_FROMALTSTACK
  OP_SWAP
  OP_TOALTSTACK
  OP_DUP
  OP_TOALTSTACK
  ${ZERO32_PUSH}
  OP_SWAP
  ${NOTE_MERKLE_WALK}
  <0> OP_UTXOTOKENCOMMITMENT
  ${EXTRACT_NOTE_ROOT}
  OP_EQUALVERIFY
  OP_FROMALTSTACK
  OP_FROMALTSTACK
  OP_SWAP
  ${NOTE_MERKLE_WALK}
  <0> OP_OUTPUTTOKENCOMMITMENT
  ${EXTRACT_NOTE_ROOT}
  OP_EQUALVERIFY
  <0> OP_UTXOTOKENCOMMITMENT
  ${EXTRACT_NF_ROOT}
  <0> OP_OUTPUTTOKENCOMMITMENT
  ${EXTRACT_NF_ROOT}
  OP_EQUALVERIFY
  OP_FROMALTSTACK OP_DROP
  OP_FROMALTSTACK OP_DROP
  OP_FROMALTSTACK OP_DROP
OP_ELSE
  OP_DROP
  OP_FROMALTSTACK
  OP_FROMALTSTACK
  OP_FROMALTSTACK
  OP_ROT
  OP_SWAP
  ${NOTE_MERKLE_WALK}
  <0> OP_UTXOTOKENCOMMITMENT
  ${EXTRACT_NOTE_ROOT}
  OP_EQUALVERIFY
  <0> OP_UTXOTOKENCOMMITMENT
  ${EXTRACT_NF_ROOT}
  OP_SWAP
  OP_CAT
  OP_SHA256
  <0> OP_OUTPUTTOKENCOMMITMENT
  ${EXTRACT_NF_ROOT}
  OP_EQUALVERIFY
  OP_FROMALTSTACK
  OP_SIZE
  OP_0 OP_GREATERTHAN
  OP_IF
    OP_FROMALTSTACK
    OP_FROMALTSTACK
    OP_FROMALTSTACK
    OP_TOALTSTACK
    OP_TOALTSTACK
    ${TAG}
    OP_SWAP
    OP_CAT
    OP_FROMALTSTACK
    OP_DUP
    OP_TOALTSTACK
    OP_CAT
    OP_SHA256
    OP_FROMALTSTACK
    OP_FROMALTSTACK
    OP_TOALTSTACK
    OP_CAT
    OP_FROMALTSTACK
    OP_CAT
    OP_SHA256
    OP_SWAP
    OP_DUP
    OP_TOALTSTACK
    ${ZERO32_PUSH}
    OP_SWAP
    ${NOTE_MERKLE_WALK}
    <0> OP_UTXOTOKENCOMMITMENT
    ${EXTRACT_NOTE_ROOT}
    OP_EQUALVERIFY
    OP_FROMALTSTACK
    ${NOTE_MERKLE_WALK}
    <0> OP_OUTPUTTOKENCOMMITMENT
    ${EXTRACT_NOTE_ROOT}
    OP_EQUALVERIFY
  OP_ELSE
    OP_DROP
    <0> OP_UTXOTOKENCOMMITMENT
    ${EXTRACT_NOTE_ROOT}
    <0> OP_OUTPUTTOKENCOMMITMENT
    ${EXTRACT_NOTE_ROOT}
    OP_EQUALVERIFY
    OP_FROMALTSTACK OP_DROP
    OP_FROMALTSTACK OP_DROP
    OP_FROMALTSTACK OP_DROP
  OP_ENDIF
OP_ENDIF
OP_1
`;

export function compileNoteAuthKernel(): Uint8Array {
  const bin = cashAssemblyToBin(NOTE_AUTH_KERNEL_ASM);
  if (typeof bin === "string") throw new Error(`note-auth-kernel: ${bin}`);
  return bin;
}

export function compileNoteAuthLockP2sh32(): Uint8Array {
  return encodeLockingBytecodeP2sh32(hash256(compileNoteAuthKernel()));
}

export function includeNoteAuth(slotKernels: number, force = false): boolean {
  return force || slotKernels > SLOT_KERNEL_COUNT;
}

/**
 * bind-T + grind + algebraicC [+ note-auth on B or C pay]. Tape hops (no pool)
 * keep 1, or 2 under option A' when the hop carries its own note-auth kernel
 * (FRI10-BATCH-EXIT.md). FRI9 tape hops pass no note, so they stay at 1.
 */
export function prefixExtraKernelCount(slotKernels: number, includePool = true, forceNoteAuth = false): number {
  if (!includePool) return forceNoteAuth ? 2 : 1;
  return includeNoteAuth(slotKernels, forceNoteAuth) ? 4 : 3;
}

export function noteAuthKernelUnlocking(args: {
  note: Note;
  spentIndex: number;
  spentPath: Uint8Array[];
  createdIndex: number;
  createdPath: Uint8Array[];
  change?: Note;
}): Uint8Array {
  const spentSteps = encodeWalkSteps(args.spentIndex, args.spentPath);
  const createdSteps = encodeWalkSteps(args.createdIndex, args.createdPath);
  const change = args.change;
  const payload = concatBytes(
    pushData(writeI64LE(args.note.amountSats)),
    pushData(args.note.rho),
    pushData(args.note.ownerSecret),
    pushData(spentSteps),
    pushData(createdSteps),
    pushData(writeI64LE(change ? change.amountSats : 0n)),
    pushData(change ? change.rho : new Uint8Array(ZERO32)),
    pushData(change ? change.ownerSecret : new Uint8Array(ZERO32)),
  );
  const redeem = pushData(compileNoteAuthKernel());
  return concatBytes(payload, redeem);
}

export function noteAuthUnlockingFromProof(args: {
  note: Note;
  change?: Note;
  proof: Uint8Array;
  statement: PoolStatement;
}): Uint8Array {
  const auth = decodeFriProof(args.proof).auth;
  const deposit = args.statement.action === "DEPOSIT";
  return noteAuthKernelUnlocking({
    note: args.note,
    change: args.change,
    spentIndex: deposit ? auth.createdIndex : auth.index,
    spentPath: deposit ? auth.createdPath : auth.path,
    createdIndex: auth.createdIndex,
    createdPath: auth.createdPath,
  });
}

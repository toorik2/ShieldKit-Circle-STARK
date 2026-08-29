import { bytesToHex, concatBytes, writeU256BE } from "./bytes.ts";
import { commitPublicNet, commitReserve, NET_BLIND_LEN } from "../amounts/hash-commit.ts";
import { encodePublicPaa1, type AnyAmountState } from "./state.ts";
import { defaultInternalHash, type InternalHash } from "../backends/circle/internal-hash.ts";

export type ActionKind = "DEPOSIT" | "WITHDRAW";

export type PoolStatement = {
  profile: "any-amount-v0";
  action: ActionKind;
  publicAmountSats: bigint;
  /** 32-byte hiding blind for the net commit. Not serialized in `encodeStatement`. */
  netBlind: Uint8Array;
  oldState: AnyAmountState;
  newState: AnyAmountState;
  noteCommitment: Uint8Array;
  nullifier: Uint8Array;
  payoutLockingDigest: Uint8Array;
  /** Tagged internal-hash amount commits (32 bytes). Not Pedersen. */
  amountCommitIn: Uint8Array;
  amountCommitOut: Uint8Array;
};

export function encodeStatement(s: PoolStatement, hash: InternalHash = defaultInternalHash()): Uint8Array {
  if (s.netBlind.length !== NET_BLIND_LEN) throw new Error("net blind width");
  const actionByte = Uint8Array.of(s.action === "DEPOSIT" ? 1 : 2);
  return concatBytes(
    new TextEncoder().encode("PAA1STMT"),
    actionByte,
    commitPublicNet(s.publicAmountSats, s.payoutLockingDigest, s.netBlind, hash),
    encodePublicPaa1(s.oldState),
    encodePublicPaa1(s.newState),
    commitReserve(s.oldState.reserveSats, s.netBlind, hash),
    commitReserve(s.newState.reserveSats, s.netBlind, hash),
    s.noteCommitment,
    s.nullifier,
    s.payoutLockingDigest,
    s.amountCommitIn.length === 32 ? s.amountCommitIn : writeU256BE(0n),
    s.amountCommitOut.length === 32 ? s.amountCommitOut : writeU256BE(0n),
  );
}

export function statementDigest(s: PoolStatement, hash: InternalHash = defaultInternalHash()): Uint8Array {
  return hash.digest(encodeStatement(s, hash));
}

export function statementHex(s: PoolStatement): string {
  return bytesToHex(encodeStatement(s));
}

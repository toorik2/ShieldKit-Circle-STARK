import { bytesToHex, concatBytes, writeI64LE } from "./bytes.ts";
import { encodeState, type AnyAmountState } from "./state.ts";
import { defaultInternalHash, type InternalHash } from "../backends/circle/internal-hash.ts";

export type ActionKind = "DEPOSIT" | "WITHDRAW";

/**
 * The complete public statement for one v16 transition.
 *
 * `poolCategory` is the UI-order CashToken category of the immutable pool
 * lineage. It is public settlement context, not duplicated inside PAA2.
 * `createdEdge` is non-zero exactly when the transition creates one note.
 */
export type PoolStatement = {
  profile: "sealed-creation-log-v1";
  action: ActionKind;
  publicAmountSats: bigint;
  poolCategory: Uint8Array;
  oldState: AnyAmountState;
  newState: AnyAmountState;
  createdEdge: Uint8Array;
  nullifier: Uint8Array;
  payoutLockingDigest: Uint8Array;
};

function width32(value: Uint8Array, label: string): Uint8Array {
  if (value.length !== 32) throw new Error(`${label} must be 32 bytes`);
  return value;
}

/** A compact, canonical host encoding used by non-CashVM diagnostics. */
export function encodeStatement(s: PoolStatement): Uint8Array {
  return concatBytes(
    new TextEncoder().encode("PAA2STMT"),
    Uint8Array.of(s.action === "DEPOSIT" ? 1 : 2),
    width32(s.poolCategory, "poolCategory"),
    writeI64LE(s.publicAmountSats),
    encodeState(s.oldState),
    encodeState(s.newState),
    width32(s.createdEdge, "createdEdge"),
    width32(s.nullifier, "nullifier"),
    width32(s.payoutLockingDigest, "payoutLockingDigest"),
  );
}

export function statementDigest(
  s: PoolStatement,
  hash: InternalHash = defaultInternalHash(),
): Uint8Array {
  return hash.digest(encodeStatement(s));
}

export function statementHex(s: PoolStatement): string {
  return bytesToHex(encodeStatement(s));
}

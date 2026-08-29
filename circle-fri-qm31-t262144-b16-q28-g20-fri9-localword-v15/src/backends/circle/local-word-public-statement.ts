import type { PoolStatement } from "../../pool/statement.ts";
import { encodeState } from "../../pool/state.ts";
import { concatBytes, writeU32BE, writeU64LE } from "../../pool/bytes.ts";

export const LOCAL_WORD_STATEMENT_MAGIC = new TextEncoder().encode("SKLWSTMT");
export const LOCAL_WORD_INITIAL_DOMAIN = new TextEncoder().encode("ShieldKit/LocalWordStatement/v1");
export const LOCAL_WORD_PUBLIC_STATEMENT_VERSION = 1;
export const LOCAL_WORD_CONSTRUCTION_ID_BYTES = 32;
export const LOCAL_WORD_PUBLIC_STATEMENT_BYTES = 8 + 1 + 1 + 8 + 8 + 128 + 128 + 32 + 32;

export type LocalWordProfile = "deposit" | "withdraw-full" | "withdraw-change";

function equal(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((byte, index) => byte === right[index]);
}

/** Exact fixed-width CashVM Script Number encoding (`<8> OP_NUM2BIN`). */
export function encodeLocalWordScriptI64(value: bigint): Uint8Array {
  if (value < -(1n << 63n) + 1n || value > (1n << 63n) - 1n) {
    throw new Error("local-word signed amount range");
  }
  const negative = value < 0n;
  let magnitude = negative ? -value : value;
  const out = new Uint8Array(8);
  for (let index = 0; index < 8; index += 1) {
    out[index] = Number(magnitude & 0xffn);
    magnitude >>= 8n;
  }
  if (negative) out[7] |= 0x80;
  return out;
}

/** The proof profile is public state geometry, never an amount-tag side channel. */
export function localWordProfile(statement: PoolStatement): LocalWordProfile {
  return statement.action === "DEPOSIT"
    ? "deposit"
    : equal(statement.oldState.noteRoot, statement.newState.noteRoot)
      ? "withdraw-full"
      : "withdraw-change";
}

/**
 * Public relation and settlement bytes for the sealed successor.
 *
 * Deliberately absent: noteCommitment, amountCommitIn/Out, netBlind, rho,
 * owner, membership index/path, and change allocation. Old/new state roots are
 * public by the constitutional boundary; individual note identities are not.
 */
export function encodeLocalWordPublicStatement(
  statement: PoolStatement,
  minerFeeSats = 0n,
): Uint8Array {
  if (statement.profile !== "any-amount-v0" || statement.nullifier.length !== 32 ||
    statement.payoutLockingDigest.length !== 32 || minerFeeSats < 0n || minerFeeSats > 0x7fff_ffff_ffff_ffffn) {
    throw new Error("local-word public statement");
  }
  const profile = { deposit: 0, "withdraw-full": 1, "withdraw-change": 2 }[localWordProfile(statement)];
  return concatBytes(
    LOCAL_WORD_STATEMENT_MAGIC,
    Uint8Array.of(LOCAL_WORD_PUBLIC_STATEMENT_VERSION, profile),
    encodeLocalWordScriptI64(statement.publicAmountSats),
    writeU64LE(minerFeeSats),
    encodeState(statement.oldState),
    encodeState(statement.newState),
    statement.nullifier,
    statement.payoutLockingDigest,
  );
}

/** Exact public Fiat-Shamir initial message for the local-word family. */
export function localWordTranscriptInitial(
  statement: PoolStatement,
  constructionId: Uint8Array,
  minerFeeSats = 0n,
): Uint8Array {
  if (constructionId.length !== LOCAL_WORD_CONSTRUCTION_ID_BYTES) {
    throw new Error("local-word construction id width");
  }
  const encoded = encodeLocalWordPublicStatement(statement, minerFeeSats);
  if (encoded.length !== LOCAL_WORD_PUBLIC_STATEMENT_BYTES) throw new Error("local-word statement width");
  return concatBytes(LOCAL_WORD_INITIAL_DOMAIN, constructionId, writeU32BE(encoded.length), encoded);
}

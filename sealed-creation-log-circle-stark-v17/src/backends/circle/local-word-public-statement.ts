import type { PoolStatement } from "../../pool/statement.ts";
import { encodeState } from "../../pool/state.ts";
import { concatBytes, isZero32, sha256, writeU32BE, writeU64LE } from "../../pool/bytes.ts";

export const LOCAL_WORD_STATEMENT_MAGIC = new TextEncoder().encode("SKLWSTMT");
export const LOCAL_WORD_INITIAL_DOMAIN = new TextEncoder().encode("ShieldKit/LocalWordStatement/v2");
export const LOCAL_WORD_PUBLIC_STATEMENT_VERSION = 2;
export const LOCAL_WORD_CONSTRUCTION_ID_BYTES = 32;
export const LOCAL_WORD_PUBLIC_STATEMENT_BYTES =
  8 + 1 + 1 + 8 + 8 + 32 + 128 + 128 + 32 + 32 + 32;
export const LOCAL_WORD_RELATION_STATEMENT_MAGIC = new TextEncoder().encode("SKLWREL2");
export const LOCAL_WORD_RELATION_STATEMENT_VERSION = 2;
export const LOCAL_WORD_RELATION_STATEMENT_BYTES =
  8 + 1 + 1 + 2 + 8 + 8 + 32 + 128 + 128 + 32 + 32 + 32;
export const LOCAL_WORD_RELATION_STATEMENT_DIGEST_WORDS = 8;

export type LocalWordProfile = "deposit" | "withdraw-full" | "withdraw-change";

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

/** The proof profile is public transition geometry, never a private amount tag. */
export function localWordProfile(statement: PoolStatement): LocalWordProfile {
  if (statement.action === "DEPOSIT") return "deposit";
  return statement.newState.creationCount === statement.oldState.creationCount
    ? "withdraw-full"
    : "withdraw-change";
}

/**
 * Canonical public relation and settlement bytes for v16.
 *
 * Deliberately absent: note commitment/preimage, amount commitments, rho,
 * owner secret, creation head preimage, historical-edge index/path, and change
 * allocation. The one pseudorandom creation edge is public only on a creation.
 */
export function encodeLocalWordPublicStatement(
  statement: PoolStatement,
  minerFeeSats = 0n,
): Uint8Array {
  if (statement.profile !== "sealed-creation-log-v1" || statement.poolCategory.length !== 32 ||
    statement.createdEdge.length !== 32 || statement.nullifier.length !== 32 ||
    statement.payoutLockingDigest.length !== 32 || minerFeeSats < 0n ||
    minerFeeSats > 0x7fff_ffff_ffff_ffffn) {
    throw new Error("local-word public statement");
  }
  const resolved = localWordProfile(statement);
  const profile = { deposit: 0, "withdraw-full": 1, "withdraw-change": 2 }[resolved];
  if ((resolved === "withdraw-full") !== isZero32(statement.createdEdge)) {
    throw new Error("local-word created edge/profile mismatch");
  }
  return concatBytes(
    LOCAL_WORD_STATEMENT_MAGIC,
    Uint8Array.of(LOCAL_WORD_PUBLIC_STATEMENT_VERSION, profile),
    encodeLocalWordScriptI64(statement.publicAmountSats),
    writeU64LE(minerFeeSats),
    statement.poolCategory,
    encodeState(statement.oldState),
    encodeState(statement.newState),
    statement.createdEdge,
    statement.nullifier,
    statement.payoutLockingDigest,
  );
}

/**
 * Word-aligned canonical view hashed inside the relation and independently by
 * CashVM. The two zero bytes remove unaligned field extraction; the amount is
 * the positive reserve movement for every profile.
 */
export function encodeLocalWordRelationStatement(
  statement: PoolStatement,
  minerFeeSats = 0n,
): Uint8Array {
  // Reuse every validation and profile rule of the Fiat-Shamir statement.
  encodeLocalWordPublicStatement(statement, minerFeeSats);
  const resolved = localWordProfile(statement);
  const profile = { deposit: 0, "withdraw-full": 1, "withdraw-change": 2 }[resolved];
  const reserveMovement = statement.publicAmountSats < 0n
    ? -statement.publicAmountSats
    : statement.publicAmountSats;
  const encoded = concatBytes(
    LOCAL_WORD_RELATION_STATEMENT_MAGIC,
    Uint8Array.of(LOCAL_WORD_RELATION_STATEMENT_VERSION, profile, 0, 0),
    encodeLocalWordScriptI64(reserveMovement),
    writeU64LE(minerFeeSats),
    statement.poolCategory,
    encodeState(statement.oldState),
    encodeState(statement.newState),
    statement.createdEdge,
    statement.nullifier,
    statement.payoutLockingDigest,
  );
  if (encoded.length !== LOCAL_WORD_RELATION_STATEMENT_BYTES) {
    throw new Error("local-word relation statement width");
  }
  return encoded;
}

/** The sole algebraic public boundary: eight SHA-256 digest words. */
export function localWordRelationStatementDigest(
  statement: PoolStatement,
  minerFeeSats = 0n,
): Uint8Array {
  return sha256(encodeLocalWordRelationStatement(statement, minerFeeSats));
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

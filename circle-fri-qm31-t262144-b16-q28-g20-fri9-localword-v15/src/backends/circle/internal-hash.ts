/**
 * Circle-FRI internal hash knob.
 *
 * One primitive for Merkle parent/leaf, Fiat–Shamir grind/queries, note
 * commitment, nullifier, and tagged amount/net commits. Selecting an
 * implementation changes those sites together. A later id is one TABLE entry
 * plus digest(); Merkle / Fiat–Shamir / note / nullifier / tagged commits
 * already take InternalHash. Prove and verify accept only when both sides
 * use the same id.
 *
 * Production default is CashVM-native SHA-256 so the on-chain OP_SHA256 /
 * OP_HASH256 walk still matches. BLAKE2s is a real alternate (Starknet OS is
 * moving some hashes to Blake2s on Circle/M31). Poseidon2-M31 is a third
 * prover-side table entry (toorik Grain t=16 RF=8 RP=14). It is not the
 * default and not a lock opcode.
 */
import { createHash } from "node:crypto";
import { sha256 } from "../../pool/bytes.ts";
import { digestPoseidon2M31Bytes } from "./poseidon2-m31.ts";

export type InternalHashId = "sha256" | "blake2s" | "poseidon2-m31";

export type InternalHash = {
  readonly id: InternalHashId;
  digest(data: Uint8Array): Uint8Array;
};

export const SHA256_INTERNAL: InternalHash = {
  id: "sha256",
  digest(data: Uint8Array): Uint8Array {
    return sha256(data);
  },
};

export const BLAKE2S_INTERNAL: InternalHash = {
  id: "blake2s",
  digest(data: Uint8Array): Uint8Array {
    return new Uint8Array(createHash("blake2s256").update(data).digest());
  },
};

export const POSEIDON2_M31_INTERNAL: InternalHash = {
  id: "poseidon2-m31",
  digest(data: Uint8Array): Uint8Array {
    return digestPoseidon2M31Bytes(data);
  },
};

const TABLE: Record<InternalHashId, InternalHash> = {
  sha256: SHA256_INTERNAL,
  blake2s: BLAKE2S_INTERNAL,
  "poseidon2-m31": POSEIDON2_M31_INTERNAL,
};

export const DEFAULT_INTERNAL_HASH_ID: InternalHashId = "sha256";
export const INTERNAL_HASH_IDS: readonly InternalHashId[] = Object.keys(TABLE) as InternalHashId[];

export function isInternalHashId(value: string): value is InternalHashId {
  return Object.hasOwn(TABLE, value);
}

export function internalHash(id: InternalHashId = DEFAULT_INTERNAL_HASH_ID): InternalHash {
  const h = TABLE[id];
  if (!h) throw new Error(`unknown internal hash ${id}`);
  return h;
}

export function defaultInternalHash(): InternalHash {
  return SHA256_INTERNAL;
}

export function resolveInternalHash(sel?: InternalHashId | InternalHash): InternalHash {
  if (!sel) return SHA256_INTERNAL;
  if (typeof sel === "string") return internalHash(sel);
  return sel;
}

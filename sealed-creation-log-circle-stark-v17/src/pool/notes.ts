import { concatBytes } from "./bytes.ts";
import { commitAmount } from "../amounts/hash-commit.ts";
import {
  defaultInternalHash,
  type InternalHash,
} from "../backends/circle/internal-hash.ts";

/** Private note preimage. Creation history belongs in `CreatedNoteRecord`. */
export type Note = {
  amountSats: bigint;
  rho: Uint8Array;
  ownerSecret: Uint8Array;
};

/** Private note commitment used by every v16 profile. */
export function commitNote(note: Note, hash: InternalHash = defaultInternalHash()): Uint8Array {
  if (note.rho.length !== 32) throw new Error("rho must be 32 bytes");
  if (note.ownerSecret.length !== 32) throw new Error("ownerSecret must be 32 bytes");
  const amountCommitment = commitAmount(note.amountSats, note.rho, hash);
  return hash.digest(concatBytes(amountCommitment, note.rho, note.ownerSecret));
}

/** Fresh note randomness. */
export function freshRho(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}

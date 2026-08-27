/**
 * Plane B note delivery: ML-KEM-768 (FIPS 203). Post-quantum encapsulation
 * of note secrets. Not an address scheme (Schnorr payouts stay until Quantumroot).
 */
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { concatBytes, sha256 } from "../pool/bytes.ts";

export type MlKemKeypair = {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
};

export function generateNoteKem(): MlKemKeypair {
  const seed = crypto.getRandomValues(new Uint8Array(64));
  const keys = ml_kem768.keygen(seed);
  return { publicKey: keys.publicKey, secretKey: keys.secretKey };
}

export function encapsulateNote(
  recipientPublicKey: Uint8Array,
  notePlaintext: Uint8Array,
): { ciphertext: Uint8Array; wrapped: Uint8Array } {
  const { cipherText, sharedSecret } = ml_kem768.encapsulate(recipientPublicKey);
  const stream = sha256(concatBytes(sharedSecret, new TextEncoder().encode("paa1-note-v0")));
  const wrapped = new Uint8Array(notePlaintext.length);
  for (let i = 0; i < notePlaintext.length; i += 1) {
    wrapped[i] = notePlaintext[i]! ^ stream[i % stream.length]!;
  }
  return { ciphertext: cipherText, wrapped };
}

export function decapsulateNote(
  secretKey: Uint8Array,
  ciphertext: Uint8Array,
  wrapped: Uint8Array,
): Uint8Array {
  const shared = ml_kem768.decapsulate(ciphertext, secretKey);
  const stream = sha256(concatBytes(shared, new TextEncoder().encode("paa1-note-v0")));
  const out = new Uint8Array(wrapped.length);
  for (let i = 0; i < wrapped.length; i += 1) {
    out[i] = wrapped[i]! ^ stream[i % stream.length]!;
  }
  return out;
}

export function encodeNotePlaintext(amountSats: bigint, rho: Uint8Array, ownerSecret: Uint8Array): Uint8Array {
  const amt = new Uint8Array(8);
  let n = amountSats;
  for (let i = 7; i >= 0; i -= 1) {
    amt[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return concatBytes(amt, rho, ownerSecret);
}

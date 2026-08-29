import { LOCAL_WORD_V15_CONSTRUCTION_ID_HEX } from
  "../backends/circle/local-word-construction-v15.ts";
import type { LocalWordVerifierBankDigests } from "./local-word-proof-carriers.ts";

/**
 * Derived deployment constants for the three standing verifier banks.
 *
 * These are deliberately outside the construction manifest: each bank embeds
 * the construction ID, so hashing the resulting digest back into that ID would
 * be circular. `scripts/derive-local-word-verifier-bank-digests.ts` recompiles
 * all 501 role scripts and checks these constants from first principles.
 */
export const LOCAL_WORD_V15_VERIFIER_BANK_CONSTRUCTION_ID_HEX =
  "8d583c84312f7c79519b65bf374dc2ffb6597544a504d88a587c578f9bed2133";

export const LOCAL_WORD_V15_VERIFIER_BANK_DIGESTS_HEX = [
  "853180105a178a0136d67603377cc159dbc4a02ba0eb453b3bb78682a7a6d66c",
  "5dac6f1f0c86b4418c3482ee134cd2a6f04173f51a8bbc4362f198ab3dcc3f4e",
  "6b7eed42ab052682f80b4f59af42203dbe333809782514165fb5896005623a59",
] as const;

function decodeHex32(hex: string): Uint8Array {
  if (!/^[0-9a-f]{64}$/.test(hex)) throw new Error("local-word verifier bank digest encoding");
  return Uint8Array.from(Buffer.from(hex, "hex"));
}

if (LOCAL_WORD_V15_VERIFIER_BANK_CONSTRUCTION_ID_HEX !== LOCAL_WORD_V15_CONSTRUCTION_ID_HEX) {
  throw new Error("local-word verifier bank digests require rederivation");
}

export const LOCAL_WORD_V15_VERIFIER_BANK_DIGESTS: LocalWordVerifierBankDigests = [
  decodeHex32(LOCAL_WORD_V15_VERIFIER_BANK_DIGESTS_HEX[0]),
  decodeHex32(LOCAL_WORD_V15_VERIFIER_BANK_DIGESTS_HEX[1]),
  decodeHex32(LOCAL_WORD_V15_VERIFIER_BANK_DIGESTS_HEX[2]),
];

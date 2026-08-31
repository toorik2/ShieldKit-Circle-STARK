import { LOCAL_WORD_V16_CONSTRUCTION_ID_HEX } from
  "../backends/circle/local-word-construction-v16.ts";
import type { LocalWordVerifierBankDigests } from "./local-word-proof-carriers.ts";

/**
 * Derived deployment constants for the three standing v16 verifier banks.
 * They are outside the construction manifest because each bank embeds the
 * construction ID; hashing them back into that ID would be circular.
 */
export const LOCAL_WORD_V16_VERIFIER_BANK_CONSTRUCTION_ID_HEX =
  "f29ef06d0e2868a4e6207f060b6246fd49a51fabd0bd14e7d41b48324a1e70e5";

export const LOCAL_WORD_V16_VERIFIER_BANK_DIGESTS_HEX = [
  "94dbffc724204c1e2c40dfb4aeb5e4b836f081b8ab31c3511e5016d194b258e6",
  "f660d2cd6be164f711b34c9e127383721793a5711c1cbba1bc4e62fc2a6150b8",
  "99cb45afaaeac4c7b95ae74b24ab72a31bbeaf1419a299977b6c129a1329b876",
] as const;

function decodeHex32(hex: string): Uint8Array {
  if (!/^[0-9a-f]{64}$/.test(hex)) throw new Error("local-word v16 bank digest encoding");
  return Uint8Array.from(Buffer.from(hex, "hex"));
}

if (LOCAL_WORD_V16_VERIFIER_BANK_CONSTRUCTION_ID_HEX !== LOCAL_WORD_V16_CONSTRUCTION_ID_HEX) {
  throw new Error("local-word v16 verifier bank digests require rederivation");
}

export const LOCAL_WORD_V16_VERIFIER_BANK_DIGESTS: LocalWordVerifierBankDigests = [
  decodeHex32(LOCAL_WORD_V16_VERIFIER_BANK_DIGESTS_HEX[0]),
  decodeHex32(LOCAL_WORD_V16_VERIFIER_BANK_DIGESTS_HEX[1]),
  decodeHex32(LOCAL_WORD_V16_VERIFIER_BANK_DIGESTS_HEX[2]),
];

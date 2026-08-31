export type LocalWordV16VerifierKey = {
  readonly profile: 0 | 1 | 2;
  readonly publicWordCount: 8;
  readonly maximumProofBytes: number;
  readonly constructionDigest: Uint8Array;
  readonly preprocessedRoot: Uint8Array;
};

function bytes32(hex: string): Uint8Array {
  if (!/^[0-9a-f]{64}$/.test(hex)) throw new Error("local-word v16 verifier-key bytes");
  return Uint8Array.from({ length: 32 }, (_, index) =>
    Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16));
}

/** Deterministic keys derived by scripts/derive-local-word-verifier-keys.ts. */
export const LOCAL_WORD_V16_VERIFIER_KEYS: readonly LocalWordV16VerifierKey[] = [
  {
    profile: 0,
    publicWordCount: 8,
    maximumProofBytes: 351_010,
    constructionDigest: bytes32("fed4c84b07b9cd92e518cefcc137e7498110d3ed752716865b25ca8c175c458b"),
    preprocessedRoot: bytes32("63215fb371daf6fdcea310dbc46795c21c9c4038bdd45ca32e9470926f8c2527"),
  },
  {
    profile: 1,
    publicWordCount: 8,
    maximumProofBytes: 351_010,
    constructionDigest: bytes32("a4593456bb0a8dc3ad5df4594b0d0f0362095acd505d9856de658b12f02f7fdb"),
    preprocessedRoot: bytes32("37c1b9093c676aa79e3737fb9100e70ac8405ac77426345cd99a63556962af5a"),
  },
  {
    profile: 2,
    publicWordCount: 8,
    maximumProofBytes: 351_010,
    constructionDigest: bytes32("2efd8a291ed1ddc7189360cf3fb873a58e0fc0eac07b6861eadce9ba1f0aab05"),
    preprocessedRoot: bytes32("1b374fd887304082212b0edeb6073031e0846c153ae96729512953b2801a6bfe"),
  },
] as const;

export function localWordV16VerifierKey(profile: 0 | 1 | 2): LocalWordV16VerifierKey {
  const key = LOCAL_WORD_V16_VERIFIER_KEYS[profile];
  if (key?.profile !== profile) throw new Error("local-word v16 verifier-key profile");
  return key;
}

export type LocalWordV17VerifierKey = {
  readonly profile: 0 | 1 | 2;
  readonly publicWordCount: 8;
  readonly maximumProofBytes: 457_514;
  readonly constructionDigest: Uint8Array;
  readonly preprocessedRoot: Uint8Array;
};

function bytes32(hex: string): Uint8Array {
  if (!/^[0-9a-f]{64}$/.test(hex)) throw new Error("local-word v17 verifier-key bytes");
  return Uint8Array.from({ length: 32 }, (_, index) =>
    Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16));
}

/** Fresh deterministic output of scripts/derive-local-word-verifier-keys.ts. */
export const LOCAL_WORD_V17_VERIFIER_KEYS: readonly LocalWordV17VerifierKey[] = [
  {
    profile: 0,
    publicWordCount: 8,
    maximumProofBytes: 457_514,
    constructionDigest: bytes32("fed4c84b07b9cd92e518cefcc137e7498110d3ed752716865b25ca8c175c458b"),
    preprocessedRoot: bytes32("5a264f2b23e9c88b84bbb3d47141e4f8e92ff2a2e388c6f28101bb6f3d5445ad"),
  },
  {
    profile: 1,
    publicWordCount: 8,
    maximumProofBytes: 457_514,
    constructionDigest: bytes32("a4593456bb0a8dc3ad5df4594b0d0f0362095acd505d9856de658b12f02f7fdb"),
    preprocessedRoot: bytes32("85c1861717ec2d6bbe8997bf3f0e848216979f442ff2257ecdab8399d4a6dc66"),
  },
  {
    profile: 2,
    publicWordCount: 8,
    maximumProofBytes: 457_514,
    constructionDigest: bytes32("2efd8a291ed1ddc7189360cf3fb873a58e0fc0eac07b6861eadce9ba1f0aab05"),
    preprocessedRoot: bytes32("112a6d31f2fbc8792f01efabc82c44ca5fe3d6c0decedcae5fc17f90e8147304"),
  },
] as const;

export function localWordV17VerifierKey(profile: 0 | 1 | 2): LocalWordV17VerifierKey {
  const key = LOCAL_WORD_V17_VERIFIER_KEYS[profile];
  if (key?.profile !== profile) throw new Error("local-word v17 verifier-key profile");
  return key;
}

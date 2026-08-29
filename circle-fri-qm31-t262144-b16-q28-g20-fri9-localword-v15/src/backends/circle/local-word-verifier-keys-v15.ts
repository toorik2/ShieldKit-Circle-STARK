export type LocalWordV15VerifierKey = {
  readonly profile: 0 | 1 | 2;
  readonly publicWordCount: 18 | 26 | 34;
  readonly maximumProofBytes: number;
  readonly constructionDigest: Uint8Array;
  readonly preprocessedRoot: Uint8Array;
};

function bytes32(hex: string): Uint8Array {
  if (!/^[0-9a-f]{64}$/.test(hex)) throw new Error("local-word v15 verifier-key bytes");
  return Uint8Array.from({ length: 32 }, (_, index) =>
    Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16));
}

/** Deterministic keys derived by scripts/derive-local-word-verifier-keys.ts. */
export const LOCAL_WORD_V15_VERIFIER_KEYS: readonly LocalWordV15VerifierKey[] = [
  {
    profile: 0,
    publicWordCount: 18,
    maximumProofBytes: 340_234,
    constructionDigest: bytes32("bb1d9537c5f2058269a8e122209a71c74fdbcca017ccdd99648dce9cbea30a61"),
    preprocessedRoot: bytes32("dd3a484fd4c59461ce92fafcd329752cc14765e49f942fd5fc3ea6c3c573f441"),
  },
  {
    profile: 1,
    publicWordCount: 26,
    maximumProofBytes: 340_362,
    constructionDigest: bytes32("5c92c541b21aab3db8ec1fb2a6ac0d030a2614950502c0f097f0725420191d90"),
    preprocessedRoot: bytes32("ea7545635617d8b7b69eab0a7421d2dd0cc2c22c9acc6a5f49a7b367c235069f"),
  },
  {
    profile: 2,
    publicWordCount: 34,
    maximumProofBytes: 340_490,
    constructionDigest: bytes32("8bc34a26a77f72421c77ce2352363ac2f8e1b02aec4389a4ca7635e078ad26b5"),
    preprocessedRoot: bytes32("20223ded84b9482bb6cd5ca4ad25b2d036f8c40823d149eb38c6fbe0d73736d2"),
  },
] as const;

export function localWordV15VerifierKey(profile: 0 | 1 | 2): LocalWordV15VerifierKey {
  const key = LOCAL_WORD_V15_VERIFIER_KEYS[profile];
  if (key?.profile !== profile) throw new Error("local-word v15 verifier-key profile");
  return key;
}

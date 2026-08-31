import { concatBytes, sha256, writeU64LE } from "../pool/bytes.ts";

/**
 * One BCH-native commitment language for the standing verifier bank.
 *
 * Input zero is deliberately excluded: it embeds the three resulting bank
 * digests. Every later infrastructure input is committed in consensus order,
 * including authenticated ROM pages. Values and sequence numbers use the same
 * fixed-width little-endian Script-number representation produced by
 * `<8> OP_NUM2BIN`, so the concatenation is unambiguous and cheap to reproduce
 * in CashVM.
 */
export const V17_BANK_DIGEST_DOMAIN = new TextEncoder().encode(
  "ShieldKit/V17BankDigest/bch-native-fold-v1",
);
export const V17_BANK_DIGEST_SEEDS = [
  sha256(concatBytes(V17_BANK_DIGEST_DOMAIN, Uint8Array.of(0))),
  sha256(concatBytes(V17_BANK_DIGEST_DOMAIN, Uint8Array.of(1))),
  sha256(concatBytes(V17_BANK_DIGEST_DOMAIN, Uint8Array.of(2))),
] as const;
export const V17_BANK_NUMBER_BYTES = 8 as const;
export const V17_BANK_LOCKING_BYTES = 35 as const;

export type V17BankIdentityRole = {
  readonly index: number;
  readonly lockingBytecode: Uint8Array;
  readonly valueSatoshis: bigint;
  readonly sequenceNumber: number;
};

export function v17BankDigestBytes(
  profile: 0 | 1 | 2,
  roles: readonly V17BankIdentityRole[],
): Uint8Array {
  if ((profile !== 0 && profile !== 1 && profile !== 2) || roles.length < 1) {
    throw new Error("v17 bank digest shape");
  }
  return roles.reduce((digest, role, local) => {
    if (role.index !== local + 1 ||
      role.lockingBytecode.length !== V17_BANK_LOCKING_BYTES ||
      role.valueSatoshis < 0n || role.valueSatoshis > 0x7fff_ffff_ffff_ffffn ||
      !Number.isSafeInteger(role.sequenceNumber) || role.sequenceNumber < 0 ||
      role.sequenceNumber > 0xffff_ffff) {
      throw new Error(`v17 bank role ${local}`);
    }
    return sha256(concatBytes(
      digest,
      role.lockingBytecode,
      writeU64LE(role.valueSatoshis),
      writeU64LE(BigInt(role.sequenceNumber)),
    ));
  }, V17_BANK_DIGEST_SEEDS[profile]);
}

export function v17BankDigestHexFromRoles(
  profile: 0 | 1 | 2,
  roles: readonly V17BankIdentityRole[],
): string {
  return Buffer.from(v17BankDigestBytes(profile, roles)).toString("hex");
}

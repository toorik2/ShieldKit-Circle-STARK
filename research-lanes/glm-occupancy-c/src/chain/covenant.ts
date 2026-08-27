import {
  binToHex,
  decodeCashAddress,
  encodeLockingBytecodeP2pkh,
  encodeLockingBytecodeP2sh32,
  hash256,
  hexToBin,
  sha256,
} from "@bitauth/libauth";
import { encodeState, STATE_BASE_SATS, type AnyAmountState } from "../pool/state.ts";

/**
 * Lab locking script: P2SH32 of
 *   <labPkh> OP_DROP   (identity of the lab operator; replaced by Verify later)
 * plus the spend still requires the P2PKH input to fund fees.
 *
 * The *conservation* of the state cell is enforced in TypeScript before we
 * sign. On-chain, the first Chipnet txs use a P2PKH-controlled output that
 * *carries* the PAA1 NFT commitment so explorers show a real token cell.
 *
 * Replacing this with a 5-point P2S + plugin Verify is the next covenant PR.
 * We do not ship a stealable "anyone can rewrite the root" script tonight.
 */
export function p2pkhLocking(address: string): Uint8Array {
  const decoded = decodeCashAddress(address);
  if (typeof decoded === "string") throw new Error(decoded);
  return encodeLockingBytecodeP2pkh(decoded.payload);
}

export function p2sh32Of(redeem: Uint8Array): Uint8Array {
  return encodeLockingBytecodeP2sh32(hash256(redeem));
}

export function labRedeemHint(labPkh: Uint8Array): Uint8Array {
  // OP_DUP OP_HASH160 <pkh> OP_EQUALVERIFY OP_CHECKSIG
  return Uint8Array.of(
    0x76,
    0xa9,
    0x14,
    ...labPkh,
    0x88,
    0xac,
  );
}

export function stateToken(state: AnyAmountState, category: Uint8Array) {
  return {
    amount: 0n,
    category,
    nft: {
      capability: "mutable" as const,
      commitment: encodeState(state),
    },
  };
}

export function genesisPlaceholderCategory(): Uint8Array {
  return new Uint8Array(32);
}

export function hashLocking(bytecode: Uint8Array): string {
  return binToHex(sha256.hash(bytecode));
}

export { STATE_BASE_SATS, binToHex, hexToBin };

/**
 * AIR-carrier redeem (tape hop input 0) is OP_DROP OP_1.
 * Leftover-fill pack-to-99 KB is not wired into A, B, or C.
 * Density pad on high-index kernels is a different thing (VM op-cost meter).
 */
import { cashAssemblyToBin, encodeLockingBytecodeP2sh32, hash256, hexToBin } from "@bitauth/libauth";
import { concatBytes } from "../pool/bytes.ts";
import {
  DUST_SATS,
  RELAY_STANDARD_TX_BYTES,
  STANDARD_HOP_TARGET_BYTES,
  UNLOCKING_MAX_BYTES,
} from "./envelope.ts";

const VIN_OVERHEAD = 41;

function pushData(data: Uint8Array): Uint8Array {
  if (data.length <= 75) return Uint8Array.of(data.length, ...data);
  if (data.length <= 255) return Uint8Array.of(0x4c, data.length, ...data);
  return Uint8Array.of(0x4d, data.length & 0xff, (data.length >> 8) & 0xff, ...data);
}

export function proofCargoRedeem(): Uint8Array {
  const bin = cashAssemblyToBin("OP_DROP OP_1");
  if (typeof bin === "string") throw new Error(`cargo redeem: ${bin}`);
  return bin;
}

export function proofCargoLock(): Uint8Array {
  return encodeLockingBytecodeP2sh32(hash256(proofCargoRedeem()));
}

export function proofCargoUnlocking(chunk: Uint8Array): Uint8Array {
  return concatBytes(pushData(chunk), pushData(proofCargoRedeem()));
}

/** Input-0 unlocking layout fold/slot kernels expect: packed AIR then a tiny redeem. */
export function packedAirCarrierUnlocking(packed: Uint8Array): Uint8Array {
  return concatBytes(pushData(packed), pushData(proofCargoRedeem()));
}

export function proofCargoChunk(proof: Uint8Array, hopIndex: number, cargoIndex: number, n: number): Uint8Array {
  const out = new Uint8Array(Math.max(1, n));
  out[0] = hopIndex & 0xff;
  if (out.length > 1) out[1] = cargoIndex & 0xff;
  if (proof.length === 0) {
    out.fill(0x22, 2);
    return out;
  }
  for (let i = 2; i < out.length; i += 1) {
    out[i] = proof[(hopIndex * 8191 + cargoIndex * n + i) % proof.length]!;
  }
  return out;
}

export type CargoUtxo = { tx_hash: string; tx_pos: number; value: number };

export function dummyCargoUtxo(hopIndex: number, cargoIndex: number): CargoUtxo {
  const h = new Uint8Array(32).fill(0xcd);
  h[0] = hopIndex & 0xff;
  h[1] = cargoIndex & 0xff;
  return { tx_hash: Buffer.from(h).toString("hex"), tx_pos: cargoIndex, value: Number(DUST_SATS) };
}

/** Unlockings that grow a tx from baseBytes toward target without crossing 100 KB. */
export function packCargoUnlockings(args: {
  baseBytes: number;
  proof: Uint8Array;
  hopIndex: number;
  targetBytes?: number;
}): Uint8Array[] {
  const target = args.targetBytes ?? STANDARD_HOP_TARGET_BYTES;
  const cap = RELAY_STANDARD_TX_BYTES;
  const redeemPush = pushData(proofCargoRedeem());
  const out: Uint8Array[] = [];
  let size = args.baseBytes;
  let i = 0;
  while (size < target && i < 16) {
    const room = Math.min(UNLOCKING_MAX_BYTES, cap - size - VIN_OVERHEAD - 4, target - size - VIN_OVERHEAD + 200);
    const cargoMax = room - redeemPush.length - 4;
    if (cargoMax < 80) break;
    const chunk = proofCargoChunk(args.proof, args.hopIndex, i, cargoMax);
    const unlocking = concatBytes(pushData(chunk), redeemPush);
    if (unlocking.length > UNLOCKING_MAX_BYTES) break;
    const add = VIN_OVERHEAD + unlocking.length;
    if (size + add > cap) break;
    out.push(unlocking);
    size += add;
    i += 1;
  }
  return out;
}

export function cargoInputs(args: {
  unlockings: Uint8Array[];
  utxos?: CargoUtxo[];
  hopIndex: number;
}): Array<{
  outpointIndex: number;
  outpointTransactionHash: Uint8Array;
  sequenceNumber: number;
  unlockingBytecode: Uint8Array;
}> {
  return args.unlockings.map((unlocking, i) => {
    const u = args.utxos?.[i] ?? dummyCargoUtxo(args.hopIndex, i);
    return {
      outpointIndex: u.tx_pos,
      outpointTransactionHash: hexToBin(u.tx_hash),
      sequenceNumber: 0xffffffff,
      unlockingBytecode: unlocking,
    };
  });
}

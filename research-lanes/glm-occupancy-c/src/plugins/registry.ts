import { circleFriPlugin } from "../backends/circle/plugin.ts";
import { circleFriBatchPlugin } from "../backends/circle-batch/plugin.ts";
import { hashLabPlugin } from "../backends/hash-lab.ts";
import type { ZkpPlugin } from "../pool/plugin.ts";

/** Separate from ZKP. See DESIGN.md. */
export type SidePlugin = {
  family: string;
  layer: "amount-hiding" | "delivery" | "key-path" | "bus";
  requiredForPool: false;
  status: "slot" | "lab";
};

/** Production amount-hiding: tagged SHA-256. Not a discrete-log Pedersen. */
export const hashAmountPlugin: SidePlugin = {
  family: "sha256-tagged-amount",
  layer: "amount-hiding",
  requiredForPool: false,
  status: "lab",
};

/** Comparison-only EC profile. Not the production note commit. */
export const pedersenAmountPlugin: SidePlugin = {
  family: "pedersen-secp-profile",
  layer: "amount-hiding",
  requiredForPool: false,
  status: "slot",
};

export const mlkemDeliveryPlugin: SidePlugin = {
  family: "ml-kem-768",
  layer: "delivery",
  requiredForPool: false,
  status: "slot",
};

export const quantumrootKeyPath: SidePlugin = {
  family: "quantumroot-lmots",
  layer: "key-path",
  requiredForPool: false,
  status: "slot",
};

export const nostrBusPlugin: SidePlugin = {
  family: "nostr-nip44-59-17",
  layer: "bus",
  requiredForPool: false,
  status: "lab",
};

export const zkpPlugins: ZkpPlugin[] = [circleFriPlugin, circleFriBatchPlugin, hashLabPlugin];

/** Production default. Circle FRI is the first backend, not the pool identity. */
export const DEFAULT_ZKP_FAMILY = circleFriPlugin.family;

/**
 * Reserved Verify() names. These are **not** the same kind of object.
 *
 * Stack: arithmetization (AIR / R1CS / …) × PCS/IOPP (FRI / Circle FRI / WHIR / …).
 * WHIR (ePrint 2024/1586) is a Reed–Solomon IOP of proximity — a FRI/STIR
 * replacement. It can back an AIR STARK (Whirlaway) **or** Spartan.
 * Spartan (ePrint 2019/550) is a sumcheck SNARK for R1CS; it needs a PCS.
 * Groth16 is a pairing SNARK (wrong CashVM default).
 *
 * A later plugin is one registry row + prove/verify; notes/nullifiers stay.
 */
export type ReservedZkpRole = "plugin" | "pcs" | "iop" | "pairing-snark";

export type ReservedZkpFamily = {
  family: string;
  status: "slot";
  role: ReservedZkpRole;
  arithmetization: "air" | "r1cs" | "none";
  pcs: "fri" | "circle-fri" | "whir" | "any" | "none";
};

export const RESERVED_ZKP_FAMILIES: readonly ReservedZkpFamily[] = [
  { family: "goldilocks-fri", status: "slot", role: "plugin", arithmetization: "air", pcs: "fri" },
  { family: "air-whir", status: "slot", role: "plugin", arithmetization: "air", pcs: "whir" },
  { family: "spartan-whir", status: "slot", role: "plugin", arithmetization: "r1cs", pcs: "whir" },
  { family: "whir", status: "slot", role: "pcs", arithmetization: "none", pcs: "whir" },
  { family: "spartan", status: "slot", role: "iop", arithmetization: "r1cs", pcs: "any" },
  { family: "groth16", status: "slot", role: "pairing-snark", arithmetization: "r1cs", pcs: "none" },
];

export function defaultZkpPlugin(): ZkpPlugin {
  return circleFriPlugin;
}

export function zkpPluginByFamily(family: string): ZkpPlugin {
  const p = zkpPlugins.find((x) => x.family === family);
  if (p) return p;
  const reserved = RESERVED_ZKP_FAMILIES.find((x) => x.family === family);
  if (reserved) {
    throw new Error(
      `zkp family ${family} is a reserved slot (not shipped). first plugin is ${DEFAULT_ZKP_FAMILY}`,
    );
  }
  throw new Error(`unknown zkp family ${family}`);
}

export function describePlugins(): unknown {
  return {
    covenant: "P2S (2026) / P2SH32 (P1 shells) — not P2PKH",
    userLock: "P2PKH today; Quantumroot later",
    defaultZkp: DEFAULT_ZKP_FAMILY,
    zkp: zkpPlugins.map((p) => ({ family: p.family, sound: p.sound, vkId: p.vkId })),
    zkpReserved: RESERVED_ZKP_FAMILIES.map((p) => ({
      family: p.family,
      status: p.status,
      role: p.role,
      arithmetization: p.arithmetization,
      pcs: p.pcs,
    })),
    side: [hashAmountPlugin, pedersenAmountPlugin, mlkemDeliveryPlugin, quantumrootKeyPath, nostrBusPlugin],
  };
}

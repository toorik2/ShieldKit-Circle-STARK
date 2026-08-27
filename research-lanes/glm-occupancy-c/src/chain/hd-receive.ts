/**
 * BIP32 receive chain for user payouts. XO-style P2PKH: one child, one address.
 * Never reuse a CashAddr. Seed stays in .local (gitignored). Not a mnemonic argv.
 */
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import {
  decodeCashAddress,
  deriveHdPath,
  deriveHdPrivateNodeFromSeed,
  encodeLockingBytecodeP2pkh,
} from "@bitauth/libauth";
import { p2pkhLockingOf, walletFromPrivateKey, type LabWallet } from "./wallet.ts";

export const HD_RECEIVE_PATH_PREFIX = "m/44'/145'/0'/0";

export type LabHd = {
  seed: Uint8Array;
  receiveIndex: number;
  usedAddresses: string[];
};

type StoredHd = {
  seedHex: string;
  receiveIndex: number;
  usedAddresses: string[];
};

const defaultHdPath = () => join(process.cwd(), ".local", "lab-hd.json");

export function createLabHd(seed?: Uint8Array): LabHd {
  const s = seed ?? crypto.getRandomValues(new Uint8Array(64));
  if (s.length !== 64) throw new Error("HD seed must be 64 bytes");
  return { seed: s, receiveIndex: 0, usedAddresses: [] };
}

function masterOf(hd: LabHd) {
  const node = deriveHdPrivateNodeFromSeed(hd.seed);
  if (typeof node === "string") throw new Error(node);
  return node;
}

export function deriveReceiveWallet(hd: LabHd, index: number): LabWallet {
  const master = masterOf(hd);
  const path = `${HD_RECEIVE_PATH_PREFIX}/${index}` as const;
  const child = deriveHdPath(master, path);
  if (typeof child === "string") throw new Error(child);
  if (!("privateKey" in child)) throw new Error("HD child missing private key");
  return walletFromPrivateKey(child.privateKey);
}

export function assertFreshPayoutAddress(address: string, used: readonly string[]): void {
  if (used.includes(address)) throw new Error(`payout address reuse forbidden (HD/P2PKH): ${address}`);
}

export function nextReceive(hd: LabHd): { wallet: LabWallet; hd: LabHd; locking: Uint8Array } {
  const wallet = deriveReceiveWallet(hd, hd.receiveIndex);
  assertFreshPayoutAddress(wallet.address, hd.usedAddresses);
  const next: LabHd = {
    seed: hd.seed,
    receiveIndex: hd.receiveIndex + 1,
    usedAddresses: [...hd.usedAddresses, wallet.address],
  };
  return { wallet, hd: next, locking: p2pkhLockingOf(wallet) };
}

export function markUsedAddress(hd: LabHd, address: string): LabHd {
  assertFreshPayoutAddress(address, hd.usedAddresses);
  return { ...hd, usedAddresses: [...hd.usedAddresses, address] };
}

export function p2pkhLockingFromAddress(address: string): Uint8Array {
  const decoded = decodeCashAddress(address);
  if (typeof decoded === "string") throw new Error(decoded);
  return encodeLockingBytecodeP2pkh(decoded.payload);
}

export async function saveLabHd(hd: LabHd, path = defaultHdPath()): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  const body: StoredHd = {
    seedHex: Buffer.from(hd.seed).toString("hex"),
    receiveIndex: hd.receiveIndex,
    usedAddresses: hd.usedAddresses,
  };
  await writeFile(path, JSON.stringify(body, null, 2));
}

export async function loadLabHd(path = defaultHdPath()): Promise<LabHd> {
  const raw = JSON.parse(await readFile(path, "utf8")) as StoredHd;
  const seed = Uint8Array.from(Buffer.from(raw.seedHex, "hex"));
  if (seed.length !== 64) throw new Error("HD seed width");
  return {
    seed,
    receiveIndex: raw.receiveIndex,
    usedAddresses: raw.usedAddresses ?? [],
  };
}

export async function loadOrCreateLabHd(path = defaultHdPath()): Promise<LabHd> {
  try {
    return await loadLabHd(path);
  } catch {
    const hd = createLabHd();
    await saveLabHd(hd, path);
    return hd;
  }
}

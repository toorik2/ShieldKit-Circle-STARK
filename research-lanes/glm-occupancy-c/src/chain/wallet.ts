import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import {
  decodeCashAddress,
  decodePrivateKeyWif,
  encodeLockingBytecodeP2pkh,
  encodePrivateKeyWif,
  generatePrivateKey,
  hexToBin,
  privateKeyToP2pkhCashAddress,
  secp256k1,
} from "@bitauth/libauth";

export type LabWallet = {
  wif: string;
  privateKeyHex: string;
  publicKeyHex: string;
  address: string;
  tokenAddress: string;
};

const defaultPath = () =>
  join(process.cwd(), ".local", "lab-wallet.json");

export function walletFromPrivateKey(privateKey: Uint8Array): LabWallet {
  const publicKey = secp256k1.derivePublicKeyCompressed(privateKey);
  if (typeof publicKey === "string") throw new Error(publicKey);
  const address = privateKeyToP2pkhCashAddress({
    privateKey,
    prefix: "bchtest",
    tokenSupport: false,
  }).address;
  const tokenAddress = privateKeyToP2pkhCashAddress({
    privateKey,
    prefix: "bchtest",
    tokenSupport: true,
  }).address;
  const wif = encodePrivateKeyWif(privateKey, "testnet");
  return {
    wif,
    privateKeyHex: Buffer.from(privateKey).toString("hex"),
    publicKeyHex: Buffer.from(publicKey).toString("hex"),
    address,
    tokenAddress,
  };
}

export function createLabWallet(): LabWallet {
  const pk = generatePrivateKey(() => crypto.getRandomValues(new Uint8Array(32)));
  return walletFromPrivateKey(pk);
}

export async function saveLabWallet(wallet: LabWallet, path = defaultPath()): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, JSON.stringify({ address: wallet.address, wif: wallet.wif }, null, 2));
}

export async function loadLabWallet(path = defaultPath()): Promise<LabWallet> {
  const raw = JSON.parse(await readFile(path, "utf8")) as { wif: string };
  const decoded = decodePrivateKeyWif(raw.wif);
  if (typeof decoded === "string") throw new Error(decoded);
  return walletFromPrivateKey(decoded.privateKey);
}

export function privateKeyOf(wallet: LabWallet): Uint8Array {
  return hexToBin(wallet.privateKeyHex);
}

export function p2pkhLockingOf(wallet: LabWallet): Uint8Array {
  const decoded = decodeCashAddress(wallet.address);
  if (typeof decoded === "string") throw new Error(decoded);
  return encodeLockingBytecodeP2pkh(decoded.payload);
}

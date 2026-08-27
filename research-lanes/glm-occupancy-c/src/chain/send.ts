import {
  binToHex,
  decodeCashAddress,
  encodeLockingBytecodeP2pkh,
  encodeTransaction,
  generateTransaction,
  hexToBin,
  walletTemplateP2pkhNonHd,
  walletTemplateToCompilerBCH,
} from "@bitauth/libauth";
import { broadcast, connectChipnet, listUnspent, type ElectrumUtxo } from "./electrum.ts";
import { privateKeyOf, type LabWallet } from "./wallet.ts";

function compiler() {
  return walletTemplateToCompilerBCH(walletTemplateP2pkhNonHd);
}

function p2pkhFromAddress(address: string): Uint8Array {
  const decoded = decodeCashAddress(address);
  if (typeof decoded === "string") throw new Error(decoded);
  return encodeLockingBytecodeP2pkh(decoded.payload);
}

export async function sendMany(
  from: LabWallet,
  pays: Array<{ address: string; sats: bigint }>,
): Promise<string> {
  const client = await connectChipnet();
  try {
    const utxos = await listUnspent(client, from.address);
    const totalOut = pays.reduce((n, p) => n + p.sats, 0n);
    const fee = 500n + BigInt(pays.length) * 50n;
    const selected: ElectrumUtxo[] = [];
    let sum = 0n;
    for (const u of utxos) {
      selected.push(u);
      sum += BigInt(u.value);
      if (sum >= totalOut + fee + 546n) break;
    }
    if (sum < totalOut + fee + 546n) {
      throw new Error(`need ${totalOut + fee} sats, have ${sum}`);
    }
    const change = sum - totalOut - fee;
    const c = compiler();
    const data = { keys: { privateKeys: { key: privateKeyOf(from) } } };
    const generated = generateTransaction({
      version: 2,
      locktime: 0,
      inputs: selected.map((u) => ({
        outpointIndex: u.tx_pos,
        outpointTransactionHash: hexToBin(u.tx_hash),
        sequenceNumber: 0xffffffff,
        unlockingBytecode: {
          compiler: c,
          script: "unlock",
          data,
          valueSatoshis: BigInt(u.value),
        },
      })),
      outputs: [
        ...pays.map((p) => ({
          lockingBytecode: p2pkhFromAddress(p.address),
          valueSatoshis: p.sats,
        })),
        {
          lockingBytecode: { compiler: c, script: "lock", data },
          valueSatoshis: change,
        },
      ],
    });
    if (!generated.success) {
      throw new Error(`sendMany: ${JSON.stringify(generated.errors).slice(0, 400)}`);
    }
    return await broadcast(client, binToHex(encodeTransaction(generated.transaction)));
  } finally {
    client.close();
  }
}

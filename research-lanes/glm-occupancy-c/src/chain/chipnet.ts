import { connectChipnet, listUnspent } from "./electrum.ts";

export async function requestFaucet(address: string): Promise<string> {
  const urls = [
    `https://tbch.googol.cash/?address=${encodeURIComponent(address)}`,
    `https://rest-chipnet.fullstack.cash/v5/faucet/bch/${address}`,
  ];
  const notes: string[] = [];
  for (const url of urls) {
    try {
      const res = await fetch(url);
      const text = (await res.text()).slice(0, 200);
      notes.push(`${url} -> ${res.status} ${text.replace(/\s+/g, " ")}`);
    } catch (e) {
      notes.push(`${url} -> ${e instanceof Error ? e.message : e}`);
    }
  }
  return `Fund ${address} at https://tbch.googol.cash/ if empty.\n${notes.join("\n")}`;
}

export async function walletBalance(address: string) {
  const client = await connectChipnet();
  try {
    const utxos = await listUnspent(client, address);
    const sats = utxos.reduce((n, u) => n + BigInt(u.value), 0n);
    return { sats, utxos };
  } finally {
    client.close();
  }
}

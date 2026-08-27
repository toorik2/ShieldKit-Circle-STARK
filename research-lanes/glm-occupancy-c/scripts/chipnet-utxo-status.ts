/** Print hot-wallet UTXO counts/values. Never prints keys. */
import { readFile } from "node:fs/promises";
import { hexToBin } from "@bitauth/libauth";
import { saveLabWallet, walletFromPrivateKey } from "../src/chain/wallet.ts";
import { connectChipnet, listUnspent } from "../src/chain/electrum.ts";

const hex = (await readFile(`${process.env.HOME}/.grok/secrets/chipnet-wallet/hot.privhex`, "utf8")).trim();
const w = walletFromPrivateKey(hexToBin(hex));
await saveLabWallet(w);
const c = await connectChipnet();
const u = await listUnspent(c, w.address);
const vals = u.map((x) => x.value).sort((a, b) => b - a);
console.log(JSON.stringify({
  address: w.address,
  n: u.length,
  max: vals[0] ?? 0,
  sum: vals.reduce((s, x) => s + x, 0),
  top: vals.slice(0, 8),
}));
c.close();

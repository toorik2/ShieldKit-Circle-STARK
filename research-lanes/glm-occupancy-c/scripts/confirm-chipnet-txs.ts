/** Confirm Chipnet txids via Electrum. No keys. */
import { connectChipnet, getTx } from "../src/chain/electrum.ts";

const ids = process.argv.slice(2);
if (ids.length === 0) throw new Error("usage: confirm-chipnet-txs <txid>...");

const client = await connectChipnet();
try {
  for (const id of ids) {
    try {
      const hex = await getTx(client, id);
      process.stdout.write(`${id} ok bytes=${hex.length / 2}\n`);
    } catch (e) {
      process.stdout.write(`${id} FAIL ${e instanceof Error ? e.message : String(e)}\n`);
    }
  }
} finally {
  client.close();
}

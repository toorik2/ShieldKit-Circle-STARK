import { decodeTransaction, hexToBin, binToHex } from "@bitauth/libauth";
import { connectChipnet, getTx, listUnspent } from "../src/chain/electrum.ts";
import { loadLabWallet } from "../src/chain/wallet.ts";

const wallet = await loadLabWallet();
const client = await connectChipnet();
try {
  const utxos = await listUnspent(client, wallet.address);
  console.log(JSON.stringify({ address: wallet.address, utxos }, null, 2));
  const genesis = process.argv[2];
  if (genesis) {
    const hex = await getTx(client, genesis);
    const tx = decodeTransaction(hexToBin(hex));
    if (typeof tx === "string") throw new Error(tx);
    console.log(
      JSON.stringify(
        {
          inputs: tx.inputs.map((i) => ({
            txid: binToHex(i.outpointTransactionHash),
            vout: i.outpointIndex,
          })),
          outputs: tx.outputs.map((o, i) => ({
            i,
            sats: o.valueSatoshis.toString(),
            lock0: o.lockingBytecode[0],
            lockLen: o.lockingBytecode.length,
            token: o.token
              ? {
                  category: binToHex(o.token.category),
                  amount: o.token.amount.toString(),
                  cap: o.token.nft?.capability,
                  commitLen: o.token.nft?.commitment.length,
                  magic: o.token.nft ? Buffer.from(o.token.nft.commitment.slice(0, 4)).toString("ascii") : null,
                }
              : null,
          })),
        },
        null,
        2,
      ),
    );
  }
} finally {
  client.close();
}

import { decodeTransaction, hexToBin, binToHex } from "@bitauth/libauth";
import { connectChipnet, getTx, listUnspent, broadcast } from "../src/chain/electrum.ts";
import { compileCovenantSuccessor } from "../src/chain/covenant-spend.ts";
import { decodeState } from "../src/pool/state.ts";
import { loadLabWallet } from "../src/chain/wallet.ts";
import { circleFriPlugin } from "../src/backends/circle/plugin.ts";
import { runMixSuccessor, mixChangedRootsAndReserve } from "../src/pool/mix-successor.ts";

const genesisTxid = process.argv[2];
if (!genesisTxid) {
  console.error("usage: tsx scripts/chipnet-successor.ts <genesis-txid>");
  process.exit(1);
}

const wallet = await loadLabWallet();
const client = await connectChipnet();
try {
  const rawHex = await getTx(client, genesisTxid);
  const tx = decodeTransaction(hexToBin(rawHex));
  if (typeof tx === "string") throw new Error(tx);
  const poolOut = tx.outputs[0]!;
  const token = poolOut.token;
  if (!token?.nft) throw new Error("genesis output 0 has no NFT");
  const onChain = decodeState(token.nft.commitment);
  const mix = runMixSuccessor({ instance: onChain.poolInstanceId, depositCount: 6, withdrawSats: 1_000n });
  if (!mixChangedRootsAndReserve(mix)) {
    throw new Error("mix successor did not update noteRoot, nullifierRoot, and reserve");
  }
  const v = circleFriPlugin.verify(mix.statement, mix.proof);
  if (!v.ok) throw new Error(v.reason);
  const utxos = await listUnspent(client, wallet.address);
  const feeUtxo = utxos.find((u) => u.value >= 20_000);
  if (!feeUtxo) throw new Error("no fee utxo on lab p2pkh");
  const measured = compileCovenantSuccessor({
    wallet,
    feeUtxo,
    pool: {
      tx_hash: genesisTxid,
      tx_pos: 0,
      value: Number(poolOut.valueSatoshis),
      category: token.category,
      commitment: token.nft.commitment,
    },
    newState: mix.newState,
    proof: mix.proof,
    lockKind: "p2sh32",
  });
  const txid = await broadcast(client, binToHex(measured.raw));
  console.log(
    JSON.stringify(
      {
        txid,
        explorer: `https://chipnet.imaginary.cash/tx/${txid}`,
        unlockingBytes: measured.unlockingBytes,
        txBytes: measured.txBytes,
        publicBefore: mix.publicBefore,
        publicAfter: mix.publicAfter,
      },
      null,
      2,
    ),
  );
} finally {
  client.close();
}

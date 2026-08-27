/**
 * Broadcast current-lock genesis + kernel fund + mix successor.
 * Uses a known vout-0 prep if provided, else waits for listunspent vout 0.
 * No keys printed.
 */
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { binToHex, hexToBin } from "@bitauth/libauth";
import { loadLabWallet } from "../src/chain/wallet.ts";
import { broadcast, connectChipnet, getTx, listUnspent } from "../src/chain/electrum.ts";
import {
  compileCovenantSpend,
  compileCovenantSuccessor,
  compileFundVerifierKernels,
} from "../src/chain/covenant-spend.ts";
import { circleFriPlugin } from "../src/backends/circle/plugin.ts";
import { mixChangedRootsAndReserve, runMixSuccessor } from "../src/pool/mix-successor.ts";
import { encodePublicPaa1, utxoValueFor } from "../src/pool/state.ts";
import { proofShardReport } from "../src/chain/fri-openings.ts";

const scratch = process.argv[2];
const prepHint = process.argv[3];
if (!scratch) throw new Error("usage: chipnet-broadcast-now <scratch> [prepTxid]");

function sleep(ms: number) {
  return new Promise((r) => setTimeout(r, ms));
}

const wallet = await loadLabWallet();
const mix = runMixSuccessor({ depositCount: 6, withdrawSats: 1_000n });
if (!mixChangedRootsAndReserve(mix)) throw new Error("mix did not update roots/reserve");
const v = circleFriPlugin.verify(mix.statement, mix.proof);
if (!v.ok) throw new Error(`verify: ${v.reason}`);

const client = await connectChipnet();
try {
  if (prepHint) {
    for (let i = 0; i < 10; i += 1) {
      try {
        await getTx(client, prepHint);
        break;
      } catch {
        await sleep(1000);
      }
    }
  }
  let picked:
    | { tx_hash: string; tx_pos: number; value: number }
    | undefined;
  for (let i = 0; i < 15; i += 1) {
    const utxos = await listUnspent(client, wallet.address);
    picked =
      (prepHint
        ? utxos.find((u) => u.tx_hash === prepHint && u.tx_pos === 0)
        : undefined) ??
      utxos.find((u) => u.tx_pos === 0 && u.value > 100_000) ??
      utxos.reduce<(typeof utxos)[0] | undefined>((a, b) => (!a || b.value > a.value ? b : a), undefined);
    if (picked && picked.tx_pos === 0) break;
    await sleep(1500);
  }
  if (!picked || picked.tx_pos !== 0) {
    throw new Error(`no vout-0 utxo after wait; last=${JSON.stringify(picked)}`);
  }

  const genesis = compileCovenantSpend({
    wallet,
    utxo: picked,
    state: mix.oldState,
    proof: mix.proof,
    lockKind: "p2sh32",
  });
  const genesisTxid = await broadcast(client, binToHex(genesis.raw));
  await sleep(2000);
  try {
    await getTx(client, genesisTxid);
  } catch {
    await sleep(2000);
  }

  if (genesis.changeValue === undefined || genesis.changeValue < 150_000) {
    throw new Error(`genesis change too small: ${genesis.changeValue}`);
  }
  const funder = { tx_hash: genesisTxid, tx_pos: 1, value: genesis.changeValue };
  const funded = compileFundVerifierKernels(wallet, funder);
  const kernelTxid = await broadcast(client, binToHex(funded.raw));
  await sleep(2000);

  const feeUtxo = { tx_hash: funded.txid, tx_pos: funded.changePos, value: funded.changeValue };
  const successor = compileCovenantSuccessor({
    wallet,
    feeUtxo,
    pool: {
      tx_hash: genesisTxid,
      tx_pos: 0,
      value: utxoValueFor(mix.oldState),
      category: hexToBin(picked.tx_hash),
      commitment: encodePublicPaa1(mix.oldState),
    },
    newState: mix.newState,
    proof: mix.proof,
    statement: mix.statement,
    lockKind: "p2sh32",
    kernelUtxos: funded.fri,
    extraKernels: funded.extra,
  });
  const succTxid = await broadcast(client, binToHex(successor.raw));
  const shards = proofShardReport(mix.proof);
  const report = {
    address: wallet.address,
    prep: prepHint ?? null,
    genesis: genesisTxid,
    kernelTxid,
    successor: succTxid,
    explorer: {
      genesis: `https://chipnet.imaginary.cash/tx/${genesisTxid}`,
      kernels: `https://chipnet.imaginary.cash/tx/${kernelTxid}`,
      successor: `https://chipnet.imaginary.cash/tx/${succTxid}`,
    },
    txBytes: successor.txBytes,
    unlockingBytes: successor.unlockingBytes,
    proofBytes: mix.proof.length,
    shards,
    plugin: circleFriPlugin.family,
    sound: circleFriPlugin.sound,
    verify: v,
    publicBefore: mix.publicBefore,
    publicAfter: mix.publicAfter,
    changed: {
      noteRoot: mix.publicBefore.noteRoot !== mix.publicAfter.noteRoot,
      nullifierRoot: mix.publicBefore.nullifierRoot !== mix.publicAfter.nullifierRoot,
      reserve: mix.publicBefore.reserveSats !== mix.publicAfter.reserveSats,
    },
  };
  writeFileSync(join(scratch, "chipnet-broadcast.log"), `${JSON.stringify(report, null, 2)}\n`);
  console.log(JSON.stringify(report, null, 2));
} finally {
  client.close();
}

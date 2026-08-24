/**
 * Electrum land of the QM31 occupancy successor (one standard tx).
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import {
  binToHex,
  encodeTransaction,
  generateTransaction,
  hashTransaction,
  hexToBin,
  walletTemplateP2pkhNonHd,
  walletTemplateToCompilerBCH,
} from "@bitauth/libauth";
import { circleFriPlugin } from "../backends/circle/plugin.ts";
import { mixChangedRootsAndReserve, runMixSuccessor } from "../pool/mix-successor.ts";
import { encodePublicPaa1, utxoValueFor } from "../pool/state.ts";
import { SLOT_KERNEL_COUNT_CONSENSUS } from "./air-cqz.ts";
import { broadcast, connectChipnet, getTx, listUnspent } from "./electrum.ts";
import { DUST_SATS, successorFeeCoinSats } from "./envelope.ts";
import {
  compileCovenantSpend,
  compileCovenantSuccessor,
  compileFundVerifierKernels,
} from "./covenant-spend.ts";
import { loadLabWallet, p2pkhLockingOf, privateKeyOf, type LabWallet } from "./wallet.ts";

function sleep(ms: number) {
  return new Promise((r) => setTimeout(r, ms));
}

async function broadcastRetry(
  client: Awaited<ReturnType<typeof connectChipnet>>,
  raw: Uint8Array,
  expectedTxid: string,
): Promise<string> {
  const hex = binToHex(raw);
  let last: Error | undefined;
  for (let i = 0; i < 3; i += 1) {
    try {
      return await broadcast(client, hex);
    } catch (e) {
      last = e instanceof Error ? e : new Error(String(e));
      const msg = last.message.toLowerCase();
      if (!msg.includes("missing") && !msg.includes("orphan") && !msg.includes("bad-txns-inputs") && !msg.includes("timed out")) {
        break;
      }
      await sleep(1200 * (i + 1));
    }
  }
  try {
    await getTx(client, expectedTxid);
    return expectedTxid;
  } catch {
    throw last ?? new Error("electrum broadcast failed");
  }
}

async function waitForTxid(client: Awaited<ReturnType<typeof connectChipnet>>, txid: string): Promise<void> {
  for (let i = 0; i < 12; i += 1) {
    try {
      await getTx(client, txid);
      return;
    } catch {
      await sleep(1500);
    }
  }
}

function splitPrep(args: { wallet: LabWallet; utxo: { tx_hash: string; tx_pos: number; value: number }; tapeSats: bigint }) {
  const fee = 2_000n;
  const rest = BigInt(args.utxo.value) - args.tapeSats - fee;
  if (rest < DUST_SATS) throw new Error("change too small to fund kernels");
  const c = walletTemplateToCompilerBCH(walletTemplateP2pkhNonHd);
  const data = { keys: { privateKeys: { key: privateKeyOf(args.wallet) } } };
  const lock = p2pkhLockingOf(args.wallet);
  const generated = generateTransaction({
    version: 2,
    locktime: 0,
    inputs: [
      {
        outpointIndex: args.utxo.tx_pos,
        outpointTransactionHash: hexToBin(args.utxo.tx_hash),
        sequenceNumber: 0xffffffff,
        unlockingBytecode: { compiler: c, script: "unlock", data, valueSatoshis: BigInt(args.utxo.value) },
      },
    ],
    outputs: [
      { lockingBytecode: lock, valueSatoshis: args.tapeSats },
      { lockingBytecode: lock, valueSatoshis: rest },
    ],
  });
  if (!generated.success) throw new Error(`prep: ${JSON.stringify(generated.errors).slice(0, 400)}`);
  const raw = encodeTransaction(generated.transaction);
  return { raw, txid: hashTransaction(raw) };
}

export async function landQm31Successor(scratch = ".local"): Promise<Record<string, unknown>> {
  const mix = runMixSuccessor({ depositCount: 6, withdrawSats: 1_000n });
  if (!mixChangedRootsAndReserve(mix)) throw new Error("mix did not update roots");
  const v = circleFriPlugin.verify(mix.statement, mix.proof);
  if (!v.ok) throw new Error(`verify: ${v.reason}`);
  const slots = SLOT_KERNEL_COUNT_CONSENSUS;
  const wallet = await loadLabWallet();
  const client = await connectChipnet();
  let step = "connect";
  try {
    const need = 400_000;
    const utxos = await listUnspent(client, wallet.address);
    const ok = utxos.filter((u) => u.value >= need).sort((a, b) => a.value - b.value);
    let picked = ok[0];
    if (!picked) {
      return { ok: false, error: `no funded utxo >= ${need}`, address: wallet.address };
    }
    let prepTxid: string | undefined;
    if (picked.tx_pos !== 0 || picked.value > need + 50_000) {
      step = "split-off";
      const split = splitPrep({ wallet, utxo: picked, tapeSats: BigInt(need) });
      prepTxid = await broadcastRetry(client, split.raw, split.txid);
      await waitForTxid(client, split.txid);
      picked = { tx_hash: split.txid, tx_pos: 0, value: need, height: 0 };
    }
    step = "genesis";
    const genesis = compileCovenantSpend({
      wallet,
      utxo: picked,
      state: mix.oldState,
      proof: mix.proof,
      lockKind: "p2sh32",
      envelope: "consensus",
      slotKernels: slots,
    });
    const genesisTxid = await broadcastRetry(client, genesis.raw, genesis.txid);
    await waitForTxid(client, genesisTxid);
    if (genesis.changeValue === undefined || genesis.changeValue < 200_000) {
      return { ok: false, genesis: genesisTxid, prep: prepTxid ?? null, error: `change too small ${genesis.changeValue}` };
    }
    step = "kernels";
    const funded = compileFundVerifierKernels(
      wallet,
      { tx_hash: genesisTxid, tx_pos: 1, value: genesis.changeValue },
      1_000,
      slots,
      successorFeeCoinSats("consensus"),
    );
    const kernelTxid = await broadcastRetry(client, funded.raw, funded.txid);
    await waitForTxid(client, kernelTxid);
    step = "successor";
    const successor = compileCovenantSuccessor({
      wallet,
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
      envelope: "consensus",
      slotKernels: slots,
      kernelUtxos: funded.fri,
      extraKernels: funded.extra,
      note: mix.spent.note,
      change: mix.witness.created?.note,
    });
    mkdirSync(scratch, { recursive: true });
    writeFileSync(join(scratch, "successor-consensus.hex"), binToHex(successor.raw));
    const sent = await broadcastRetry(client, successor.raw, successor.txid);
    return {
      ok: true,
      path: "electrum",
      prep: prepTxid ?? null,
      genesis: genesisTxid,
      kernels: kernelTxid,
      successor: sent,
      txBytes: successor.txBytes,
      unlockingBytes: successor.unlockingBytes,
      explorer: `https://chipnet.imaginary.cash/tx/${sent}`,
      verify: v,
    };
  } catch (e) {
    throw new Error(`${step}: ${e instanceof Error ? e.message : String(e)}`);
  } finally {
    client.close();
  }
}

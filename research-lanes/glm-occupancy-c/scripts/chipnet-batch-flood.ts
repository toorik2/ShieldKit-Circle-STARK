/**
 * Chipnet batch-exit flood: N notes in, one successor, N P2PKH payouts.
 * Each output = that note. Sum = pool UTXO drop. Not a chain-analysis theorem.
 */
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import {
  binToHex,
  decodeCashAddress,
  encodeLockingBytecodeP2pkh,
  hexToBin,
} from "@bitauth/libauth";
import { applyBatchExit, applyDeposit, type PoolMachine } from "../src/pool/transition.ts";
import { IncrementalMerkle, NullifierSet, type Note } from "../src/pool/notes.ts";
import { emptyState, encodePublicPaa1, utxoValueFor } from "../src/pool/state.ts";
import { createLabWallet, loadLabWallet, saveLabWallet } from "../src/chain/wallet.ts";
import { encodeFriProof, proveFri, wBatchExit } from "../src/backends/circle/fri.ts";
import { circleFriPlugin } from "../src/backends/circle/plugin.ts";
import {
  compileCovenantSpend,
  compileCovenantSuccessor,
  compileFundVerifierKernels,
  compileSelfSendVout0,
} from "../src/chain/covenant-spend.ts";
import { broadcast, connectChipnet, listUnspent } from "../src/chain/electrum.ts";
import { hashPayoutSet } from "../src/chain/payout.ts";

const COUNT = 24;

function rnd32(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}

function p2pkh(address: string): Uint8Array {
  const decoded = decodeCashAddress(address);
  if (typeof decoded === "string") throw new Error(decoded);
  return encodeLockingBytecodeP2pkh(decoded.payload);
}

function shuffle<T>(items: T[]): T[] {
  const out = items.slice();
  for (let i = out.length - 1; i > 0; i -= 1) {
    const j = Number(crypto.getRandomValues(new Uint8Array(1))[0]!) % (i + 1);
    const tmp = out[i]!;
    out[i] = out[j]!;
    out[j] = tmp;
  }
  return out;
}

async function main(): Promise<void> {
  const lab = await loadLabWallet();
  const dir = join(process.cwd(), ".local", "batch-flood");
  await mkdir(dir, { recursive: true });

  const wallets = [];
  for (let i = 0; i < COUNT; i += 1) {
    const w = createLabWallet();
    await saveLabWallet(w, join(dir, `w${i + 1}.json`));
    wallets.push(w);
  }

  let machine: PoolMachine = {
    state: emptyState(rnd32()),
    notes: new IncrementalMerkle(),
    nullifiers: new NullifierSet(),
  };
  const held: Array<{ note: Note; index: number; address: string }> = [];
  for (let i = 0; i < COUNT; i += 1) {
    const note: Note = {
      amountSats: 20_000n + BigInt(i % 8) * 1_000n,
      rho: rnd32(),
      ownerSecret: rnd32(),
    };
    const d = applyDeposit(machine, note);
    machine = d.machine;
    held.push({ note, index: d.index, address: wallets[i]!.address });
  }

  const shuffled = shuffle(held);
  const items = shuffled.map((h) => ({
    note: h.note,
    index: h.index,
    withdrawSats: h.note.amountSats,
    payoutLocking: p2pkh(h.address),
  }));
  const oldState = machine.state;
  const batch = applyBatchExit(machine, items);
  const sum = batch.payouts.reduce((n, p) => n + p.sats, 0n);
  if (sum !== oldState.reserveSats - batch.machine.state.reserveSats) {
    throw new Error("internal conservation failed");
  }
  if (batch.payouts.some((p, i) => p.sats !== items[i]!.withdrawSats)) {
    throw new Error("payout does not match its note");
  }
  const setDigest = hashPayoutSet(batch.payouts);
  if (setDigest.some((b, i) => b !== batch.statement.payoutLockingDigest[i])) {
    throw new Error("payout-set digest mismatch");
  }

  const proof = encodeFriProof(
    proveFri(
      batch.statement,
      wBatchExit(batch.spent.map((s) => ({ note: s.note, index: s.index, path: s.path }))),
    ),
  );
  const v = circleFriPlugin.verify(batch.statement, proof);
  if (!v.ok) throw new Error(`verify: ${v.reason}`);

  const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
  const client = await connectChipnet();
  try {
    const utxos = await listUnspent(client, lab.address);
    console.error(`utxos=${utxos.length} ${JSON.stringify(utxos.map((u) => ({ v: u.value, pos: u.tx_pos, h: u.height, tx: u.tx_hash.slice(0, 12) })))}`);
    const need = Number(utxoValueFor(oldState)) + 200_000;
    const confirmed = utxos.filter((u) => u.height > 0 && u.value >= need).sort((a, b) => b.value - a.value);
    const any = utxos.filter((u) => u.value >= need).sort((a, b) => b.value - a.value);
    let picked = confirmed[0] ?? any[0];
    if (!picked) throw new Error(`no utxo >= ${need} sats`);
    if (picked.tx_pos !== 0) {
      const prep = compileSelfSendVout0(lab, picked);
      const prepTxid = await broadcast(client, binToHex(prep.raw));
      console.error(`prep vout0 ${prepTxid}`);
      await sleep(5000);
      picked = { tx_hash: prep.txid, tx_pos: 0, value: prep.value, height: 0 };
    }
    const genesisM = compileCovenantSpend({
      wallet: lab,
      utxo: picked,
      state: oldState,
      proof,
      lockKind: "p2sh32",
    });
    if (genesisM.changeValue === undefined || genesisM.changeValue < 150_000) {
      throw new Error("genesis left no change for kernels");
    }
    const genesisTxid = await broadcast(client, binToHex(genesisM.raw));
    console.error(`genesis ${genesisTxid} ${genesisM.txBytes}B`);
    const funder = { tx_hash: genesisTxid, tx_pos: 1, value: genesisM.changeValue };
    const funded = compileFundVerifierKernels(lab, funder);
    let kernelTxid = "";
    let lastErr: Error | undefined;
    for (let i = 0; i < 8; i += 1) {
      await sleep(2500 * (i + 1));
      try {
        kernelTxid = await broadcast(client, binToHex(funded.raw));
        lastErr = undefined;
        break;
      } catch (e) {
        lastErr = e instanceof Error ? e : new Error(String(e));
        console.error(`kernel try ${i + 1}: ${lastErr.message}`);
      }
    }
    if (!kernelTxid) throw lastErr ?? new Error("kernel broadcast failed");
    console.error(`kernels ${kernelTxid}`);
    let succTxid = "";
    lastErr = undefined;
    const successor = compileCovenantSuccessor({
      pool: {
        tx_hash: genesisTxid,
        tx_pos: 0,
        value: utxoValueFor(oldState),
        category: hexToBin(picked.tx_hash),
        commitment: encodePublicPaa1(oldState),
      },
      newState: batch.machine.state,
      proof,
      statement: batch.statement,
      extraPayouts: batch.payouts,
      payoutLockingBytecode: batch.payouts[0]!.lockingBytecode,
      kernelUtxos: funded.fri,
      extraKernels: funded.extra,
    });
    if (successor.txBytes > 100_000) {
      throw new Error(`successor ${successor.txBytes} B exceeds 100 KB relay`);
    }
    for (let i = 0; i < 8; i += 1) {
      await sleep(2000 * (i + 1));
      try {
        succTxid = await broadcast(client, binToHex(successor.raw));
        lastErr = undefined;
        break;
      } catch (e) {
        lastErr = e instanceof Error ? e : new Error(String(e));
        console.error(`successor try ${i + 1}: ${lastErr.message}`);
      }
    }
    if (!succTxid) throw lastErr ?? new Error("successor broadcast failed");
    const report = {
      fundingTx: "3eb74a3cd5998fc9e1cbb8542ea4781bc496a6a4080bd7df542feb9ba24c7d22",
      waiters: COUNT,
      payouts: batch.payouts.map((p, i) => ({
        sats: p.sats.toString(),
        address: shuffled[i]!.address,
      })),
      sumSats: sum.toString(),
      poolIn: utxoValueFor(oldState).toString(),
      poolOut: utxoValueFor(batch.machine.state).toString(),
      genesis: genesisTxid,
      kernelTxid,
      successor: succTxid,
      txBytes: successor.txBytes,
      explorer: `https://chipnet.imaginary.cash/tx/${succTxid}`,
      note: "Each output equals that note. Sum equals pool drop. Not untraceable.",
    };
    await writeFile(join(dir, "report.json"), JSON.stringify(report, null, 2));
    console.log(JSON.stringify(report, null, 2));
  } finally {
    client.close();
  }
}

main().catch((e) => {
  console.error(e instanceof Error ? e.message : e);
  process.exit(1);
});

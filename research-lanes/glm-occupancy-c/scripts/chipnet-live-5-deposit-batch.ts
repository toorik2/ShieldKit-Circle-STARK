/**
 * Live Chipnet pool: empty genesis, 5 distinct on-chain deposits, then exit
 * all 5 notes as B successors (1-note membership each).
 *
 * A single 5-note step-kernel successor cannot spend this genesis: step locks
 * must be pinned when the pool NFT is created, and those locks bake the
 * nullifiers of notes that do not exist yet. Live walk-in deposits + one-bus
 * batch needs a covenant that does not pin per-note step hashes at genesis.
 *
 * Never prints keys.
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { hexToBin } from "@bitauth/libauth";
import { encodeFriProof, proveFri, verifyFri, wWithdraw } from "../src/backends/circle/fri.ts";
import { wDeposit } from "../src/backends/circle/air.ts";
import { applyDeposit, applyWithdraw } from "../src/pool/transition.ts";
import { IncrementalMerkle, NullifierSet, type Note } from "../src/pool/notes.ts";
import { emptyState, encodePublicPaa1, utxoValueFor, type AnyAmountState } from "../src/pool/state.ts";
import { LAB_PAYOUT_DIGEST } from "../src/chain/payout.ts";
import { loadLabWallet, type LabWallet } from "../src/chain/wallet.ts";
import { connectChipnet, listUnspent, type ElectrumClient } from "../src/chain/electrum.ts";
import {
  compileCovenantSpend,
  compileCovenantSuccessor,
  compileFundVerifierKernels,
} from "../src/chain/covenant-spend.ts";
import { compileTapeFunder } from "../src/chain/chained.ts";
import { SLOT_KERNEL_COUNT_CONSENSUS } from "../src/chain/air-cqz.ts";
import { successorFeeCoinSats } from "../src/chain/envelope.ts";
import { broadcastRetry, waitForTxid } from "../src/chain/land-envelopes.ts";
import { evaluatePoolSuccessorVm } from "../src/chain/vm-verifier.ts";
import { FRI_QUERIES, FRI_VERSION, VK_ID } from "../src/backends/circle/params.ts";

const SLOTS = SLOT_KERNEL_COUNT_CONSENSUS;
const AMOUNTS = [10_000n, 20_000n, 30_000n, 40_000n, 50_000n];
const EXPLORER = "https://chipnet.chaingraph.cash/tx";

type Utxo = { tx_hash: string; tx_pos: number; value: number; height: number };

function pickFunded(utxos: Utxo[], need: number, used: Set<string>): Utxo | undefined {
  return utxos
    .filter((u) => u.value >= need && !used.has(`${u.tx_hash}:${u.tx_pos}`))
    .sort((a, b) => a.value - b.value)[0];
}

async function fundKernels(
  client: ElectrumClient,
  wallet: LabWallet,
  used: Set<string>,
): Promise<{ fri: Utxo[]; extra: Utxo[]; txid: string; path: string }> {
  const utxos = await listUnspent(client, wallet.address);
  const u = pickFunded(utxos, 200_000, used);
  if (!u) throw new Error("no utxo for kernels");
  used.add(`${u.tx_hash}:${u.tx_pos}`);
  const funded = compileFundVerifierKernels(
    wallet,
    u,
    1_000,
    SLOTS,
    successorFeeCoinSats("consensus"),
  );
  const sent = await broadcastRetry(client, funded.raw, funded.txid);
  await waitForTxid(client, sent.txid);
  return {
    fri: funded.fri,
    extra: funded.extra,
    txid: sent.txid,
    path: sent.path,
  };
}

const scratch = process.argv[2] ?? ".local/chipnet-live-5";
mkdirSync(scratch, { recursive: true });
const wallet = await loadLabWallet();
const client = await connectChipnet();
const used = new Set<string>();
const report: Record<string, unknown> = {
  vk: VK_ID,
  friVersion: FRI_VERSION,
  queries: FRI_QUERIES,
  slots: SLOTS,
  note: "5 live deposits; 5 live 1-note B exits. One-tx 5-note step batch needs nfs pinned at genesis.",
};

try {
  let utxos = await listUnspent(client, wallet.address);
  const genesisNeed = 400_000;
  let genesisU = pickFunded(utxos, genesisNeed, used);
  if (!genesisU) throw new Error(`no utxo >= ${genesisNeed}`);
  if (genesisU.tx_pos !== 0 || genesisU.value > genesisNeed + 50_000) {
    const split = compileTapeFunder({ wallet, utxo: genesisU, tapeSats: BigInt(genesisNeed) });
    const prep = await broadcastRetry(client, split.raw, split.txid);
    await waitForTxid(client, split.txid);
    report.prep = { txid: prep.txid, explorer: `${EXPLORER}/${prep.txid}` };
    genesisU = { tx_hash: split.txid, tx_pos: 0, value: genesisNeed, height: 0 };
  }
  used.add(`${genesisU.tx_hash}:${genesisU.tx_pos}`);

  const genesisState = emptyState(crypto.getRandomValues(new Uint8Array(32)));
  const genesis = compileCovenantSpend({
    wallet,
    utxo: genesisU,
    state: genesisState,
    proof: new Uint8Array(32),
    lockKind: "p2sh32",
    envelope: "consensus",
    slotKernels: SLOTS,
  });
  const genesisSent = await broadcastRetry(client, genesis.raw, genesis.txid);
  await waitForTxid(client, genesisSent.txid);
  report.genesis = { txid: genesisSent.txid, path: genesisSent.path, explorer: `${EXPLORER}/${genesisSent.txid}` };
  const category = hexToBin(genesisU.tx_hash);

  let machine = {
    state: genesisState,
    notes: new IncrementalMerkle(),
    nullifiers: new NullifierSet(),
  };
  let pool: { tx_hash: string; tx_pos: number; value: number } = {
    tx_hash: genesisSent.txid,
    tx_pos: 0,
    value: utxoValueFor(genesisState),
  };
  let oldState: AnyAmountState = genesisState;
  const held: Array<{ note: Note; index: number }> = [];
  const deposits: unknown[] = [];

  for (const sats of AMOUNTS) {
    const ker = await fundKernels(client, wallet, used);
    const note: Note = {
      amountSats: sats,
      rho: crypto.getRandomValues(new Uint8Array(32)),
      ownerSecret: crypto.getRandomValues(new Uint8Array(32)),
    };
    const d = applyDeposit(machine, note);
    const proved = proveFri(d.statement, wDeposit(note, d.index, d.path));
    const proof = encodeFriProof(proved);
    const fri = verifyFri(d.statement, proved);
    if (!fri.ok) throw new Error(`deposit ${sats} verifyFri fail`);
    utxos = await listUnspent(client, wallet.address);
    const feeU = pickFunded(utxos, 150_000, used);
    if (!feeU) throw new Error(`no deposit funder for ${sats}`);
    used.add(`${feeU.tx_hash}:${feeU.tx_pos}`);
    const tx = compileCovenantSuccessor({
      wallet,
      feeUtxo: feeU,
      pool: { ...pool, category, commitment: encodePublicPaa1(oldState) },
      newState: d.machine.state,
      proof,
      statement: d.statement,
      lockKind: "p2sh32",
      envelope: "consensus",
      slotKernels: SLOTS,
      kernelUtxos: ker.fri,
      extraKernels: ker.extra,
      note,
    });
    const vm = evaluatePoolSuccessorVm({
      oldState,
      newState: d.machine.state,
      proof,
      statement: d.statement,
      slotKernels: SLOTS,
      standard: true,
      note,
    });
    if (!vm.accepted) throw new Error(`deposit ${sats} VM: ${vm.error}`);
    const sent = await broadcastRetry(client, tx.raw, tx.txid);
    await waitForTxid(client, sent.txid);
    deposits.push({
      sats: Number(sats),
      txid: sent.txid,
      txBytes: tx.txBytes,
      path: sent.path,
      explorer: `${EXPLORER}/${sent.txid}`,
      kernels: ker.txid,
    });
    machine = d.machine;
    oldState = d.machine.state;
    pool = { tx_hash: sent.txid, tx_pos: 0, value: utxoValueFor(d.machine.state) };
    held.push({ note, index: d.index });
  }
  report.deposits = deposits;

  const exits: unknown[] = [];
  for (const h of held) {
    const ker = await fundKernels(client, wallet, used);
    const w = applyWithdraw(machine, h.note, h.index, LAB_PAYOUT_DIGEST, h.note.amountSats);
    const wit = wWithdraw(h.note, h.index, w.path, w.created);
    const proved = proveFri(w.statement, wit);
    const proof = encodeFriProof(proved);
    const fri = verifyFri(w.statement, proved);
    if (!fri.ok) throw new Error(`withdraw ${h.note.amountSats} verifyFri fail`);
    const tx = compileCovenantSuccessor({
      wallet,
      pool: { ...pool, category, commitment: encodePublicPaa1(oldState) },
      newState: w.machine.state,
      proof,
      statement: w.statement,
      lockKind: "p2sh32",
      envelope: "consensus",
      slotKernels: SLOTS,
      kernelUtxos: ker.fri,
      extraKernels: ker.extra,
      note: h.note,
      change: w.created?.note,
    });
    const vm = evaluatePoolSuccessorVm({
      oldState,
      newState: w.machine.state,
      proof,
      statement: w.statement,
      slotKernels: SLOTS,
      standard: true,
      note: h.note,
      change: w.created?.note,
    });
    if (!vm.accepted) throw new Error(`withdraw ${h.note.amountSats} VM: ${vm.error}`);
    const sent = await broadcastRetry(client, tx.raw, tx.txid);
    await waitForTxid(client, sent.txid);
    exits.push({
      sats: Number(h.note.amountSats),
      txid: sent.txid,
      txBytes: tx.txBytes,
      path: sent.path,
      explorer: `${EXPLORER}/${sent.txid}`,
      kernels: ker.txid,
    });
    machine = w.machine;
    oldState = w.machine.state;
    pool = { tx_hash: sent.txid, tx_pos: 0, value: utxoValueFor(w.machine.state) };
  }
  report.exits = exits;
  writeFileSync(join(scratch, "report.json"), `${JSON.stringify(report, null, 2)}\n`);
  console.log(JSON.stringify(report, null, 2));
} catch (e) {
  report.error = e instanceof Error ? e.message : String(e);
  writeFileSync(join(scratch, "report.json"), `${JSON.stringify(report, null, 2)}\n`);
  console.error(JSON.stringify(report, null, 2));
  process.exitCode = 1;
} finally {
  client.close();
}

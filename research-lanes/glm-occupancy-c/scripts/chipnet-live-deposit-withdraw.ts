/**
 * Live Chipnet: genesis empty B pool, deposit successor, withdraw successor.
 * Freeze walker (6 slot kernels, leftover-pairs empty, PICK-bounded). Electrum only.
 * Never prints keys.
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { hexToBin } from "@bitauth/libauth";
import { encodeFriProof, proveFri, verifyFri, wWithdraw } from "../src/backends/circle/fri.ts";
import { wDeposit } from "../src/backends/circle/air.ts";
import { applyDeposit, applyWithdraw } from "../src/pool/transition.ts";
import { IncrementalMerkle, NullifierSet, type Note } from "../src/pool/notes.ts";
import { emptyState, encodePublicPaa1, utxoValueFor } from "../src/pool/state.ts";
import { LAB_PAYOUT_DIGEST } from "../src/chain/payout.ts";
import { loadLabWallet } from "../src/chain/wallet.ts";
import { connectChipnet, listUnspent } from "../src/chain/electrum.ts";
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
import { FRI_VERSION, FRI_QUERIES, VK_ID } from "../src/backends/circle/params.ts";

const SLOTS = SLOT_KERNEL_COUNT_CONSENSUS;
const DEPOSIT_SATS = 10_000n;
const EXPLORER = "https://chipnet.imaginary.cash/tx";

function pickFunded(
  utxos: Array<{ tx_hash: string; tx_pos: number; value: number; height: number }>,
  need: number,
  used: Set<string>,
) {
  const ok = utxos
    .filter((u) => u.value >= need && !used.has(`${u.tx_hash}:${u.tx_pos}`))
    .sort((a, b) => a.value - b.value);
  return ok[0];
}

const scratch = process.argv[2] ?? ".local/chipnet-live-dw";
mkdirSync(scratch, { recursive: true });

const wallet = await loadLabWallet();
const client = await connectChipnet();
const used = new Set<string>();
const report: Record<string, unknown> = {
  vk: VK_ID,
  friVersion: FRI_VERSION,
  queries: FRI_QUERIES,
  slots: SLOTS,
  address: wallet.address,
};

try {
  let utxos = await listUnspent(client, wallet.address);
  const genesisNeed = 400_000;
  let genesisU = pickFunded(utxos, genesisNeed, used);
  if (!genesisU) throw new Error(`no utxo >= ${genesisNeed} (n=${utxos.length})`);
  if (genesisU.tx_pos !== 0 || genesisU.value > genesisNeed + 50_000) {
    const split = compileTapeFunder({ wallet, utxo: genesisU, tapeSats: BigInt(genesisNeed) });
    const prep = await broadcastRetry(client, split.raw, split.txid);
    await waitForTxid(client, split.txid);
    report.prep = prep.txid;
    genesisU = { tx_hash: split.txid, tx_pos: 0, value: genesisNeed, height: 0 };
  }
  used.add(`${genesisU.tx_hash}:${genesisU.tx_pos}`);

  const instance = crypto.getRandomValues(new Uint8Array(32));
  const genesisState = emptyState(instance);
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

  if (genesis.changeValue === undefined || genesis.changeValue < 200_000) {
    throw new Error(`genesis change ${genesis.changeValue} too small for kernels`);
  }
  const funded1 = compileFundVerifierKernels(
    wallet,
    { tx_hash: genesisSent.txid, tx_pos: 1, value: genesis.changeValue },
    1_000,
    SLOTS,
    successorFeeCoinSats("consensus"),
  );
  const ker1 = await broadcastRetry(client, funded1.raw, funded1.txid);
  await waitForTxid(client, ker1.txid);
  report.kernelsDeposit = { txid: ker1.txid, path: ker1.path, explorer: `${EXPLORER}/${ker1.txid}` };

  const note: Note = {
    amountSats: DEPOSIT_SATS,
    rho: crypto.getRandomValues(new Uint8Array(32)),
    ownerSecret: crypto.getRandomValues(new Uint8Array(32)),
  };
  let machine = {
    state: genesisState,
    notes: new IncrementalMerkle(),
    nullifiers: new NullifierSet(),
  };
  const d = applyDeposit(machine, note);
  const depProved = proveFri(d.statement, wDeposit(note, d.index, d.path));
  const depProof = encodeFriProof(depProved);
  const depFri = verifyFri(d.statement, depProved);
  if (!depFri.ok) throw new Error(`deposit verifyFri: ${"reason" in depFri ? depFri.reason : "fail"}`);

  utxos = await listUnspent(client, wallet.address);
  const feeU = pickFunded(utxos, 150_000, used);
  if (!feeU) throw new Error("no utxo for deposit funder");
  used.add(`${feeU.tx_hash}:${feeU.tx_pos}`);

  const depositTx = compileCovenantSuccessor({
    wallet,
    feeUtxo: feeU,
    pool: {
      tx_hash: genesisSent.txid,
      tx_pos: 0,
      value: utxoValueFor(genesisState),
      category: hexToBin(genesisU.tx_hash),
      commitment: encodePublicPaa1(genesisState),
    },
    newState: d.machine.state,
    proof: depProof,
    statement: d.statement,
    lockKind: "p2sh32",
    envelope: "consensus",
    slotKernels: SLOTS,
    kernelUtxos: funded1.fri,
    extraKernels: funded1.extra,
    note,
  });
  const depVm = evaluatePoolSuccessorVm({
    oldState: genesisState,
    newState: d.machine.state,
    proof: depProof,
    statement: d.statement,
    slotKernels: SLOTS,
    standard: true,
    note,
  });
  if (!depVm.accepted) throw new Error(`deposit VM reject: ${depVm.error}`);
  const depSent = await broadcastRetry(client, depositTx.raw, depositTx.txid);
  await waitForTxid(client, depSent.txid);
  report.deposit = {
    txid: depSent.txid,
    path: depSent.path,
    txBytes: depositTx.txBytes,
    unlockingBytes: depositTx.unlockingBytes,
    explorer: `${EXPLORER}/${depSent.txid}`,
    standardVm: depVm.accepted,
    verifyFri: true,
  };

  utxos = await listUnspent(client, wallet.address);
  const ker2U = pickFunded(utxos, 200_000, used);
  if (!ker2U) throw new Error("no utxo for withdraw kernels");
  used.add(`${ker2U.tx_hash}:${ker2U.tx_pos}`);
  const funded2 = compileFundVerifierKernels(
    wallet,
    ker2U,
    1_000,
    SLOTS,
    successorFeeCoinSats("consensus"),
  );
  const ker2 = await broadcastRetry(client, funded2.raw, funded2.txid);
  await waitForTxid(client, ker2.txid);
  report.kernelsWithdraw = { txid: ker2.txid, path: ker2.path, explorer: `${EXPLORER}/${ker2.txid}` };

  machine = d.machine;
  const w = applyWithdraw(machine, note, d.index, LAB_PAYOUT_DIGEST, DEPOSIT_SATS);
  const wit = wWithdraw(note, d.index, w.path, w.created);
  const wdProved = proveFri(w.statement, wit);
  const wdProof = encodeFriProof(wdProved);
  const wdFri = verifyFri(w.statement, wdProved);
  if (!wdFri.ok) throw new Error(`withdraw verifyFri: ${"reason" in wdFri ? wdFri.reason : "fail"}`);

  const withdrawTx = compileCovenantSuccessor({
    wallet,
    pool: {
      tx_hash: depSent.txid,
      tx_pos: 0,
      value: utxoValueFor(d.machine.state),
      category: hexToBin(genesisU.tx_hash),
      commitment: encodePublicPaa1(d.machine.state),
    },
    newState: w.machine.state,
    proof: wdProof,
    statement: w.statement,
    lockKind: "p2sh32",
    envelope: "consensus",
    slotKernels: SLOTS,
    kernelUtxos: funded2.fri,
    extraKernels: funded2.extra,
    note,
    change: w.created?.note,
  });
  const wdVm = evaluatePoolSuccessorVm({
    oldState: d.machine.state,
    newState: w.machine.state,
    proof: wdProof,
    statement: w.statement,
    slotKernels: SLOTS,
    standard: true,
    note,
    change: w.created?.note,
  });
  if (!wdVm.accepted) throw new Error(`withdraw VM reject: ${wdVm.error}`);
  const wdSent = await broadcastRetry(client, withdrawTx.raw, withdrawTx.txid);
  await waitForTxid(client, wdSent.txid);
  report.withdraw = {
    txid: wdSent.txid,
    path: wdSent.path,
    txBytes: withdrawTx.txBytes,
    unlockingBytes: withdrawTx.unlockingBytes,
    explorer: `${EXPLORER}/${wdSent.txid}`,
    standardVm: wdVm.accepted,
    verifyFri: true,
  };

  writeFileSync(join(scratch, "live-deposit-withdraw.json"), `${JSON.stringify(report, null, 2)}\n`);
  console.log(JSON.stringify(report, null, 2));
} catch (e) {
  report.error = e instanceof Error ? e.message : String(e);
  writeFileSync(join(scratch, "live-deposit-withdraw.json"), `${JSON.stringify(report, null, 2)}\n`);
  console.error(JSON.stringify(report, null, 2));
  process.exitCode = 1;
} finally {
  client.close();
}

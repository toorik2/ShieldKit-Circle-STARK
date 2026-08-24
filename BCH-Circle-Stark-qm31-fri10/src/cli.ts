#!/usr/bin/env node
import { decodeTransaction } from "@bitauth/libauth";
import { circleFriPlugin } from "./backends/circle/plugin.ts";
import { FRI_QUERIES, FRI_VERSION, RULES_SHA256, VK_ID } from "./backends/circle/params.ts";
import { soundnessWorksheet } from "./backends/circle/soundness.ts";
import { SLOT_KERNEL_COUNT_CONSENSUS } from "./chain/air-cqz.ts";
import { requestFaucet, walletBalance } from "./chain/chipnet.ts";
import { compileCovenantSuccessor } from "./chain/covenant-spend.ts";
import { landQm31Successor } from "./chain/land.ts";
import { createLabWallet, loadLabWallet, saveLabWallet } from "./chain/wallet.ts";
import { evaluatePoolSuccessorVm } from "./chain/vm-verifier.ts";
import { inspectHex, loadSuccessorHex } from "./inspect.ts";
import { runMixSuccessor } from "./pool/mix-successor.ts";
import { encodePublicPaa1, utxoValueFor } from "./pool/state.ts";

const help = `BCH Circle STARK  (QM31 FRI10 occupancy)

  vk                 print vk, RULES sha256, worksheet
  prove              mix successor: prove + verifyFri
  measure            compile 18-input B, print bytes
  vm                 measure + createVirtualMachineBch2026(true)
  inspect [txid|hex] leftover-bind / occupancy of a successor
  wallet new|show    Chipnet lab key in .local/ (gitignored)
  faucet             public Chipnet faucet URLs
  balance            electrum listunspent
  land               Electrum land of this family (needs funded wallet)

Chipnet only. RULES.md is hashed into the vk — do not edit it in place.
`;

const cmd = process.argv[2] ?? "help";

if (cmd === "help" || cmd === "-h" || cmd === "--help") {
  process.stdout.write(help);
} else if (cmd === "vk") {
  const w = soundnessWorksheet();
  console.log(
    JSON.stringify(
      {
        vk: VK_ID,
        rulesSha256: RULES_SHA256,
        friVersion: FRI_VERSION,
        queries: FRI_QUERIES,
        worksheet: w,
      },
      null,
      2,
    ),
  );
} else if (cmd === "prove") {
  const mix = runMixSuccessor({ depositCount: 6, withdrawSats: 1_000n });
  const v = circleFriPlugin.verify(mix.statement, mix.proof);
  if (!v.ok) throw new Error(v.reason);
  console.log(JSON.stringify({ ok: true, vk: VK_ID, proofBytes: mix.proof.length }, null, 2));
} else if (cmd === "measure" || cmd === "vm") {
  const mix = runMixSuccessor({ depositCount: 6, withdrawSats: 1_000n });
  const fri = circleFriPlugin.verify(mix.statement, mix.proof);
  if (!fri.ok) throw new Error(fri.reason);
  const measured = compileCovenantSuccessor({
    wallet: createLabWallet(),
    pool: {
      tx_hash: "11".repeat(32),
      tx_pos: 0,
      value: utxoValueFor(mix.oldState),
      category: new Uint8Array(32).fill(0x11),
      commitment: encodePublicPaa1(mix.oldState),
    },
    newState: mix.newState,
    proof: mix.proof,
    statement: mix.statement,
    lockKind: "p2sh32",
    envelope: "consensus",
    slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
    note: mix.spent.note,
    change: mix.witness.created?.note,
  });
  const tx = decodeTransaction(measured.raw);
  if (typeof tx === "string") throw new Error(tx);
  const report: Record<string, unknown> = {
    vk: VK_ID,
    verifyFri: fri,
    txBytes: measured.txBytes,
    inputs: tx.inputs.length,
    maxUnlocking: Math.max(...tx.inputs.map((i) => i.unlockingBytecode.length)),
  };
  if (cmd === "vm") {
    const vm = evaluatePoolSuccessorVm({
      oldState: mix.oldState,
      newState: mix.newState,
      proof: mix.proof,
      statement: mix.statement,
      slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
      standard: true,
      note: mix.spent.note,
      change: mix.witness.created?.note,
    });
    report.vmAccepted = vm.accepted;
    report.vmError = vm.error;
    if (!vm.accepted) process.exitCode = 1;
  }
  console.log(JSON.stringify(report, null, 2));
} else if (cmd === "inspect") {
  const { hex, txid } = await loadSuccessorHex(process.argv[3]);
  console.log(JSON.stringify(inspectHex(hex, txid), null, 2));
} else if (cmd === "wallet") {
  const sub = process.argv[3] ?? "show";
  if (sub === "new") {
    const w = createLabWallet();
    await saveLabWallet(w);
    console.log(JSON.stringify({ address: w.address }, null, 2));
  } else {
    const w = await loadLabWallet();
    console.log(JSON.stringify({ address: w.address }, null, 2));
  }
} else if (cmd === "faucet") {
  const w = await loadLabWallet();
  console.log(await requestFaucet(w.address));
} else if (cmd === "balance") {
  const w = await loadLabWallet();
  const b = await walletBalance(w.address);
  console.log(JSON.stringify({ address: w.address, sats: b.sats.toString(), utxos: b.utxos.length }, null, 2));
} else if (cmd === "land") {
  const r = await landQm31Successor();
  console.log(JSON.stringify(r, null, 2));
  if (r.ok !== true) process.exitCode = 1;
} else {
  process.stderr.write(`unknown command ${cmd}\n${help}`);
  process.exitCode = 1;
}

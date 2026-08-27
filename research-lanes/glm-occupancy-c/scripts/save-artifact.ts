/**
 * Write a checkpoint pack for the current B successor.
 * Usage: npx tsx scripts/save-artifact.ts 400000
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { decodeTransaction, binToHex } from "@bitauth/libauth";
import { applyDeposit, applyWithdraw } from "../src/pool/transition.ts";
import { IncrementalMerkle, NullifierSet, type Note } from "../src/pool/notes.ts";
import { emptyState, encodePublicPaa1, utxoValueFor } from "../src/pool/state.ts";
import { LAB_PAYOUT_DIGEST } from "../src/chain/payout.ts";
import { encodeFriProof, proveFri, verifyFri, wWithdraw } from "../src/backends/circle/fri.ts";
import { FRI_QUERIES, FRI_VERSION, VK_ID, CONJECTURAL_BITS } from "../src/backends/circle/params.ts";
import { DEFAULT_INTERNAL_HASH_ID } from "../src/backends/circle/internal-hash.ts";
import { compileCovenantSuccessor } from "../src/chain/covenant-spend.ts";
import { createLabWallet } from "../src/chain/wallet.ts";
import { evaluatePoolSuccessorVm } from "../src/chain/vm-verifier.ts";
import { SLOT_KERNEL_COUNT_CONSENSUS } from "../src/chain/air-cqz.ts";
import { RELAY_STANDARD_TX_BYTES } from "../src/chain/envelope.ts";

const mark = Number(process.argv[2] ?? "400000");
const note: Note = {
  amountSats: 10_000n,
  rho: crypto.getRandomValues(new Uint8Array(32)),
  ownerSecret: crypto.getRandomValues(new Uint8Array(32)),
};
const d = applyDeposit(
  { state: emptyState(crypto.getRandomValues(new Uint8Array(32))), notes: new IncrementalMerkle(), nullifiers: new NullifierSet() },
  note,
);
const w = applyWithdraw(d.machine, note, d.index, LAB_PAYOUT_DIGEST, 3_000n);
const proved = proveFri(w.statement, wWithdraw(note, d.index, w.path, w.created));
const proof = encodeFriProof(proved);
const v = verifyFri(w.statement, proved);
const pool = {
  tx_hash: "11".repeat(32),
  tx_pos: 0,
  value: utxoValueFor(w.statement.oldState),
  category: new Uint8Array(32).fill(0x11),
  commitment: encodePublicPaa1(w.statement.oldState),
};
const B = compileCovenantSuccessor({
  wallet: createLabWallet(),
  pool,
  newState: w.statement.newState,
  proof,
  statement: w.statement,
  lockKind: "p2sh32",
  envelope: "consensus",
  slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
  note,
  change: w.created?.note,
});
const tx = decodeTransaction(B.raw);
if (typeof tx === "string") throw new Error(tx);
const std = evaluatePoolSuccessorVm({
  oldState: w.statement.oldState,
  newState: w.statement.newState,
  proof,
  statement: w.statement,
  slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
  standard: true,
  note,
  change: w.created?.note,
});
const cons = evaluatePoolSuccessorVm({
  oldState: w.statement.oldState,
  newState: w.statement.newState,
  proof,
  statement: w.statement,
  slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
  standard: false,
  note,
  change: w.created?.note,
});
const dir = join("survey/artifacts", `${mark}b`);
mkdirSync(dir, { recursive: true });
writeFileSync(join(dir, "tx.hex"), `${binToHex(B.raw)}\n`);
writeFileSync(join(dir, "proof.bin"), proof);
writeFileSync(join(dir, "inputs.json"), `${JSON.stringify({
  txBytes: B.txBytes,
  inputs: tx.inputs.map((i, n) => ({
    i: n,
    unlocking: i.unlockingBytecode.length,
  })),
}, null, 2)}\n`);
writeFileSync(join(dir, "meta.json"), `${JSON.stringify({
  mark,
  txBytes: B.txBytes,
  txid: B.txid,
  inputs: tx.inputs.length,
  maxUnlocking: Math.max(...tx.inputs.map((i) => i.unlockingBytecode.length)),
  unlockingSum: tx.inputs.reduce((n, i) => n + i.unlockingBytecode.length, 0),
  friVersion: FRI_VERSION,
  queries: FRI_QUERIES,
  vkId: VK_ID,
  hash: DEFAULT_INTERNAL_HASH_ID,
  conjecturalBits: CONJECTURAL_BITS,
  verifyFri: v,
  standardAccepted: std.accepted,
  standardError: std.error,
  consensusAccepted: cons.accepted,
  consensusError: cons.error,
  standardLimit: RELAY_STANDARD_TX_BYTES,
  completeness: {
    friVersion: FRI_VERSION,
    uniqueOrbits: FRI_QUERIES,
    grind: 20,
    sha256: DEFAULT_INTERNAL_HASH_ID,
    worksheetBits: CONJECTURAL_BITS,
    dummyPad: false,
  },
}, null, 2)}\n`);
writeFileSync(join(dir, "README.md"), `# B checkpoint ≤ ${mark} B

txBytes **${B.txBytes}**. Completeness: FRI${FRI_VERSION}, q=${FRI_QUERIES}, vk \`${VK_ID}\`, hash ${DEFAULT_INTERNAL_HASH_ID}.

Recompile/verify:

\`\`\`bash
cd research-lanes/envelope-b-standard
npx tsx --test --test-name-pattern 'honest 36-query B successor' test/hole-free-b.test.ts
npx tsx scripts/save-artifact.ts ${mark}
\`\`\`

standard=true accept: ${std.accepted} (${std.error ?? "ok"})
consensus accept: ${cons.accepted}
verifyFri: ${JSON.stringify(v)}
`);
console.log(JSON.stringify({ dir, txBytes: B.txBytes, standardAccepted: std.accepted, consensusAccepted: cons.accepted, verifyFri: v }, null, 2));

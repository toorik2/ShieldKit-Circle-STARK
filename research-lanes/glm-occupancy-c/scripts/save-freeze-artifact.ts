/**
 * Self-contained pack of the argument-freeze B successor (standard-size, leftover-pairs empty, PICK-bounded).
 * Usage: npx tsx scripts/save-freeze-artifact.ts
 */
import { copyFileSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { binToHex, decodeTransaction } from "@bitauth/libauth";
import { applyDeposit, applyWithdraw } from "../src/pool/transition.ts";
import { IncrementalMerkle, NullifierSet, type Note } from "../src/pool/notes.ts";
import { emptyState, encodePublicPaa1, utxoValueFor } from "../src/pool/state.ts";
import { encodeFriProof, proveFri, verifyFri, wWithdraw } from "../src/backends/circle/fri.ts";
import { CONJECTURAL_BITS, FRI_QUERIES, FRI_VERSION, GRIND_BITS, VK_ID } from "../src/backends/circle/params.ts";
import { DEFAULT_INTERNAL_HASH_ID } from "../src/backends/circle/internal-hash.ts";
import { LAB_PAYOUT_DIGEST } from "../src/chain/payout.ts";
import { compileCovenantSuccessor } from "../src/chain/covenant-spend.ts";
import { createLabWallet } from "../src/chain/wallet.ts";
import { SLOT_KERNEL_COUNT_CONSENSUS } from "../src/chain/air-cqz.ts";
import { evaluatePoolSuccessorVm, evaluateSuccessorInputMeters } from "../src/chain/vm-verifier.ts";
import { compactLayerKernelAsm } from "../src/chain/fri-kernel.ts";
import { RELAY_STANDARD_TX_BYTES } from "../src/chain/envelope.ts";

const CHIPNET = {
  successor: "58b7df7f59c3b85a5c8357b0b4c10ab12c74dac984f7a8e95832ab6965c3b03a",
  txBytes: 91598,
  broadcastPath: "electrum",
  explorer: "https://chipnet.imaginary.cash/tx/58b7df7f59c3b85a5c8357b0b4c10ab12c74dac984f7a8e95832ab6965c3b03a",
  not: ["56be9ac0… skip-N walker", "86d5413f… leftover-pairs, unbounded PICK"],
};

const walker = compactLayerKernelAsm(6);
const encoding = {
  leftoverPairsEmpty: walker.includes("OP_SIZE") && walker.includes("<0>") && walker.includes("OP_NUMEQUALVERIFY"),
  pickBounded: walker.includes("OP_GREATERTHANOREQUAL") && walker.includes("OP_LESSTHAN"),
};

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
const meters = evaluateSuccessorInputMeters({
  oldState: w.statement.oldState,
  newState: w.statement.newState,
  proof,
  statement: w.statement,
  slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
  standard: true,
  note,
  change: w.created?.note,
});

const dir = join("survey/artifacts", "argument-freeze");
mkdirSync(dir, { recursive: true });
writeFileSync(join(dir, "tx.hex"), `${binToHex(B.raw)}\n`);
writeFileSync(join(dir, "proof.bin"), proof);
copyFileSync("ARGUMENT.md", join(dir, "ARGUMENT.md"));
const argument = readFileSync("ARGUMENT.md", "utf8");

const unlocking = tx.inputs.map((i, n) => ({ i: n, unlocking: i.unlockingBytecode.length }));
writeFileSync(join(dir, "inputs.json"), `${JSON.stringify({ txBytes: B.txBytes, inputs: unlocking }, null, 2)}\n`);
writeFileSync(join(dir, "meters.json"), `${JSON.stringify({
  mark: "argument-freeze",
  labSuccessor: {
    txBytes: B.txBytes,
    standardTxAccepted: meters.standardTxAccepted,
    standardTxError: meters.standardTxError,
    verifyFri: v.ok,
    friVersion: FRI_VERSION,
    queries: FRI_QUERIES,
    hash: DEFAULT_INTERNAL_HASH_ID,
    inputs: meters.inputs,
  },
}, null, 2)}\n`);
writeFileSync(join(dir, "meta.json"), `${JSON.stringify({
  mark: "argument-freeze",
  vkId: VK_ID,
  txBytes: B.txBytes,
  txid: B.txid,
  inputs: tx.inputs.length,
  maxUnlocking: Math.max(...unlocking.map((r) => r.unlocking)),
  unlockingSum: unlocking.reduce((n, r) => n + r.unlocking, 0),
  standardLimit: RELAY_STANDARD_TX_BYTES,
  standardAccepted: std.accepted,
  standardError: std.error,
  verifyFri: v,
  encoding,
  chipnet: CHIPNET,
  completeness: {
    friVersion: FRI_VERSION,
    uniqueOrbits: FRI_QUERIES,
    grind: GRIND_BITS,
    sha256: DEFAULT_INTERNAL_HASH_ID,
    worksheetBits: CONJECTURAL_BITS,
    dummyPad: false,
    leftoverPairsEmpty: encoding.leftoverPairsEmpty,
    pickBounded: encoding.pickBounded,
    argumentSha256Prefix: argument.slice(0, 80),
  },
}, null, 2)}\n`);

writeFileSync(join(dir, "README.md"), `# Argument-freeze B (standard-size verifier)

Lab compile **${B.txBytes} B**. Chipnet Electrum land **${CHIPNET.txBytes} B** \`${CHIPNET.successor}\`.

vk \`${VK_ID}\`. FRI${FRI_VERSION}, q=${FRI_QUERIES}, grind ${GRIND_BITS}, hash ${DEFAULT_INTERNAL_HASH_ID}, worksheet ${CONJECTURAL_BITS} (query conjecture; M31 field gap in ARGUMENT.md).

Encoding: leftover pair groups size 0; compact-path PICK bounded (\`k ≥ 0\` and \`k < DEPTH\`). This pack is that walker. Not \`56be9ac0…\` (skip-N). Not \`86d5413f…\` (unbounded PICK).

This directory is self-contained: \`tx.hex\`, \`proof.bin\`, \`ARGUMENT.md\` (the vk), \`meta.json\`, \`inputs.json\`, \`meters.json\` (VM \`operationCost\` / \`hashDigestIterations\`, \`standard=true\`).

Chipnet: ${CHIPNET.explorer}

standard=true: ${std.accepted} (${std.error ?? "ok"})
verifyFri: ${JSON.stringify(v)}
leftoverPairsEmpty: ${encoding.leftoverPairsEmpty}
pickBounded: ${encoding.pickBounded}

Recompile/verify from the lane (needs the rest of the tree to *rebuild*; the pack itself is the saved instance):

\`\`\`bash
cd research-lanes/envelope-b-standard
npx tsx --test --test-name-pattern 'full-completeness B successor|correspondence oracle' test/hole-free-b.test.ts test/correspondence-oracle.test.ts
npx tsx scripts/save-freeze-artifact.ts
\`\`\`
`);

if (B.txBytes > RELAY_STANDARD_TX_BYTES || !std.accepted || !v.ok || !encoding.leftoverPairsEmpty || !encoding.pickBounded) {
  throw new Error(`freeze pack failed: tx=${B.txBytes} std=${std.accepted} fri=${v.ok} enc=${JSON.stringify(encoding)}`);
}
console.log(JSON.stringify({
  dir,
  txBytes: B.txBytes,
  standardAccepted: std.accepted,
  verifyFri: v,
  encoding,
  chipnet: CHIPNET.successor,
}, null, 2));

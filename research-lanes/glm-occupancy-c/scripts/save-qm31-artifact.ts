/**
 * Self-contained pack of the QM31 occupancy family (FRI_VERSION 10, leftover bind).
 * Usage: npx tsx scripts/save-qm31-artifact.ts
 *
 * This pack is a measured wall, not the named end. RULES §6 / §7 stay open.
 */
import { copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { binToHex, decodeTransaction, hash256, hexToBin } from "@bitauth/libauth";
import { encodePublicPaa1, utxoValueFor } from "../src/pool/state.ts";
import { decodeFriProof, verifyFri } from "../src/backends/circle/fri.ts";
import { runMixSuccessor } from "../src/pool/mix-successor.ts";
import {
  BLOWUP,
  CONJECTURAL_BITS,
  FRI_QUERIES,
  FRI_VERSION,
  GRIND_BITS,
  RULES_SHA256,
  SECURE_FIELD_BIT_LENGTH,
  TRACE_LEN,
  VK_ID,
} from "../src/backends/circle/params.ts";
import { soundnessWorksheet } from "../src/backends/circle/soundness.ts";
import { DEFAULT_INTERNAL_HASH_ID } from "../src/backends/circle/internal-hash.ts";
import { compileCovenantSuccessor } from "../src/chain/covenant-spend.ts";
import { createLabWallet } from "../src/chain/wallet.ts";
import { SLOT_KERNEL_COUNT_CONSENSUS } from "../src/chain/air-cqz.ts";
import { evaluatePoolSuccessorVm, evaluateSuccessorInputMeters } from "../src/chain/vm-verifier.ts";
import { compactLayerKernelAsm, FRI_LEFTOVER_BYTES } from "../src/chain/fri-kernel.ts";
import { compileFoldKernel, foldKernelAsm, FOLD_QUERIES_PER_KERNEL } from "../src/chain/fold-kernel.ts";
import { RELAY_STANDARD_TX_BYTES } from "../src/chain/envelope.ts";

const CHIPNET = {
  successor: "60d186ded18897a50d0a4205ed446ab02339a53eb6d8f4a7043b4e405796edc4",
  txBytes: 99043,
  inputs: 18,
  outputs: 2,
  broadcastPath: "electrum",
  explorer:
    "https://chipnet.imaginary.cash/tx/60d186ded18897a50d0a4205ed446ab02339a53eb6d8f4a7043b4e405796edc4",
  not: [
    "58b7df7f… parent M31 freeze (FRI9, leftover-pairs empty)",
    "62ba0d9a… pre-leftover-bind QM31 land",
    "named end (RULES §6 / §7 still open)",
  ],
};

function sha256Hex(buf: Uint8Array | string): string {
  return createHash("sha256").update(buf).digest("hex");
}

function dummy22Prefix(u: Uint8Array): number {
  if (u.length < 2) return 0;
  const op = u[0]!;
  let n = 0;
  let off = 1;
  if (op > 0 && op <= 75) n = op;
  else if (op === 0x4c && u.length >= 2) {
    n = u[1]!;
    off = 2;
  } else if (op === 0x4d && u.length >= 3) {
    n = u[1]! | (u[2]! << 8);
    off = 3;
  } else return 0;
  if (n < 1 || off + n > u.length) return 0;
  const body = u.subarray(off, off + n);
  return body.every((b) => b === 0x22) ? n : 0;
}

function txidOfRaw(raw: Uint8Array): string {
  const h = hash256(raw);
  return Buffer.from(h).reverse().toString("hex");
}

const rulesBytes = readFileSync("RULES.md");
const rulesSha = sha256Hex(rulesBytes);
if (rulesSha !== RULES_SHA256) {
  throw new Error(`RULES.md sha256 ${rulesSha} != params RULES_SHA256 ${RULES_SHA256}`);
}
if (!VK_ID.endsWith(RULES_SHA256) || !VK_ID.includes("qm31") || !VK_ID.includes(`fri${FRI_VERSION}`)) {
  throw new Error(`VK_ID ${VK_ID} does not pin full RULES sha256 / qm31 / fri${FRI_VERSION}`);
}
if (FRI_VERSION !== 10) throw new Error(`expected FRI_VERSION 10, got ${FRI_VERSION}`);

const walker = compactLayerKernelAsm(6);
const foldAsm = foldKernelAsm(FOLD_QUERIES_PER_KERNEL, 0);
const foldBin = compileFoldKernel(FOLD_QUERIES_PER_KERNEL, 0);
const encoding = {
  leftoverBound: foldAsm.includes("OP_EQUALVERIFY") && foldAsm.includes("OP_9 OP_PICK"),
  leftoverBytes: FRI_LEFTOVER_BYTES,
  pickBounded: walker.includes("OP_GREATERTHANOREQUAL") && walker.includes("OP_LESSTHAN"),
  foldVkPinsRulesSha: Buffer.from(foldBin).includes(Buffer.from(RULES_SHA256, "hex")),
  dummyPad: false,
};

const mix = runMixSuccessor({ depositCount: 6, withdrawSats: 1_000n });
const proof = mix.proof;
const v = verifyFri(mix.statement, decodeFriProof(proof));
const pool = {
  tx_hash: "11".repeat(32),
  tx_pos: 0,
  value: utxoValueFor(mix.oldState),
  category: new Uint8Array(32).fill(0x11),
  commitment: encodePublicPaa1(mix.oldState),
};
const B = compileCovenantSuccessor({
  wallet: createLabWallet(),
  pool,
  newState: mix.newState,
  proof,
  statement: mix.statement,
  lockKind: "p2sh32",
  envelope: "consensus",
  slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
  note: mix.spent.note,
  change: mix.witness.created?.note,
});
const tx = decodeTransaction(B.raw);
if (typeof tx === "string") throw new Error(tx);
const unlocking = tx.inputs.map((i, n) => ({ i: n, unlocking: i.unlockingBytecode.length }));
const padSum = tx.inputs.reduce((n, i) => n + dummy22Prefix(i.unlockingBytecode), 0);
const maxUnlocking = Math.max(...unlocking.map((r) => r.unlocking));
const std = evaluatePoolSuccessorVm({
  oldState: mix.oldState,
  newState: mix.newState,
  proof,
  statement: mix.statement,
  slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
  standard: true,
  note: mix.spent.note,
  change: mix.witness.created?.note,
});
const meters = evaluateSuccessorInputMeters({
  oldState: mix.oldState,
  newState: mix.newState,
  proof,
  statement: mix.statement,
  slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
  standard: true,
  note: mix.spent.note,
  change: mix.witness.created?.note,
});

const chipnetHexPath = ".local/chipnet-qm31/successor-consensus.hex";
let chipnetHex: string | null = existsSync(chipnetHexPath)
  ? readFileSync(chipnetHexPath, "utf8").trim()
  : null;
if (chipnetHex?.startsWith("0x")) chipnetHex = chipnetHex.slice(2);
let chipnetRaw: Uint8Array | null = null;
let chipnetTxid: string | null = null;
if (chipnetHex) {
  const raw = hexToBin(chipnetHex);
  if (typeof raw === "string") throw new Error(raw);
  chipnetRaw = raw;
  chipnetTxid = txidOfRaw(raw);
  if (chipnetTxid !== CHIPNET.successor) {
    throw new Error(`chipnet hex txid ${chipnetTxid} != ${CHIPNET.successor}`);
  }
  if (raw.length !== CHIPNET.txBytes) {
    throw new Error(`chipnet hex ${raw.length} B != ${CHIPNET.txBytes}`);
  }
}

const worksheet = soundnessWorksheet();
const dir = join("survey/artifacts", "qm31-fri10");
mkdirSync(dir, { recursive: true });
writeFileSync(join(dir, "tx.hex"), `${binToHex(B.raw)}\n`);
writeFileSync(join(dir, "proof.bin"), proof);
copyFileSync("ARGUMENT.md", join(dir, "ARGUMENT.md"));
copyFileSync("RULES.md", join(dir, "RULES.md"));
writeFileSync(join(dir, "vk.txt"), `${VK_ID}\n`);
if (chipnetRaw) writeFileSync(join(dir, "chipnet-successor.hex"), `${binToHex(chipnetRaw)}\n`);

writeFileSync(
  join(dir, "inputs.json"),
  `${JSON.stringify({ txBytes: B.txBytes, inputs: unlocking }, null, 2)}\n`,
);
writeFileSync(
  join(dir, "meters.json"),
  `${JSON.stringify(
    {
      mark: "qm31-fri10",
      labSuccessor: {
        txBytes: B.txBytes,
        standardTxAccepted: meters.standardTxAccepted,
        standardTxError: meters.standardTxError,
        verifyFri: v.ok,
        friVersion: FRI_VERSION,
        queries: FRI_QUERIES,
        hash: DEFAULT_INTERNAL_HASH_ID,
        padSum,
        inputs: meters.inputs,
      },
    },
    null,
    2,
  )}\n`,
);

const argument = readFileSync("ARGUMENT.md", "utf8");
writeFileSync(
  join(dir, "meta.json"),
  `${JSON.stringify(
    {
      mark: "qm31-fri10",
      vkId: VK_ID,
      rulesSha256: RULES_SHA256,
      rulesSha256OfPackedRules: sha256Hex(readFileSync(join(dir, "RULES.md"))),
      occupancy: {
        baseField: "M31",
        secureField: "QM31",
        hash: "SHA-256",
        qTableLayer0Bytes: 4,
        laterPairBytes: 16,
        fieldBits: SECURE_FIELD_BIT_LENGTH,
      },
      txBytes: B.txBytes,
      txid: B.txid,
      inputs: tx.inputs.length,
      outputs: tx.outputs.length,
      maxUnlocking,
      unlockingSum: unlocking.reduce((n, r) => n + r.unlocking, 0),
      padSum,
      leftoverBytes: FRI_LEFTOVER_BYTES,
      standardLimit: RELAY_STANDARD_TX_BYTES,
      standardAccepted: std.accepted,
      standardError: std.error,
      verifyFri: v,
      encoding,
      worksheet,
      chipnet: { ...CHIPNET, packedHex: Boolean(chipnetRaw), packedTxid: chipnetTxid },
      completeness: {
        friVersion: FRI_VERSION,
        uniqueOrbits: FRI_QUERIES,
        grind: GRIND_BITS,
        trace: TRACE_LEN,
        blowup: BLOWUP,
        sha256: DEFAULT_INTERNAL_HASH_ID,
        worksheetBits: CONJECTURAL_BITS,
        fieldBits: SECURE_FIELD_BIT_LENGTH,
        dummyPad: padSum !== 0,
        leftoverBound: encoding.leftoverBound,
        pickBounded: encoding.pickBounded,
        argumentSha256Prefix: argument.slice(0, 120),
      },
      doesNotClaim: [
        "named end",
        "RULES §6 shielded unlocking",
        "RULES §7 walk-in batch",
        "parent freeze circle-fri-m31-t64-b16-q36-g20-fri9",
        "Stwo-128 (query 128 is speculative)",
      ],
    },
    null,
    2,
  )}\n`,
);

writeFileSync(
  join(dir, "README.md"),
  `# ${VK_ID}

Lab compile **${B.txBytes} B**. Chipnet Electrum land **${CHIPNET.txBytes} B** \`${CHIPNET.successor}\`.

FRI${FRI_VERSION}, q=${FRI_QUERIES}, grind ${GRIND_BITS}, TRACE ${TRACE_LEN}, blowup ${BLOWUP}, hash ${DEFAULT_INTERNAL_HASH_ID}.
Occupancy: B = M31 (qTable / layer-0 4-byte), F_fri = QM31 (~${SECURE_FIELD_BIT_LENGTH} bits), H = SHA-256.
Query worksheet ${CONJECTURAL_BITS} (speculative, rate 2/B). Field ${SECURE_FIELD_BIT_LENGTH}. min ≈ ${worksheet.minBits}.

Encoding: leftover **bound** (${FRI_LEFTOVER_BYTES} B, layers 0–6); fold EQUALVERIFYs pairShard against Merkle leftover; compact-path PICK bounded. padSum ${padSum}. Not leftover-fill. Not the parent freeze (leftover-pairs empty, FRI9, M31).

This directory is self-contained: \`tx.hex\` (lab rebuild), \`chipnet-successor.hex\` (mined object), \`proof.bin\`, \`ARGUMENT.md\` (the vk), \`RULES.md\` (vk includes its SHA-256), \`vk.txt\`, \`meta.json\`, \`inputs.json\`, \`meters.json\`.

Chipnet: ${CHIPNET.explorer}

standard=true: ${std.accepted} (${std.error ?? "ok"})
verifyFri: ${JSON.stringify(v)}
leftoverBound: ${encoding.leftoverBound}
pickBounded: ${encoding.pickBounded}
foldVkPinsRulesSha: ${encoding.foldVkPinsRulesSha}

**Not the named end.** RULES §6 (rho/owner/amount not in unlocking) and §7 (walk-in N-note batch) are not this object. Only the human declares that end.

Recompile/verify from the lane (needs the rest of the tree to *rebuild*; the pack itself is the saved instance):

\`\`\`bash
cd research-lanes/ideal-bch-shielded-pool-stark
npx tsx --test test/qm31-artifact.test.ts test/qm31-occupancy.test.ts
npx tsx scripts/save-qm31-artifact.ts
\`\`\`
`,
);

if (
  B.txBytes > RELAY_STANDARD_TX_BYTES ||
  maxUnlocking > 10_000 ||
  !std.accepted ||
  !v.ok ||
  !encoding.leftoverBound ||
  !encoding.pickBounded ||
  !encoding.foldVkPinsRulesSha ||
  padSum !== 0 ||
  FRI_VERSION !== 10
) {
  throw new Error(
    `qm31 pack failed: tx=${B.txBytes} maxUnlock=${maxUnlocking} std=${std.accepted} fri=${JSON.stringify(v)} enc=${JSON.stringify(encoding)} padSum=${padSum}`,
  );
}

console.log(
  JSON.stringify(
    {
      dir,
      vkId: VK_ID,
      txBytes: B.txBytes,
      inputs: tx.inputs.length,
      padSum,
      leftoverBytes: FRI_LEFTOVER_BYTES,
      standardAccepted: std.accepted,
      verifyFri: v,
      encoding,
      chipnet: CHIPNET.successor,
      packedChipnetHex: Boolean(chipnetRaw),
    },
    null,
    2,
  ),
);

/**
 * Week-0 survey of envelope B. Compile and measure only. Does not change kernels.
 *
 * Usage: npx tsx scripts/survey-week.ts [out-dir]
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import {
  createVirtualMachineBch2026,
  decodeAuthenticationInstructions,
  decodeTransaction,
} from "@bitauth/libauth";
import { applyDeposit, applyWithdraw } from "../src/pool/transition.ts";
import { IncrementalMerkle, NullifierSet, type Note } from "../src/pool/notes.ts";
import { emptyState, encodePublicPaa1, utxoValueFor } from "../src/pool/state.ts";
import { LAB_PAYOUT_DIGEST } from "../src/chain/payout.ts";
import { encodeFriProof, proveFri, wWithdraw } from "../src/backends/circle/fri.ts";
import { FRI_QUERIES, FRI_VERSION, CONJECTURAL_BITS } from "../src/backends/circle/params.ts";
import { compileCovenantSuccessor } from "../src/chain/covenant-spend.ts";
import { createLabWallet } from "../src/chain/wallet.ts";
import {
  CONSENSUS_TX_BYTES,
  KERNEL_UNLOCK_PAD_HIGH,
  RELAY_STANDARD_TX_BYTES,
  UNLOCKING_MAX_BYTES,
} from "../src/chain/envelope.ts";
import { buildPoolSuccessorTx, evaluatePoolSuccessorVm } from "../src/chain/vm-verifier.ts";
import {
  compileSlotsLockP2sh32,
  compileSlotsKernel,
  SLOT_KERNEL_COUNT,
  SLOT_KERNEL_COUNT_CONSENSUS,
  slotsKernelUnlocking,
} from "../src/chain/air-cqz.ts";
import { compileFoldKernel, compileFoldLockP2sh32, foldKernelUnlocking } from "../src/chain/fold-kernel.ts";
import { FRI_KERNEL_INPUTS } from "../src/chain/fri-kernel.ts";
import { includeNoteAuth } from "../src/chain/note-auth-kernel.ts";

const outDir = process.argv[2] ?? join(process.cwd(), "survey");
mkdirSync(outDir, { recursive: true });

function isPush(ix: { data?: Uint8Array }): ix is { data: Uint8Array; opcode: number } {
  return ix.data instanceof Uint8Array;
}

function allFilled(data: Uint8Array, v: number): boolean {
  if (data.length === 0) return false;
  for (const b of data) if (b !== v) return false;
  return true;
}

function encodedPushLength(payload: Uint8Array): number {
  if (payload.length <= 75) return 1 + payload.length;
  if (payload.length <= 255) return 2 + payload.length;
  return 3 + payload.length;
}

function splitUnlocking(unlocking: Uint8Array): {
  padBytes: number;
  redeemBytes: number;
  otherBytes: number;
  unlockingBytes: number;
} {
  const decoded = decodeAuthenticationInstructions(unlocking);
  const pushes = decoded.filter(isPush);
  const last = pushes.at(-1);
  const first = pushes[0];
  const redeemBytes = last ? last.data.length : 0;
  const redeemEncoded = last ? encodedPushLength(last.data) : 0;
  const padded = Boolean(first && first !== last && allFilled(first.data, 0x22) && first.data.length > 1);
  const padBytes = padded ? encodedPushLength(first!.data) : 0;
  return {
    padBytes,
    redeemBytes,
    otherBytes: unlocking.length - padBytes - redeemEncoded,
    unlockingBytes: unlocking.length,
  };
}

type Family =
  | "pool"
  | "fri-merkle"
  | "bind-T"
  | "grind"
  | "algebraicC"
  | "note-auth"
  | "fold"
  | "r-slot"
  | "other";

function labelInput(i: number, inputCount: number): { family: Family; indexInFamily: number } {
  const friN = FRI_KERNEL_INPUTS;
  const extras = 4; // cqz, grind, algebraicC, note-auth on B
  if (i === 0) return { family: "pool", indexInFamily: 0 };
  if (i >= 1 && i <= friN) return { family: "fri-merkle", indexInFamily: i - 1 };
  const extra0 = 1 + friN;
  if (i === extra0) return { family: "bind-T", indexInFamily: 0 };
  if (i === extra0 + 1) return { family: "grind", indexInFamily: 0 };
  if (i === extra0 + 2) return { family: "algebraicC", indexInFamily: 0 };
  if (i === extra0 + 3) return { family: "note-auth", indexInFamily: 0 };
  const fold0 = extra0 + extras;
  const foldN = FRI_QUERIES;
  if (i >= fold0 && i < fold0 + foldN) return { family: "fold", indexInFamily: i - fold0 };
  const slot0 = fold0 + foldN;
  if (i >= slot0 && i < slot0 + FRI_QUERIES) return { family: "r-slot", indexInFamily: i - slot0 };
  return { family: "other", indexInFamily: i };
}

function mix() {
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
  const proof = encodeFriProof(proveFri(w.statement, wWithdraw(note, d.index, w.path, w.created)));
  return { w, proof, note, change: w.created?.note };
}

function num(v: unknown): number {
  if (typeof v === "bigint") return Number(v);
  if (typeof v === "number") return v;
  return 0;
}

const t0 = performance.now();
const { w, proof, note, change } = mix();
const proveMs = +(performance.now() - t0).toFixed(2);

const pool = {
  tx_hash: "11".repeat(32),
  tx_pos: 0,
  value: utxoValueFor(w.statement.oldState),
  category: new Uint8Array(32).fill(0x11),
  commitment: encodePublicPaa1(w.statement.oldState),
};

const tCompile = performance.now();
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
  change,
});
const compileMs = +(performance.now() - tCompile).toFixed(2);

const decoded = decodeTransaction(B.raw);
if (typeof decoded === "string") throw new Error(decoded);

const rows = decoded.inputs.map((inp, i) => {
  const split = splitUnlocking(inp.unlockingBytecode);
  const { family, indexInFamily } = labelInput(i, decoded.inputs.length);
  return { i, family, indexInFamily, ...split };
});

const familySums = new Map<string, { count: number; unlocking: number; pad: number; redeem: number; other: number }>();
for (const r of rows) {
  const cur = familySums.get(r.family) ?? { count: 0, unlocking: 0, pad: 0, redeem: 0, other: 0 };
  cur.count += 1;
  cur.unlocking += r.unlockingBytes;
  cur.pad += r.padBytes;
  cur.redeem += r.redeemBytes;
  cur.other += r.otherBytes;
  familySums.set(r.family, cur);
}

const byteSurvey = {
  at: new Date().toISOString(),
  friVersion: FRI_VERSION,
  queries: FRI_QUERIES,
  conjecturalBits: CONJECTURAL_BITS,
  proveMs,
  compileMs,
  txBytes: B.txBytes,
  txid: B.txid,
  inputCount: decoded.inputs.length,
  outputCount: decoded.outputs.length,
  poolUnlockingBytes: B.unlockingBytes,
  standardLimit: RELAY_STANDARD_TX_BYTES,
  consensusLimit: CONSENSUS_TX_BYTES,
  unlockingMax: UNLOCKING_MAX_BYTES,
  padTargetHigh: KERNEL_UNLOCK_PAD_HIGH,
  headroomVs1MB: CONSENSUS_TX_BYTES - B.txBytes,
  overStandard: B.txBytes - RELAY_STANDARD_TX_BYTES,
  families: [...familySums.entries()].map(([family, s]) => ({ family, ...s })),
  inputs: rows,
};

writeFileSync(join(outDir, "b-input-bytes.json"), `${JSON.stringify(byteSurvey, null, 2)}\n`);

function mdTable(headers: string[], body: string[][]): string {
  const head = `| ${headers.join(" | ")} |`;
  const sep = `| ${headers.map(() => "---").join(" | ")} |`;
  return [head, sep, ...body.map((r) => `| ${r.join(" | ")} |`)].join("\n");
}

const familyMd = mdTable(
  ["family", "count", "unlocking Σ", "pad Σ", "redeem payload Σ", "other Σ"],
  byteSurvey.families.map((f) => [
    f.family,
    String(f.count),
    String(f.unlocking),
    String(f.pad),
    String(f.redeem),
    String(f.other),
  ]),
);

const inputMd = mdTable(
  ["i", "family", "k", "unlocking", "pad", "redeem payload", "other"],
  rows.map((r) => [
    String(r.i),
    r.family,
    String(r.indexInFamily),
    String(r.unlockingBytes),
    String(r.padBytes),
    String(r.redeemBytes),
    String(r.otherBytes),
  ]),
);

const bytesMd = `# B successor per-input bytes

Measured ${byteSurvey.at} in this lane. One compiled consensus successor, FRI${FRI_VERSION}, q=${FRI_QUERIES}. Not a Chipnet land. Kernels were not changed.

| | |
|---|---|
| txBytes | **${B.txBytes}** |
| vs standard 100 000 | **${B.txBytes - RELAY_STANDARD_TX_BYTES} over** |
| vs consensus 1 000 000 | ${CONSENSUS_TX_BYTES - B.txBytes} headroom |
| inputs | ${decoded.inputs.length} |
| proveMs | ${proveMs} |
| compileMs | ${compileMs} |
| pad target (high-index) | ${KERNEL_UNLOCK_PAD_HIGH} |

## Family sums

${familyMd}

Pad is the leading \`0x22\` dummy push from \`densityPadUnlocking\`. Redeem payload is the last P2SH32 push (script body, not the push opcode). Other is slot-index / Merkle witness / remaining pushes.

## Every input

${inputMd}
`;
writeFileSync(join(outDir, "b-input-bytes.md"), bytesMd);

const indices = [0, 4, 18, 35] as const;
type Meter = { operationCost: number; maximumOperationCost: number; hashDigestIterations: number; maximumHashDigestIterations: number; densityControlLength: number; accepted: boolean; error: string | null; unlocking: number; redeem: number };

function meterOf(standard: boolean, kind: "fold" | "slot", idx: number): Meter {
  const vm = createVirtualMachineBch2026(standard);
  const unlocking = kind === "fold" ? foldKernelUnlocking(1, idx) : slotsKernelUnlocking(idx);
  const locking = kind === "fold" ? compileFoldLockP2sh32(1, idx) : compileSlotsLockP2sh32(idx);
  const split = splitUnlocking(unlocking);
  const program = {
    inputIndex: 0,
    sourceOutputs: [{ lockingBytecode: locking, valueSatoshis: 1000n }],
    transaction: {
      version: 2,
      locktime: 0,
      inputs: [
        {
          outpointTransactionHash: new Uint8Array(32).fill(0x11),
          outpointIndex: 0,
          sequenceNumber: 0xffffffff,
          unlockingBytecode: unlocking,
        },
      ],
      outputs: [{ lockingBytecode: locking, valueSatoshis: 1000n }],
    },
  };
  const state = vm.evaluate(program as never);
  const ok = vm.stateSuccess(state);
  const m = (state as { metrics?: Record<string, number | bigint> }).metrics ?? {};
  return {
    operationCost: num(m.operationCost),
    maximumOperationCost: num(m.maximumOperationCost),
    hashDigestIterations: num(m.hashDigestIterations),
    maximumHashDigestIterations: num(m.maximumHashDigestIterations),
    densityControlLength: num(m.densityControlLength),
    accepted: ok === true,
    error: ok === true ? null : String(ok),
    unlocking: unlocking.length,
    redeem: split.redeemBytes,
  };
}

const densityRows: Array<{
  kind: "fold" | "slot";
  index: number;
  standard: Meter;
  consensus: Meter;
  isolatedAcceptedNote: string;
}> = [];

for (const kind of ["fold", "slot"] as const) {
  for (const idx of indices) {
    densityRows.push({
      kind,
      index: idx,
      standard: meterOf(true, kind, idx),
      consensus: meterOf(false, kind, idx),
      isolatedAcceptedNote:
        "Isolated one-input program: kernel reads packed AIR / pair blobs from sibling inputs in the real successor, so accepted=false here is expected. Costs still count the ops that ran before the fail, and the **budgets** (max op-cost, max hash-iter, density length) are exact for this unlocking.",
    });
  }
}

const successorArgs = {
  oldState: w.statement.oldState,
  newState: w.statement.newState,
  proof,
  statement: w.statement,
  slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
  note,
  change,
};
const built = buildPoolSuccessorTx({ ...successorArgs, standard: false });
const fold0Input = 1 + FRI_KERNEL_INPUTS + 4;
const slot0Input = fold0Input + FRI_QUERIES;

function inContextMeter(standard: boolean, inputIndex: number): Meter {
  const vm = createVirtualMachineBch2026(standard);
  const unlocking = built.transaction.inputs[inputIndex]!.unlockingBytecode;
  const split = splitUnlocking(unlocking);
  const state = vm.evaluate({
    inputIndex,
    sourceOutputs: built.sourceOutputs,
    transaction: built.transaction,
  } as never);
  const ok = vm.stateSuccess(state);
  const m = (state as { metrics?: Record<string, number | bigint> }).metrics ?? {};
  return {
    operationCost: num(m.operationCost),
    maximumOperationCost: num(m.maximumOperationCost),
    hashDigestIterations: num(m.hashDigestIterations),
    maximumHashDigestIterations: num(m.maximumHashDigestIterations),
    densityControlLength: num(m.densityControlLength),
    accepted: ok === true,
    error: ok === true ? null : String(ok),
    unlocking: unlocking.length,
    redeem: split.redeemBytes,
  };
}

const inContext = indices.flatMap((idx) =>
  (["fold", "slot"] as const).map((kind) => ({
    kind,
    index: idx,
    inputIndex: kind === "fold" ? fold0Input + idx : slot0Input + idx,
    standard: inContextMeter(true, kind === "fold" ? fold0Input + idx : slot0Input + idx),
    consensus: inContextMeter(false, kind === "fold" ? fold0Input + idx : slot0Input + idx),
  })),
);

const tVm = performance.now();
const fullStd = evaluatePoolSuccessorVm({ ...successorArgs, standard: true });
const fullCons = evaluatePoolSuccessorVm({ ...successorArgs, standard: false });
const vmMs = +(performance.now() - tVm).toFixed(2);

const densitySurvey = {
  at: byteSurvey.at,
  slotKernelCount: SLOT_KERNEL_COUNT,
  consensusSlots: SLOT_KERNEL_COUNT_CONSENSUS,
  includeNoteAuth: includeNoteAuth(SLOT_KERNEL_COUNT_CONSENSUS),
  redeemSizes: {
    fold0: compileFoldKernel(1, 0).length,
    fold35: compileFoldKernel(1, 35).length,
    slot0: compileSlotsKernel(0).length,
    slot35: compileSlotsKernel(35).length,
  },
  isolated: densityRows,
  inContext,
  fullSuccessor: {
    vmMs,
    standardAccepted: fullStd.accepted,
    standardError: fullStd.error,
    consensusAccepted: fullCons.accepted,
    consensusError: fullCons.error,
  },
};

writeFileSync(join(outDir, "density-law.json"), `${JSON.stringify(densitySurvey, null, 2)}\n`);

const densMd = mdTable(
  [
    "kernel",
    "idx",
    "unlocking",
    "redeem",
    "std opCost",
    "std opMax",
    "std hashIter",
    "std hashMax",
    "nonstd opCost",
    "nonstd opMax",
    "nonstd hashIter",
    "nonstd hashMax",
  ],
  densityRows.map((r) => [
    r.kind,
    String(r.index),
    String(r.standard.unlocking),
    String(r.standard.redeem),
    String(r.standard.operationCost),
    String(r.standard.maximumOperationCost),
    String(r.standard.hashDigestIterations),
    String(r.standard.maximumHashDigestIterations),
    String(r.consensus.operationCost),
    String(r.consensus.maximumOperationCost),
    String(r.consensus.hashDigestIterations),
    String(r.consensus.maximumHashDigestIterations),
  ]),
);

const densityMd = `# Density law (fold / R-slot at 0, 4, 18, 35)

Same compiled unlocking as B. Two meters: \`createVirtualMachineBch2026(true)\` = **standard** (0.5 hash-iter/byte, 192 cost/iter) and \`(false)\` = **consensus/nonstandard** (3.5 iter/byte, 64 cost/iter). Op-cost budget is always \`800 × (41 + unlocking)\`.

Isolated one-input evaluation **does not** have sibling packed-AIR / FRI pair-blob inputs, so \`accepted\` is not the B-successor bar. **Budgets** (opMax, hashMax, densityControlLength) are exact. \`operationCost\` / \`hashDigestIterations\` are ops that ran before the script failed on missing context — a lower bound on a full honest run, not the honest total.

Full B successor on this proof:

| meter | accepted | error |
|---|---|---|
| standard=true | ${fullStd.accepted} | ${fullStd.error ?? ""} |
| standard=false | ${fullCons.accepted} | ${fullCons.error ?? ""} |

vmMs (both full verifies) = ${vmMs}

## Isolated (budgets exact; opCost is a fail-path lower bound)

${densMd}

## In the real B successor (this is the density law)

${mdTable(
  [
    "kernel",
    "idx",
    "input",
    "accepted std",
    "accepted nonstd",
    "unlocking",
    "std opCost/max",
    "std hashIter/max",
    "nonstd opCost/max",
    "nonstd hashIter/max",
  ],
  inContext.map((r) => [
    r.kind,
    String(r.index),
    String(r.inputIndex),
    String(r.standard.accepted),
    String(r.consensus.accepted),
    String(r.standard.unlocking),
    `${r.standard.operationCost}/${r.standard.maximumOperationCost}`,
    `${r.standard.hashDigestIterations}/${r.standard.maximumHashDigestIterations}`,
    `${r.consensus.operationCost}/${r.consensus.maximumOperationCost}`,
    `${r.consensus.hashDigestIterations}/${r.consensus.maximumHashDigestIterations}`,
  ]),
)}


Redeem sizes: fold0=${densitySurvey.redeemSizes.fold0} fold35=${densitySurvey.redeemSizes.fold35} slot0=${densitySurvey.redeemSizes.slot0} slot35=${densitySurvey.redeemSizes.slot35}.
`;
writeFileSync(join(outDir, "density-law.md"), densityMd);

process.stdout.write(
  JSON.stringify(
    {
      outDir,
      txBytes: B.txBytes,
      inputs: decoded.inputs.length,
      families: byteSurvey.families,
      fullSuccessor: densitySurvey.fullSuccessor,
    },
    null,
    2,
  ) + "\n",
);

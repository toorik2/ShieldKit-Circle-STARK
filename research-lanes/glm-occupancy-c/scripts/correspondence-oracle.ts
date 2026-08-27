/**
 * Lab oracle: JS verifyFri and CashVM standard=true on the same proof.
 * P0: mutated proof, verifyFri rejects, VM accepts.
 * Chain-stricter (honest proof, cooked unlocking, VM rejects) is allowed.
 */
import { applyDeposit, applyWithdraw } from "../src/pool/transition.ts";
import { IncrementalMerkle, NullifierSet, type Note } from "../src/pool/notes.ts";
import { emptyState } from "../src/pool/state.ts";
import {
  decodeFriProof,
  encodeFriProof,
  mutateTraceAndProve,
  proveFri,
  verifyFri,
  wWithdraw,
} from "../src/backends/circle/fri.ts";
import { LAB_PAYOUT_DIGEST } from "../src/chain/payout.ts";
import { SLOT_KERNEL_COUNT_CONSENSUS } from "../src/chain/air-cqz.ts";
import {
  evaluatePoolSuccessorVm,
  evaluateSuccessorInputMeters,
} from "../src/chain/vm-verifier.ts";
import { collectFriOpenings } from "../src/chain/fri-openings.ts";
import { buildLayerProofs, encodeLayerUnlocking } from "../src/chain/merkle-multiproof.ts";
import { compileFriQueryKernel } from "../src/chain/fri-kernel.ts";
import { FRI_QUERIES, FRI_VERSION, VK_ID } from "../src/backends/circle/params.ts";

export type OracleRow = {
  name: string;
  js: boolean;
  vm: boolean;
  p0: boolean;
  error: string | null;
};

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
  const wit = wWithdraw(note, d.index, w.path, w.created);
  const proved = proveFri(w.statement, wit);
  const proof = encodeFriProof(proved);
  return { w, proof, note, change: w.created?.note, wit, proved };
}

function baseOf(m: ReturnType<typeof mix>) {
  return {
    oldState: m.w.statement.oldState,
    newState: m.w.statement.newState,
    proof: m.proof,
    statement: m.w.statement,
    slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
    standard: true as const,
    note: m.note,
    change: m.change,
  };
}

export function runCorrespondenceOracle(): {
  vk: string;
  friVersion: number;
  queries: number;
  rows: OracleRow[];
  p0: OracleRow[];
} {
  const m = mix();
  const base = baseOf(m);
  const rows: OracleRow[] = [];

  const jsH = verifyFri(m.w.statement, m.proved);
  const vmH = evaluatePoolSuccessorVm(base);
  const meters = evaluateSuccessorInputMeters(base);
  rows.push({
    name: "honest B",
    js: jsH.ok,
    vm: vmH.accepted && meters.standardTxAccepted && meters.inputs.every((i) => i.accepted),
    p0: vmH.accepted && !jsH.ok,
    error: vmH.error,
  });

  const bad = mutateTraceAndProve(m.w.statement, 0, m.wit);
  const jsB = verifyFri(m.w.statement, bad, m.wit);
  const vmB = evaluatePoolSuccessorVm({ ...base, proof: encodeFriProof(bad) });
  rows.push({
    name: "mutated trace proof",
    js: jsB.ok,
    vm: vmB.accepted,
    p0: vmB.accepted && !jsB.ok,
    error: vmB.error,
  });

  const proofs = buildLayerProofs(collectFriOpenings(m.proof));
  const omit = proofs.map((p) =>
    encodeLayerUnlocking(
      { ...p, openings: [p.openings[p.openings.length - 1]!] },
      compileFriQueryKernel(p.layer),
    ),
  );
  const jsO = verifyFri(m.w.statement, decodeFriProof(m.proof));
  const vmO = evaluatePoolSuccessorVm({ ...base, kernelUnlockings: omit });
  rows.push({
    name: "honest proof, omit Merkle openings (chain must be stricter)",
    js: jsO.ok,
    vm: vmO.accepted,
    p0: vmO.accepted && !jsO.ok,
    error: vmO.error,
  });

  return {
    vk: VK_ID,
    friVersion: FRI_VERSION,
    queries: FRI_QUERIES,
    rows,
    p0: rows.filter((r) => r.p0),
  };
}

if (process.argv[1]?.endsWith("scripts/correspondence-oracle.ts")) {
  const out = runCorrespondenceOracle();
  console.log(JSON.stringify(out, null, 2));
  if (out.p0.length || !out.rows[0]!.js || !out.rows[0]!.vm || out.rows[1]!.js || out.rows[1]!.vm || out.rows[2]!.vm) {
    process.exitCode = 1;
  }
}

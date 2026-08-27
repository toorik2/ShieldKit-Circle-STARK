import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { circleFriPlugin } from "../src/backends/circle/plugin.ts";
import {
  decodeFriProof,
  encodeFriProof,
  mutateTraceAndProve,
  proveFri,
  proveFromTLde,
  publicEvals,
  verifyFri,
  wDeposit,
  wWithdraw,
  circleDomain,
} from "../src/backends/circle/fri.ts";
import { TRACE_LEN } from "../src/backends/circle/params.ts";
import { applyDeposit, applyWithdraw } from "../src/pool/transition.ts";
import { IncrementalMerkle, NullifierSet, commitNote, type Note } from "../src/pool/notes.ts";
import { concatBytes, sha256 } from "../src/pool/bytes.ts";
import { emptyState } from "../src/pool/state.ts";
import { encodeAirPacked } from "../src/chain/air-cqz.ts";
import {
  evaluateDigestOnlyPool,
  evaluateDummyKernels,
  evaluateDummyConsistent,
  evaluateDummyNoL0,
  evaluateDummyShortPath,
  evaluateCrossPacked,
  evaluateDummyUnbound,
  evaluateCookedLaterSlot,
  evaluateCookedNTable,
  evaluateCookedT,
  evaluateSwappedDummyKernels,
  evaluateMissingProofPool,
  evaluateOnChainVerify,
  evaluatePoolSuccessorVm,
  proofFitsEnvelope,
} from "../src/chain/vm-verifier.ts";

const scratch = process.argv[2];
if (!scratch) throw new Error("usage: capture-goal <scratch-dir>");

function rnd32(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}

function freshDeposit() {
  const note: Note = { amountSats: 12_000n, rho: rnd32(), ownerSecret: rnd32() };
  const d = applyDeposit(
    { state: emptyState(rnd32()), notes: new IncrementalMerkle(), nullifiers: new NullifierSet() },
    note,
  );
  return { note, d };
}

const { note, d } = freshDeposit();
const depProof = await circleFriPlugin.prove(d.statement, wDeposit(note, d.index, d.path));
const depV = circleFriPlugin.verify(d.statement, depProof);

const w = applyWithdraw(d.machine, note, d.index, rnd32(), 3_000n);
const wit = wWithdraw(note, d.index, w.path, w.created);
const raw = encodeFriProof(proveFri(w.statement, wit));
const hon = circleFriPlugin.verify(w.statement, raw);

const fakeNf = { ...w.statement, nullifier: rnd32() };
let proveFake = "threw";
try {
  proveFri(fakeNf, wit);
  proveFake = "accepted (BUG)";
} catch (e) {
  proveFake = e instanceof Error ? e.message : String(e);
}
const forced = proveFromTLde(fakeNf, publicEvals(fakeNf, circleDomain(TRACE_LEN), circleDomain()), {
  leaf: commitNote(note),
  index: d.index,
  path: w.path,
  root: fakeNf.oldState.noteRoot,
  nullifier: fakeNf.nullifier,
  rho: note.rho,
  owner: note.ownerSecret,
  amountSats: note.amountSats,
  publicDeltaSats: 3_000n,
  amountCommit: new Uint8Array(32),
  createdLeaf: new Uint8Array(32),
  createdIndex: 0,
  createdPath: [],
}, { occupancyOnly: true });
const forcedV = circleFriPlugin.verify(fakeNf, encodeFriProof(forced));
const forcedFri = verifyFri(fakeNf, forced);

const tampered = {
  ...d.statement,
  newState: { ...d.statement.newState, reserveSats: d.statement.newState.reserveSats + 1n },
};
const tamperV = circleFriPlugin.verify(tampered, depProof);

const mutated = mutateTraceAndProve(d.statement, 0, wDeposit(note, d.index, d.path));
const mutV = verifyFri(d.statement, mutated);

const proveLog = {
  path: "circleFriPlugin.prove / circleFriPlugin.verify / verifyFri (no witness)",
  honestDeposit: { ok: depV.ok, proofBytes: depProof.length },
  honestWithdraw: { ok: hon.ok, proofBytes: raw.length },
  fakeNullifierProve: proveFake,
  fakeNullifierPluginVerify: forcedV,
  fakeNullifierVerifyFriNoWitness: forcedFri,
  tamperedReserveVerify: tamperV,
  mutatedQuotientVerify: mutV,
};
writeFileSync(join(scratch, "prove-verify.log"), `${JSON.stringify(proveLog, null, 2)}\n`);

const mixOn = evaluateOnChainVerify(w.statement, raw);
const digest = evaluateDigestOnlyPool(w.statement.oldState);
const missing = evaluateMissingProofPool(w.statement.oldState);
const rewritten = evaluatePoolSuccessorVm({
  oldState: w.statement.oldState,
  newState: { ...w.statement.newState, noteRoot: rnd32() },
  proof: raw,
});
const drain = evaluatePoolSuccessorVm({
  oldState: w.statement.oldState,
  newState: w.statement.newState,
  proof: raw,
  outputValueSats: 0n,
});
const seq99 = evaluatePoolSuccessorVm({
  oldState: w.statement.oldState,
  newState: { ...w.statement.newState, sequence: 99n },
  proof: raw,
});
const fakeLeaf = rnd32();
const fakeStmt = { ...w.statement, noteCommitment: fakeLeaf };
const forcedMem = proveFromTLde(fakeStmt, publicEvals(fakeStmt, circleDomain(TRACE_LEN), circleDomain()), {
  leaf: fakeLeaf,
  index: d.index,
  path: w.path,
  root: fakeStmt.oldState.noteRoot,
  nullifier: w.statement.nullifier,
  rho: note.rho,
  owner: note.ownerSecret,
  amountSats: note.amountSats,
  publicDeltaSats: 3_000n,
  amountCommit: new Uint8Array(32),
  createdLeaf: fakeLeaf,
  createdIndex: w.created?.index ?? 0,
  createdPath: w.created?.path ?? [],
}, { occupancyOnly: true });
const fakeMem = evaluatePoolSuccessorVm({
  oldState: w.statement.oldState,
  newState: w.statement.newState,
  proof: encodeFriProof(forcedMem),
});
const fakeNfOnchain = rnd32();
const decoded = decodeFriProof(raw);
const fakeNfProof = encodeFriProof({
  ...decoded,
  auth: { ...decoded.auth, nullifier: fakeNfOnchain },
});
const fakeNfVm = evaluatePoolSuccessorVm({
  oldState: w.statement.oldState,
  newState: {
    ...w.statement.newState,
    nullifierRoot: sha256(concatBytes(w.statement.oldState.nullifierRoot, fakeNfOnchain)),
  },
  proof: fakeNfProof,
});
const dummyShortPath = evaluateDummyShortPath({
  oldState: w.statement.oldState,
  newState: w.statement.newState,
  proof: raw,
  statement: w.statement,
});
const otherDep = freshDeposit();
const otherPacked = encodeAirPacked(
  otherDep.d.statement,
  encodeFriProof(proveFri(otherDep.d.statement, wDeposit(otherDep.note, otherDep.d.index, otherDep.d.path))),
);
const crossPacked = evaluateCrossPacked({
  oldState: w.statement.oldState,
  newState: w.statement.newState,
  proof: raw,
  statement: w.statement,
  otherPacked,
});
const dummyNoL0 = evaluateDummyNoL0({
  oldState: w.statement.oldState,
  newState: w.statement.newState,
  proof: raw,
  statement: w.statement,
});
const dummyUnbound = evaluateDummyUnbound({
  oldState: w.statement.oldState,
  newState: w.statement.newState,
  proof: raw,
  statement: w.statement,
});
const dummyConsistent = evaluateDummyConsistent({
  oldState: w.statement.oldState,
  newState: w.statement.newState,
  proof: raw,
  statement: w.statement,
});
const dummyKernels = evaluateDummyKernels({
  oldState: w.statement.oldState,
  newState: w.statement.newState,
  proof: raw,
  statement: w.statement,
});
const swappedDummy = evaluateSwappedDummyKernels({
  oldState: w.statement.oldState,
  newState: w.statement.newState,
  proof: raw,
  statement: w.statement,
});
const cookedNTable = evaluateCookedNTable({
  oldState: w.statement.oldState,
  newState: w.statement.newState,
  proof: raw,
  statement: w.statement,
});
const cookedT = evaluateCookedT({
  oldState: w.statement.oldState,
  newState: w.statement.newState,
  proof: raw,
  statement: w.statement,
});
const cookedLater = evaluateCookedLaterSlot({
  oldState: w.statement.oldState,
  newState: w.statement.newState,
  proof: raw,
  statement: w.statement,
});
const env = proofFitsEnvelope(raw);
const vmLog = {
  path: "evaluatePoolSuccessorVm only (no JS AND); NFT PAA1 + CashAssembly/libauth 2026 VM; kernels bind packed AIR",
  envelope: env,
  honest: { accepted: mixOn.pool.accepted, pool: mixOn.pool.accepted, stark: mixOn.stark },
  digestOnly: { accepted: digest.accepted, error: digest.error },
  missingProof: { accepted: missing.accepted, error: missing.error },
  rewrittenNoteRoot: { accepted: rewritten.accepted, error: rewritten.error },
  drainReserve: { accepted: drain.accepted, error: drain.error },
  sequence99: { accepted: seq99.accepted, error: seq99.error },
  fakeMembership: { accepted: fakeMem.accepted, error: fakeMem.error },
  fakeNullifier: { accepted: fakeNfVm.accepted, error: fakeNfVm.error },
  dummyShortPath: { accepted: dummyShortPath.accepted, error: dummyShortPath.error },
  crossPacked: { accepted: crossPacked.accepted, error: crossPacked.error },
  dummyNoL0: { accepted: dummyNoL0.accepted, error: dummyNoL0.error },
  dummyUnbound: { accepted: dummyUnbound.accepted, error: dummyUnbound.error },
  dummyConsistent: { accepted: dummyConsistent.accepted, error: dummyConsistent.error },
  dummyKernels: { accepted: dummyKernels.accepted, error: dummyKernels.error },
  swappedDummy: { accepted: swappedDummy.accepted, error: swappedDummy.error },
  cookedNTable: { accepted: cookedNTable.accepted, error: cookedNTable.error },
  cookedT: { accepted: cookedT.accepted, error: cookedT.error },
};
writeFileSync(join(scratch, "vm-onchain.log"), `${JSON.stringify(vmLog, null, 2)}\n`);

const { evaluateProofOnVm } = await import("../src/chain/vm-verifier.ts");
const { soundnessWorksheet } = await import("../src/backends/circle/soundness.ts");
const { mixChangedRootsAndReserve, runMixSuccessor } = await import("../src/pool/mix-successor.ts");
const t0 = performance.now();
const benchProof = await circleFriPlugin.prove(d.statement, wDeposit(note, d.index, d.path));
const t1 = performance.now();
const benchV = circleFriPlugin.verify(d.statement, benchProof);
const t2 = performance.now();
const tVm0 = performance.now();
const benchVm = evaluateProofOnVm(benchProof);
const tVm1 = performance.now();
const benchLog = {
  family: circleFriPlugin.family,
  sound: circleFriPlugin.sound,
  ok: benchV.ok,
  vmAccepted: benchVm.accepted,
  vmQueries: benchVm.queryEvals,
  proofBytes: benchProof.length,
  proveMs: +(t1 - t0).toFixed(2),
  verifyMs: +(t2 - t1).toFixed(2),
  vmMs: +(tVm1 - tVm0).toFixed(2),
  envelope: proofFitsEnvelope(benchProof),
  worksheet: soundnessWorksheet(),
};
writeFileSync(join(scratch, "bench.log"), `${JSON.stringify(benchLog)}\n`);

function e2e(tag: string) {
  const mix = runMixSuccessor({ depositCount: 6, withdrawSats: 1_000n });
  const v = circleFriPlugin.verify(mix.statement, mix.proof);
  if (!v.ok) throw new Error(`${tag} mix proof: ${v.reason}`);
  if (!mixChangedRootsAndReserve(mix)) throw new Error(`${tag} mix did not update roots/reserve`);
  return {
    tag,
    publicBefore: mix.publicBefore,
    publicAfter: mix.publicAfter,
    sound: circleFriPlugin.sound,
    changed: {
      noteRoot: mix.publicBefore.noteRoot !== mix.publicAfter.noteRoot,
      nullifierRoot: mix.publicBefore.nullifierRoot !== mix.publicAfter.nullifierRoot,
      reserve: mix.publicBefore.reserveSats !== mix.publicAfter.reserveSats,
    },
  };
}
const a = e2e("e2e-1");
const b = e2e("e2e-2");
const e2eBody = { a, b, grew: a.publicAfter.anonSet >= 6 && b.publicAfter.anonSet >= 6 };
writeFileSync(join(scratch, "pool-e2e-1.log"), `${JSON.stringify({ a, grew: e2eBody.grew }, null, 2)}\n`);
writeFileSync(join(scratch, "pool-e2e-2.log"), `${JSON.stringify({ b, grew: e2eBody.grew }, null, 2)}\n`);
writeFileSync(join(scratch, "pool-e2e-mix.json"), `${JSON.stringify(e2eBody, null, 2)}\n`);

console.log("wrote prove-verify.log, vm-onchain.log, bench.log, pool-e2e-1/2.log");
console.log(JSON.stringify({ prove: proveLog, vm: vmLog, bench: benchLog, e2e: e2eBody }, null, 2));

import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { cashAssemblyToBin } from "@bitauth/libauth";
import { foldPair } from "../src/backends/circle/fold.ts";
import { addPoints, CIRCLE_GEN, scalarMul } from "../src/backends/circle/group.ts";
import { inv, neg } from "../src/backends/circle/m31.ts";
import { encodeFriProof, proveFri, verifyFri, wDeposit } from "../src/backends/circle/fri.ts";
import { applyDeposit } from "../src/pool/transition.ts";
import { IncrementalMerkle, NullifierSet, type Note } from "../src/pool/notes.ts";
import { emptyState } from "../src/pool/state.ts";
import { concatBytes, sha256 } from "../src/pool/bytes.ts";
import { encodeStatement } from "../src/pool/statement.ts";
import { hashBytesToQm31 } from "../src/backends/circle/qm31.ts";
import { COMMITTED_LAYERS, FRI_N } from "../src/backends/circle/params.ts";
import { encodeAirPacked, G1024, SLOT_KERNEL_COUNT_CONSENSUS } from "../src/chain/air-cqz.ts";
import { compileFoldPairLock, compileM31InvLock, lambdaFromPackedAsm } from "../src/chain/fold-asm.ts";
import { compileFirstQueryPairsLock, compileFoldKernel, FOLD_QUERIES_PER_KERNEL, foldKernelAsm } from "../src/chain/fold-kernel.ts";
import { compileFriQueryKernel } from "../src/chain/fri-kernel.ts";
import { packedWithPairs, friShardUnlockings, queryPairShard } from "../src/chain/fri-openings.ts";
import { pushData } from "../src/chain/covenant-p2s.ts";
import {
  evaluateBch2026,
  evaluateFoldKernelOnly,
  evaluateOnChainVerify,
  evaluatePoolSuccessorVm,
  evaluateWrongFoldIndex,
} from "../src/chain/vm-verifier.ts";

function pushNum(n: bigint): Uint8Array {
  if (n === 0n) return Uint8Array.of(0x00);
  if (n >= 1n && n <= 16n) return Uint8Array.of(0x50 + Number(n));
  const bytes: number[] = [];
  let v = n;
  while (v > 0n) {
    bytes.push(Number(v & 0xffn));
    v >>= 8n;
  }
  if ((bytes[bytes.length - 1]! & 0x80) !== 0) bytes.push(0);
  return pushData(Uint8Array.from(bytes));
}

function deposit() {
  const note: Note = {
    amountSats: 8_000n,
    rho: crypto.getRandomValues(new Uint8Array(32)),
    ownerSecret: crypto.getRandomValues(new Uint8Array(32)),
  };
  const d = applyDeposit(
    { state: emptyState(crypto.getRandomValues(new Uint8Array(32))), notes: new IncrementalMerkle(), nullifiers: new NullifierSet() },
    note,
  );
  return { ...d, note, witness: wDeposit(note, d.index, d.path) };
}

describe("on-chain Circle fold", () => {
  it("M31 inverse matches TypeScript", () => {
    const a = 123456789n;
    const ev = evaluateBch2026(compileM31InvLock(inv(a)), pushNum(a));
    assert.equal(ev.accepted, true, ev.error ?? "inv");
  });

  it("foldPair matches TypeScript", () => {
    const p = scalarMul(CIRCLE_GEN, 11n);
    const fP = 99n;
    const fConj = 17n;
    const lambda = 123n;
    const folded = foldPair(p, fP, fConj, lambda);
    const denom = p.x !== 0n ? p.x : p.y;
    const unlocking = Uint8Array.of(
      ...pushNum(p.x),
      ...pushNum(p.y),
      ...pushNum(fP),
      ...pushNum(fConj),
      ...pushNum(lambda),
      ...pushNum(inv(denom)),
    );
    const ev = evaluateBch2026(compileFoldPairLock(folded.value), unlocking);
    assert.equal(ev.accepted, true, ev.error ?? "foldPair");
  });

  it("lambda from packed matches hashToQm31", () => {
    const d = deposit();
    const proof = proveFri(d.statement, d.witness);
    const packed = encodeAirPacked(d.statement, proof);
    const lambda = hashBytesToQm31(
      sha256(concatBytes(
        sha256(encodeStatement(d.statement)),
        Uint8Array.of(0),
        proof.layerRoots[0]!,
        new TextEncoder().encode("lambda"),
      )),
    );
    const lock = cashAssemblyToBin(`
${lambdaFromPackedAsm()}
<${lambda[3]!.toString()}> OP_EQUALVERIFY
<${lambda[2]!.toString()}> OP_EQUALVERIFY
<${lambda[1]!.toString()}> OP_EQUALVERIFY
<${lambda[0]!.toString()}> OP_NUMEQUAL
`);
    if (typeof lock === "string") throw new Error(lock);
    const ev = evaluateBch2026(lock, Uint8Array.of(...pushData(packed), ...pushNum(0n)));
    assert.equal(ev.accepted, true, ev.error ?? "lambda");
  });

  it("reads the first query pair blob from packed||pairs on input 0", () => {
    const d = deposit();
    const proof = proveFri(d.statement, d.witness);
    const packed = encodeAirPacked(d.statement, proof);
    const carrier = packedWithPairs(packed, proof);
    const ev = evaluateBch2026(compileFirstQueryPairsLock(), pushData(carrier));
    assert.equal(ev.accepted, true, ev.error ?? "first query pairs");
  });

  it("chained layer points match [idx % (N>>r+1)] · 2^r G", () => {
    for (const idx of [0, 1, 17, 88, 255, 256, 400, 511, 512, 600, 1023]) {
      let p = scalarMul(G1024, BigInt(idx % (FRI_N >> 1)));
      for (let r = 0; r < COMMITTED_LAYERS; r += 1) {
        const k = idx % (FRI_N >> (r + 1));
        let naive = scalarMul(G1024, BigInt(k));
        for (let i = 0; i < r; i += 1) naive = addPoints(naive, naive);
        assert.deepEqual(p, naive, `idx ${idx} layer ${r}`);
        if (r + 1 < COMMITTED_LAYERS) {
          p = addPoints(p, p);
          if (idx % (FRI_N >> (r + 1)) >= FRI_N >> (r + 2)) {
            p = { x: neg(p.x), y: neg(p.y) };
          }
        }
      }
    }
  });

  it("fold kernel redeem stays under 10 KB", () => {
    const redeem = compileFoldKernel(6);
    assert.ok(redeem.length > 200, "fold kernel is not a stub");
    assert.ok(redeem.length <= 10_000, `fold redeem ${redeem.length} > 10KB`);
    assert.ok(foldKernelAsm(6).includes("OP_INVOKE"));
    const fri = compileFriQueryKernel();
    assert.ok(fri.length <= 10_000, `FRI kernel ${fri.length}`);
  });

  it("one-query fold kernel accepts honest packed and shard 0", () => {
    const d = deposit();
    const proof = proveFri(d.statement, d.witness);
    const ev = evaluateFoldKernelOnly({
      statement: d.statement,
      proof: encodeFriProof(proof),
      nFold: 1,
    });
    assert.equal(ev.accepted, true, ev.error ?? "one-query fold");
    assert.ok(ev.unlockingBytes <= 10_000);
  });

  it("one-query fold kernel accepts shard 1 at the matching FS index", () => {
    const d = deposit();
    const proof = proveFri(d.statement, d.witness);
    const ev = evaluateFoldKernelOnly({
      statement: d.statement,
      proof: encodeFriProof(proof),
      nFold: 1,
      queryIndex: 1,
    });
    assert.equal(ev.accepted, true, ev.error ?? "shard-1 fold");
  });

  it("one-query fold kernel accepts query 10 (second pair group on shard 0)", () => {
    const d = deposit();
    const proof = proveFri(d.statement, d.witness);
    const ev = evaluateFoldKernelOnly({
      statement: d.statement,
      proof: encodeFriProof(proof),
      nFold: 1,
      queryIndex: 10,
    });
    assert.equal(ev.accepted, true, ev.error ?? "query-10 fold");
  });

  it("two-query fold kernel accepts honest packed with density bind", () => {
    const d = deposit();
    const proof = proveFri(d.statement, d.witness);
    const ev = evaluateFoldKernelOnly({
      statement: d.statement,
      proof: encodeFriProof(proof),
      nFold: 2,
      queryIndex: 0,
    });
    assert.equal(ev.accepted, true, ev.error ?? "two-query fold");
    assert.ok(ev.unlockingBytes <= 10_000);
  });

  it("four-query fold kernel accepts honest packed with density bind", () => {
    const d = deposit();
    const proof = proveFri(d.statement, d.witness);
    const ev = evaluateFoldKernelOnly({
      statement: d.statement,
      proof: encodeFriProof(proof),
      nFold: 4,
      queryIndex: 0,
    });
    assert.equal(ev.accepted, true, ev.error ?? "four-query fold");
    assert.ok(ev.unlockingBytes <= 10_000);
  });

  it("six-query fold kernel accepts honest packed with inv witnesses", () => {
    const d = deposit();
    const proof = proveFri(d.statement, d.witness);
    const ev = evaluateFoldKernelOnly({
      statement: d.statement,
      proof: encodeFriProof(proof),
      nFold: 6,
      queryIndex: 0,
    });
    assert.equal(ev.accepted, true, ev.error ?? "six-query fold");
    assert.ok(ev.unlockingBytes <= 10_000);
  });

  it("one-query fold kernel accepts query 35 without dummy pad", () => {
    const d = deposit();
    const proof = proveFri(d.statement, d.witness);
    const ev = evaluateFoldKernelOnly({
      statement: d.statement,
      proof: encodeFriProof(proof),
      nFold: 1,
      queryIndex: 35,
    });
    assert.equal(ev.accepted, true, ev.error ?? "query-35 fold");
    assert.ok(ev.unlockingBytes <= 10_000);
  });

  it("honest successor still VM-accepts after on-chain fold", () => {
    const d = deposit();
    const proof = proveFri(d.statement, d.witness);
    const raw = encodeFriProof(proof);
    assert.equal(verifyFri(d.statement, proof).ok, true);
    const on = evaluateOnChainVerify(d.statement, raw);
    assert.equal(on.stark.ok, true, on.stark.ok ? "" : on.stark.reason);
    assert.equal(on.pool.accepted, true, on.pool.error ?? "honest fold successor");
  });

  it("honest Merkle leftover + alternate fold pairShard is VM-rejected", () => {
    const d = deposit();
    const proof = proveFri(d.statement, d.witness);
    const raw = encodeFriProof(proof);
    const n = FOLD_QUERIES_PER_KERNEL;
    const honest0 = queryPairShard(raw, 0, n);
    const alt = queryPairShard(raw, n, n);
    assert.notDeepEqual(Buffer.from(alt), Buffer.from(honest0));
    const shards = Array.from({ length: 6 }, (_, f) => queryPairShard(raw, f * n, n));
    shards[0] = alt;
    const honest = evaluatePoolSuccessorVm({
      oldState: d.statement.oldState,
      newState: d.statement.newState,
      proof: raw,
      statement: d.statement,
      slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
      standard: true,
      note: d.note,
    });
    assert.equal(honest.accepted, true, honest.error ?? "honest control");
    const ev = evaluatePoolSuccessorVm({
      oldState: d.statement.oldState,
      newState: d.statement.newState,
      proof: raw,
      statement: d.statement,
      slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
      standard: true,
      note: d.note,
      foldPairShards: shards,
    });
    assert.equal(ev.accepted, false, "fold pairShard must EQUALVERIFY Merkle leftover");
  });

  it("cooked pair blob is rejected when Merkle left/right stay honest", () => {
    const d = deposit();
    const proof = proveFri(d.statement, d.witness);
    const raw = encodeFriProof(proof);
    const shards = friShardUnlockings(raw);
    const cooked0 = new Uint8Array(shards[0]!);
    const op = cooked0[0]!;
    const dataOff = op === 0x4d ? 3 : op === 0x4c ? 2 : 1;
    cooked0[dataOff] ^= 0xff;
    const ev = evaluatePoolSuccessorVm({
      oldState: d.statement.oldState,
      newState: d.statement.newState,
      proof: raw,
      statement: d.statement,
      kernelUnlockings: [cooked0, ...shards.slice(1)],
    });
    assert.equal(ev.accepted, false, "fold pair blob must equal merklized left||right");
  });

  it("wrong FS index on a folded query is rejected", () => {
    const d = deposit();
    const proof = proveFri(d.statement, d.witness);
    const raw = encodeFriProof(proof);
    const honest = evaluatePoolSuccessorVm({
      oldState: d.statement.oldState,
      newState: d.statement.newState,
      proof: raw,
      statement: d.statement,
    });
    assert.equal(honest.accepted, true, honest.error ?? "honest control");
    const bad = evaluateWrongFoldIndex({
      oldState: d.statement.oldState,
      newState: d.statement.newState,
      proof: raw,
      statement: d.statement,
    });
    assert.equal(bad.accepted, false, "unfolded / wrong-index query must fail");
    void COMMITTED_LAYERS;
    void FRI_N;
  });
});

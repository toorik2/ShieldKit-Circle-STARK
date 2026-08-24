import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { cashAssemblyToBin } from "@bitauth/libauth";
import { foldPairSecure } from "../src/backends/circle/fold.ts";
import { proveFri, verifyFri, wDeposit } from "../src/backends/circle/fri.ts";
import { encodeLe } from "../src/backends/circle/m31.ts";
import { decodeQm31, encodeQm31, hashBytesToQm31, type QM31El } from "../src/backends/circle/qm31.ts";
import { applyDeposit } from "../src/pool/transition.ts";
import { IncrementalMerkle, NullifierSet, type Note } from "../src/pool/notes.ts";
import { emptyState } from "../src/pool/state.ts";
import { concatBytes, sha256 } from "../src/pool/bytes.ts";
import { encodeStatement } from "../src/pool/statement.ts";
import { encodeAirPacked, G1024 } from "../src/chain/air-cqz.ts";
import { lambdaFromPackedAsm, compileFoldPairSecureLock } from "../src/chain/fold-asm.ts";
import { queryPairShard } from "../src/chain/fri-openings.ts";
import { pushData } from "../src/chain/covenant-p2s.ts";
import { evaluateBch2026 } from "../src/chain/vm-verifier.ts";
import { scalarMul } from "../src/backends/circle/group.ts";
import { inv } from "../src/backends/circle/m31.ts";
import { FRI_N } from "../src/backends/circle/params.ts";

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

describe("lambda + first fold vs layer-1 pair", () => {
  it("lambdaFromPackedAsm matches hashBytesToQm31", () => {
    const note: Note = {
      amountSats: 8_000n,
      rho: crypto.getRandomValues(new Uint8Array(32)),
      ownerSecret: crypto.getRandomValues(new Uint8Array(32)),
    };
    const d = applyDeposit(
      { state: emptyState(crypto.getRandomValues(new Uint8Array(32))), notes: new IncrementalMerkle(), nullifiers: new NullifierSet() },
      note,
    );
    const proof = proveFri(d.statement, wDeposit(note, d.index, d.path));
    assert.equal(verifyFri(d.statement, proof).ok, true);
    const packed = encodeAirPacked(d.statement, proof);
    const digest = sha256(encodeStatement(d.statement));
    const lambda = hashBytesToQm31(
      sha256(concatBytes(digest, Uint8Array.of(0), proof.layerRoots[0]!, new TextEncoder().encode("lambda"))),
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

  it("first-fold of query 0 pair equals a layer-1 opening", () => {
    const note: Note = {
      amountSats: 8_000n,
      rho: crypto.getRandomValues(new Uint8Array(32)),
      ownerSecret: crypto.getRandomValues(new Uint8Array(32)),
    };
    const d = applyDeposit(
      { state: emptyState(crypto.getRandomValues(new Uint8Array(32))), notes: new IncrementalMerkle(), nullifiers: new NullifierSet() },
      note,
    );
    const proof = proveFri(d.statement, wDeposit(note, d.index, d.path));
    const q = proof.queries[0]!;
    const pair = queryPairShard(proof, 0, 1);
    const fP = BigInt(pair[0]!) | (BigInt(pair[1]!) << 8n) | (BigInt(pair[2]!) << 16n) | (BigInt(pair[3]!) << 24n);
    const fConj = BigInt(pair[4]!) | (BigInt(pair[5]!) << 8n) | (BigInt(pair[6]!) << 16n) | (BigInt(pair[7]!) << 24n);
    const digest = sha256(encodeStatement(d.statement));
    const lambda = hashBytesToQm31(
      sha256(concatBytes(digest, Uint8Array.of(0), proof.layerRoots[0]!, new TextEncoder().encode("lambda"))),
    );
    const idx = q.index % (FRI_N >> 1);
    const p = scalarMul(G1024, BigInt(idx));
    const folded = foldPairSecure(p, fP, fConj, lambda);
    const l1 = pair.subarray(8, 40);
    const left = decodeQm31(l1, 0);
    const right = decodeQm31(l1, 16);
    const hit = [left, right].some((v) => v.every((limb, i) => limb === folded.value[i]));
    assert.equal(hit, true, `fold ${folded.value} vs L ${left} R ${right} idx=${q.index}`);
    const denom = p.x !== 0n ? p.x : p.y;
    const unlocking = Uint8Array.of(
      ...pushNum(p.x),
      ...pushNum(p.y),
      ...pushNum(fP),
      ...pushNum(fConj),
      ...pushNum(inv(denom)),
      ...pushNum(lambda[0]),
      ...pushNum(lambda[1]),
      ...pushNum(lambda[2]),
      ...pushNum(lambda[3]),
    );
    const ev = evaluateBch2026(compileFoldPairSecureLock(folded.value), unlocking);
    assert.equal(ev.accepted, true, ev.error ?? "fold0");
    void encodeLe;
    void encodeQm31;
    void (0 as unknown as QM31El);
  });
});

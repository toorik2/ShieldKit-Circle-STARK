import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { M31 } from "../src/backends/circle/m31.ts";
import { inv } from "../src/backends/circle/m31.ts";
import { foldPairQm31, foldPairSecure } from "../src/backends/circle/fold.ts";
import { CIRCLE_GEN, scalarMul } from "../src/backends/circle/group.ts";
import {
  cm31,
  cmAdd,
  cmMul,
  qm31,
  qmAdd,
  qmMul,
  qmMulM31,
  qmSub,
} from "../src/backends/circle/qm31.ts";
import { evaluateBch2026 } from "../src/chain/vm-verifier.ts";
import { pushData } from "../src/chain/covenant-p2s.ts";
import {
  compileCm31AddLock,
  compileCm31MulLock,
  compileCm31MulRLock,
  compileQm31AddLock,
  compileQm31EvenOddLock,
  compileQm31MulLock,
  compileQm31MulM31Lock,
} from "../src/chain/qm31-asm.ts";
import { compileFoldPairQm31Lock, compileFoldPairSecureLock } from "../src/chain/fold-asm.ts";

const P = M31;

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

function unlock(nums: readonly bigint[]): Uint8Array {
  return Uint8Array.of(...nums.flatMap((n) => [...pushNum(n)]));
}

describe("on-chain QM31 arithmetic", () => {
  it("CM31 mul matches Stwo (1+2i)(4+5i)", () => {
    const prod = cmMul(cm31(1n, 2n), cm31(4n, 5n));
    const ev = evaluateBch2026(compileCm31MulLock(prod), unlock([1n, 2n, 4n, 5n]));
    assert.equal(ev.accepted, true, ev.error ?? "cm31 mul");
  });

  it("CM31 add and R=2+i mul match TypeScript", () => {
    const sum = cmAdd(cm31(1n, 2n), cm31(4n, 5n));
    const evAdd = evaluateBch2026(compileCm31AddLock(sum), unlock([1n, 2n, 4n, 5n]));
    assert.equal(evAdd.accepted, true, evAdd.error ?? "cm31 add");
    const rbd = cmMul(cm31(2n, 1n), cm31(3n, 4n));
    const evR = evaluateBch2026(compileCm31MulRLock(rbd), unlock([3n, 4n]));
    assert.equal(evR.accepted, true, evR.error ?? "cm31 * R");
  });

  it("QM31 mul matches Stwo (1,2,3,4)*(4,5,6,7)", () => {
    const a = qm31(1n, 2n, 3n, 4n);
    const b = qm31(4n, 5n, 6n, 7n);
    const prod = qmMul(a, b);
    assert.deepEqual(prod, qm31(P - 71n, 93n, P - 16n, 50n));
    const ev = evaluateBch2026(compileQm31MulLock(prod), unlock([...a, ...b]));
    assert.equal(ev.accepted, true, ev.error ?? "qm31 mul");
  });

  it("QM31 add matches TypeScript", () => {
    const a = qm31(1n, 2n, 3n, 4n);
    const b = qm31(4n, 5n, 6n, 7n);
    const ev = evaluateBch2026(compileQm31AddLock(qmAdd(a, b)), unlock([...a, ...b]));
    assert.equal(ev.accepted, true, ev.error ?? "qm31 add");
  });

  it("QM31 * M31 matches TypeScript", () => {
    const a = qm31(1n, 2n, 3n, 4n);
    const ev = evaluateBch2026(compileQm31MulM31Lock(qmMulM31(a, 8n)), unlock([...a, 8n]));
    assert.equal(ev.accepted, true, ev.error ?? "qm31 * m31");
  });

  it("even/odd halves match TypeScript", () => {
    const a = qm31(9n, 1n, 4n, 8n);
    const b = qm31(3n, 7n, 2n, 6n);
    const twoInv = inv(2n);
    const even = qmMulM31(qmAdd(a, b), twoInv);
    const odd = qmMulM31(qmSub(a, b), twoInv);
    const ev = evaluateBch2026(compileQm31EvenOddLock(even, odd), unlock([...a, ...b]));
    assert.equal(ev.accepted, true, ev.error ?? "even/odd");
  });

  it("foldPairQm31 matches TypeScript on createVirtualMachineBch2026(true)", () => {
    const p = scalarMul(CIRCLE_GEN, 11n);
    const fP = qm31(9n, 1n, 4n, 8n);
    const fConj = qm31(3n, 7n, 2n, 6n);
    const lambda = qm31(123n, 456n, 789n, 1011n);
    const folded = foldPairQm31(p, fP, fConj, lambda);
    const denom = p.x !== 0n ? p.x : p.y;
    const unlocking = unlock([
      p.x,
      p.y,
      ...fP,
      ...fConj,
      inv(denom),
      ...lambda,
    ]);
    const ev = evaluateBch2026(compileFoldPairQm31Lock(folded.value), unlocking);
    assert.equal(ev.accepted, true, ev.error ?? "foldPairQm31");
    assert.ok(ev.lockingBytes! <= 10000);
  });

  it("foldPairSecure still matches (control)", () => {
    const p = scalarMul(CIRCLE_GEN, 11n);
    const folded = foldPairSecure(p, 99n, 17n, qm31(123n, 456n, 789n, 1011n));
    const denom = p.x !== 0n ? p.x : p.y;
    const unlocking = unlock([p.x, p.y, 99n, 17n, inv(denom), 123n, 456n, 789n, 1011n]);
    const ev = evaluateBch2026(compileFoldPairSecureLock(folded.value), unlocking);
    assert.equal(ev.accepted, true, ev.error ?? "foldPairSecure");
  });
});

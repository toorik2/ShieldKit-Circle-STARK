import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { createTestAuthenticationProgramBch, createVirtualMachineBch2026 } from "@bitauth/libauth";
import { foldPairSecure } from "../src/backends/circle/fold.ts";
import { CIRCLE_GEN, scalarMul } from "../src/backends/circle/group.ts";
import { inv } from "../src/backends/circle/m31.ts";
import { qm31 } from "../src/backends/circle/qm31.ts";
import { compileFoldPairSecureLock } from "../src/chain/fold-asm.ts";
import { pushData } from "../src/chain/covenant-p2s.ts";

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

describe("isolated foldPair: M31 openings + QM31 λ", () => {
  it("matches TypeScript on createVirtualMachineBch2026(true)", () => {
    const p = scalarMul(CIRCLE_GEN, 11n);
    const fP = 99n;
    const fConj = 17n;
    const lambda = qm31(123n, 456n, 789n, 1011n);
    const folded = foldPairSecure(p, fP, fConj, lambda);
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
    const locking = compileFoldPairSecureLock(folded.value);
    const vm = createVirtualMachineBch2026(true);
    const program = createTestAuthenticationProgramBch({
      lockingBytecode: locking,
      unlockingBytecode: unlocking,
      valueSatoshis: 1000n,
    });
    const state = vm.evaluate(program);
    const ok = vm.stateSuccess(state);
    const cost = Number((state as { metrics?: { operationCost?: number | bigint } }).metrics?.operationCost ?? 0);
    const max = Number((state as { metrics?: { maximumOperationCost?: number | bigint } }).metrics?.maximumOperationCost ?? 0);
    console.log(
      `foldPairSecure locking=${locking.length} unlocking=${unlocking.length} op=${cost} max=${max} pct=${max ? ((100 * cost) / max).toFixed(2) : "?"}`,
    );
    assert.equal(ok, true, String(ok));
    assert.ok(locking.length <= 10000);
    assert.ok(unlocking.length <= 10000);
  });
});

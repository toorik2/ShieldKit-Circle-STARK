import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { cashAssemblyToBin } from "@bitauth/libauth";
import {
  encodeFriProof,
  firstFoldOrbit,
  mutateTraceAndProve,
  proveFri,
  sampleUniqueQueryIndices,
  uniqueQueryIndices,
  verifyFri,
  wDeposit,
  wWithdraw,
} from "../src/backends/circle/fri.ts";
import { FRI_N, FRI_QUERIES } from "../src/backends/circle/params.ts";
import { defaultInternalHash, type InternalHash } from "../src/backends/circle/internal-hash.ts";
import { applyDeposit, applyWithdraw } from "../src/pool/transition.ts";
import { IncrementalMerkle, NullifierSet, type Note } from "../src/pool/notes.ts";
import { emptyState } from "../src/pool/state.ts";
import { encodeStatement } from "../src/pool/statement.ts";
import { sha256 } from "../src/pool/bytes.ts";

import {
  AIR_NEWTON_BYTES,
  AIR_OFF_EVEN,
  AIR_OFF_IDX,
  AIR_OFF_ODD,
  encodeAirPacked,
  fiatShamirQueryIndices,
  fsIndex0Asm,
  fsIndexFromAltSlotAsm,
  fsIndexSlotAsm,
  orbitHasAsm,
  uniqueQueryAttemptAsm,
} from "../src/chain/air-cqz.ts";
import { evaluateBch2026 } from "../src/chain/vm-verifier.ts";
import { pushData } from "../src/chain/covenant-p2s.ts";
import { foldKernelUnlocking } from "../src/chain/fold-kernel.ts";
import { slotsKernelUnlocking, SLOT_KERNEL_COUNT } from "../src/chain/air-cqz.ts";
import { KERNEL_UNLOCK_PAD_HIGH, UNLOCKING_MAX_BYTES } from "../src/chain/envelope.ts";

function rnd32(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}

function machine() {
  return {
    state: emptyState(rnd32()),
    notes: new IncrementalMerkle(),
    nullifiers: new NullifierSet(),
  };
}

function beIndex(packed: Uint8Array, slot: number): number {
  const o = AIR_OFF_IDX + slot * 2;
  return ((packed[o]! << 8) | packed[o + 1]!) >>> 0;
}

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

function padUnlock(inner: Uint8Array, pad = 8_000): Uint8Array {
  const dummy = new Uint8Array(pad);
  dummy.fill(0x11);
  const suffix = pushData(dummy);
  const out = new Uint8Array(inner.length + suffix.length);
  out.set(inner, 0);
  out.set(suffix, inner.length);
  return out;
}

function evalPadded(lock: Uint8Array, inner: Uint8Array) {
  const drop = cashAssemblyToBin("OP_DROP");
  if (typeof drop === "string") throw new Error(drop);
  const locking = new Uint8Array(drop.length + lock.length);
  locking.set(drop, 0);
  locking.set(lock, drop.length);
  return evaluateBch2026(locking, padUnlock(inner));
}

/** digest() returns 32 bytes whose first two set (h0<<8|h1)%n. */
function scriptedHash(values: number[], n = FRI_N): InternalHash {
  let i = 0;
  return {
    id: "sha256",
    digest(_data: Uint8Array): Uint8Array {
      const v = values[Math.min(i, values.length - 1)]!;
      i += 1;
      const out = new Uint8Array(32);
      const mod = ((v % n) + n) % n;
      out[0] = (mod >> 8) & 0xff;
      out[1] = mod & 0xff;
      return out;
    },
  };
}

describe("unique first-fold FRI query orbits", () => {
  it("orbitHasAsm: empty blob misses; stored LE orbit hits", () => {
    const miss = cashAssemblyToBin(`<5>\n${orbitHasAsm()}\nOP_NIP\nOP_NOT\n`);
    if (typeof miss === "string") throw new Error(miss);
    const ev0 = evalPadded(miss, Uint8Array.of(0x00));
    assert.equal(ev0.accepted, true, ev0.error ?? "empty miss");
    const hit = cashAssemblyToBin(`<5>\n${orbitHasAsm()}\nOP_NIP\n`);
    if (typeof hit === "string") throw new Error(hit);
    const ev1 = evalPadded(hit, pushData(Uint8Array.of(0x05, 0x00)));
    assert.equal(ev1.accepted, true, ev1.error ?? "stored hit");
  });

  it("one uniqueQueryAttempt from empty blobs accepts the first cand", () => {
    const seed = rnd32();
    const expect = uniqueQueryIndices(defaultInternalHash(), seed, FRI_N, 1)[0]!;
    const lock = cashAssemblyToBin(`
OP_0
OP_SWAP
OP_0
OP_0
${uniqueQueryAttemptAsm()}
OP_NIP
OP_NIP
OP_NIP
OP_BIN2NUM
<${expect}>
OP_NUMEQUAL
`);
    if (typeof lock === "string") throw new Error(lock);
    const ev = evalPadded(lock, pushData(seed));
    assert.equal(ev.accepted, true, ev.error ?? `attempt expected ${expect}`);
  });

  it("shipped sampler returns 36 distinct indices and orbits on 1024", () => {
    assert.equal(FRI_QUERIES, 36);
    assert.equal(FRI_N, 1024);
    const seed = rnd32();
    const sampled = sampleUniqueQueryIndices(defaultInternalHash(), seed, FRI_N, FRI_QUERIES);
    assert.equal(sampled.indices.length, 36);
    assert.equal(new Set(sampled.indices).size, 36);
    assert.equal(new Set(sampled.indices.map((i) => firstFoldOrbit(i, FRI_N))).size, 36);
    assert.ok(sampled.indices.every((i) => i >= 0 && i < FRI_N));
    assert.ok(sampled.attempts >= 36);
  });

  it("discards a colliding digest-step and retries (duplicate index)", () => {
    const hash = scriptedHash([7, 7, 9, 11]);
    const sampled = sampleUniqueQueryIndices(hash, new Uint8Array(32), FRI_N, 3);
    assert.deepEqual(sampled.indices, [7, 9, 11]);
    assert.equal(sampled.attempts, 4);
  });

  it("discards a same first-fold partner (i and i+N/2) and retries", () => {
    const hash = scriptedHash([5, 5 + FRI_N / 2, 40]);
    const sampled = sampleUniqueQueryIndices(hash, new Uint8Array(32), FRI_N, 2);
    assert.equal(firstFoldOrbit(5, FRI_N), firstFoldOrbit(5 + FRI_N / 2, FRI_N));
    assert.deepEqual(sampled.indices, [5, 40]);
    assert.equal(sampled.attempts, 3);
  });

  it("proveFri/verifyFri honest deposit+withdraw; packed FS matches unique list", () => {
    const note: Note = { amountSats: 12_000n, rho: rnd32(), ownerSecret: rnd32() };
    const d = applyDeposit(machine(), note);
    const dep = proveFri(d.statement, wDeposit(note, d.index, d.path));
    assert.equal(verifyFri(d.statement, dep).ok, true);
    assert.equal(dep.queries.length, FRI_QUERIES);
    const depIdx = dep.queries.map((q) => q.index);
    assert.equal(new Set(depIdx).size, FRI_QUERIES);
    assert.equal(new Set(depIdx.map((i) => firstFoldOrbit(i, FRI_N))).size, FRI_QUERIES);
    const digest = sha256(encodeStatement(d.statement));
    const packed = encodeAirPacked(d.statement, encodeFriProof(dep));
    const even = packed.subarray(AIR_OFF_EVEN, AIR_OFF_EVEN + AIR_NEWTON_BYTES);
    const odd = packed.subarray(AIR_OFF_ODD, AIR_OFF_ODD + AIR_NEWTON_BYTES);
    const fs = fiatShamirQueryIndices(digest, dep, defaultInternalHash(), even, odd);
    assert.deepEqual(fs, depIdx);
    for (let s = 0; s < FRI_QUERIES; s += 1) {
      assert.equal(beIndex(packed, s), depIdx[s]);
    }
    const w = applyWithdraw(d.machine, note, d.index, rnd32(), 3_000n);
    const wd = proveFri(w.statement, wWithdraw(note, d.index, w.path, w.created));
    assert.equal(verifyFri(w.statement, wd).ok, true);
    const wdIdx = wd.queries.map((q) => q.index);
    assert.equal(new Set(wdIdx).size, FRI_QUERIES);
    const falseProof = mutateTraceAndProve(d.statement, 0, wDeposit(note, d.index, d.path));
    assert.equal(verifyFri(d.statement, falseProof).ok, false);
  });

  it("on-chain FS unique-orbit recompute matches prover slots 0, 3, and 10", () => {
    const note: Note = { amountSats: 9_000n, rho: rnd32(), ownerSecret: rnd32() };
    const d = applyDeposit(machine(), note);
    const proof = proveFri(d.statement, wDeposit(note, d.index, d.path));
    const packed = encodeAirPacked(d.statement, encodeFriProof(proof));
    const digest = sha256(encodeStatement(d.statement));
    const even = packed.subarray(AIR_OFF_EVEN, AIR_OFF_EVEN + AIR_NEWTON_BYTES);
    const odd = packed.subarray(AIR_OFF_ODD, AIR_OFF_ODD + AIR_NEWTON_BYTES);
    const fs = fiatShamirQueryIndices(digest, proof, defaultInternalHash(), even, odd);
    for (const slot of [0, 3, 10]) {
      const want = fs[slot]!;
      const asm = slot === 0 ? fsIndex0Asm() : fsIndexSlotAsm(slot);
      const lock = cashAssemblyToBin(`${asm}\nOP_NIP\n<${want}>\nOP_NUMEQUAL`);
      if (typeof lock === "string") throw new Error(lock);
      const ev = evalPadded(lock, pushData(packed));
      assert.equal(ev.accepted, true, ev.error ?? `fsIndex slot ${slot} expected ${want}`);
    }
    const i3 = fs[3]!;
    const lock3 = cashAssemblyToBin(
      `<3> OP_TOALTSTACK\n${fsIndexFromAltSlotAsm()}\nOP_NIP\n<${i3}>\nOP_NUMEQUAL`,
    );
    if (typeof lock3 === "string") throw new Error(lock3);
    const ev3 = evalPadded(lock3, pushData(packed));
    assert.equal(ev3.accepted, true, ev3.error ?? `alt-slot 3 expected ${i3}`);
  });

  it("uniqueQueryIndices is the shipped sampler (not a test copy)", () => {
    const seed = rnd32();
    const a = uniqueQueryIndices(defaultInternalHash(), seed, FRI_N, FRI_QUERIES);
    const b = sampleUniqueQueryIndices(defaultInternalHash(), seed, FRI_N, FRI_QUERIES).indices;
    assert.deepEqual(a, b);
  });

  it("fold/R-slot unlocking has no KERNEL_UNLOCK_PAD_HIGH dummy; stays ≤ 10 KB", () => {
    const fold0 = foldKernelUnlocking(1, 0);
    const fold18 = foldKernelUnlocking(1, 18);
    const fold35 = foldKernelUnlocking(1, 35);
    assert.ok(fold0.length < KERNEL_UNLOCK_PAD_HIGH, `fold0 ${fold0.length}`);
    assert.ok(fold18.length < KERNEL_UNLOCK_PAD_HIGH, `fold18 ${fold18.length}`);
    assert.ok(fold35.length < KERNEL_UNLOCK_PAD_HIGH, `fold35 ${fold35.length}`);
    assert.ok(fold35.length <= UNLOCKING_MAX_BYTES);
    const slot0 = slotsKernelUnlocking(0);
    const slotStd = slotsKernelUnlocking(SLOT_KERNEL_COUNT - 1);
    const slotCons = slotsKernelUnlocking(SLOT_KERNEL_COUNT);
    const slot35 = slotsKernelUnlocking(35);
    assert.ok(slot0.length <= UNLOCKING_MAX_BYTES, `slot0 ${slot0.length}`);
    assert.ok(slotStd.length <= UNLOCKING_MAX_BYTES, `slot${SLOT_KERNEL_COUNT - 1} ${slotStd.length}`);
    assert.ok(slotCons.length <= UNLOCKING_MAX_BYTES, `slot${SLOT_KERNEL_COUNT} ${slotCons.length}`);
    assert.ok(slot35.length <= UNLOCKING_MAX_BYTES, `slot35 ${slot35.length}`);
    assert.ok(slot35.length < KERNEL_UNLOCK_PAD_HIGH, `slot35 ${slot35.length}`);
  });
});

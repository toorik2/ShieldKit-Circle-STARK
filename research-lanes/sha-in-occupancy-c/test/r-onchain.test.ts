import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { cashAssemblyToBin } from "@bitauth/libauth";
import { encodeLe } from "../src/backends/circle/m31.ts";
import {
  evalMaskPoly,
  openingMaskAt,
  openingMaskCoeffs,
  OPEN_MASK_DEGREE,
  OPEN_MASK_OFF_DEGREE,
} from "../src/backends/circle/witness-mask.ts";
import { applyDeposit } from "../src/pool/transition.ts";
import { IncrementalMerkle, NullifierSet, type Note } from "../src/pool/notes.ts";
import { emptyState } from "../src/pool/state.ts";
import { encodeFriProof, proveFri, wDeposit } from "../src/backends/circle/fri.ts";
import { evaluateBch2026 } from "../src/chain/vm-verifier.ts";
import { pushData } from "../src/chain/covenant-p2s.ts";
import {
  AIR_NEWTON_BYTES,
  AIR_OFF_EVEN,
  AIR_OFF_NTABLE,
  AIR_OFF_ODD,
  AIR_OFF_OPEN_MASK,
  AIR_OFF_QTABLE,
  AIR_OFF_IDX,
  AIR_OFF_SHA_OPEN,
  SLOT_KERNEL_COUNT,
  compileSlot0CqzLock,
  compileSlotsKernel,
  encodeAirPacked,
  fiatShamirQueryIndices,
  nqzAt,
} from "../src/chain/air-cqz.ts";
import {
  compileFusedLeftoverCLock,
  compileNFromTSlot0Lock,
  compileRAtSlot0Lock,
  compileSlotRCqzLock,
  evalMaskPolyFromBlobAsm,
  openingMaskAtBlobAsm,
  shaPubsAccFrom96Asm,
  slotRCqzAsm,
  slotRCqzBodyBlobAsm,
} from "../src/chain/r-kernel.ts";
import { leftoverPairs } from "../src/chain/fri-openings.ts";
import { FRI_LEFTOVER_BYTES, FRI_LEFTOVER_L0_BYTES } from "../src/chain/fri-kernel.ts";
import { foldKernelAsm } from "../src/chain/fold-kernel.ts";
import { shaPubsAcc, statementShaOpens } from "../src/chain/note-auth-air.ts";
import { encodeFeltBlob } from "../src/chain/m31-asm.ts";
import { encodeStatement } from "../src/pool/statement.ts";
import { concatBytes, sha256 } from "../src/pool/bytes.ts";
import { UNLOCKING_MAX_BYTES } from "../src/chain/envelope.ts";
import { defaultInternalHash } from "../src/backends/circle/internal-hash.ts";


function padUnlock(inner: Uint8Array, pad = 8_000): Uint8Array {
  const room = UNLOCKING_MAX_BYTES - inner.length - 4;
  const n = Math.max(0, Math.min(pad, room));
  const dummy = new Uint8Array(n);
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

function mix() {
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
  const packed = encodeAirPacked(d.statement, encodeFriProof(proof));
  const digest = sha256(encodeStatement(d.statement));
  const i0 = fiatShamirQueryIndices(
    digest,
    proof,
    defaultInternalHash(),
    packed.subarray(AIR_OFF_EVEN, AIR_OFF_EVEN + AIR_NEWTON_BYTES),
    packed.subarray(AIR_OFF_ODD, AIR_OFF_ODD + AIR_NEWTON_BYTES),
    proof.hashRoot,
  )[0]!;
  const nqz = nqzAt(d.statement, i0);
  const r = openingMaskAt(proof.viewingCommit!, i0, undefined, nqz.z);
  const leftover = leftoverPairs(packed, proof);
  return { d, proof, packed, leftover, i0, nqz, r };
}

function pushNum(n: bigint): Uint8Array {
  if (n === 0n) return Uint8Array.of(0x00);
  const bytes: number[] = [];
  let v = n;
  while (v > 0n) {
    bytes.push(Number(v & 0xffn));
    v >>= 8n;
  }
  if ((bytes[bytes.length - 1]! & 0x80) !== 0) bytes.push(0);
  return pushData(Uint8Array.from(bytes));
}

describe("on-chain R_on + Z·R_off (plan 4)", () => {
  it("sequential mask Horner matches evalMaskPoly on and off stream", () => {
    const commit = crypto.getRandomValues(new Uint8Array(32));
    const on = openingMaskCoeffs(commit, defaultInternalHash(), "on");
    const off = openingMaskCoeffs(commit, defaultInternalHash(), "off");
    const blob = new Uint8Array(32 + 144);
    blob.set(encodeFeltBlob(on), 0);
    blob.set(encodeFeltBlob(off), 32);
    const index = 17;
    const x = BigInt(index + 1);
    for (const [offset, degree, coeffs] of [
      [0, OPEN_MASK_DEGREE, on],
      [32, OPEN_MASK_OFF_DEGREE, off],
    ] as const) {
      const expected = evalMaskPoly(coeffs, index);
      const lock = cashAssemblyToBin(`
${evalMaskPolyFromBlobAsm(offset, degree)}
<${expected.toString()}>
OP_NUMEQUAL
`);
      if (typeof lock === "string") throw new Error(lock);
      const ev = evalPadded(lock, Uint8Array.of(...pushData(blob), ...pushNum(x)));
      assert.equal(ev.accepted, true, ev.error ?? `horner off=${offset} R=${expected}`);
    }
  });

  it("consume-blob openingMask matches R_on + Z·R_off", () => {
    const commit = crypto.getRandomValues(new Uint8Array(32));
    const on = openingMaskCoeffs(commit, defaultInternalHash(), "on");
    const off = openingMaskCoeffs(commit, defaultInternalHash(), "off");
    const blob = new Uint8Array(32 + 144);
    blob.set(encodeFeltBlob(on), 0);
    blob.set(encodeFeltBlob(off), 32);
    const index = 17;
    const z = 100n;
    const expected = openingMaskAt(commit, index, defaultInternalHash(), z);
    const lock = cashAssemblyToBin(`
${openingMaskAtBlobAsm()}
<${expected.toString()}>
OP_NUMEQUAL
`);
    if (typeof lock === "string") throw new Error(lock);
    const ev = evalPadded(
      lock,
      Uint8Array.of(...pushData(blob), ...pushNum(BigInt(index)), ...pushNum(z)),
    );
    assert.equal(ev.accepted, true, ev.error ?? `blob R=${expected}`);
  });

  it("slot R redeem stays under 10 KB", () => {
    const asm = slotRCqzAsm(0);
    const bin = cashAssemblyToBin(asm);
    if (typeof bin === "string") throw new Error(bin);
    assert.ok(bin.length <= UNLOCKING_MAX_BYTES, `slotR redeem ${bin.length}`);
    assert.ok(compileSlotsKernel(0).length <= UNLOCKING_MAX_BYTES, `slots kernel ${compileSlotsKernel(0).length}`);
    assert.ok(compileSlotsKernel(SLOT_KERNEL_COUNT - 1).length <= UNLOCKING_MAX_BYTES);
    console.log(`slotR redeem ${bin.length} slots0 ${compileSlotsKernel(0).length}`);
  });

  it("isolated R at FS slot 0 matches JS openingMaskAt", () => {
    const { packed, r } = mix();
    const ok = evalPadded(compileRAtSlot0Lock(r), pushData(packed));
    assert.equal(ok.accepted, true, ok.error ?? `R=${r}`);
    const bad = evalPadded(compileRAtSlot0Lock((r + 1n) % 2147483647n), pushData(packed));
    assert.equal(bad.accepted, false, "wrong R must fail");
  });

  it("isolated N = C(z) at FS slot 0 matches residual interpolant", () => {
    const { packed, nqz } = mix();
    const ok = evalPadded(compileNFromTSlot0Lock(nqz.n), pushData(packed));
    assert.equal(ok.accepted, true, ok.error ?? `N=${nqz.n}`);
    const bad = evalPadded(compileNFromTSlot0Lock((nqz.n + 1n) % 2147483647n), pushData(packed));
    assert.equal(bad.accepted, false, "wrong N must fail");
  });

  it("fused leftover L0 C(z) is N — not parked <0>", () => {
    const asm = foldKernelAsm(6, 0);
    assert.equal(
      asm.includes("<0>\nOP_TOALTSTACK\n<0>\n<8> OP_INVOKE"),
      false,
      "shipped fused R must not park N=<0>",
    );
    assert.match(asm, new RegExp(String(FRI_LEFTOVER_BYTES - FRI_LEFTOVER_L0_BYTES)));
    assert.match(asm, /<8> OP_INVOKE/);
    const rslot = slotRCqzBodyBlobAsm(2, 3);
    assert.equal(rslot.includes("<0>\nOP_TOALTSTACK"), false, "rslot N is leftover L0, not <0>");
    assert.match(rslot, /OP_7 OP_PICK/);
    assert.match(rslot, /OP_NUMEQUALVERIFY/);
  });

  it("fused leftover L0 C(z) + independent C_SHA accepts honest zeros", () => {
    const { packed, leftover } = mix();
    const commit = packed.subarray(AIR_OFF_OPEN_MASK, AIR_OFF_OPEN_MASK + 32);
    const q24 = packed.subarray(AIR_OFF_QTABLE, AIR_OFF_QTABLE + 24);
    const idx = packed.subarray(AIR_OFF_IDX, AIR_OFF_IDX + 12);
    const l0 = leftover.subarray(FRI_LEFTOVER_BYTES - FRI_LEFTOVER_L0_BYTES, FRI_LEFTOVER_BYTES);
    const pairs = l0.subarray(0, 48);
    const sha24 = packed.subarray(AIR_OFF_SHA_OPEN, AIR_OFF_SHA_OPEN + 24);
    const inner = Uint8Array.of(
      ...pushData(commit),
      ...pushData(q24),
      ...pushData(idx),
      ...pushData(pairs),
      ...pushData(sha24),
    );
    const ev = evalPadded(compileFusedLeftoverCLock(6), inner);
    assert.equal(ev.accepted, true, ev.error ?? "fused leftover C + zeros C_SHA");
    const cooked = new Uint8Array(pairs);
    cooked[0] ^= 0xff;
    cooked[4] ^= 0xff;
    const bad = evalPadded(
      compileFusedLeftoverCLock(6),
      Uint8Array.of(
        ...pushData(commit),
        ...pushData(q24),
        ...pushData(idx),
        ...pushData(cooked),
        ...pushData(sha24),
      ),
    );
    assert.equal(bad.accepted, false, "cooked leftover L0 must fail (q−R)·Z==C(z)");
    const mixedSha = new Uint8Array(24);
    mixedSha[0] = 1;
    const skip = evalPadded(
      compileFusedLeftoverCLock(6),
      Uint8Array.of(
        ...pushData(commit),
        ...pushData(q24),
        ...pushData(idx),
        ...pushData(pairs),
        ...pushData(mixedSha),
      ),
    );
    assert.equal(skip.accepted, false, "nonzero independent C_SHA must fail fused N");
  });

  it("shaPubsAccFrom96Asm matches JS shaPubsAcc", () => {
    const { d, proof } = mix();
    const pubs = statementShaOpens(d.statement, proof.auth.leaf);
    const acc = shaPubsAcc(pubs);
    const blob = concatBytes(pubs.amountCommit, pubs.leaf, pubs.nf);
    const lock = cashAssemblyToBin(`${shaPubsAccFrom96Asm()}\n<${acc.toString()}>\nOP_NUMEQUAL`);
    if (typeof lock === "string") throw new Error(lock);
    const ev = evalPadded(lock, pushData(blob));
    assert.equal(ev.accepted, true, ev.error ?? `acc=${acc}`);
  });

  it("leftover SHA-in-C vanish N is 0 at FS slot 0", () => {
    const { packed } = mix();
    const ok = evalPadded(compileNFromTSlot0Lock(0n), pushData(packed));
    assert.equal(ok.accepted, true, ok.error ?? "honest leftover SHA-in-C N=0");
    const bad = evalPadded(compileNFromTSlot0Lock(1n), pushData(packed));
    assert.equal(bad.accepted, false, "nonzero leftover N must fail vanish");
  });

  it("honest (q−R)·Z == C(z) accepts", () => {
    const { packed } = mix();
    const ok = evalPadded(compileSlotRCqzLock(0), pushData(packed));
    assert.equal(ok.accepted, true, ok.error ?? "honest slot R");
    const viaCqz = evalPadded(compileSlot0CqzLock(), pushData(packed));
    assert.equal(viaCqz.accepted, true, viaCqz.error ?? "slotCqzAsm is R-aware");
  });

  it("cooked viewing-commit rejects (R mismatch)", () => {
    const { packed } = mix();
    const cooked = new Uint8Array(packed);
    cooked[AIR_OFF_OPEN_MASK] ^= 0xff;
    const ev = evalPadded(compileSlotRCqzLock(0), pushData(cooked));
    assert.equal(ev.accepted, false, "commit flip must fail R check");
  });

  it("cooked qTable rejects even if nTable is recooked to match masked C=QZ", () => {
    const { packed, nqz, r } = mix();
    if (nqz.z === 0n) return;
    const cooked = new Uint8Array(packed);
    const qPrime = (nqz.q + r + 1n) % 2147483647n;
    const nPrime = (qPrime * nqz.z) % 2147483647n;
    cooked.set(encodeLe(qPrime), AIR_OFF_QTABLE);
    cooked.set(encodeLe(nPrime), AIR_OFF_NTABLE);
    const ev = evalPadded(compileSlotRCqzLock(0), pushData(cooked));
    assert.equal(ev.accepted, false, "masked-consistent recook of Q/N must still fail independent N");
  });
});

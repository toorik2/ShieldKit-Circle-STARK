/**
 * Isolated 2026-VM measurements: one field mul, wire size of one element.
 * Not a vk, not a fold kernel, not a successor.
 */
import {
  bigIntToVmNumber,
  cashAssemblyToBin,
  createTestAuthenticationProgramBch,
  createVirtualMachineBch2026,
  encodeLockingBytecodeP2sh32,
  hash256,
} from "@bitauth/libauth";

function pushData(data: Uint8Array): Uint8Array {
  if (data.length <= 75) return Uint8Array.of(data.length, ...data);
  if (data.length <= 255) return Uint8Array.of(0x4c, data.length, ...data);
  return Uint8Array.of(0x4d, data.length & 0xff, (data.length >> 8) & 0xff, ...data);
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((s, p) => s + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

function pushInt(n: bigint): Uint8Array {
  return pushData(bigIntToVmNumber(n));
}

function asm(s: string): Uint8Array {
  const b = cashAssemblyToBin(s);
  if (typeof b === "string") throw new Error(b);
  return b;
}

function meter(locking: Uint8Array, unlocking: Uint8Array) {
  const vm = createVirtualMachineBch2026(true);
  const program = createTestAuthenticationProgramBch({
    lockingBytecode: locking,
    unlockingBytecode: unlocking,
    valueSatoshis: 1000n,
  });
  const state = vm.evaluate(program);
  const ok = vm.stateSuccess(state);
  const m = (state as { metrics?: Record<string, number | bigint> }).metrics ?? {};
  const num = (x: number | bigint | undefined) =>
    x === undefined ? 0 : typeof x === "bigint" ? Number(x) : x;
  const operationCost = num(m.operationCost);
  const maximumOperationCost = num(m.maximumOperationCost);
  return {
    accepted: ok === true,
    error: ok === true ? null : String(ok).slice(0, 180),
    unlocking: unlocking.length,
    locking: locking.length,
    operationCost,
    maximumOperationCost,
    opPct: maximumOperationCost ? +(100 * operationCost / maximumOperationCost).toFixed(2) : 0,
    hashDigestIterations: num(m.hashDigestIterations),
  };
}

const M31 = (1n << 31n) - 1n;
const M107 = (1n << 107n) - 1n;
const M127 = (1n << 127n) - 1n;

function mulModLock(p: bigint): Uint8Array {
  return concat(asm("OP_MUL"), pushInt(p), asm("OP_MOD OP_EQUAL"));
}

function oneMul(name: string, p: bigint, a: bigint, b: bigint) {
  const c = (a * b) % p;
  const unlockingBare = concat(pushInt(c), pushInt(a), pushInt(b));
  const redeem = mulModLock(p);
  const bare = meter(redeem, unlockingBare);
  const p2sh = encodeLockingBytecodeP2sh32(hash256(redeem));
  const unlockingP2sh = concat(unlockingBare, pushData(redeem));
  const wrapped = meter(p2sh, unlockingP2sh);
  const maxEl = p - 1n;
  return {
    name,
    pBits: p.toString(2).length,
    limbVmBytes: bigIntToVmNumber(maxEl).length,
    pushMaxElement: pushInt(maxEl).length,
    formulaMulExtra: Number(bigIntToVmNumber(maxEl).length) ** 2,
    bare,
    p2sh32: wrapped,
  };
}

/** n sequential squares in M31: isolates “how many 4-byte muls” vs one wide mul. */
function m31Squares(n: number, a: bigint) {
  let x = a % M31;
  if (x === 0n) x = 3n;
  let cur = x;
  for (let i = 0; i < n; i += 1) cur = (cur * cur) % M31;
  const body = Array.from({ length: n }, () => `OP_DUP ${`OP_MUL <${M31}> OP_MOD`}`).join("\n");
  const redeem = asm(`${body}\nOP_EQUAL`);
  const unlockingBare = concat(pushInt(cur), pushInt(x));
  const bare = meter(redeem, unlockingBare);
  const p2sh = encodeLockingBytecodeP2sh32(hash256(redeem));
  return {
    name: `m31-square-x${n}`,
    n,
    bare,
    p2sh32: meter(p2sh, concat(unlockingBare, pushData(redeem))),
  };
}

const a31 = 0x1234567n;
const b31 = 0x7654321n;
const a107 = (M107 / 3n) ^ 0x1111n;
const b107 = (M107 / 5n) ^ 0x2222n;
const a127 = (M127 / 3n) ^ 0x3333n;
const b127 = (M127 / 7n) ^ 0x4444n;

const rows = [
  oneMul("m31", M31, a31, b31),
  oneMul("m107", M107, a107 % M107, b107 % M107),
  oneMul("m127", M127, a127 % M127, b127 % M127),
];
const squares = [1, 3, 9, 16].map((n) => m31Squares(n, a31));

const fourLimbPush = concat(pushInt(a31), pushInt(b31), pushInt(a31 + 1n), pushInt(b31 + 1n));
const oneM107Push = pushInt(a107 % M107);

const out = {
  vm: "createVirtualMachineBch2026(true)",
  note: "One mul a*b % p. Unlocking = expected || a || b. Not a fold, not a successor.",
  wire: {
    m31_maxElementVmBytes: bigIntToVmNumber(M31 - 1n).length,
    m107_maxElementVmBytes: bigIntToVmNumber(M107 - 1n).length,
    m127_maxElementVmBytes: bigIntToVmNumber(M127 - 1n).length,
    four_m31_limbs_unlocking: fourLimbPush.length,
    one_m107_unlocking: oneM107Push.length,
  },
  mul: rows,
  m31Squares: squares,
};

console.log(JSON.stringify(out, null, 2));

/**
 * Stwo SecureField. CM31 = M31[i]/(i^2+1). QM31 = CM31[u]/(u^2-2-i).
 * Element (a0,a1,a2,a3) = (a0 + a1 i) + (a2 + a3 i) u.
 * Circle / Merkle / qTable stay M31. Challenges and post-fold values live here.
 */
import {
  add as mAdd,
  el,
  encodeLe,
  inv as mInv,
  mul as mMul,
  neg as mNeg,
  sub as mSub,
  type M31El,
} from "./m31.ts";

export type CM31El = readonly [M31El, M31El];
export type QM31El = readonly [M31El, M31El, M31El, M31El];

export const CM31_ZERO: CM31El = [0n, 0n];
export const CM31_ONE: CM31El = [1n, 0n];
export const QM31_ZERO: QM31El = [0n, 0n, 0n, 0n];
export const QM31_ONE: QM31El = [1n, 0n, 0n, 0n];
/** u^2 = 2 + i  (Stwo R). */
export const QM31_R: CM31El = [2n, 1n];
/** log2(p^4) ≈ 123.999; Stwo names the challenge space 124-bit. */
export const QM31_FIELD_BITS = 124;

export function cm31(re: M31El, im: M31El): CM31El {
  return [el(re, "cm.re"), el(im, "cm.im")];
}

export function qm31(a0: M31El, a1: M31El, a2: M31El, a3: M31El): QM31El {
  return [el(a0, "q0"), el(a1, "q1"), el(a2, "q2"), el(a3, "q3")];
}

export function liftM31(a: M31El): QM31El {
  return qm31(a, 0n, 0n, 0n);
}

export function cmAdd(a: CM31El, b: CM31El): CM31El {
  return [mAdd(a[0], b[0]), mAdd(a[1], b[1])];
}

export function cmSub(a: CM31El, b: CM31El): CM31El {
  return [mSub(a[0], b[0]), mSub(a[1], b[1])];
}

export function cmNeg(a: CM31El): CM31El {
  return [mNeg(a[0]), mNeg(a[1])];
}

/** (a+bi)(c+di) = (ac−bd)+(ad+bc)i */
export function cmMul(a: CM31El, b: CM31El): CM31El {
  return [mSub(mMul(a[0], b[0]), mMul(a[1], b[1])), mAdd(mMul(a[0], b[1]), mMul(a[1], b[0]))];
}

export function cmSquare(a: CM31El): CM31El {
  return cmMul(a, a);
}

/** 1/(a+bi) = (a−bi)/(a²+b²) */
export function cmInv(a: CM31El): CM31El {
  const n2 = mAdd(mMul(a[0], a[0]), mMul(a[1], a[1]));
  const invN = mInv(n2);
  return [mMul(a[0], invN), mMul(mNeg(a[1]), invN)];
}

function asCm(a: QM31El, which: 0 | 1): CM31El {
  return which === 0 ? [a[0], a[1]] : [a[2], a[3]];
}

function joinCm(r: CM31El, s: CM31El): QM31El {
  return [r[0], r[1], s[0], s[1]];
}

export function qmAdd(a: QM31El, b: QM31El): QM31El {
  return [mAdd(a[0], b[0]), mAdd(a[1], b[1]), mAdd(a[2], b[2]), mAdd(a[3], b[3])];
}

export function qmSub(a: QM31El, b: QM31El): QM31El {
  return [mSub(a[0], b[0]), mSub(a[1], b[1]), mSub(a[2], b[2]), mSub(a[3], b[3])];
}

export function qmNeg(a: QM31El): QM31El {
  return [mNeg(a[0]), mNeg(a[1]), mNeg(a[2]), mNeg(a[3])];
}

/** (a+bu)(c+du) = (ac + R bd) + (ad+bc)u , R=2+i. Stwo Mul. */
export function qmMul(a: QM31El, b: QM31El): QM31El {
  const r = asCm(a, 0);
  const s = asCm(a, 1);
  const t = asCm(b, 0);
  const v = asCm(b, 1);
  const ac = cmMul(r, t);
  const bd = cmMul(s, v);
  const ad = cmMul(r, v);
  const bc = cmMul(s, t);
  return joinCm(cmAdd(ac, cmMul(QM31_R, bd)), cmAdd(ad, bc));
}

/** QM31 * M31 (first-fold: λ · lift(odd)). */
export function qmMulM31(a: QM31El, m: M31El): QM31El {
  return [mMul(a[0], m), mMul(a[1], m), mMul(a[2], m), mMul(a[3], m)];
}

export function qmSquare(a: QM31El): QM31El {
  return qmMul(a, a);
}

/**
 * (a+bu)^{-1} = (a − bu) / (a² − (2+i)b²)
 * Stwo: ib2 = (−b².im, b².re); denom = a² − (b²+b²+ib2).
 */
export function qmInv(a: QM31El): QM31El {
  if (a[0] === 0n && a[1] === 0n && a[2] === 0n && a[3] === 0n) {
    throw new Error("zero has no inverse");
  }
  const r = asCm(a, 0);
  const s = asCm(a, 1);
  const s2 = cmSquare(s);
  const ib2: CM31El = [mNeg(s2[1]), s2[0]];
  const denom = cmSub(cmSquare(r), cmAdd(cmAdd(s2, s2), ib2));
  const di = cmInv(denom);
  return joinCm(cmMul(r, di), cmNeg(cmMul(s, di)));
}

export function qmEq(a: QM31El, b: QM31El): boolean {
  return a[0] === b[0] && a[1] === b[1] && a[2] === b[2] && a[3] === b[3];
}

export function encodeQm31(v: QM31El): Uint8Array {
  const out = new Uint8Array(16);
  out.set(encodeLe(v[0]), 0);
  out.set(encodeLe(v[1]), 4);
  out.set(encodeLe(v[2]), 8);
  out.set(encodeLe(v[3]), 12);
  return out;
}

export function decodeQm31(bytes: Uint8Array, offset = 0): QM31El {
  const limb = (o: number): M31El =>
    BigInt(bytes[offset + o]!) |
    (BigInt(bytes[offset + o + 1]!) << 8n) |
    (BigInt(bytes[offset + o + 2]!) << 16n) |
    (BigInt(bytes[offset + o + 3]!) << 24n);
  return qm31(limb(0), limb(4), limb(8), limb(12));
}

/** Four BE-u64 limbs from a 32-byte digest, each mod M31 — uses the whole SHA-256. */
export function hashBytesToQm31(digest: Uint8Array): QM31El {
  if (digest.length < 32) throw new Error("qm31 hash width");
  const u64be = (o: number): bigint => {
    let n = 0n;
    for (let i = 0; i < 8; i += 1) n = (n << 8n) | BigInt(digest[o + i]!);
    return n % 2147483647n;
  };
  return qm31(u64be(0), u64be(8), u64be(16), u64be(24));
}

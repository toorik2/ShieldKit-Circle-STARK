import { add, el, encodeLe, mul, type M31El } from "./m31.ts";

/** 4-limb state. 4 rounds of cube + circulant mix. Same function in the note tree and the AIR. */
export type Felt4 = [M31El, M31El, M31El, M31El];

const C: Felt4[] = [
  [3n, 5n, 7n, 11n],
  [13n, 17n, 19n, 23n],
  [29n, 31n, 37n, 41n],
  [43n, 47n, 53n, 59n],
];

function cubeAdd(x: M31El, c: M31El): M31El {
  const y = add(x, c);
  return mul(y, mul(y, y));
}

export function compressFelt4(left: Felt4, right: Felt4): Felt4 {
  let s: M31El[] = [...left, ...right];
  for (let r = 0; r < 4; r += 1) {
    for (let i = 0; i < 8; i += 1) {
      s[i] = cubeAdd(s[i]!, C[r]![i % 4]!);
    }
    const b = s.slice();
    for (let i = 0; i < 8; i += 1) {
      s[i] = add(add(b[i]!, b[(i + 1) % 8]!), mul(3n, b[(i + 3) % 8]!));
    }
  }
  return [el(s[0]!), el(s[1]!), el(s[2]!), el(s[3]!)];
}

export function bytesToFelt4(bytes: Uint8Array): Felt4 {
  const out: M31El[] = [];
  for (let i = 0; i < 4; i += 1) {
    const o = i * 4;
    const v =
      BigInt(bytes[o] ?? 0) |
      (BigInt(bytes[o + 1] ?? 0) << 8n) |
      (BigInt(bytes[o + 2] ?? 0) << 16n) |
      (BigInt((bytes[o + 3] ?? 0) & 0x7f) << 24n);
    out.push(v % 2147483647n);
  }
  return [out[0]!, out[1]!, out[2]!, out[3]!];
}

export function felt4ToBytes(v: Felt4): Uint8Array {
  const out = new Uint8Array(32);
  for (let i = 0; i < 4; i += 1) out.set(encodeLe(v[i]!), i * 4);
  return out;
}

export function parent32(left: Uint8Array, right: Uint8Array): Uint8Array {
  return felt4ToBytes(compressFelt4(bytesToFelt4(left), bytesToFelt4(right)));
}

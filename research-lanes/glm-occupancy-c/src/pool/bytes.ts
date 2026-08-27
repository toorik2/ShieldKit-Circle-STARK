import { createHash } from "node:crypto";

export function hexToBytes(hex: string, name = "hex"): Uint8Array {
  const h = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (h.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(h)) {
    throw new Error(`${name} must be even-length hex`);
  }
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(h.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

export function writeU16BE(value: number): Uint8Array {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff) {
    throw new Error("u16 out of range");
  }
  return Uint8Array.of((value >> 8) & 0xff, value & 0xff);
}

export function writeU32BE(value: number): Uint8Array {
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) {
    throw new Error("u32 out of range");
  }
  return Uint8Array.of((value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff);
}

export function readU32BE(bytes: Uint8Array, offset: number): number {
  return (
    ((bytes[offset]! << 24) | (bytes[offset + 1]! << 16) | (bytes[offset + 2]! << 8) | bytes[offset + 3]!) >>> 0
  );
}

export function writeU64BE(value: bigint): Uint8Array {
  if (value < 0n || value > 0xffffffffffffffffn) throw new Error("u64 out of range");
  const out = new Uint8Array(8);
  let n = value;
  for (let i = 7; i >= 0; i -= 1) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
}

export function writeI64BE(value: bigint): Uint8Array {
  const asU = value < 0n ? (1n << 64n) + value : value;
  return writeU64BE(asU);
}

export function writeU64LE(value: bigint): Uint8Array {
  if (value < 0n || value > 0xffffffffffffffffn) throw new Error("u64 out of range");
  const out = new Uint8Array(8);
  let n = value;
  for (let i = 0; i < 8; i += 1) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
}

export function writeI64LE(value: bigint): Uint8Array {
  const asU = value < 0n ? (1n << 64n) + value : value;
  return writeU64LE(asU);
}

export function readU16BE(bytes: Uint8Array, offset: number): number {
  return (bytes[offset]! << 8) | bytes[offset + 1]!;
}

export function readU64BE(bytes: Uint8Array, offset: number): bigint {
  let n = 0n;
  for (let i = 0; i < 8; i += 1) n = (n << 8n) | BigInt(bytes[offset + i]!);
  return n;
}

export function sha256(data: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha256").update(data).digest());
}

export const ZERO32 = new Uint8Array(32);

export function writeU256BE(value: bigint): Uint8Array {
  if (value < 0n) throw new Error("u256 negative");
  const out = new Uint8Array(32);
  let n = value;
  for (let i = 31; i >= 0; i -= 1) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
}

export function readU256BE(bytes: Uint8Array): bigint {
  if (bytes.length !== 32) throw new Error("u256 width");
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  return n;
}

export function isZero32(bytes: Uint8Array): boolean {
  return bytes.length === 32 && bytes.every((b) => b === 0);
}

/** Minimally encoded Bitcoin script number (≤ 8 bytes). */
export function encodeVmNumber(n: bigint): Uint8Array {
  if (n === 0n) return Uint8Array.of(0x00);
  const neg = n < 0n;
  let v = neg ? -n : n;
  const bytes: number[] = [];
  while (v > 0n) {
    bytes.push(Number(v & 0xffn));
    v >>= 8n;
  }
  if ((bytes[bytes.length - 1]! & 0x80) !== 0) bytes.push(0);
  if (neg) bytes[bytes.length - 1]! |= 0x80;
  if (bytes.length > 8) throw new Error("vm number wider than 8 bytes");
  return Uint8Array.from(bytes);
}

export function eq32(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === 32 && b.length === 32 && a.every((x, i) => x === b[i]);
}

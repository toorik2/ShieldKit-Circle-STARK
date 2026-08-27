/**
 * Comparison-only Pedersen profile — BCR 1570.
 * C = v·G + r·H. Homomorphic: C(v1,r1)+C(v2,r2)=C(v1+v2,r1+r2).
 *
 * Not the production note-amount commit (see hash-commit.ts). Discrete-log,
 * not PQ. On-chain EC verify still waits on CHIP 2025-05.
 */
import { sha256 } from "../pool/bytes.ts";

const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

export type PedPoint = { x: bigint; y: bigint };

function mod(a: bigint, m = P): bigint {
  const r = a % m;
  return r < 0n ? r + m : r;
}

function shaInt(tag: string): bigint {
  const h = sha256(new TextEncoder().encode(tag));
  let n = 0n;
  for (const b of h) n = (n << 8n) | BigInt(b);
  return mod(n, N);
}

/** Nothing-up-my-sleeve generators (hash-to-scalar). Not a consensus curve pin. */
export const PEDERSEN_G = shaInt("PAA1-PEDERSEN-G");
export const PEDERSEN_H = shaInt("PAA1-PEDERSEN-H");

export function commitAmount(value: bigint, blind: bigint): bigint {
  if (value < 0n) throw new Error("negative amount");
  return mod(value * PEDERSEN_G + blind * PEDERSEN_H, N);
}

export function addCommits(a: bigint, b: bigint): bigint {
  return mod(a + b, N);
}

/** Conservation: sum of openings equals sum of commits. */
export function conserves(
  ins: Array<{ v: bigint; r: bigint }>,
  outs: Array<{ v: bigint; r: bigint }>,
): boolean {
  const ci = ins.reduce((s, x) => addCommits(s, commitAmount(x.v, x.r)), 0n);
  const co = outs.reduce((s, x) => addCommits(s, commitAmount(x.v, x.r)), 0n);
  const vi = ins.reduce((s, x) => s + x.v, 0n);
  const vo = outs.reduce((s, x) => s + x.v, 0n);
  return ci === co && vi === vo;
}

export type PedPointExport = PedPoint;

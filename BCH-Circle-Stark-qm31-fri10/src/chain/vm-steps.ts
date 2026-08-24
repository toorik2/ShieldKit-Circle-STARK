/** Encode path as (bit||sib) records so the script always knows CAT order. */
export function encodeSteps(parentIndex: number, parentPath: Uint8Array[]): Uint8Array {
  const parts: Uint8Array[] = [];
  let i = parentIndex;
  for (const sib of parentPath) {
    parts.push(Uint8Array.of(i & 1), sib);
    i >>= 1;
  }
  const n = parts.reduce((s, p) => s + p.length, 0);
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

export function parentIndexOf(valueIndex: number, n: number): number {
  const i = valueIndex % n;
  return i < n / 2 ? i : i - n / 2;
}

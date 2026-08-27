import { concatBytes, bytesToHex } from "../../pool/bytes.ts";
import { encodeLe, type M31El } from "./m31.ts";
import { defaultInternalHash, type InternalHash } from "./internal-hash.ts";

export function merkleParent(
  left: Uint8Array,
  right: Uint8Array,
  hash: InternalHash = defaultInternalHash(),
): Uint8Array {
  return hash.digest(concatBytes(left, right));
}

export function leafHash(value: M31El, hash: InternalHash = defaultInternalHash()): Uint8Array {
  return hash.digest(encodeLe(value));
}

export class MerkleTree {
  readonly layers: Uint8Array[][];
  readonly hash: InternalHash;

  constructor(values: M31El[] | Uint8Array[], hash: InternalHash = defaultInternalHash()) {
    if (values.length === 0 || (values.length & (values.length - 1)) !== 0) {
      throw new Error("merkle width must be a power of two");
    }
    this.hash = hash;
    const leaves = values.map((v) => (v instanceof Uint8Array ? hash.digest(v) : leafHash(v, hash)));
    this.layers = [leaves];
    let cur = leaves;
    while (cur.length > 1) {
      const next: Uint8Array[] = [];
      for (let i = 0; i < cur.length; i += 2) {
        next.push(merkleParent(cur[i]!, cur[i + 1]!, hash));
      }
      this.layers.push(next);
      cur = next;
    }
  }

  get root(): Uint8Array {
    return this.layers[this.layers.length - 1]![0]!;
  }

  path(index: number): Uint8Array[] {
    const out: Uint8Array[] = [];
    let i = index;
    for (let d = 0; d < this.layers.length - 1; d += 1) {
      const layer = this.layers[d]!;
      out.push(layer[i ^ 1]!);
      i >>= 1;
    }
    return out;
  }

  static verify(
    value: M31El,
    index: number,
    path: Uint8Array[],
    root: Uint8Array,
    hash: InternalHash = defaultInternalHash(),
  ): boolean {
    return MerkleTree.verifyLeaf(leafHash(value, hash), index, path, root, hash);
  }

  static verifyBytes(
    raw: Uint8Array,
    index: number,
    path: Uint8Array[],
    root: Uint8Array,
    hash: InternalHash = defaultInternalHash(),
  ): boolean {
    return MerkleTree.verifyLeaf(hash.digest(raw), index, path, root, hash);
  }

  static verifyLeaf(
    leaf: Uint8Array,
    index: number,
    path: Uint8Array[],
    root: Uint8Array,
    hash: InternalHash = defaultInternalHash(),
  ): boolean {
    let acc = leaf;
    let i = index;
    for (const sib of path) {
      acc = i % 2 === 0 ? merkleParent(acc, sib, hash) : merkleParent(sib, acc, hash);
      i >>= 1;
    }
    return bytesToHex(acc) === bytesToHex(root);
  }

  /** Partner-as-sibling: both leaves known, path starts at their parent. */
  static verifyPaired(
    value: M31El,
    partner: M31El,
    valueIndex: number,
    n: number,
    parentPath: Uint8Array[],
    root: Uint8Array,
    hash: InternalHash = defaultInternalHash(),
  ): boolean {
    const i = valueIndex % n;
    const lo = i < n / 2;
    const left = lo ? leafHash(value, hash) : leafHash(partner, hash);
    const right = lo ? leafHash(partner, hash) : leafHash(value, hash);
    const parent = merkleParent(left, right, hash);
    return MerkleTree.verifyLeaf(parent, lo ? i : i - n / 2, parentPath, root, hash);
  }

  /** Partner-as-sibling for raw leaves (QM31 16-byte encodings). */
  static verifyPairedRaw(
    value: Uint8Array,
    partner: Uint8Array,
    valueIndex: number,
    n: number,
    parentPath: Uint8Array[],
    root: Uint8Array,
    hash: InternalHash = defaultInternalHash(),
  ): boolean {
    const i = valueIndex % n;
    const lo = i < n / 2;
    const left = lo ? hash.digest(value) : hash.digest(partner);
    const right = lo ? hash.digest(partner) : hash.digest(value);
    const parent = merkleParent(left, right, hash);
    return MerkleTree.verifyLeaf(parent, lo ? i : i - n / 2, parentPath, root, hash);
  }
}

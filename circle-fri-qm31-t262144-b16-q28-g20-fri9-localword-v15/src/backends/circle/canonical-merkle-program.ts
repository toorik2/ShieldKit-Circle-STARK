import { eq32 } from "../../pool/bytes.ts";
import {
  canonicalMerkleLeaf,
  canonicalMerkleParent,
} from "./canonical-merkle.ts";

export type CanonicalMerkleProgram = Uint8Array;

/**
 * Queue-machine encoding of the unique level-order canonical multiproof:
 * bits 2..6 = level, bit 1 = first queue node is the right child,
 * bit 0 = second node comes from the sibling stream rather than the queue.
 */
export function canonicalMerkleProgram(
  indices: readonly number[],
  siblingCount: number,
  rowCount: number,
): CanonicalMerkleProgram {
  if (!Number.isInteger(rowCount) || rowCount < 2 || (rowCount & (rowCount - 1)) !== 0 ||
    !Number.isInteger(siblingCount) || siblingCount < 0 ||
    indices.length < 1 || indices.some((index, position) =>
      !Number.isInteger(index) || index < 0 || index >= rowCount ||
      (position > 0 && index <= indices[position - 1]!))) {
    throw new Error("canonical Merkle program shape");
  }
  const tokens: number[] = [];
  let frontier = [...indices];
  let consumedSiblings = 0;
  for (let level = 0; level < Math.log2(rowCount); level += 1) {
    const present = new Set(frontier);
    const next: number[] = [];
    for (const index of frontier) {
      if ((index & 1) === 1 && present.has(index ^ 1)) continue;
      const fromProof = !present.has(index ^ 1);
      if (fromProof) consumedSiblings += 1;
      tokens.push((level << 2) | ((index & 1) << 1) | Number(fromProof));
      next.push(index >> 1);
    }
    frontier = [...new Set(next)];
  }
  if (frontier.length !== 1 || frontier[0] !== 0 || consumedSiblings !== siblingCount ||
    tokens.length !== indices.length + siblingCount - 1) {
    throw new Error("canonical Merkle program coverage");
  }
  return Uint8Array.from(tokens);
}

/** Independent queue interpreter for the exact bytes intended for CashVM. */
export function verifyCanonicalMerkleProgram(args: {
  readonly label: string;
  readonly indices: readonly number[];
  readonly rows: readonly Uint8Array[];
  readonly siblings: readonly Uint8Array[];
  readonly rowCount: number;
  readonly root: Uint8Array;
  readonly program?: CanonicalMerkleProgram;
}): boolean {
  try {
    if (args.indices.length !== args.rows.length || args.root.length !== 32 ||
      args.siblings.some((sibling) => sibling.length !== 32)) return false;
    const program = args.program ?? canonicalMerkleProgram(
      args.indices,
      args.siblings.length,
      args.rowCount,
    );
    const leaves = args.rows.map((raw, position) =>
      canonicalMerkleLeaf(args.label, args.indices[position]!, raw));
    const hashes: Uint8Array[] = [];
    let leafCursor = 0;
    let hashCursor = 0;
    let siblingCursor = 0;
    const nextQueue = (): Uint8Array => {
      if (leafCursor < leaves.length) return leaves[leafCursor++]!;
      const value = hashes[hashCursor++];
      if (!value) throw new Error("canonical Merkle queue underflow");
      return value;
    };
    for (const token of program) {
      const level = token >>> 2;
      const firstIsRight = (token & 2) !== 0;
      const fromProof = (token & 1) !== 0;
      if (level >= Math.log2(args.rowCount) || (!fromProof && firstIsRight)) return false;
      const first = nextQueue();
      const second = fromProof ? args.siblings[siblingCursor++] : nextQueue();
      if (!second) return false;
      hashes.push(firstIsRight
        ? canonicalMerkleParent(args.label, level, second, first)
        : canonicalMerkleParent(args.label, level, first, second));
    }
    return leafCursor === leaves.length && siblingCursor === args.siblings.length &&
      hashCursor === hashes.length - 1 && hashes.length > 0 && eq32(hashes.at(-1)!, args.root);
  } catch {
    return false;
  }
}

import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  SPARSE_NULLIFIER_DEPTH,
  SPARSE_NULLIFIER_PATH_BYTES,
  SparseNullifierTree,
  emptySparseNullifierRoot,
  verifySparseNullifierInsertion,
} from "../src/pool/sparse-nullifiers.ts";

describe("successor sparse nullifier set", () => {
  it("proves absence and insertion using one public 8192-byte path", () => {
    const tree = new SparseNullifierTree();
    assert.deepEqual(tree.root, emptySparseNullifierRoot());
    const nullifier = new Uint8Array(32).fill(0x42);
    const inserted = tree.insert(nullifier);
    assert.equal(inserted.path.length, SPARSE_NULLIFIER_DEPTH);
    assert.equal(inserted.path.reduce((sum, node) => sum + node.length, 0), SPARSE_NULLIFIER_PATH_BYTES);
    assert.equal(
      verifySparseNullifierInsertion({ nullifier, path: inserted.path, oldRoot: inserted.oldRoot, newRoot: inserted.newRoot }),
      true,
    );
  });

  it("rejects replay of the same public nullifier", () => {
    const tree = new SparseNullifierTree();
    const nullifier = new Uint8Array(32).fill(0x42);
    const first = tree.insert(nullifier);
    assert.throws(() => tree.insert(nullifier), /already used/);
    assert.equal(
      verifySparseNullifierInsertion({
        nullifier,
        path: first.path,
        oldRoot: first.newRoot,
        newRoot: first.newRoot,
      }),
      false,
    );
  });

  it("updates independent keys without invalidating later absence proofs", () => {
    const tree = new SparseNullifierTree();
    tree.insert(new Uint8Array(32).fill(0x11));
    const second = tree.insert(new Uint8Array(32).fill(0x22));
    assert.equal(
      verifySparseNullifierInsertion({
        nullifier: new Uint8Array(32).fill(0x22),
        path: second.path,
        oldRoot: second.oldRoot,
        newRoot: second.newRoot,
      }),
      true,
    );
  });
});

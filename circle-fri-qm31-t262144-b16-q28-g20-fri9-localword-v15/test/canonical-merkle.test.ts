import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  CanonicalMerkleTree,
  CanonicalMerkleTree4,
  canonicalMerkleFrontier4,
  encodeCanonicalMerkleFrontier4,
} from "../src/backends/circle/canonical-merkle.ts";
import { encodeQm31, type QM31El } from "../src/backends/circle/qm31.ts";

describe("canonical successor Merkle tree", () => {
  const rows = Array.from({ length: 16 }, (_, row) => new Uint8Array(37).fill(row));

  it("verifies every indexed row", () => {
    const tree = new CanonicalMerkleTree("sealed-sha", rows);
    for (let index = 0; index < rows.length; index += 1) {
      assert.equal(CanonicalMerkleTree.verify("sealed-sha", rows[index]!, index, tree.path(index), tree.root), true);
    }
  });

  it("binds role, index, row, and path", () => {
    const tree = new CanonicalMerkleTree("sealed-sha", rows);
    const path = tree.path(3);
    assert.equal(CanonicalMerkleTree.verify("sealed-bus", rows[3]!, 3, path, tree.root), false);
    assert.equal(CanonicalMerkleTree.verify("sealed-sha", rows[3]!, 2, path, tree.root), false);
    const changed = new Uint8Array(rows[3]!);
    changed[0] ^= 1;
    assert.equal(CanonicalMerkleTree.verify("sealed-sha", changed, 3, path, tree.root), false);
    const changedPath = path.map((node) => new Uint8Array(node));
    changedPath[0]![0] ^= 1;
    assert.equal(CanonicalMerkleTree.verify("sealed-sha", rows[3]!, 3, changedPath, tree.root), false);
  });

  it("matches the Rust row-commitment known-answer vector", () => {
    const columns = [
      [3, 17, 31, 45],
      [1003, 1017, 1031, 1045],
    ];
    const matrixRows = columns[0]!.map((_, row) => {
      const raw = new Uint8Array(8);
      const view = new DataView(raw.buffer);
      view.setUint32(0, columns[0]![row]!, true);
      view.setUint32(4, columns[1]![row]!, true);
      return raw;
    });
    assert.equal(
      Buffer.from(new CanonicalMerkleTree("kat-matrix", matrixRows).root).toString("hex"),
      "2068701f436d3535d7444aed74a1bee641bd92e6c61f3c79e4f71eb82ccc6401",
    );
  });

  it("opens a minimal shared frontier and rejects every changed component", () => {
    const tree = new CanonicalMerkleTree("sealed-sha", rows);
    const indices = [0, 1, 2, 7, 8, 15];
    const opened = indices.map((index) => ({ index, raw: rows[index]! }));
    const siblings = tree.multiproof(indices);
    assert.equal(siblings.length < indices.length * 4, true);
    assert.equal(CanonicalMerkleTree.verifyMany("sealed-sha", opened, siblings, 16, tree.root), true);

    const changedRows = opened.map(({ index, raw }) => ({ index, raw: new Uint8Array(raw) }));
    changedRows[2]!.raw[0] ^= 1;
    assert.equal(CanonicalMerkleTree.verifyMany("sealed-sha", changedRows, siblings, 16, tree.root), false);
    const changedSiblings = siblings.map((node) => new Uint8Array(node));
    changedSiblings[0]![0] ^= 1;
    assert.equal(CanonicalMerkleTree.verifyMany("sealed-sha", opened, changedSiblings, 16, tree.root), false);
    assert.equal(CanonicalMerkleTree.verifyMany("sealed-bus", opened, siblings, 16, tree.root), false);
    assert.equal(CanonicalMerkleTree.verifyMany("sealed-sha", opened, siblings.slice(1), 16, tree.root), false);
  });
});

describe("canonical radix-4 Merkle tree", () => {
  const values = Array.from(
    { length: 16 },
    (_, row): QM31El => [
      BigInt(row * 101 + 9),
      BigInt(row * 101 + 26),
      BigInt(row * 101 + 43),
      BigInt(row * 101 + 60),
    ],
  );
  const rows = values.map(encodeQm31);
  const indices = [0, 1, 2, 7, 8, 15];

  it("matches Rust and verifies one minimal four-way frontier", () => {
    const tree = new CanonicalMerkleTree4("fri:layer:0", rows);
    assert.equal(
      Buffer.from(tree.root).toString("hex"),
      "8e85e234ddfe4efce5b2fc1f640d008976de4b8142b11ca8ebac26ba8dd8967f",
    );
    const siblings = tree.multiproof(indices);
    assert.equal(siblings.length, 10);
    const opened = indices.map((index) => ({ index, raw: rows[index]! }));
    assert.equal(CanonicalMerkleTree4.verifyMany("fri:layer:0", opened, siblings, 16, tree.root), true);

    const changedRows = opened.map(({ index, raw }) => ({ index, raw: new Uint8Array(raw) }));
    changedRows[2]!.raw[0] ^= 1;
    assert.equal(CanonicalMerkleTree4.verifyMany("fri:layer:0", changedRows, siblings, 16, tree.root), false);
    const changedSiblings = siblings.map((node) => new Uint8Array(node));
    changedSiblings[0]![0] ^= 1;
    assert.equal(CanonicalMerkleTree4.verifyMany("fri:layer:0", opened, changedSiblings, 16, tree.root), false);
    assert.equal(CanonicalMerkleTree4.verifyMany("fri:layer:1", opened, siblings, 16, tree.root), false);
    assert.equal(CanonicalMerkleTree4.verifyMany("fri:layer:0", opened, siblings.slice(1), 16, tree.root), false);
  });

  it("derives the one canonical cross-gate frontier", () => {
    const tree = new CanonicalMerkleTree4("fri:layer:0", rows);
    const siblings = tree.multiproof(indices);
    const opened = indices.map((index) => ({ index, raw: rows[index]! }));
    const frontier = canonicalMerkleFrontier4("fri:layer:0", opened, siblings, 16, 1);
    assert.deepEqual(frontier.nodes.map(({ index }) => index), [0, 1, 2, 3]);
    assert.equal(frontier.siblingCount, 10);
    assert.equal(encodeCanonicalMerkleFrontier4(frontier).length, 4 * 36);
    frontier.nodes.forEach(({ index, hash }) => assert.deepEqual(hash, tree.layers[1]![index]));
  });
});

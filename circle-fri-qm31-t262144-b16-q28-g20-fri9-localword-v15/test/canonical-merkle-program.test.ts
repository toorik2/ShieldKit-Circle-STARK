import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { CanonicalMerkleTree } from "../src/backends/circle/canonical-merkle.ts";
import {
  canonicalMerkleProgram,
  verifyCanonicalMerkleProgram,
} from "../src/backends/circle/canonical-merkle-program.ts";

describe("canonical Merkle queue program", () => {
  it("is uniquely derived, covers every input, and rejects an altered opcode", () => {
    const rows = Array.from({ length: 64 }, (_, row) =>
      Uint8Array.from({ length: 13 }, (_, byte) => (row * 17 + byte * 29) & 0xff));
    const indices = [0, 1, 5, 17, 31, 32, 47, 63];
    const tree = new CanonicalMerkleTree("queue-program-kat", rows);
    const siblings = tree.multiproof(indices);
    const program = canonicalMerkleProgram(indices, siblings.length, rows.length);
    assert.equal(program.length, indices.length + siblings.length - 1);
    assert.equal(verifyCanonicalMerkleProgram({
      label: "queue-program-kat",
      indices,
      rows: indices.map((index) => rows[index]!),
      siblings,
      rowCount: rows.length,
      root: tree.root,
      program,
    }), true);
    const altered = new Uint8Array(program);
    altered[Math.floor(altered.length / 2)]! ^= 1;
    assert.equal(verifyCanonicalMerkleProgram({
      label: "queue-program-kat",
      indices,
      rows: indices.map((index) => rows[index]!),
      siblings,
      rowCount: rows.length,
      root: tree.root,
      program: altered,
    }), false);
  });
});

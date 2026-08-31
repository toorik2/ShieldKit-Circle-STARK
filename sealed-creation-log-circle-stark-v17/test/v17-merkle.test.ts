import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  V17MerkleTree,
  decodeV17MerkleOpening,
  encodeV17MerkleOpening,
  maximumV17MerkleOpening,
  v17ProductionMerkleDescriptors,
  v17MerkleSchedule,
  v17MerkleTreeKey,
  verifyV17MerkleOpening,
  type V17MerkleDescriptor,
} from "../src/backends/circle/v17-merkle.ts";
import {
  planV17MerkleStages,
  verifyV17MerklePlanCertificate,
} from "../src/chain/v17-merkle-planner.ts";
import { bytesToHex } from "../src/pool/bytes.ts";

function fixtureRows(count: number): Uint8Array[] {
  return Array.from({ length: count }, (_, index) =>
    Uint8Array.of(index, index ^ 0x55, 0xff - index, index * 17));
}

function indicesFromMask(mask: number, width: number): number[] {
  return Array.from({ length: width }, (_, index) => index)
    .filter((index) => (mask & (1 << index)) !== 0);
}

function mutate(bytes: Uint8Array, offset: number): Uint8Array {
  const changed = bytes.slice();
  changed[offset]! ^= 1;
  return changed;
}

function focusedSixteenLeafMasks(): readonly number[] {
  const masks = new Set<number>();
  const full = 0xffff;
  for (let left = 0; left < 16; left += 1) {
    masks.add(1 << left);
    masks.add(full ^ (1 << left));
    masks.add((1 << (left + 1)) - 1);
    masks.add(full ^ ((1 << left) - 1));
    for (let right = left + 1; right < 16; right += 1) {
      masks.add((1 << left) | (1 << right));
    }
  }
  masks.add(0x5555);
  masks.add(0xaaaa);
  masks.add(0x0f0f);
  masks.add(0xf0f0);
  let state = 0x6d2b79f5;
  while (masks.size < 512) {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    const mask = state & full;
    if (mask !== 0) masks.add(mask);
  }
  return [...masks].sort((left, right) => left - right);
}

describe("v17 canonical Merkle descriptor", () => {
  const rows = fixtureRows(8);
  const binary: V17MerkleDescriptor = {
    shape: "binary",
    label: "kat:rows",
    logRows: 3,
    rowWidth: 4,
  };
  const mixed: V17MerkleDescriptor = { ...binary, shape: "quartet-first" };

  it("locks the exact domain-separated binary and quartet-first vectors", () => {
    assert.equal(
      bytesToHex(v17MerkleTreeKey(binary)),
      "8c7291742b1976210a11ba281959ad1c3460a868cddc24b821f53e16d66fd629",
    );
    assert.equal(
      bytesToHex(new V17MerkleTree(binary, rows).root),
      "e5909628ca401674f421f4bd3ac98a3aec2a5b320388bba8e1d24ef6c7dde556",
    );
    assert.equal(
      bytesToHex(v17MerkleTreeKey(mixed)),
      "4a654d86d56f931b94e16537c3c74ffb630698515e320889cc9ec0587242235f",
    );
    assert.equal(
      bytesToHex(new V17MerkleTree(mixed, rows).root),
      "4e10757cb6738da05b36a3ca0eb2864997747797d7b4ba6548bfd52f189b076e",
    );
  });

  it("rejects noncanonical descriptors and row sets", () => {
    assert.throws(() => v17MerkleTreeKey({ ...binary, label: "not canonical" }), /label/);
    assert.throws(() => v17MerkleTreeKey({ ...binary, label: "mérkle" }), /label/);
    assert.throws(() => v17MerkleTreeKey({ ...mixed, logRows: 1 }), /geometry/);
    assert.throws(() => v17MerkleTreeKey({ ...binary, rowWidth: 0 }), /width/);
    assert.throws(() => new V17MerkleTree(binary, rows.slice(1)), /tree rows/);
    assert.throws(() => new V17MerkleTree(binary, [new Uint8Array(3), ...rows.slice(1)]), /tree rows/);
  });

  it("locks the complete production commitment inventory", () => {
    const production = v17ProductionMerkleDescriptors();
    assert.deepEqual(production.matrices, {
      preprocessed: {
        shape: "binary", label: "local-word:preprocessed", logRows: 24, rowWidth: 172,
      },
      original: {
        shape: "binary", label: "local-word:original", logRows: 24, rowWidth: 136,
      },
      interaction: {
        shape: "binary", label: "local-word:interaction", logRows: 24, rowWidth: 224,
      },
      interactionGlobal: {
        shape: "binary", label: "local-word:interaction-global", logRows: 24, rowWidth: 48,
      },
      quotientAndFriMask: {
        shape: "binary", label: "local-word:quotient-and-fri-mask", logRows: 24, rowWidth: 32,
      },
    });
    assert.deepEqual(production.fri, [24, 22, 20, 18, 16, 14, 12, 10, 8]
      .map((logRows, layer) => ({
        shape: layer < 8 ? "quartet-first" : "binary",
        label: `fri:layer:${layer}`,
        logRows,
        rowWidth: 16,
      })));
    const second = v17ProductionMerkleDescriptors();
    assert.notEqual(second.matrices.preprocessed, production.matrices.preprocessed);
    assert.notEqual(second.fri[0], production.fri[0]);
  });
});

describe("v17 one traversal and strict opening codec", () => {
  for (const shape of ["binary", "quartet-first"] as const) {
    it(`round-trips every nonempty eight-leaf ${shape} opening`, () => {
      const descriptor: V17MerkleDescriptor = {
        shape,
        label: `exhaustive:${shape}`,
        logRows: 3,
        rowWidth: 4,
      };
      const tree = new V17MerkleTree(descriptor, fixtureRows(8));
      const cutBits = shape === "binary" ? [0, 1, 2] : [0, 2];
      const rowCount = 2 ** descriptor.logRows;
      for (let mask = 1; mask < 2 ** rowCount; mask += 1) {
        const indices = indicesFromMask(mask, 8);
        const opening = tree.opening(indices);
        const encoded = encodeV17MerkleOpening({
          descriptor,
          rows: opening.rows,
          siblings: opening.siblings,
          cutBits,
        });
        const decoded = decodeV17MerkleOpening(encoded, {
          descriptor,
          indices,
          cutBits,
          expectedRoot: tree.root,
        });
        assert.deepEqual(decoded.rows, opening.rows);
        assert.deepEqual(decoded.siblings, opening.siblings);
        assert.deepEqual(decoded.root, tree.root);
        assert.equal(
          encoded.length,
          indices.length * descriptor.rowWidth +
            v17MerkleSchedule(descriptor, indices).siblingCount * 32 +
            decoded.cuts.reduce((sum, cut) => sum + cut.nodes.length * 36, 0),
        );
      }
    });
  }

  for (const shape of ["binary", "quartet-first"] as const) {
    it(`cross-checks a 512-subset sixteen-leaf ${shape} codec corpus`, () => {
      const descriptor: V17MerkleDescriptor = {
        shape,
        label: `codec16:${shape}`,
        logRows: 4,
        rowWidth: 4,
      };
      const tree = new V17MerkleTree(descriptor, fixtureRows(16));
      const cutBits = shape === "binary" ? [0, 1, 3] : [0, 2, 3];
      for (const mask of focusedSixteenLeafMasks()) {
        const indices = indicesFromMask(mask, 16);
        const opening = tree.opening(indices);
        const encoded = encodeV17MerkleOpening({
          descriptor,
          rows: opening.rows,
          siblings: opening.siblings,
          cutBits,
        });
        assert.equal(verifyV17MerkleOpening(encoded, {
          descriptor,
          indices,
          cutBits,
          expectedRoot: tree.root,
        }), true, `mask=${mask.toString(16)}`);
      }
    });
  }

  it("rejects every malformed or context-substituted component", () => {
    const descriptor: V17MerkleDescriptor = {
      shape: "quartet-first",
      label: "adversarial:opening",
      logRows: 3,
      rowWidth: 4,
    };
    const indices = [0, 1, 2, 7];
    const cutBits = [0, 2];
    const tree = new V17MerkleTree(descriptor, fixtureRows(8));
    const opening = tree.opening(indices);
    const encoded = encodeV17MerkleOpening({
      descriptor,
      rows: opening.rows,
      siblings: opening.siblings,
      cutBits,
    });
    const schedule = v17MerkleSchedule(descriptor, indices);
    const cutStart = indices.length * descriptor.rowWidth + schedule.siblingCount * 32;
    const wrongRoot = mutate(tree.root, 0);
    const verify = (bytes: Uint8Array, overrides: Partial<Parameters<typeof verifyV17MerkleOpening>[1]> = {}) =>
      verifyV17MerkleOpening(bytes, {
        descriptor,
        indices,
        cutBits,
        expectedRoot: tree.root,
        ...overrides,
      });

    assert.equal(verify(encoded), true);
    assert.equal(verify(mutate(encoded, 0)), false, "row");
    assert.equal(verify(mutate(encoded, indices.length * descriptor.rowWidth)), false, "sibling");
    assert.equal(verify(mutate(encoded, cutStart)), false, "cut index");
    assert.equal(verify(mutate(encoded, cutStart + 4)), false, "cut hash");
    assert.equal(verify(encoded, { expectedRoot: wrongRoot }), false, "root");
    assert.equal(verify(encoded.slice(0, -1)), false, "truncated");
    assert.equal(verify(new Uint8Array([...encoded, 0])), false, "trailing");
    assert.equal(verify(encoded, {
      descriptor: { ...descriptor, shape: "binary" },
    }), false, "shape");
    assert.equal(verify(encoded, {
      descriptor: { ...descriptor, label: "adversarial:other" },
    }), false, "label");
    assert.equal(verify(encoded, {
      descriptor: { ...descriptor, rowWidth: 5 },
    }), false, "row width");
    assert.throws(() => decodeV17MerkleOpening(encoded, {
      descriptor,
      indices: [1, 0, 2, 7],
      cutBits,
    }), /indices/);
    assert.throws(() => decodeV17MerkleOpening(encoded, {
      descriptor,
      indices: [0, 1, 1, 7],
      cutBits,
    }), /indices/);
    assert.throws(() => encodeV17MerkleOpening({
      descriptor,
      rows: opening.rows,
      siblings: opening.siblings.slice(1),
      cutBits,
    }), /siblings/);
    assert.throws(() => encodeV17MerkleOpening({
      descriptor,
      rows: opening.rows,
      siblings: opening.siblings,
      cutBits: [2, 0],
    }), /cuts/);
    assert.throws(() => encodeV17MerkleOpening({
      descriptor,
      rows: opening.rows,
      siblings: opening.siblings,
      cutBits: [1],
    }), /cuts/);
  });

  it("rejects reordered and mutated sixteen-leaf authentication material", () => {
    const descriptor: V17MerkleDescriptor = {
      shape: "quartet-first",
      label: "adversarial:opening16",
      logRows: 4,
      rowWidth: 4,
    };
    const indices = [0, 1, 2, 3, 5, 8, 14, 15];
    const cutBits = [0, 2, 3];
    const tree = new V17MerkleTree(descriptor, fixtureRows(16));
    const opening = tree.opening(indices);
    const encoded = encodeV17MerkleOpening({
      descriptor,
      rows: opening.rows,
      siblings: opening.siblings,
      cutBits,
    });
    const siblingStart = indices.length * descriptor.rowWidth;
    const cutStart = siblingStart + opening.siblings.length * 32;
    const verify = (bytes: Uint8Array, expectedIndices: readonly number[] = indices) =>
      verifyV17MerkleOpening(bytes, {
        descriptor,
        indices: expectedIndices,
        cutBits,
        expectedRoot: tree.root,
      });
    assert.equal(verify(encoded), true);
    assert.equal(verify(mutate(encoded, siblingStart)), false);
    assert.equal(verify(mutate(encoded, cutStart)), false);
    assert.equal(verify(encoded, [0, 1, 2, 3, 5, 9, 14, 15]), false);
    assert.ok(opening.siblings.length >= 2);
    const reordered = encoded.slice();
    const first = reordered.slice(siblingStart, siblingStart + 32);
    const second = reordered.slice(siblingStart + 32, siblingStart + 64);
    reordered.set(second, siblingStart);
    reordered.set(first, siblingStart + 32);
    assert.equal(verify(reordered), false);
  });
});

describe("v17 all-schedule recurrence", () => {
  for (const shape of ["binary", "quartet-first"] as const) {
    it(`is tight for every arbitrary opening of a 16-leaf ${shape} tree`, () => {
      const descriptor: V17MerkleDescriptor = {
        shape,
        label: `recurrence:${shape}`,
        logRows: 4,
        rowWidth: 1,
      };
      const observed = Array.from({ length: 17 }, () => -1);
      for (let mask = 1; mask < 1 << 16; mask += 1) {
        const indices = indicesFromMask(mask, 16);
        observed[indices.length] = Math.max(
          observed[indices.length]!,
          v17MerkleSchedule(descriptor, indices).siblingCount,
        );
      }
      for (let openedLeaves = 1; openedLeaves <= 16; openedLeaves += 1) {
        assert.equal(
          maximumV17MerkleOpening(descriptor, { openedLeaves }).siblingCount,
          observed[openedLeaves],
          `openedLeaves=${openedLeaves}`,
        );
      }
    });

    it(`is tight for complete first-level groups in a 16-leaf ${shape} tree`, () => {
      const descriptor: V17MerkleDescriptor = {
        shape,
        label: `cosets:${shape}`,
        logRows: 4,
        rowWidth: 1,
      };
      const arity = shape === "binary" ? 2 : 4;
      const groupCount = 16 / arity;
      const observed = Array.from({ length: groupCount + 1 }, () => -1);
      for (let mask = 1; mask < 1 << groupCount; mask += 1) {
        const groups = indicesFromMask(mask, groupCount);
        const indices = groups.flatMap((group) =>
          Array.from({ length: arity }, (_, child) => group * arity + child));
        observed[groups.length] = Math.max(
          observed[groups.length]!,
          v17MerkleSchedule(descriptor, indices).siblingCount,
        );
      }
      for (let groups = 1; groups <= groupCount; groups += 1) {
        assert.equal(
          maximumV17MerkleOpening(descriptor, { completeFirstGroups: groups }).siblingCount,
          observed[groups],
          `groups=${groups}`,
        );
      }
    });
  }

  it("locks the historical q29 authentication ceiling under v17 geometry", () => {
    const production = v17ProductionMerkleDescriptors();
    const matrixNodes = Object.entries(production.matrices).reduce(
      (sum, [name, descriptor]) => sum + maximumV17MerkleOpening(
        descriptor,
        { openedLeaves: name === "interactionGlobal" ? 58 : 29 },
      ).siblingCount,
      0,
    );
    const friNodes = production.fri.reduce((sum, descriptor) =>
      sum + maximumV17MerkleOpening(descriptor, { completeFirstGroups: 29 }).siblingCount, 0);
    assert.equal(matrixNodes, 3_266);
    assert.equal(friNodes, 2_405);
    assert.equal(matrixNodes + friNodes, 5_671);
    assert.equal((matrixNodes + friNodes) * 32, 181_472);
  });

  it("reproduces 5,374 nodes for the frozen v16 schedule under v17 geometry", () => {
    const queries = [
      9_112_211, 14_212_599, 13_549_215, 8_366_956, 13_255_966, 8_836_866,
      3_755_068, 5_697_842, 15_011_300, 3_853_091, 13_216_405, 10_314_408,
      490_047, 1_977_320, 16_379_213, 5_305_657, 6_661_832, 3_298_150,
      1_780_329, 8_732_740, 8_129_591, 1_274_824, 16_158_534, 14_475_313,
      8_952_495, 7_305_278, 7_724_622, 9_538_226, 5_778_552,
    ];
    const sortedUnique = (values: readonly number[]) => [...new Set(values)].sort((a, b) => a - b);
    const bitReverse = (value: number, bits: number): number => {
      let result = 0;
      for (let bit = 0; bit < bits; bit += 1) result = result * 2 + ((value >>> bit) & 1);
      return result;
    };
    const predecessor = (index: number): number => {
      let natural = bitReverse(index, 24);
      const half = 2 ** 23;
      const step = -(2 ** 5);
      natural = natural < half
        ? ((natural + step) % half + half) % half
        : ((natural - half - step) % half + half) % half + half;
      return bitReverse(natural, 24);
    };
    const current = sortedUnique(queries);
    const global = sortedUnique(queries.flatMap((query) => [query, predecessor(query)]));
    const matrixDescriptor: V17MerkleDescriptor = {
      shape: "binary",
      label: "actual:matrix",
      logRows: 24,
      rowWidth: 16,
    };
    let nodes = 4 * v17MerkleSchedule(matrixDescriptor, current).siblingCount +
      v17MerkleSchedule(matrixDescriptor, global).siblingCount;
    let positions = [...queries];
    const foldCounts = [2, 2, 2, 2, 2, 2, 2, 2, 1];
    let logRows = 24;
    foldCounts.forEach((folds, layer) => {
      const arity = 2 ** folds;
      const opened = sortedUnique(positions.flatMap((position) => {
        const base = position - (position % arity);
        return Array.from({ length: arity }, (_, child) => base + child);
      }));
      nodes += v17MerkleSchedule({
        shape: folds === 2 ? "quartet-first" : "binary",
        label: `fri:layer:${layer}`,
        logRows,
        rowWidth: 16,
      }, opened).siblingCount;
      positions = sortedUnique(positions.map((position) => Math.floor(position / arity)));
      logRows -= folds;
    });
    assert.equal(nodes, 5_374);
    assert.equal(nodes * 32, 171_968);
  });
});

describe("v17 deterministic stage planner", () => {
  const binaryInput = {
    descriptor: {
      shape: "binary" as const,
      label: "planner:binary",
      logRows: 4,
      rowWidth: 16,
    },
    opening: { openedLeaves: 3 },
    weights: { leafHash: 1, binaryParent: 2, quartetParent: 3 },
    limits: { maxWork: 10, maxHandoffBytes: 1_000 },
  };

  it("proves the minimal three-stage, minimum-handoff binary partition", () => {
    const plan = planV17MerkleStages(binaryInput);
    assert.deepEqual(plan.cuts, [1, 3]);
    assert.deepEqual(plan.stages.map(({ work }) => work), [9, 10, 2]);
    assert.equal(plan.serializedCutBytes, 180);
    assert.equal(plan.certificate.selectedStageCount, 3);
    assert.equal(plan.certificate.minimumStagesToBoundary.at(-1), 3);
    assert.equal(
      plan.certificate.edges.find(({ startLevel, endLevel }) => startLevel === 0 && endLevel === 4)!
        .rejectedBy.includes("work"),
      true,
    );
    assert.equal(verifyV17MerklePlanCertificate(plan.certificate), true);

    const changed = structuredClone(plan.certificate);
    (changed.selectedCuts as number[])[0] = 2;
    assert.equal(verifyV17MerklePlanCertificate(changed), false);
  });

  it("uses consumed-bit cuts and never splits the quartet", () => {
    const plan = planV17MerkleStages({
      descriptor: {
        shape: "quartet-first",
        label: "planner:mixed",
        logRows: 4,
        rowWidth: 16,
      },
      opening: { completeFirstGroups: 2 },
      weights: { leafHash: 1, binaryParent: 2, quartetParent: 2 },
      limits: { maxWork: 12, maxHandoffBytes: 1_000 },
    });
    assert.deepEqual(plan.cuts, [2]);
    assert.deepEqual(plan.stages.map(({ startBits, endBits }) => [startBits, endBits]), [
      [0, 2],
      [2, 4],
    ]);
  });

  it("collapses to one stage when the exact envelope permits it", () => {
    const plan = planV17MerkleStages({
      ...binaryInput,
      limits: { maxWork: 100, maxHandoffBytes: 1_000 },
    });
    assert.deepEqual(plan.cuts, []);
    assert.equal(plan.stages.length, 1);
    assert.equal(plan.serializedCutBytes, 0);
  });

  it("fails closed when no first stage fits", () => {
    assert.throws(() => planV17MerkleStages({
      ...binaryInput,
      limits: { maxWork: 8, maxHandoffBytes: 1_000 },
    }), /infeasible/);
  });
});

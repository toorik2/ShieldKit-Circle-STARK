import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { wWithdraw } from "../src/pool/relation-witness.ts";
import { qm31, qmEq, type QM31El } from "../src/backends/circle/qm31.ts";
import { compilePoolLocalShaGraph } from "../src/chain/pool-relation-local-word-machine.ts";
import {
  LocalShaCircuitBuilder,
  buildLocalShaTrace,
  executeLocalShaProgram,
  type LocalShaProgram,
  type LocalShaTrace,
} from "../src/chain/sha256-local-word-machine.ts";
import {
  buildLocalShaWordCopyTrace,
  compileLocalShaWordCopyPermutation,
  localShaWordCopyGeometry,
  localShaWordCopySoundness,
  verifyLocalShaWordCopyOccurrences,
  verifyLocalShaWordCopyTrace,
  type LocalShaWordCopyChallenges,
  type LocalShaWordCopyTrace,
} from "../src/chain/sha256-local-word-permutation.ts";
import { IncrementalMerkle, NullifierSet, type Note } from "../src/pool/notes.ts";
import { emptyState } from "../src/pool/state.ts";
import { applyDeposit, applyWithdraw } from "../src/pool/transition.ts";

const CHALLENGES: LocalShaWordCopyChallenges = {
  gamma: qm31(3n, 5n, 7n, 11n),
  identity: qm31(13n, 17n, 19n, 23n),
  limbs: [
    qm31(29n, 31n, 37n, 41n),
    qm31(43n, 47n, 53n, 59n),
    qm31(61n, 67n, 71n, 73n),
    qm31(79n, 83n, 89n, 97n),
    qm31(101n, 103n, 107n, 109n),
    qm31(113n, 127n, 131n, 137n),
    qm31(139n, 149n, 151n, 157n),
    qm31(163n, 167n, 173n, 179n),
  ],
};

function fixture(): { program: LocalShaProgram; trace: LocalShaTrace; rotationRow: number; maskRow: number } {
  const builder = new LocalShaCircuitBuilder();
  const left = builder.input("left");
  const right = builder.input("right");
  const mask = builder.mask("mask");
  builder.equalWord(left, right);
  const rotated = builder.rotate(left, 7, "rotated");
  const output = builder.xor(rotated, mask, "output");
  const program = builder.finish([[output]], []);
  const execution = executeLocalShaProgram(program, [0x1234_5678, 0x1234_5678, 0xffff_ffff]);
  return { program, trace: buildLocalShaTrace(program, execution), rotationRow: rotated, maskRow: mask };
}

function changedTrace(trace: LocalShaTrace, row: number, port: "a" | "b" | "out", limb: number): LocalShaTrace {
  const rows = trace.rows.map((value) => ({
    a: [...value.a],
    b: [...value.b],
    out: [...value.out],
    carry: [...value.carry],
  }));
  const word = rows[row]![port];
  word[limb] = (word[limb]! + 1n) % 16n;
  return { rows };
}

function changedInteraction(
  interaction: LocalShaWordCopyTrace,
  family: "compressed" | "products",
  column: number,
  row: number,
): LocalShaWordCopyTrace {
  const compressed: [QM31El[], QM31El[], QM31El[]] = [
    [...interaction.compressed[0]],
    [...interaction.compressed[1]],
    [...interaction.compressed[2]],
  ];
  const products: [QM31El[], QM31El[], QM31El[]] = [
    [...interaction.products[0]],
    [...interaction.products[1]],
    [...interaction.products[2]],
  ];
  const columns = family === "compressed" ? compressed : products;
  const value = columns[column]![row]!;
  columns[column]![row] = qm31((value[0] + 1n) % 2_147_483_647n, value[1], value[2], value[3]);
  return { relationRows: interaction.relationRows, compressed, products };
}

function fullGraph() {
  const note: Note = {
    amountSats: 20_000n,
    rho: new Uint8Array(32).fill(0x52),
    ownerSecret: new Uint8Array(32).fill(0xad),
  };
  const deposited = applyDeposit({
    state: emptyState(new Uint8Array(32).fill(0x31)),
    notes: new IncrementalMerkle(),
    nullifiers: new NullifierSet(),
  }, note);
  const withdrawn = applyWithdraw(
    deposited.machine,
    note,
    deposited.index,
    new Uint8Array(32).fill(0x70),
    7_777n,
  );
  return compilePoolLocalShaGraph(
    withdrawn.statement,
    wWithdraw(note, deposited.index, withdrawn.path, withdrawn.created),
  );
}

describe("word-compressed local SHA copy permutation", () => {
  it("checks one whole-word permutation, including unaligned rotations", () => {
    const { program, trace, rotationRow } = fixture();
    const permutation = compileLocalShaWordCopyPermutation(program);
    const interaction = buildLocalShaWordCopyTrace(program, trace, CHALLENGES, permutation);
    assert.equal(verifyLocalShaWordCopyTrace(program, trace, interaction, CHALLENGES), undefined);
    assert.equal(permutation.activeSlots, 9);

    const leftOutput = interaction.compressed[2][0]!;
    assert.equal(qmEq(interaction.compressed[0][rotationRow]!, leftOutput), true);
    assert.equal(qmEq(interaction.compressed[1][rotationRow]!, leftOutput), true);
  });

  it("rejects a broken word alias, mask, compression, and product", () => {
    const { program, trace, maskRow } = fixture();
    const honest = buildLocalShaWordCopyTrace(program, trace, CHALLENGES);

    const brokenAlias = changedTrace(trace, 1, "out", 0);
    const brokenAliasInteraction = buildLocalShaWordCopyTrace(program, brokenAlias, CHALLENGES);
    assert.equal(
      verifyLocalShaWordCopyTrace(program, brokenAlias, brokenAliasInteraction, CHALLENGES)?.constraint,
      "word-product-boundary",
    );

    const brokenMask = changedTrace(trace, maskRow, "out", 1);
    const brokenMaskInteraction = buildLocalShaWordCopyTrace(program, brokenMask, CHALLENGES);
    assert.equal(verifyLocalShaWordCopyTrace(program, brokenMask, brokenMaskInteraction, CHALLENGES)?.constraint,
      "mask-limb:1");

    assert.equal(
      verifyLocalShaWordCopyTrace(program, trace, changedInteraction(honest, "compressed", 0, 0), CHALLENGES)
        ?.constraint,
      "word-compress:a",
    );
    assert.equal(
      verifyLocalShaWordCopyTrace(program, trace, changedInteraction(honest, "products", 2, 0), CHALLENGES)
        ?.constraint,
      "word-product:out",
    );
  });

  it("refuses arbitrary nibble aliases instead of silently weakening them", () => {
    const builder = new LocalShaCircuitBuilder();
    const left = builder.input("left");
    const right = builder.input("right");
    builder.equalCell({ wire: left, limb: 0 }, { wire: right, limb: 1 });
    const program = builder.finish([[left]], []);
    assert.throws(() => compileLocalShaWordCopyPermutation(program), /unsupported cell alias/);
  });

  it("measures the complete withdrawal graph and keeps the named v15 floor", () => {
    const graph = fullGraph();
    const program = graph.program;
    assert.equal(
      verifyLocalShaWordCopyOccurrences(program, executeLocalShaProgram(program, graph.inputs)),
      undefined,
    );
    const geometry = localShaWordCopyGeometry(program);
    assert.deepEqual({
      relationRows: geometry.relationRows,
      legacyNibbleCopyQm31Columns: geometry.legacyNibbleCopyQm31Columns,
      wordCopyQm31Columns: geometry.wordCopyQm31Columns,
      preprocessedM31Columns: geometry.preprocessedM31Columns,
      interactionQm31Columns: geometry.interactionQm31Columns,
      previousQm31Columns: geometry.previousQm31Columns,
      openedM31ValuesPerQuery: geometry.openedM31ValuesPerQuery,
      openedM31ValuesPerQueryWithPoolBoundary: geometry.openedM31ValuesPerQueryWithPoolBoundary,
    }, {
      relationRows: 262_144,
      legacyNibbleCopyQm31Columns: 96,
      wordCopyQm31Columns: 6,
      preprocessedM31Columns: 40,
      interactionQm31Columns: 15,
      previousQm31Columns: 2,
      openedM31ValuesPerQuery: 142,
      openedM31ValuesPerQueryWithPoolBoundary: 153,
    });
    assert.equal(geometry.activeWordSlots, 728_097);
    const soundness = localShaWordCopySoundness(program);
    assert.equal(soundness.permutationPolynomialDegree, geometry.activeWordSlots);
    assert.equal(soundness.permutationDenominatorTerms, 786_432);
    assert.equal(soundness.lookupTerms, 1_945_961);
    assert.equal(soundness.publicBoundaryTerms, 34);
    assert.equal(soundness.constraintMixingTerms, 24);
    assert.equal(soundness.oracleBatchingTerms, 26);
    assert.equal(soundness.permutationBits > 104, true);
    assert.equal(soundness.lookupBits > 103, true);
    assert.equal(soundness.constraintMixingBits > 119, true);
    assert.equal(soundness.oracleBatchingBits > 119, true);
    assert.equal(soundness.friQueryConjectureBits, 104);
    assert.equal(soundness.classicalHashCollisionBits, 128);
    assert.equal(soundness.conservativeUnionBits > 101 && soundness.conservativeUnionBits < 102, true);
    assert.equal(soundness.conservativeUnionBits > 100, true);
    assert.equal(soundness.meetsFloor, true);
    assert.equal(soundness.claimBoundary, "fri-query-term-conjectural-classical-rom");
  });
});

import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { qm31, qmAdd } from "../src/backends/circle/qm31.ts";
import { sha256 } from "../src/pool/bytes.ts";
import {
  buildLocalShaTrace,
  buildLocalShaInteractionTrace,
  compileLocalShaProgram,
  compileLocalShaCopyCells,
  compileLocalShaCopyPermutation,
  executeLocalShaProgram,
  localShaCopyLogupSum,
  LOCAL_SHA_COPY_INACTIVE_ID,
  localShaGeometry,
  localShaLookupLogupSum,
  localShaOutputBytes,
  localShaProgramForMessages,
  localShaQm31IsZero,
  localShaRelationFrameAt,
  localShaSoundnessProjection,
  localShaTableMultiplicitiesForExecution,
  LocalShaCircuitBuilder,
  verifyLocalShaTrace,
  verifyLocalShaInteractionTrace,
  withLocalShaCopyAliases,
  type LocalShaTrace,
} from "../src/chain/sha256-local-word-machine.ts";

const COPY_CHALLENGES = {
  gamma: qm31(13n, 17n, 19n, 23n),
  identity: qm31(29n, 31n, 37n, 41n),
  value: qm31(43n, 47n, 53n, 59n),
};

const LOOKUP_CHALLENGES = {
  gamma: qm31(211n, 223n, 227n, 229n),
  tuple: [
    qm31(233n, 239n, 241n, 251n),
    qm31(257n, 263n, 269n, 271n),
    qm31(277n, 281n, 283n, 293n),
    qm31(307n, 311n, 313n, 317n),
    qm31(331n, 337n, 347n, 349n),
    qm31(353n, 359n, 367n, 373n),
  ] as const,
};

const INTERACTION_CHALLENGES = {
  lookup: LOOKUP_CHALLENGES,
  copy: [
    COPY_CHALLENGES,
    {
      gamma: qm31(379n, 383n, 389n, 397n),
      identity: qm31(401n, 409n, 419n, 421n),
      value: qm31(431n, 433n, 439n, 443n),
    },
  ] as const,
};

function cloneTrace(trace: LocalShaTrace): {
  rows: Array<{ a: bigint[]; b: bigint[]; out: bigint[]; carry: bigint[] }>;
} {
  return { rows: trace.rows.map((row) => ({
    a: [...row.a],
    b: [...row.b],
    out: [...row.out],
    carry: [...row.carry],
  })) };
}

describe("local four-bit SHA word machine", () => {
  it("reduces a generic word vector to one nonzero assertion", () => {
    const builder = new LocalShaCircuitBuilder();
    const left = builder.input("left");
    const right = builder.input("right");
    builder.assertSomeNonzero([left, right], "vector");
    const program = builder.finish([], []);

    const honest = buildLocalShaTrace(program, executeLocalShaProgram(program, [0, 0x10]));
    assert.equal(verifyLocalShaTrace(program, honest), undefined);

    const zero = buildLocalShaTrace(program, executeLocalShaProgram(program, [0, 0]));
    assert.equal(verifyLocalShaTrace(program, zero)?.constraint, "lookup");
  });

  it("selects with one private all-zero or all-one mask and rejects partial masks", () => {
    const builder = new LocalShaCircuitBuilder();
    const mask = builder.mask("private-direction");
    const whenZero = builder.input("left");
    const whenOne = builder.input("right");
    const selected = builder.select(mask, whenZero, whenOne, "private-select");
    const program = builder.finish([[selected]], [0]);

    for (const [maskValue, expected] of [[0, 0x1234_5678], [0xffff_ffff, 0x90ab_cdef]] as const) {
      const execution = executeLocalShaProgram(program, [maskValue, 0x1234_5678, 0x90ab_cdef]);
      const trace = buildLocalShaTrace(program, execution);
      assert.equal(execution.wireValues[selected], expected);
      assert.equal(verifyLocalShaTrace(program, trace), undefined);
      assert.equal(localShaQm31IsZero(localShaLookupLogupSum(program, trace, LOOKUP_CHALLENGES)), true);
      assert.equal(localShaQm31IsZero(localShaCopyLogupSum(program, trace, COPY_CHALLENGES)), true);
    }

    const partial = buildLocalShaTrace(program, executeLocalShaProgram(program, [0x0000_000f, 1, 2]));
    assert.match(verifyLocalShaTrace(program, partial)?.constraint ?? "", /^(copy:|lookup$)/);
    assert.equal(localShaQm31IsZero(localShaCopyLogupSum(program, partial, COPY_CHALLENGES)), false);
  });

  it("computes SHA-256 and closes its one copy and one lookup ledger", () => {
    const message = new TextEncoder().encode("abc");
    const { program, inputs } = localShaProgramForMessages([message]);
    const execution = executeLocalShaProgram(program, inputs);
    const trace = buildLocalShaTrace(program, execution);

    assert.deepEqual(localShaOutputBytes(program, execution, 0), sha256(message));
    assert.equal(verifyLocalShaTrace(program, trace), undefined);
    assert.equal(localShaQm31IsZero(localShaCopyLogupSum(program, trace, COPY_CHALLENGES)), true);
    assert.equal(localShaQm31IsZero(localShaLookupLogupSum(program, trace, LOOKUP_CHALLENGES)), true);
    assert.equal(program.rows.length, 2354);
  });

  it("rejects a locally valid word whose static copy was changed", () => {
    const { program, inputs } = localShaProgramForMessages([new TextEncoder().encode("copy falsifier")]);
    const execution = executeLocalShaProgram(program, inputs);
    const changed = cloneTrace(buildLocalShaTrace(program, execution));
    const row = program.rows.findIndex((instruction) => instruction.operation === "xor");
    assert.notEqual(row, -1);
    changed.rows[row]!.a[0] = (changed.rows[row]!.a[0]! + 1n) % 16n;
    const a = changed.rows[row]!.a.reduce((sum, limb, index) => sum | (Number(limb) << (index * 4)), 0) >>> 0;
    const b = changed.rows[row]!.b.reduce((sum, limb, index) => sum | (Number(limb) << (index * 4)), 0) >>> 0;
    const out = (a ^ b) >>> 0;
    changed.rows[row]!.out = Array.from({ length: 8 }, (_, index) => BigInt((out >>> (index * 4)) & 15));

    assert.match(verifyLocalShaTrace(program, changed)?.constraint ?? "", /^copy:/);
    assert.equal(localShaQm31IsZero(localShaCopyLogupSum(program, changed, COPY_CHALLENGES)), false);
  });

  it("makes cross-job semantic aliases part of the same copy ledger", () => {
    const message = new TextEncoder().encode("same semantic word");
    const built = localShaProgramForMessages([message, message]);
    const left = built.program.inputWires[0]!;
    const right = built.program.inputWires[16]!;
    const program = withLocalShaCopyAliases(built.program, Array.from({ length: 8 }, (_, limb) => [
      { wire: left, limb },
      { wire: right, limb },
    ] as const));
    const honest = buildLocalShaTrace(program, executeLocalShaProgram(program, built.inputs));
    assert.equal(verifyLocalShaTrace(program, honest), undefined);
    assert.equal(localShaQm31IsZero(localShaCopyLogupSum(program, honest, COPY_CHALLENGES)), true);

    const changedInputs = [...built.inputs];
    changedInputs[16] = (changedInputs[16]! ^ 1) >>> 0;
    const changed = buildLocalShaTrace(program, executeLocalShaProgram(program, changedInputs));
    assert.match(verifyLocalShaTrace(program, changed)?.constraint ?? "", /^copy:/);
    assert.equal(localShaQm31IsZero(localShaCopyLogupSum(program, changed, COPY_CHALLENGES)), false);
  });

  it("matches the compact full-graph copy permutation to the diagnostic compiler", () => {
    const built = localShaProgramForMessages([new TextEncoder().encode("copy permutation")]);
    const compact = compileLocalShaCopyPermutation(built.program);
    const diagnostic = compileLocalShaCopyCells(built.program);
    const ports = ["a", "b", "out"] as const;
    for (const cell of diagnostic) {
      const slot = cell.row * 24 + ports.indexOf(cell.port) * 8 + cell.limb;
      assert.equal(compact.identities[slot], Number(cell.identity));
      assert.equal(compact.sigmas[slot], Number(cell.sigma));
    }
    assert.equal(
      compact.identities.filter((identity) => identity !== Number(LOCAL_SHA_COPY_INACTIVE_ID)).length,
      diagnostic.length,
    );
  });

  it("builds exact 34/64-column relation frames without materializing the matrix", () => {
    const built = localShaProgramForMessages([new TextEncoder().encode("relation frame")]);
    const execution = executeLocalShaProgram(built.program, built.inputs);
    const permutation = compileLocalShaCopyPermutation(built.program);
    const multiplicities = localShaTableMultiplicitiesForExecution(built.program, execution);
    const frame = localShaRelationFrameAt(built.program, execution, permutation, multiplicities, 17);
    assert.equal(frame.original.length, 34);
    assert.equal(frame.preprocessed.length, 64);
    assert.equal(multiplicities.reduce((sum, value) => sum + value, 0), built.program.rows.length * 8);
    const padded = localShaRelationFrameAt(built.program, execution, permutation, multiplicities, 4095);
    assert.equal(padded.preprocessed[57], 0n, "padded row is inactive");
  });

  it("rejects an invalid lookup tuple and an invalid addition", () => {
    const { program, inputs } = localShaProgramForMessages([new Uint8Array([1, 2, 3, 4, 5])]);
    const execution = executeLocalShaProgram(program, inputs);
    const trace = buildLocalShaTrace(program, execution);

    const badLookup = cloneTrace(trace);
    const xorRow = program.rows.findIndex((instruction) => instruction.operation === "xor");
    badLookup.rows[xorRow]!.out[0] = (badLookup.rows[xorRow]!.out[0]! + 1n) % 16n;
    assert.equal(localShaQm31IsZero(localShaLookupLogupSum(program, badLookup, LOOKUP_CHALLENGES)), false);

    const badAdd = cloneTrace(trace);
    const addRow = program.rows.findIndex((instruction) => instruction.operation === "add");
    badAdd.rows[addRow]!.carry[1] ^= 1n;
    assert.equal(verifyLocalShaTrace(program, badAdd)?.constraint, "add-identity");
  });

  it("builds the exact quadratic interaction columns and rejects a changed accumulator", () => {
    const { program, inputs } = localShaProgramForMessages([new TextEncoder().encode("interaction")]);
    const trace = buildLocalShaTrace(program, executeLocalShaProgram(program, inputs));
    const interaction = buildLocalShaInteractionTrace(program, trace, INTERACTION_CHALLENGES);
    assert.equal(interaction.columns.length, 105);
    assert.equal(interaction.relationRows, 4096);
    assert.equal(verifyLocalShaInteractionTrace(program, trace, interaction, INTERACTION_CHALLENGES), undefined);

    const columns = interaction.columns.map((column) => [...column]);
    columns[0]![0] = qmAdd(columns[0]![0]!, qm31(1n, 0n, 0n, 0n));
    assert.equal(verifyLocalShaInteractionTrace(
      program,
      trace,
      { ...interaction, columns },
      INTERACTION_CHALLENGES,
    )?.constraint, "interaction:0");
  });

  it("fits the complete 106-compression workload in a 2^18 relation table", () => {
    const program = compileLocalShaProgram(Array<number>(106).fill(1));
    const geometry = localShaGeometry(program);
    assert.deepEqual(geometry, {
      activeRows: 241754,
      relationRows: 262144,
      sealedDegreeBound: 524288,
      quotientDegreeBound: 1048576,
      ldeRows: 16777216,
      openedM31ValuesPerQuery: 522,
      directValueBytes: 58464,
    });
    const soundness = localShaSoundnessProjection(program);
    assert.equal(soundness.lookupTerms, 1935873);
    assert.equal(soundness.copyTermsPerLane, 6291456);
    assert.equal(soundness.lookupBits > 102 && soundness.lookupBits < 104, true);
    assert.equal(soundness.singleCopyLaneBits > 101 && soundness.singleCopyLaneBits < 102, true);
    assert.equal(soundness.independentCopyLanesBits > 202, true);
    assert.equal(soundness.friQueryConjectureBits, 104);
    assert.equal(soundness.conservativeUnionBits > 101, true);
    assert.equal(soundness.meetsFloor, true);
    assert.equal(soundness.claimBoundary, "projection-pending-quotient-and-transcript-integration");
  });
});

import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { add as mAdd } from "../src/backends/circle/m31.ts";
import { QM31_ZERO, qm31, qmEq } from "../src/backends/circle/qm31.ts";
import {
  LOCAL_WORD_V14_AIR_CONSTRAINTS,
  combineLocalWordV14AirCompositionPartials,
  localWordV14AirCompositionPartials,
  localWordV14AirResiduals,
  mixLocalWordV14AirResiduals,
  type LocalWordV14AirFrame,
} from "../src/backends/circle/local-word-air-v14.ts";
import type { LocalWordV14InteractionChallenges } from "../src/backends/circle/local-word-transcript-v14.ts";
import {
  buildPoolLocalBoundaryTrace,
  poolLocalBoundaryPreprocessedAt,
} from "../src/chain/pool-relation-local-word-boundary.ts";
import type { PoolLocalShaGraph } from "../src/chain/pool-relation-local-word-machine.ts";
import {
  LocalShaCircuitBuilder,
  buildLocalShaTrace,
  executeLocalShaProgram,
  localShaTableMultiplicitiesForExecution,
} from "../src/chain/sha256-local-word-machine.ts";
import { buildLocalShaV14InteractionTrace } from "../src/chain/sha256-local-word-interaction-v14.ts";
import {
  compileLocalShaWordCopyPermutation,
  localShaWordRelationFrameAt,
} from "../src/chain/sha256-local-word-permutation.ts";

const CHALLENGES: LocalWordV14InteractionChallenges = {
  lookup: {
    gamma: qm31(211n, 223n, 227n, 229n),
    tuple: [
      qm31(233n, 239n, 241n, 251n),
      qm31(257n, 263n, 269n, 271n),
      qm31(277n, 281n, 283n, 293n),
      qm31(307n, 311n, 313n, 317n),
      qm31(331n, 337n, 347n, 349n),
      qm31(353n, 359n, 367n, 373n),
    ],
  },
  wordCopy: {
    gamma: qm31(13n, 17n, 19n, 23n),
    identity: qm31(29n, 31n, 37n, 41n),
    limbs: Array.from({ length: 8 }, (_, limb) =>
      qm31(BigInt(43 + 18 * limb), BigInt(47 + 18 * limb), BigInt(53 + 18 * limb), BigInt(59 + 18 * limb))) as
      unknown as LocalWordV14InteractionChallenges["wordCopy"]["limbs"],
  },
  boundary: {
    gamma: qm31(379n, 383n, 389n, 397n),
    identity: qm31(401n, 409n, 419n, 421n),
    limbs: Array.from({ length: 8 }, (_, limb) =>
      qm31(BigInt(431 + 18 * limb), BigInt(433 + 18 * limb), BigInt(439 + 18 * limb), BigInt(443 + 18 * limb))) as
      unknown as LocalWordV14InteractionChallenges["boundary"]["limbs"],
  },
};

function fixture() {
  const builder = new LocalShaCircuitBuilder();
  const input = builder.input("public-input");
  const mask = builder.mask("private-mask");
  const rotated = builder.rotate(input, 7, "rotated");
  const output = builder.xor(rotated, mask, "output");
  const program = builder.finish([[output]], []);
  const inputs = [0x1234_5678, 0xffff_ffff];
  const graph: PoolLocalShaGraph = {
    profile: "deposit",
    program,
    inputs,
    inputLayout: [{
      input: 0,
      wire: input,
      label: "public-input",
      visibility: "public",
      value: inputs[0]!,
    }],
    boundaries: [],
    hashes: [],
    amountWires: { primary: [input], relation: "deposit-public-equality" },
    compressions: 0,
    hasChange: false,
    minerFeeSats: 0n,
  };
  const execution = executeLocalShaProgram(program, inputs);
  const trace = buildLocalShaTrace(program, execution);
  const permutation = compileLocalShaWordCopyPermutation(program);
  const multiplicities = localShaTableMultiplicitiesForExecution(program, execution);
  const coreInteraction = buildLocalShaV14InteractionTrace(program, trace, CHALLENGES);
  const boundary = buildPoolLocalBoundaryTrace(graph, execution, CHALLENGES.boundary);
  return { graph, execution, permutation, multiplicities, coreInteraction, boundary, mask, rotated };
}

function frameAt(built: ReturnType<typeof fixture>, row: number): LocalWordV14AirFrame {
  const core = localShaWordRelationFrameAt(
    built.graph.program,
    built.execution,
    built.permutation,
    built.multiplicities,
    row,
  );
  const previous = row === 0 ? built.coreInteraction.relationRows - 1 : row - 1;
  return {
    original: core.original,
    preprocessed: [...core.preprocessed, ...poolLocalBoundaryPreprocessedAt(built.graph, row)],
    interaction: [
      ...built.coreInteraction.columns.map((column) => column[row]!),
      built.boundary.columns[0][row]!,
      built.boundary.columns[1][row]!,
    ],
    interactionPrevious: [
      ...built.coreInteraction.columns.map((column) => column[previous]!),
      built.boundary.columns[0][previous]!,
      built.boundary.columns[1][previous]!,
    ],
  };
}

describe("version-14 word-compressed quadratic AIR", () => {
  it("vanishes on every honest row and pins the rotation selectors", () => {
    const built = fixture();
    const rotation = frameAt(built, built.rotated);
    assert.deepEqual(rotation.preprocessed.slice(9, 17), [0n, 1n, 0n, 0n, 0n, 0n, 0n, 0n]);
    assert.deepEqual(rotation.preprocessed.slice(17, 25), [0n, 0n, 1n, 0n, 0n, 0n, 0n, 0n]);
    for (let row = 0; row < built.coreInteraction.relationRows; row += 1) {
      const residuals = localWordV14AirResiduals(frameAt(built, row), CHALLENGES, built.boundary.claimedSum);
      assert.equal(residuals.length, LOCAL_WORD_V14_AIR_CONSTRAINTS);
      assert.deepEqual(
        residuals.flatMap((residual, index) => qmEq(residual, QM31_ZERO) ? [] : [index]),
        [],
        `row ${row}`,
      );
    }
  });

  it("rejects trace, selector, word product, mask, and public mutations", () => {
    const built = fixture();
    const alpha = qm31(5n, 7n, 11n, 13n);
    const assertRejects = (frame: LocalWordV14AirFrame, label: string): void => {
      const residuals = localWordV14AirResiduals(frame, CHALLENGES, built.boundary.claimedSum);
      assert.equal(residuals.some((residual) => !qmEq(residual, QM31_ZERO)), true, label);
      const mixed = mixLocalWordV14AirResiduals(residuals, alpha);
      assert.equal(qmEq(combineLocalWordV14AirCompositionPartials(
        localWordV14AirCompositionPartials(residuals, alpha),
        alpha,
      ), mixed), true, `${label} partials`);
      assert.equal(qmEq(mixed, QM31_ZERO), false, label);
    };

    const rotation = frameAt(built, built.rotated);
    const changedTrace = [...rotation.original];
    changedTrace[0] = mAdd(changedTrace[0]!, 1n);
    assertRejects({ ...rotation, original: changedTrace }, "trace");

    const changedShift = [...rotation.preprocessed];
    changedShift[10] = 0n;
    assertRejects({ ...rotation, preprocessed: changedShift }, "rotation selector");

    const changedProduct = [...rotation.interaction];
    changedProduct[12] = qm31(1n, 2n, 3n, 4n);
    assertRejects({ ...rotation, interaction: changedProduct }, "word product");

    const mask = frameAt(built, built.mask);
    const changedMask = [...mask.original];
    changedMask[17] = 0n;
    assertRejects({ ...mask, original: changedMask }, "mask consistency");

    const publicRow = frameAt(built, 0);
    const changedPublic = [...publicRow.preprocessed];
    changedPublic[42] = mAdd(changedPublic[42]!, 1n);
    assertRejects({ ...publicRow, preprocessed: changedPublic }, "public boundary");
  });
});

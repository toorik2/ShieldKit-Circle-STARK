import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { describe, it } from "node:test";
import {
  decodeLocalWordSealedProof,
  type LocalWordProofContext,
  type LocalWordSealedProof,
} from "../src/backends/circle/local-word-sealed-proof.ts";
import type { LocalWordProofParameters } from
  "../src/backends/circle/local-word-successor-params.ts";
import {
  localWordRelationZerofierAtBitReversed,
  verifyLocalWordSealedProof,
  verifyLocalWordSealedProofBytes,
} from "../src/backends/circle/local-word-verifier.ts";
import { QM31_ONE, qmAdd } from "../src/backends/circle/qm31.ts";

type RustFixtureManifest = {
  readonly profile: number;
  readonly transcriptInitialHex: string;
  readonly constructionDescriptorHex: string;
  readonly publicWords: readonly {
    readonly id: number;
    readonly row: number;
    readonly expected: number;
  }[];
  readonly expectedPreprocessedRootHex: string;
  readonly parameters: LocalWordProofParameters;
  readonly proofBytes: number;
  readonly zerofierIndices: readonly number[];
  readonly zerofierValues: readonly number[];
};

function fromHex(hex: string): Uint8Array {
  return new Uint8Array(Buffer.from(hex, "hex"));
}

function rustFixture(): {
  readonly bytes: Uint8Array;
  readonly context: LocalWordProofContext;
  readonly parameters: LocalWordProofParameters;
  readonly manifest: RustFixtureManifest;
} {
  const worker = spawnSync(
    "cargo",
    [
      "+nightly-2026-01-15",
      "run",
      "--quiet",
      "--manifest-path",
      "crates/circle-fri-worker/Cargo.toml",
      "--",
      "local-word-reference-fixture-binary",
    ],
    { cwd: process.cwd(), maxBuffer: 64 * 1024 * 1024 },
  );
  if (worker.status !== 0) throw new Error(worker.stderr.toString() || worker.stdout.toString());
  const manifest = JSON.parse(worker.stderr.toString().trim().split("\n").at(-1)!) as RustFixtureManifest;
  const bytes = new Uint8Array(worker.stdout);
  assert.equal(bytes.length, manifest.proofBytes);
  return {
    bytes,
    manifest,
    parameters: manifest.parameters,
    context: {
      profile: manifest.profile,
      transcriptInitial: fromHex(manifest.transcriptInitialHex),
      constructionDescriptor: fromHex(manifest.constructionDescriptorHex),
      publicWords: manifest.publicWords.map((word) => ({ ...word, id: BigInt(word.id) })),
      expectedPreprocessedRoot: fromHex(manifest.expectedPreprocessedRootHex),
    },
  };
}

function alterMatrixRow(
  proof: LocalWordSealedProof,
  name: "original" | "quotientAndFriMask",
): LocalWordSealedProof {
  const rows = proof.matrices[name].rows.map((row) => row.slice());
  rows[0]![0] ^= 1;
  return {
    ...proof,
    matrices: {
      ...proof.matrices,
      [name]: { ...proof.matrices[name], rows },
    },
  };
}

describe("independent local-word reference verifier", () => {
  it("accepts one exact Rust proof and rejects every mutated verifier boundary", () => {
    const { bytes, context, parameters, manifest } = rustFixture();
    assert.deepEqual(
      manifest.zerofierIndices.map((index) => Number(localWordRelationZerofierAtBitReversed(index, parameters))),
      manifest.zerofierValues,
    );
    const accepted = verifyLocalWordSealedProofBytes(bytes, context, parameters);
    assert.equal(accepted.ok, true, accepted.ok ? undefined : accepted.reason);
    const proof = decodeLocalWordSealedProof(bytes, context, parameters);

    for (const [label, altered] of [
      ["opening", alterMatrixRow(proof, "original")],
      ["mask", alterMatrixRow(proof, "quotientAndFriMask")],
      ["composition", {
        ...proof,
        compositionPartials: proof.compositionPartials.map((partials, query) => query === 0
          ? [qmAdd(partials[0], QM31_ONE), partials[1], partials[2]] as const
          : partials),
      }],
      ["fold", {
        ...proof,
        fri: {
          ...proof.fri,
          layers: proof.fri.layers.map((layer, round) => round === 0 ? {
            ...layer,
            values: layer.values.map((value, index) => index === 0 ? qmAdd(value, QM31_ONE) : value),
          } : layer),
        },
      }],
      ["root", {
        ...proof,
        matrices: {
          ...proof.matrices,
          original: {
            ...proof.matrices.original,
            root: proof.matrices.original.root.map((byte, index) => index === 0 ? byte ^ 1 : byte),
          },
        },
      }],
    ] as const) {
      const result = verifyLocalWordSealedProof(altered, context, parameters);
      assert.equal(result.ok, false, `${label} mutation accepted`);
    }

    const falseStatement = {
      ...context,
      publicWords: context.publicWords.map((word, index) => index === 0
        ? { ...word, expected: word.expected ^ 1 }
        : word),
    };
    assert.equal(verifyLocalWordSealedProofBytes(bytes, falseStatement, parameters).ok, false);

    const alteredBytes = bytes.slice();
    alteredBytes[alteredBytes.length - 1] ^= 1;
    assert.equal(verifyLocalWordSealedProofBytes(alteredBytes, context, parameters).ok, false);
  });
});

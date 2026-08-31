import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { describe, it } from "node:test";
import { bytesToHex, hexToBytes } from "../src/pool/bytes.ts";
import {
  decodeSuccessorFriProof,
  encodeSuccessorFriProof,
  verifySuccessorFri,
  type SuccessorFriConfig,
  type SuccessorFriProof,
} from "../src/backends/circle/successor-fri.ts";
import { SuccessorTranscript } from "../src/backends/circle/successor-transcript.ts";

type Fixture = {
  ok: true;
  proofHex: string;
  proofBytes: number;
  inputLog: number;
  config: SuccessorFriConfig;
};

function rustFixture(): Fixture {
  const result = spawnSync(
    "cargo",
    ["+nightly-2026-01-15", "run", "--quiet", "--manifest-path", "crates/circle-fri-worker/Cargo.toml"],
    { cwd: process.cwd(), input: '{"cmd":"successor-fri-fixture"}\n', encoding: "utf8" },
  );
  if (result.status !== 0) throw new Error(result.stderr || result.stdout);
  return JSON.parse(result.stdout.trim()) as Fixture;
}

function verifierTranscript(): SuccessorTranscript {
  const transcript = new SuccessorTranscript(new TextEncoder().encode("successor-fri-test"));
  transcript.absorb("statement", new TextEncoder().encode("fixed-public-statement"));
  return transcript;
}

function cloneProof(proof: SuccessorFriProof): SuccessorFriProof {
  return decodeSuccessorFriProof(encodeSuccessorFriProof(proof));
}

describe("cross-language successor Circle FRI", () => {
  it("decodes and verifies the exact Rust proof bytes in TypeScript", () => {
    const fixture = rustFixture();
    const encoded = hexToBytes(fixture.proofHex);
    const proof = decodeSuccessorFriProof(encoded);
    assert.equal(encoded.length, fixture.proofBytes);
    assert.equal(bytesToHex(encodeSuccessorFriProof(proof)), fixture.proofHex);
    assert.deepEqual(verifySuccessorFri(proof, fixture.inputLog, verifierTranscript(), fixture.config), { ok: true });
  });

  it("rejects altered roots, values, paths, final data, grind, and framing", () => {
    const fixture = rustFixture();
    const encoded = hexToBytes(fixture.proofHex);
    const proof = decodeSuccessorFriProof(encoded);
    const verify = (candidate: SuccessorFriProof) =>
      verifySuccessorFri(candidate, fixture.inputLog, verifierTranscript(), fixture.config).ok;

    const value = cloneProof(proof);
    (value.layers[0]!.values[0] as unknown as bigint[])[0] ^= 1n;
    assert.equal(verify(value), false);
    const path = cloneProof(proof);
    path.layers[0]!.siblings[0]![0] ^= 1;
    assert.equal(verify(path), false);
    const root = cloneProof(proof);
    root.layers[1]!.root[0] ^= 1;
    assert.equal(verify(root), false);
    const final = cloneProof(proof);
    (final.finalCoefficients[0] as unknown as bigint[])[0] ^= 1n;
    assert.equal(verify(final), false);
    const grind = { ...cloneProof(proof), grindNonce: proof.grindNonce ^ 1 };
    assert.equal(verify(grind), false);
    assert.throws(() => decodeSuccessorFriProof(encoded.slice(0, -1)));
    assert.throws(() => decodeSuccessorFriProof(new Uint8Array([...encoded, 0])));
  });
});

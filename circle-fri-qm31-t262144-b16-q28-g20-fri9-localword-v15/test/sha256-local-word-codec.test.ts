import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { wDeposit } from "../src/pool/relation-witness.ts";
import { compilePoolLocalShaGraph } from "../src/chain/pool-relation-local-word-machine.ts";
import {
  decodeLocalShaProgram,
  encodeLocalShaProgram,
  encodePoolLocalShaConstruction,
  localShaProgramDigest,
  poolLocalShaConstructionDigest,
} from "../src/chain/sha256-local-word-codec.ts";
import { executeLocalShaProgram, verifyLocalShaExplicitAliases } from "../src/chain/sha256-local-word-machine.ts";
import { IncrementalMerkle, NullifierSet, type Note } from "../src/pool/notes.ts";
import { emptyState } from "../src/pool/state.ts";
import { applyDeposit } from "../src/pool/transition.ts";

function graph(byte: number) {
  const note: Note = {
    amountSats: BigInt(20_000 + byte),
    rho: new Uint8Array(32).fill(byte),
    ownerSecret: new Uint8Array(32).fill(byte ^ 0xff),
  };
  const deposited = applyDeposit({
    state: emptyState(new Uint8Array(32).fill(byte + 1)),
    notes: new IncrementalMerkle(),
    nullifiers: new NullifierSet(),
  }, note);
  return compilePoolLocalShaGraph(deposited.statement, wDeposit(note, deposited.index, deposited.path));
}

describe("canonical local SHA constraint-program codec", () => {
  it("roundtrips the complete deposit program and preserves execution constraints", () => {
    const built = graph(0x41);
    const encoded = encodeLocalShaProgram(built.program);
    const decoded = decodeLocalShaProgram(encoded);
    assert.deepEqual(encodeLocalShaProgram(decoded), encoded);
    assert.equal(encoded.length, 1_264_904);
    const originalExecution = executeLocalShaProgram(built.program, built.inputs);
    const decodedExecution = executeLocalShaProgram(decoded, built.inputs);
    assert.deepEqual(decodedExecution.wireValues, originalExecution.wireValues);
    assert.equal(verifyLocalShaExplicitAliases(decoded, decodedExecution), undefined);
  });

  it("is witness-independent and rejects trailing or malformed programs", () => {
    const left = graph(0x41);
    const right = graph(0x52);
    assert.deepEqual(localShaProgramDigest(left.program), localShaProgramDigest(right.program));
    const encoded = encodeLocalShaProgram(left.program);
    const trailing = new Uint8Array(encoded.length + 1);
    trailing.set(encoded);
    assert.throws(() => decodeLocalShaProgram(trailing), /trailing/);
    const changed = new Uint8Array(encoded);
    changed[21] = 0xff;
    assert.throws(() => decodeLocalShaProgram(changed), /operation|wire|input|rotation/);
  });

  it("pins typed public-row ownership without committing witness values", () => {
    const left = graph(0x41);
    const right = graph(0x52);
    const descriptor = encodePoolLocalShaConstruction(left);
    assert.equal(descriptor.length, 190);
    assert.deepEqual(descriptor, encodePoolLocalShaConstruction(right));
    assert.deepEqual(poolLocalShaConstructionDigest(left), poolLocalShaConstructionDigest(right));
    assert.notDeepEqual(poolLocalShaConstructionDigest(left), localShaProgramDigest(left.program));
  });
});

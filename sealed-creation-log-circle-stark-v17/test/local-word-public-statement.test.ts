import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  encodeLocalWordPublicStatement,
  encodeLocalWordRelationStatement,
  LOCAL_WORD_PUBLIC_STATEMENT_BYTES,
  LOCAL_WORD_RELATION_STATEMENT_BYTES,
  localWordRelationStatementDigest,
  localWordProfile,
} from "../src/backends/circle/local-word-public-statement.ts";
import { sha256 } from "../src/pool/bytes.ts";
import { EdgeHistory } from "../src/pool/edge-history.ts";
import { SparseNullifierTree } from "../src/pool/sparse-nullifiers.ts";
import { emptyState } from "../src/pool/state.ts";
import { applyDeposit, applyWithdraw, type PoolMachine } from "../src/pool/transition.ts";

const category = new Uint8Array(32).fill(0x31);
const note = {
  amountSats: 20_000n,
  rho: new Uint8Array(32).fill(0x11),
  ownerSecret: new Uint8Array(32).fill(0x22),
};

function machine(): PoolMachine {
  return {
    state: emptyState(),
    poolCategory: category,
    history: new EdgeHistory(),
    nullifiers: new SparseNullifierTree(),
  };
}

describe("local-word v16 public statement boundary", () => {
  it("has one exact 410-byte public encoding and binds the public miner fee", () => {
    const deposit = applyDeposit(machine(), note);
    const encoded = encodeLocalWordPublicStatement(deposit.statement);
    assert.equal(encoded.length, LOCAL_WORD_PUBLIC_STATEMENT_BYTES);
    assert.equal(LOCAL_WORD_PUBLIC_STATEMENT_BYTES, 410);
    assert.notDeepEqual(encodeLocalWordPublicStatement(deposit.statement, 1_000n), encoded);
    assert.equal(localWordProfile(deposit.statement), "deposit");
  });

  it("has one exact word-aligned relation preimage and one eight-word boundary", () => {
    const deposit = applyDeposit(machine(), note);
    const encoded = encodeLocalWordRelationStatement(deposit.statement, 1_000n);
    const digest = localWordRelationStatementDigest(deposit.statement, 1_000n);
    assert.equal(encoded.length, LOCAL_WORD_RELATION_STATEMENT_BYTES);
    assert.equal(LOCAL_WORD_RELATION_STATEMENT_BYTES, 412);
    assert.equal(digest.length, 32);
    assert.deepEqual(digest, sha256(encoded));
    assert.notDeepEqual(
      localWordRelationStatementDigest(deposit.statement, 1_001n),
      digest,
    );
    assert.notDeepEqual(
      localWordRelationStatementDigest({
        ...deposit.statement,
        payoutLockingDigest: new Uint8Array(32).fill(0x7a),
      }, 1_000n),
      digest,
    );
  });

  it("derives withdrawal profile from the public creation-count transition", () => {
    const fullDeposit = applyDeposit(machine(), note);
    const full = applyWithdraw(
      fullDeposit.machine,
      fullDeposit.created,
      new Uint8Array(32).fill(0x70),
      note.amountSats,
    );
    assert.equal(localWordProfile(full.statement), "withdraw-full");

    const changeDeposit = applyDeposit(machine(), note);
    const change = applyWithdraw(
      changeDeposit.machine,
      changeDeposit.created,
      new Uint8Array(32).fill(0x70),
      7_000n,
      { changeRho: new Uint8Array(32).fill(0x43) },
    );
    assert.equal(localWordProfile(change.statement), "withdraw-change");
    assert.throws(
      () => encodeLocalWordPublicStatement({
        ...full.statement,
        createdEdge: new Uint8Array(32).fill(1),
      }),
      /created edge\/profile mismatch/,
    );
  });
});

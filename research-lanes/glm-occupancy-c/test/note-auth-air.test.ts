import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { createHash } from "node:crypto";
import {
  assertHashTraceConstraints,
  buildHashBitTrace,
  decodeHashBitRows,
  encodeHashBitShards,
  hashAir36InputBytes,
  hashBitRootOf,
  hashBitRows,
  hashBitTraceFromRows,
  messagesFromHashBitRows,
  HASH_BIT_COLUMNS,
  HASH_BIT_ROW_BYTES,
  HASH_BIT_SHARD_BYTES,
  noteAuthPublicsFromWitness,
  noteAuthResidualsVanish,
  shaAirResiduals,
  shaCAtQuery,
  shaStatementResiduals,
  shaTraceAcc,
  witnessMessages,
  sha256Blocks,
  sha256Pad,
  wordsToHash,
  type NoteAuthWitness,
} from "../src/chain/note-auth-air.ts";
import { commitAmount, HASH_AMOUNT_TAG } from "../src/amounts/hash-commit.ts";
import { commitNote, nullifierOf } from "../src/pool/notes.ts";
import { circleDomain } from "../src/backends/circle/fri.ts";
import { defaultInternalHash } from "../src/backends/circle/internal-hash.ts";
import { viewingCommit, freshViewingKey } from "../src/backends/circle/witness-mask.ts";
import {
  SHA_LDE_BUNDLE,
  SHA_LDE_OFF_DEGREE,
  buildShaLdeLeaves,
  encodeShaLdeShards,
  openShaLde,
  walkShaOpening,
} from "../src/chain/sha-lde.ts";
import { TRACE_LEN, FRI_N, FRI_QUERIES } from "../src/backends/circle/params.ts";
import { concatBytes, writeI64LE, ZERO32 } from "../src/pool/bytes.ts";

const rnd32 = () => crypto.getRandomValues(new Uint8Array(32));

function nodeSha(msg: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha256").update(msg).digest());
}

describe("note-auth SHA-256 AIR", () => {
  it("sha256Blocks matches node crypto", () => {
    const msg = concatBytes(HASH_AMOUNT_TAG, writeI64LE(20_000n), rnd32());
    const { out } = sha256Blocks(msg);
    assert.equal(Buffer.from(wordsToHash(out)).toString("hex"), Buffer.from(nodeSha(msg)).toString("hex"));
    assert.equal(sha256Pad(msg).length % 64, 0);
  });

  it("honest residuals vanish; mixed publics do not; bit trace is 0/1", () => {
    const w: NoteAuthWitness = {
      amountSats: 20_000n,
      rho: rnd32(),
      owner: rnd32(),
      poolInstanceId: rnd32(),
      action: "WITHDRAW",
    };
    const pubs = noteAuthPublicsFromWitness(w);
    assert.equal(noteAuthResidualsVanish(w, pubs), true);
    const note = { amountSats: w.amountSats, rho: w.rho, ownerSecret: w.owner };
    assert.equal(Buffer.from(pubs.leaf).toString("hex"), Buffer.from(commitNote(note)).toString("hex"));
    assert.equal(Buffer.from(pubs.amountCommit).toString("hex"), Buffer.from(commitAmount(w.amountSats, w.rho)).toString("hex"));
    assert.equal(
      Buffer.from(pubs.nf).toString("hex"),
      Buffer.from(nullifierOf(note, w.poolInstanceId)).toString("hex"),
    );
    const mixed = { ...pubs, nf: rnd32(), amountCommit: rnd32() };
    assert.equal(noteAuthResidualsVanish(w, mixed), false);
    assert.ok(shaAirResiduals(w, pubs).every((x) => x === 0n), "honest SHA-in-C vanishes");
    assert.ok(shaAirResiduals(w, mixed).some((x) => x !== 0n), "mixed publics do not vanish in SHA-in-C");
    const stmt = {
      action: w.action,
      amountCommitIn: pubs.amountCommit,
      amountCommitOut: pubs.amountCommit,
      noteCommitment: pubs.leaf,
      nullifier: pubs.nf,
    };
    const trace = buildHashBitTrace(w);
    assert.ok(
      shaStatementResiduals(stmt, trace, undefined, pubs.leaf).every((x) => x === 0n),
      "honest statement+TRACE SHA residuals vanish",
    );
    assert.ok(
      shaStatementResiduals(
        { ...stmt, nullifier: rnd32(), amountCommitIn: rnd32() },
        trace,
        undefined,
        pubs.leaf,
      ).some((x) => x !== 0n),
      "mixed statement + victim TRACE do not vanish",
    );
    const fromRows = hashBitTraceFromRows(hashBitRows(trace));
    assert.ok(
      shaStatementResiduals(stmt, fromRows, undefined, pubs.leaf).every((x) => x === 0n),
      "encoded TRACE rows recompute SHA vs honest statement",
    );
    assert.ok(
      shaStatementResiduals(
        { ...stmt, nullifier: rnd32(), amountCommitIn: rnd32() },
        fromRows,
        undefined,
        pubs.leaf,
      ).some((x) => x !== 0n),
      "encoded TRACE rows vs mixed statement do not vanish",
    );
    assertHashTraceConstraints(trace, w);
    assert.equal(trace.columns.length, HASH_BIT_COLUMNS);
    assert.equal(trace.columns[0]!.length, 64);
    const opening = shaTraceAcc(trace, w.action);
    assert.equal(shaCAtQuery(stmt, opening, 0, pubs.leaf), 0n);
    assert.notEqual(
      shaCAtQuery({ ...stmt, nullifier: rnd32(), amountCommitIn: rnd32() }, opening, 0, pubs.leaf),
      0n,
    );
    assert.notEqual(shaCAtQuery(stmt, undefined, 0, pubs.leaf), 0n, "missing opening fail-closed");
    assert.ok(
      shaStatementResiduals(stmt, undefined, undefined, pubs.leaf).some((x) => x !== 0n),
      "missing TRACE is empty rows, not occupancy-only zeros",
    );
    assert.ok(
      shaStatementResiduals(stmt, undefined, undefined, pubs.leaf, true).every((x) => x === 0n),
      "occupancyOnly skips SHA",
    );
  });

  it("deposit nf is zero and still satisfies the AIR", () => {
    const w: NoteAuthWitness = {
      amountSats: 8_000n,
      rho: rnd32(),
      owner: rnd32(),
      poolInstanceId: rnd32(),
      action: "DEPOSIT",
    };
    const pubs = noteAuthPublicsFromWitness(w);
    assert.equal(Buffer.from(pubs.nf).toString("hex"), Buffer.from(ZERO32).toString("hex"));
    assertHashTraceConstraints(buildHashBitTrace(w), w);
  });

  it("TRACE bit-rows reconstruct SHA messages in JS only (not unlocking)", () => {
    const w: NoteAuthWitness = {
      amountSats: 20_000n,
      rho: rnd32(),
      owner: rnd32(),
      poolInstanceId: rnd32(),
      action: "WITHDRAW",
    };
    const rows = hashBitRows(buildHashBitTrace(w));
    assert.equal(rows.length, 64);
    assert.equal(rows[0]!.length, HASH_BIT_ROW_BYTES);
    const expect = witnessMessages(w);
    const got = messagesFromHashBitRows(rows);
    assert.equal(Buffer.from(got.amountCommitMsg).toString("hex"), Buffer.from(expect.amountCommitMsg).toString("hex"));
    assert.equal(Buffer.from(got.leafMsg).toString("hex"), Buffer.from(expect.leafMsg).toString("hex"));
    assert.equal(Buffer.from(got.nfMsg).toString("hex"), Buffer.from(expect.nfMsg).toString("hex"));
    const root = hashBitRootOf(rows);
    const shards = encodeHashBitShards(rows, root);
    assert.equal(shards.length, 6);
    assert.equal(shards[0]!.length, HASH_BIT_SHARD_BYTES);
    const back = decodeHashBitRows(shards);
    assert.equal(Buffer.from(hashBitRootOf(back)).toString("hex"), Buffer.from(root).toString("hex"));
  });

  it("36 LDE openings do not uniquely reconstruct TRACE w; compact merkle verifies", () => {
    const w: NoteAuthWitness = {
      amountSats: 20_000n,
      rho: rnd32(),
      owner: rnd32(),
      poolInstanceId: rnd32(),
      action: "WITHDRAW",
    };
    const hash = defaultInternalHash();
    const commit = viewingCommit(freshViewingKey(), hash);
    const { leaves } = buildShaLdeLeaves({
      witness: w,
      small: circleDomain(TRACE_LEN),
      big: circleDomain(FRI_N),
      commit,
      hash,
    });
    const idx = Array.from({ length: FRI_QUERIES }, (_, i) => (i * 17 + 3) % FRI_N);
    const proof = openShaLde(leaves, idx, hash);
    assert.equal(proof.openings.length, FRI_QUERIES);
    assert.equal(proof.leaves.length, leaves.length);
    for (const o of proof.openings) {
      assert.equal(walkShaOpening(o.value, o.compact, proof.table, proof.root, hash), true);
      assert.equal(Buffer.from(o.value.subarray(0, 4)).toString("hex"), Buffer.from(noteAuthPublicsFromWitness(w).amountCommit.subarray(0, 4)).toString("hex"));
    }
    const shards = encodeShaLdeShards(proof);
    assert.equal(shards.length, 6);
    assert.ok(shards.reduce((n, s) => n + s.length, 0) === 7200);
    assert.ok(
      FRI_QUERIES * SHA_LDE_BUNDLE < 32 + SHA_LDE_OFF_DEGREE,
      "36×bundle mix samples must stay below deg(Z·R) so TRACE does not interpolate",
    );
    const vector = Buffer.concat(proof.leaves);
    assert.equal(vector.toString("hex").includes(Buffer.from(w.rho).toString("hex")), false);
  });

  it("36-query bit-AIR extra-input meter (wall, not a pad)", () => {
    const m = hashAir36InputBytes();
    assert.equal(m.extraInputs, 36);
    assert.equal(HASH_BIT_COLUMNS, 576);
    assert.equal(m.perUnlocking, 41 + 576 * 4 + 9 * 32);
    assert.equal(m.extraTxBytes, 94788);
    assert.ok(99397 + m.extraTxBytes > 100000, `occupancy+hash-air ${99397 + m.extraTxBytes}`);
  });
});

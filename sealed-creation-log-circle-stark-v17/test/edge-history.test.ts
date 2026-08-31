import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { bytesToHex } from "../src/pool/bytes.ts";
import {
  CREATION_EDGE_DOMAIN,
  CREATION_LINK_DOMAIN,
  CREATION_LOG_CONTEXT,
  EDGE_HISTORY_CAPACITY,
  EDGE_HISTORY_DEPTH,
  EDGE_NULLIFIER_DOMAIN,
  EdgeHistory,
  createdNoteContext,
  createdNoteRecord,
  creationLink,
  edgeNullifier,
  emptyEdgeHistoryRoot,
  encodeCreationEdgeMessage,
  encodeCreationLinkMessage,
  encodeEdgeNullifierMessage,
  verifyEdgeAppend,
  verifyEdgeMembership,
} from "../src/pool/edge-history.ts";
import type { Note } from "../src/pool/notes.ts";

function fill32(byte: number): Uint8Array {
  return new Uint8Array(32).fill(byte);
}

function note(byte: number, amountSats = 100n): Note {
  return { amountSats, rho: fill32(byte), ownerSecret: fill32(byte ^ 0xff) };
}

describe("sealed creation log domains", () => {
  it("pins the independent non-circular context and hash domains", () => {
    assert.equal(bytesToHex(CREATION_LOG_CONTEXT), "d90f2574eef2b5f838cc1fe14e3ee8a97338e9df85eb231de12dac825321a882");
    assert.equal(bytesToHex(CREATION_LINK_DOMAIN), "84038ab85d30fc8010e2081f1c3be392a4054c29315952f75bce8bcb9af1c047");
    assert.equal(bytesToHex(CREATION_EDGE_DOMAIN), "a54dd236612d9fdbec88c28593421800537d2a4272175e341c56671edf9d7e83");
    assert.equal(bytesToHex(EDGE_NULLIFIER_DOMAIN), "64a22d52e8d3401a7dc42eca345b66eb5254afabf7e7652123312bff68014e91");
    assert.equal(EDGE_HISTORY_DEPTH, 32);
  });

  it("uses fixed-width messages and u64 big-endian creation indices", () => {
    const poolCategory = fill32(0x11);
    const previousHead = fill32(0x22);
    const noteCommitment = fill32(0x33);
    const creationHead = fill32(0x44);
    const edge = fill32(0x55);
    const index = 0x01020304n;

    const link = encodeCreationLinkMessage({ poolCategory, creationIndex: index, previousHead, noteCommitment });
    const publicEdge = encodeCreationEdgeMessage({ poolCategory, creationIndex: index, previousHead, creationHead });
    const nullifier = encodeEdgeNullifierMessage({ poolCategory, edge, ownerSecret: fill32(0x66), rho: fill32(0x77) });
    assert.equal(link.length, 168);
    assert.equal(publicEdge.length, 168);
    assert.equal(nullifier.length, 192);
    assert.deepEqual(link.subarray(96, 104), Uint8Array.of(0, 0, 0, 0, 1, 2, 3, 4));
    assert.deepEqual(publicEdge.subarray(96, 104), Uint8Array.of(0, 0, 0, 0, 1, 2, 3, 4));
  });
});

describe("depth-32 public edge history", () => {
  it("pins the deterministic empty root", () => {
    assert.equal(
      bytesToHex(emptyEdgeHistoryRoot()),
      "c6f67e02e6e4e1bdefb994c6098953f34636ba2b6ca20a4721d2b26a886722ff",
    );
  });

  it("verifies every append and refreshes membership against the latest root", () => {
    const history = new EdgeHistory();
    const poolCategory = fill32(0xa5);
    const records = [note(1), note(2), note(3), note(4)].map((created, i) =>
      createdNoteRecord(created, BigInt(i), i === 0 ? new Uint8Array(32) : fill32(i)),
    );

    const firstContext = createdNoteContext(records[0]!, poolCategory);
    const firstAppend = history.append(firstContext.edge);
    assert.equal(firstAppend.index, 0n);
    assert.equal(firstAppend.path.length, 32);
    assert.ok(verifyEdgeAppend(firstAppend));
    const rootAfterFirst = history.root;

    for (const record of records.slice(1)) {
      const appended = history.append(createdNoteContext(record, poolCategory).edge);
      assert.ok(verifyEdgeAppend(appended));
    }
    const refreshed = history.membership(0n);
    assert.notDeepEqual(refreshed.root, rootAfterFirst);
    assert.ok(verifyEdgeMembership(refreshed));
    assert.equal(history.count, 4n);
  });

  it("rebuilds exactly from public handles and rejects path mutations", () => {
    const source = new EdgeHistory([fill32(1), fill32(2), fill32(3), fill32(4), fill32(5)]);
    const rebuilt = EdgeHistory.rebuild(source.publicEdges());
    assert.deepEqual(rebuilt.root, source.root);
    const witness = rebuilt.membership(3n);
    assert.ok(verifyEdgeMembership(witness));
    const path = witness.path.map((sibling) => sibling.slice());
    path[7]![0] ^= 1;
    assert.equal(verifyEdgeMembership({ ...witness, path }), false);
    assert.equal(verifyEdgeMembership({ ...witness, edge: new Uint8Array(32) }), false);
    assert.equal(verifyEdgeAppend({
      index: 5n,
      edge: new Uint8Array(32),
      path: new Array(32).fill(undefined).map(() => new Uint8Array(32)),
      oldRoot: emptyEdgeHistoryRoot(),
      newRoot: emptyEdgeHistoryRoot(),
    }), false);
  });

  it("binds identical note secrets to their distinct public creation edges", () => {
    const poolCategory = fill32(0xcc);
    const sameNote = note(9, 50_000n);
    const first = createdNoteContext(createdNoteRecord(sameNote, 0n, new Uint8Array(32)), poolCategory);
    const second = createdNoteContext(createdNoteRecord(sameNote, 1n, first.creationHead), poolCategory);
    assert.notDeepEqual(first.edge, second.edge);
    assert.notDeepEqual(
      edgeNullifier(sameNote, poolCategory, first.edge),
      edgeNullifier(sameNote, poolCategory, second.edge),
    );
  });

  it("enforces the 2^32 creation capacity at hash-message boundaries", () => {
    assert.equal(EDGE_HISTORY_CAPACITY, 4_294_967_296n);
    const args = {
      poolCategory: fill32(1),
      creationIndex: EDGE_HISTORY_CAPACITY,
      previousHead: fill32(2),
      noteCommitment: fill32(3),
    };
    assert.throws(() => creationLink(args), /creation index out of range/);
  });
});

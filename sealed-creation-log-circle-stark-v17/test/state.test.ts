import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { EDGE_HISTORY_CAPACITY, emptyEdgeHistoryRoot } from "../src/pool/edge-history.ts";
import { emptySparseNullifierRoot } from "../src/pool/sparse-nullifiers.ts";
import {
  ANY_STATE_BYTES,
  decodeState,
  emptyState,
  encodePublicPaa2,
  encodeState,
  utxoValueFor,
} from "../src/pool/state.ts";

function fill32(byte: number): Uint8Array {
  return new Uint8Array(32).fill(byte);
}

describe("PAA2 state", () => {
  it("has one exact canonical 128-byte layout", () => {
    const state = {
      ...emptyState(),
      sequence: 0x0102030405060708n,
      reserveSats: 42_000n,
      creationCount: 0x11121314n,
      creationHead: fill32(0x21),
      edgeHistoryRoot: fill32(0x42),
      nullifierRoot: fill32(0x63),
    };
    const encoded = encodeState(state);

    assert.equal(encoded.length, ANY_STATE_BYTES);
    assert.equal(new TextDecoder().decode(encoded.subarray(0, 4)), "PAA2");
    assert.equal(encoded[4], 2);
    assert.deepEqual(encoded.subarray(5, 8), new Uint8Array(3));
    assert.deepEqual(encoded.subarray(8, 16), Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8));
    assert.deepEqual(encoded.subarray(16, 24), Uint8Array.of(0, 0, 0, 0, 0x11, 0x12, 0x13, 0x14));
    assert.deepEqual(encoded.subarray(24, 32), new Uint8Array(8));
    assert.deepEqual(encoded.subarray(32, 64), state.creationHead);
    assert.deepEqual(encoded.subarray(64, 96), state.edgeHistoryRoot);
    assert.deepEqual(encoded.subarray(96, 128), state.nullifierRoot);
    assert.deepEqual(encodePublicPaa2(state), encoded);
  });

  it("keeps the UTXO-derived reserve out of the PAA2 bytes", () => {
    const state = emptyState();
    const low = encodeState({ ...state, reserveSats: 1n });
    const high = encodeState({ ...state, reserveSats: 9_999_999n });
    assert.deepEqual(low, high);

    const decoded = decodeState(low, 9_999_999n);
    assert.equal(decoded.reserveSats, 9_999_999n);
    assert.equal(utxoValueFor(decoded), 10_001_999n);
  });

  it("starts with the deterministic depth-32 empty history root", () => {
    const state = emptyState();
    assert.equal(state.creationCount, 0n);
    assert.deepEqual(state.creationHead, new Uint8Array(32));
    assert.deepEqual(state.edgeHistoryRoot, emptyEdgeHistoryRoot());
    assert.deepEqual(state.nullifierRoot, emptySparseNullifierRoot());
  });

  it("rejects non-canonical reserved bytes and capacity overflow", () => {
    const encoded = encodeState(emptyState());
    encoded[27] = 1;
    assert.throws(() => decodeState(encoded, 0n), /reserved state byte 27/);
    assert.doesNotThrow(() => encodeState({ ...emptyState(), creationCount: EDGE_HISTORY_CAPACITY }));
    assert.throws(
      () => encodeState({ ...emptyState(), creationCount: EDGE_HISTORY_CAPACITY + 1n }),
      /exceeds depth-32/,
    );
  });
});

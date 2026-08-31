import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { encodeTransaction } from "@bitauth/libauth";
import {
  analyzeLocalWordObserverTransaction,
  extractLegacyLocalWordProofFromTransaction,
  extractLocalWordProofFromTransaction,
} from "../src/backends/circle/local-word-observer-view.ts";
import {
  LOCAL_WORD_PROOF_LENGTH_OFFSET,
  LOCAL_WORD_PROOF_VERSION,
  type LocalWordProofContext,
} from "../src/backends/circle/local-word-sealed-proof.ts";
import {
  partitionLocalWordProofBytes,
} from "../src/chain/local-word-proof-carriers.ts";
import {
  V17_BOOTSTRAP_AFFINE_ALLOCATION,
  measuredV17AffineAllocation,
  type V17AffineAssignment,
} from "../src/chain/v17-affine-allocation.ts";
import { writeU32BE } from "../src/pool/bytes.ts";

function boundaryShiftedMeasuredAllocation() {
  const assignments = V17_BOOTSTRAP_AFFINE_ALLOCATION.assignments.map(
    (assignment): V17AffineAssignment => ({ ...assignment }),
  );
  assignments[0] = {
    ...assignments[0]!,
    basePrefixEnd: assignments[0]!.basePrefixEnd + 1,
  };
  assignments[1] = {
    ...assignments[1]!,
    basePrefixStart: assignments[1]!.basePrefixStart + 1,
  };
  return measuredV17AffineAllocation(assignments);
}

function canonicalProofBytes(length: number): Uint8Array {
  const proof = new Uint8Array(length);
  proof.set(new TextEncoder().encode("SKLW"), 0);
  proof[4] = LOCAL_WORD_PROOF_VERSION;
  proof.set(writeU32BE(length), LOCAL_WORD_PROOF_LENGTH_OFFSET);
  return proof;
}

function carrierTransaction(proof: Uint8Array, allocation = V17_BOOTSTRAP_AFFINE_ALLOCATION) {
  const carriers = partitionLocalWordProofBytes(proof, allocation);
  return encodeTransaction({
    version: 2,
    locktime: 0,
    inputs: carriers.map((carrier, index) => ({
      outpointTransactionHash: new Uint8Array(32).fill((index + 1) & 0xff),
      outpointIndex: index,
      sequenceNumber: 0,
      unlockingBytecode: carrier.unlockingBytecode,
    })),
    outputs: [],
  });
}

describe("v17 observer allocation ownership", () => {
  it("refuses bootstrap geometry at the final observer entry point", () => {
    assert.throws(
      () => analyzeLocalWordObserverTransaction(
        new Uint8Array(),
        {} as LocalWordProofContext,
        V17_BOOTSTRAP_AFFINE_ALLOCATION,
      ),
      /final allocation must be measured/,
    );
  });

  it("accepts the exact measured partition and rejects bootstrap ownership drift", () => {
    const measured = boundaryShiftedMeasuredAllocation();
    const proof = canonicalProofBytes(measured.minimumProofBytes);
    const raw = carrierTransaction(proof, measured);

    assert.deepEqual(extractLocalWordProofFromTransaction(raw, measured), proof);
    assert.throws(
      () => extractLocalWordProofFromTransaction(raw, V17_BOOTSTRAP_AFFINE_ALLOCATION),
      /local-word observer carrier placement/,
    );
  });

  it("keeps bootstrap replay behind an explicitly legacy API", () => {
    const proof = canonicalProofBytes(V17_BOOTSTRAP_AFFINE_ALLOCATION.minimumProofBytes);
    const raw = carrierTransaction(proof);
    assert.deepEqual(extractLegacyLocalWordProofFromTransaction(raw), proof);
  });
});

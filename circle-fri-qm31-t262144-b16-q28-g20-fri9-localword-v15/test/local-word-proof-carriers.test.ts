import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  LOCAL_WORD_CARRIER_INPUTS,
  LOCAL_WORD_CARRIER_PREFIXES,
  locateLocalWordProofByte,
  measureLocalWordProofCarriers,
  partitionLocalWordProofBytes,
  reassembleLocalWordProofBytes,
} from "../src/chain/local-word-proof-carriers.ts";
import {
  LOCAL_WORD_PROOF_LENGTH_OFFSET,
  LOCAL_WORD_PROOF_VERSION,
  localWordMaximumCanonicalProofBytes,
} from "../src/backends/circle/local-word-sealed-proof.ts";
import { writeU32BE } from "../src/pool/bytes.ts";

function syntheticCanonicalBytes(length = localWordMaximumCanonicalProofBytes(34)): Uint8Array {
  const bytes = new Uint8Array(length);
  bytes.set(new TextEncoder().encode("SKLW"), 0);
  bytes[4] = LOCAL_WORD_PROOF_VERSION;
  bytes.set(writeU32BE(length), LOCAL_WORD_PROOF_LENGTH_OFFSET);
  for (let index = 42; index < bytes.length; index += 1) bytes[index] = index & 0xff;
  return bytes;
}

describe("local-word byte-only proof carriers", () => {
  it("partitions every canonical byte once and locates every role budget", () => {
    const proofBytes = syntheticCanonicalBytes();
    const carriers = partitionLocalWordProofBytes(proofBytes);
    assert.equal(carriers.length, LOCAL_WORD_CARRIER_INPUTS);
    assert.deepEqual(reassembleLocalWordProofBytes(carriers), proofBytes);
    assert.equal(LOCAL_WORD_CARRIER_PREFIXES.length, carriers.length + 1);
    assert.equal(carriers.reduce((sum, carrier) => sum + carrier.chunk.length, 0), proofBytes.length);
    assert.ok(carriers.every((carrier) => carrier.unlockingBytecode.length <= 10_000));

    for (const carrier of carriers) {
      for (const proofOffset of [carrier.start, carrier.end - 1]) {
        const location = locateLocalWordProofByte(proofBytes.length, proofOffset);
        assert.equal(location.carrierIndex, carrier.index);
        assert.equal(location.chunkOffset, proofOffset - carrier.start);
        assert.equal(location.chunkLength, carrier.chunk.length);
      }
    }

    const changed = carriers.map((carrier) => ({ ...carrier }));
    changed[17] = { ...changed[17]!, start: changed[17]!.start + 1 };
    assert.throws(() => reassembleLocalWordProofBytes(changed), /placement/);
  });

  it("measures the exact unpadded carrier transaction below the consensus envelope", () => {
    const proofBytes = syntheticCanonicalBytes();
    const measurement = measureLocalWordProofCarriers(proofBytes);
    assert.deepEqual(measurement, {
      proofBytes: 340_490,
      carrierInputs: 168,
      carrierChunkMin: 268,
      carrierChunkMax: 8_805,
      budgetWeight: 40_643,
      unlockingSum: proofBytes.length + 3 * LOCAL_WORD_CARRIER_INPUTS,
      transactionBytes: 348_238,
      remainingConsensusBytes: 651_762,
    });
  });
});

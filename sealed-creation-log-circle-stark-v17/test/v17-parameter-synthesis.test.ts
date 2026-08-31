import assert from "node:assert/strict";
import test from "node:test";

import {
  defaultV17FriParameterCandidates,
  synthesizeV17FriParameters,
} from "../src/assurance/v17-parameter-synthesis.ts";

test("v17 synthesis uses only proven Johnson inputs and a practical per-round grind cap", () => {
  const candidates = defaultV17FriParameterCandidates();
  assert.ok(candidates.length > 0);
  for (const candidate of candidates) {
    assert.equal(candidate.bounds.regime, "johnson");
    assert.ok(candidate.grindingBits.maximum <= 32);
    assert.equal(candidate.grindingBits.folds.length, 9);
    assert.equal(candidate.friRoundCount, 11);
    assert.equal(candidate.proofCoreCeiling.authenticationBytes,
      candidate.proofCoreCeiling.authenticationNodes * 32);
    assert.equal(candidate.proofCoreCeiling.totalBytes,
      candidate.proofCoreCeiling.fixedBytes + candidate.proofCoreCeiling.openedRowBytes +
      candidate.proofCoreCeiling.authenticationBytes);
  }
  assert.ok(candidates.some(({ logBlowup }) => logBlowup === 4));
  assert.ok(candidates.some(({ logBlowup }) => logBlowup === 6));
  assert.ok(candidates[0]!.proofCoreCeiling.totalBytes <= candidates.at(-1)!.proofCoreCeiling.totalBytes);
});

test("v17 synthesis fails closed when the grind cap leaves no theorem candidate", () => {
  assert.deepEqual(synthesizeV17FriParameters({
    logBlowups: [4],
    minimumQueries: 29,
    maximumQueries: 29,
    maximumRoundGrindingBits: 1,
    batchWidth: 27,
    precedingRounds: 3,
    thetaGridDenominator: 32,
  }), []);
});

test("v17 synthesis rejects conjectural odd-blowup search space", () => {
  assert.throws(() => synthesizeV17FriParameters({
    logBlowups: [5],
    minimumQueries: 29,
    maximumQueries: 64,
    maximumRoundGrindingBits: 32,
    batchWidth: 27,
    precedingRounds: 3,
  }), /range/);
});

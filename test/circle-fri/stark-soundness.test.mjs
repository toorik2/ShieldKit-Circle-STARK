import test from 'node:test';
import assert from 'node:assert/strict';

import {
  SOUNDNESS_EVENT_FAMILIES,
  SOUNDNESS_EVEN_X_NEIGHBORS,
  SOUNDNESS_ROLES,
  computeStarkSoundnessArtifactDigests,
  inspectStarkSoundnessDag,
  loadStarkSoundnessDag,
} from '../../src/circle-fri/stark-soundness.mjs';

import {
  CIRCLE_DEEP_EVEN_X,
} from '../../src/circle-fri/deep-pi-native.mjs';

test('unselected soundness DAG names every role and six event families', () => {
  const artifact = loadStarkSoundnessDag();
  const inspection = inspectStarkSoundnessDag(artifact);
  assert.equal(inspection.ok, true, inspection.dagErrors.join('\n'));
  assert.deepEqual(inspection.roles, SOUNDNESS_ROLES);
  for (const family of SOUNDNESS_EVENT_FAMILIES) {
    assert.ok(inspection.families.includes(family), `missing family ${family}`);
  }
  assert.equal(inspection.selected, false);
  assert.equal(inspection.systemic128, false);
  assert.equal(inspection.ethStark144ClaimedAsSystemic, false);
  assert.equal(inspection.qualification, 'not-qualified');
  assert.equal(artifact.worksheet.conclusion.selectionAllowed, false);
  assert.equal(inspection.conjecturalSTotal.numerator, '3');
  assert.equal(inspection.conjecturalSTotal.denominator, '562949953421312');
  assert.equal(inspection.floorSecurityBits, 47);
  assert.notEqual(inspection.floorSecurityBits, 128);
  const digests = computeStarkSoundnessArtifactDigests();
  assert.equal(artifact.worksheet.candidateTupleDigest, digests.candidateTuple);
  assert.equal(artifact.worksheet.artifactDigests.relation, digests.relation);
  assert.equal(artifact.worksheet.artifactDigests.derivation, digests.derivation);
  assert.equal(artifact.worksheet.toolchain.lockfileDigest, digests.lockfile);
  assert.match(digests.relation, /^[0-9a-f]{64}$/u);
  assert.notEqual(digests.relation, 'c'.repeat(64));
  assert.notEqual(digests.candidateTuple, 'a'.repeat(64));
  assert.notEqual(digests.lockfile, 'b'.repeat(64));
  assert.equal(digests.qDeep, CIRCLE_DEEP_EVEN_X);
  assert.equal(artifact.roles.Q_deep, CIRCLE_DEEP_EVEN_X);
  assert.match(artifact.roles.F_deep, /even-x/u);
  assert.deepEqual(digests.neighbors, SOUNDNESS_EVEN_X_NEIGHBORS);
  assert.equal(SOUNDNESS_EVEN_X_NEIGHBORS.deep, 'deep-pi-native.mjs');
  assert.equal(SOUNDNESS_EVEN_X_NEIGHBORS.air, 'stark-air.mjs');
  assert.equal(SOUNDNESS_EVEN_X_NEIGHBORS.algebraicAir, 'algebraic-hash-air.mjs');
  assert.equal(SOUNDNESS_EVEN_X_NEIGHBORS.poseidon2Air, 'poseidon2-air.mjs');
  assert.equal(SOUNDNESS_EVEN_X_NEIGHBORS.poseidon2, 'poseidon2-m31.mjs');
  assert.equal(SOUNDNESS_EVEN_X_NEIGHBORS.partition, 'relation-partition.mjs');
  assert.ok(artifact.worksheet.sourceCommits[0].paths.includes('src/circle-fri/deep-pi-native.mjs'));
  assert.ok(artifact.worksheet.sourceCommits[0].paths.includes('src/circle-fri/algebraic-hash-air.mjs'));
  assert.ok(artifact.worksheet.sourceCommits[0].paths.includes('src/circle-fri/poseidon2-air.mjs'));
  assert.ok(artifact.worksheet.sourceCommits[0].paths.includes('src/circle-fri/relation-partition.mjs'));
  console.log('SOUNDNESS_DAG', {
    proven: [
      'v2 DAG validates',
      'ten roles including grind',
      'six families',
      'S_total=3/2^49 floor 47',
      'F_deep/Q_deep digest even-x DEEP/AIR/partition artifacts',
    ],
    failed: [],
    speculative: ['all event bounds are conjectural 2^-50 slots'],
    selected: false,
    systemic128: false,
    ethStark144AsSystemic: false,
    qDeep: artifact.roles.Q_deep,
    neighbors: digests.neighbors,
  });
});

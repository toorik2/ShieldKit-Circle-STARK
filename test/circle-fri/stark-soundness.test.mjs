import test from 'node:test';
import assert from 'node:assert/strict';

import {
  SOUNDNESS_128_WALL,
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

import {
  measureCircleFriHlp24Bound,
} from '../../src/circle-fri/circle-fri-hlp24-bound.mjs';

import {
  S_TOTAL_NEXT,
  S_TOTAL_NEXT_WALL,
} from '../../src/circle-fri/circle-fri-s-total-next.mjs';

test('unselected soundness DAG names every role and six event families', () => {
  const artifact = loadStarkSoundnessDag();
  const inspection = inspectStarkSoundnessDag(artifact);
  assert.equal(inspection.ok, true, inspection.dagErrors.join('\n'));
  assert.deepEqual(inspection.roles, SOUNDNESS_ROLES);
  for (const family of SOUNDNESS_EVENT_FAMILIES) {
    assert.ok(inspection.families.includes(family), `missing family ${family}`);
  }
  assert.equal(inspection.selected, false);
  assert.equal(inspection.ethStark144ClaimedAsSystemic, false);
  assert.equal(inspection.qualification, 'not-qualified');
  assert.equal(inspection.systemic128, true);
  assert.ok(inspection.floorSecurityBits >= 128, 'unselected S_total floor must be ≥128');
  assert.equal(artifact.worksheet.conclusion.selectionAllowed, false);
  assert.equal(inspection.conjecturalSTotal.numerator, '2658455991569831745807614120560689153');
  assert.equal(inspection.conjecturalSTotal.denominator, '115792089237316195423570985008687907853269984665640564039457584007913129639936');
  assert.equal(inspection.floorSecurityBits, 134);
  assert.match(SOUNDNESS_128_WALL, /134 bits/u);
  assert.match(SOUNDNESS_128_WALL, /unique-decoding/u);
  assert.match(SOUNDNESS_128_WALL, /2\^-135/u);
  assert.match(SOUNDNESS_128_WALL, /is the FRI summand/u);
  assert.match(SOUNDNESS_128_WALL, /Not a selected tuple/u);
  assert.match(SOUNDNESS_128_WALL, /Queries were not dropped/u);
  const hlp24 = measureCircleFriHlp24Bound();
  assert.equal(hlp24.hypotheses.applies, false);
  assert.equal(hlp24.hypotheses.evenK, false);
  assert.equal(hlp24.hypotheses.dimensionGapLambdaSent, true);
  assert.equal(hlp24.totalBits, null);
  assert.equal(hlp24.uniqueDecodingBits, 135);
  assert.equal(S_TOTAL_NEXT.uniqueDecoding128.needClusters, 43);
  assert.equal(S_TOTAL_NEXT.hlp24ListDecoding128.needClusters, 165);
  assert.equal(S_TOTAL_NEXT.moreClustersQ44.accepted, true);
  assert.equal(S_TOTAL_NEXT.moreClustersQ48.accepted, true);
  assert.equal(S_TOTAL_NEXT.moreClustersQ50.accepted, true);
  assert.equal(S_TOTAL_NEXT.moreClustersQ52.accepted, true);
  assert.equal(S_TOTAL_NEXT.moreClustersQ60.accepted, true);
  assert.equal(S_TOTAL_NEXT.moreClustersQ64.accepted, false);
  assert.equal(S_TOTAL_NEXT.moreClustersQ90.accepted, true);
  assert.equal(S_TOTAL_NEXT.tripleCluster.airQ90.accepted, true);
  assert.equal(S_TOTAL_NEXT.shipped.uniqueDecodingBits, 135);
  assert.equal(S_TOTAL_NEXT.blowup8.accepted, true);
  assert.equal(S_TOTAL_NEXT.independentQueries.encodedWitness, 7566);
  assert.equal(S_TOTAL_NEXT.independentQueries.dummyQ8.redeem, 5910);
  assert.equal(S_TOTAL_NEXT.independentQueries.dummyQ8.accepted, false);
  assert.equal(S_TOTAL_NEXT.independentQueries.measured, 'redeem-and-unlocking-miss');
  assert.equal(S_TOTAL_NEXT.dualCluster.dummyQ4.redeem, 4997);
  assert.equal(S_TOTAL_NEXT.dualCluster.dummyQ4.accepted, true);
  assert.equal(S_TOTAL_NEXT.dualCluster.dummyQ8.accepted, true);
  assert.equal(S_TOTAL_NEXT.dualCluster.dummyQ52.accepted, true);
  assert.equal(S_TOTAL_NEXT.dualCluster.measured, 'envelope-fit');
  assert.match(S_TOTAL_NEXT_WALL, /q=90 k=45/u);
  assert.match(SOUNDNESS_128_WALL, /q=90 k=45 cpi=3 Libauth 15\/15/u);
  assert.match(SOUNDNESS_128_WALL, /HLP24 Theorem 6/u);
  assert.match(SOUNDNESS_128_WALL, /k=45 is odd/u);
  assert.match(artifact.worksheet.conclusion.reason, /134 bits/u);
  assert.match(artifact.worksheet.conclusion.reason, /unique-decoding/i);
  assert.match(artifact.worksheet.conclusion.reason, /2\^-135/u);
  assert.match(artifact.worksheet.conclusion.reason, /Not a selected tuple/u);
  assert.match(artifact.worksheet.conclusion.reason, /Queries were not dropped/u);
  assert.match(artifact.worksheet.conclusion.reason, /LDE-only absorb-in-Q bind holds/u);
  const friNode = artifact.worksheet.eventDag.nodes.find((node) => node.eventId === 'event:fri-query');
  assert.equal(friNode.bound.exactUpperBound.numerator, '1');
  assert.equal(friNode.bound.exactUpperBound.denominator, '43556142965880123323311949751266331066368');
  assert.match(friNode.bound.expression, /PROVEN unique-decoding/u);
  assert.match(friNode.bound.expression, /queryCount=90/u);
  assert.match(friNode.bound.expression, /k=45/u);
  assert.match(friNode.bound.expression, /4-to-1/u);
  assert.match(friNode.bound.expression, /2\^-135/u);
  assert.match(friNode.bound.expression, /NOT this union term/u);
  assert.match(friNode.bound.expression, /NOT this union term/u);
  assert.notEqual(friNode.bound.exactUpperBound.denominator, '1125899906842624');
  assert.notEqual(friNode.bound.exactUpperBound.denominator, '2048');
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
      'F_deep/Q_deep digest even-x DEEP/AIR/partition artifacts',
      'AIR-bound-to-the-table (LDE-only bind holds; DAG of that object)',
      'proven unique-decoding FRI on blowup-8 domain is (1/8)^k with k=q/2 independent 4-to-1 clusters (2^-135 at q=90 cpi=3)',
      'union rational arithmetic of the two systemic summands is checked',
    ],
    failed: [],
    speculative: [
      SOUNDNESS_128_WALL,
      'S_total union is proven unique-decoding (1/8)^45 plus HASH256 2^-256, floor 134 bits; conjectural (2^17/M31^2)^45 is not the union; HASH256-as-RO stays conjectural; v2 cannot express 128-bit-pass',
    ],
    selected: false,
    systemic128: inspection.systemic128,
    ethStark144AsSystemic: false,
    qDeep: artifact.roles.Q_deep,
    neighbors: digests.neighbors,
  });
});

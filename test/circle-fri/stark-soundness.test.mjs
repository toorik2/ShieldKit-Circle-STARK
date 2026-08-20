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
  assert.equal(inspection.systemic128, false);
  assert.equal(inspection.ethStark144ClaimedAsSystemic, false);
  assert.equal(inspection.qualification, 'not-qualified');
  assert.equal(artifact.worksheet.conclusion.selectionAllowed, false);
  assert.equal(inspection.conjecturalSTotal.numerator, '426752918537530492438970121052703522648267239372591076064826362174457081932164497074690263260790111209543550296851288776414006106595764957261826010647566854021357038948077652083053353067261177167458346546626388646656618532175943354391927455745');
  assert.equal(inspection.conjecturalSTotal.denominator, '49414612025582859633938910547642219014296394079571318303661286243939779752588825718757729038255635199343330728898042140616018028245869951311551462225750336791819596022704071298431686491397688424290207671683010747083822531332415959346403994586147279446296995560556779599318776050520778573509502575919681439372365732511744');
  assert.equal(inspection.floorSecurityBits, 255);
  assert.match(SOUNDNESS_128_WALL, /255 bits/u);
  assert.match(SOUNDNESS_128_WALL, /conjectural/u);
  assert.match(SOUNDNESS_128_WALL, /2\^-26/u);
  assert.match(SOUNDNESS_128_WALL, /That proven term is not the union/u);
  assert.match(SOUNDNESS_128_WALL, /Not a selected tuple/u);
  assert.match(SOUNDNESS_128_WALL, /Queries were not dropped/u);
  const hlp24 = measureCircleFriHlp24Bound();
  assert.equal(hlp24.hypotheses.applies, true);
  assert.equal(hlp24.hypotheses.dimensionGapLambdaSent, true);
  assert.equal(hlp24.totalBits, 10);
  assert.equal(hlp24.uniqueDecodingBits, 26);
  assert.equal(S_TOTAL_NEXT.uniqueDecoding128.needClusters, 64);
  assert.equal(S_TOTAL_NEXT.hlp24ListDecoding128.needClusters, 165);
  assert.equal(S_TOTAL_NEXT.moreClustersQ28.accepted, false);
  assert.equal(S_TOTAL_NEXT.blowup8.accepted, false);
  assert.equal(S_TOTAL_NEXT.independentQueries.encodedWitness, 7700);
  assert.match(S_TOTAL_NEXT_WALL, /437k executed op-cost cut/u);
  assert.match(SOUNDNESS_128_WALL, /q=28 density-miss/u);
  assert.match(SOUNDNESS_128_WALL, /HLP24 Theorem 6/u);
  assert.match(SOUNDNESS_128_WALL, /10 bits/u);
  assert.match(artifact.worksheet.conclusion.reason, /255 bits/u);
  assert.match(artifact.worksheet.conclusion.reason, /conjectural/i);
  assert.match(artifact.worksheet.conclusion.reason, /2\^-26/u);
  assert.match(artifact.worksheet.conclusion.reason, /Not a selected tuple/u);
  assert.match(artifact.worksheet.conclusion.reason, /Queries were not dropped/u);
  assert.match(artifact.worksheet.conclusion.reason, /LDE-only absorb-in-Q bind holds/u);
  const friNode = artifact.worksheet.eventDag.nodes.find((node) => node.eventId === 'event:fri-query');
  assert.equal(friNode.bound.exactUpperBound.numerator, '411376139330301510538742295639337626245683966408394965837152256');
  assert.match(friNode.bound.expression, /CONJECTURAL/u);
  assert.match(friNode.bound.expression, /queryCount=26/u);
  assert.match(friNode.bound.expression, /k=13/u);
  assert.match(friNode.bound.expression, /4-to-1/u);
  assert.match(friNode.bound.expression, /2\^-26/u);
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
      'proven unique-decoding FRI on blowup-4 domain is (1/4)^k with k=q/2 independent 4-to-1 clusters (2^-26 at q=26)',
      'union rational arithmetic of the two systemic summands is checked',
    ],
    failed: [],
    speculative: [
      SOUNDNESS_128_WALL,
      'conjectural FRI (2^16/M31^2)^13 union HASH256 floors to 255 bits; 255 is not proven; unique-decoding 2^-26 is not the union; v2 cannot express 128-bit-pass',
    ],
    selected: false,
    systemic128: false,
    ethStark144AsSystemic: false,
    qDeep: artifact.roles.Q_deep,
    neighbors: digests.neighbors,
  });
});

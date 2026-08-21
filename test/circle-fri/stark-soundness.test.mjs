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
  assert.equal(inspection.conjecturalSTotal.numerator, '747632004499243740296762280969131935089401750934256588302599259892458708474430610833113426952004978313951948392296141389208694820619386189057409390925538429203172069969912087355850353745603665035860285313629271580643033790434077891000073466260399819192367901970330332363251905455498284785870424121142207038149446995326802465594817020639453868887658694951605546834144673844057981867453034904075546914492875447489676360515570673642280849652243292407704485552165691230624837612488776780162487322893904762338054383480949552427892235165633746478561301865043470258335025391945874070065536867245146060806223273190990203283002701682223488597184656915753520835018897631994696897769463986194098113860432597187534878150621394198863530080790028166348832888718342840597318361054847030586881146874380630605918076728024200073844038064197179146644330905601');
  assert.equal(inspection.conjecturalSTotal.denominator, '86569871781650014493794213844380987415558285650923295282513452172665046235459895962484182089102760227519995253426467160606298542582352417664192670529738510388537413862097209094164307583772310831657501293211096603936721389627670031435475918461990137210066600817376952265168759664641422148059480963413116234935729127342793124652957884960844827658586090029976934266579667931930788852486427664220368156228573692786937641584407552754440651866255960292400241487094487637784322863966124681528501115306964908354671187697389681894116088179778693716957023581951389882930047082697940084977071489591049202389562461908396866128959846370765921163221255018696253483458792294184228943917877732558048570268130178364927636090283591578284699420216648626186725611797440800896153033770124404079691861818614768007274563781341222001992384368005739735066748704479145352644434247617454615945975541642311885353574259743961389768055152143499264');
  assert.equal(inspection.floorSecurityBits, 255);
  assert.match(SOUNDNESS_128_WALL, /255 bits/u);
  assert.match(SOUNDNESS_128_WALL, /conjectural/u);
  assert.match(SOUNDNESS_128_WALL, /2\^-135/u);
  assert.match(SOUNDNESS_128_WALL, /That proven term is not the union/u);
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
  assert.match(artifact.worksheet.conclusion.reason, /255 bits/u);
  assert.match(artifact.worksheet.conclusion.reason, /conjectural/i);
  assert.match(artifact.worksheet.conclusion.reason, /2\^-135/u);
  assert.match(artifact.worksheet.conclusion.reason, /Not a selected tuple/u);
  assert.match(artifact.worksheet.conclusion.reason, /Queries were not dropped/u);
  assert.match(artifact.worksheet.conclusion.reason, /LDE-only absorb-in-Q bind holds/u);
  const friNode = artifact.worksheet.eventDag.nodes.find((node) => node.eventId === 'event:fri-query');
  assert.equal(friNode.bound.exactUpperBound.numerator, '194064761537588616893622436057812819407110752139587076392381504753256369085797110791359801103580809743810966337141384150771447505514351798930535909380147642400556872002606238193783160703949805603157874899214558593861605856727007232');
  assert.match(friNode.bound.expression, /CONJECTURAL/u);
  assert.match(friNode.bound.expression, /queryCount=90/u);
  assert.match(friNode.bound.expression, /k=45/u);
  assert.match(friNode.bound.expression, /4-to-1/u);
  assert.match(friNode.bound.expression, /2\^-135/u);
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
      'conjectural FRI (2^17/M31^2)^45 union HASH256 floors to 255 bits; 255 is not proven; unique-decoding 2^-135 is not the union; v2 cannot express 128-bit-pass',
    ],
    selected: false,
    systemic128: false,
    ethStark144AsSystemic: false,
    qDeep: artifact.roles.Q_deep,
    neighbors: digests.neighbors,
  });
});

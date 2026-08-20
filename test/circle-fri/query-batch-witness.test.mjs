import { createHash } from 'node:crypto';
import test from 'node:test';
import assert from 'node:assert/strict';

import {
  M31_MODULUS,
} from '../../research-lanes/bch-shielded-pool-design/p2/reference/m31.mjs';

import {
  utf8,
} from '../../src/circle-fri/bytes.mjs';

import {
  encodeCircleFriQueryProof,
  proveCircleFriQueries,
} from '../../src/circle-fri/query-proof.mjs';

import {
  createCircleFriQ2BatchWitness,
  decodeCircleFriQ2BatchWitness,
  encodeCircleFriQ2BatchWitness,
  verifyCircleFriQ2BatchWitness,
} from '../../src/circle-fri/query-batch-witness.mjs';

import {
  circleFriTopologyRecordBytes,
} from '../../src/circle-fri/topology-table.mjs';

const deterministicCoefficients = (length, seed = 0x465249n) => {
  let state = seed;
  return Array.from({ length }, () => {
    state = (state * 2_862_933_555_777_941_757n + 3_037_000_493n) & ((1n << 64n) - 1n);
    return (state >> 11n) % M31_MODULUS;
  });
};

const PARAMETERS = Object.freeze({ logDegreeBound: 6, logBlowup: 3, queryCount: 4 });
const CONTEXT = utf8('ShieldKit Circle-FRI executable query KAT v3');

const buildProof = () => proveCircleFriQueries({
  coefficients: deterministicCoefficients(1 << PARAMETERS.logDegreeBound),
  logBlowup: PARAMETERS.logBlowup,
  queryCount: PARAMETERS.queryCount,
  protocolContext: CONTEXT,
});

const buildWitness = (proof, queryOrdinals) => createCircleFriQ2BatchWitness({
  proof,
  expected: PARAMETERS,
  protocolContext: CONTEXT,
  queryOrdinals,
});

const verifyWitness = (witness, queryOrdinals = witness.queryOrdinals) => (
  verifyCircleFriQ2BatchWitness({
    witness,
    expected: PARAMETERS,
    protocolContext: CONTEXT,
    queryOrdinals,
  })
);

const codecOffsets = (encoded) => {
  const fixedHeader = 4 + 1 + 5 + 2 * 2 + 2 * 4;
  const finalCodeword = fixedHeader;
  const topologyRecords = finalCodeword + (2 ** PARAMETERS.logBlowup) * 4;
  const firstLayer = topologyRecords + 2 * circleFriTopologyRecordBytes(PARAMETERS);
  return Object.freeze({ finalCodeword, topologyRecords, firstLayer });
};

test('q4 public proof packages as two canonical q2 witnesses without changing proof bytes', () => {
  const proof = buildProof();
  const proofBefore = encodeCircleFriQueryProof(proof);
  const first = buildWitness(proof, [0, 1]);
  const second = buildWitness(proof, [2, 3]);
  const proofAfter = encodeCircleFriQueryProof(proof);

  assert.deepEqual(proofAfter, proofBefore);
  assert.deepEqual(first.queryIndices, [394, 174]);
  assert.deepEqual(second.queryIndices, [359, 202]);
  assert.equal(verifyWitness(first).ok, true, verifyWitness(first).reason);
  assert.equal(verifyWitness(second).ok, true, verifyWitness(second).reason);

  for (const witness of [first, second]) {
    assert.deepEqual(witness.topology.indices, [...witness.queryIndices].sort((left, right) => left - right));
    assert.equal(new Set(witness.queryIndices.map((index) => Math.min(index, 511 - index))).size, 2);
    for (const layer of witness.layers) {
      assert.deepEqual(layer.indices, [...new Set(layer.indices)].sort((left, right) => left - right));
      assert.ok(layer.siblings.length < layer.indices.length * PARAMETERS.logDegreeBound + 16);
    }
  }
});

test('exact q2 operand codec round-trips and measures q4 as two q2 packages', () => {
  const proof = buildProof();
  const first = encodeCircleFriQ2BatchWitness(buildWitness(proof, [0, 1]));
  const second = encodeCircleFriQ2BatchWitness(buildWitness(proof, [2, 3]));
  assert.equal(first.length, 3_830);
  assert.equal(second.length, 3_830);
  assert.equal(first.length + second.length, 7_660);
  assert.equal(
    createHash('sha256').update(first).digest('hex'),
    '17359a67d69fba60e096a35f67ac619312ba48f22bb82da562762f1a445a5434',
  );
  assert.equal(
    createHash('sha256').update(second).digest('hex'),
    '486f205da3ceb561c4690ed69c84f4ee07b94a56b4d78f49b7939607c7be3254',
  );

  for (const encoded of [first, second]) {
    const decoded = decodeCircleFriQ2BatchWitness(encoded);
    assert.deepEqual(encodeCircleFriQ2BatchWitness(decoded), encoded);
  }
});

test('builder refuses unverified full paths and altered public fold/final inputs', () => {
  const pathTamper = structuredClone(buildProof());
  pathTamper.queries[0].layers[2].leftSiblings[0][0] ^= 1;
  assert.throws(() => buildWitness(pathTamper, [0, 1]), /source Circle-FRI proof is invalid/);

  const valueTamper = structuredClone(buildProof());
  valueTamper.queries[1].layers[0].rightValue = (valueTamper.queries[1].layers[0].rightValue + 1n) % M31_MODULUS;
  assert.throws(() => buildWitness(valueTamper, [0, 1]), /source Circle-FRI proof is invalid/);

  const finalTamper = structuredClone(buildProof());
  finalTamper.finalCodeword[0] = (finalTamper.finalCodeword[0] + 1n) % M31_MODULUS;
  assert.throws(() => buildWitness(finalTamper, [0, 1]), /source Circle-FRI proof is invalid/);
});

test('verifier rejects batch swaps, query swaps, duplicate queries, and duplicate first-fold orbits', () => {
  const proof = buildProof();
  const first = buildWitness(proof, [0, 1]);
  const second = buildWitness(proof, [2, 3]);
  assert.match(verifyWitness(second, [0, 1]).reason, /expected batch/);

  const ordinalSwap = structuredClone(first);
  ordinalSwap.queryOrdinals.reverse();
  assert.match(verifyWitness(ordinalSwap, [0, 1]).reason, /strictly increasing/);

  const duplicateOrdinal = structuredClone(first);
  duplicateOrdinal.queryOrdinals[1] = duplicateOrdinal.queryOrdinals[0];
  assert.match(verifyWitness(duplicateOrdinal, [0, 1]).reason, /strictly increasing/);

  const querySwap = structuredClone(first);
  querySwap.queryIndices.reverse();
  assert.match(verifyWitness(querySwap, [0, 1]).reason, /public v3 transcript schedule/);

  const duplicateQuery = structuredClone(first);
  duplicateQuery.queryIndices[1] = duplicateQuery.queryIndices[0];
  assert.match(verifyWitness(duplicateQuery, [0, 1]).reason, /distinct/);

  const duplicateOrbit = structuredClone(first);
  duplicateOrbit.queryIndices[1] = (2 ** (PARAMETERS.logDegreeBound + PARAMETERS.logBlowup))
    - 1 - duplicateOrbit.queryIndices[0];
  assert.match(verifyWitness(duplicateOrbit, [0, 1]).reason, /distinct first-fold pairs/);

  const recordSwap = structuredClone(first);
  recordSwap.topology.records.reverse();
  assert.match(verifyWitness(recordSwap, [0, 1]).reason, /canonical query-index order/);
});

test('verifier rejects wrong roots, topology, values, frontiers, fold hints, and final codeword', () => {
  const witness = buildWitness(buildProof(), [0, 1]);

  const rootTamper = structuredClone(witness);
  rootTamper.roots[0][0] ^= 1;
  assert.equal(verifyWitness(rootTamper).ok, false);

  const topologyRootTamper = structuredClone(witness);
  topologyRootTamper.topology.root[0] ^= 1;
  assert.match(verifyWitness(topologyRootTamper).reason, /topology root/);

  const valueTamper = structuredClone(witness);
  valueTamper.layers[0].values[0] = (valueTamper.layers[0].values[0] + 1n) % M31_MODULUS;
  assert.match(verifyWitness(valueTamper).reason, /Merkle multiproof failed/);

  const pathTamper = structuredClone(witness);
  pathTamper.layers[2].siblings[0][0] ^= 1;
  assert.match(verifyWitness(pathTamper).reason, /Merkle multiproof failed/);

  const topologyPathTamper = structuredClone(witness);
  topologyPathTamper.topology.siblings[0][0] ^= 1;
  assert.match(verifyWitness(topologyPathTamper).reason, /topology multiproof failed/);

  const foldHintTamper = structuredClone(witness);
  foldHintTamper.layers[1].inverseTwoCoordinates[0]
    = (foldHintTamper.layers[1].inverseTwoCoordinates[0] + 1n) % M31_MODULUS;
  assert.match(verifyWitness(foldHintTamper).reason, /inverse-coordinate hint failed/);

  const finalTamper = structuredClone(witness);
  finalTamper.finalCodeword[0] = (finalTamper.finalCodeword[0] + 1n) % M31_MODULUS;
  assert.match(verifyWitness(finalTamper).reason, /final codeword is not constant/);
});

test('shape and decoder reject nonminimal frontiers, malformed counts, and noncanonical framing', () => {
  const witness = buildWitness(buildProof(), [0, 1]);
  const extraLayerHash = structuredClone(witness);
  extraLayerHash.layers[0].siblings.push(new Uint8Array(32));
  assert.match(verifyWitness(extraLayerHash).reason, /frontier count is noncanonical/);
  assert.throws(() => encodeCircleFriQ2BatchWitness(extraLayerHash), /frontier count is noncanonical/);

  const extraTopologyHash = structuredClone(witness);
  extraTopologyHash.topology.siblings.push(new Uint8Array(32));
  assert.match(verifyWitness(extraTopologyHash).reason, /topology frontier count is noncanonical/);

  const encoded = encodeCircleFriQ2BatchWitness(witness);
  const decoded = decodeCircleFriQ2BatchWitness(encoded);
  assert.equal(decoded.topology.siblings.length, 0);
  assert.deepEqual(encodeCircleFriQ2BatchWitness(decoded), encoded);
  const offsets = codecOffsets(encoded);
  assert.throws(() => decodeCircleFriQ2BatchWitness(encoded.slice(0, -1)), /truncated/);
  const trailing = new Uint8Array(encoded.length + 1);
  trailing.set(encoded);
  assert.throws(() => decodeCircleFriQ2BatchWitness(trailing), /trailing bytes/);

  const badMagic = encoded.slice();
  badMagic[0] ^= 1;
  assert.throws(() => decodeCircleFriQ2BatchWitness(badMagic), /magic/);
  const oldWitnessVersion = encoded.slice();
  oldWitnessVersion[4] = 0;
  assert.throws(() => decodeCircleFriQ2BatchWitness(oldWitnessVersion), /unsupported q2 witness version/);
  const oldProofVersion = encoded.slice();
  oldProofVersion[5] = 2;
  assert.throws(() => decodeCircleFriQ2BatchWitness(oldProofVersion), /query proof v3/);

  const noncanonicalM31 = encoded.slice();
  noncanonicalM31.set(Uint8Array.of(0xff, 0xff, 0xff, 0x7f), offsets.finalCodeword);
  assert.throws(() => decodeCircleFriQ2BatchWitness(noncanonicalM31), /not canonical/);
  const badTopologyRecord = encoded.slice();
  badTopologyRecord[offsets.topologyRecords] ^= 1;
  assert.throws(() => decodeCircleFriQ2BatchWitness(badTopologyRecord), /topology record magic/);

  const wrongValueCount = encoded.slice();
  wrongValueCount[offsets.firstLayer] += 1;
  assert.throws(() => decodeCircleFriQ2BatchWitness(wrongValueCount), /value count is noncanonical/);
  const nonminimalLayerCount = encoded.slice();
  nonminimalLayerCount[offsets.firstLayer + 2] += 1;
  assert.throws(() => decodeCircleFriQ2BatchWitness(nonminimalLayerCount), /frontier count is noncanonical/);
});

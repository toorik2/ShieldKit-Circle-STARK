import { createHash } from 'node:crypto';
import test from 'node:test';
import assert from 'node:assert/strict';

import { M31_MODULUS } from '../../research-lanes/bch-shielded-pool-design/p2/reference/m31.mjs';

import { utf8 } from '../../src/circle-fri/bytes.mjs';

import {
  decodeCircleFriQueryProof,
  encodeCircleFriQueryProof,
  estimateCircleFriQueryProofBytes,
  proveCircleFriQueries,
  verifyCircleFriQueries,
} from '../../src/circle-fri/query-proof.mjs';

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

test('one complete Circle-FRI proof verifies through every Merkle and fold layer', () => {
  const proof = buildProof();
  const verdict = verifyCircleFriQueries({ proof, expected: PARAMETERS, protocolContext: CONTEXT });
  assert.equal(verdict.ok, true, verdict.reason);
  assert.equal(new Set(verdict.queryIndices).size, PARAMETERS.queryCount);
  assert.equal(
    new Set(verdict.queryIndices.map((index) => Math.min(index, (2 ** (PARAMETERS.logDegreeBound + PARAMETERS.logBlowup)) - 1 - index))).size,
    PARAMETERS.queryCount,
  );
  assert.equal(verdict.betas.length, PARAMETERS.logDegreeBound);
  assert.equal(proof.finalCodeword.length, 1 << PARAMETERS.logBlowup);
  assert.equal(new Set(proof.finalCodeword).size, 1);
  assert.equal(proof.dimensionGapLambda, 0n);
});

test('canonical proof codec round-trips with an exact measured byte length', () => {
  const proof = buildProof();
  const encoded = encodeCircleFriQueryProof(proof);
  assert.equal(encoded.length, 10_409);
  assert.equal(encoded.length, estimateCircleFriQueryProofBytes(PARAMETERS));
  assert.equal(
    createHash('sha256').update(encoded).digest('hex'),
    'bff11c09dc44215fc684eaa33e3b7cbcf5b16ac5f8674a8fa3db6ec9c6455df8',
  );
  const decoded = decodeCircleFriQueryProof(encoded);
  assert.deepEqual(encodeCircleFriQueryProof(decoded), encoded);
  assert.equal(
    verifyCircleFriQueries({ proof: decoded, expected: PARAMETERS, protocolContext: CONTEXT }).ok,
    true,
  );
});

test('complete proofs verify across several degree and blowup sizes', () => {
  for (const [logDegreeBound, logBlowup, queryCount] of [
    [1, 0, 1],
    [2, 2, 3],
    [4, 3, 4],
    [8, 2, 5],
  ]) {
    const proof = proveCircleFriQueries({
      coefficients: deterministicCoefficients(1 << logDegreeBound, BigInt(logDegreeBound * 100 + logBlowup)),
      logBlowup,
      queryCount,
      protocolContext: CONTEXT,
    });
    assert.equal(verifyCircleFriQueries({
      proof,
      expected: { logDegreeBound, logBlowup, queryCount },
      protocolContext: CONTEXT,
    }).ok, true);
  }
});

test('wrong context, expected parameters, root, opening, or final value rejects', () => {
  const proof = buildProof();
  assert.equal(verifyCircleFriQueries({
    proof,
    expected: PARAMETERS,
    protocolContext: utf8('wrong context'),
  }).ok, false);
  assert.equal(verifyCircleFriQueries({
    proof,
    expected: { ...PARAMETERS, queryCount: 3 },
    protocolContext: CONTEXT,
  }).ok, false);

  const rootTamper = structuredClone(proof);
  rootTamper.roots[0][0] ^= 1;
  assert.equal(verifyCircleFriQueries({ proof: rootTamper, expected: PARAMETERS, protocolContext: CONTEXT }).ok, false);

  const valueTamper = structuredClone(proof);
  valueTamper.queries[0].layers[0].leftValue = (valueTamper.queries[0].layers[0].leftValue + 1n) % M31_MODULUS;
  assert.equal(verifyCircleFriQueries({ proof: valueTamper, expected: PARAMETERS, protocolContext: CONTEXT }).ok, false);

  const pathTamper = structuredClone(proof);
  pathTamper.queries[0].layers[1].rightSiblings[0][0] ^= 1;
  assert.equal(verifyCircleFriQueries({ proof: pathTamper, expected: PARAMETERS, protocolContext: CONTEXT }).ok, false);

  const finalTamper = structuredClone(proof);
  finalTamper.finalCodeword[0] = (finalTamper.finalCodeword[0] + 1n) % M31_MODULUS;
  assert.equal(verifyCircleFriQueries({ proof: finalTamper, expected: PARAMETERS, protocolContext: CONTEXT }).ok, false);
});

test('proof decoder rejects truncation, trailing bytes, bad magic, and noncanonical fields', () => {
  const encoded = encodeCircleFriQueryProof(buildProof());
  assert.throws(() => decodeCircleFriQueryProof(encoded.slice(0, -1)), /canonical length/);
  const trailing = new Uint8Array(encoded.length + 1);
  trailing.set(encoded);
  assert.throws(() => decodeCircleFriQueryProof(trailing), /canonical length/);
  const badMagic = encoded.slice();
  badMagic[0] ^= 1;
  assert.throws(() => decodeCircleFriQueryProof(badMagic), /magic/);
  const oldVersion = encoded.slice();
  oldVersion[4] = 2;
  assert.throws(() => decodeCircleFriQueryProof(oldVersion), /unsupported/);
  const noncanonical = encoded.slice();
  const finalOffset = 9 + PARAMETERS.logDegreeBound * 32;
  noncanonical.set(Uint8Array.of(0xff, 0xff, 0xff, 0x7f), finalOffset);
  assert.throws(() => decodeCircleFriQueryProof(noncanonical), /not canonical/);
  assert.throws(() => proveCircleFriQueries({
    coefficients: [1n, 2n, 3n, 4n],
    logBlowup: 0,
    queryCount: 3,
    protocolContext: CONTEXT,
  }), /domainLength \/ 2/);
});

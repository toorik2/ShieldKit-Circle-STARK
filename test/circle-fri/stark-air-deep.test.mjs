import test from 'node:test';
import assert from 'node:assert/strict';

import {
  CIRCLE_DEEP_STRATEGY,
} from '../../src/circle-fri/deep.mjs';

import {
  provePoolActionAirDeep,
  verifyPoolActionAirDeep,
  publicFeltsFromStatement,
} from '../../src/circle-fri/stark-air.mjs';

import {
  depositStatement,
} from './pool-action-statement-fixture.mjs';

test('honest bound-statement AIR+DEEP proof accepts; DEEP is pinned Re/Im', () => {
  const statement = depositStatement();
  const proof = provePoolActionAirDeep({ statement, queryCount: 2, logBlowup: 3 });
  assert.equal(proof.deepStrategy, CIRCLE_DEEP_STRATEGY);
  assert.equal(CIRCLE_DEEP_STRATEGY, 'circle-deep-re-im-v1');
  const verdict = verifyPoolActionAirDeep({ proof, expectedStatement: statement });
  assert.equal(verdict.ok, true, verdict.reason);
  assert.equal(verdict.deepStrategy, 'circle-deep-re-im-v1');
  assert.equal(proof.deepFriCompatible, false);
  assert.equal(proof.evenXDeep.labeledFriOfDeep, true);
  assert.match(proof.deepFriWall ?? '', /not degree < 64/u);
  console.log('AIR_DEEP_HONEST', {
    accept: true,
    deepStrategy: proof.deepStrategy,
    deepFriCompatible: proof.deepFriCompatible,
    deepFriWall: proof.deepFriWall,
    proven: ['AIR binds PAST', 'f(ζ) recomputes', 'FRI of bound trace'],
    failed: ['Re/Im DEEP still not Circle-FFT low-degree'],
    speculative: [],
  });
});

test('garbage coefficients reject', () => {
  const statement = depositStatement();
  const proof = provePoolActionAirDeep({ statement, queryCount: 2, logBlowup: 3 });
  const garbage = structuredClone(proof);
  garbage.coefficients = proof.coefficients.map((value, index) => (
    index === 0 ? (value + 1n) % 2147483647n : value
  ));
  const verdict = verifyPoolActionAirDeep({ proof: garbage, expectedStatement: statement });
  assert.equal(verdict.ok, false);
  assert.match(verdict.reason ?? '', /garbage coefficients|not the bound statement|FRI/u);
  console.log('AIR_DEEP_GARBAGE', { rejected: true, reason: verdict.reason });
});

test('unbound or mutated statement rejects', () => {
  const statement = depositStatement();
  const proof = provePoolActionAirDeep({ statement, queryCount: 2, logBlowup: 3 });
  assert.equal(verifyPoolActionAirDeep({ proof, expectedStatement: null }).ok, false);
  const flipped = depositStatement();
  flipped.transactionContextDigestHex = '99'.repeat(32);
  const unbound = verifyPoolActionAirDeep({ proof, expectedStatement: flipped });
  assert.equal(unbound.ok, false);
  console.log('AIR_DEEP_UNBOUND', { rejected: true, reason: unbound.reason });
});

test('public felts are derived from the PAST statement, not a random CFFT vector', () => {
  const felts = publicFeltsFromStatement(depositStatement());
  assert.equal(felts.length, 14);
  assert.equal(felts[0], 0n);
  assert.equal(felts[1], 0n);
  assert.equal(felts[2], 1n);
});

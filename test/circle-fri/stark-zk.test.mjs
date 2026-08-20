import test from 'node:test';
import assert from 'node:assert/strict';

import {
  provePoolActionAirDeep,
} from '../../src/circle-fri/stark-air.mjs';

import {
  DEGREE0_MASK_KIND,
  classifyZkMask,
  observePublicProof,
  provePoolActionAirDeepZk,
  verifyPoolActionAirDeepZk,
} from '../../src/circle-fri/stark-zk.mjs';

import {
  depositStatement,
} from './pool-action-statement-fixture.mjs';

import {
  buildHonestDeposit,
} from '../../src/circle-fri/pool-action-fixtures.mjs';

import {
  provePoolActionRelation,
} from '../../src/circle-fri/pool-action-relation.mjs';

import {
  observePoseidon2Air,
  observeSnapshot0Inversion,
  provePoseidon2Air,
} from '../../src/circle-fri/poseidon2-air.mjs';

import {
  hexToBytes,
} from '../../research-lanes/bch-shielded-pool-design/p1/codec/common.mjs';

import {
  measureNestedLdeSubset,
  measureNestedTraceCoset,
} from '../../src/circle-fri/nested-coset.mjs';

import {
  measurePublishedCircleHashLane,
} from '../../src/circle-fri/algebraic-hash-air.mjs';

const TICKET = 10_000_000n;

test('public AIR+DEEP proof does not reveal rho, owner, or secret amount slot; degree-0 is failed', () => {
  const statement = depositStatement();
  const rho = Uint8Array.from({ length: 32 }, (_, index) => index + 3);
  const owner = Uint8Array.from({ length: 32 }, (_, index) => 200 - index);
  const proof = provePoolActionAirDeepZk({ statement, rho, owner, queryCount: 2, logBlowup: 3 });
  assert.equal(proof.zk.kind, 'zh-r-lde-tail-v1');
  assert.equal(proof.zk.hiddenStart, 64);
  assert.equal(proof.coefficients.length, 128);
  assert.equal(proof.zk.newtonTRecoverable, false);
  assert.equal(proof.zk.viewingKey, undefined);
  assert.equal(typeof proof.evaluate, 'function');
  assert.notEqual(proof.evaluate(proof.slots.amountSlot), TICKET);
  assert.notEqual(proof.evaluate(proof.slots.ownerSlot), proof.evaluate(0));
  const verdict = verifyPoolActionAirDeepZk({ proof, expectedStatement: statement });
  assert.equal(verdict.ok, true, verdict.reason);
  assert.equal(verdict.zhR, true);
  assert.equal(verdict.zhREvenX, true);
  assert.equal(verdict.evenXDeep, 'circle-deep-even-x-quotient-v1');
  assert.equal(proof.evenXDeep.labeledFriOfDeep, true);
  assert.equal(proof.evenXDeep.zhR.kind, 'zh-r-even-x-deep-v1');
  assert.equal(proof.evenXDeep.zhR.onChain, false);
  assert.equal(proof.evenXDeep.zhRCoefficients.length, 128);
  const observed = observePublicProof(proof, { rho, owner, amount: TICKET });
  assert.equal(observed.rho, null);
  assert.equal(observed.owner, null);
  assert.equal(observed.amount, null);
  assert.equal(observed.newtonTRecoveredMask, false);

  const deposit = buildHonestDeposit();
  const relation = provePoolActionRelation(deposit);
  assert.equal(relation.poseidon2Air.columnCoefficients, undefined);
  assert.equal(relation.poseidon2Air.hostColumnCoefficients, undefined);
  const snapshot0Public = observeSnapshot0Inversion(relation.poseidon2Air, {
    owner: deposit.witness.owner,
    rho: deposit.witness.rho,
  });
  assert.equal(snapshot0Public.leaked, false);
  const airObserved = observePublicProof(relation.poseidon2Air, {
    rho: deposit.witness.rho,
    owner: deposit.witness.owner,
    amount: TICKET,
  });
  assert.equal(airObserved.owner, null);
  assert.equal(airObserved.rho, null);
  const limbObserved = observePoseidon2Air(relation.poseidon2Air, {
    owner: deposit.witness.owner,
    rho: deposit.witness.rho,
  });
  assert.equal(limbObserved.leaked, false);
  assert.equal(limbObserved.owner, null);
  assert.equal(limbObserved.rho, null);
  const degree0 = classifyZkMask({ kind: DEGREE0_MASK_KIND, newtonTRecoverable: true });
  assert.equal(degree0.status, 'failed');
  const nesting = measureNestedTraceCoset({ logTrace: 6, logBlowup: 3 });
  assert.equal(nesting.nested, false);
  assert.equal(nesting.intersection, 0);
  assert.match(nesting.wall ?? '', /0\/64/u);
  const nestedSubset = measureNestedLdeSubset({ logTrace: 10, logBlowup: 4 });
  assert.equal(nestedSubset.nestedCfft, false);
  assert.equal(nestedSubset.uniqueHXsInD, 0);
  assert.match(nestedSubset.wall ?? '', /x\(H\)∩x\(LDE\)=0\/512/u);
  assert.match(nestedSubset.wall ?? '', /Not 0\/64, not 0\/1024 restated/u);
  const hashLane = measurePublishedCircleHashLane();
  assert.equal(hashLane.selectedAir, 'poseidon2-m31-grain-t16-a5-rf8-rp14');
  assert.equal(hashLane.nestedCfft, false);
  assert.equal(hashLane.envelopeFit, true);
  assert.equal(hashLane.sTotal128, false);
  assert.notEqual(hashLane.absorbOpenedWithoutRateLeak, true);
  assert.match(hashLane.remainingProductionWalls ?? '', /LDE-only absorb-in-Q bind holds/u);
  assert.doesNotMatch(hashLane.remainingProductionWalls ?? '', /cannot state a production Circle STARK/u);
  console.log('ZK_OBSERVER', {
    proven: [
      'secret-slot interpolant !== ticket/hash(owner)/hash(rho)',
      'degree-0 classified failed',
      'Z_H·R on even-x DEEP FRI domain recomputes and verifies',
      'public poseidon2Air omits TRACE interpolant; snapshot0 inversion does not recover owner||rho',
      'AIR-bound-to-the-table (LDE-only; TRACE merkle forbidden)',
    ],
    failed: [nestedSubset.wall, hashLane.wall, hashLane.remainingProductionWalls],
    speculative: ['nested CFFT H⊂LDE still failed; conjectural FRI (2^16/M31^2)^13 ∪ HASH256 floors to 255 bits and is not proven; unique-decoding is (1/4)^13=2^-26; HLP24 on CM31 is 10 bits; v2 cannot express 128-bit-pass'],
    nestedCoset: nesting,
    nestedLdeSubset: nestedSubset,
    publishedHashLane: hashLane,
    observed,
  });
});

test('observer interpolant evaluation catches an unmasked AIR proof', () => {
  const statement = depositStatement();
  const rho = Uint8Array.from({ length: 32 }, (_, index) => index + 7);
  const owner = Uint8Array.from({ length: 32 }, (_, index) => 180 - index);
  const raw = provePoolActionAirDeep({
    statement,
    witness: { rho, owner, amountFelt: TICKET },
    queryCount: 2,
    logBlowup: 3,
  });
  const leaked = observePublicProof(raw, { rho, owner, amount: TICKET });
  assert.equal(leaked.amount, 'unmasked-interpolant');
  assert.equal(leaked.rho, 'unmasked-interpolant');
  assert.equal(leaked.owner, 'unmasked-interpolant');
  const deposit = buildHonestDeposit();
  const hostColumns = provePoseidon2Air({
    statement: deposit.statement,
    poolInstanceId: hexToBytes(deposit.statement.poolInstanceIdHex, 'pool'),
    owner: deposit.witness.owner,
    rho: deposit.witness.rho,
    includeHostColumns: true,
  });
  const airLeak = observePoseidon2Air(hostColumns, {
    owner: deposit.witness.owner,
    rho: deposit.witness.rho,
  });
  assert.equal(airLeak.owner, 'unmasked-column-fft');
  assert.equal(airLeak.rho, 'unmasked-column-fft');
  const snapshot0Host = observeSnapshot0Inversion(hostColumns, {
    owner: deposit.witness.owner,
    rho: deposit.witness.rho,
  });
  assert.equal(snapshot0Host.leaked, true);
  assert.equal(snapshot0Host.method, 'snapshot0-external-inverse');
  console.log('ZK_UNMASKED_CAUGHT', { leaked, airLeak, snapshot0Host });
});

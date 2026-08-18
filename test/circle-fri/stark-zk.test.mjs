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
  provePoseidon2Air,
} from '../../src/circle-fri/poseidon2-air.mjs';

import {
  hexToBytes,
} from '../../research-lanes/bch-shielded-pool-design/p1/codec/common.mjs';

import {
  measureNestedTraceCoset,
} from '../../src/circle-fri/nested-coset.mjs';

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
  assert.equal(relation.poseidon2Air.columnCoefficients.length, 16);
  assert.equal(relation.poseidon2Air.hostColumnCoefficients, undefined);
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
  console.log('ZK_OBSERVER', {
    proven: [
      'secret-slot interpolant !== ticket/hash(owner)/hash(rho)',
      'degree-0 classified failed',
      'Z_H·R on even-x DEEP FRI domain recomputes and verifies',
      'public poseidon2Air publishes masked columnCoefficients; limb FFT does not recover owner||rho',
    ],
    failed: [],
    speculative: ['128-coset tail remains; nested H⊂LDE cannot be stated for this CFFT family; 2^14 AIR Z_H·R is host-only (32768-coeff)'],
    nestedCoset: nesting,
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
  console.log('ZK_UNMASKED_CAUGHT', { leaked, airLeak });
});

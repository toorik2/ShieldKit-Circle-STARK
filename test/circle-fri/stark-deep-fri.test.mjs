import test from 'node:test';
import assert from 'node:assert/strict';

import {
  CIRCLE_DEEP_STRATEGY,
} from '../../src/circle-fri/deep.mjs';

import {
  CIRCLE_DEEP_E_ONLY,
  proveEOnlyDeepOrWall,
} from '../../src/circle-fri/deep-e-only.mjs';

import {
  CIRCLE_DEEP_STWO,
  measureStwoDeepOrWall,
} from '../../src/circle-fri/deep-stwo.mjs';

import {
  CIRCLE_DEEP_EVEN_X,
  proveEvenXDeepFri,
  verifyEvenXDeepFri,
} from '../../src/circle-fri/deep-pi-native.mjs';

import {
  verifyCircleFriQueries,
} from '../../src/circle-fri/query-proof.mjs';

import {
  buildStandardCoset,
} from '../../src/circle-fri/circle.mjs';

import {
  provePoolActionAirDeep,
} from '../../src/circle-fri/stark-air.mjs';

import {
  provePoseidon2Air,
} from '../../src/circle-fri/poseidon2-air.mjs';

import {
  hexToBytes,
} from '../../research-lanes/bch-shielded-pool-design/p1/codec/common.mjs';

import {
  buildHonestDeposit,
} from '../../src/circle-fri/pool-action-fixtures.mjs';

import {
  depositStatement,
} from './pool-action-statement-fixture.mjs';

test('DEEP is pinned; FRI-of-DEEP is a named wall, not a relabel', () => {
  const proof = provePoolActionAirDeep({
    statement: depositStatement(),
    queryCount: 2,
    logBlowup: 3,
  });
  assert.equal(proof.deepStrategy, CIRCLE_DEEP_STRATEGY);
  assert.equal(proof.deepFriCompatible, false);
  assert.match(proof.deepFriWall ?? '', /not degree < 64/u);
  const even = proof.coefficients.slice(0, proof.coefficients.length / 2);
  const eonly = proveEOnlyDeepOrWall(even);
  assert.equal(eonly.strategy, CIRCLE_DEEP_E_ONLY);
  assert.equal(eonly.friOfDeep, false);
  assert.equal(eonly.labeledFriOfDeep, false);
  assert.ok(eonly.wall);
  const lde = buildStandardCoset(proof.parameters.logDegreeBound + proof.parameters.logBlowup);
  const stwo = measureStwoDeepOrWall({
    coefficients: proof.coefficients,
    ldeDomain: lde,
    zeta: { x: proof.zeta.x, y: proof.zeta.y },
    degreeBound: proof.coefficients.length,
  });
  assert.equal(stwo.strategy, CIRCLE_DEEP_STWO);
  assert.equal(stwo.friOfDeep, false);
  assert.equal(stwo.labeledFriOfDeep, false);
  const evenX = proveEvenXDeepFri({
    evenCoefficients: even,
    ldeDomain: lde,
    zetaX: proof.zeta.x,
    logBlowup: proof.parameters.logBlowup,
    queryCount: 2,
    contextSeed: 'gating',
  });
  assert.equal(evenX.strategy, CIRCLE_DEEP_EVEN_X);
  assert.equal(evenX.friOfDeep, true);
  assert.equal(evenX.labeledFriOfDeep, true);
  assert.equal(evenX.wall, null);
  assert.equal(evenX.nonzero, 31);
  assert.equal(evenX.zhR.kind, 'zh-r-even-x-deep-v1');
  assert.equal(evenX.zhR.onChain, false);
  assert.equal(evenX.parameters.logDegreeBound, 6);
  const evenV = verifyEvenXDeepFri({
    evenCoefficients: even,
    ldeDomain: lde,
    zetaX: proof.zeta.x,
    deepFri: evenX,
  });
  assert.equal(evenV.ok, true, evenV.reason);
  const fri = verifyCircleFriQueries({
    proof: evenX.friProof,
    expected: evenX.parameters,
    protocolContext: evenX.protocolContext,
  });
  assert.equal(fri.ok, true, fri.reason);
  assert.equal(proof.evenXDeep.labeledFriOfDeep, true);
  const deposit = buildHonestDeposit();
  const air = provePoseidon2Air({
    statement: deposit.statement,
    poolInstanceId: hexToBytes(deposit.statement.poolInstanceIdHex, 'pool'),
    owner: deposit.witness.owner,
    rho: deposit.witness.rho,
  });
  assert.equal(air.labeledFriOfAir, true);
  assert.equal(air.interpolantFri, false);
  assert.equal(air.residualObject, 'poseidon2-m31-absorb-snapshot-quotient-v1');
  assert.equal(air.bind, 'lde-only-commitment-v1');
  assert.equal(air.wall, null);
  assert.ok(air.ldeOpenings);
  assert.equal(air.rowMerkleRoot, undefined);
  assert.ok((air.quotientNonzero ?? 0) > 0);
  assert.equal(air.evenXDeep.parameters.logDegreeBound, 14);
  assert.equal(air.evenXDeep.parameters.logBlowup, 3);
  assert.equal(air.evenXDeep.parameters.queryCount, 90);
  assert.equal(air.evenXDeep.zhR.onChain, true);
  assert.match(air.evenXDeep.zhR.reason, /redeem 5168/u);
  assert.match(air.evenXDeep.zhR.reason, /tx 99265/u);
  assert.ok(air.transitions > 0);
  console.log('DEEP_FRI', {
    proven: [
      'even-x DEEP (even(x)-even(ζx))/(x-ζx) is Circle-FFT deg<64',
      'J-then-π FRI prove/verify accepts that codeword',
      'labeledFriOfDeep true',
      'TRACE-64 even-x FRI remains of the bound interpolant',
      'Poseidon2-M31 absorb+snapshot Q even-x FRI, LDE-opened at zeta',
      'AIR-bound-to-the-table (LDE-only; TRACE merkle forbidden)',
    ],
    failed: [
      `Re/Im still dense: ${proof.deepFriWall}`,
      `E-only interpolant is not this object: ${eonly.wall}`,
      `Stwo inner-product still dense: ${stwo.wall}`,
    ],
    speculative: [],
    labeledFriOfDeep: true,
    evenXStrategy: evenX.strategy,
    nonzero: evenX.nonzero,
  });
});

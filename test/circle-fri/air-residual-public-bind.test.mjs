import test from 'node:test';
import assert from 'node:assert/strict';

import {
  createTestAuthenticationProgramBch,
  createVirtualMachineBch2026,
} from '@bitauth/libauth';

import {
  decodeM31,
  mul,
} from '../../research-lanes/bch-shielded-pool-design/p2/reference/m31.mjs';

import { hexToBytes } from '../../research-lanes/bch-shielded-pool-design/p1/codec/common.mjs';

import { buildHonestDeposit } from '../../src/circle-fri/pool-action-fixtures.mjs';

import {
  provePoseidon2Air,
  encodeAirResidualUnlocking,
  publicBindRows,
  buildPhaseSelectors,
  POSEIDON2_AIR_ROWS,
} from '../../src/circle-fri/poseidon2-air.mjs';

import {
  evaluateConstraintResidualAt,
  buildAirResidualUnlockingDefs,
  encodeAirResidualPublic,
  encodeAirResidualTape,
  FUNCTION_AIR_RESIDUAL,
  residualKernelInternals as K,
} from '../../src/circle-fri/bch-air-residual-kernel.mjs';

import { buildStandardCoset } from '../../src/circle-fri/circle.mjs';
import { createCircleFriQ2BatchWitness } from '../../src/circle-fri/query-batch-witness.mjs';
import {
  createBchCircleFriQ2BatchFixture,
  encodeBchCircleFriQ2PartitionP2sTransactionFixture,
  evaluateBchCircleFriQ2PartitionTransactionFixture,
} from '../../src/circle-fri/bch-query-batch-kernel.mjs';
import { circleIFFT, evaluateCirclePolynomial } from '../../src/circle-fri/cfft.mjs';

const evalResidual = (locking, tape) => {
  const pad = new Uint8Array(2200);
  const unlocking = K.concat(K.encodeMinimalDataPush(pad), K.encodeMinimalDataPush(tape));
  const vm = createVirtualMachineBch2026(true);
  const state = vm.evaluate(createTestAuthenticationProgramBch({
    lockingBytecode: locking,
    unlockingBytecode: unlocking,
    valueSatoshis: 1000n,
  }));
  const top = state.stack?.[0];
  const accepted = state.error === undefined
    && state.stack?.length === 1
    && top?.length === 1
    && top[0] === 1
    && (state.alternateStack?.length ?? 0) === 0;
  return { accepted, error: state.error ?? null };
};

test('on-chain residual C/Z equals FRI Q with public binds at transcript zeta', { timeout: 120_000 }, () => {
  const bundle = buildHonestDeposit();
  const air = provePoseidon2Air({
    statement: bundle.statement,
    poolInstanceId: hexToBytes(bundle.statement.poolInstanceIdHex, 'pool'),
    owner: bundle.witness.owner,
    rho: bundle.witness.rho,
    queryCount: 2,
    logBlowup: 3,
  });
  const friQ = decodeM31(air.airResidualQ);
  const lde = air.ldeOpenings;
  const LDE = buildStandardCoset(14);
  const H = buildStandardCoset(10);
  const selAt = (column) => evaluateCirclePolynomial(circleIFFT(H, column), LDE[lde.index]);
  const selectors = buildPhaseSelectors(air.layout);
  const snapSelectors = selectors.snap.map((column) => selAt(column));
  const x = LDE[lde.index].x;
  const empty = evaluateConstraintResidualAt({
    state: lde.state,
    next: lde.next,
    prev: lde.prev,
    snapSelectors,
    freshSelector: selAt(selectors.fresh),
    contSelector: selAt(selectors.cont),
    publicBinds: [],
    x,
  });
  assert.notEqual(empty.expectedQ, friQ, 'empty-bind Q must not equal FRI Q at zeta');

  const residual = encodeAirResidualUnlocking(air);
  assert.equal(residual.host.expectedQ, friQ, 'encoded residual Q must be the FRI-absorbed Q');
  assert.equal(mul(residual.host.vanishing, residual.host.invZ), 1n, 'π⁹(x)·invZ must be 1');
  const binds = publicBindRows(air.layout, air.publicFelts, air.statementPublicFelts);
  assert.ok(binds.length >= 1);
  assert.ok(binds.every((bind) => bind.row >= 0 && bind.row < POSEIDON2_AIR_ROWS));
  assert.ok(binds.some((bind) => selAt((() => {
    const column = new Array(POSEIDON2_AIR_ROWS).fill(0n);
    column[bind.row] = 1n;
    return column;
  })()) !== 0n), 'at least one public-bind selector is live at zeta');

  const locking = K.concat(
    buildAirResidualUnlockingDefs({ airResidualQ: air.airResidualQ, zetaX: x }),
    K.invokeFunction(FUNCTION_AIR_RESIDUAL),
    Uint8Array.of(0x77),
  );
  const honest = evalResidual(locking, residual.tape);
  assert.equal(honest.accepted, true, honest.error ?? 'honest residual rejected');

  const emptyBlob = encodeAirResidualPublic({
    snapSelectors,
    freshSelector: selAt(selectors.fresh),
    contSelector: selAt(selectors.cont),
    publicBinds: [],
    x,
    expectedQ: empty.expectedQ,
    invZ: empty.invZ,
  });
  const emptyTape = encodeAirResidualTape({
    state: lde.state,
    next: lde.next,
    prev: lde.prev,
    publicBlob: emptyBlob,
  });
  const emptyWalk = evalResidual(locking, emptyTape);
  assert.equal(emptyWalk.accepted, false, 'empty-bind blob Q must not satisfy FRI-absorbed Q');

  const wrongXTape = Uint8Array.from(residual.tape);
  wrongXTape[wrongXTape.length - 12] ^= 1;
  const wrongXWalk = evalResidual(locking, wrongXTape);
  assert.equal(wrongXWalk.accepted, false, 'blob x must equal LDE[transcript zeta].x');

  console.log('PUBLIC_BIND_RESIDUAL', {
    emptyQ: empty.expectedQ.toString(),
    friQ: friQ.toString(),
    hostQ: residual.host.expectedQ.toString(),
    emptyEqualsFri: empty.expectedQ === friQ,
    hostEqualsFri: residual.host.expectedQ === friQ,
    pi9InvZ: mul(residual.host.vanishing, residual.host.invZ).toString(),
    honestAccepted: honest.accepted,
    emptyBlobRejected: emptyWalk.accepted === false,
    emptyBlobError: emptyWalk.error,
    wrongXRejected: wrongXWalk.accepted === false,
    wrongXError: wrongXWalk.error,
    zetaIndex: lde.index,
    zetaX: x.toString(),
    redeemDefs: locking.length,
  });
});

test('VERIFY_AIR_LDE binds opening indices to transcript zeta / zeta±stride', { timeout: 120_000 }, () => {
  const bundle = buildHonestDeposit();
  const air = provePoseidon2Air({
    statement: bundle.statement,
    poolInstanceId: hexToBytes(bundle.statement.poolInstanceIdHex, 'pool'),
    owner: bundle.witness.owner,
    rho: bundle.witness.rho,
    queryCount: 6,
    logBlowup: 3,
  });
  const residual = encodeAirResidualUnlocking(air);
  const deep = air.evenXDeep;
  const airLdeRoot = new Uint8Array(air.ldeMerkleRoot);
  const fixturesFor = ({ swapStateNext = false } = {}) => {
    const fixtures = [];
    for (let batch = 0; batch < 3; batch += 1) {
      const residualHere = batch === 0;
      fixtures.push(createBchCircleFriQ2BatchFixture({
        witness: createCircleFriQ2BatchWitness({
          proof: deep.friProof,
          expected: deep.parameters,
          protocolContext: deep.protocolContext,
          queryOrdinals: [batch * 2, batch * 2 + 1],
          airResidualQ: air.airResidualQ,
          airLdeRoot,
        }),
        expected: deep.parameters,
        protocolContext: deep.protocolContext,
        airResidualQ: air.airResidualQ,
        airLdeZeta: air.ldeOpenings.index,
        airLdeOpening: residualHere
          ? (swapStateNext ? residual.nextOpening : residual.stateOpening)
          : null,
        airLdeOpeningNext: residualHere
          ? (swapStateNext ? residual.stateOpening : residual.nextOpening)
          : null,
        airLdeOpeningPrev: residualHere ? residual.prevOpening : null,
        airResidualPublic: residualHere ? residual.publicBlob : null,
        airLdeRoot,
      }));
    }
    return fixtures;
  };
  const evalFixtures = (fixtures) => {
    const wires = encodeBchCircleFriQ2PartitionP2sTransactionFixture(fixtures, {
      unlockingFloor: 10_000,
      clustersPerInput: 3,
    });
    return evaluateBchCircleFriQ2PartitionTransactionFixture(wires);
  };
  const honest = evalFixtures(fixturesFor());
  assert.equal(honest.every((row) => row.accepted), true, honest[0]?.error);
  const swapped = evalFixtures(fixturesFor({ swapStateNext: true }));
  assert.equal(swapped.every((row) => row.accepted), false, 'next-row opening must not satisfy zeta index');
});

/**
 * BCH-2026 partition of the Poseidon2-M31 snapshot-quotient even-x DEEP FRI.
 * Does not fall back to statement-bound 64-coeff interpolant FRI or to
 * state-composition even-x. q2 unlocking at blowup 2 is a measured 10k wall.
 */

import {
  PARTITION_UNLOCKING_FLOOR,
  countOpInputBytecode,
  createBchCircleFriQ2BatchFixture,
  encodeBchCircleFriQ2PartitionP2sTransactionFixture,
  encodeBchCircleFriQ2PartitionTransactionFixture,
  evaluateBchCircleFriQ2PartitionTransactionFixture,
} from './bch-query-batch-kernel.mjs';

import {
  createCircleFriQ2BatchWitness,
} from './query-batch-witness.mjs';

import {
  provePoolActionRelation,
  verifyPoolActionRelation,
} from './pool-action-relation.mjs';

import {
  provePoseidon2Air,
} from './poseidon2-air.mjs';

import {
  hexToBytes,
} from '../../research-lanes/bch-shielded-pool-design/p1/codec/common.mjs';

const buildAirFixtures = (deep) => {
  const fixtures = [];
  for (let batch = 0; batch < deep.parameters.queryCount / 2; batch += 1) {
    fixtures.push(createBchCircleFriQ2BatchFixture({
      witness: createCircleFriQ2BatchWitness({
        proof: deep.friProof,
        expected: deep.parameters,
        protocolContext: deep.protocolContext,
        queryOrdinals: [batch * 2, batch * 2 + 1],
      }),
      expected: deep.parameters,
      protocolContext: deep.protocolContext,
    }));
  }
  return fixtures;
};

export const evaluateRelationBoundPartition = ({
  statement,
  witness,
  queryCount = 4,
  logBlowup = 1,
  maxFriNonce = 32,
}) => {
  const pool = hexToBytes(statement.poolInstanceIdHex, 'poolInstanceId');
  let poseidon2Air = null;
  let fixtures = null;
  let lastError = null;
  for (let friNonce = 0; friNonce <= maxFriNonce; friNonce += 1) {
    poseidon2Air = provePoseidon2Air({
      statement,
      poolInstanceId: pool,
      owner: witness.owner,
      rho: witness.rho,
      logBlowup,
      queryCount,
      friNonce,
    });
    const deep = poseidon2Air.evenXDeep;
    if (!deep?.friProof || deep.labeledFriOfDeep !== true) {
      lastError = new TypeError('AIR even-x DEEP FRI object is missing');
      continue;
    }
    if ((deep.nonzero ?? 0) < 1) {
      lastError = new TypeError('AIR composition FRI is degenerate (zero codeword)');
      continue;
    }
    try {
      fixtures = buildAirFixtures(deep);
      lastError = null;
      break;
    } catch (error) {
      lastError = error;
    }
  }
  if (!fixtures || !poseidon2Air) {
    throw lastError ?? new TypeError('AIR q2 four-leaf profile was not reached');
  }
  const relation = provePoolActionRelation({
    statement,
    witness,
    queryCount,
    logBlowup,
    includeAir: false,
  });
  const proof = Object.freeze({
    ...relation,
    poseidon2Air,
    commitmentScheme: poseidon2Air.commitmentScheme,
    algebraicAir: Object.freeze({
      ...relation.algebraicAir,
      labeledFriOfAir: poseidon2Air.labeledFriOfAir === true,
      statedInHoldingLane: true,
      wall: poseidon2Air.wall,
      interpolantFri: false,
      airKind: poseidon2Air.kind,
      transitions: poseidon2Air.transitions,
    }),
  });
  const host = verifyPoolActionRelation({ proof, expectedStatement: statement, witness });
  const p2sh = encodeBchCircleFriQ2PartitionTransactionFixture(fixtures);
  const p2shUnlocking = p2sh.materialized.map((item) => item.unlockingBytecode.length);
  const overFloor = p2shUnlocking.some((bytes) => bytes > PARTITION_UNLOCKING_FLOOR);
  const wires = overFloor
    ? encodeBchCircleFriQ2PartitionP2sTransactionFixture(fixtures)
    : p2sh;
  const results = evaluateBchCircleFriQ2PartitionTransactionFixture(wires);
  const unlockingBytes = wires.materialized.map((item) => item.unlockingBytecode.length);
  const redeemBytes = wires.materialized[0].redeemBytecode.length;
  const accepted = results.every(({ accepted: ok }) => ok);
  const airOnChainWall = accepted
    ? null
    : [
        `AIR even-x q2 unlocking ${unlockingBytes.join('/')} redeem ${redeemBytes}`,
        `carrier ${wires.carrier ?? 'p2sh32'}; ${results.map((row) => row.error).filter(Boolean).join('; ')}`,
      ].join(' ');
  return Object.freeze({
    proof,
    host,
    wires,
    results,
    inputBytecodeOps: countOpInputBytecode(wires.materialized[0].redeemBytecode),
    unlockingBytes,
    redeemBytes,
    floor: PARTITION_UNLOCKING_FLOOR,
    friNonce: poseidon2Air.friNonce ?? 0,
    chainObject: 'air-absorb-in-q-even-x',
    carrier: wires.carrier ?? 'p2sh32',
    airWall: poseidon2Air.wall,
    airOnChainWall,
    airStatedInLane: false,
    airStatedInHoldingLane: true,
    commitmentScheme: poseidon2Air.commitmentScheme,
    compositionNonzero: poseidon2Air.compositionNonzero,
    envelope: Object.freeze({
      target: Object.freeze({ redeem: 5200, unlocking: 10_000, tx: 100_000 }),
      miss: Object.freeze({
        schedule: '36-query / N=1024 / blowup 16',
        txBytes: 174794,
        bindingConstraint: 'standard transaction size 100000; queries were not dropped',
      }),
      airObject: Object.freeze({
        schedule: 'Poseidon2-M31 16×1024 absorb+snapshot Q even-x / deg<8192 / blowup 2 / q=4',
        redeemBytes,
        unlockingBytes,
        carrier: wires.carrier ?? 'p2sh32',
        transactionBytes: wires.transactionBytes,
        bindingConstraint: airOnChainWall
          ?? (redeemBytes > 5200 || unlockingBytes.some((bytes) => bytes > 10_000)
            ? 'AIR envelope over 5200/10k; queries were not dropped'
            : null),
      }),
    }),
  });
};

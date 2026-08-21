/**
 * BCH-2026 partition of the Poseidon2-M31 snapshot-quotient even-x DEEP FRI.
 * Does not fall back to statement-bound 64-coeff interpolant FRI or to
 * state-composition even-x. Production object is q=90 cpi=3 blowup 8, merkle stride 16.
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
  encodeAirZetaLdeOpening,
  provePoseidon2Air,
} from './poseidon2-air.mjs';

import {
  hexToBytes,
} from '../../research-lanes/bch-shielded-pool-design/p1/codec/common.mjs';

const buildAirFixtures = (deep, airProof) => {
  const airLdeOpening = encodeAirZetaLdeOpening(airProof);
  const airLdeRoot = new Uint8Array(airProof.ldeMerkleRoot);
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
      airLdeOpening,
      airLdeRoot,
    }));
  }
  return fixtures;
};

export const evaluateRelationBoundPartition = ({
  statement,
  witness,
  queryCount = 90,
  logBlowup = 3,
  maxFriNonce = 32,
  clustersPerInput = 3,
}) => {
  const pool = hexToBytes(statement.poolInstanceIdHex, 'poolInstanceId');
  let poseidon2Air = null;
  let fixtures = null;
  let lastError = null;
  for (let friNonce = 0; friNonce <= maxFriNonce; friNonce += 1) {
    try {
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
      fixtures = buildAirFixtures(deep, poseidon2Air);
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
    queryCount: 2,
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
  const p2sh = clustersPerInput > 1
    ? null
    : encodeBchCircleFriQ2PartitionTransactionFixture(fixtures);
  const p2shUnlocking = p2sh?.materialized.map((item) => item.unlockingBytecode.length) ?? [PARTITION_UNLOCKING_FLOOR + 1];
  const overFloor = clustersPerInput > 1
    || p2shUnlocking.some((bytes) => bytes > PARTITION_UNLOCKING_FLOOR)
    || (p2sh?.transactionBytes ?? 100_001) > 100_000;
  const encodeP2sDensity = () => {
    const raw = encodeBchCircleFriQ2PartitionP2sTransactionFixture(fixtures, {
      unlockingFloor: 0,
      clustersPerInput,
    });
    const unpadded = raw.materialized.map((item) => item.unlockingBytecode.length);
    const unpaddedMax = Math.max(...unpadded);
    const inputs = unpadded.length;
    const extra = raw.transactionBytes - unpadded.reduce((sum, bytes) => sum + bytes, 0);
    const maxFit = Math.min(
      PARTITION_UNLOCKING_FLOOR,
      Math.floor((100_000 - extra) / inputs),
    );
    const tryFloor = (floor) => {
      const needed = typeof floor === 'number'
        ? floor
        : Math.max(floor.input0 ?? 0, floor.other ?? 0);
      if (typeof floor === 'number' && floor <= unpaddedMax) {
        return { wires: raw, densityFloor: unpaddedMax };
      }
      if (typeof floor !== 'number' && needed <= unpaddedMax) {
        return { wires: raw, densityFloor: unpaddedMax };
      }
      try {
        return {
          wires: encodeBchCircleFriQ2PartitionP2sTransactionFixture(fixtures, {
            unlockingFloor: floor,
            clustersPerInput,
          }),
          densityFloor: floor,
        };
      } catch {
        return null;
      }
    };
    const txFits = (floor) => {
      if (typeof floor === 'number') return floor <= maxFit;
      const input0 = floor.input0 ?? unpaddedMax;
      const other = floor.other ?? unpaddedMax;
      return input0 <= PARTITION_UNLOCKING_FLOOR
        && other <= PARTITION_UNLOCKING_FLOOR
        && input0 + Math.max(0, inputs - 1) * other + extra <= 100_000;
    };
    // 800 ops per unlocking byte. Prefer 8600 when it still fits 10k/100k so
    // two honest sizes share a density floor. Skip-layer q=44 (22 inputs)
    // cannot take 8600: pad only until 800*(u+41) covers measured op-cost.
    const preferred = Math.max(unpaddedMax, 8_600);
    if (preferred <= maxFit) {
      for (let floor = preferred; floor > unpaddedMax; floor -= 1) {
        const hit = tryFloor(floor);
        if (hit) return hit;
      }
    }
    // Density aborts report cost-at-limit (~4.39M), not full script cost
    // (~5.55M). Try the measured min floor (~6900) then tx-budget maxFit.
    const accepts = (item) => evaluateBchCircleFriQ2PartitionTransactionFixture(item.wires)
      .every(({ accepted: ok }) => ok);
    const hittable = (target) => {
      for (let floor = Math.min(target, maxFit); floor > unpaddedMax; floor -= 1) {
        const hit = tryFloor(floor);
        if (hit) return hit;
      }
      return null;
    };
    if (clustersPerInput > 1 && inputs > 1) {
      for (const input0 of [9_000, 8_600, 8_000, 9_200, 10_000]) {
        for (const other of [6_400, 6_300, 6_200, 6_500, 6_900, 7_600]) {
          const floor = { input0, other };
          if (!txFits(floor)) continue;
          const hit = tryFloor(floor);
          if (hit && accepts(hit)) return hit;
        }
      }
    }
    for (const guess of [5_400, 6_900, 7_600, maxFit]) {
      const hit = hittable(guess);
      if (hit && accepts(hit)) return hit;
    }
    return { wires: raw, densityFloor: unpaddedMax };
  };
  const p2s = overFloor ? encodeP2sDensity() : null;
  const wires = p2s?.wires ?? p2sh;
  const results = evaluateBchCircleFriQ2PartitionTransactionFixture(wires);
  const unlockingBytes = wires.materialized.map((item) => item.unlockingBytecode.length);
  const redeemBytes = wires.materialized[0].redeemBytecode.length;
  const accepted = results.every(({ accepted: ok }) => ok);
  const densityFloor = p2s?.densityFloor ?? PARTITION_UNLOCKING_FLOOR;
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
    floor: densityFloor,
    friNonce: poseidon2Air.friNonce ?? 0,
    chainObject: 'air-lde-only-even-x',
    carrier: wires.carrier ?? 'p2sh32',
    airWall: poseidon2Air.wall,
    airOnChainWall,
    airStatedInLane: false,
    airStatedInHoldingLane: poseidon2Air.labeledFriOfAir === true,
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
        schedule: `Poseidon2-M31 16×1024 absorb+snapshot Q even-x / deg<8192 / blowup ${2 ** logBlowup} / q=${queryCount}`,
        redeemBytes,
        unlockingBytes,
        carrier: wires.carrier ?? 'p2sh32',
        transactionBytes: wires.transactionBytes,
        bindingConstraint: airOnChainWall
          ?? (redeemBytes > 5200
            || unlockingBytes.some((bytes) => bytes > 10_000)
            || wires.transactionBytes > 100_000
            ? 'AIR envelope over 5200/10k/100k; queries were not dropped'
            : null),
      }),
    }),
  });
};

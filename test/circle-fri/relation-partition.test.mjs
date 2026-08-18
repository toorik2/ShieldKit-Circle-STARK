import test from 'node:test';
import assert from 'node:assert/strict';

import {
  measureInScriptAirDeepWall,
} from '../../src/circle-fri/in-script-air-deep-wall.mjs';

import {
  evaluateRelationBoundPartition,
} from '../../src/circle-fri/relation-partition.mjs';

import {
  buildHonestDeposit,
  buildHonestWithdrawal,
} from '../../src/circle-fri/pool-action-fixtures.mjs';

const runPartition = (label, bundle) => {
  const evaluated = evaluateRelationBoundPartition(bundle);
  assert.equal(evaluated.host.ok, true, evaluated.host.reason);
  assert.equal(evaluated.proof.deepFriCompatible, false);
  assert.equal(evaluated.proof.evenXDeep?.labeledFriOfDeep, true);
  assert.equal(evaluated.chainObject, 'air-masked-snapshot-quotient-even-x');
  assert.ok((evaluated.compositionNonzero ?? 0) > 0);
  assert.equal(evaluated.airStatedInHoldingLane, true);
  assert.equal(evaluated.airStatedInLane, false);
  assert.equal(evaluated.host.poseidon2Air.ok, true);
  assert.equal(evaluated.host.poseidon2Air.labeledFriOfAir, false);
  assert.match(evaluated.airWall ?? '', /18 unopened absorb rows/u);
  assert.notEqual(evaluated.chainObject, 'even-x-deep-fri');
  assert.equal(evaluated.commitmentScheme, 'poseidon2-m31-rate8-v1');
  assert.equal(evaluated.envelope.miss.txBytes, 174794);
  assert.match(evaluated.envelope.miss.bindingConstraint, /queries were not dropped/u);
  assert.equal(evaluated.proof.evenXDeep.zhR?.kind, 'zh-r-even-x-deep-v1');
  assert.equal(evaluated.proof.evenXDeep.zhR?.onChain, false);
  assert.equal(evaluated.inputBytecodeOps, 1);
  const owner = bundle.witness.owner;
  const rho = bundle.witness.rho;
  for (const item of evaluated.wires.materialized) {
    const hex = Buffer.from(item.unlockingBytecode).toString('hex');
    assert.equal(hex.includes(Buffer.from(owner).toString('hex')), false);
    assert.equal(hex.includes(Buffer.from(rho).toString('hex')), false);
  }
  for (const item of evaluated.wires.materialized) {
    if (item.padLength > 0) {
      assert.equal(item.unlockingBytecode.length, evaluated.floor);
    }
  }
  const accepted = evaluated.results.every(({ accepted: ok }) => ok);
  if (accepted) {
    assert.equal(evaluated.airOnChainWall, null);
  } else {
    assert.ok(evaluated.airOnChainWall);
    assert.match(evaluated.airOnChainWall, /unlocking|10000|10k|Maximum bytecode/i);
    assert.ok(evaluated.unlockingBytes.every((bytes) => bytes > 10_000));
  }
  console.log(`PARTITION_RELATION_${label}`, {
    proven: [
      `host Poseidon2 AIR + AIR even-x partition of ${label}`,
      `BCH-2026 partition ${evaluated.results.every(({ accepted }) => accepted) ? 'accepts' : 'rejects'} AIR snapshot-quotient even-x FRI (${evaluated.carrier})`,
      'exactly one OP_INPUTBYTECODE opcode',
      `density pad ${evaluated.floor} on ${evaluated.unlockingBytes.length} inputs`,
    ],
    failed: [
      evaluated.airWall,
      evaluated.airOnChainWall,
      '36-query / 100k already 174794 B',
    ],
    speculative: [],
    envelope: evaluated.envelope,
    redeemBytes: evaluated.redeemBytes,
    unlockingBytes: evaluated.unlockingBytes,
    operationCost: evaluated.results.map(({ metrics }) => metrics.operationCost),
    hashDigestIterations: evaluated.results.map(({ metrics }) => metrics.hashDigestIterations),
    accepted: evaluated.results.map(({ accepted }) => accepted),
    inputBytecodeOps: evaluated.inputBytecodeOps,
  });
  return evaluated;
};

test('partition accepts honest deposit and withdrawal on the same relation-bound path', () => {
  const deposit = runPartition('deposit', buildHonestDeposit());
  const withdrawal = runPartition('withdrawal', buildHonestWithdrawal());
  assert.equal(deposit.inputBytecodeOps, withdrawal.inputBytecodeOps);
  const wall = measureInScriptAirDeepWall({ friRedeemBytes: deposit.redeemBytes });
  assert.match(wall.wall, /even-x DEEP FRI/u);
  assert.match(wall.wall, /owner\|\|rho/u);
  console.log('IN_SCRIPT_AIR_DEEP_WALL', {
    proven: [
      `AIR HASH256 predicates compile to ${wall.airPredicateBytes} bytes`,
    ],
    failed: [wall.wall],
    speculative: [],
    airPredicateBytes: wall.airPredicateBytes,
    deepLowerBoundBytes: wall.deepLowerBoundBytes,
    friRedeemBytes: wall.friRedeemBytes,
    combinedRedeemBytes: wall.combinedRedeemBytes,
  });
});

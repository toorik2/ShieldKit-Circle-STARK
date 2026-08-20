import test from 'node:test';
import assert from 'node:assert/strict';

import {
  M31_MODULUS,
} from '../../research-lanes/bch-shielded-pool-design/p2/reference/m31.mjs';

import {
  utf8,
} from '../../src/circle-fri/bytes.mjs';

import {
  proveCircleFriQueries,
} from '../../src/circle-fri/query-proof.mjs';

import {
  createCircleFriQ2BatchWitness,
} from '../../src/circle-fri/query-batch-witness.mjs';

import {
  PARTITION_UNLOCKING_FLOOR,
  countOpInputBytecode,
  createBchCircleFriQ2BatchFixture,
  encodeBchCircleFriQ2PartitionTransactionFixture,
  evaluateBchCircleFriQ2PartitionTransactionFixture,
  materializeBchCircleFriQ2PartitionP2sh32,
} from '../../src/circle-fri/bch-query-batch-kernel.mjs';

const PARAMETERS = Object.freeze({ logDegreeBound: 6, logBlowup: 3, queryCount: 4 });
const CONTEXT = utf8('ShieldKit Circle-FRI executable query KAT v3');

const deterministicCoefficients = () => {
  let state = 0x465249n;
  return Array.from({ length: 1 << PARAMETERS.logDegreeBound }, () => {
    state = (state * 2_862_933_555_777_941_757n + 3_037_000_493n) & ((1n << 64n) - 1n);
    return (state >> 11n) % M31_MODULUS;
  });
};

const proof = proveCircleFriQueries({
  coefficients: deterministicCoefficients(),
  logBlowup: PARAMETERS.logBlowup,
  queryCount: PARAMETERS.queryCount,
  protocolContext: CONTEXT,
});

const fixtures = [[0, 1], [2, 3]].map((queryOrdinals) => createBchCircleFriQ2BatchFixture({
  witness: createCircleFriQ2BatchWitness({
    proof,
    expected: PARAMETERS,
    protocolContext: CONTEXT,
    queryOrdinals,
  }),
  expected: PARAMETERS,
  protocolContext: CONTEXT,
}));

test('partition binds one digest without all-sibling INPUTBYTECODE and pads unlocking to the density floor', () => {
  const left = materializeBchCircleFriQ2PartitionP2sh32(fixtures[0]);
  const right = materializeBchCircleFriQ2PartitionP2sh32(fixtures[1]);
  assert.equal(left.unlockingBytecode.length, PARTITION_UNLOCKING_FLOOR);
  assert.equal(right.unlockingBytecode.length, PARTITION_UNLOCKING_FLOOR);
  assert.equal(countOpInputBytecode(left.redeemBytecode), 1);
  assert.equal(countOpInputBytecode(right.redeemBytecode), 1);
  const stuffed = new Uint8Array([0x4c, 2, 0xca, 0xca, 0xca]);
  assert.equal(countOpInputBytecode(stuffed), 1);
  const wires = encodeBchCircleFriQ2PartitionTransactionFixture(fixtures);
  const results = evaluateBchCircleFriQ2PartitionTransactionFixture(wires);
  assert.equal(results[0].accepted, true, results[0].error);
  assert.equal(results[1].accepted, true, results[1].error);
  assert.ok(results[0].metrics.operationCost < 8_000_000);
  assert.ok(results[1].metrics.operationCost < 8_000_000);
  console.log('PARTITION', {
    proven: [
      'one OP_INPUTBYTECODE (input 0 only)',
      'unlocking padded to 10000 for both witness sizes',
      'both inputs accept inside density',
    ],
    failed: [],
    speculative: [],
    redeemBytes: left.redeemBytecode.length,
    unlockingBytes: [left.unlockingBytecode.length, right.unlockingBytecode.length],
    witnessBytes: [fixtures[0].encodedWitness.length, fixtures[1].encodedWitness.length],
    padLength: [left.padLength, right.padLength],
    operationCost: results.map(({ metrics }) => metrics.operationCost),
    hashDigestIterations: results.map(({ metrics }) => metrics.hashDigestIterations),
    accepted: results.map(({ accepted }) => accepted),
    inputBytecodeOps: countOpInputBytecode(left.redeemBytecode),
  });
});

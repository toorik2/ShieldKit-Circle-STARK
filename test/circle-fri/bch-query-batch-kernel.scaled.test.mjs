import { createHash } from 'node:crypto';
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
  circleFriTopologyRecordBytes,
} from '../../src/circle-fri/topology-table.mjs';

import {
  createBchCircleFriQ2BatchFixture,
  encodeBchCircleFriQ2BatchTransactionFixture,
  evaluateBchCircleFriQ2BatchTransactionFixture,
  measureBchCircleFriQ2UnrolledQueryDerivationBytes,
} from '../../src/circle-fri/bch-query-batch-kernel.mjs';

const PARAMETERS = Object.freeze({ logDegreeBound: 6, logBlowup: 4, queryCount: 36 });
const CONTEXT = utf8('ShieldKit Circle-FRI scaled q2 TRACE64-B16-N1024-Q36');
const REDEEM_ENVELOPE = 5_200;
const UNLOCK_ENVELOPE = 10_000;
const TX_ENVELOPE = 100_000;

const sha256hex = (bytes) => createHash('sha256').update(bytes).digest('hex');

const deterministicCoefficients = (seed = 0x465249n) => {
  let state = seed;
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

const honest = Array.from({ length: PARAMETERS.queryCount / 2 }, (_, batch) => (
  createBchCircleFriQ2BatchFixture({
    witness: createCircleFriQ2BatchWitness({
      proof,
      expected: PARAMETERS,
      protocolContext: CONTEXT,
      queryOrdinals: [batch * 2, batch * 2 + 1],
    }),
    expected: PARAMETERS,
    protocolContext: CONTEXT,
  })
));

const wires = encodeBchCircleFriQ2BatchTransactionFixture(honest);

const readU16 = (bytes, offset) => bytes[offset] + bytes[offset + 1] * 0x100;

const codecOffsets = (bytes) => {
  const roots = 22;
  const finalCodeword = roots + PARAMETERS.logDegreeBound * 32;
  const topologyRoot = finalCodeword + (2 ** PARAMETERS.logBlowup) * 4;
  const record0 = topologyRoot + 32;
  const recordBytes = circleFriTopologyRecordBytes(PARAMETERS);
  const record1 = record0 + recordBytes;
  const topologySiblingCount = record1 + recordBytes;
  let cursor = topologySiblingCount + 2 + readU16(bytes, topologySiblingCount) * 32;
  const layers = [];
  for (let round = 0; round < PARAMETERS.logDegreeBound; round += 1) {
    const siblingCount = readU16(bytes, cursor + 2);
    layers.push(Object.freeze({
      header: cursor,
      inverse0: cursor + 4,
      inverse1: cursor + 8,
      values: cursor + 12,
      siblings: cursor + 28,
      siblingCount,
    }));
    cursor += 28 + siblingCount * 32;
  }
  return Object.freeze({
    queryOrdinals: 10,
    queryIndices: 14,
    roots,
    finalCodeword,
    topologyRoot,
    record0,
    record1,
    recordBytes,
    topologySiblingCount,
    topologySiblings: topologySiblingCount + 2,
    layers,
    end: cursor,
  });
};

const mutateFixture = (fixture, mutation) => {
  const candidate = structuredClone(fixture);
  candidate.encodedWitness = candidate.encodedWitness.slice();
  mutation(candidate.encodedWitness, codecOffsets(candidate.encodedWitness));
  return candidate;
};

const evaluateInput0 = (encoded) => evaluateBchCircleFriQ2BatchTransactionFixture({
  ...encoded,
  materialized: encoded.materialized.slice(0, 1),
})[0];

const p2sTxEstimate = wires.transactionBytes - wires.materialized.reduce(
  (sum, item) => sum + item.redeemBytecode.length + 3,
  0,
);

test('scaled schedule is TRACE 64 / blowup 16 / N=1024 / 36 queries on the shipped q2 path', () => {
  assert.equal(PARAMETERS.logDegreeBound, 6);
  assert.equal(PARAMETERS.logBlowup, 4);
  assert.equal(PARAMETERS.queryCount, 36);
  assert.equal(1 << (PARAMETERS.logDegreeBound + PARAMETERS.logBlowup), 1024);
  assert.equal(proof.logDegreeBound, 6);
  assert.equal(proof.logBlowup, 4);
  assert.equal(proof.queryCount, 36);
  assert.equal(honest.length, 18);
  assert.equal(honest[0].parameters.logDegreeBound, 6);
  assert.equal(honest[0].parameters.logBlowup, 4);
  assert.equal(honest[0].parameters.queryCount, 36);
  assert.equal(honest[0].parameters.domainLength, 1024);
  assert.equal(honest[0].queryBatchSize, 2);
  assert.equal(honest[0].transactionBatchCount, 18);
  assert.deepEqual(honest.map(({ batchOrdinal }) => batchOrdinal), [...Array(18).keys()]);
  const unrolled = measureBchCircleFriQ2UnrolledQueryDerivationBytes(PARAMETERS);
  assert.equal(unrolled, 23_950);
  assert.ok(unrolled > 10_000, 'unrolled 36-query derivation must be the 10k script wall');
  console.log('SCALED_SCHEDULE', {
    logDegreeBound: 6,
    logBlowup: 4,
    domainLength: 1024,
    queryCount: 36,
    batches: 18,
    unrolledQueryDerivationBytes: unrolled,
  });
});

test('honest scaled q2 fixture metrics, hashes, envelopes, and Libauth 2026 verdict', { timeout: 120_000 }, () => {
  assert.equal(wires.materialized[0].redeemBytecode.length, 4_457);
  assert.deepEqual(wires.materialized.map(({ unlockingBytecode }) => unlockingBytecode.length), [
    9608, 9640, 9768, 9672, 9512, 9384, 9576, 9800, 9960, 8072,
    9864, 9992, 9896, 9640, 9768, 9928, 9928, 9992,
  ]);
  assert.equal(wires.transactionBytes, 174_794);
  assert.equal(wires.sourceOutputsBytes, 793);
  assert.equal(
    sha256hex(wires.materialized[0].redeemBytecode),
    '1b16648ab863de2e72de0c9f9049b046ca0b18cd022fb4a94a60fa38fb022da2',
  );
  assert.equal(
    sha256hex(wires.materialized[0].encodedWitness),
    '3214094cd451b8b514c18e432d987770f8e66dac9370eb4bc7e352b383d57385',
  );
  assert.equal(wires.transactionDigestSha256, '44d6e8fbd227fad52f020ecd4c198ea0f20226121a854311d657a49630f9c7a4');

  const redeemFits = wires.materialized.every(({ redeemBytecode }) => redeemBytecode.length <= REDEEM_ENVELOPE);
  const unlockFits = wires.materialized.every(({ unlockingBytecode }) => unlockingBytecode.length <= UNLOCK_ENVELOPE);
  const txFits = wires.transactionBytes <= TX_ENVELOPE;
  assert.equal(redeemFits, true);
  assert.equal(unlockFits, true);
  assert.equal(txFits, false);

  const results = evaluateBchCircleFriQ2BatchTransactionFixture(wires);
  assert.deepEqual(results.map(({ accepted }) => accepted), [
    true, true, true, true, true, true, true, true, true, false,
    true, true, true, true, true, true, true, true,
  ]);
  assert.equal(results[9].accepted, false);
  assert.match(results[9].error ?? '', /operation cost density limit/);
  assert.deepEqual(results.map(({ metrics }) => metrics.operationCost), [
    7407448, 7414893, 7496772, 7421229, 7338756, 7257879, 7399561, 7503886, 7611258, 6490401,
    7545500, 7626345, 7570973, 7420669, 7509017, 7586392, 7584075, 7623036,
  ]);
  assert.deepEqual(results.map(({ metrics }) => metrics.hashDigestIterations), [
    821, 824, 836, 827, 812, 800, 818, 839, 854, 677,
    845, 857, 848, 824, 836, 851, 851, 857,
  ]);

  console.log('SCALED_HONEST_METRICS', {
    redeemBytes: 4457,
    unlockingBytes: wires.materialized.map(({ unlockingBytecode }) => unlockingBytecode.length),
    transactionBytes: 174794,
    sourceOutputsBytes: 793,
    operationCost: results.map(({ metrics }) => metrics.operationCost),
    hashDigestIterations: results.map(({ metrics }) => metrics.hashDigestIterations),
    standard: results.map(({ standard }) => standard),
    accepted: results.map(({ accepted }) => accepted),
    envelopes: { redeem5200: redeemFits, unlock10000: unlockFits, tx100000: txFits },
    hashes: {
      redeem: sha256hex(wires.materialized[0].redeemBytecode),
      witness0: sha256hex(wires.materialized[0].encodedWitness),
      transaction: wires.transactionDigestSha256,
    },
    p2sTxEstimate,
  });
});

test('scaled cheap falsifiers reject', { timeout: 120_000 }, () => {
  const swapped = structuredClone(wires);
  [swapped.transaction.inputs[0].unlockingBytecode, swapped.transaction.inputs[1].unlockingBytecode] = [
    swapped.transaction.inputs[1].unlockingBytecode,
    swapped.transaction.inputs[0].unlockingBytecode,
  ];
  const swapResults = evaluateBchCircleFriQ2BatchTransactionFixture({
    ...swapped,
    materialized: swapped.materialized.slice(0, 2),
  });
  assert.equal(swapResults.every(({ accepted }) => !accepted), true);

  const mixed = structuredClone(wires);
  mixed.transaction.inputs[1].unlockingBytecode[1] ^= 1;
  assert.equal(evaluateInput0(mixed).accepted, false);

  const mutations = [
    (bytes, offsets) => { bytes[offsets.roots] ^= 1; },
    (bytes, offsets) => { bytes[offsets.topologyRoot] ^= 1; },
    (bytes, offsets) => { bytes[offsets.record0 + 10] ^= 1; },
    (bytes, offsets) => { bytes[offsets.topologySiblings] ^= 1; },
    (bytes, offsets) => { bytes[offsets.layers[0].values] ^= 1; },
    (bytes, offsets) => { bytes[offsets.layers[2].siblings] ^= 1; },
    (bytes, offsets) => { bytes[offsets.layers[1].inverse0] ^= 1; },
    (bytes, offsets) => { bytes[offsets.finalCodeword] ^= 1; },
  ];
  for (const [ordinal, mutation] of mutations.entries()) {
    const mutated = honest.slice();
    mutated[0] = mutateFixture(honest[0], mutation);
    const result = evaluateInput0(encodeBchCircleFriQ2BatchTransactionFixture(mutated));
    assert.equal(result.accepted, false, `runtime mutation ${ordinal} was accepted`);
  }

  const short = {
    ...structuredClone(wires),
    materialized: wires.materialized.slice(0, 1),
    transaction: {
      ...structuredClone(wires.transaction),
      inputs: structuredClone(wires.transaction.inputs.slice(0, 17)),
    },
    sourceOutputs: structuredClone(wires.sourceOutputs.slice(0, 17)),
  };
  assert.equal(evaluateBchCircleFriQ2BatchTransactionFixture(short)[0].accepted, false);

  const extra = {
    ...structuredClone(wires),
    transaction: {
      ...structuredClone(wires.transaction),
      inputs: [...structuredClone(wires.transaction.inputs), structuredClone(wires.transaction.inputs[0])],
    },
    sourceOutputs: [...structuredClone(wires.sourceOutputs), structuredClone(wires.sourceOutputs[0])],
  };
  assert.equal(evaluateInput0(extra).accepted, false);

  console.log('SCALED_FALSIFIERS', { rejected: true });
});

test('terminal verdict: scaled q2 does not fit; first wall is the 100k tx envelope', () => {
  const verdict = Object.freeze({
    status: 'FAILED_ENVELOPE',
    schedule: 'TRACE 64 / blowup 16 / N=1024 / 36 queries / 18 q2 inputs',
    proven: Object.freeze({
      unrolledQueryDerivationBytes: 23_950,
      redeemBytes: 4_457,
      transactionBytes: 174_794,
      input9DensityReject: true,
      seventeenInputsAccept: true,
      falsifiersReject: true,
    }),
    failed: Object.freeze({
      firstBindingConstraint: 'transactionBytes 174794 > 100000',
      additional: 'input 9 (unlocking 8072, smallest witness) exceeds 2026 op-cost density by 1',
    }),
    speculative: Object.freeze({
      nextAttemptConsidered: 'P2S so each unlocking omits the 4457-byte redeem',
      p2sTxEstimate,
      whyNotTaken: 'P2S shrinks unlocking and therefore the density budget; input 9 already fails density on P2SH32',
      stop: true,
    }),
  });
  assert.equal(verdict.status, 'FAILED_ENVELOPE');
  assert.ok(verdict.proven.transactionBytes > TX_ENVELOPE);
  assert.ok(p2sTxEstimate < TX_ENVELOPE);
  console.log('SCALED_TERMINAL_VERDICT', verdict);
});

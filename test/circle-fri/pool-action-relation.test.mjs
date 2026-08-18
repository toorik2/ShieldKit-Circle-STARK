import test from 'node:test';
import assert from 'node:assert/strict';

import {
  HOST_ORACLE_SPLIT,
  OFF_CHAIN_FOREVER,
  provePoolActionRelation,
  verifyPoolActionRelation,
} from '../../src/circle-fri/pool-action-relation.mjs';

import {
  ABSORB_UNOPENED_BIND_WALL,
  MASKED_ABSORB_BIND,
  SNAPSHOT_QUOTIENT_KIND,
  forgeUnboundQuotientFri,
  measureGarbageMiddleQuotientWall,
  observePoseidon2Air,
  proveDummyZeroTableAir,
  proveGarbageAbsorbAir,
  verifyPoseidon2Air,
} from '../../src/circle-fri/poseidon2-air.mjs';

import {
  buildHonestDeposit,
  buildHonestWithdrawal,
} from '../../src/circle-fri/pool-action-fixtures.mjs';

import {
  hexToBytes,
} from '../../research-lanes/bch-shielded-pool-design/p1/codec/common.mjs';

test('honest deposit and withdrawal relation proofs accept', () => {
  const deposit = buildHonestDeposit();
  const depositProof = provePoolActionRelation(deposit);
  const depositOk = verifyPoolActionRelation({
    proof: depositProof,
    expectedStatement: deposit.statement,
    witness: deposit.witness,
  });
  assert.equal(depositOk.ok, true, depositOk.reason);
  assert.ok(depositOk.predicates || depositProof.relation.predicates.includes('note-well-formed'));
  assert.deepEqual(OFF_CHAIN_FOREVER, depositProof.relation.offChainForever);
  assert.equal(HOST_ORACLE_SPLIT.status, 'not-a-production-lock');
  assert.ok(HOST_ORACLE_SPLIT.hostOracleForever.includes(OFF_CHAIN_FOREVER[0]));
  assert.equal(HOST_ORACLE_SPLIT.hostOracleForever.some((item) => item.includes('note well-formedness')), false);
  assert.ok(depositProof.poseidon2Air.predicateBinds >= 4);
  assert.equal(depositProof.algebraicAir.statedInLane, false);
  assert.equal(depositProof.algebraicAir.statedInHoldingLane, true);
  assert.equal(depositProof.algebraicAir.labeledFriOfAir, false);
  assert.equal(depositProof.algebraicAir.productionLock, false);
  assert.equal(depositProof.algebraicAir.wall, ABSORB_UNOPENED_BIND_WALL);
  assert.equal(depositProof.algebraicAir.interpolantFri, false);
  assert.ok(depositProof.poseidon2Air.transitions > 0);
  assert.equal(depositOk.statedInHoldingLane, true);
  assert.equal(depositOk.poseidon2Air.ok, true);
  assert.equal(depositOk.poseidon2Air.labeledFriOfAir, false);
  assert.equal(depositProof.poseidon2Air.labeledFriOfAir, false);
  assert.equal(depositProof.poseidon2Air.wall, ABSORB_UNOPENED_BIND_WALL);
  assert.match(depositProof.poseidon2Air.wall, /18 unopened absorb rows/u);
  assert.equal(depositProof.poseidon2Air.bind, MASKED_ABSORB_BIND);
  assert.equal(depositProof.poseidon2Air.columnCoefficients.length, 16);
  assert.equal(depositProof.poseidon2Air.hostColumnCoefficients, undefined);
  assert.equal(depositProof.poseidon2Air.residualObject, SNAPSHOT_QUOTIENT_KIND);
  const publicLimbs = observePoseidon2Air(depositProof.poseidon2Air, {
    owner: deposit.witness.owner,
    rho: deposit.witness.rho,
  });
  assert.equal(publicLimbs.leaked, false);
  assert.ok((depositProof.poseidon2Air.quotientNonzero ?? 0) > 0);
  assert.equal(depositProof.poseidon2Air.evenXDeep.parameters.logDegreeBound, 13);
  assert.equal(depositProof.poseidon2Air.evenXDeep.zhR.onChain, false);
  const withoutSecrets = verifyPoseidon2Air({
    proof: depositProof.poseidon2Air,
    expectedStatement: deposit.statement,
  });
  assert.equal(withoutSecrets.ok, true, withoutSecrets.reason);
  assert.equal(withoutSecrets.labeledFriOfAir, false);
  assert.equal(withoutSecrets.wall, ABSORB_UNOPENED_BIND_WALL);
  assert.equal(withoutSecrets.bind, MASKED_ABSORB_BIND);
  const wrongStatement = verifyPoseidon2Air({
    proof: depositProof.poseidon2Air,
    expectedStatement: buildHonestWithdrawal().statement,
  });
  assert.equal(wrongStatement.ok, false);
  assert.match(wrongStatement.reason ?? '', /public felts|statement/i);
  assert.equal(HOST_ORACLE_SPLIT.status, 'not-a-production-lock');
  const ownerHex = Buffer.from(deposit.witness.owner).toString('hex');
  const rhoHex = Buffer.from(deposit.witness.rho).toString('hex');
  const publicJson = JSON.stringify(depositProof, (_, value) => {
    if (typeof value === 'bigint') return value.toString();
    if (value instanceof Uint8Array) return Buffer.from(value).toString('hex');
    return value;
  });
  assert.equal(publicJson.includes(ownerHex), false);
  assert.equal(publicJson.includes(rhoHex), false);

  const withdrawal = buildHonestWithdrawal();
  const withdrawalProof = provePoolActionRelation(withdrawal);
  const withdrawalOk = verifyPoolActionRelation({
    proof: withdrawalProof,
    expectedStatement: withdrawal.statement,
    witness: withdrawal.witness,
  });
  assert.equal(withdrawalOk.ok, true, withdrawalOk.reason);
  console.log('AIR_RELATION_HONEST', {
    proven: [
      'deposit accept',
      'withdrawal accept',
      'off-chain-forever listed',
      'Poseidon2-M31 four-predicate AIR absorb/squeeze + snapshot constraints vanish',
      'public residual-at-openings uses publicFelts.note',
      'AIR verify without owner||rho re-execution',
      'masked interpolant + snapshot Merkle + published-Q FRI verify',
    ],
    failed: [ABSORB_UNOPENED_BIND_WALL],
    speculative: [],
    offChainForever: OFF_CHAIN_FOREVER,
    algebraicAir: {
      statedInLane: depositProof.algebraicAir.statedInLane,
      statedInHoldingLane: true,
      labeledFriOfAir: false,
      transitions: depositProof.poseidon2Air.transitions,
      commitmentScheme: depositProof.commitmentScheme,
      snapshotRows: depositProof.poseidon2Air.snapshotRows,
      productionLock: false,
    },
  });
});

test('fake note, fake nullifier, and garbage coefficients reject', () => {
  const deposit = buildHonestDeposit();
  const fakeNoteStatement = {
    ...deposit.statement,
    noteCommitmentOrZeroHex: 'ab'.repeat(32),
  };
  const fakeNoteVerdict = verifyPoolActionRelation({
    proof: provePoolActionRelation(deposit),
    expectedStatement: fakeNoteStatement,
    witness: deposit.witness,
  });
  assert.equal(fakeNoteVerdict.ok, false);
  assert.match(fakeNoteVerdict.reason ?? '', /public felts|statement|slot/i);

  const withdrawal = buildHonestWithdrawal();
  const fakeNfStatement = {
    ...withdrawal.statement,
    nullifierOrZeroHex: 'cd'.repeat(32),
  };
  const fakeNf = verifyPoolActionRelation({
    proof: provePoolActionRelation(withdrawal),
    expectedStatement: fakeNfStatement,
    witness: withdrawal.witness,
  });
  assert.equal(fakeNf.ok, false);
  assert.match(fakeNf.reason ?? '', /public felts|statement|slot|nullifier/i);

  const honestProof = provePoolActionRelation(deposit);
  const garbage = structuredClone(honestProof);
  garbage.coefficients = honestProof.coefficients.map((value, index) => (
    index === 0 ? (value + 1n) % 2147483647n : value
  ));
  const garbageVerdict = verifyPoolActionRelation({
    proof: garbage,
    expectedStatement: deposit.statement,
    witness: deposit.witness,
  });
  assert.equal(garbageVerdict.ok, false);
  const zeroedNote = structuredClone(honestProof.poseidon2Air);
  zeroedNote.publicFelts = {
    ...zeroedNote.publicFelts,
    note: Array.from({ length: 8 }, () => 0n),
  };
  const zeroedNoteVerdict = verifyPoseidon2Air({
    proof: zeroedNote,
    expectedStatement: deposit.statement,
  });
  assert.equal(zeroedNoteVerdict.ok, false);
  assert.match(zeroedNoteVerdict.reason ?? '', /residual-at-openings|note|publicFelts/i);
  const dummyZero = proveDummyZeroTableAir({ statement: deposit.statement });
  const dummyZeroVerdict = verifyPoseidon2Air({
    proof: dummyZero,
    expectedStatement: deposit.statement,
  });
  assert.equal(dummyZeroVerdict.ok, false);
  const dummyRow0 = proveDummyZeroTableAir({
    statement: deposit.statement,
    honestPublicRow: true,
  });
  const dummyRow0Verdict = verifyPoseidon2Air({
    proof: dummyRow0,
    expectedStatement: deposit.statement,
  });
  assert.equal(dummyRow0Verdict.ok, false);
  assert.match(dummyRow0Verdict.reason ?? '', /residual-at-openings|snapshot|note|required|quotient/i);
  const garbageMiddle = measureGarbageMiddleQuotientWall({
    statement: deposit.statement,
    poolInstanceId: hexToBytes(deposit.statement.poolInstanceIdHex, 'pool'),
    owner: deposit.witness.owner,
    rho: deposit.witness.rho,
  });
  assert.equal(garbageMiddle.ok, false, garbageMiddle.wall);
  assert.equal(garbageMiddle.labeledFriOfAir, false);
  assert.match(garbageMiddle.wall ?? '', /degree < 8192|coefficient/i);
  const forgedQ = forgeUnboundQuotientFri(honestProof.poseidon2Air);
  const forgedQVerdict = verifyPoseidon2Air({
    proof: forgedQ,
    expectedStatement: deposit.statement,
  });
  assert.equal(forgedQVerdict.ok, false, 'forged random Q even-x must not verify');
  assert.match(forgedQVerdict.reason ?? '', /published Q|DEEP|coefficient|quotient/i);
  assert.equal(forgedQVerdict.labeledFriOfAir ?? false, false);
  const tamperedCols = structuredClone(honestProof.poseidon2Air);
  tamperedCols.columnCoefficients[0][8] = (tamperedCols.columnCoefficients[0][8] + 1n) % 2147483647n;
  const tamperedColsVerdict = verifyPoseidon2Air({
    proof: tamperedCols,
    expectedStatement: deposit.statement,
  });
  assert.equal(tamperedColsVerdict.ok, false);
  assert.match(tamperedColsVerdict.reason ?? '', /columnDigest|quotient|committed snapshot|absorb/i);
  const garbageAbsorb = proveGarbageAbsorbAir({
    statement: deposit.statement,
    poolInstanceId: hexToBytes(deposit.statement.poolInstanceIdHex, 'pool'),
    owner: deposit.witness.owner,
    rho: deposit.witness.rho,
  });
  assert.equal(garbageAbsorb.garbageAbsorb.hostResidualsVanish, false);
  assert.equal(garbageAbsorb.garbageAbsorb.rows, 18);
  const garbageAbsorbVerdict = verifyPoseidon2Air({
    proof: garbageAbsorb,
    expectedStatement: deposit.statement,
  });
  assert.equal(garbageAbsorbVerdict.ok, true, garbageAbsorbVerdict.reason);
  assert.equal(garbageAbsorbVerdict.labeledFriOfAir, false);
  assert.equal(garbageAbsorbVerdict.wall, ABSORB_UNOPENED_BIND_WALL);
  console.log('AIR_RELATION_FALSIFIERS', {
    proven: [
      'fake note reject',
      'fake nullifier reject',
      'garbage coefficients reject',
      'dummy last-snapshot reject',
      'forgedRandomQ reject (even-x is not DEEP of published Q)',
      'tampered masked interpolant reject',
    ],
    failed: [
      'garbage absorb (18 rows, all-1s) still verifies — Q is of the masked interpolant',
      ABSORB_UNOPENED_BIND_WALL,
    ],
    speculative: [],
    fakeNote: fakeNoteVerdict.reason,
    fakeNullifier: fakeNf.reason,
    garbage: garbageVerdict.reason,
  });
});

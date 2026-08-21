import test from 'node:test';
import assert from 'node:assert/strict';

import {
  HOST_ORACLE_SPLIT,
  OFF_CHAIN_FOREVER,
  provePoolActionRelation,
  verifyPoolActionRelation,
} from '../../src/circle-fri/pool-action-relation.mjs';

import {
  LDE_ONLY_BIND,
  ABSORB_SNAPSHOT_QUOTIENT_KIND,
  forgeUnboundQuotientFri,
  measureGarbageMiddleQuotientWall,
  observePoseidon2Air,
  observeSnapshot0Inversion,
  proveDummyZeroTableAir,
  proveGarbageAbsorbAir,
  proveHonestLdeGarbageTraceAbsorb,
  provePoseidon2Air,
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
  assert.equal(depositProof.algebraicAir.labeledFriOfAir, true);
  assert.equal(depositProof.algebraicAir.productionLock, false);
  assert.equal(depositProof.algebraicAir.wall, null);
  assert.equal(depositProof.algebraicAir.interpolantFri, false);
  assert.ok(depositProof.poseidon2Air.transitions > 0);
  assert.equal(depositOk.statedInHoldingLane, true);
  assert.equal(depositOk.poseidon2Air.ok, true);
  assert.equal(depositOk.poseidon2Air.labeledFriOfAir, true);
  assert.equal(depositProof.poseidon2Air.labeledFriOfAir, true);
  assert.equal(depositProof.poseidon2Air.wall, null);
  assert.equal(depositProof.poseidon2Air.bind, LDE_ONLY_BIND);
  assert.equal(depositProof.poseidon2Air.rowMerkleRoot, undefined);
  assert.equal(depositProof.poseidon2Air.columnCoefficients, undefined);
  assert.equal(depositProof.poseidon2Air.hostColumnCoefficients, undefined);
  assert.equal(depositProof.poseidon2Air.residualObject, ABSORB_SNAPSHOT_QUOTIENT_KIND);
  assert.ok(depositProof.poseidon2Air.ldeOpenings);
  const publicLimbs = observePoseidon2Air(depositProof.poseidon2Air, {
    owner: deposit.witness.owner,
    rho: deposit.witness.rho,
  });
  assert.equal(publicLimbs.leaked, false);
  const snapshot0Public = observeSnapshot0Inversion(depositProof.poseidon2Air, {
    owner: deposit.witness.owner,
    rho: deposit.witness.rho,
  });
  assert.equal(snapshot0Public.leaked, false);
  const hostCols = provePoseidon2Air({
    statement: deposit.statement,
    poolInstanceId: hexToBytes(deposit.statement.poolInstanceIdHex, 'pool'),
    owner: deposit.witness.owner,
    rho: deposit.witness.rho,
    includeHostColumns: true,
  });
  const snapshot0Host = observeSnapshot0Inversion(hostCols, {
    owner: deposit.witness.owner,
    rho: deposit.witness.rho,
  });
  assert.equal(snapshot0Host.leaked, true);
  assert.equal(snapshot0Host.method, 'snapshot0-external-inverse');
  assert.ok((depositProof.poseidon2Air.quotientNonzero ?? 0) > 0);
  assert.equal(depositProof.poseidon2Air.evenXDeep.parameters.logDegreeBound, 14);
  assert.equal(depositProof.poseidon2Air.evenXDeep.parameters.logBlowup, 3);
  assert.equal(depositProof.poseidon2Air.evenXDeep.parameters.queryCount, 90);
  assert.equal(depositProof.poseidon2Air.evenXDeep.zhR.onChain, true);
  assert.match(depositProof.poseidon2Air.evenXDeep.zhR.reason, /redeem 5015/u);
  assert.match(depositProof.poseidon2Air.evenXDeep.zhR.reason, /unlocking 9000\/6400/u);
  assert.match(depositProof.poseidon2Air.evenXDeep.zhR.reason, /tx 99265/u);
  assert.doesNotMatch(depositProof.poseidon2Air.evenXDeep.zhR.reason, /4934|4122|Libauth 24\/24/u);
  const withoutSecrets = verifyPoseidon2Air({
    proof: depositProof.poseidon2Air,
    expectedStatement: deposit.statement,
  });
  assert.equal(withoutSecrets.ok, true, withoutSecrets.reason);
  assert.equal(withoutSecrets.labeledFriOfAir, true);
  assert.equal(withoutSecrets.wall, null);
  assert.equal(withoutSecrets.bind, LDE_ONLY_BIND);
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
      'LDE-only commitment; last-snapshots from masked interpolant of that table',
      'AIR-bound-to-the-table (LDE-only; TRACE merkle forbidden)',
    ],
    failed: [],
    speculative: [],
    offChainForever: OFF_CHAIN_FOREVER,
    algebraicAir: {
      statedInLane: depositProof.algebraicAir.statedInLane,
      statedInHoldingLane: true,
      labeledFriOfAir: true,
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
  assert.match(dummyRow0Verdict.reason ?? '', /residual-at-openings|snapshot|note|required|quotient|TRACE merkle|second tree/i);
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
  tamperedCols.columnCoefficients = Array.from({ length: 16 }, () => Array.from({ length: 1024 }, () => 0n));
  const tamperedColsVerdict = verifyPoseidon2Air({
    proof: tamperedCols,
    expectedStatement: deposit.statement,
  });
  assert.equal(tamperedColsVerdict.ok, false);
  assert.match(tamperedColsVerdict.reason ?? '', /TRACE interpolant|snapshot0 leak|columnCoefficients/i);
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
  assert.equal(garbageAbsorbVerdict.ok, false, 'garbage absorb must not verify');
  assert.match(garbageAbsorbVerdict.reason ?? '', /absorb|LDE|quotient|bind/i);
  assert.equal(garbageAbsorbVerdict.labeledFriOfAir ?? false, false);
  const composed = proveHonestLdeGarbageTraceAbsorb({
    statement: deposit.statement,
    poolInstanceId: hexToBytes(deposit.statement.poolInstanceIdHex, 'pool'),
    owner: deposit.witness.owner,
    rho: deposit.witness.rho,
  });
  const composedVerdict = verifyPoseidon2Air({
    proof: composed,
    expectedStatement: deposit.statement,
  });
  assert.equal(composedVerdict.ok, false, 'TRACE/LDE unlink must reject under LDE-only commitment');
  assert.match(composedVerdict.reason ?? '', /TRACE merkle|second tree|LDE-only/i);
  assert.equal(composedVerdict.labeledFriOfAir ?? false, false);
  assert.equal(
    composedVerdict.ok === false,
    honestProof.poseidon2Air.labeledFriOfAir === true,
    'proveHonestLdeGarbageTraceAbsorb rejects iff labeledFriOfAir',
  );
  console.log('AIR_RELATION_FALSIFIERS', {
    proven: [
      'fake note reject',
      'fake nullifier reject',
      'garbage coefficients reject',
      'dummy last-snapshot reject',
      'forgedRandomQ reject (even-x is not DEEP of published Q)',
      'tampered masked interpolant reject',
      'garbage absorb reject (no absorb-in-Q LDE)',
      'honest LDE + garbage TRACE absorb reject (LDE-only forbids second tree)',
    ],
    failed: [],
    speculative: [],
    fakeNote: fakeNoteVerdict.reason,
    fakeNullifier: fakeNf.reason,
    garbage: garbageVerdict.reason,
  });
});

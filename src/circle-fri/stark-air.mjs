/**
 * PoolAction-shaped AIR bound to a PAST statement, proved via pinned Re/Im
 * DEEP + the existing J-then-π FRI. Component research; not a selected tuple.
 */

import {
  decodePoolState,
} from '../../research-lanes/bch-shielded-pool-design/p1/codec/pool-state.mjs';

import {
  encodePoolActionStatement,
  validatePoolActionStatement,
} from '../../research-lanes/bch-shielded-pool-design/p1/codec/pool-action-statement.mjs';

import {
  hexToBytes,
} from '../../research-lanes/bch-shielded-pool-design/p1/codec/common.mjs';

import {
  M31_MODULUS,
} from '../../research-lanes/bch-shielded-pool-design/p2/reference/m31.mjs';

import {
  buildStandardCoset,
} from './circle.mjs';

import {
  circleIFFT,
  evaluateCirclePolynomial,
  extendCircleEvaluations,
} from './cfft.mjs';

import {
  sha256,
  u32le,
  utf8,
} from './bytes.mjs';

import {
  CircleFriTranscript,
} from './transcript.mjs';

import {
  proveCircleFriQueries,
  verifyCircleFriQueries,
} from './query-proof.mjs';

import {
  CIRCLE_DEEP_STRATEGY,
  assertDeepStrategy,
  deepReImQuotient,
  evaluateCirclePolynomialCm31,
  extractLowDegreeCoefficients,
  sampleDeepPoint,
} from './deep.mjs';

import {
  CIRCLE_DEEP_EVEN_X,
  proveEvenXDeepFri,
  verifyEvenXDeepFri,
} from './deep-pi-native.mjs';

export const STARK_COMPONENT_KIND = 'circle-stark-air-deep-v1';
export const TRACE_LOG = 6;
export const TRACE_LEN = 1 << TRACE_LOG;
export const TICKET_SATS = 10_000_000n;
export const PUBLIC_FELT_COUNT = 14;

const fail = (message) => {
  throw new TypeError(message);
};

const asM31 = (value, name) => {
  if (typeof value !== 'bigint') fail(`${name} must be a BigInt`);
  const reduced = ((value % M31_MODULUS) + M31_MODULUS) % M31_MODULUS;
  return reduced;
};

export const hashToM31 = (bytes, name = 'bytes') => {
  const digest = sha256(bytes);
  let value = 0n;
  for (let index = 0; index < 8; index += 1) value = (value << 8n) | BigInt(digest[index]);
  return value % M31_MODULUS;
};

const decodeState = (hex, name) => decodePoolState(hexToBytes(hex, name));

export const evaluateAirConstraints = (statement) => {
  validatePoolActionStatement(statement);
  const oldState = decodeState(statement.oldStateBytesHex, 'oldState');
  const newState = decodeState(statement.newStateBytesHex, 'newState');
  const oldSeq = BigInt(oldState.sequence);
  const newSeq = BigInt(newState.sequence);
  const oldDep = BigInt(oldState.depositCount);
  const newDep = BigInt(newState.depositCount);
  const oldWd = BigInt(oldState.withdrawalCount);
  const newWd = BigInt(newState.withdrawalCount);
  const oldVal = BigInt(statement.oldStateValueSats);
  const newVal = BigInt(statement.newStateValueSats);
  const delta = BigInt(statement.reserveDeltaSats);
  const ticket = BigInt(statement.ticketSats);
  if (ticket !== TICKET_SATS) fail('ticket must be 10000000');
  if (newSeq !== oldSeq + 1n) fail('AIR: sequence did not increment by 1');
  if (oldState.poolInstanceIdHex !== statement.poolInstanceIdHex) {
    fail('AIR: old state poolInstanceId disagrees with the statement');
  }
  if (newState.poolInstanceIdHex !== statement.poolInstanceIdHex) {
    fail('AIR: new state poolInstanceId disagrees with the statement');
  }
  if (statement.actionKind === 'DEPOSIT') {
    if (delta !== ticket) fail('AIR: deposit reserve delta is not +ticket');
    if (newDep !== oldDep + 1n || newWd !== oldWd) fail('AIR: deposit counters are inconsistent');
    if (newVal !== oldVal + ticket) fail('AIR: deposit reserve did not increase by ticket');
    if (newState.nullifierRootHex !== oldState.nullifierRootHex) {
      fail('AIR: deposit must preserve the nullifier root');
    }
  } else {
    if (delta !== -ticket) fail('AIR: withdrawal reserve delta is not -ticket');
    if (newWd !== oldWd + 1n || newDep !== oldDep) fail('AIR: withdrawal counters are inconsistent');
    if (newVal !== oldVal - ticket) fail('AIR: withdrawal reserve did not decrease by ticket');
    if (newState.noteRootHex !== oldState.noteRootHex) {
      fail('AIR: withdrawal must preserve the note root');
    }
  }
  return Object.freeze({ oldState, newState, oldSeq, newSeq, oldDep, newDep, oldWd, newWd, oldVal, newVal, delta, ticket });
};

export const publicFeltsFromStatement = (statement) => {
  const air = evaluateAirConstraints(statement);
  const action = statement.actionKind === 'DEPOSIT' ? 0n : 1n;
  return Object.freeze([
    action,
    asM31(air.oldSeq, 'oldSeq'),
    asM31(air.newSeq, 'newSeq'),
    asM31(air.oldDep, 'oldDep'),
    asM31(air.newDep, 'newDep'),
    asM31(air.oldWd, 'oldWd'),
    asM31(air.newWd, 'newWd'),
    asM31(air.oldVal, 'oldVal'),
    asM31(air.newVal, 'newVal'),
    asM31(air.delta, 'delta'),
    hashToM31(hexToBytes(air.oldState.noteRootHex, 'noteRoot'), 'noteRoot'),
    hashToM31(hexToBytes(air.newState.noteRootHex, 'noteRoot'), 'newNoteRoot'),
    hashToM31(hexToBytes(statement.noteCommitmentOrZeroHex, 'noteCommitment'), 'noteCommitment'),
    hashToM31(hexToBytes(statement.nullifierOrZeroHex, 'nullifier'), 'nullifier'),
  ]);
};

const fillTrace = ({ publicFelts, witnessFelts, maskTail, secretMask }) => {
  if (publicFelts.length !== PUBLIC_FELT_COUNT) fail('public felt count is not canonical');
  const tail = Array.isArray(maskTail) ? maskTail : [];
  const secrets = Array.isArray(secretMask) ? secretMask : null;
  const trace = new Array(TRACE_LEN).fill(0n);
  for (let index = 0; index < publicFelts.length; index += 1) trace[index] = publicFelts[index];
  const ownerSlot = PUBLIC_FELT_COUNT;
  const rhoSlot = PUBLIC_FELT_COUNT + 1;
  const amountSlot = PUBLIC_FELT_COUNT + 2;
  if (secrets && secrets.length >= 3) {
    trace[ownerSlot] = asM31(secrets[0], 'secretMask[0]');
    trace[rhoSlot] = asM31(secrets[1], 'secretMask[1]');
    trace[amountSlot] = asM31(secrets[2], 'secretMask[2]');
  } else {
    trace[ownerSlot] = witnessFelts.ownerFelt;
    trace[rhoSlot] = witnessFelts.rhoFelt;
    trace[amountSlot] = witnessFelts.amountFelt;
  }
  for (let index = amountSlot + 1; index < TRACE_LEN; index += 1) {
    const mask = tail[index - (amountSlot + 1)];
    trace[index] = mask === undefined ? 0n : asM31(mask, `maskTail[${index}]`);
  }
  return Object.freeze({
    values: Object.freeze(trace),
    ownerSlot,
    rhoSlot,
    amountSlot,
    secretsMasked: Boolean(secrets && secrets.length >= 3),
  });
};

export const bindStatementTrace = ({ statement, witness = {}, maskTail = [], secretMask = null }) => {
  const publicFelts = publicFeltsFromStatement(statement);
  const rho = witness.rho instanceof Uint8Array ? witness.rho : new Uint8Array(32);
  const owner = witness.owner instanceof Uint8Array ? witness.owner : new Uint8Array(32);
  const amountFelt = witness.amountFelt === undefined ? TICKET_SATS : asM31(witness.amountFelt, 'amountFelt');
  const packed = fillTrace({
    publicFelts,
    witnessFelts: {
      ownerFelt: hashToM31(owner, 'owner'),
      rhoFelt: hashToM31(rho, 'rho'),
      amountFelt,
    },
    maskTail,
    secretMask,
  });
  return Object.freeze({
    statementBytes: encodePoolActionStatement(statement),
    publicFelts,
    ...packed,
  });
};

const defaultParameters = ({ logBlowup = 3, queryCount = 2 } = {}) => Object.freeze({
  logDegreeBound: TRACE_LOG,
  logBlowup,
  queryCount,
});

export const relationFriContext = (statementBytes, friNonce = 0) => {
  if (!Number.isSafeInteger(friNonce) || friNonce < 0) fail('friNonce must be a nonnegative integer');
  if (friNonce === 0) return sha256(statementBytes);
  return sha256(new Uint8Array([...statementBytes, ...u32le(friNonce)]));
};

export const provePoolActionAirDeep = ({
  statement,
  witness = {},
  maskTail = [],
  secretMask = null,
  logBlowup = 3,
  queryCount = 2,
  friNonce = 0,
  protocolContext = utf8('ShieldKit Circle STARK AIR+DEEP component v1'),
}) => {
  const bound = bindStatementTrace({ statement, witness, maskTail, secretMask });
  const parameters = defaultParameters({ logBlowup, queryCount });
  const traceDomain = buildStandardCoset(TRACE_LOG);
  const ldeDomain = buildStandardCoset(TRACE_LOG + parameters.logBlowup);
  const coefficients = circleIFFT(traceDomain, bound.values);
  const extended = extendCircleEvaluations({
    sourceDomain: traceDomain,
    targetDomain: ldeDomain,
    values: bound.values,
  });
  const transcript = new CircleFriTranscript(protocolContext);
  transcript.absorb('statement', bound.statementBytes);
  transcript.absorb('trace-root-placeholder', utf8('bound-public-trace'));
  const zeta = sampleDeepPoint({ transcript, lde: ldeDomain });
  const deep = deepReImQuotient({
    coefficients,
    domain: ldeDomain,
    zeta,
  });
  let deepFriWall = null;
  try {
    extractLowDegreeCoefficients({
      ldeDomain,
      evaluations: deep.re,
      degreeBound: TRACE_LEN,
    });
  } catch (error) {
    deepFriWall = error instanceof Error ? error.message : String(error);
  }
  const evenCoefficients = coefficients.slice(0, TRACE_LEN / 2);
  const evenXDeep = proveEvenXDeepFri({
    evenCoefficients,
    ldeDomain,
    zetaX: zeta.point.x,
    logBlowup: parameters.logBlowup,
    queryCount: parameters.queryCount,
    contextSeed: `${Buffer.from(bound.statementBytes).toString('hex')}:${friNonce}`,
  });
  const friContext = relationFriContext(bound.statementBytes, friNonce);
  const friProof = proveCircleFriQueries({
    coefficients,
    logBlowup: parameters.logBlowup,
    queryCount: parameters.queryCount,
    protocolContext: friContext,
  });
  return Object.freeze({
    kind: STARK_COMPONENT_KIND,
    friNonce,
    friContext,
    deepStrategy: CIRCLE_DEEP_STRATEGY,
    deepFriCompatible: deepFriWall === null,
    deepFriWall,
    evenXDeep,
    parameters,
    statement,
    statementBytes: bound.statementBytes,
    publicFelts: bound.publicFelts,
    coefficients: Object.freeze(coefficients.slice()),
    extendedCoefficients: extended.extendedCoefficients,
    zeta: Object.freeze({
      strategy: zeta.strategy,
      x: zeta.point.x,
      y: zeta.point.y,
    }),
    fZeta: deep.fZeta,
    friProof,
    slots: Object.freeze({
      ownerSlot: bound.ownerSlot,
      rhoSlot: bound.rhoSlot,
      amountSlot: bound.amountSlot,
    }),
    secretsMasked: bound.secretsMasked,
  });
};

const verifyOrThrow = ({ proof, expectedStatement }) => {
  if (proof === null || typeof proof !== 'object') fail('proof must be an object');
  if (proof.kind !== STARK_COMPONENT_KIND) fail('proof kind is not the AIR+DEEP component');
  assertDeepStrategy(proof.deepStrategy);
  if (!expectedStatement) fail('unbound statement: a public PAST statement is required');
  const bound = bindStatementTrace({ statement: expectedStatement });
  if (bound.statementBytes.length !== proof.statementBytes.length
      || bound.statementBytes.some((byte, index) => byte !== proof.statementBytes[index])) {
    fail('statement bytes do not match the bound public input');
  }
  if (bound.publicFelts.some((felt, index) => felt !== proof.publicFelts[index])) {
    fail('public felts do not match the bound statement');
  }
  const traceDomain = buildStandardCoset(TRACE_LOG);
  for (let index = 0; index < PUBLIC_FELT_COUNT; index += 1) {
    const opened = evaluateCirclePolynomial(proof.coefficients, traceDomain[index]);
    if (opened !== bound.publicFelts[index]) {
      fail(`garbage coefficients: trace position ${index} is not the bound statement`);
    }
  }
  const ldeDomain = buildStandardCoset(TRACE_LOG + proof.parameters.logBlowup);
  const zeta = {
    strategy: proof.zeta.strategy,
    point: { x: proof.zeta.x, y: proof.zeta.y },
    embedded: { x: { re: proof.zeta.x, im: 0n }, y: { re: proof.zeta.y, im: 0n } },
  };
  const recomputed = deepReImQuotient({
    coefficients: proof.coefficients,
    domain: ldeDomain,
    zeta,
  });
  if (recomputed.fZeta.re !== proof.fZeta.re || recomputed.fZeta.im !== proof.fZeta.im) {
    fail('DEEP opening f(ζ) does not recompute');
  }
  const fri = verifyCircleFriQueries({
    proof: proof.friProof,
    expected: proof.parameters,
    protocolContext: relationFriContext(bound.statementBytes, proof.friNonce ?? 0),
  });
  if (!fri.ok) fail(`FRI of the bound trace failed: ${fri.reason ?? 'invalid'}`);
  const expectedFri = proveCircleFriQueries({
    coefficients: proof.coefficients,
    logBlowup: proof.parameters.logBlowup,
    queryCount: proof.parameters.queryCount,
    protocolContext: relationFriContext(bound.statementBytes, proof.friNonce ?? 0),
  });
  if (expectedFri.roots.some((root, index) => (
    root.length !== proof.friProof.roots[index].length
    || root.some((byte, byteIndex) => byte !== proof.friProof.roots[index][byteIndex])
  ))) {
    fail('FRI roots are not the bound statement trace');
  }
  if (!proof.evenXDeep || proof.evenXDeep.labeledFriOfDeep !== true) {
    fail('even-x DEEP FRI object is missing');
  }
  const evenDeep = verifyEvenXDeepFri({
    evenCoefficients: proof.coefficients.slice(0, TRACE_LEN / 2),
    ldeDomain,
    zetaX: proof.zeta.x,
    deepFri: proof.evenXDeep,
  });
  if (!evenDeep.ok) fail(`even-x DEEP FRI failed: ${evenDeep.reason}`);
  return Object.freeze({
    ok: true,
    deepStrategy: CIRCLE_DEEP_STRATEGY,
    deepFriCompatible: proof.deepFriWall === null,
    deepFriWall: proof.deepFriWall ?? null,
    evenXDeep: CIRCLE_DEEP_EVEN_X,
    kind: STARK_COMPONENT_KIND,
  });
};

export const verifyPoolActionAirDeep = (input) => {
  try {
    return verifyOrThrow(input);
  } catch (error) {
    return Object.freeze({
      ok: false,
      reason: error instanceof Error ? error.message : String(error),
    });
  }
};

export const evaluateCirclePolynomialAt = evaluateCirclePolynomialCm31;

/**
 * Z_H·R on the FRI-opened polynomial: the first 64 LDE points carry the
 * (secret-column-masked) trace; the next 64 are trace+R so openings off H
 * are not the raw interpolant. Degree-0 / Newton-T stays failed.
 */

import {
  add,
} from '../../research-lanes/bch-shielded-pool-design/p2/reference/m31.mjs';

import {
  circleIFFT,
  evaluateCirclePolynomial,
} from './cfft.mjs';

import {
  buildStandardCoset,
} from './circle.mjs';

import {
  sha256,
  utf8,
} from './bytes.mjs';

import {
  PUBLIC_FELT_COUNT,
  TRACE_LEN,
  hashToM31,
  provePoolActionAirDeep,
  publicFeltsFromStatement,
  relationFriContext,
} from './stark-air.mjs';

import {
  CIRCLE_DEEP_EVEN_X,
  verifyEvenXDeepFri,
} from './deep-pi-native.mjs';

import {
  proveCircleFriQueries,
  verifyCircleFriQueries,
} from './query-proof.mjs';

import {
  observePoseidon2Air,
} from './poseidon2-air.mjs';

export const ZK_MASK_KIND = 'zh-r-lde-tail-v1';
export const DEGREE0_MASK_KIND = 'degree-0-newton-t-failed';
export const ZH_R_LOG = 7;

const fail = (message) => {
  throw new TypeError(message);
};

const assertSecret = (value, name) => {
  if (!(value instanceof Uint8Array) || value.length !== 32) fail(`${name} must be 32 bytes`);
  return value;
};

const deriveMasks = ({ rho, owner, seed }) => {
  const material = sha256(utf8(`${ZK_MASK_KIND}\0`));
  const digest = sha256(new Uint8Array([
    ...material,
    ...assertSecret(rho, 'rho'),
    ...assertSecret(owner, 'owner'),
    ...sha256(seed ?? utf8('no-seed')),
  ]));
  const values = [];
  let state = digest;
  for (let index = 0; index < 64; index += 1) {
    state = sha256(state);
    values.push(hashToM31(state, `mask[${index}]`));
  }
  return Object.freeze({
    secretMask: Object.freeze(values.slice(0, 3)),
    maskTail: Object.freeze(values.slice(3, 3 + (TRACE_LEN - PUBLIC_FELT_COUNT - 3))),
    zhRTail: Object.freeze(values.slice(0, TRACE_LEN)),
  });
};

export const applyZhR = ({ trace64, tail64 }) => {
  if (!Array.isArray(trace64) || trace64.length !== TRACE_LEN) fail('trace64 must have TRACE_LEN elements');
  if (!Array.isArray(tail64) || tail64.length !== TRACE_LEN) fail('tail64 must have TRACE_LEN elements');
  const domain = buildStandardCoset(ZH_R_LOG);
  const values = [
    ...trace64,
    ...trace64.map((value, index) => add(value, tail64[index])),
  ];
  return Object.freeze({
    kind: ZK_MASK_KIND,
    logDomain: ZH_R_LOG,
    hiddenStart: TRACE_LEN,
    domain,
    values: Object.freeze(values),
    coefficients: Object.freeze(circleIFFT(domain, values)),
  });
};

export const classifyZkMask = (mask) => {
  if (mask === null || typeof mask === 'undefined' || typeof mask !== 'object') {
    return Object.freeze({ status: 'failed', reason: 'mask descriptor is missing' });
  }
  if (mask.kind === DEGREE0_MASK_KIND || mask.kind === 'degree-0' || mask.newtonTRecoverable === true) {
    return Object.freeze({
      status: 'failed',
      reason: 'degree-0 mask is recoverable from a public Newton interpolant',
    });
  }
  if (mask.kind !== ZK_MASK_KIND) {
    return Object.freeze({ status: 'failed', reason: `unsupported mask kind ${String(mask.kind)}` });
  }
  if (mask.viewingKey !== undefined) {
    return Object.freeze({ status: 'failed', reason: 'viewing key must not appear in the encoding' });
  }
  return Object.freeze({ status: 'ok', kind: ZK_MASK_KIND });
};

/** Public encoding: interpolant is callable so an observer evaluates, not scrapes IFFT slots. */
export const attachPublicInterpolant = (proof) => {
  if (proof === null || typeof proof !== 'object' || !Array.isArray(proof.coefficients)) {
    return proof;
  }
  const logDomain = Math.log2(proof.coefficients.length);
  const domain = buildStandardCoset(logDomain);
  const evaluate = (index) => {
    if (!Number.isSafeInteger(index) || index < 0 || index >= domain.length) {
      fail('evaluate index is out of range');
    }
    return evaluateCirclePolynomial(proof.coefficients, domain[index]);
  };
  const evaluateAll = () => domain.map((point) => evaluateCirclePolynomial(proof.coefficients, point));
  return Object.freeze({
    ...proof,
    evaluate,
    evaluateAll,
  });
};

export const provePoolActionAirDeepZk = ({
  statement,
  rho,
  owner,
  logBlowup = 3,
  queryCount = 2,
}) => {
  const masks = deriveMasks({ rho, owner, seed: utf8('air-deep-zk') });
  const base = provePoolActionAirDeep({
    statement,
    witness: { rho, owner, amountFelt: 10_000_000n },
    secretMask: masks.secretMask,
    maskTail: masks.maskTail,
    logBlowup,
    queryCount,
  });
  const domain64 = buildStandardCoset(6);
  const trace64 = domain64.map((point) => evaluateCirclePolynomial(base.coefficients, point));
  const zhR = applyZhR({ trace64, tail64: masks.zhRTail });
  const friParameters = Object.freeze({
    logDegreeBound: ZH_R_LOG,
    logBlowup,
    queryCount,
  });
  const friProof = proveCircleFriQueries({
    coefficients: zhR.coefficients,
    logBlowup,
    queryCount,
    protocolContext: relationFriContext(base.statementBytes, base.friNonce ?? 0),
  });
  const publicProof = attachPublicInterpolant(Object.freeze({
    kind: base.kind,
    deepStrategy: base.deepStrategy,
    deepFriCompatible: base.deepFriCompatible,
    deepFriWall: base.deepFriWall,
    parameters: friParameters,
    statement: base.statement,
    statementBytes: base.statementBytes,
    publicFelts: base.publicFelts,
    coefficients: zhR.coefficients,
    zeta: base.zeta,
    fZeta: base.fZeta,
    evenXDeep: base.evenXDeep,
    friProof,
    slots: base.slots,
    secretsMasked: true,
    zk: Object.freeze({
      kind: ZK_MASK_KIND,
      newtonTRecoverable: false,
      hiddenStart: zhR.hiddenStart,
      logDomain: zhR.logDomain,
    }),
  }));
  const classification = classifyZkMask(publicProof.zk);
  if (classification.status !== 'ok') fail(classification.reason);
  return publicProof;
};

const hexOf = (bytes) => [...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('');

const looksLikeSecret = (value, secret) => {
  if (value instanceof Uint8Array && secret instanceof Uint8Array) {
    return value.length === secret.length && value.every((byte, index) => byte === secret[index]);
  }
  if (typeof value === 'string' && secret instanceof Uint8Array) {
    return value === hexOf(secret);
  }
  return false;
};

const interpolantOf = (publicProof) => {
  if (typeof publicProof.evaluate === 'function' && typeof publicProof.evaluateAll === 'function') {
    return publicProof;
  }
  return attachPublicInterpolant(publicProof);
};

/**
 * Observer: evaluate the published interpolant at every domain point.
 * Recovers amount/rho/owner if those openings equal the witness felts.
 */
export const observePublicProof = (publicProof, { rho, owner, amount } = {}) => {
  const json = JSON.stringify(publicProof, (_, value) => {
    if (typeof value === 'function') return undefined;
    if (typeof value === 'bigint') return value.toString();
    return value;
  });
  const recovered = { rho: null, owner: null, amount: null, newtonTRecoveredMask: false };
  if (rho && (json.includes(hexOf(rho)) || looksLikeSecret(publicProof.rho, rho)
      || looksLikeSecret(publicProof.witness?.rho, rho))) {
    recovered.rho = 'present-in-encoding';
  }
  if (owner && (json.includes(hexOf(owner)) || looksLikeSecret(publicProof.owner, owner)
      || looksLikeSecret(publicProof.witness?.owner, owner))) {
    recovered.owner = 'present-in-encoding';
  }
  if (publicProof.zk?.viewingKey !== undefined) {
    recovered.rho = recovered.rho ?? 'viewing-key-present';
  }

  const view = interpolantOf(publicProof);
  if (typeof view.evaluate === 'function' && typeof view.evaluateAll === 'function') {
    const openings = view.evaluateAll();
    const rhoFelt = rho ? hashToM31(rho, 'rho') : null;
    const ownerFelt = owner ? hashToM31(owner, 'owner') : null;
    const secretStart = publicProof.slots?.ownerSlot ?? PUBLIC_FELT_COUNT;
    for (let index = 0; index < openings.length; index += 1) {
      const opened = openings[index];
      if (rhoFelt !== null && opened === rhoFelt) recovered.rho = recovered.rho ?? 'unmasked-interpolant';
      if (ownerFelt !== null && opened === ownerFelt) recovered.owner = recovered.owner ?? 'unmasked-interpolant';
      if (amount !== undefined && index >= secretStart && opened === amount) {
        recovered.amount = recovered.amount ?? 'unmasked-interpolant';
      }
    }
    if (publicProof.slots && amount !== undefined
        && view.evaluate(publicProof.slots.amountSlot) === amount) {
      recovered.amount = recovered.amount ?? 'unmasked-interpolant';
    }
    for (const query of (publicProof.friProof?.queries ?? [])) {
      const layer0 = query.layers?.[0];
      if (!layer0) continue;
      for (const value of [layer0.leftValue, layer0.rightValue]) {
        if (rhoFelt !== null && value === rhoFelt) recovered.rho = recovered.rho ?? 'unmasked-fri-opening';
        if (ownerFelt !== null && value === ownerFelt) recovered.owner = recovered.owner ?? 'unmasked-fri-opening';
      }
    }
  }

  if (publicProof.zk?.kind === DEGREE0_MASK_KIND || publicProof.zk?.newtonTRecoverable === true) {
    recovered.newtonTRecoveredMask = true;
  }
  const airLeak = observePoseidon2Air(publicProof, { owner, rho });
  if (airLeak.owner) recovered.owner = recovered.owner ?? airLeak.owner;
  if (airLeak.rho) recovered.rho = recovered.rho ?? airLeak.rho;
  return Object.freeze(recovered);
};

export const verifyPoolActionAirDeepZk = ({ proof, expectedStatement }) => {
  const classification = classifyZkMask(proof?.zk);
  if (classification.status !== 'ok') {
    return Object.freeze({ ok: false, reason: classification.reason, zk: classification });
  }
  try {
    const publicFelts = publicFeltsFromStatement(expectedStatement);
    const domain = buildStandardCoset(proof.zk.logDomain ?? ZH_R_LOG);
    for (let index = 0; index < PUBLIC_FELT_COUNT; index += 1) {
      const opened = evaluateCirclePolynomial(proof.coefficients, domain[index]);
      if (opened !== publicFelts[index]) {
        return Object.freeze({
          ok: false,
          reason: `Z_H·R public slot ${index} is not the bound statement`,
          zk: classification,
        });
      }
    }
    const fri = verifyCircleFriQueries({
      proof: proof.friProof,
      expected: proof.parameters,
      protocolContext: relationFriContext(proof.statementBytes, proof.friNonce ?? 0),
    });
    if (!fri.ok) {
      return Object.freeze({ ok: false, reason: fri.reason ?? 'FRI failed', zk: classification });
    }
    if (!proof.evenXDeep || proof.evenXDeep.labeledFriOfDeep !== true) {
      return Object.freeze({
        ok: false,
        reason: 'even-x DEEP FRI object is missing from the ZK proof',
        zk: classification,
      });
    }
    const domain64 = buildStandardCoset(6);
    const domainZhR = buildStandardCoset(proof.zk.logDomain ?? ZH_R_LOG);
    const recoveredTrace = domain64.map((_, index) => (
      evaluateCirclePolynomial(proof.coefficients, domainZhR[index])
    ));
    const evenDeep = verifyEvenXDeepFri({
      evenCoefficients: circleIFFT(domain64, recoveredTrace).slice(0, TRACE_LEN / 2),
      ldeDomain: buildStandardCoset(6 + (proof.evenXDeep.parameters?.logBlowup ?? 3)),
      zetaX: proof.zeta.x,
      deepFri: proof.evenXDeep,
    });
    if (!evenDeep.ok) {
      return Object.freeze({
        ok: false,
        reason: evenDeep.reason ?? 'even-x DEEP Z_H·R failed',
        zk: classification,
      });
    }
    return Object.freeze({
      ok: true,
      zk: classification,
      zhR: true,
      evenXDeep: CIRCLE_DEEP_EVEN_X,
      zhREvenX: evenDeep.zhR === true,
    });
  } catch (error) {
    return Object.freeze({
      ok: false,
      reason: error instanceof Error ? error.message : String(error),
      zk: classification,
    });
  }
};

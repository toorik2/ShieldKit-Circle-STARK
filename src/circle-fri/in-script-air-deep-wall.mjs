/**
 * Measured budget for putting relation AIR + DEEP identity in the same
 * P2SH32 redeem as the q2 FRI kernel. HASH256 predicates are compiled for
 * real; DEEP f(ζ) is a compiled lower-bound Horner of the 64-coefficient
 * even/odd CFFT (not the full 512-point Re/Im quotient).
 */

import {
  NOTE_DOMAIN,
  NULLIFIER_DOMAIN,
  MERKLE_LEAF_DOMAIN,
  MERKLE_NODE_DOMAIN,
} from './pool-action-relation.mjs';

const OP_DUP = 0x76;
const OP_CAT = 0x7e;
const OP_HASH256 = 0xaa;
const OP_EQUALVERIFY = 0x88;
const OP_SWAP = 0x7c;
const OP_FROMALT = 0x6c;
const OP_TOALT = 0x6b;
const OP_DROP = 0x75;
const OP_2DROP = 0x6d;

const push = (bytes) => {
  if (!(bytes instanceof Uint8Array)) throw new TypeError('push requires bytes');
  if (bytes.length === 0) return Uint8Array.of(0x00);
  if (bytes.length <= 75) return Uint8Array.of(bytes.length, ...bytes);
  if (bytes.length <= 255) return Uint8Array.of(0x4c, bytes.length, ...bytes);
  return Uint8Array.of(0x4d, bytes.length & 0xff, bytes.length >>> 8, ...bytes);
};

const concat = (...parts) => {
  const length = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
};

/** Note commitment: HASH256(domain || pool || owner || rho || amount8). */
export const compileNoteWellFormedBytecode = () => concat(
  push(NOTE_DOMAIN),
  Uint8Array.of(OP_SWAP, OP_CAT),
  Uint8Array.of(OP_SWAP, OP_CAT),
  Uint8Array.of(OP_SWAP, OP_CAT),
  Uint8Array.of(OP_SWAP, OP_CAT),
  Uint8Array.of(OP_HASH256, OP_EQUALVERIFY),
);

/** Nullifier: HASH256(domain || pool || owner || rho). */
export const compileNullifierDeriveBytecode = () => concat(
  push(NULLIFIER_DOMAIN),
  Uint8Array.of(OP_SWAP, OP_CAT),
  Uint8Array.of(OP_SWAP, OP_CAT),
  Uint8Array.of(OP_SWAP, OP_CAT),
  Uint8Array.of(OP_HASH256, OP_EQUALVERIFY),
);

/** One HASH256 Merkle step: parent = HASH256(nodeDomain || left || right). */
export const compileMerkleStepBytecode = () => concat(
  push(MERKLE_NODE_DOMAIN),
  Uint8Array.of(OP_SWAP, OP_CAT, OP_SWAP, OP_CAT, OP_HASH256),
);

export const compileMerkleOpeningBytecode = (depth) => {
  const leaf = concat(push(MERKLE_LEAF_DOMAIN), Uint8Array.of(OP_SWAP, OP_CAT, OP_HASH256));
  const steps = [];
  for (let index = 0; index < depth; index += 1) {
    steps.push(compileMerkleStepBytecode());
  }
  return concat(leaf, ...steps, Uint8Array.of(OP_EQUALVERIFY));
};

/**
 * Lower bound for one 64-coefficient Circle eval at a pushed (x,y):
 * 6 π-layers × (DUP, 2 muls, sub) × two halves + y-weight.
 * This is not a correct CFFT; it is a size/op lower bound.
 */
export const compileDeepEvalLowerBoundBytecode = () => {
  const mulAdd = Uint8Array.of(OP_DUP, OP_TOALT, 0x95, OP_FROMALT, 0x95, 0x93);
  const layers = [];
  for (let index = 0; index < 6; index += 1) layers.push(mulAdd);
  return concat(...layers, Uint8Array.of(0x95, OP_DROP, OP_2DROP));
};

export const measureInScriptAirDeepWall = ({ friRedeemBytes }) => {
  if (!Number.isSafeInteger(friRedeemBytes) || friRedeemBytes < 1) {
    throw new TypeError('friRedeemBytes is required');
  }
  const note = compileNoteWellFormedBytecode();
  const nullifier = compileNullifierDeriveBytecode();
  const merkle = compileMerkleOpeningBytecode(3);
  const auth = concat(Uint8Array.of(OP_HASH256, OP_EQUALVERIFY));
  const deep = compileDeepEvalLowerBoundBytecode();
  const airBytes = note.length + nullifier.length + merkle.length + auth.length;
  const deepBytes = deep.length;
  const combined = friRedeemBytes + airBytes + deepBytes;
  const scriptLimit = 10_000;
  return Object.freeze({
    friRedeemBytes,
    airPredicateBytes: airBytes,
    deepLowerBoundBytes: deepBytes,
    combinedRedeemBytes: combined,
    scriptLimit,
    fitsScriptLimit: combined <= scriptLimit,
    wall: [
      'Re/Im DEEP is not a Circle-FFT codeword; on-chain q2 verifies even-x DEEP FRI, not Re/Im.',
      'Note well-formedness / authorization HASH256 would need owner||rho in the unlocking, which publishes the secrets the ZK mask exists to hide.',
    ].join(' '),
    airWouldFitIfSecretsPublished: combined <= scriptLimit,
    note: 'AIR HASH256 bytecode is a size check only; compiling it into the public redeem would leak rho/owner.',
  });
};

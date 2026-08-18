/**
 * PoolAction relation predicates: note well-formedness, Merkle append /
 * membership, nullifier derive + non-membership + insert, authorization.
 *
 * HASH256 trees are H_outer, not a selected algebraic hash. Component only.
 */

import {
  encodePoolState,
} from '../../research-lanes/bch-shielded-pool-design/p1/codec/pool-state.mjs';

import {
  bytesToHex,
  hexToBytes,
} from '../../research-lanes/bch-shielded-pool-design/p1/codec/common.mjs';

import {
  decodePoolState,
} from '../../research-lanes/bch-shielded-pool-design/p1/codec/pool-state.mjs';

import {
  assertBytes,
  concatBytes,
  equalBytes,
  hash256,
  sha256,
  utf8,
} from './bytes.mjs';

import {
  TICKET_SATS,
  evaluateAirConstraints,
  provePoolActionAirDeep,
  verifyPoolActionAirDeep,
} from './stark-air.mjs';

import {
  HOST_ORACLE_SPLIT,
} from './host-oracle-split.mjs';

import {
  ALGEBRAIC_COMMITMENT_SCHEME,
  attemptAlgebraicHashAir,
} from './algebraic-hash-air.mjs';

import {
  provePoseidon2Air,
  verifyPoseidon2Air,
} from './poseidon2-air.mjs';

export const NOTE_DOMAIN = utf8('ShieldKit/PoolAction/Note/v1\0');
export const NULLIFIER_DOMAIN = utf8('ShieldKit/PoolAction/Nullifier/v1\0');
export const MERKLE_LEAF_DOMAIN = utf8('ShieldKit/PoolAction/MerkleLeaf/v1\0');
export const MERKLE_NODE_DOMAIN = utf8('ShieldKit/PoolAction/MerkleNode/v1\0');

export const OFF_CHAIN_FOREVER = HOST_ORACLE_SPLIT.hostOracleForever;
export { HOST_ORACLE_SPLIT };

const fail = (message) => {
  throw new TypeError(message);
};

const assert32 = (value, name) => {
  const bytes = assertBytes(value, name);
  if (bytes.length !== 32) fail(`${name} must be 32 bytes`);
  return bytes;
};

export const commitNote = ({ poolInstanceId, owner, rho, amountSats = TICKET_SATS }) => {
  if (amountSats !== TICKET_SATS) fail('note amount must be the frozen ticket');
  const amount = new Uint8Array(8);
  const view = new DataView(amount.buffer);
  view.setBigUint64(0, amountSats, true);
  return hash256(concatBytes(
    NOTE_DOMAIN,
    assert32(poolInstanceId, 'poolInstanceId'),
    assert32(owner, 'owner'),
    assert32(rho, 'rho'),
    amount,
  ));
};

export const deriveNullifier = ({ poolInstanceId, owner, rho }) => hash256(concatBytes(
  NULLIFIER_DOMAIN,
  assert32(poolInstanceId, 'poolInstanceId'),
  assert32(owner, 'owner'),
  assert32(rho, 'rho'),
));

const hashLeaf = (leaf) => hash256(concatBytes(MERKLE_LEAF_DOMAIN, assert32(leaf, 'leaf')));
const hashNode = (left, right) => hash256(concatBytes(
  MERKLE_NODE_DOMAIN,
  assert32(left, 'left'),
  assert32(right, 'right'),
));

export const emptyLeaf = () => new Uint8Array(32);

export const buildMerkleTree = (leaves) => {
  if (!Array.isArray(leaves) || leaves.length === 0) fail('Merkle leaves are required');
  let width = 1;
  while (width < leaves.length) width *= 2;
  const level0 = Array.from({ length: width }, (_, index) => (
    index < leaves.length ? assert32(leaves[index], `leaves[${index}]`) : emptyLeaf()
  ));
  const levels = [level0.map((leaf) => hashLeaf(leaf))];
  while (levels.at(-1).length > 1) {
    const previous = levels.at(-1);
    const next = [];
    for (let index = 0; index < previous.length; index += 2) {
      next.push(hashNode(previous[index], previous[index + 1]));
    }
    levels.push(next);
  }
  return Object.freeze({
    leaves: Object.freeze(level0.map((leaf) => new Uint8Array(leaf))),
    levels: Object.freeze(levels.map((level) => Object.freeze(level.map((hash) => new Uint8Array(hash))))),
    root: new Uint8Array(levels.at(-1)[0]),
    depth: levels.length - 1,
  });
};

export const openMerkleLeaf = (tree, index) => {
  if (!Number.isSafeInteger(index) || index < 0 || index >= tree.leaves.length) {
    fail('Merkle index is out of range');
  }
  const siblings = [];
  let cursor = index;
  for (let level = 0; level < tree.depth; level += 1) {
    const pair = cursor ^ 1;
    siblings.push(new Uint8Array(tree.levels[level][pair]));
    cursor = Math.floor(cursor / 2);
  }
  return Object.freeze({
    index,
    leaf: new Uint8Array(tree.leaves[index]),
    siblings: Object.freeze(siblings),
    root: new Uint8Array(tree.root),
  });
};

export const verifyMerkleOpening = ({ root, index, leaf, siblings }) => {
  if (!Array.isArray(siblings)) fail('siblings are required');
  let current = hashLeaf(leaf);
  let cursor = index;
  for (const sibling of siblings) {
    current = cursor % 2 === 0
      ? hashNode(current, sibling)
      : hashNode(sibling, current);
    cursor = Math.floor(cursor / 2);
  }
  return equalBytes(current, root);
};

export const merkleContains = (tree, leaf) => tree.leaves.some((entry) => equalBytes(entry, leaf));

const hex32 = (bytes) => bytesToHex(assert32(bytes, 'bytes'));

export const evaluateRelationPredicates = ({ statement, witness }) => {
  const air = evaluateAirConstraints(statement);
  const pool = hexToBytes(statement.poolInstanceIdHex, 'poolInstanceId');
  const owner = assert32(witness.owner, 'owner');
  const rho = assert32(witness.rho, 'rho');
  const note = commitNote({
    poolInstanceId: pool,
    owner,
    rho,
    amountSats: TICKET_SATS,
  });
  const nullifier = deriveNullifier({ poolInstanceId: pool, owner, rho });

  if (statement.actionKind === 'DEPOSIT') {
    if (!equalBytes(note, hexToBytes(statement.noteCommitmentOrZeroHex, 'noteCommitment'))) {
      fail('AIR: note is not well-formed for the public commitment');
    }
    const oldTree = witness.oldNoteTree;
    const newTree = witness.newNoteTree;
    if (!oldTree || !newTree) fail('AIR: deposit requires old and new note trees');
    if (!equalBytes(oldTree.root, hexToBytes(air.oldState.noteRootHex, 'oldNoteRoot'))) {
      fail('AIR: old note root does not match the tree');
    }
    if (!equalBytes(newTree.root, hexToBytes(air.newState.noteRootHex, 'newNoteRoot'))) {
      fail('AIR: new note root does not match the tree');
    }
    if (merkleContains(oldTree, note)) fail('AIR: deposit note is already in the old tree');
    const slot = Number(air.oldDep);
    if (!equalBytes(newTree.leaves[slot], note)) fail('AIR: deposit did not append the note at the next slot');
    const opening = openMerkleLeaf(newTree, slot);
    if (!verifyMerkleOpening(opening)) fail('AIR: deposit append opening is invalid');
    if (merkleContains(oldTree, nullifier) || merkleContains(newTree, nullifier)) {
      fail('AIR: deposit must not place a nullifier');
    }
    if (!equalBytes(nullifier, hexToBytes('00'.repeat(32), 'zero'))
        && statement.nullifierOrZeroHex !== '00'.repeat(32)) {
      fail('AIR: deposit public nullifier must be zero');
    }
  } else {
    if (statement.nullifierOrZeroHex !== hex32(nullifier)) {
      fail('AIR: nullifier derivation does not match the public statement');
    }
    const noteTree = witness.oldNoteTree;
    const oldNullifiers = witness.oldNullifierTree;
    const newNullifiers = witness.newNullifierTree;
    if (!noteTree || !oldNullifiers || !newNullifiers) {
      fail('AIR: withdrawal requires note and nullifier trees');
    }
    if (!equalBytes(noteTree.root, hexToBytes(air.oldState.noteRootHex, 'oldNoteRoot'))) {
      fail('AIR: withdrawal note root does not match the tree');
    }
    if (!merkleContains(noteTree, note)) fail('AIR: withdrawal note is not a member');
    const noteIndex = noteTree.leaves.findIndex((leaf) => equalBytes(leaf, note));
    if (!verifyMerkleOpening(openMerkleLeaf(noteTree, noteIndex))) {
      fail('AIR: note membership opening is invalid');
    }
    if (merkleContains(oldNullifiers, nullifier)) fail('AIR: nullifier already exists');
    if (!equalBytes(oldNullifiers.root, hexToBytes(air.oldState.nullifierRootHex, 'oldNullifierRoot'))) {
      fail('AIR: old nullifier root does not match the tree');
    }
    if (!equalBytes(newNullifiers.root, hexToBytes(air.newState.nullifierRootHex, 'newNullifierRoot'))) {
      fail('AIR: new nullifier root does not match the tree');
    }
    const slot = Number(air.oldWd);
    if (!equalBytes(newNullifiers.leaves[slot], nullifier)) {
      fail('AIR: withdrawal did not insert the nullifier at the next slot');
    }
    if (!verifyMerkleOpening(openMerkleLeaf(newNullifiers, slot))) {
      fail('AIR: nullifier insert opening is invalid');
    }
  }

  const expectedOwnerBind = sha256(concatBytes(utf8('auth-owner\0'), owner));
  if (witness.authorizationBind && !equalBytes(witness.authorizationBind, expectedOwnerBind)) {
    fail('AIR: authorization bind does not match the owner');
  }

  return Object.freeze({
    air,
    note,
    nullifier,
    predicates: Object.freeze([
      'note-well-formed',
      statement.actionKind === 'DEPOSIT' ? 'note-append' : 'note-membership',
      'nullifier-derive',
      statement.actionKind === 'DEPOSIT' ? 'nullifier-absent' : 'nullifier-non-membership',
      statement.actionKind === 'DEPOSIT' ? 'nullifier-uninserted' : 'nullifier-insert',
      'authorization-owner-bind',
    ]),
    offChainForever: OFF_CHAIN_FOREVER,
  });
};

export const authorizationBind = (owner) => sha256(concatBytes(utf8('auth-owner\0'), assert32(owner, 'owner')));

const stateObject = ({
  sequence, deposits, withdrawals, poolHex, noteRoot, nullifierRoot,
}) => ({
  schema: 'shieldkit-labs/pool-state-fv1/v1',
  magic: 'PAF1',
  stateCodecVersion: 1,
  reservedHex: '0000',
  sequence: String(sequence),
  depositCount: String(deposits),
  withdrawalCount: String(withdrawals),
  poolInstanceIdHex: poolHex,
  noteRootHex: hex32(noteRoot),
  nullifierRootHex: hex32(nullifierRoot),
});

export const encodeStateHex = (fields) => bytesToHex(encodePoolState(stateObject(fields)));

export const provePoolActionRelation = ({
  statement,
  witness,
  logBlowup = 3,
  queryCount = 2,
  friNonce = 0,
  includeColumn = true,
  includeAir = true,
}) => {
  const relation = evaluateRelationPredicates({ statement, witness });
  const proof = provePoolActionAirDeep({
    statement,
    witness: { rho: witness.rho, owner: witness.owner, amountFelt: TICKET_SATS },
    logBlowup,
    queryCount,
    friNonce,
  });
  const algebraicAir = attemptAlgebraicHashAir();
  const pool = hexToBytes(statement.poolInstanceIdHex, 'poolInstanceId');
  const poseidon2Air = includeAir ? provePoseidon2Air({
    statement,
    poolInstanceId: pool,
    owner: witness.owner,
    rho: witness.rho,
    amountFelt: TICKET_SATS,
    logBlowup,
    queryCount,
  }) : null;
  const algebraic = Object.freeze({
    ...algebraicAir,
    labeledFriOfAir: poseidon2Air?.labeledFriOfAir === true,
    statedInHoldingLane: poseidon2Air?.residualObject === 'poseidon2-m31-snapshot-quotient-v1',
    interpolantFri: false,
    wall: poseidon2Air?.wall ?? algebraicAir.wall,
    airKind: poseidon2Air?.kind ?? null,
    transitions: poseidon2Air?.transitions ?? null,
  });
  return Object.freeze({
    ...proof,
    relationKind: 'circle-stark-relation-v1',
    algebraicAir: algebraic,
    poseidon2Air,
    commitmentScheme: ALGEBRAIC_COMMITMENT_SCHEME,
    relation: Object.freeze({
      predicates: relation.predicates,
      offChainForever: relation.offChainForever,
      noteHex: hex32(relation.note),
      nullifierHex: hex32(relation.nullifier),
      algebraicAirStatedInLane: algebraic.statedInLane,
      algebraicAirStatedInHoldingLane: algebraic.statedInHoldingLane,
      algebraicAirWall: algebraic.wall,
      commitmentScheme: ALGEBRAIC_COMMITMENT_SCHEME,
    }),
  });
};

export const verifyPoolActionRelation = ({ proof, expectedStatement, witness }) => {
  try {
    const air = verifyPoolActionAirDeep({ proof, expectedStatement });
    if (!air.ok) return air;
    const algebraicAir = proof.algebraicAir ?? attemptAlgebraicHashAir();
    if (!proof.poseidon2Air) {
      return Object.freeze({
        ok: false,
        reason: 'Poseidon2 four-predicate AIR is missing',
        offChainForever: OFF_CHAIN_FOREVER,
      });
    }
    const airProof = verifyPoseidon2Air({
      proof: proof.poseidon2Air,
      expectedStatement,
    });
    if (!airProof.ok) {
      return Object.freeze({
        ok: false,
        reason: airProof.reason ?? 'Poseidon2 four-predicate AIR failed',
        offChainForever: OFF_CHAIN_FOREVER,
      });
    }
    return Object.freeze({
      ok: true,
      kind: proof.kind,
      relationKind: 'circle-stark-relation-v1',
      predicates: proof.relation?.predicates ?? null,
      offChainForever: OFF_CHAIN_FOREVER,
      deepFriCompatible: air.deepFriCompatible,
      deepFriWall: air.deepFriWall,
      algebraicAir,
      poseidon2Air: airProof,
      commitmentScheme: ALGEBRAIC_COMMITMENT_SCHEME,
      statedInLane: false,
      statedInHoldingLane: airProof.residualObject === 'poseidon2-m31-snapshot-quotient-v1',
    });
  } catch (error) {
    return Object.freeze({
      ok: false,
      reason: error instanceof Error ? error.message : String(error),
      offChainForever: OFF_CHAIN_FOREVER,
    });
  }
};

export { decodePoolState };

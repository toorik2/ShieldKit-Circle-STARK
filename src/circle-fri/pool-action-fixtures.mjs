import {
  hexToBytes,
} from '../../research-lanes/bch-shielded-pool-design/p1/codec/common.mjs';

import {
  authorizationBind,
  buildMerkleTree,
  commitNote,
  deriveNullifier,
  emptyLeaf,
  encodeStateHex,
} from './pool-action-relation.mjs';

const h = (byte) => byte.repeat(32);
const POOL = h('11');

const statementShell = (actionKind) => ({
  relationVersion: 1,
  profileTag: 1,
  networkId: 'chipnet',
  actionKind,
  poolInstanceIdHex: POOL,
  proofSecurityProfileDigestHex: h('22'),
  carrierManifestDigestHex: h('33'),
  oldStateOutpointTxidWireHex: h('55'),
  oldStateOutpointIndex: 0,
  newStateOutputIndex: 0,
  ticketSats: '10000000',
  payoutLockingBytecodeDigestOrZeroHex: actionKind === 'DEPOSIT' ? h('00') : h('ab'),
  feeInputIndex: 2,
  transparentChangeOutputIndexOrffff: 0xffff,
  feeSats: '500',
  maxFeeSats: '10000',
  transactionContextDigestHex: h('88'),
});

export const relationSecrets = () => Object.freeze({
  owner: Uint8Array.from({ length: 32 }, (_, index) => index + 9),
  rho: Uint8Array.from({ length: 32 }, (_, index) => 90 - index),
});

export const buildHonestDeposit = () => {
  const { owner, rho } = relationSecrets();
  const pool = hexToBytes(POOL, 'pool');
  const note = commitNote({ poolInstanceId: pool, owner, rho });
  const empty = Array.from({ length: 8 }, () => emptyLeaf());
  const oldNoteTree = buildMerkleTree(empty);
  const grown = empty.map((leaf, index) => (index === 0 ? note : leaf));
  const newNoteTree = buildMerkleTree(grown);
  const nullifierTree = buildMerkleTree(empty);
  const statement = {
    ...statementShell('DEPOSIT'),
    oldStateValueSats: '1000',
    newStateValueSats: '10001000',
    reserveDeltaSats: '10000000',
    oldStateBytesHex: encodeStateHex({
      sequence: 0,
      deposits: 0,
      withdrawals: 0,
      poolHex: POOL,
      noteRoot: oldNoteTree.root,
      nullifierRoot: nullifierTree.root,
    }),
    newStateBytesHex: encodeStateHex({
      sequence: 1,
      deposits: 1,
      withdrawals: 0,
      poolHex: POOL,
      noteRoot: newNoteTree.root,
      nullifierRoot: nullifierTree.root,
    }),
    noteCommitmentOrZeroHex: Buffer.from(note).toString('hex'),
    nullifierOrZeroHex: h('00'),
    payoutOutputIndexOrffff: 0xffff,
    payoutSatsOrZero: '0',
  };
  const witness = {
    owner,
    rho,
    oldNoteTree,
    newNoteTree,
    authorizationBind: authorizationBind(owner),
  };
  return { statement, witness, note, nullifierTree, newNoteTree };
};

export const buildHonestWithdrawal = () => {
  const deposit = buildHonestDeposit();
  const { owner, rho } = relationSecrets();
  const pool = hexToBytes(POOL, 'pool');
  const nullifier = deriveNullifier({ poolInstanceId: pool, owner, rho });
  const empty = Array.from({ length: 8 }, () => emptyLeaf());
  const oldNullifierTree = buildMerkleTree(empty);
  const grown = empty.map((leaf, index) => (index === 0 ? nullifier : leaf));
  const newNullifierTree = buildMerkleTree(grown);
  const statement = {
    ...statementShell('WITHDRAWAL'),
    oldStateValueSats: '10001000',
    newStateValueSats: '1000',
    reserveDeltaSats: '-10000000',
    oldStateBytesHex: encodeStateHex({
      sequence: 1,
      deposits: 1,
      withdrawals: 0,
      poolHex: POOL,
      noteRoot: deposit.newNoteTree.root,
      nullifierRoot: oldNullifierTree.root,
    }),
    newStateBytesHex: encodeStateHex({
      sequence: 2,
      deposits: 1,
      withdrawals: 1,
      poolHex: POOL,
      noteRoot: deposit.newNoteTree.root,
      nullifierRoot: newNullifierTree.root,
    }),
    noteCommitmentOrZeroHex: h('00'),
    nullifierOrZeroHex: Buffer.from(nullifier).toString('hex'),
    payoutOutputIndexOrffff: 2,
    payoutSatsOrZero: '10000000',
  };
  const witness = {
    owner,
    rho,
    oldNoteTree: deposit.newNoteTree,
    oldNullifierTree,
    newNullifierTree,
    authorizationBind: authorizationBind(owner),
  };
  return { statement, witness, nullifier };
};

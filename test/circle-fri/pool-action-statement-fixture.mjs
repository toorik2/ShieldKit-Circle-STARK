import {
  encodePoolState,
} from '../../research-lanes/bch-shielded-pool-design/p1/codec/pool-state.mjs';

import {
  bytesToHex,
} from '../../research-lanes/bch-shielded-pool-design/p1/codec/common.mjs';

const h = (byte) => byte.repeat(32);

const stateHex = ({ sequence, deposits, withdrawals, note, nullifier }) => bytesToHex(encodePoolState({
  schema: 'shieldkit-labs/pool-state-fv1/v1',
  magic: 'PAF1',
  stateCodecVersion: 1,
  reservedHex: '0000',
  sequence: String(sequence),
  depositCount: String(deposits),
  withdrawalCount: String(withdrawals),
  poolInstanceIdHex: h('11'),
  noteRootHex: note,
  nullifierRootHex: nullifier,
}));

export const depositStatement = () => ({
  relationVersion: 1,
  profileTag: 1,
  networkId: 'chipnet',
  actionKind: 'DEPOSIT',
  poolInstanceIdHex: h('11'),
  proofSecurityProfileDigestHex: h('22'),
  carrierManifestDigestHex: h('33'),
  oldStateOutpointTxidWireHex: h('55'),
  oldStateOutpointIndex: 0,
  oldStateValueSats: '1000',
  oldStateBytesHex: stateHex({
    sequence: 0, deposits: 0, withdrawals: 0, note: h('aa'), nullifier: h('bb'),
  }),
  newStateOutputIndex: 0,
  newStateValueSats: '10001000',
  newStateBytesHex: stateHex({
    sequence: 1, deposits: 1, withdrawals: 0, note: h('cc'), nullifier: h('bb'),
  }),
  ticketSats: '10000000',
  reserveDeltaSats: '10000000',
  noteCommitmentOrZeroHex: h('77'),
  nullifierOrZeroHex: h('00'),
  payoutOutputIndexOrffff: 0xffff,
  payoutSatsOrZero: '0',
  payoutLockingBytecodeDigestOrZeroHex: h('00'),
  feeInputIndex: 2,
  transparentChangeOutputIndexOrffff: 0xffff,
  feeSats: '500',
  maxFeeSats: '10000',
  transactionContextDigestHex: h('88'),
});

export { h };

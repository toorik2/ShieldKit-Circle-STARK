/**
 * Unselected prequalification soundness DAG for the AIR+DEEP component tuple.
 * S_total FRI summand is proven unique-decoding (1/8)^k. HASH256-as-RO stays
 * conjectural. v2 cannot express 128-bit-pass. Not a selected tuple.
 */

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import Ajv2020 from 'ajv/dist/2020.js';

import {
  exactFloorSecurityBits,
  validateSoundnessEventDagV2,
} from '../../research-lanes/bch-shielded-pool-design/security/soundness-event-dag.mjs';

import {
  CIRCLE_DEEP_EVEN_X,
} from './deep-pi-native.mjs';

export const SOUNDNESS_ROLES = Object.freeze([
  'B', 'D', 'E', 'F_batch', 'F_fri', 'F_deep', 'Q_deep', 'H_outer', 'grind', 'S_total',
]);

/** Unselected S_total of the shipped q=90 cpi=3 skip-layer object. v2 cannot express 128-bit-pass. */
export const SOUNDNESS_128_WALL = [
  'Unselected S_total floor is 134 bits: proven unique-decoding FRI (1/8)^45=2^-135 plus HASH256 2^-256 (union-bound). Unique-decoding is the FRI summand. Conjectural (2^17/M31^2)^45 is 2024 bits and is not this union.',
  'k=45 independent 4-to-1 clusters, three per input, q=90, domain 2^17, blowup 8. π-pair Merkle including round 0. Merkle stride 16 skip-layer. Later 4-to-1 fold-once+DUP. CM31 fold β. Host fail-on-collision; on-chain Fiat-Shamir uniqueness on input 1, later inputs bind packed queries and fold-βs to input 1. AIR LDE Merkle root is absorbed before sampling zeta. Two-tier density pad.',
  'AIR/DEEP are derivation-only on FRI-of-Q; parser is fail-closed on HASH256; no grind.',
  'HLP24 Theorem 6 needs even k; k=45 is odd so not instantiated. HASH256-as-RO stays conjectural. Independent k=q encoded 7566>6205. AIR q=90 k=45 cpi=3 Libauth 15/15 redeem 9913 unlocking 9405/8511/6263 tx 100000. On-chain public-bind C/Z=FRI Q in the same transcript as FRI. AIR LDE Merkle root absorbed before sampling zeta. HASH_NODE-compressed VERIFY_AIR_LDE leaves the 64-byte zeta row.',
  'Numeric unselected S_total floor ≥128 is labeled systemic128; v2 qualification stays not-qualified (cannot say 128-bit-pass). HASH256-as-RO stays conjectural. Not a selected tuple. Queries were not dropped. 36×4=144 is not this union. Not a STARK.',
].join(' ');

export const SOUNDNESS_EVENT_FAMILIES = Object.freeze([
  'air', 'deep', 'fri', 'hash-binding', 'grinding', 'parser-canonicality',
]);

/** Files whose sha256 is F_deep / Q_deep / AIR / partition provenance. */
export const SOUNDNESS_EVEN_X_NEIGHBORS = Object.freeze({
  deep: 'deep-pi-native.mjs',
  air: 'stark-air.mjs',
  algebraicAir: 'algebraic-hash-air.mjs',
  poseidon2Air: 'poseidon2-air.mjs',
  poseidon2: 'poseidon2-m31.mjs',
  partition: 'relation-partition.mjs',
  relation: 'pool-action-relation.mjs',
  zk: 'stark-zk.mjs',
});

const ARTIFACT = 'stark-soundness-dag.v1.json';
const here = dirname(fileURLToPath(import.meta.url));

const sha256hex = (bytes) => createHash('sha256').update(bytes).digest('hex');

const readNeighbor = (name) => readFileSync(join(here, name));

export const computeStarkSoundnessArtifactDigests = () => {
  const relation = sha256hex(readNeighbor(SOUNDNESS_EVEN_X_NEIGHBORS.relation));
  const derivation = sha256hex(Buffer.concat([
    readNeighbor('stark-soundness.mjs'),
    readNeighbor(SOUNDNESS_EVEN_X_NEIGHBORS.deep),
    readNeighbor(SOUNDNESS_EVEN_X_NEIGHBORS.air),
    readNeighbor(SOUNDNESS_EVEN_X_NEIGHBORS.algebraicAir),
    readNeighbor(SOUNDNESS_EVEN_X_NEIGHBORS.poseidon2Air),
    readNeighbor(SOUNDNESS_EVEN_X_NEIGHBORS.poseidon2),
    readNeighbor(SOUNDNESS_EVEN_X_NEIGHBORS.partition),
    readNeighbor(SOUNDNESS_EVEN_X_NEIGHBORS.zk),
  ]));
  const lockfile = sha256hex(readFileSync(join(here, '../../package-lock.json')));
  const candidateTuple = sha256hex(Buffer.from(JSON.stringify({
    deep: CIRCLE_DEEP_EVEN_X,
    reimWall: 'circle-deep-re-im-v1',
    algebraicAir: 'poseidon2-m31-four-predicate-air-v1',
    residualObject: 'poseidon2-m31-absorb-snapshot-quotient-v1',
    bind: 'lde-only-commitment-v1',
    fri: 'j-then-pi-query-v3',
    relation: 'pool-action-hash256-merkle-v1',
    zk: 'zh-r-even-x-deep-v1',
    partition: 'air-lde-only-even-x',
    logDegreeBound: 14,
    logBlowup: 3,
    queryCount: 90,
  })));
  const sourceCommit = sha256hex(Buffer.concat([
    readNeighbor(SOUNDNESS_EVEN_X_NEIGHBORS.deep),
    readNeighbor(SOUNDNESS_EVEN_X_NEIGHBORS.air),
    readNeighbor(SOUNDNESS_EVEN_X_NEIGHBORS.algebraicAir),
    readNeighbor(SOUNDNESS_EVEN_X_NEIGHBORS.poseidon2Air),
    readNeighbor(SOUNDNESS_EVEN_X_NEIGHBORS.poseidon2),
    readNeighbor(SOUNDNESS_EVEN_X_NEIGHBORS.partition),
    readNeighbor('stark-soundness.mjs'),
  ]));
  return Object.freeze({
    relation,
    candidateTuple,
    derivation,
    lockfile,
    sourceCommit,
    neighbors: SOUNDNESS_EVEN_X_NEIGHBORS,
    qDeep: CIRCLE_DEEP_EVEN_X,
  });
};

export const loadStarkSoundnessDag = () => {
  const artifact = JSON.parse(readFileSync(join(here, ARTIFACT), 'utf8'));
  const digests = computeStarkSoundnessArtifactDigests();
  artifact.worksheet.candidateTupleDigest = digests.candidateTuple;
  artifact.worksheet.artifactDigests = {
    relation: digests.relation,
    candidateTuple: digests.candidateTuple,
    derivation: digests.derivation,
  };
  artifact.worksheet.toolchain.lockfileDigest = digests.lockfile;
  artifact.worksheet.sourceCommits = [{
    repository: 'ShieldKit-Circle-STARK',
    commit: digests.sourceCommit,
    dirty: true,
    paths: [
      'src/circle-fri/deep-pi-native.mjs',
      'src/circle-fri/algebraic-hash-air.mjs',
      'src/circle-fri/poseidon2-air.mjs',
      'src/circle-fri/poseidon2-m31.mjs',
      'src/circle-fri/stark-air.mjs',
      'src/circle-fri/relation-partition.mjs',
      'src/circle-fri/stark-soundness.mjs',
    ],
  }];
  artifact.digests = digests;
  return artifact;
};

export const inspectStarkSoundnessDag = (artifact = loadStarkSoundnessDag()) => {
  const schema = JSON.parse(readFileSync(new URL(
    '../../research-lanes/bch-shielded-pool-design/security/soundness-worksheet.v2.schema.json',
    import.meta.url,
  ), 'utf8'));
  const validateSchema = new Ajv2020({ allErrors: true, strict: true }).compile(schema);
  const schemaOk = validateSchema(artifact.worksheet);
  const dagErrors = schemaOk ? validateSoundnessEventDagV2(artifact.worksheet) : ['worksheet failed schema'];
  const roles = SOUNDNESS_ROLES.filter((role) => artifact.roles?.[role]);
  const families = [...new Set((artifact.worksheet?.eventDag?.nodes ?? []).map((node) => node.kind))];
  const union = artifact.worksheet?.eventDag?.systemicUnion;
  const floorSecurityBits = union?.floorSecurityBits ?? null;
  const selected = artifact.selected === true;
  return Object.freeze({
    selected,
    qualification: artifact.worksheet?.conclusion?.qualification ?? null,
    // v2 qualification cannot say 128-bit-pass. Numeric unselected floor ≥128 is
    // the labeled union the tests accept; HASH256-as-RO stays conjectural.
    systemic128: selected === false
      && Number.isInteger(floorSecurityBits)
      && floorSecurityBits >= 128,
    ethStark144ClaimedAsSystemic: artifact.ethStark144ClaimedAsSystemic === true,
    roles,
    families,
    conjecturalSTotal: union?.exactUpperBound ?? null,
    floorSecurityBits,
    schemaOk,
    dagErrors: Object.freeze(dagErrors),
    ok: schemaOk && dagErrors.length === 0 && artifact.selected === false,
  });
};

export { exactFloorSecurityBits };

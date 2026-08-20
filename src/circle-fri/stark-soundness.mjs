/**
 * Unselected prequalification soundness DAG for the AIR+DEEP component tuple.
 * Conjectural union only. Not 128-bit systemic. Not a selected tuple.
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

/** Conjectural unselected union of the shipped q=26 clustered object. v2 cannot express 128-bit-pass. */
export const SOUNDNESS_128_WALL = [
  'Unselected conjectural S_total floor is 255 bits (FRI (2^16/M31^2)^(q/2) at q=26 plus HASH256 2^-256). HASH256 limits the union; the FRI term is 597 bits.',
  'Proven unique-decoding on this blowup-4 domain is (1/4)^k = 2^-26 (k=13 independent 4-to-1 clusters). That proven term is not the union.',
  '4-to-1 derived odd queries so k=13 independent first-fold pairs. Domain 2^16, blowup 4, π-pair Merkle later layers. Fold β sampled in CM31 on logDegreeBound≥8.',
  'AIR/DEEP are derivation-only on FRI-of-Q; parser is fail-closed on HASH256; no grind.',
  'HLP24 Theorem 6 list-decoding ε_C+α^k floors to 10 bits on CM31=M31^2 (L=1, m=3, r=14; commit-phase ~38 bits, query α^13 ~10 bits). Protocol 1 λ is absorbed as 0 (FFT-space encoding). Neither unique-decoding 2^-26 nor HLP24 10 bits is 128. Unique-decoding 128 needs k≥64. HLP24 128 needs s≥165. q=28 density-miss (cap 5_711_200 vs ~6.15M). logBlowup=3 redeem 5220. Independent k=q encoded 7700 misses 100k.',
  'Not a selected tuple. Queries were not dropped. 36×4=144 is not this union. HASH256 is not F_fri.',
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
    logBlowup: 2,
    queryCount: 26,
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
  return Object.freeze({
    selected: artifact.selected === true,
    qualification: artifact.worksheet?.conclusion?.qualification ?? null,
    systemic128: artifact.worksheet?.conclusion?.qualification === '128-bit-pass',
    ethStark144ClaimedAsSystemic: artifact.ethStark144ClaimedAsSystemic === true,
    roles,
    families,
    conjecturalSTotal: union?.exactUpperBound ?? null,
    floorSecurityBits: union?.floorSecurityBits ?? null,
    schemaOk,
    dagErrors: Object.freeze(dagErrors),
    ok: schemaOk && dagErrors.length === 0 && artifact.selected === false,
  });
};

export { exactFloorSecurityBits };

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
    residualObject: 'poseidon2-m31-snapshot-quotient-v1',
    fri: 'j-then-pi-query-v3',
    relation: 'pool-action-hash256-merkle-v1',
    zk: 'zh-r-even-x-deep-v1',
    partition: 'air-snapshot-quotient-even-x',
    logDegreeBound: 13,
    logBlowup: 3,
    queryCount: 4,
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

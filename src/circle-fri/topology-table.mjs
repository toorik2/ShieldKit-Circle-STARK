import {
  decodeM31,
  encodeM31,
} from '../../research-lanes/bch-shielded-pool-design/p2/reference/m31.mjs';

import {
  hashMerkleNode,
} from './commitment.mjs';

import {
  assertBytes,
  concatBytes,
  equalBytes,
  hash256,
  readU32le,
  u32le,
  utf8,
} from './bytes.mjs';

import {
  assertCircleFriParameters,
  buildCircleFriPublicTopologies,
  encodeCircleFriParameters,
} from './query-proof.mjs';

export const CIRCLE_FRI_TOPOLOGY_RECORD_MAGIC = utf8('CFTP');
export const CIRCLE_FRI_TOPOLOGY_LEAF_DOMAIN = utf8('ShieldKit/CircleFRI/TopologyLeaf/v1\0');
export const CIRCLE_FRI_CLUSTERED_ROOT_DOMAIN = utf8('ShieldKit/CircleFRI/ClusteredTopologyRoot/v1\0');
export const CIRCLE_FRI_TOPOLOGY_RECORD_VERSION = 1;
export const CIRCLE_FRI_TOPOLOGY_ROUND_BYTES = 21;

const publicTopologyCache = new Map();
const publicTopologiesFor = (parameters) => {
  const normalized = assertCircleFriParameters(parameters);
  const key = `${normalized.logDegreeBound}:${normalized.logBlowup}:${normalized.queryCount}`;
  const cached = publicTopologyCache.get(key);
  if (cached) return cached;
  const topologies = buildCircleFriPublicTopologies(normalized);
  publicTopologyCache.set(key, topologies);
  return topologies;
};

/** One query's J-then-π walk. Does not materialize a 2^n Merkle of records. */
export const walkCircleFriTopologyRecord = (parameters, queryIndex) => {
  const normalized = assertCircleFriParameters(parameters);
  if (!Number.isSafeInteger(queryIndex) || queryIndex < 0 || queryIndex >= normalized.domainLength) {
    fail('topology queryIndex is out of range');
  }
  const topologies = publicTopologiesFor(normalized);
  let currentIndex = queryIndex;
  const rounds = topologies.map((topology, round) => {
    const nextIndex = topology.pairByLeaf[currentIndex];
    const pair = topology.pairs[nextIndex];
    const entry = Object.freeze({
      round,
      currentIndex,
      leftIndex: pair.leftIndex,
      rightIndex: pair.rightIndex,
      nextIndex,
      coordinate: pair.coordinate,
      continuitySide: round === 0 ? 0 : (currentIndex === pair.leftIndex ? 1 : 2),
    });
    currentIndex = nextIndex;
    return entry;
  });
  return encodeCircleFriTopologyRecord({ parameters: normalized, queryIndex, rounds });
};

/** Canonical clustered topology root: parameters, not a 2^n record Merkle. */
export const clusteredTopologyRoot = (parameters) => hash256(concatBytes(
  CIRCLE_FRI_CLUSTERED_ROOT_DOMAIN,
  encodeCircleFriParameters(assertCircleFriParameters(parameters)),
));

const fail = (message) => {
  throw new TypeError(message);
};

const isPowerOfTwo = (value) => (
  Number.isSafeInteger(value)
  && value > 0
  && (value & (value - 1)) === 0
);

const equalParameters = (left, right) => equalBytes(
  encodeCircleFriParameters(left),
  encodeCircleFriParameters(right),
);

export const circleFriTopologyRecordBytes = (parameters) => (
  CIRCLE_FRI_TOPOLOGY_RECORD_MAGIC.length
  + 1
  + encodeCircleFriParameters(parameters).length
  + 4
  + parameters.logDegreeBound * CIRCLE_FRI_TOPOLOGY_ROUND_BYTES
);

/** Clustered q2 unlocking ships only the round-0 plan; later left/right are N-1-P. */
export const circleFriCodecTopologyRecordBytes = (parameters) => {
  const normalized = assertCircleFriParameters(parameters);
  return normalized.logDegreeBound >= 8
    ? CIRCLE_FRI_TOPOLOGY_RECORD_MAGIC.length
      + 1
      + encodeCircleFriParameters(normalized).length
      + 4
      + CIRCLE_FRI_TOPOLOGY_ROUND_BYTES
    : circleFriTopologyRecordBytes(normalized);
};

export const encodeCircleFriTopologyRecord = ({ parameters, queryIndex, rounds }) => {
  const normalized = assertCircleFriParameters(parameters);
  if (!Number.isSafeInteger(queryIndex) || queryIndex < 0 || queryIndex >= normalized.domainLength) {
    fail('topology queryIndex is out of range');
  }
  if (!Array.isArray(rounds) || rounds.length !== normalized.logDegreeBound) {
    fail('topology record has the wrong round count');
  }
  const encodedRounds = rounds.map((round, ordinal) => {
    const expectedKeys = ['round', 'currentIndex', 'leftIndex', 'rightIndex', 'nextIndex', 'coordinate', 'continuitySide'];
    if (round === null || typeof round !== 'object' || Object.keys(round).sort().join(',') !== expectedKeys.sort().join(',')) {
      fail(`topology round ${ordinal} has invalid fields`);
    }
    if (round.round !== ordinal) fail(`topology round ${ordinal} has the wrong ordinal`);
    for (const name of ['currentIndex', 'leftIndex', 'rightIndex', 'nextIndex']) {
      if (!Number.isSafeInteger(round[name]) || round[name] < 0 || round[name] > 0xffff_ffff) {
        fail(`topology round ${ordinal} ${name} is out of range`);
      }
    }
    if (![0, 1, 2].includes(round.continuitySide)) {
      fail(`topology round ${ordinal} continuitySide is invalid`);
    }
    return concatBytes(
      u32le(round.currentIndex),
      u32le(round.leftIndex),
      u32le(round.rightIndex),
      u32le(round.nextIndex),
      encodeM31(round.coordinate),
      Uint8Array.of(round.continuitySide),
    );
  });
  return concatBytes(
    CIRCLE_FRI_TOPOLOGY_RECORD_MAGIC,
    Uint8Array.of(CIRCLE_FRI_TOPOLOGY_RECORD_VERSION),
    encodeCircleFriParameters(normalized),
    u32le(queryIndex),
    ...encodedRounds,
  );
};

export const decodeCircleFriTopologyRecord = (bytes) => {
  const input = assertBytes(bytes, 'topology record');
  const minimum = CIRCLE_FRI_TOPOLOGY_RECORD_MAGIC.length + 1 + 5 + 4;
  if (input.length < minimum || (input.length - minimum) % CIRCLE_FRI_TOPOLOGY_ROUND_BYTES !== 0) {
    fail('topology record length is invalid');
  }
  if (!equalBytes(input.subarray(0, 4), CIRCLE_FRI_TOPOLOGY_RECORD_MAGIC)) fail('topology record magic is invalid');
  if (input[4] !== CIRCLE_FRI_TOPOLOGY_RECORD_VERSION) fail('topology record version is invalid');
  const parameterBytes = input.subarray(5, 10);
  const parameters = assertCircleFriParameters({
    logDegreeBound: parameterBytes[1],
    logBlowup: parameterBytes[2],
    queryCount: parameterBytes[3] | (parameterBytes[4] << 8),
  });
  if (!equalBytes(parameterBytes, encodeCircleFriParameters(parameters))) fail('topology parameters are noncanonical');
  if (input.length !== circleFriTopologyRecordBytes(parameters)) fail('topology record round count disagrees with parameters');
  const queryIndex = readU32le(input, 10);
  if (queryIndex >= parameters.domainLength) fail('topology queryIndex is out of range');
  const rounds = [];
  let offset = 14;
  for (let round = 0; round < parameters.logDegreeBound; round += 1) {
    const continuitySide = input[offset + 20];
    if (![0, 1, 2].includes(continuitySide)) fail(`topology round ${round} continuitySide is invalid`);
    rounds.push(Object.freeze({
      round,
      currentIndex: readU32le(input, offset),
      leftIndex: readU32le(input, offset + 4),
      rightIndex: readU32le(input, offset + 8),
      nextIndex: readU32le(input, offset + 12),
      coordinate: decodeM31(input.subarray(offset + 16, offset + 20)),
      continuitySide,
    }));
    offset += CIRCLE_FRI_TOPOLOGY_ROUND_BYTES;
  }
  return Object.freeze({ parameters, queryIndex, rounds });
};

export const hashCircleFriTopologyRecord = (recordBytes) => hash256(concatBytes(
  CIRCLE_FRI_TOPOLOGY_LEAF_DOMAIN,
  assertBytes(recordBytes, 'topology record'),
));

export const buildCircleFriTopologyTable = (parameters) => {
  const normalized = assertCircleFriParameters(parameters);
  const topologies = buildCircleFriPublicTopologies(normalized);
  const records = Array.from({ length: normalized.domainLength }, (_, queryIndex) => {
    let currentIndex = queryIndex;
    const rounds = topologies.map((topology, round) => {
      const nextIndex = topology.pairByLeaf[currentIndex];
      const pair = topology.pairs[nextIndex];
      const entry = Object.freeze({
        round,
        currentIndex,
        leftIndex: pair.leftIndex,
        rightIndex: pair.rightIndex,
        nextIndex,
        coordinate: pair.coordinate,
        continuitySide: round === 0 ? 0 : (currentIndex === pair.leftIndex ? 1 : 2),
      });
      currentIndex = nextIndex;
      return entry;
    });
    return encodeCircleFriTopologyRecord({ parameters: normalized, queryIndex, rounds });
  });
  const layers = [records.map(hashCircleFriTopologyRecord)];
  while (layers.at(-1).length > 1) {
    const current = layers.at(-1);
    const parent = new Array(current.length / 2);
    for (let index = 0; index < current.length; index += 2) {
      parent[index / 2] = hashMerkleNode(current[index], current[index + 1]);
    }
    layers.push(parent);
  }
  return Object.freeze({
    parameters: normalized,
    length: records.length,
    recordBytes: records[0].length,
    records,
    layers,
    root: new Uint8Array(layers.at(-1)[0]),
  });
};

export const openCircleFriTopologyTable = (table, queryIndex) => {
  if (table === null || typeof table !== 'object' || !isPowerOfTwo(table.length) || !Array.isArray(table.layers)) {
    fail('table must be a Circle-FRI topology table');
  }
  if (!Number.isSafeInteger(queryIndex) || queryIndex < 0 || queryIndex >= table.length) {
    fail('topology queryIndex is out of range');
  }
  const siblings = [];
  let currentIndex = queryIndex;
  for (let level = 0; level < table.layers.length - 1; level += 1) {
    siblings.push(new Uint8Array(table.layers[level][currentIndex ^ 1]));
    currentIndex = Math.floor(currentIndex / 2);
  }
  return Object.freeze({
    queryIndex,
    record: new Uint8Array(table.records[queryIndex]),
    siblings,
  });
};

export const verifyCircleFriTopologyOpening = ({ root, parameters, queryIndex, record, siblings }) => {
  const expectedRoot = assertBytes(root, 'topology root');
  if (expectedRoot.length !== 32) fail('topology root must be exactly 32 bytes');
  const normalized = assertCircleFriParameters(parameters);
  if (!Number.isSafeInteger(queryIndex) || queryIndex < 0 || queryIndex >= normalized.domainLength) {
    fail('topology queryIndex is out of range');
  }
  if (!Array.isArray(siblings) || siblings.length !== normalized.logDomain) {
    fail('topology path length disagrees with the domain');
  }
  const decoded = decodeCircleFriTopologyRecord(assertBytes(record, 'topology record'));
  if (!equalParameters(decoded.parameters, normalized) || decoded.queryIndex !== queryIndex) return false;
  let current = hashCircleFriTopologyRecord(record);
  let currentIndex = queryIndex;
  for (let level = 0; level < siblings.length; level += 1) {
    const sibling = assertBytes(siblings[level], `topology siblings[${level}]`);
    if (sibling.length !== 32) fail(`topology siblings[${level}] must be exactly 32 bytes`);
    current = (currentIndex & 1) === 0
      ? hashMerkleNode(current, sibling)
      : hashMerkleNode(sibling, current);
    currentIndex = Math.floor(currentIndex / 2);
  }
  return equalBytes(current, expectedRoot);
};

import {
  M31_MODULUS,
  decodeM31,
  encodeM31,
  inverse,
  mul,
} from '../../research-lanes/bch-shielded-pool-design/p2/reference/m31.mjs';

import {
  assertBytes,
  concatBytes,
  equalBytes,
  readU32le,
  u16le,
  u32le,
  utf8,
} from './bytes.mjs';

import {
  hashCm31Leaf,
  hashM31Leaf,
  hashMerkleNode,
  verifyM31MerkleMulti,
} from './commitment.mjs';

import {
  foldPair,
} from './fold.mjs';

import {
  CIRCLE_FRI_DIMENSION_GAP_LAMBDA_LABEL,
  CIRCLE_FRI_QUERY_CANDIDATE_LABEL,
  CIRCLE_FRI_QUERY_PROOF_VERSION,
  DEFAULT_MAXIMUM_LOG_DOMAIN,
  applyAirResidualTranscript,
  assertCircleFriParameters,
  circleFriCommitsMerkleRound,
  circleFriUsesCm31Fold,
  circleFriUsesPiPairMerkle,
  encodeCircleFriDimensionGapLambda,
  encodeCircleFriParameters,
  fourToOnePartnerIndex,
  circleFriUsesFourToOne,
  verifyCircleFriQueries,
} from './query-proof.mjs';

import {
  piPairMerkleCodeword,
  piPairMerkleIndex,
} from './fold.mjs';

import {
  cm31,
  cm31Eq,
  isCm31,
} from './cm31.mjs';

import {
  CircleFriTranscript,
} from './transcript.mjs';

import {
  buildCircleFriTopologyTable,
  clusteredTopologyRoot,
  circleFriCodecTopologyRecordBytes,
  circleFriTopologyRecordBytes,
  decodeCircleFriTopologyRecord,
  hashCircleFriTopologyRecord,
  openCircleFriTopologyTable,
  verifyCircleFriTopologyOpening,
  walkCircleFriTopologyRecord,
} from './topology-table.mjs';

const QUERY_BATCH_WITNESS_MAGIC = utf8('CFBW');
export const QUERY_BATCH_WITNESS_VERSION = 6;
const QUERY_BATCH_SIZE = 2;
const SMALL_LAYER_LENGTH = 16;

/** Clustered (logDegreeBound≥8) layers with domain ≤16 send the full codeword. */
const merkleLayerCount = (parameters) => {
  if (parameters.logDegreeBound < 8) return parameters.logDegreeBound;
  const firstSmall = parameters.logDegreeBound + parameters.logBlowup - Math.log2(SMALL_LAYER_LENGTH);
  return Math.min(parameters.logDegreeBound, Math.max(1, firstSmall));
};

const fail = (message) => {
  throw new TypeError(message);
};

const assertElement = (value, name) => {
  if (typeof value !== 'bigint' || value < 0n || value >= M31_MODULUS) {
    fail(`${name} must be a canonical M31 element`);
  }
  return value;
};

const assertHash = (value, name) => {
  const bytes = assertBytes(value, name);
  if (bytes.length !== 32) fail(`${name} must be exactly 32 bytes`);
  return bytes;
};

const equalNumbers = (left, right) => (
  left.length === right.length && left.every((value, index) => value === right[index])
);

const isPowerOfTwo = (value) => (
  Number.isSafeInteger(value)
  && value > 0
  && (value & (value - 1)) === 0
);

const canonicalIndices = (indices, length, name) => {
  if (!Array.isArray(indices) || indices.length === 0) fail(`${name} must be a nonempty array`);
  const result = indices.map((index, ordinal) => {
    if (!Number.isSafeInteger(index) || index < 0 || index >= length) {
      fail(`${name}[${ordinal}] is out of range`);
    }
    return index;
  }).sort((left, right) => left - right);
  return [...new Set(result)];
};

const canonicalFrontierCount = (indices, length) => {
  if (!isPowerOfTwo(length)) fail('Merkle length must be a positive power of two');
  let current = canonicalIndices(indices, length, 'Merkle indices');
  let count = 0;
  let levelLength = length;
  while (levelLength > 1) {
    const known = new Set(current);
    for (const index of current) {
      if (!known.has(index ^ 1)) count += 1;
    }
    current = [...new Set(current.map((index) => Math.floor(index / 2)))].sort((left, right) => left - right);
    levelLength /= 2;
  }
  return count;
};

const firstFoldPairIndex = (index, domainLength) => (
  index < domainLength / 2 ? index : domainLength - 1 - index
);

const layerMerkleIndices = (roundRecords, layerLength, parameters, round) => {
  const domainIndices = roundRecords.flatMap((record) => [
    record.leftIndex,
    record.rightIndex,
  ]);
  if (!circleFriUsesPiPairMerkle(parameters, round)) {
    return canonicalIndices(domainIndices, layerLength, `layers[${round}] derived indices`);
  }
  return canonicalIndices(
    domainIndices.map((index) => piPairMerkleIndex(index, layerLength)),
    layerLength,
    `layers[${round}] pi-pair Merkle indices`,
  );
};

const assertQ2Ordinals = (queryOrdinals, queryCount, name = 'queryOrdinals') => {
  if (!Array.isArray(queryOrdinals) || queryOrdinals.length !== QUERY_BATCH_SIZE) {
    fail(`${name} must contain exactly two ordinals`);
  }
  const ordinals = queryOrdinals.map((ordinal, index) => {
    if (!Number.isSafeInteger(ordinal) || ordinal < 0 || ordinal >= queryCount) {
      fail(`${name}[${index}] is out of range`);
    }
    return ordinal;
  });
  if (ordinals[0] >= ordinals[1]) {
    fail(`${name} must be strictly increasing and unique`);
  }
  return ordinals;
};

const assertQueryIndices = (queryIndices, parameters) => {
  if (!Array.isArray(queryIndices) || queryIndices.length !== QUERY_BATCH_SIZE) {
    fail('queryIndices must contain exactly two indices');
  }
  const indices = queryIndices.map((index, ordinal) => {
    if (!Number.isSafeInteger(index) || index < 0 || index >= parameters.domainLength) {
      fail(`queryIndices[${ordinal}] is out of range`);
    }
    return index;
  });
  if (indices[0] === indices[1]) fail('q2 query indices must be distinct');
  if (firstFoldPairIndex(indices[0], parameters.domainLength)
      === firstFoldPairIndex(indices[1], parameters.domainLength)) {
    fail('q2 queries must occupy distinct first-fold pairs');
  }
  return indices;
};

const encodeFelt = (value, name) => (
  isCm31(value)
    ? concatBytes(encodeM31(value.re), encodeM31(value.im))
    : encodeM31(assertElement(value, name))
);

const decodeFelt = (bytes, name, cm31Valued) => {
  if (cm31Valued) {
    if (bytes.length !== 8) fail(`${name} CM31 encoding must be 8 bytes`);
    return cm31(decodeM31(bytes.subarray(0, 4)), decodeM31(bytes.subarray(4, 8)));
  }
  return decodeM31(bytes);
};

const encodeM31Vector = (values, name) => concatBytes(...values.map(
  (value, index) => encodeFelt(value, `${name}[${index}]`),
));

const setNode = (nodes, level, index, hash, name) => {
  const bytes = assertHash(hash, name);
  const key = `${level}:${index}`;
  const existing = nodes.get(key);
  if (existing !== undefined && !equalBytes(existing, bytes)) {
    fail(`full Merkle paths disagree at node ${key}`);
  }
  if (existing === undefined) nodes.set(key, new Uint8Array(bytes));
};

/** Merge already-authenticated full paths into their unique minimal frontier. */
const mergeFullMerklePaths = ({ root, length, entries, name }) => {
  const expectedRoot = assertHash(root, `${name} root`);
  if (!isPowerOfTwo(length)) fail(`${name} length must be a positive power of two`);
  if (!Array.isArray(entries) || entries.length === 0) fail(`${name} paths must be nonempty`);
  const depth = Math.log2(length);
  const nodes = new Map();
  const openedIndices = [];

  for (let ordinal = 0; ordinal < entries.length; ordinal += 1) {
    const entry = entries[ordinal];
    if (entry === null || typeof entry !== 'object') fail(`${name} paths[${ordinal}] must be an object`);
    if (!Number.isSafeInteger(entry.index) || entry.index < 0 || entry.index >= length) {
      fail(`${name} paths[${ordinal}].index is out of range`);
    }
    if (!Array.isArray(entry.siblings) || entry.siblings.length !== depth) {
      fail(`${name} paths[${ordinal}] has the wrong full-path length`);
    }
    openedIndices.push(entry.index);
    let current = assertHash(entry.leafHash, `${name} paths[${ordinal}].leafHash`);
    let currentIndex = entry.index;
    setNode(nodes, 0, currentIndex, current, `${name} paths[${ordinal}].leafHash`);
    for (let level = 0; level < depth; level += 1) {
      const sibling = assertHash(entry.siblings[level], `${name} paths[${ordinal}].siblings[${level}]`);
      setNode(nodes, level, currentIndex ^ 1, sibling, `${name} paths[${ordinal}].siblings[${level}]`);
      current = (currentIndex & 1) === 0
        ? hashMerkleNode(current, sibling)
        : hashMerkleNode(sibling, current);
      currentIndex = Math.floor(currentIndex / 2);
      setNode(nodes, level + 1, currentIndex, current, `${name} paths[${ordinal}] parent`);
    }
    if (!equalBytes(current, expectedRoot)) fail(`${name} paths[${ordinal}] does not authenticate its root`);
  }

  const indices = canonicalIndices(openedIndices, length, `${name} indices`);
  const siblings = [];
  let current = indices;
  for (let level = 0; level < depth; level += 1) {
    const known = new Set(current);
    for (const index of current) {
      const siblingIndex = index ^ 1;
      if (!known.has(siblingIndex)) {
        const sibling = nodes.get(`${level}:${siblingIndex}`);
        if (sibling === undefined) fail(`${name} full paths do not cover the canonical frontier`);
        siblings.push(new Uint8Array(sibling));
      }
    }
    current = [...new Set(current.map((index) => Math.floor(index / 2)))].sort((left, right) => left - right);
  }
  if (siblings.length !== canonicalFrontierCount(indices, length)) {
    throw new Error(`internal ${name} frontier count mismatch`);
  }
  return Object.freeze({
    indices: Object.freeze(indices),
    siblings: Object.freeze(siblings),
  });
};

const verifyHashedMerkleMulti = ({ root, length, indices, leafHashes, siblings, name }) => {
  const expectedRoot = assertHash(root, `${name} root`);
  if (!isPowerOfTwo(length)) fail(`${name} length must be a positive power of two`);
  const canonical = canonicalIndices(indices, length, `${name} indices`);
  if (!equalNumbers(indices, canonical)) fail(`${name} indices must be strictly increasing and unique`);
  if (!Array.isArray(leafHashes) || leafHashes.length !== canonical.length) {
    fail(`${name} leaf hashes must match the index count`);
  }
  if (!Array.isArray(siblings)) fail(`${name} siblings must be an array`);
  if (siblings.length !== canonicalFrontierCount(canonical, length)) {
    fail(`${name} frontier count is noncanonical`);
  }
  const frontier = siblings.map((hash, index) => assertHash(hash, `${name} siblings[${index}]`));
  let current = new Map(canonical.map((index, ordinal) => [
    index,
    assertHash(leafHashes[ordinal], `${name} leafHashes[${ordinal}]`),
  ]));
  let siblingCursor = 0;
  let levelLength = length;
  while (levelLength > 1) {
    const parents = new Map();
    for (const index of [...current.keys()].sort((left, right) => left - right)) {
      const parentIndex = Math.floor(index / 2);
      if (parents.has(parentIndex)) continue;
      const leftIndex = parentIndex * 2;
      const rightIndex = leftIndex + 1;
      const left = current.get(leftIndex) ?? frontier[siblingCursor++];
      const right = current.get(rightIndex) ?? frontier[siblingCursor++];
      if (left === undefined || right === undefined) fail(`${name} frontier is truncated`);
      parents.set(parentIndex, hashMerkleNode(left, right));
    }
    current = parents;
    levelLength /= 2;
  }
  if (siblingCursor !== frontier.length) fail(`${name} frontier has unused hashes`);
  return equalBytes(current.get(0), expectedRoot);
};

const derivePublicTranscript = ({
  roots,
  finalCodeword,
  parameters,
  protocolContext,
  airResidualQ = null,
  airLdeRoot = null,
}) => {
  const transcript = new CircleFriTranscript(assertBytes(protocolContext, 'protocolContext'));
  transcript.absorb('fri-parameters', encodeCircleFriParameters(parameters));
  transcript.absorb(CIRCLE_FRI_DIMENSION_GAP_LAMBDA_LABEL, encodeCircleFriDimensionGapLambda());
  applyAirResidualTranscript(transcript, airResidualQ, airLdeRoot);
  const betas = roots.map((root, round) => {
    transcript.absorb(`fri-layer-root-${round}`, root);
    return circleFriUsesCm31Fold(parameters)
      ? transcript.challengeCm31(`fri-fold-beta-${round}`)
      : transcript.challengeField(`fri-fold-beta-${round}`);
  });
  transcript.absorb('fri-final-codeword', encodeM31Vector(finalCodeword, 'finalCodeword'));
  const queryIndices = [];
  const seenFirstFoldPairs = new Set();
  for (let query = 0; query < parameters.queryCount; query += 1) {
    if (query % 2 === 1 && circleFriUsesFourToOne(parameters)) {
      const partner = fourToOnePartnerIndex(
        firstFoldPairIndex(queryIndices[query - 1], parameters.domainLength),
        parameters.domainLength,
      );
      const pairIndex = firstFoldPairIndex(partner, parameters.domainLength);
      if (seenFirstFoldPairs.has(pairIndex)) fail('4-to-1 partner collides with an earlier J-pair');
      seenFirstFoldPairs.add(pairIndex);
      queryIndices.push(partner);
      continue;
    }
    const index = transcript.challengeIndex(CIRCLE_FRI_QUERY_CANDIDATE_LABEL, parameters.domainLength);
    const pairIndex = firstFoldPairIndex(index, parameters.domainLength);
    if (seenFirstFoldPairs.has(pairIndex)) fail('query first-fold pair collided');
    seenFirstFoldPairs.add(pairIndex);
    queryIndices.push(index);
  }
  return Object.freeze({ betas: Object.freeze(betas), queryIndices: Object.freeze(queryIndices) });
};

const decodeAndCheckTopologyRecords = ({ records, parameters, queryIndices }) => {
  if (!Array.isArray(records) || records.length !== QUERY_BATCH_SIZE) {
    fail('topology records must contain exactly two records');
  }
  const expectedIndices = [...queryIndices].sort((left, right) => left - right);
  const recordLength = circleFriTopologyRecordBytes(parameters);
  const decoded = records.map((record, ordinal) => {
    const bytes = assertBytes(record, `topology.records[${ordinal}]`);
    if (bytes.length !== recordLength) fail(`topology.records[${ordinal}] has the wrong length`);
    const item = decodeCircleFriTopologyRecord(bytes);
    for (const field of ['logDegreeBound', 'logBlowup', 'queryCount']) {
      if (item.parameters[field] !== parameters[field]) {
        fail(`topology.records[${ordinal}] ${field} disagrees with the witness`);
      }
    }
    if (item.queryIndex !== expectedIndices[ordinal]) {
      fail('topology records are not in canonical query-index order');
    }
    return item;
  });
  const byQueryIndex = new Map(decoded.map((record) => [record.queryIndex, record]));
  return Object.freeze({
    decoded: Object.freeze(decoded),
    byOrdinal: Object.freeze(queryIndices.map((index) => byQueryIndex.get(index))),
    expectedIndices: Object.freeze(expectedIndices),
  });
};

const assertWitnessShape = (witness, maximumLogDomain = DEFAULT_MAXIMUM_LOG_DOMAIN) => {
  if (witness === null || typeof witness !== 'object') fail('q2 witness must be an object');
  if (witness.version !== QUERY_BATCH_WITNESS_VERSION) fail('unsupported q2 witness version');
  if (witness.proofVersion !== CIRCLE_FRI_QUERY_PROOF_VERSION) fail('q2 witness must bind Circle-FRI query proof v3');
  const parameters = assertCircleFriParameters({
    logDegreeBound: witness.logDegreeBound,
    logBlowup: witness.logBlowup,
    queryCount: witness.queryCount,
    fourToOneClustering: witness.fourToOneClustering,
    maximumLogDomain,
  });
  const queryOrdinals = assertQ2Ordinals(witness.queryOrdinals, parameters.queryCount);
  const queryIndices = assertQueryIndices(witness.queryIndices, parameters);

  if (!Array.isArray(witness.roots) || witness.roots.length !== parameters.logDegreeBound) {
    fail('q2 witness root count must equal logDegreeBound');
  }
  witness.roots.forEach((root, round) => assertHash(root, `roots[${round}]`));
  if (!Array.isArray(witness.finalCodeword) || witness.finalCodeword.length !== parameters.blowup) {
    fail('q2 witness finalCodeword length must equal blowup');
  }
  const cm31Final = circleFriUsesCm31Fold(parameters);
  witness.finalCodeword.forEach((value, index) => {
    if (cm31Final) {
      if (!isCm31(value)) fail(`finalCodeword[${index}] must be CM31`);
    } else {
      assertElement(value, `finalCodeword[${index}]`);
    }
  });

  if (witness.topology === null || typeof witness.topology !== 'object') fail('q2 witness topology is required');
  assertHash(witness.topology.root, 'topology.root');
  const recordPlan = decodeAndCheckTopologyRecords({
    records: witness.topology.records,
    parameters,
    queryIndices,
  });
  if (!Array.isArray(witness.topology.indices)
      || !equalNumbers(witness.topology.indices, recordPlan.expectedIndices)) {
    fail('topology indices are not the canonical sorted query indices');
  }
  if (!Array.isArray(witness.topology.siblings)) fail('topology siblings must be an array');
  const topologyFrontierCount = canonicalFrontierCount(recordPlan.expectedIndices, parameters.domainLength);
  if (witness.topology.siblings.length !== 0
      && witness.topology.siblings.length !== topologyFrontierCount) {
    fail('topology frontier count is noncanonical');
  }
  witness.topology.siblings.forEach((hash, index) => assertHash(hash, `topology.siblings[${index}]`));

  if (!Array.isArray(witness.layers) || witness.layers.length !== parameters.logDegreeBound) {
    fail('q2 witness layer count must equal logDegreeBound');
  }
  const layerPlans = witness.layers.map((layer, round) => {
    if (layer === null || typeof layer !== 'object') fail(`layers[${round}] must be an object`);
    const layerLength = parameters.domainLength / (2 ** round);
    const roundRecords = recordPlan.byOrdinal.map((record) => record.rounds[round]);
    const queriedIndices = layerMerkleIndices(roundRecords, layerLength, parameters, round);
    const fullLayer = Array.isArray(layer.siblings) && layer.siblings.length === 0
      && Array.isArray(layer.values) && layer.values.length === layerLength
      && Array.isArray(layer.indices)
      && layer.indices.length === layerLength
      && layer.indices.every((index, ordinal) => index === ordinal);
    const indices = fullLayer ? layer.indices : queriedIndices;
    if (!fullLayer) {
      if (!Array.isArray(layer.indices) || !equalNumbers(layer.indices, queriedIndices)) {
        fail(`layers[${round}] indices are not canonical for the authenticated topology`);
      }
      if (!Array.isArray(layer.values) || layer.values.length !== indices.length) {
        fail(`layers[${round}] value count is noncanonical`);
      }
    }
    layer.values.forEach((value, index) => {
      if (circleFriUsesCm31Fold(parameters) && round > 0) {
        if (!isCm31(value)) fail(`layers[${round}].values[${index}] must be CM31`);
      } else {
        assertElement(value, `layers[${round}].values[${index}]`);
      }
    });
    if (!Array.isArray(layer.inverseTwoCoordinates)
        || layer.inverseTwoCoordinates.length !== QUERY_BATCH_SIZE) {
      fail(`layers[${round}] must contain two inverse-coordinate hints`);
    }
    layer.inverseTwoCoordinates.forEach((value, index) => (
      assertElement(value, `layers[${round}].inverseTwoCoordinates[${index}]`)
    ));
    if (!Array.isArray(layer.siblings)) fail(`layers[${round}].siblings must be an array`);
    const skipMerkle = !fullLayer && !circleFriCommitsMerkleRound(parameters, round);
    const frontierCount = (fullLayer || skipMerkle) ? 0 : canonicalFrontierCount(indices, layerLength);
    if (layer.siblings.length !== frontierCount) {
      fail(`layers[${round}] frontier count is noncanonical`);
    }
    layer.siblings.forEach((hash, index) => assertHash(hash, `layers[${round}].siblings[${index}]`));
    return Object.freeze({
      layerLength,
      indices: Object.freeze(indices),
      roundRecords: Object.freeze(roundRecords),
      fullLayer,
    });
  });

  return Object.freeze({
    ...parameters,
    queryOrdinals: Object.freeze(queryOrdinals),
    queryIndices: Object.freeze(queryIndices),
    topology: recordPlan,
    layerPlans: Object.freeze(layerPlans),
  });
};

const freezeWitness = (witness) => Object.freeze({
  version: witness.version,
  proofVersion: witness.proofVersion,
  logDegreeBound: witness.logDegreeBound,
  logBlowup: witness.logBlowup,
  queryCount: witness.queryCount,
  fourToOneClustering: witness.fourToOneClustering !== false,
  queryOrdinals: Object.freeze([...witness.queryOrdinals]),
  queryIndices: Object.freeze([...witness.queryIndices]),
  roots: Object.freeze(witness.roots.map((root) => new Uint8Array(root))),
  finalCodeword: Object.freeze([...witness.finalCodeword]),
  topology: Object.freeze({
    root: new Uint8Array(witness.topology.root),
    indices: Object.freeze([...witness.topology.indices]),
    records: Object.freeze(witness.topology.records.map((record) => new Uint8Array(record))),
    siblings: Object.freeze(witness.topology.siblings.map((hash) => new Uint8Array(hash))),
  }),
  layers: Object.freeze(witness.layers.map((layer) => Object.freeze({
    indices: Object.freeze([...layer.indices]),
    values: Object.freeze([...layer.values]),
    inverseTwoCoordinates: Object.freeze([...layer.inverseTwoCoordinates]),
    siblings: Object.freeze(layer.siblings.map((hash) => new Uint8Array(hash))),
  }))),
});

const verifyQ2WitnessOrThrow = ({
  witness,
  expected,
  protocolContext = new Uint8Array(),
  queryOrdinals,
  maximumLogDomain = DEFAULT_MAXIMUM_LOG_DOMAIN,
  airResidualQ = null,
  airLdeRoot = null,
}) => {
  const parameters = assertWitnessShape(witness, maximumLogDomain);
  if (expected === null || typeof expected !== 'object') fail('expected parameters are required');
  const expectedParameters = assertCircleFriParameters({ ...expected, maximumLogDomain });
  for (const field of ['logDegreeBound', 'logBlowup', 'queryCount']) {
    if (parameters[field] !== expectedParameters[field]) fail(`q2 witness ${field} does not match expected parameters`);
  }
  const expectedOrdinals = assertQ2Ordinals(queryOrdinals, parameters.queryCount, 'expected queryOrdinals');
  if (!equalNumbers(parameters.queryOrdinals, expectedOrdinals)) {
    fail('q2 witness query ordinals do not match the expected batch');
  }

  const finalValue = witness.finalCodeword[0];
  const sameFinal = isCm31(finalValue)
    ? (value) => cm31Eq(value, finalValue)
    : (value) => value === finalValue;
  if (!witness.finalCodeword.every(sameFinal)) {
    fail('q2 witness final codeword is not constant');
  }
  const transcript = derivePublicTranscript({
    roots: witness.roots,
    finalCodeword: witness.finalCodeword,
    parameters,
    protocolContext,
    airResidualQ,
    airLdeRoot,
  });
  const scheduledIndices = expectedOrdinals.map((ordinal) => transcript.queryIndices[ordinal]);
  if (!equalNumbers(witness.queryIndices, scheduledIndices)) {
    fail('q2 witness query indices do not match the public v3 transcript schedule');
  }

  const clustered = parameters.logDegreeBound >= 8;
  const topologyTable = clustered ? null : buildCircleFriTopologyTable(parameters);
  const expectedRoot = clustered ? clusteredTopologyRoot(parameters) : topologyTable.root;
  if (!equalBytes(witness.topology.root, expectedRoot)) fail('q2 witness topology root is not canonical');
  for (let ordinal = 0; ordinal < witness.topology.indices.length; ordinal += 1) {
    const index = witness.topology.indices[ordinal];
    const canonical = clustered
      ? walkCircleFriTopologyRecord(parameters, index)
      : topologyTable.records[index];
    if (!equalBytes(witness.topology.records[ordinal], canonical)) {
      fail(`q2 witness topology record ${ordinal} is not canonical`);
    }
  }
  if (witness.topology.siblings.length > 0
      && !verifyHashedMerkleMulti({
        root: witness.topology.root,
        length: parameters.domainLength,
        indices: witness.topology.indices,
        leafHashes: witness.topology.records.map(hashCircleFriTopologyRecord),
        siblings: witness.topology.siblings,
        name: 'topology multiproof',
      })) fail('q2 witness topology multiproof failed');

  const previousFolds = new Array(QUERY_BATCH_SIZE);
  for (let round = 0; round < parameters.logDegreeBound; round += 1) {
    const layer = witness.layers[round];
    const plan = parameters.layerPlans[round];
    if (circleFriCommitsMerkleRound(parameters, round)) {
      if (!verifyM31MerkleMulti({
        root: witness.roots[round],
        length: plan.layerLength,
        indices: layer.indices,
        values: layer.values,
        siblings: layer.siblings,
      })) fail(`q2 witness round ${round} Merkle multiproof failed`);
    } else if (layer.siblings.length !== 0) {
      fail(`q2 witness round ${round} skip-layer must not carry siblings`);
    }
    const valueByIndex = new Map(layer.indices.map((index, ordinal) => [index, layer.values[ordinal]]));
    const usesPiMerkle = circleFriUsesPiPairMerkle(parameters, round);
    const merkleOf = (domainIndex) => (
      usesPiMerkle ? piPairMerkleIndex(domainIndex, plan.layerLength) : domainIndex
    );
    for (let query = 0; query < QUERY_BATCH_SIZE; query += 1) {
      const record = plan.roundRecords[query];
      const expectedInverse = inverse(mul(2n, record.coordinate));
      if (layer.inverseTwoCoordinates[query] !== expectedInverse) {
        fail(`q2 witness query ${query} round ${round} inverse-coordinate hint failed`);
      }
      if (previousFolds[query] !== undefined
          && !(isCm31(previousFolds[query])
            ? cm31Eq(previousFolds[query], valueByIndex.get(merkleOf(record.currentIndex)))
            : previousFolds[query] === valueByIndex.get(merkleOf(record.currentIndex)))) {
        fail(`q2 witness query ${query} round ${round} fold continuity failed`);
      }
      previousFolds[query] = foldPair({
        positive: valueByIndex.get(merkleOf(record.leftIndex)),
        negative: valueByIndex.get(merkleOf(record.rightIndex)),
        coordinate: record.coordinate,
        beta: transcript.betas[round],
      }).value;
    }
  }
  for (let query = 0; query < QUERY_BATCH_SIZE; query += 1) {
    const finalIndex = parameters.topology.byOrdinal[query].rounds.at(-1).nextIndex;
    const finalFelt = witness.finalCodeword[finalIndex];
    if (!(isCm31(previousFolds[query])
      ? cm31Eq(previousFolds[query], finalFelt)
      : previousFolds[query] === finalFelt)) {
      fail(`q2 witness query ${query} final low-degree check failed`);
    }
  }
  return Object.freeze({
    ok: true,
    queryOrdinals: Object.freeze([...expectedOrdinals]),
    queryIndices: Object.freeze([...scheduledIndices]),
    betas: Object.freeze([...transcript.betas]),
  });
};

/** Package one exact pair of already-verified public v3 query paths. */
export const createCircleFriQ2BatchWitness = ({
  proof,
  expected,
  protocolContext = new Uint8Array(),
  queryOrdinals,
  maximumLogDomain = DEFAULT_MAXIMUM_LOG_DOMAIN,
  airResidualQ = null,
  airLdeRoot = null,
}) => {
  const sourceVerdict = verifyCircleFriQueries({
    proof,
    expected,
    protocolContext,
    maximumLogDomain,
    airResidualQ,
    airLdeRoot,
  });
  if (!sourceVerdict.ok) fail(`source Circle-FRI proof is invalid: ${sourceVerdict.reason ?? 'invalid'}`);
  const parameters = assertCircleFriParameters({ ...expected, maximumLogDomain });
  const ordinals = assertQ2Ordinals(queryOrdinals, parameters.queryCount);
  const queryIndices = ordinals.map((ordinal) => sourceVerdict.queryIndices[ordinal]);
  assertQueryIndices(queryIndices, parameters);

  const clustered = parameters.logDegreeBound >= 8;
  const sortedIndices = [...queryIndices].sort((left, right) => left - right);
  const topologyRecords = clustered
    ? sortedIndices.map((queryIndex) => walkCircleFriTopologyRecord(parameters, queryIndex))
    : null;
  const topologyTable = clustered ? null : buildCircleFriTopologyTable(parameters);
  const topologyOpenings = clustered
    ? queryIndices.map((queryIndex) => Object.freeze({
      queryIndex,
      record: walkCircleFriTopologyRecord(parameters, queryIndex),
      siblings: Object.freeze([]),
    }))
    : queryIndices.map((queryIndex) => {
      const opening = openCircleFriTopologyTable(topologyTable, queryIndex);
      if (!verifyCircleFriTopologyOpening({
        root: topologyTable.root,
        parameters,
        queryIndex,
        record: opening.record,
        siblings: opening.siblings,
      })) fail(`source topology path ${queryIndex} is invalid`);
      return opening;
    });
  const topologyFrontier = clustered
    ? Object.freeze({
      indices: Object.freeze(sortedIndices),
      siblings: Object.freeze([]),
    })
    : mergeFullMerklePaths({
      root: topologyTable.root,
      length: topologyTable.length,
      entries: topologyOpenings.map((opening) => ({
        index: opening.queryIndex,
        leafHash: hashCircleFriTopologyRecord(opening.record),
        siblings: opening.siblings,
      })),
      name: 'topology',
    });
  const packedTopologyRecords = clustered
    ? topologyRecords
    : topologyFrontier.indices.map((index) => (
      new Uint8Array(topologyOpenings.find((opening) => opening.queryIndex === index).record)
    ));
  const topologyByOrdinal = topologyOpenings.map((opening) => decodeCircleFriTopologyRecord(opening.record));

  const layers = Array.from({ length: parameters.logDegreeBound }, (_, round) => {
    const layerLength = parameters.domainLength / (2 ** round);
    const inverseTwoCoordinates = Object.freeze(topologyByOrdinal.map((record) => (
      inverse(mul(2n, record.rounds[round].coordinate))
    )));
    if (round >= merkleLayerCount(parameters)) {
      const codeword = proof.smallLayerCodewords?.[round];
      if (!Array.isArray(codeword) || codeword.length !== layerLength) {
        fail(`source proof is missing the length-${layerLength} codeword at round ${round}`);
      }
      const merkleValues = circleFriUsesPiPairMerkle(parameters, round)
        ? piPairMerkleCodeword(codeword)
        : codeword;
      return Object.freeze({
        indices: Object.freeze(Array.from({ length: layerLength }, (_, index) => index)),
        values: Object.freeze(merkleValues.map((value, index) => (
          isCm31(value) ? value : assertElement(value, `smallLayerCodewords[${round}][${index}]`)
        ))),
        inverseTwoCoordinates,
        siblings: Object.freeze([]),
      });
    }
    const skipMerkle = !circleFriCommitsMerkleRound(parameters, round);
    const valuesByIndex = new Map();
    const entries = [];
    const addOpening = (index, value, siblings, name) => {
      const canonicalValue = isCm31(value) ? value : assertElement(value, `${name} value`);
      const existing = valuesByIndex.get(index);
      if (existing !== undefined && !(isCm31(existing)
        ? cm31Eq(existing, canonicalValue)
        : existing === canonicalValue)) {
        fail(`source query paths disagree on round ${round} leaf ${index}`);
      }
      valuesByIndex.set(index, canonicalValue);
      entries.push(Object.freeze({
        index,
        leafHash: isCm31(canonicalValue) ? hashCm31Leaf(canonicalValue) : hashM31Leaf(canonicalValue),
        siblings,
      }));
    };
    const usesPiMerkle = circleFriUsesPiPairMerkle(parameters, round);
    for (let query = 0; query < QUERY_BATCH_SIZE; query += 1) {
      const topologyRound = topologyByOrdinal[query].rounds[round];
      const sourceOpening = proof.queries[ordinals[query]].layers[round];
      addOpening(
        usesPiMerkle
          ? piPairMerkleIndex(topologyRound.leftIndex, layerLength)
          : topologyRound.leftIndex,
        sourceOpening.leftValue,
        sourceOpening.leftSiblings,
        `query ${ordinals[query]} round ${round} left`,
      );
      addOpening(
        usesPiMerkle
          ? piPairMerkleIndex(topologyRound.rightIndex, layerLength)
          : topologyRound.rightIndex,
        sourceOpening.rightValue,
        sourceOpening.rightSiblings,
        `query ${ordinals[query]} round ${round} right`,
      );
    }
    const frontier = mergeFullMerklePaths({
      root: proof.roots[round],
      length: layerLength,
      entries,
      name: `FRI round ${round}`,
    });
    return Object.freeze({
      indices: frontier.indices,
      values: Object.freeze(frontier.indices.map((index) => valuesByIndex.get(index))),
      inverseTwoCoordinates,
      siblings: skipMerkle ? Object.freeze([]) : frontier.siblings,
    });
  });

  const witness = freezeWitness({
    version: QUERY_BATCH_WITNESS_VERSION,
    proofVersion: CIRCLE_FRI_QUERY_PROOF_VERSION,
    logDegreeBound: parameters.logDegreeBound,
    logBlowup: parameters.logBlowup,
    queryCount: parameters.queryCount,
    fourToOneClustering: parameters.fourToOneClustering,
    queryOrdinals: ordinals,
    queryIndices,
    roots: proof.roots,
    finalCodeword: proof.finalCodeword,
    topology: {
      root: clustered ? clusteredTopologyRoot(parameters) : topologyTable.root,
      indices: topologyFrontier.indices,
      records: packedTopologyRecords,
      siblings: topologyFrontier.siblings,
    },
    layers,
  });
  const packagedVerdict = verifyQ2WitnessOrThrow({
    witness,
    expected,
    protocolContext,
    queryOrdinals: ordinals,
    maximumLogDomain,
    airResidualQ,
    airLdeRoot,
  });
  if (!packagedVerdict.ok) throw new Error('internal q2 witness verification failed');
  return witness;
};

/** Fail-closed verifier for one self-contained q2 BCH witness package. */
export const verifyCircleFriQ2BatchWitness = (input) => {
  try {
    return verifyQ2WitnessOrThrow(input);
  } catch (error) {
    return Object.freeze({ ok: false, reason: error instanceof Error ? error.message : String(error) });
  }
};

/** Encode the exact operand package consumed by the forthcoming q2 BCH kernel. */
export const encodeCircleFriQ2BatchWitness = (
  witness,
  { maximumLogDomain = DEFAULT_MAXIMUM_LOG_DOMAIN } = {},
) => {
  const parameters = assertWitnessShape(witness, maximumLogDomain);
  const chunks = [
    QUERY_BATCH_WITNESS_MAGIC,
    Uint8Array.of(QUERY_BATCH_WITNESS_VERSION),
    encodeCircleFriParameters(parameters),
    u16le(witness.queryOrdinals[0]),
    u16le(witness.queryOrdinals[1]),
    u32le(witness.queryIndices[0]),
    u32le(witness.queryIndices[1]),
    encodeM31Vector(witness.finalCodeword, 'finalCodeword'),
  ];
  if (parameters.logDegreeBound < 8) {
    chunks.push(
      ...witness.topology.records.map((record) => record.subarray(0, circleFriCodecTopologyRecordBytes(parameters))),
    );
  }
  const firstSmall = merkleLayerCount(parameters);
  for (let round = 0; round < witness.layers.length; round += 1) {
    const layer = witness.layers[round];
    const layerLength = parameters.domainLength / (2 ** round);
    if (round > firstSmall && layer.siblings.length === 0 && layer.values.length === layerLength) {
      const records = witness.topology.records.map((record) => decodeCircleFriTopologyRecord(record));
      const queried = layerMerkleIndices(
        records.map((record) => record.rounds[round]),
        layerLength,
        parameters,
        round,
      );
      if (queried.length === 2 && parameters.logDegreeBound >= 8) {
        chunks.push(
          u16le(0),
          encodeM31Vector(layer.inverseTwoCoordinates, `layers[${round}].inverseTwoCoordinates`),
          encodeM31Vector(queried.map((index) => layer.values[index]), `layers[${round}].values`),
        );
      } else {
        chunks.push(
          u16le(queried.length),
          u16le(0),
          encodeM31Vector(layer.inverseTwoCoordinates, `layers[${round}].inverseTwoCoordinates`),
          encodeM31Vector(queried.map((index) => layer.values[index]), `layers[${round}].values`),
        );
      }
      continue;
    }
    if (
      parameters.logDegreeBound >= 8
      && round > 0
      && layer.values.length === 2
      && layerLength !== SMALL_LAYER_LENGTH
    ) {
      chunks.push(
        u16le(layer.siblings.length),
        encodeM31Vector(layer.inverseTwoCoordinates, `layers[${round}].inverseTwoCoordinates`),
        encodeM31Vector(layer.values, `layers[${round}].values`),
        ...layer.siblings,
      );
      continue;
    }
    chunks.push(
      u16le(layer.values.length),
      u16le(layer.siblings.length),
      encodeM31Vector(layer.inverseTwoCoordinates, `layers[${round}].inverseTwoCoordinates`),
      encodeM31Vector(layer.values, `layers[${round}].values`),
      ...layer.siblings,
    );
  }
  return concatBytes(...chunks);
};

/** Decode one exact q2 operand package with bounded, canonical count parsing. */
export const decodeCircleFriQ2BatchWitness = (
  encoded,
  { maximumLogDomain = DEFAULT_MAXIMUM_LOG_DOMAIN } = {},
) => {
  const bytes = assertBytes(encoded, 'encoded q2 witness');
  let offset = 0;
  const read = (length, name) => {
    if (!Number.isSafeInteger(length) || length < 0 || offset + length > bytes.length) fail(`${name} is truncated`);
    const result = bytes.slice(offset, offset + length);
    offset += length;
    return result;
  };
  const readU16 = (name) => {
    const value = read(2, name);
    return value[0] + value[1] * 0x100;
  };
  const readU32 = (name) => readU32le(read(4, name));

  if (!equalBytes(read(4, 'q2 witness magic'), QUERY_BATCH_WITNESS_MAGIC)) {
    fail('invalid q2 witness magic');
  }
  const version = read(1, 'q2 witness version')[0];
  if (version !== QUERY_BATCH_WITNESS_VERSION) fail('unsupported q2 witness version');
  const parameterBytes = read(5, 'q2 witness parameters');
  const proofVersion = parameterBytes[0];
  if (proofVersion !== CIRCLE_FRI_QUERY_PROOF_VERSION) fail('q2 witness must bind Circle-FRI query proof v3');
  const parameters = assertCircleFriParameters({
    logDegreeBound: parameterBytes[1],
    logBlowup: parameterBytes[2],
    queryCount: parameterBytes[3] + parameterBytes[4] * 0x100,
    maximumLogDomain,
  });
  if (!equalBytes(parameterBytes, encodeCircleFriParameters(parameters))) fail('q2 witness parameters are noncanonical');
  const queryOrdinals = [readU16('queryOrdinals[0]'), readU16('queryOrdinals[1]')];
  assertQ2Ordinals(queryOrdinals, parameters.queryCount);
  const queryIndices = [readU32('queryIndices[0]'), readU32('queryIndices[1]')];
  assertQueryIndices(queryIndices, parameters);
  const roots = Array.from({ length: parameters.logDegreeBound }, () => new Uint8Array(32));
  const cm31Valued = circleFriUsesCm31Fold(parameters);
  const finalFeltBytes = cm31Valued ? 8 : 4;
  const finalCodeword = Array.from({ length: parameters.blowup }, (_, index) => (
    decodeFelt(read(finalFeltBytes, `finalCodeword[${index}]`), `finalCodeword[${index}]`, cm31Valued)
  ));
  const topologyTable = parameters.logDegreeBound >= 8 ? null : buildCircleFriTopologyTable(parameters);
  const topologyRecords = parameters.logDegreeBound >= 8
    ? [...queryIndices].sort((left, right) => left - right).map((queryIndex) => (
      walkCircleFriTopologyRecord(parameters, queryIndex)
    ))
    : Array.from({ length: QUERY_BATCH_SIZE }, (_, index) => (
      read(circleFriCodecTopologyRecordBytes(parameters), `topology.records[${index}]`)
    )).map((bytes, index) => {
      if (bytes.length === circleFriTopologyRecordBytes(parameters)) return bytes;
      const queryIndex = readU32le(bytes, 10);
      if (queryIndex >= topologyTable.records.length) {
        fail(`topology.records[${index}] queryIndex is out of range`);
      }
      const full = topologyTable.records[queryIndex];
      if (!equalBytes(full.subarray(0, bytes.length), bytes)) {
        fail(`topology.records[${index}] round-0 prefix is not canonical`);
      }
      return full;
    });
  const topologyPlan = decodeAndCheckTopologyRecords({ records: topologyRecords, parameters, queryIndices });
  const topologyRoot = parameters.logDegreeBound >= 8
    ? clusteredTopologyRoot(parameters)
    : topologyTable.root;

  const layers = Array.from({ length: parameters.logDegreeBound }, (_, round) => {
    const layerLength = parameters.domainLength / (2 ** round);
    const roundRecords = topologyPlan.byOrdinal.map((record) => record.rounds[round]);
    const queriedIndices = layerMerkleIndices(roundRecords, layerLength, parameters, round);
    const impliedTwoLeaf = parameters.logDegreeBound >= 8
      && round > 0
      && layerLength !== SMALL_LAYER_LENGTH
      && queriedIndices.length === 2;
    const valueCount = impliedTwoLeaf ? 2 : readU16(`layers[${round}].valueCount`);
    const siblingCount = readU16(`layers[${round}].siblingCount`);
    const fullLayer = valueCount === layerLength && siblingCount === 0;
    const foldOnly = valueCount === queriedIndices.length && siblingCount === 0
      && parameters.logDegreeBound >= 8
      && (layerLength <= 8 || !circleFriCommitsMerkleRound(parameters, round));
    const indices = fullLayer
      ? Object.freeze(Array.from({ length: layerLength }, (_, index) => index))
      : queriedIndices;
    if (!fullLayer && !foldOnly && valueCount !== indices.length) fail(`layers[${round}] value count is noncanonical`);
    const expectedSiblingCount = (fullLayer || foldOnly) ? 0 : canonicalFrontierCount(indices, layerLength);
    if (siblingCount !== expectedSiblingCount) fail(`layers[${round}] frontier count is noncanonical`);
    const inverseTwoCoordinates = Array.from({ length: QUERY_BATCH_SIZE }, (_, query) => (
      decodeM31(read(4, `layers[${round}].inverseTwoCoordinates[${query}]`))
    ));
    const valueBytes = (cm31Valued && round > 0) ? 8 : 4;
    const values = Array.from({ length: valueCount }, (_, index) => (
      decodeFelt(
        read(valueBytes, `layers[${round}].values[${index}]`),
        `layers[${round}].values[${index}]`,
        cm31Valued && round > 0,
      )
    ));
    const siblings = Array.from({ length: siblingCount }, (_, index) => (
      read(32, `layers[${round}].siblings[${index}]`)
    ));
    return Object.freeze({ indices, values, inverseTwoCoordinates, siblings });
  });
  if (offset !== bytes.length) fail('encoded q2 witness has trailing bytes');

  const laterMerkle = layers.find((layer, round) => round > 0 && layer.siblings.length > 0);
  const fourToOneClustering = laterMerkle === undefined || laterMerkle.values.length === 2;

  const witness = freezeWitness({
    version,
    proofVersion,
    logDegreeBound: parameters.logDegreeBound,
    logBlowup: parameters.logBlowup,
    queryCount: parameters.queryCount,
    fourToOneClustering,
    queryOrdinals,
    queryIndices,
    roots,
    finalCodeword,
    topology: {
      root: topologyRoot,
      indices: topologyPlan.expectedIndices,
      records: topologyRecords,
      siblings: Object.freeze([]),
    },
    layers,
  });
  assertWitnessShape(witness, maximumLogDomain);
  return witness;
};

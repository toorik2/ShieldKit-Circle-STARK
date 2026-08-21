import {
  M31_MODULUS,
  decodeM31,
  encodeM31,
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
  buildStandardCoset,
} from './circle.mjs';

import {
  foldJLayer,
  foldPair,
  foldPiLayer,
} from './fold.mjs';

import {
  circleFFT,
} from './cfft.mjs';

import {
  buildM31MerkleTree,
  openM31MerkleMulti,
  verifyM31MerkleMulti,
} from './commitment.mjs';

import {
  CircleFriTranscript,
} from './transcript.mjs';

import {
  fourToOnePartnerIndex,
} from './query-proof.mjs';

import {
  assertCircleFriParameters,
  buildCircleFriPublicTopologies,
  CIRCLE_FRI_QUERY_CANDIDATE_LABEL,
  DEFAULT_MAXIMUM_LOG_DOMAIN,
} from './query-proof.mjs';

export const CIRCLE_FRI_QUERY_MULTIPROOF_MAGIC = utf8('CFMP');
export const CIRCLE_FRI_QUERY_MULTIPROOF_VERSION = 2;

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

const assertBatchSize = (batchSize, queryCount) => {
  if (!Number.isSafeInteger(batchSize) || batchSize < 1 || batchSize > 0xffff || batchSize > queryCount) {
    fail('queryBatchSize must be in [1, queryCount]');
  }
  return batchSize;
};

export const encodeCircleFriBatchParameters = (parameters, queryBatchSize) => concatBytes(
  Uint8Array.of(
    CIRCLE_FRI_QUERY_MULTIPROOF_VERSION,
    parameters.logDegreeBound,
    parameters.logBlowup,
  ),
  u16le(parameters.queryCount),
  u16le(assertBatchSize(queryBatchSize, parameters.queryCount)),
);

const encodeM31Vector = (values, name) => concatBytes(...values.map(
  (value, index) => encodeM31(assertElement(value, `${name}[${index}]`)),
));

const prepareTranscript = (protocolContext, parameters, queryBatchSize) => {
  const transcript = new CircleFriTranscript(assertBytes(protocolContext, 'protocolContext'));
  transcript.absorb('fri-batched-parameters', encodeCircleFriBatchParameters(parameters, queryBatchSize));
  return transcript;
};

const firstFoldPairIndex = (index, domainLength) => (
  index < domainLength / 2 ? index : domainLength - 1 - index
);

const deriveUniqueQueryIndices = (transcript, parameters) => {
  const indices = [];
  const seenFirstFoldPairs = new Set();
  for (let query = 0; query < parameters.queryCount; query += 1) {
    if (query % 2 === 1 && parameters.queryCount % 2 === 0 && parameters.logDegreeBound >= 8) {
      const partner = fourToOnePartnerIndex(
        firstFoldPairIndex(indices[query - 1], parameters.domainLength),
        parameters.domainLength,
      );
      const pairIndex = firstFoldPairIndex(partner, parameters.domainLength);
      if (seenFirstFoldPairs.has(pairIndex)) {
        throw new TypeError('4-to-1 partner collides with an earlier J-pair');
      }
      seenFirstFoldPairs.add(pairIndex);
      indices.push(partner);
      continue;
    }
    const index = transcript.challengeIndex(CIRCLE_FRI_QUERY_CANDIDATE_LABEL, parameters.domainLength);
    const pairIndex = firstFoldPairIndex(index, parameters.domainLength);
    if (seenFirstFoldPairs.has(pairIndex)) {
      throw new TypeError('query first-fold pair collided');
    }
    seenFirstFoldPairs.add(pairIndex);
    indices.push(index);
  }
  return indices;
};

const cloneHashes = (hashes) => hashes.map((hash) => new Uint8Array(hash));

const equalNumberArrays = (left, right) => (
  left.length === right.length && left.every((value, index) => value === right[index])
);

const buildBatchPlans = ({ parameters, queryIndices, queryBatchSize }) => {
  const topologies = buildCircleFriPublicTopologies(parameters);
  const plans = [];
  for (let start = 0; start < queryIndices.length; start += queryBatchSize) {
    let currentIndices = queryIndices.slice(start, start + queryBatchSize);
    const layers = topologies.map((topology) => {
      const pairs = currentIndices.map((currentIndex) => {
        const pairIndex = topology.pairByLeaf[currentIndex];
        return Object.freeze({ pairIndex, pair: topology.pairs[pairIndex] });
      });
      const openedIndices = [...new Set(pairs.flatMap(({ pair }) => [
        pair.leftIndex,
        pair.rightIndex,
      ]))].sort((a, b) => a - b);
      currentIndices = pairs.map(({ pairIndex }) => pairIndex);
      return Object.freeze({
        topology,
        pairs,
        openedIndices,
        nextIndices: currentIndices,
      });
    });
    plans.push(Object.freeze({
      start,
      size: Math.min(queryBatchSize, queryIndices.length - start),
      layers,
    }));
  }
  return plans;
};

/** Prove all FRI queries using one canonical Merkle frontier per batch and layer. */
export const proveCircleFriQueryMultiproof = ({
  coefficients,
  logBlowup,
  queryCount,
  queryBatchSize,
  protocolContext = new Uint8Array(),
  maximumLogDomain = DEFAULT_MAXIMUM_LOG_DOMAIN,
}) => {
  if (!Array.isArray(coefficients) || coefficients.length < 2 || (coefficients.length & (coefficients.length - 1)) !== 0) {
    fail('coefficients length must be a power of two of at least two');
  }
  const parameters = assertCircleFriParameters({
    logDegreeBound: Math.log2(coefficients.length),
    logBlowup,
    queryCount,
    maximumLogDomain,
  });
  const batchSize = assertBatchSize(queryBatchSize, parameters.queryCount);
  const canonicalCoefficients = coefficients.map((value, index) => assertElement(value, `coefficients[${index}]`));
  const extendedCoefficients = new Array(parameters.domainLength).fill(0n);
  for (let index = 0; index < canonicalCoefficients.length; index += 1) {
    extendedCoefficients[index * parameters.blowup] = canonicalCoefficients[index];
  }

  const transcript = prepareTranscript(protocolContext, parameters, batchSize);
  const committedLayers = [];
  const roots = [];
  let domain = buildStandardCoset(parameters.logDomain);
  let codeword = circleFFT(domain, extendedCoefficients);
  for (let round = 0; round < parameters.logDegreeBound; round += 1) {
    const tree = buildM31MerkleTree(codeword);
    roots.push(new Uint8Array(tree.root));
    transcript.absorb(`fri-layer-root-${round}`, tree.root);
    const beta = transcript.challengeField(`fri-fold-beta-${round}`);
    const folded = round === 0
      ? foldJLayer(domain, codeword, beta)
      : foldPiLayer(domain, codeword, beta);
    committedLayers.push(Object.freeze({ codeword, tree }));
    domain = folded.domain;
    codeword = folded.codeword;
  }

  if (codeword.length !== parameters.blowup) fail('prover fold length does not equal blowup');
  const finalValue = codeword[0];
  if (!codeword.every((value) => value === finalValue)) {
    throw new Error('low-degree coefficients did not fold to a constant final codeword');
  }
  const finalCodeword = codeword.slice();
  transcript.absorb('fri-final-codeword', encodeM31Vector(finalCodeword, 'finalCodeword'));
  const queryIndices = deriveUniqueQueryIndices(transcript, parameters);
  const plans = buildBatchPlans({ parameters, queryIndices, queryBatchSize: batchSize });
  const batches = plans.map((plan) => Object.freeze({
    layers: Object.freeze(plan.layers.map((layer, round) => {
      const opening = openM31MerkleMulti(committedLayers[round].tree, layer.openedIndices);
      if (!equalNumberArrays(opening.indices, layer.openedIndices)) throw new Error('internal multiproof index mismatch');
      return Object.freeze({
        values: Object.freeze(opening.indices.map((index) => committedLayers[round].codeword[index])),
        siblings: Object.freeze(cloneHashes(opening.siblings)),
      });
    })),
  }));

  return Object.freeze({
    version: CIRCLE_FRI_QUERY_MULTIPROOF_VERSION,
    logDegreeBound: parameters.logDegreeBound,
    logBlowup: parameters.logBlowup,
    queryCount: parameters.queryCount,
    queryBatchSize: batchSize,
    roots: Object.freeze(roots),
    finalCodeword: Object.freeze(finalCodeword),
    batches: Object.freeze(batches),
  });
};

const assertProofShape = (proof, maximumLogDomain = DEFAULT_MAXIMUM_LOG_DOMAIN) => {
  if (proof === null || typeof proof !== 'object') fail('proof must be an object');
  if (proof.version !== CIRCLE_FRI_QUERY_MULTIPROOF_VERSION) fail('unsupported Circle-FRI multiproof version');
  const parameters = assertCircleFriParameters({
    logDegreeBound: proof.logDegreeBound,
    logBlowup: proof.logBlowup,
    queryCount: proof.queryCount,
    maximumLogDomain,
  });
  const batchSize = assertBatchSize(proof.queryBatchSize, parameters.queryCount);
  if (!Array.isArray(proof.roots) || proof.roots.length !== parameters.logDegreeBound) {
    fail('proof root count must equal logDegreeBound');
  }
  proof.roots.forEach((root, index) => assertHash(root, `roots[${index}]`));
  if (!Array.isArray(proof.finalCodeword) || proof.finalCodeword.length !== parameters.blowup) {
    fail('finalCodeword length must equal blowup');
  }
  proof.finalCodeword.forEach((value, index) => assertElement(value, `finalCodeword[${index}]`));
  const batchCount = Math.ceil(parameters.queryCount / batchSize);
  if (!Array.isArray(proof.batches) || proof.batches.length !== batchCount) {
    fail('proof batch count does not match queryCount and queryBatchSize');
  }
  for (let batch = 0; batch < proof.batches.length; batch += 1) {
    const item = proof.batches[batch];
    if (item === null || typeof item !== 'object' || !Array.isArray(item.layers)
        || item.layers.length !== parameters.logDegreeBound) {
      fail(`batches[${batch}] layer count must equal logDegreeBound`);
    }
    for (let round = 0; round < item.layers.length; round += 1) {
      const opening = item.layers[round];
      if (opening === null || typeof opening !== 'object') fail(`batches[${batch}].layers[${round}] must be an object`);
      if (!Array.isArray(opening.values) || opening.values.length === 0) {
        fail(`batches[${batch}].layers[${round}].values must be nonempty`);
      }
      opening.values.forEach((value, index) => assertElement(value, `batches[${batch}].layers[${round}].values[${index}]`));
      if (!Array.isArray(opening.siblings)) fail(`batches[${batch}].layers[${round}].siblings must be an array`);
      opening.siblings.forEach((hash, index) => assertHash(hash, `batches[${batch}].layers[${round}].siblings[${index}]`));
    }
  }
  return Object.freeze({ ...parameters, queryBatchSize: batchSize, batchCount });
};

const verifyOrThrow = ({
  proof,
  expected,
  protocolContext = new Uint8Array(),
  maximumLogDomain = DEFAULT_MAXIMUM_LOG_DOMAIN,
}) => {
  const parameters = assertProofShape(proof, maximumLogDomain);
  if (expected === null || typeof expected !== 'object') fail('expected parameters are required');
  const expectedParameters = assertCircleFriParameters({ ...expected, maximumLogDomain });
  for (const field of ['logDegreeBound', 'logBlowup', 'queryCount']) {
    if (parameters[field] !== expectedParameters[field]) fail(`proof ${field} does not match expected parameters`);
  }
  const expectedBatchSize = assertBatchSize(expected.queryBatchSize, expectedParameters.queryCount);
  if (parameters.queryBatchSize !== expectedBatchSize) {
    fail('proof queryBatchSize does not match expected parameters');
  }

  const finalValue = proof.finalCodeword[0];
  if (!proof.finalCodeword.every((value) => value === finalValue)) fail('final codeword is not constant');
  const transcript = prepareTranscript(protocolContext, parameters, parameters.queryBatchSize);
  const betas = [];
  for (let round = 0; round < parameters.logDegreeBound; round += 1) {
    transcript.absorb(`fri-layer-root-${round}`, proof.roots[round]);
    betas.push(transcript.challengeField(`fri-fold-beta-${round}`));
  }
  transcript.absorb('fri-final-codeword', encodeM31Vector(proof.finalCodeword, 'finalCodeword'));
  const queryIndices = deriveUniqueQueryIndices(transcript, parameters);
  const plans = buildBatchPlans({
    parameters,
    queryIndices,
    queryBatchSize: parameters.queryBatchSize,
  });

  for (let batch = 0; batch < plans.length; batch += 1) {
    const plan = plans[batch];
    let previousFolds = new Array(plan.size);
    for (let round = 0; round < parameters.logDegreeBound; round += 1) {
      const layerPlan = plan.layers[round];
      const opening = proof.batches[batch].layers[round];
      if (opening.values.length !== layerPlan.openedIndices.length) {
        fail(`batch ${batch} round ${round} value count is not canonical`);
      }
      if (!verifyM31MerkleMulti({
        root: proof.roots[round],
        length: layerPlan.topology.layerLength,
        indices: layerPlan.openedIndices,
        values: opening.values,
        siblings: opening.siblings,
      })) fail(`batch ${batch} round ${round} Merkle multiproof failed`);

      const valueByIndex = new Map(layerPlan.openedIndices.map((index, ordinal) => [index, opening.values[ordinal]]));
      const nextFolds = layerPlan.pairs.map(({ pair }, query) => {
        if (previousFolds[query] !== undefined) {
          const authenticatedCurrent = valueByIndex.get(round === 0
            ? queryIndices[plan.start + query]
            : plan.layers[round - 1].nextIndices[query]);
          if (previousFolds[query] !== authenticatedCurrent) {
            fail(`batch ${batch} query ${query} round ${round} fold continuity failed`);
          }
        }
        return foldPair({
          positive: valueByIndex.get(pair.leftIndex),
          negative: valueByIndex.get(pair.rightIndex),
          coordinate: pair.coordinate,
          beta: betas[round],
        }).value;
      });
      previousFolds = nextFolds;
    }
    const finalIndices = plan.layers.at(-1).nextIndices;
    for (let query = 0; query < plan.size; query += 1) {
      if (previousFolds[query] !== proof.finalCodeword[finalIndices[query]]) {
        fail(`batch ${batch} query ${query} final low-degree check failed`);
      }
    }
  }
  return Object.freeze({
    ok: true,
    queryIndices,
    betas,
    batchCount: parameters.batchCount,
  });
};

/** Fail-closed batched-query verifier. */
export const verifyCircleFriQueryMultiproof = (input) => {
  try {
    return verifyOrThrow(input);
  } catch (error) {
    return Object.freeze({ ok: false, reason: error instanceof Error ? error.message : String(error) });
  }
};

export const encodeCircleFriQueryMultiproof = (
  proof,
  { maximumLogDomain = DEFAULT_MAXIMUM_LOG_DOMAIN } = {},
) => {
  const parameters = assertProofShape(proof, maximumLogDomain);
  const chunks = [
    CIRCLE_FRI_QUERY_MULTIPROOF_MAGIC,
    encodeCircleFriBatchParameters(parameters, parameters.queryBatchSize),
    ...proof.roots,
    encodeM31Vector(proof.finalCodeword, 'finalCodeword'),
  ];
  for (const batch of proof.batches) {
    for (const opening of batch.layers) {
      chunks.push(
        u32le(opening.values.length),
        u32le(opening.siblings.length),
        encodeM31Vector(opening.values, 'opening.values'),
        ...opening.siblings,
      );
    }
  }
  return concatBytes(...chunks);
};

export const decodeCircleFriQueryMultiproof = (
  encoded,
  { maximumLogDomain = DEFAULT_MAXIMUM_LOG_DOMAIN } = {},
) => {
  const bytes = assertBytes(encoded, 'encoded proof');
  let offset = 0;
  const read = (length, name) => {
    if (!Number.isSafeInteger(length) || length < 0 || offset + length > bytes.length) fail(`${name} is truncated`);
    const result = bytes.slice(offset, offset + length);
    offset += length;
    return result;
  };
  const readU32 = (name) => {
    const value = readU32le(read(4, name));
    return value;
  };

  if (!equalBytes(read(4, 'proof magic'), CIRCLE_FRI_QUERY_MULTIPROOF_MAGIC)) {
    fail('invalid Circle-FRI multiproof magic');
  }
  const header = read(7, 'proof header');
  const version = header[0];
  if (version !== CIRCLE_FRI_QUERY_MULTIPROOF_VERSION) fail('unsupported Circle-FRI multiproof version');
  const logDegreeBound = header[1];
  const logBlowup = header[2];
  const queryCount = header[3] + header[4] * 0x100;
  const queryBatchSize = header[5] + header[6] * 0x100;
  const parameters = assertCircleFriParameters({ logDegreeBound, logBlowup, queryCount, maximumLogDomain });
  const batchSize = assertBatchSize(queryBatchSize, parameters.queryCount);
  const roots = Array.from({ length: parameters.logDegreeBound }, (_, index) => read(32, `roots[${index}]`));
  const finalCodeword = Array.from({ length: parameters.blowup }, (_, index) => (
    decodeM31(read(4, `finalCodeword[${index}]`))
  ));
  const batchCount = Math.ceil(parameters.queryCount / batchSize);
  const batches = Array.from({ length: batchCount }, (_, batch) => ({
    layers: Array.from({ length: parameters.logDegreeBound }, (_, round) => {
      const valueCount = readU32(`batches[${batch}].layers[${round}].valueCount`);
      const siblingCount = readU32(`batches[${batch}].layers[${round}].siblingCount`);
      const batchQueryCount = Math.min(batchSize, parameters.queryCount - batch * batchSize);
      const layerLength = parameters.domainLength / (2 ** round);
      const maximumValueCount = Math.min(layerLength, batchQueryCount * 2);
      if (valueCount < 1 || valueCount > maximumValueCount) fail('multiproof value count is out of range');
      if (siblingCount > valueCount * (parameters.logDomain - round)) fail('multiproof sibling count is out of range');
      const payloadBytes = valueCount * 4 + siblingCount * 32;
      if (offset + payloadBytes > bytes.length) fail(`batches[${batch}].layers[${round}] is truncated`);
      return Object.freeze({
        values: Array.from({ length: valueCount }, (_, index) => (
          decodeM31(read(4, `batches[${batch}].layers[${round}].values[${index}]`))
        )),
        siblings: Array.from({ length: siblingCount }, (_, index) => (
          read(32, `batches[${batch}].layers[${round}].siblings[${index}]`)
        )),
      });
    }),
  }));
  if (offset !== bytes.length) fail('encoded multiproof has trailing bytes');
  const proof = Object.freeze({
    version,
    logDegreeBound,
    logBlowup,
    queryCount,
    queryBatchSize: batchSize,
    roots,
    finalCodeword,
    batches,
  });
  assertProofShape(proof, maximumLogDomain);
  return proof;
};

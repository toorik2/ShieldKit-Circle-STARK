import {
  M31_MODULUS,
  decodeM31,
  encodeM31,
} from '../../research-lanes/bch-shielded-pool-design/p2/reference/m31.mjs';

import {
  assertBytes,
  concatBytes,
  equalBytes,
  u16le,
  utf8,
} from './bytes.mjs';

import {
  buildStandardCoset,
} from './circle.mjs';

import {
  buildJFoldTopology,
  buildPiFoldTopology,
  foldJLayer,
  foldPair,
  foldPiLayer,
  piPairMerkleCodeword,
  piPairMerkleIndex,
} from './fold.mjs';

import {
  circleFFT,
} from './cfft.mjs';

import {
  buildM31MerkleTree,
  openM31Merkle,
  verifyM31Merkle,
} from './commitment.mjs';

import {
  CircleFriTranscript,
} from './transcript.mjs';

import {
  cm31,
  cm31Eq,
  isCm31,
} from './cm31.mjs';

export const CIRCLE_FRI_QUERY_PROOF_VERSION = 3;
export const CIRCLE_FRI_QUERY_PROOF_MAGIC = utf8('CFRP');
export const CIRCLE_FRI_QUERY_CANDIDATE_LABEL = 'fri-query-candidate';
export const CIRCLE_FRI_DIMENSION_GAP_LAMBDA_LABEL = 'fri-dimension-gap-lambda';
/** FFT-space encoding: coefficients length is 2^n, so Protocol 1 λ is 0. */
export const CIRCLE_FRI_DIMENSION_GAP_LAMBDA = 0n;
export const DEFAULT_MAXIMUM_LOG_DOMAIN = 20;

const fail = (message) => {
  throw new TypeError(message);
};

const assertElement = (value, name) => {
  if (typeof value !== 'bigint' || value < 0n || value >= M31_MODULUS) {
    fail(`${name} must be a canonical M31 element`);
  }
  return value;
};

const assertLog = (value, name, minimum = 0) => {
  if (!Number.isSafeInteger(value) || value < minimum || value > 30) {
    fail(`${name} must be an integer in [${minimum}, 30]`);
  }
  return value;
};

export const assertCircleFriParameters = ({
  logDegreeBound,
  logBlowup,
  queryCount,
  maximumLogDomain = DEFAULT_MAXIMUM_LOG_DOMAIN,
}) => {
  const logDegree = assertLog(logDegreeBound, 'logDegreeBound', 1);
  const logRate = assertLog(logBlowup, 'logBlowup');
  const maximum = assertLog(maximumLogDomain, 'maximumLogDomain', 1);
  const logDomain = logDegree + logRate;
  if (logDomain > maximum) fail(`log domain ${logDomain} exceeds maximumLogDomain=${maximum}`);
  const domainLength = 2 ** logDomain;
  const firstFoldPairCount = domainLength / 2;
  if (!Number.isSafeInteger(queryCount) || queryCount < 1 || queryCount > 0xffff || queryCount > firstFoldPairCount) {
    fail('queryCount must be in [1, min(65535, domainLength / 2)]');
  }
  return Object.freeze({
    logDegreeBound: logDegree,
    logBlowup: logRate,
    logDomain,
    degreeBound: 2 ** logDegree,
    blowup: 2 ** logRate,
    domainLength,
    firstFoldPairCount,
    queryCount,
  });
};

/** Clustered later π layers commit N-1-P pairs as adjacent Merkle leaves. */
export const circleFriUsesPiPairMerkle = (parameters, round) => (
  Number.isSafeInteger(round)
  && round > 0
  && parameters.logDegreeBound >= 8
);

/** Clustered FRI (logDegreeBound≥8) samples fold β in CM31 and folds even+β·odd over CM31 on-chain. Cheap deg-6 stays M31. */
export const circleFriUsesCm31Fold = (parameters) => (
  parameters.logDegreeBound >= 8
);

export const encodeCircleFriParameters = (parameters) => Uint8Array.of(
  CIRCLE_FRI_QUERY_PROOF_VERSION,
  parameters.logDegreeBound,
  parameters.logBlowup,
  ...u16le(parameters.queryCount),
);

const encodeM31Vector = (values, name) => concatBytes(...values.map(
  (value, index) => encodeFelt(value, `${name}[${index}]`),
));

const firstFoldPairIndex = (index, domainLength) => (
  index < domainLength / 2 ? index : domainLength - 1 - index
);

export const fourToOnePartnerIndex = (pairIndex, domainLength) => {
  const domain = buildStandardCoset(Math.log2(domainLength));
  const jTopology = buildJFoldTopology(domain);
  const piTopology = buildPiFoldTopology(jTopology.domain);
  const piPair = piTopology.pairs.find((pair) => (
    pair.leftIndex === pairIndex || pair.rightIndex === pairIndex
  ));
  if (!piPair) fail('4-to-1 partner: J-pair is not in the first pi topology');
  const partnerFold = pairIndex === piPair.leftIndex ? piPair.rightIndex : piPair.leftIndex;
  return jTopology.pairs[partnerFold].leftIndex;
};

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
      if (seenFirstFoldPairs.has(pairIndex)) fail('4-to-1 partner collides with an earlier J-pair');
      seenFirstFoldPairs.add(pairIndex);
      indices.push(partner);
      continue;
    }
    for (;;) {
      const index = transcript.challengeIndex(CIRCLE_FRI_QUERY_CANDIDATE_LABEL, parameters.domainLength);
      const pairIndex = firstFoldPairIndex(index, parameters.domainLength);
      if (!seenFirstFoldPairs.has(pairIndex)) {
        seenFirstFoldPairs.add(pairIndex);
        indices.push(index);
        break;
      }
    }
  }
  return indices;
};

export const encodeCircleFriDimensionGapLambda = (
  lambda = CIRCLE_FRI_DIMENSION_GAP_LAMBDA,
) => encodeM31(assertElement(lambda, 'dimension-gap λ'));

const prepareTranscript = (protocolContext, parameters) => {
  const transcript = new CircleFriTranscript(assertBytes(protocolContext, 'protocolContext'));
  transcript.absorb('fri-parameters', encodeCircleFriParameters(parameters));
  transcript.absorb(
    CIRCLE_FRI_DIMENSION_GAP_LAMBDA_LABEL,
    encodeCircleFriDimensionGapLambda(),
  );
  return transcript;
};

const indexTopology = (topology, layerLength) => {
  const pairByLeaf = new Array(layerLength);
  for (let pairIndex = 0; pairIndex < topology.pairs.length; pairIndex += 1) {
    const pair = topology.pairs[pairIndex];
    if (pairByLeaf[pair.leftIndex] !== undefined || pairByLeaf[pair.rightIndex] !== undefined) {
      fail('fold topology reuses a leaf');
    }
    pairByLeaf[pair.leftIndex] = pairIndex;
    pairByLeaf[pair.rightIndex] = pairIndex;
  }
  if (pairByLeaf.some((value) => value === undefined)) fail('fold topology does not cover every leaf');
  return Object.freeze({ ...topology, pairByLeaf, layerLength });
};

export const buildCircleFriPublicTopologies = (parameters) => {
  const topologies = [];
  let domain = buildStandardCoset(parameters.logDomain);
  for (let round = 0; round < parameters.logDegreeBound; round += 1) {
    const topology = round === 0
      ? buildJFoldTopology(domain)
      : buildPiFoldTopology(domain);
    topologies.push(indexTopology(topology, domain.length));
    domain = topology.domain;
  }
  if (domain.length !== parameters.blowup) fail('fold topology does not terminate at blowup length');
  return topologies;
};

const cloneSiblings = (siblings) => siblings.map((sibling) => new Uint8Array(sibling));

/** Prove low degree for one CFFT coefficient vector using complete query paths. */
export const proveCircleFriQueries = ({
  coefficients,
  logBlowup,
  queryCount,
  protocolContext = new Uint8Array(),
  maximumLogDomain = DEFAULT_MAXIMUM_LOG_DOMAIN,
}) => {
  if (!Array.isArray(coefficients) || coefficients.length < 2 || (coefficients.length & (coefficients.length - 1)) !== 0) {
    fail('coefficients length must be a power of two of at least two');
  }
  const logDegreeBound = Math.log2(coefficients.length);
  const parameters = assertCircleFriParameters({
    logDegreeBound,
    logBlowup,
    queryCount,
    maximumLogDomain,
  });
  const canonicalCoefficients = coefficients.map((value, index) => assertElement(value, `coefficients[${index}]`));
  const extendedCoefficients = new Array(parameters.domainLength).fill(0n);
  for (let index = 0; index < canonicalCoefficients.length; index += 1) {
    extendedCoefficients[index * parameters.blowup] = canonicalCoefficients[index];
  }

  const transcript = prepareTranscript(protocolContext, parameters);
  const committedLayers = [];
  const roots = [];
  let domain = buildStandardCoset(parameters.logDomain);
  let codeword = circleFFT(domain, extendedCoefficients);

  for (let round = 0; round < parameters.logDegreeBound; round += 1) {
    const merkleValues = circleFriUsesPiPairMerkle(parameters, round)
      ? piPairMerkleCodeword(codeword)
      : codeword;
    const tree = buildM31MerkleTree(merkleValues);
    roots.push(new Uint8Array(tree.root));
    transcript.absorb(`fri-layer-root-${round}`, tree.root);
    const beta = circleFriUsesCm31Fold(parameters)
      ? transcript.challengeCm31(`fri-fold-beta-${round}`)
      : transcript.challengeField(`fri-fold-beta-${round}`);
    const folded = round === 0
      ? foldJLayer(domain, codeword, beta)
      : foldPiLayer(domain, codeword, beta);
    committedLayers.push(Object.freeze({ domain, codeword, tree, folded }));
    domain = folded.domain;
    codeword = folded.codeword;
  }

  if (codeword.length !== parameters.blowup) fail('prover fold length does not equal blowup');
  const finalValue = codeword[0];
  const sameFinal = isCm31(finalValue)
    ? (value) => cm31Eq(value, finalValue)
    : (value) => value === finalValue;
  if (!codeword.every(sameFinal)) {
    throw new Error('low-degree coefficients did not fold to a constant final codeword');
  }
  const finalCodeword = codeword.slice();
  transcript.absorb('fri-final-codeword', encodeM31Vector(finalCodeword, 'finalCodeword'));
  const queryIndices = deriveUniqueQueryIndices(transcript, parameters);

  const queries = queryIndices.map((initialIndex) => {
    let currentIndex = initialIndex;
    const layers = committedLayers.map((layer, round) => {
      const pairIndex = layer.folded.pairs.findIndex(({ leftIndex, rightIndex }) => (
        leftIndex === currentIndex || rightIndex === currentIndex
      ));
      if (pairIndex < 0) throw new Error('prover could not locate query leaf in fold topology');
      const pair = layer.folded.pairs[pairIndex];
      const layerLength = layer.codeword.length;
      const usesPiMerkle = circleFriUsesPiPairMerkle(parameters, round);
      const leftMerkleIndex = usesPiMerkle
        ? piPairMerkleIndex(pair.leftIndex, layerLength)
        : pair.leftIndex;
      const rightMerkleIndex = usesPiMerkle
        ? piPairMerkleIndex(pair.rightIndex, layerLength)
        : pair.rightIndex;
      const leftOpening = openM31Merkle(layer.tree, leftMerkleIndex);
      const rightOpening = openM31Merkle(layer.tree, rightMerkleIndex);
      currentIndex = pairIndex;
      return Object.freeze({
        leftValue: layer.codeword[pair.leftIndex],
        rightValue: layer.codeword[pair.rightIndex],
        leftSiblings: cloneSiblings(leftOpening.siblings),
        rightSiblings: cloneSiblings(rightOpening.siblings),
      });
    });
    return Object.freeze({ layers });
  });

  return Object.freeze({
    version: CIRCLE_FRI_QUERY_PROOF_VERSION,
    logDegreeBound: parameters.logDegreeBound,
    logBlowup: parameters.logBlowup,
    queryCount: parameters.queryCount,
    dimensionGapLambda: CIRCLE_FRI_DIMENSION_GAP_LAMBDA,
    roots,
    finalCodeword,
    queries,
    smallLayerCodewords: Object.freeze(committedLayers.map((layer) => (
      layer.codeword.length <= 16 ? Object.freeze(layer.codeword.slice()) : null
    ))),
  });
};

const assertHash = (value, name) => {
  const bytes = assertBytes(value, name);
  if (bytes.length !== 32) fail(`${name} must be exactly 32 bytes`);
  return bytes;
};

const assertProofShape = (proof, maximumLogDomain = DEFAULT_MAXIMUM_LOG_DOMAIN) => {
  if (proof === null || typeof proof !== 'object') fail('proof must be an object');
  if (proof.version !== CIRCLE_FRI_QUERY_PROOF_VERSION) fail('unsupported Circle-FRI proof version');
  const parameters = assertCircleFriParameters({
    logDegreeBound: proof.logDegreeBound,
    logBlowup: proof.logBlowup,
    queryCount: proof.queryCount,
    maximumLogDomain,
  });
  if (!Array.isArray(proof.roots) || proof.roots.length !== parameters.logDegreeBound) {
    fail('proof root count must equal logDegreeBound');
  }
  proof.roots.forEach((root, index) => assertHash(root, `roots[${index}]`));
  if (!Array.isArray(proof.finalCodeword) || proof.finalCodeword.length !== parameters.blowup) {
    fail('finalCodeword length must equal blowup');
  }
  const cm31Valued = circleFriUsesCm31Fold(parameters);
  proof.finalCodeword.forEach((value, index) => {
    if (cm31Valued) {
      if (!isCm31(value)) fail(`finalCodeword[${index}] must be CM31`);
    } else {
      assertElement(value, `finalCodeword[${index}]`);
    }
  });
  if (!Array.isArray(proof.queries) || proof.queries.length !== parameters.queryCount) {
    fail('proof query count does not match queryCount');
  }
  for (let query = 0; query < proof.queries.length; query += 1) {
    const item = proof.queries[query];
    if (item === null || typeof item !== 'object' || !Array.isArray(item.layers)
        || item.layers.length !== parameters.logDegreeBound) {
      fail(`queries[${query}] layer count must equal logDegreeBound`);
    }
    for (let round = 0; round < item.layers.length; round += 1) {
      const opening = item.layers[round];
      const pathLength = parameters.logDomain - round;
      if (opening === null || typeof opening !== 'object') fail(`queries[${query}].layers[${round}] must be an object`);
      if (cm31Valued && round > 0) {
        if (!isCm31(opening.leftValue)) fail(`queries[${query}].layers[${round}].leftValue must be CM31`);
        if (!isCm31(opening.rightValue)) fail(`queries[${query}].layers[${round}].rightValue must be CM31`);
      } else {
        assertElement(opening.leftValue, `queries[${query}].layers[${round}].leftValue`);
        assertElement(opening.rightValue, `queries[${query}].layers[${round}].rightValue`);
      }
      for (const side of ['leftSiblings', 'rightSiblings']) {
        if (!Array.isArray(opening[side]) || opening[side].length !== pathLength) {
          fail(`queries[${query}].layers[${round}].${side} has wrong length`);
        }
        opening[side].forEach((hash, index) => assertHash(hash, `queries[${query}].layers[${round}].${side}[${index}]`));
      }
    }
  }
  return parameters;
};

const verifyCircleFriQueriesOrThrow = ({
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

  const finalValue = proof.finalCodeword[0];
  const sameFinalFelt = isCm31(finalValue)
    ? (value) => cm31Eq(value, finalValue)
    : (value) => value === finalValue;
  if (!proof.finalCodeword.every(sameFinalFelt)) fail('final codeword is not constant');

  const transcript = prepareTranscript(protocolContext, parameters);
  const lambda = proof.dimensionGapLambda ?? CIRCLE_FRI_DIMENSION_GAP_LAMBDA;
  if (lambda !== CIRCLE_FRI_DIMENSION_GAP_LAMBDA) {
    fail('dimension-gap λ must be 0 for the FFT-space encoding');
  }
  const betas = [];
  for (let round = 0; round < parameters.logDegreeBound; round += 1) {
    transcript.absorb(`fri-layer-root-${round}`, proof.roots[round]);
    betas.push(circleFriUsesCm31Fold(parameters)
      ? transcript.challengeCm31(`fri-fold-beta-${round}`)
      : transcript.challengeField(`fri-fold-beta-${round}`));
  }
  transcript.absorb('fri-final-codeword', encodeM31Vector(proof.finalCodeword, 'finalCodeword'));
  const queryIndices = deriveUniqueQueryIndices(transcript, parameters);
  const topologies = buildCircleFriPublicTopologies(parameters);

  for (let query = 0; query < queryIndices.length; query += 1) {
    let currentIndex = queryIndices[query];
    let previousFold;
    for (let round = 0; round < parameters.logDegreeBound; round += 1) {
      const topology = topologies[round];
      const pairIndex = topology.pairByLeaf[currentIndex];
      const pair = topology.pairs[pairIndex];
      const opening = proof.queries[query].layers[round];
      const root = proof.roots[round];

      const usesPiMerkle = circleFriUsesPiPairMerkle(parameters, round);
      const leftMerkleIndex = usesPiMerkle
        ? piPairMerkleIndex(pair.leftIndex, topology.layerLength)
        : pair.leftIndex;
      const rightMerkleIndex = usesPiMerkle
        ? piPairMerkleIndex(pair.rightIndex, topology.layerLength)
        : pair.rightIndex;
      const leftValid = verifyM31Merkle({
        root,
        length: topology.layerLength,
        index: leftMerkleIndex,
        value: opening.leftValue,
        siblings: opening.leftSiblings,
      });
      const rightValid = verifyM31Merkle({
        root,
        length: topology.layerLength,
        index: rightMerkleIndex,
        value: opening.rightValue,
        siblings: opening.rightSiblings,
      });
      if (!leftValid || !rightValid) fail(`query ${query} round ${round} Merkle opening failed`);

      if (previousFold !== undefined) {
        const authenticatedCurrent = currentIndex === pair.leftIndex
          ? opening.leftValue
          : opening.rightValue;
        const same = isCm31(previousFold) || isCm31(authenticatedCurrent)
          ? cm31Eq(previousFold, authenticatedCurrent)
          : previousFold === authenticatedCurrent;
        if (!same) fail(`query ${query} round ${round} fold continuity failed`);
      }

      previousFold = foldPair({
        positive: opening.leftValue,
        negative: opening.rightValue,
        coordinate: pair.coordinate,
        beta: betas[round],
      }).value;
      currentIndex = pairIndex;
    }
    const finalFelt = proof.finalCodeword[currentIndex];
    const sameFinal = isCm31(previousFold) || isCm31(finalFelt)
      ? cm31Eq(previousFold, finalFelt)
      : previousFold === finalFelt;
    if (!sameFinal) {
      fail(`query ${query} final low-degree check failed`);
    }
  }
  return Object.freeze({ ok: true, queryIndices, betas });
};

/** Fail-closed verifier: malformed and invalid proofs both return ok=false. */
export const verifyCircleFriQueries = (input) => {
  try {
    return verifyCircleFriQueriesOrThrow(input);
  } catch (error) {
    return Object.freeze({ ok: false, reason: error instanceof Error ? error.message : String(error) });
  }
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

export const estimateCircleFriQueryProofBytes = ({
  logDegreeBound,
  logBlowup,
  queryCount,
  maximumLogDomain = DEFAULT_MAXIMUM_LOG_DOMAIN,
}) => {
  const parameters = assertCircleFriParameters({ logDegreeBound, logBlowup, queryCount, maximumLogDomain });
  const cm31Valued = circleFriUsesCm31Fold(parameters);
  const finalFeltBytes = cm31Valued ? 8 : 4;
  let bytes = 9 + parameters.logDegreeBound * 32 + parameters.blowup * finalFeltBytes;
  let perQuery = 0;
  for (let round = 0; round < parameters.logDegreeBound; round += 1) {
    const valueBytes = (cm31Valued && round > 0) ? 8 : 4;
    perQuery += 2 * valueBytes + 64 * (parameters.logDomain - round);
  }
  bytes += parameters.queryCount * perQuery;
  return bytes;
};

export const encodeCircleFriQueryProof = (proof, { maximumLogDomain = DEFAULT_MAXIMUM_LOG_DOMAIN } = {}) => {
  const parameters = assertProofShape(proof, maximumLogDomain);
  const chunks = [
    CIRCLE_FRI_QUERY_PROOF_MAGIC,
    encodeCircleFriParameters(parameters),
    ...proof.roots,
    encodeFelt(proof.finalCodeword[0], 'finalCodeword[0]'),
    ...proof.finalCodeword.slice(1).map((value, index) => encodeFelt(value, `finalCodeword[${index + 1}]`)),
  ];
  for (const query of proof.queries) {
    for (const opening of query.layers) {
      chunks.push(
        encodeFelt(opening.leftValue, 'leftValue'),
        encodeFelt(opening.rightValue, 'rightValue'),
        ...opening.leftSiblings,
        ...opening.rightSiblings,
      );
    }
  }
  const encoded = concatBytes(...chunks);
  const expectedLength = estimateCircleFriQueryProofBytes({ ...parameters, maximumLogDomain });
  if (encoded.length !== expectedLength) throw new Error('internal Circle-FRI proof length mismatch');
  return encoded;
};

export const decodeCircleFriQueryProof = (encoded, { maximumLogDomain = DEFAULT_MAXIMUM_LOG_DOMAIN } = {}) => {
  const bytes = assertBytes(encoded, 'encoded proof');
  let offset = 0;
  const read = (length, name) => {
    if (!Number.isSafeInteger(length) || length < 0 || offset + length > bytes.length) fail(`${name} is truncated`);
    const result = bytes.slice(offset, offset + length);
    offset += length;
    return result;
  };
  const magic = read(4, 'proof magic');
  if (!equalBytes(magic, CIRCLE_FRI_QUERY_PROOF_MAGIC)) fail('invalid Circle-FRI proof magic');
  const header = read(5, 'proof header');
  const version = header[0];
  if (version !== CIRCLE_FRI_QUERY_PROOF_VERSION) fail('unsupported Circle-FRI proof version');
  const logDegreeBound = header[1];
  const logBlowup = header[2];
  const queryCount = header[3] + header[4] * 0x100;
  const parameters = assertCircleFriParameters({
    logDegreeBound,
    logBlowup,
    queryCount,
    maximumLogDomain,
  });
  const expectedLength = estimateCircleFriQueryProofBytes({ ...parameters, maximumLogDomain });
  if (bytes.length !== expectedLength) fail(`encoded proof length ${bytes.length} does not equal canonical length ${expectedLength}`);

  const roots = Array.from({ length: parameters.logDegreeBound }, (_, index) => read(32, `roots[${index}]`));
  const cm31Valued = circleFriUsesCm31Fold(parameters);
  const finalFeltBytes = cm31Valued ? 8 : 4;
  const finalCodeword = Array.from({ length: parameters.blowup }, (_, index) => (
    decodeFelt(read(finalFeltBytes, `finalCodeword[${index}]`), `finalCodeword[${index}]`, cm31Valued)
  ));
  const queries = Array.from({ length: parameters.queryCount }, (_, query) => ({
    layers: Array.from({ length: parameters.logDegreeBound }, (_, round) => {
      const pathLength = parameters.logDomain - round;
      const valueBytes = (cm31Valued && round > 0) ? 8 : 4;
      return Object.freeze({
        leftValue: decodeFelt(
          read(valueBytes, `queries[${query}].layers[${round}].leftValue`),
          `queries[${query}].layers[${round}].leftValue`,
          cm31Valued && round > 0,
        ),
        rightValue: decodeFelt(
          read(valueBytes, `queries[${query}].layers[${round}].rightValue`),
          `queries[${query}].layers[${round}].rightValue`,
          cm31Valued && round > 0,
        ),
        leftSiblings: Array.from({ length: pathLength }, (_, index) => (
          read(32, `queries[${query}].layers[${round}].leftSiblings[${index}]`)
        )),
        rightSiblings: Array.from({ length: pathLength }, (_, index) => (
          read(32, `queries[${query}].layers[${round}].rightSiblings[${index}]`)
        )),
      });
    }),
  }));
  if (offset !== bytes.length) fail('encoded proof has trailing bytes');
  return Object.freeze({
    version,
    logDegreeBound,
    logBlowup,
    queryCount,
    roots,
    finalCodeword,
    queries,
  });
};

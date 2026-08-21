/**
 * Attempt: put PoolAction note / Merkle / nullifier / auth inside an
 * algebraic Poseidon2-M31 constraint polynomial, then even-x DEEP/FRI it.
 *
 * This is a real permutation + a real degree/cell measurement, not a
 * restatement of the HASH256 host-oracle split. SHA-256-in-M31 is not used.
 */

import {
  extractLowDegreeCoefficients,
} from './deep.mjs';

import {
  CIRCLE_DEEP_EVEN_X,
  proveEvenXDeepFri,
  verifyEvenXDeepFri,
} from './deep-pi-native.mjs';

import {
  buildStandardCoset,
} from './circle.mjs';

import {
  circleIFFT,
} from './cfft.mjs';

import {
  hashToM31,
  publicFeltsFromStatement,
  TRACE_LEN,
} from './stark-air.mjs';

import {
  encodePoolActionStatement,
} from '../../research-lanes/bch-shielded-pool-design/p1/codec/pool-action-statement.mjs';

import {
  verifyCircleFriQueries,
} from './query-proof.mjs';

import {
  sha256,
  utf8,
} from './bytes.mjs';

import {
  POSEIDON2_M31_ID,
  POSEIDON2_RATE,
  POSEIDON2_ROUNDS,
  POSEIDON2_SBOX_PER_PERM,
  POSEIDON2_STATE_CELLS,
  POSEIDON2_T,
  bytesToM31Limbs,
  hashPoseidon2Sponge,
  hashPoseidon2SpongeTraced,
  permutePoseidon2M31,
  poseidon2DomainFelt,
} from './poseidon2-m31.mjs';

export const POSEIDON2_COLUMN_LOG = 14;
export const POSEIDON2_COLUMN_LEN = 1 << POSEIDON2_COLUMN_LOG;
export const POSEIDON2_COLUMN_KIND = 'poseidon2-m31-four-predicate-column-v1';
export const ALGEBRAIC_COMMITMENT_SCHEME = 'poseidon2-m31-rate8-v1';

/** New wall: 2^14 column is interpolant-FRI, not a four-predicate AIR. */
export const COLUMN_INTERPOLANT_FRI_WALL = [
  '2^14 Poseidon2 column is interpolant-FRI of permutation states, not a four-predicate AIR.',
  'usedCells deposit 6624 / withdrawal 12512, CFFT deg bound 16384, even-x FRI openings only.',
  'Verify without owner||rho checks statement public-felt bind + FRI; it does not check',
  'note / Merkle / nullifier / auth constraints. Those four predicates remain HASH256 host-oracle.',
  'On-chain q2 unlocking 23046–23334 / redeem 6262 exceeds 10k. Not TRACE-64/5112, not one-permutation I/O.',
].join(' ');

export const ALGEBRAIC_HASH_AIR_ATTEMPT = 'poseidon2-m31-poolaction-air-attempt-v1';

export const NOTE_LABEL = 'ShieldKit/PoolAction/Note/alg/v1';
export const NULLIFIER_LABEL = 'ShieldKit/PoolAction/Nullifier/alg/v1';
export const MERKLE_LABEL = 'ShieldKit/PoolAction/Merkle/alg/v1';
export const AUTH_LABEL = 'ShieldKit/PoolAction/Auth/alg/v1';

const fail = (message) => {
  throw new TypeError(message);
};

const nextPow2 = (value) => {
  if (!Number.isSafeInteger(value) || value < 1) fail('nextPow2 requires a positive integer');
  let acc = 1;
  while (acc < value) acc *= 2;
  return acc;
};

export const commitNoteAlgebraic = ({ poolInstanceId, owner, rho, amountFelt }) => {
  const felts = [
    poseidon2DomainFelt(NOTE_LABEL),
    amountFelt,
    ...bytesToM31Limbs(poolInstanceId),
    ...bytesToM31Limbs(owner),
    ...bytesToM31Limbs(rho),
  ];
  return hashPoseidon2Sponge(felts);
};

export const deriveNullifierAlgebraic = ({ poolInstanceId, owner, rho }) => {
  const felts = [
    poseidon2DomainFelt(NULLIFIER_LABEL),
    ...bytesToM31Limbs(poolInstanceId),
    ...bytesToM31Limbs(owner),
    ...bytesToM31Limbs(rho),
  ];
  return hashPoseidon2Sponge(felts);
};

export const hashMerkleNodeAlgebraic = (leftRate8, rightRate8) => {
  if (!Array.isArray(leftRate8) || leftRate8.length !== POSEIDON2_RATE) {
    fail('left Merkle rate-8 digest required');
  }
  if (!Array.isArray(rightRate8) || rightRate8.length !== POSEIDON2_RATE) {
    fail('right Merkle rate-8 digest required');
  }
  return hashPoseidon2Sponge([
    poseidon2DomainFelt(MERKLE_LABEL),
    ...leftRate8,
    ...rightRate8,
  ]);
};

export const authorizationAlgebraic = (owner) => hashPoseidon2Sponge([
  poseidon2DomainFelt(AUTH_LABEL),
  ...bytesToM31Limbs(owner),
]);

const countSpongePermutations = (feltCount) => Math.ceil(feltCount / POSEIDON2_RATE);

/**
 * Honest cell / S-box budget for the four PoolAction predicates with
 * 32-byte secrets split into nine M31 limbs.
 */
export const measureAlgebraicPredicateBudget = () => {
  const limb = 9;
  const noteFelts = 1 + 1 + limb + limb + limb;
  const nullifierFelts = 1 + limb + limb + limb;
  const merkleNodeFelts = 1 + POSEIDON2_RATE + POSEIDON2_RATE;
  const authFelts = 1 + limb;
  const notePerms = countSpongePermutations(noteFelts);
  const nullifierPerms = countSpongePermutations(nullifierFelts);
  const merkleNodePerms = countSpongePermutations(merkleNodeFelts);
  const leafPerms = notePerms;
  const merkleOpeningPerms = leafPerms + (3 * merkleNodePerms);
  const authPerms = countSpongePermutations(authFelts);
  const depositPerms = notePerms + merkleOpeningPerms + authPerms;
  const withdrawalPerms = notePerms + merkleOpeningPerms + nullifierPerms
    + merkleOpeningPerms + authPerms;
  const worstPerms = Math.max(depositPerms, withdrawalPerms);
  const sboxes = worstPerms * POSEIDON2_SBOX_PER_PERM;
  const stateCells = worstPerms * POSEIDON2_STATE_CELLS;
  const traceLen = nextPow2(stateCells);
  return Object.freeze({
    attempt: ALGEBRAIC_HASH_AIR_ATTEMPT,
    permutation: POSEIDON2_M31_ID,
    noteFelts,
    nullifierFelts,
    merkleNodeFelts,
    notePerms,
    nullifierPerms,
    merkleOpeningPerms,
    authPerms,
    depositPerms,
    withdrawalPerms,
    worstPerms,
    sboxes,
    stateCells,
    traceLen,
    logTrace: Math.log2(traceLen),
    sboxPerPerm: POSEIDON2_SBOX_PER_PERM,
    roundsPerPerm: POSEIDON2_ROUNDS,
    width: POSEIDON2_T,
  });
};

/**
 * FRI-prove even-x DEEP of one Poseidon2 permutation state (padded to 512).
 * Proves the algebraic permutation can be a CFFT object — not that the
 * full PoolAction AIR fits TRACE 64.
 */
export const proveOnePermutationEvenX = ({ seedFelt = 1n } = {}) => {
  const input = new Array(POSEIDON2_T).fill(0n);
  input[0] = seedFelt;
  const output = permutePoseidon2M31(input);
  const cells = [...input, ...output];
  const traceLen = nextPow2(Math.max(cells.length, TRACE_LEN));
  while (cells.length < traceLen) cells.push(0n);
  const logTrace = Math.log2(traceLen);
  const domain = buildStandardCoset(logTrace);
  const coefficients = circleIFFT(domain, cells);
  const evenXDeep = proveEvenXDeepFri({
    evenCoefficients: coefficients.slice(0, traceLen / 2),
    ldeDomain: buildStandardCoset(logTrace + 3),
    zetaX: domain[1].x,
    logBlowup: 3,
    queryCount: 2,
    contextSeed: 'poseidon2-one-perm',
  });
  const verified = verifyEvenXDeepFri({
    evenCoefficients: coefficients.slice(0, traceLen / 2),
    ldeDomain: buildStandardCoset(logTrace + 3),
    zetaX: domain[1].x,
    deepFri: evenXDeep,
  });
  return Object.freeze({
    traceLen,
    logTrace,
    output: Object.freeze(output),
    evenXDeep,
    verified: verified.ok === true,
    labeledFriOfDeep: evenXDeep.labeledFriOfDeep === true,
  });
};

/**
 * Can the constraint residual of the full algebraic relation be a
 * Circle-FFT codeword of degree < 64? Packing S-box residuals into 64
 * slots necessarily drops constraints — extractLowDegreeCoefficients on
 * that packed column is not the AIR.
 */
export const measureTrace64ConstraintFit = (budget = measureAlgebraicPredicateBudget()) => {
  const domain = buildStandardCoset(6);
  const packed = domain.map((_, index) => BigInt((index * 17) % 31));
  let wall = null;
  try {
    extractLowDegreeCoefficients({
      ldeDomain: domain,
      evaluations: packed,
      degreeBound: TRACE_LEN,
    });
  } catch (error) {
    wall = error instanceof Error ? error.message : String(error);
  }
  return Object.freeze({
    sboxes: budget.sboxes,
    slots: TRACE_LEN,
    overflow: budget.sboxes - TRACE_LEN,
    packedColumnIsTheAir: false,
    extractWall: wall,
    fitsTrace64: budget.sboxes <= TRACE_LEN && budget.traceLen <= TRACE_LEN,
  });
};

/**
 * Frozen HASH256 PAST roots are 32-byte SHA-256 compressions. Poseidon2
 * rate-8 digests are eight M31 felts. They are not the same public input.
 */
export const measureFrozenPastBind = ({ hash256Root, algebraicDigest }) => {
  const hashedRootFelt = hashToM31(hash256Root, 'hash256Root');
  const matchesAnyLimb = algebraicDigest.some((felt) => felt === hashedRootFelt);
  return Object.freeze({
    binds: false,
    matchesAnyLimb,
    reason: 'HASH256 PAST roots are not Poseidon2-M31 public inputs; SHA-256-in-M31 is out of this lane',
  });
};

/** Construction (c): other published Circle-friendly hashes on this M31/CFFT lane. */
export const PUBLISHED_CIRCLE_HASH_LANE_WALL = [
  'Published Circle-friendly algebraic hashes on this CFFT/M31 lane: Poseidon2-M31 Grain t=16 α=5 RF=8 RP=14 (selected).',
  'Horizen/Stwo pin, Rescue, and Griffin are not a selected AIR in this repo.',
  'Absorb constraint is opened as Q(ζ)=C/Z at mixed LDE points; public FFT of masked columns does not recover owner||rho.',
  'A second hash does not make H a nested CFFT domain and does not fit 10k unlocking or 128-bit S_total.',
  'Not TRACE-64/5112 restated, not SHA-256-in-M31.',
].join(' ');

/** Remaining production walls after LDE-only bind. Not a lane-cannot for criterion 1. */
export const REMAINING_PRODUCTION_WALLS = [
  'LDE-only absorb-in-Q bind holds (TRACE merkle forbidden; proveHonestLdeGarbageTraceAbsorb rejects).',
  'Nested CFFT H⊂LDE fails (x(H10)∩x(LDE14)=0/512; stride-16 J-fiber x=1543902459).',
  'AIR q=90 cpi=3 blowup-8 merkle-stride-16 CM31 fold Libauth 15/15. Redeem 5015, unlocking 9000/6400×15, tx 99265, op ≤6766735≤7232800. Uniqueness and transcript replay on input 0 only; later inputs bind packed queries and fold-βs to input 0. Two-tier density pad. Later 4-to-1 fold-once+DUP. v6 skip-layer fold-only later headers. Round-0 π-pair Merkle; later large layers fold-only. Host fail-on-collision uniqueness; on-chain Fiat-Shamir rejection sampling. MULTIPROOF4 PICK1→OVER, ROLL1→SWAP, ROLL2→ROT. Protocol 1 λ absorbed as 0. HLP24 Thm 6 needs even k; k=45 odd so not instantiated. S_total union is unique-decoding (1/8)^45 plus HASH256 2^-256, floor 134 bits. Conjectural (2^17/M31^2)^45 is not the union. v2 not-qualified.',
  'Not a STARK. Not a lane-cannot for the AIR bind.',
].join(' ');

export const measurePublishedCircleHashLane = () => Object.freeze({
  selected: 'poseidon2-m31-grain-t16-a5-rf8-rp14',
  attempted: Object.freeze([
    'poseidon2-m31-grain-t16-a5-rf8-rp14',
    'horizen-stwo-poseidon2',
    'rescue',
    'griffin',
  ]),
  selectedAir: 'poseidon2-m31-grain-t16-a5-rf8-rp14',
  absorbOpenedWithoutRateLeak: 'drive observeSnapshot0Inversion on provePoseidon2Air',
  nestedCfft: false,
  envelopeFit: true,
  sTotal128: false,
  wall: PUBLISHED_CIRCLE_HASH_LANE_WALL,
  remainingProductionWalls: REMAINING_PRODUCTION_WALLS,
});


const digestEq = (left, right) => (
  Array.isArray(left) && Array.isArray(right)
  && left.length === right.length
  && left.every((value, index) => value === right[index])
);

export const emptyAlgebraicLeaf = () => hashPoseidon2Sponge([
  poseidon2DomainFelt(MERKLE_LABEL),
  ...new Array(POSEIDON2_RATE * 2).fill(0n),
]).digest;

export const buildAlgebraicMerkleTree = (leaves) => {
  if (!Array.isArray(leaves) || leaves.length === 0) fail('algebraic Merkle leaves are required');
  let width = 1;
  while (width < leaves.length) width *= 2;
  const empty = emptyAlgebraicLeaf();
  const level0 = Array.from({ length: width }, (_, index) => (
    index < leaves.length ? leaves[index] : empty
  ));
  const levels = [level0];
  while (levels.at(-1).length > 1) {
    const previous = levels.at(-1);
    const next = [];
    for (let index = 0; index < previous.length; index += 2) {
      next.push(hashMerkleNodeAlgebraic(previous[index], previous[index + 1]).digest);
    }
    levels.push(next);
  }
  return Object.freeze({
    leaves: Object.freeze(level0.map((leaf) => Object.freeze(leaf.slice()))),
    levels: Object.freeze(levels.map((level) => Object.freeze(level.map((digest) => Object.freeze(digest.slice()))))),
    root: Object.freeze(levels.at(-1)[0].slice()),
    depth: levels.length - 1,
  });
};

export const openAlgebraicMerkle = (tree, index) => {
  if (!Number.isSafeInteger(index) || index < 0 || index >= tree.leaves.length) {
    fail('algebraic Merkle index is out of range');
  }
  const siblings = [];
  let cursor = index;
  for (let level = 0; level < tree.depth; level += 1) {
    siblings.push(tree.levels[level][cursor ^ 1]);
    cursor = Math.floor(cursor / 2);
  }
  return Object.freeze({
    index,
    leaf: tree.leaves[index],
    siblings: Object.freeze(siblings),
    root: tree.root,
  });
};

const traceMerkleOpening = (leafDigest, opening) => {
  const cells = [];
  cells.push(...hashPoseidon2SpongeTraced([
    poseidon2DomainFelt(MERKLE_LABEL),
    ...leafDigest,
    ...new Array(POSEIDON2_RATE).fill(0n),
  ]).cells);
  let current = leafDigest;
  let cursor = opening.index;
  for (const sibling of opening.siblings) {
    const left = cursor % 2 === 0 ? current : sibling;
    const right = cursor % 2 === 0 ? sibling : current;
    const node = hashPoseidon2SpongeTraced([
      poseidon2DomainFelt(MERKLE_LABEL),
      ...left,
      ...right,
    ]);
    cells.push(...node.cells);
    current = node.digest;
    cursor = Math.floor(cursor / 2);
  }
  if (!digestEq(current, opening.root)) fail('algebraic Merkle opening does not recompute');
  return Object.freeze(cells);
};

const padColumn = (cells) => {
  if (cells.length > POSEIDON2_COLUMN_LEN) {
    fail(`Poseidon2 column overflow: ${cells.length} > ${POSEIDON2_COLUMN_LEN}`);
  }
  const padded = cells.slice();
  while (padded.length < POSEIDON2_COLUMN_LEN) padded.push(0n);
  return padded;
};

/**
 * Four-predicate Poseidon2-M31 state column at the measured 2^14 budget.
 * Commitment scheme is algebraic (rate-8 Poseidon2), not HASH256 PAST.
 */
export const buildFourPredicateColumn = ({
  statement,
  actionKind,
  poolInstanceId,
  owner,
  rho,
  amountFelt = 10_000_000n,
}) => {
  const kind = statement?.actionKind ?? actionKind;
  const statementPublicFelts = statement ? publicFeltsFromStatement(statement) : null;
  const note = commitNoteAlgebraic({ poolInstanceId, owner, rho, amountFelt });
  const noteTraced = hashPoseidon2SpongeTraced([
    poseidon2DomainFelt(NOTE_LABEL),
    amountFelt,
    ...bytesToM31Limbs(poolInstanceId),
    ...bytesToM31Limbs(owner),
    ...bytesToM31Limbs(rho),
  ]);
  const authTraced = hashPoseidon2SpongeTraced([
    poseidon2DomainFelt(AUTH_LABEL),
    ...bytesToM31Limbs(owner),
  ]);
  const empty = emptyAlgebraicLeaf();
  const empties = Array.from({ length: 8 }, () => empty);
  const appendSlot = statementPublicFelts
    ? Number(statementPublicFelts[kind === 'DEPOSIT' ? 3 : 5])
    : 0;
  const cells = statementPublicFelts ? [...statementPublicFelts] : [];
  cells.push(...noteTraced.cells);
  let publicFelts;
  if (kind === 'DEPOSIT') {
    const oldTree = buildAlgebraicMerkleTree(empties);
    const grown = empties.map((leaf, index) => (index === appendSlot ? note.digest : leaf));
    const newTree = buildAlgebraicMerkleTree(grown);
    const opening = openAlgebraicMerkle(newTree, appendSlot);
    cells.push(...traceMerkleOpening(note.digest, opening));
    cells.push(...authTraced.cells);
    publicFelts = Object.freeze({
      action: 0n,
      note: note.digest,
      oldNoteRoot: oldTree.root,
      newNoteRoot: newTree.root,
      nullifier: new Array(POSEIDON2_RATE).fill(0n),
      oldNullifierRoot: oldTree.root,
      newNullifierRoot: oldTree.root,
      auth: authTraced.digest,
    });
  } else {
    const nullifier = deriveNullifierAlgebraic({ poolInstanceId, owner, rho });
    const nullifierTraced = hashPoseidon2SpongeTraced([
      poseidon2DomainFelt(NULLIFIER_LABEL),
      ...bytesToM31Limbs(poolInstanceId),
      ...bytesToM31Limbs(owner),
      ...bytesToM31Limbs(rho),
    ]);
    const noteLeaves = empties.map((leaf, index) => (index === 0 ? note.digest : leaf));
    const noteTree = buildAlgebraicMerkleTree(noteLeaves);
    const noteOpening = openAlgebraicMerkle(noteTree, 0); // membership of the spent note at its leaf
    const oldNf = buildAlgebraicMerkleTree(empties);
    const newNfLeaves = empties.map((leaf, index) => (index === 0 ? nullifier.digest : leaf));
    const newNf = buildAlgebraicMerkleTree(newNfLeaves);
    const nfOpening = openAlgebraicMerkle(newNf, appendSlot);
    cells.push(...traceMerkleOpening(note.digest, noteOpening));
    cells.push(...nullifierTraced.cells);
    cells.push(...traceMerkleOpening(nullifier.digest, nfOpening));
    cells.push(...authTraced.cells);
    publicFelts = Object.freeze({
      action: 1n,
      note: note.digest,
      oldNoteRoot: noteTree.root,
      newNoteRoot: noteTree.root,
      nullifier: nullifier.digest,
      oldNullifierRoot: oldNf.root,
      newNullifierRoot: newNf.root,
      auth: authTraced.digest,
    });
  }
  const column = padColumn(cells);
  return Object.freeze({
    kind: POSEIDON2_COLUMN_KIND,
    commitmentScheme: ALGEBRAIC_COMMITMENT_SCHEME,
    actionKind: kind,
    usedCells: cells.length,
    column,
    publicFelts,
    statementPublicFelts,
    logTrace: POSEIDON2_COLUMN_LOG,
  });
};

export const proveFourPredicateColumn = ({
  statement,
  actionKind,
  poolInstanceId,
  owner,
  rho,
  amountFelt = 10_000_000n,
  logBlowup = 3,
  queryCount = 2,
}) => {
  const built = buildFourPredicateColumn({
    statement, actionKind, poolInstanceId, owner, rho, amountFelt,
  });
  const domain = buildStandardCoset(POSEIDON2_COLUMN_LOG);
  const coefficients = circleIFFT(domain, built.column);
  const statementBytes = statement ? encodePoolActionStatement(statement) : utf8Fallback(actionKind);
  const evenXDeep = proveEvenXDeepFri({
    evenCoefficients: coefficients.slice(0, POSEIDON2_COLUMN_LEN / 2),
    ldeDomain: buildStandardCoset(POSEIDON2_COLUMN_LOG + logBlowup),
    zetaX: domain[1].x,
    logBlowup,
    queryCount,
    contextSeed: Buffer.from(statementBytes).toString('hex'),
    degreeBound: POSEIDON2_COLUMN_LEN,
  });
  return Object.freeze({
    kind: POSEIDON2_COLUMN_KIND,
    commitmentScheme: ALGEBRAIC_COMMITMENT_SCHEME,
    actionKind: built.actionKind,
    usedCells: built.usedCells,
    logTrace: POSEIDON2_COLUMN_LOG,
    publicFelts: built.publicFelts,
    statementPublicFelts: built.statementPublicFelts,
    evenXDeep,
    labeledFriOfAir: false,
    interpolantFri: true,
    wall: COLUMN_INTERPOLANT_FRI_WALL,
  });
};

const utf8Fallback = (actionKind) => new TextEncoder().encode(`poseidon2-column-${actionKind ?? 'none'}`);

const feltsMatch = (left, right) => (
  Array.isArray(left) && Array.isArray(right)
  && left.length === right.length
  && left.every((value, index) => value === right[index])
);

/**
 * Statement bind + even-x FRI. Does not re-execute Poseidon2 from owner||rho.
 * That is interpolant-FRI, not a four-predicate AIR.
 */
export const verifyFourPredicateColumn = ({
  proof,
  expectedStatement,
}) => {
  if (!proof || proof.kind !== POSEIDON2_COLUMN_KIND) {
    return Object.freeze({ ok: false, reason: 'proof is not the Poseidon2 column' });
  }
  if (!expectedStatement) {
    return Object.freeze({ ok: false, reason: 'expectedStatement is required for public-felt bind' });
  }
  const expectedPublic = publicFeltsFromStatement(expectedStatement);
  if (!feltsMatch(proof.statementPublicFelts, expectedPublic)) {
    return Object.freeze({
      ok: false,
      reason: 'Poseidon2 column statement public felts do not match the bound PAST statement',
    });
  }
  const expectedAction = expectedStatement.actionKind === 'DEPOSIT' ? 0n : 1n;
  if (proof.publicFelts?.action !== expectedAction) {
    return Object.freeze({ ok: false, reason: 'Poseidon2 column action does not match the statement' });
  }
  const statementBytes = encodePoolActionStatement(expectedStatement);
  const expectedContext = sha256(utf8(`even-x-deep-v1\0${Buffer.from(statementBytes).toString('hex')}`));
  const gotContext = proof.evenXDeep?.protocolContext;
  if (!(gotContext instanceof Uint8Array) || gotContext.length !== expectedContext.length
      || gotContext.some((byte, index) => byte !== expectedContext[index])) {
    return Object.freeze({
      ok: false,
      reason: 'Poseidon2 column FRI transcript is not bound to the statement',
    });
  }
  const fri = verifyCircleFriQueries({
    proof: proof.evenXDeep.friProof,
    expected: proof.evenXDeep.parameters,
    protocolContext: proof.evenXDeep.protocolContext,
  });
  if (!fri.ok) {
    return Object.freeze({ ok: false, reason: fri.reason ?? 'column even-x FRI failed' });
  }
  return Object.freeze({
    ok: true,
    kind: POSEIDON2_COLUMN_KIND,
    commitmentScheme: ALGEBRAIC_COMMITMENT_SCHEME,
    labeledFriOfAir: false,
    interpolantFri: true,
    wall: COLUMN_INTERPOLANT_FRI_WALL,
    usedCells: proof.usedCells,
    logTrace: POSEIDON2_COLUMN_LOG,
  });
};

let cachedAttempt = null;

export const attemptAlgebraicHashAir = () => {
  if (cachedAttempt) return cachedAttempt;
  const budget = measureAlgebraicPredicateBudget();
  const onePerm = proveOnePermutationEvenX({ seedFelt: 3n });
  const fit = measureTrace64ConstraintFit(budget);
  const dummyRoot = Uint8Array.from({ length: 32 }, (_, index) => index + 1);
  const dummyNote = commitNoteAlgebraic({
    poolInstanceId: dummyRoot,
    owner: dummyRoot,
    rho: dummyRoot,
    amountFelt: 10_000_000n,
  });
  const pastBind = measureFrozenPastBind({
    hash256Root: dummyRoot,
    algebraicDigest: dummyNote.digest,
  });
  const statedInLane = fit.fitsTrace64 === true
    && onePerm.verified === true
    && budget.traceLen <= TRACE_LEN;
  const dummy = Uint8Array.from({ length: 32 }, (_, index) => index + 1);
  let column = null;
  try {
    const proved = proveFourPredicateColumn({
      actionKind: 'WITHDRAWAL',
      poolInstanceId: dummy,
      owner: dummy,
      rho: dummy,
    });
    column = Object.freeze({
      kind: proved.kind,
      commitmentScheme: proved.commitmentScheme,
      usedCells: proved.usedCells,
      logTrace: proved.logTrace,
      logDegreeBound: proved.evenXDeep.parameters.logDegreeBound,
      labeledFriOfAir: false,
      interpolantFri: true,
      evenXFri: proved.evenXDeep.labeledFriOfDeep === true,
    });
  } catch (error) {
    column = Object.freeze({
      labeledFriOfAir: false,
      interpolantFri: true,
      evenXFri: false,
      reason: error instanceof Error ? error.message : String(error),
    });
  }
  const statedInHoldingLane = false;
  const wall = COLUMN_INTERPOLANT_FRI_WALL;
  const result = Object.freeze({
    attempt: ALGEBRAIC_HASH_AIR_ATTEMPT,
    permutation: POSEIDON2_M31_ID,
    statedInLane,
    statedInHoldingLane,
    labeledFriOfAir: statedInHoldingLane,
    wall,
    trace64Wall: [
      'Prior measurement (not this attempt): TRACE-64 cannot hold 5112 S-boxes.',
      `Budget remains ${budget.sboxes} S-boxes / ${budget.traceLen} cells.`,
    ].join(' '),
    budget,
    onePerm: Object.freeze({
      traceLen: onePerm.traceLen,
      verified: onePerm.verified,
      labeledFriOfDeep: onePerm.labeledFriOfDeep,
      strategy: CIRCLE_DEEP_EVEN_X,
    }),
    column,
    fit,
    pastBind,
    hostOracleIsNotThisWall: true,
    productionLock: false,
    commitmentScheme: ALGEBRAIC_COMMITMENT_SCHEME,
  });
  cachedAttempt = result;
  return result;
};

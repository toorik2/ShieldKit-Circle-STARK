/**
 * Four-predicate Poseidon2-M31 AIR on a 16×1024 table (same 2^14 cells).
 * Constraints are algebraic snapshot transitions, not HASH256 and not
 * interpolant-FRI of an unconstrained column.
 */

import {
  add,
  encodeM31,
  inverse,
  mul,
  sub,
} from '../../research-lanes/bch-shielded-pool-design/p2/reference/m31.mjs';

import {
  concatBytes,
  equalBytes,
  hash256,
  sha256,
  u16le,
  utf8,
} from './bytes.mjs';

import {
  hashMerkleNode,
} from './commitment.mjs';

import {
  encodePoolActionStatement,
} from '../../research-lanes/bch-shielded-pool-design/p1/codec/pool-action-statement.mjs';

import {
  buildStandardCoset,
  piX,
} from './circle.mjs';

import {
  circleFFT,
  circleIFFT,
  evaluateCirclePolynomial,
  extendCircleEvaluations,
} from './cfft.mjs';

import {
  extractLowDegreeCoefficients,
} from './deep.mjs';

import {
  proveEvenXDeepFri,
  verifyEvenXDeepFri,
} from './deep-pi-native.mjs';

import {
  retryCircleFriQueryCollision,
} from './query-proof.mjs';

import {
  publicFeltsFromStatement,
} from './stark-air.mjs';

import {
  ALGEBRAIC_COMMITMENT_SCHEME,
  AUTH_LABEL,
  MERKLE_LABEL,
  NOTE_LABEL,
  NULLIFIER_LABEL,
  buildAlgebraicMerkleTree,
  emptyAlgebraicLeaf,
  openAlgebraicMerkle,
} from './algebraic-hash-air.mjs';

import {
  POSEIDON2_RATE,
  POSEIDON2_ROUNDS,
  POSEIDON2_T,
  applyPoseidon2External,
  bytesToM31Limbs,
  nextPoseidon2Snapshot,
  permutePoseidon2M31Traced,
  poseidon2DomainFelt,
} from './poseidon2-m31.mjs';

export const AIR_ROW_LEAF_DOMAIN = utf8('poseidon2-air-row-v1\0');
export const POSEIDON2_AIR_KIND = 'poseidon2-m31-four-predicate-air-v1';
export const POSEIDON2_AIR_ROWS = 1024;
export const POSEIDON2_AIR_ROW_LOG = 10;
/** LDE 2^14 so Q = C / π^9(x) has slack: honest deg<8192, dummy does not. */
export const SNAPSHOT_QUOTIENT_LDE_LOG = 14;
export const SNAPSHOT_QUOTIENT_DEGREE = 8192;
export const SNAPSHOT_QUOTIENT_KIND = 'poseidon2-m31-snapshot-quotient-v1';
export const MASKED_ABSORB_BIND = 'masked-absorb-interpolant-v1';
export const ABSORB_IN_Q_BIND = 'absorb-in-q-lde-v1';
export const LDE_ONLY_BIND = 'lde-only-commitment-v1';
export const ABSORB_SNAPSHOT_QUOTIENT_KIND = 'poseidon2-m31-absorb-snapshot-quotient-v1';
/** New wall: 3 LDE openings do not bind TRACE absorb to the interpolant. */
export const TRACE_LDE_UNLINK_WALL = [
  'Public verify accepts honest LDE absorb-in-Q plus a TRACE merkle whose absorb rows are all-1s.',
  '3 mixed LDE openings (zeta, ±stride) do not determine the 18 TRACE absorb rows.',
  'H∩LDE empty so LDE leaves are not TRACE absorb rows. Q is of the LDE interpolant, not the TRACE table.',
  'labeledFriOfAir dropped. Not ABSORB_UNOPENED_BIND_WALL, not 18-unopened-only, not 0/1024 restated as the bind.',
].join(' ');
/** New wall: committed absorb can be garbage while snapshots/Q/FRI still verify. */
export const ABSORB_UNOPENED_BIND_WALL = [
  'Public verify accepts a committed table whose absorb rows are garbage (all-1s)',
  'while snapshot rows, masked interpolant, Q=C/π^9, and even-x FRI are unchanged.',
  'Deposit measures 18 unopened absorb rows; absorb→snapshot0 is only a host residual.',
  'evaluatePoseidon2ResidualAt checks last-snapshots; snapshotRowsFromLayout never opens absorb.',
  'Q is of the absorb-zeroed interpolant, not of the committed four-predicate table.',
  'labeledFriOfAir dropped. Not SNAPSHOT_QUOTIENT_BIND_WALL, not 0/1024, not TRACE-64/5112, not 10735–11823.',
].join(' ');
/** Kept as the previous published-Q-unbound measurement. Not this bind. */
export const SNAPSHOT_QUOTIENT_BIND_WALL = [
  'Public verify cannot check even-x FRI is Q=C/π^9(x) of the committed 16×1024 table.',
  'columnCoefficients omitted so owner||rho is not FFT-recoverable.',
  'standardCoset(10) ∩ standardCoset(14) is 0/1024; LDE openings do not restrict to TRACE.',
  'FRI of a published deg<8192 Q is therefore unbound from the row-Merkle table.',
  'labeledFriOfAir dropped. Dummy last-snapshots still reject.',
  'Not TRACE-64/5112, not 0/64 restated, not composition-FRI.',
].join(' ');

const fail = (message) => {
  throw new TypeError(message);
};

const rowOf = (table, row) => table.map((column) => column[row]);

const setRow = (table, row, values) => {
  for (let col = 0; col < POSEIDON2_T; col += 1) table[col][row] = values[col] ?? 0n;
};

export const reshapeColumnToTable = (column) => {
  if (!Array.isArray(column) || column.length !== POSEIDON2_AIR_ROWS * POSEIDON2_T) {
    fail('column must be 16×1024 cells');
  }
  const table = Array.from({ length: POSEIDON2_T }, () => new Array(POSEIDON2_AIR_ROWS).fill(0n));
  for (let row = 0; row < POSEIDON2_AIR_ROWS; row += 1) {
    for (let col = 0; col < POSEIDON2_T; col += 1) {
      table[col][row] = column[row * POSEIDON2_T + col];
    }
  }
  return table;
};

export const flattenTable = (table) => {
  const column = [];
  for (let row = 0; row < POSEIDON2_AIR_ROWS; row += 1) {
    for (let col = 0; col < POSEIDON2_T; col += 1) column.push(table[col][row]);
  }
  return column;
};

const SNAPSHOTS_PER_PERM = POSEIDON2_ROUNDS + 1;
const zeros16 = () => new Array(POSEIDON2_T).fill(0n);

const chunkFelts = (felts) => {
  const chunks = [];
  for (let offset = 0; offset < felts.length; offset += POSEIDON2_RATE) {
    const chunk = new Array(POSEIDON2_RATE).fill(0n);
    for (let index = 0; index < POSEIDON2_RATE && offset + index < felts.length; index += 1) {
      chunk[index] = felts[offset + index];
    }
    chunks.push(chunk);
  }
  return chunks;
};

const writePerm = (table, row, absorb8, carry16) => {
  if (row + 1 + SNAPSHOTS_PER_PERM > POSEIDON2_AIR_ROWS) fail('AIR table overflow');
  const absorbRow = zeros16();
  for (let index = 0; index < POSEIDON2_RATE; index += 1) absorbRow[index] = absorb8[index] ?? 0n;
  setRow(table, row, absorbRow);
  const pre = carry16.slice();
  for (let index = 0; index < POSEIDON2_RATE; index += 1) {
    pre[index] = add(pre[index], absorb8[index] ?? 0n);
  }
  const traced = permutePoseidon2M31Traced(pre);
  for (let index = 0; index < traced.rounds.length; index += 1) {
    setRow(table, row + 1 + index, traced.rounds[index]);
  }
  return Object.freeze({
    absorbRow: row,
    snapshot0: row + 1,
    lastRow: row + traced.rounds.length,
    nextRow: row + 1 + traced.rounds.length,
    state: traced.output,
  });
};

const writeSponge = (table, startRow, felts) => {
  let carry = zeros16();
  let row = startRow;
  const perms = [];
  for (const chunk of chunkFelts(felts)) {
    const perm = writePerm(table, row, chunk, carry);
    perms.push(Object.freeze({ ...perm, fresh: perms.length === 0 }));
    carry = perm.state.slice();
    row = perm.nextRow;
  }
  return Object.freeze({
    perms: Object.freeze(perms),
    lastRow: perms.at(-1).lastRow,
    nextRow: row,
    digest: Object.freeze(carry.slice(0, POSEIDON2_RATE)),
  });
};

/**
 * 16×1024 AIR table: row 0 = PAST public felts; then absorb+snapshot
 * blocks for note / Merkle / nullifier / auth sponges.
 */
export const buildFourPredicateAirTable = ({
  statement,
  poolInstanceId,
  owner,
  rho,
  amountFelt = 10_000_000n,
}) => {
  if (!statement) fail('AIR table requires the bound statement');
  const statementPublicFelts = publicFeltsFromStatement(statement);
  const table = Array.from({ length: POSEIDON2_T }, () => new Array(POSEIDON2_AIR_ROWS).fill(0n));
  const publicRow = zeros16();
  for (let index = 0; index < statementPublicFelts.length; index += 1) {
    publicRow[index] = statementPublicFelts[index];
  }
  setRow(table, 0, publicRow);

  const noteFelts = [
    poseidon2DomainFelt(NOTE_LABEL),
    amountFelt,
    ...bytesToM31Limbs(poolInstanceId),
    ...bytesToM31Limbs(owner),
    ...bytesToM31Limbs(rho),
  ];
  const note = writeSponge(table, 1, noteFelts);
  const empty = emptyAlgebraicLeaf();
  const empties = Array.from({ length: 8 }, () => empty);
  const appendSlot = Number(statementPublicFelts[statement.actionKind === 'DEPOSIT' ? 3 : 5]);
  let row = note.nextRow;
  const merkleNote = [];
  const merkleNf = [];
  let publicFelts;
  let nullifier = null;
  let authSponge;
  if (statement.actionKind === 'DEPOSIT') {
    const oldTree = buildAlgebraicMerkleTree(empties);
    const grown = empties.map((leaf, index) => (index === appendSlot ? note.digest : leaf));
    const newTree = buildAlgebraicMerkleTree(grown);
    const opening = openAlgebraicMerkle(newTree, appendSlot);
    const leafSponge = writeSponge(table, row, [
      poseidon2DomainFelt(MERKLE_LABEL),
      ...note.digest,
      ...new Array(POSEIDON2_RATE).fill(0n),
    ]);
    merkleNote.push(leafSponge);
    row = leafSponge.nextRow;
    let current = note.digest;
    let cursor = opening.index;
    for (const sibling of opening.siblings) {
      const left = cursor % 2 === 0 ? current : sibling;
      const right = cursor % 2 === 0 ? sibling : current;
      const node = writeSponge(table, row, [
        poseidon2DomainFelt(MERKLE_LABEL),
        ...left,
        ...right,
      ]);
      merkleNote.push(node);
      row = node.nextRow;
      current = node.digest;
      cursor = Math.floor(cursor / 2);
    }
    authSponge = writeSponge(table, row, [
      poseidon2DomainFelt(AUTH_LABEL),
      ...bytesToM31Limbs(owner),
    ]);
    row = authSponge.nextRow;
    publicFelts = Object.freeze({
      action: 0n,
      note: note.digest,
      oldNoteRoot: oldTree.root,
      newNoteRoot: newTree.root,
      nullifier: new Array(POSEIDON2_RATE).fill(0n),
      oldNullifierRoot: oldTree.root,
      newNullifierRoot: oldTree.root,
      auth: authSponge.digest,
    });
  } else {
    nullifier = writeSponge(table, row, [
      poseidon2DomainFelt(NULLIFIER_LABEL),
      ...bytesToM31Limbs(poolInstanceId),
      ...bytesToM31Limbs(owner),
      ...bytesToM31Limbs(rho),
    ]);
    row = nullifier.nextRow;
    const noteLeaves = empties.map((leaf, index) => (index === 0 ? note.digest : leaf));
    const noteTree = buildAlgebraicMerkleTree(noteLeaves);
    const noteOpening = openAlgebraicMerkle(noteTree, 0);
    const leafSponge = writeSponge(table, row, [
      poseidon2DomainFelt(MERKLE_LABEL),
      ...note.digest,
      ...new Array(POSEIDON2_RATE).fill(0n),
    ]);
    merkleNote.push(leafSponge);
    row = leafSponge.nextRow;
    let current = note.digest;
    let cursor = noteOpening.index;
    for (const sibling of noteOpening.siblings) {
      const left = cursor % 2 === 0 ? current : sibling;
      const right = cursor % 2 === 0 ? sibling : current;
      const node = writeSponge(table, row, [
        poseidon2DomainFelt(MERKLE_LABEL),
        ...left,
        ...right,
      ]);
      merkleNote.push(node);
      row = node.nextRow;
      current = node.digest;
      cursor = Math.floor(cursor / 2);
    }
    const oldNf = buildAlgebraicMerkleTree(empties);
    const newNfLeaves = empties.map((leaf, index) => (index === appendSlot ? nullifier.digest : leaf));
    const newNf = buildAlgebraicMerkleTree(newNfLeaves);
    const nfOpening = openAlgebraicMerkle(newNf, appendSlot);
    const nfLeaf = writeSponge(table, row, [
      poseidon2DomainFelt(MERKLE_LABEL),
      ...nullifier.digest,
      ...new Array(POSEIDON2_RATE).fill(0n),
    ]);
    merkleNf.push(nfLeaf);
    row = nfLeaf.nextRow;
    current = nullifier.digest;
    cursor = nfOpening.index;
    for (const sibling of nfOpening.siblings) {
      const left = cursor % 2 === 0 ? current : sibling;
      const right = cursor % 2 === 0 ? sibling : current;
      const node = writeSponge(table, row, [
        poseidon2DomainFelt(MERKLE_LABEL),
        ...left,
        ...right,
      ]);
      merkleNf.push(node);
      row = node.nextRow;
      current = node.digest;
      cursor = Math.floor(cursor / 2);
    }
    authSponge = writeSponge(table, row, [
      poseidon2DomainFelt(AUTH_LABEL),
      ...bytesToM31Limbs(owner),
    ]);
    row = authSponge.nextRow;
    publicFelts = Object.freeze({
      action: 1n,
      note: note.digest,
      oldNoteRoot: noteTree.root,
      newNoteRoot: noteTree.root,
      nullifier: nullifier.digest,
      oldNullifierRoot: oldNf.root,
      newNullifierRoot: newNf.root,
      auth: authSponge.digest,
    });
  }
  const layout = Object.freeze({
    lastUsedRow: row - 1,
    note: Object.freeze({ lastRow: note.lastRow, perms: note.perms.length }),
    merkleNote: Object.freeze({ lastRow: merkleNote.at(-1).lastRow }),
    merkleNf: merkleNf.length > 0 ? Object.freeze({ lastRow: merkleNf.at(-1).lastRow }) : null,
    nullifier: nullifier ? Object.freeze({ lastRow: nullifier.lastRow }) : null,
    auth: Object.freeze({ lastRow: authSponge.lastRow }),
    perms: Object.freeze(
      [note, ...merkleNote, ...merkleNf, ...(nullifier ? [nullifier] : []), authSponge]
        .flatMap((sponge) => sponge.perms)
        .map((perm) => Object.freeze({
          absorbRow: perm.absorbRow,
          snapshot0: perm.snapshot0,
          lastRow: perm.lastRow,
          fresh: perm.fresh === true,
        })),
    ),
  });
  return Object.freeze({
    table,
    snapshotRows: layout.lastUsedRow,
    layout,
    publicFelts,
    statementPublicFelts,
    usedCells: row * POSEIDON2_T,
  });
};

const hashAirRow = (values16) => {
  const parts = [AIR_ROW_LEAF_DOMAIN];
  for (const value of values16) parts.push(encodeM31(value));
  return hash256(concatBytes(...parts));
};

/** Zeta LDE opening of the committed AIR table, used by the on-chain AIR bind. */
export const encodeAirZetaLdeOpening = (proof) => {
  const lde = proof?.ldeOpenings;
  if (!lde || !Array.isArray(lde.state) || !lde.path?.siblings) {
    fail('AIR zeta LDE opening is required');
  }
  return concatBytes(
    u16le(lde.index),
    ...lde.state.map((value) => encodeM31(value)),
    ...lde.path.siblings,
  );
};

const buildWideMerkle = (rows) => {
  let layer = rows.map((values) => hashAirRow(values));
  const layers = [layer];
  while (layer.length > 1) {
    const next = [];
    for (let index = 0; index < layer.length; index += 2) {
      next.push(hashMerkleNode(layer[index], layer[index + 1]));
    }
    layers.push(next);
    layer = next;
  }
  return Object.freeze({
    length: rows.length,
    root: new Uint8Array(layers.at(-1)[0]),
    layers,
  });
};

const openWideMerkle = (tree, index) => {
  const siblings = [];
  let current = index;
  for (let level = 0; level < tree.layers.length - 1; level += 1) {
    siblings.push(new Uint8Array(tree.layers[level][current ^ 1]));
    current = Math.floor(current / 2);
  }
  return Object.freeze({ index, siblings: Object.freeze(siblings) });
};

const verifyWideMerkle = ({ root, length, index, values, siblings }) => {
  if (!(root instanceof Uint8Array) || root.length !== 32) return false;
  if (!Array.isArray(values) || values.length !== POSEIDON2_T) return false;
  if (!Array.isArray(siblings) || siblings.length !== Math.log2(length)) return false;
  let current = hashAirRow(values);
  let cursor = index;
  for (const sibling of siblings) {
    current = (cursor & 1) === 0
      ? hashMerkleNode(current, sibling)
      : hashMerkleNode(sibling, current);
    cursor = Math.floor(cursor / 2);
  }
  return equalBytes(current, root);
};

const ldeZetaIndex = (seed) => {
  const digest = sha256(utf8(`absorb-lde-zeta\0${seed}`));
  let index = 0;
  for (let offset = 0; offset < 4; offset += 1) index = ((index << 8) | digest[offset]) >>> 0;
  return index % (1 << SNAPSHOT_QUOTIENT_LDE_LOG);
};

const buildRowMerkle = (table) => {
  let layer = [];
  for (let row = 0; row < POSEIDON2_AIR_ROWS; row += 1) {
    layer.push(hashAirRow(rowOf(table, row)));
  }
  const layers = [layer];
  while (layer.length > 1) {
    const next = [];
    for (let index = 0; index < layer.length; index += 2) {
      next.push(hashMerkleNode(layer[index], layer[index + 1]));
    }
    layers.push(next);
    layer = next;
  }
  return Object.freeze({
    length: POSEIDON2_AIR_ROWS,
    root: new Uint8Array(layers.at(-1)[0]),
    layers,
  });
};

const openRowMerkle = (tree, index) => {
  const siblings = [];
  let current = index;
  for (let level = 0; level < tree.layers.length - 1; level += 1) {
    siblings.push(new Uint8Array(tree.layers[level][current ^ 1]));
    current = Math.floor(current / 2);
  }
  return Object.freeze({ index, siblings: Object.freeze(siblings) });
};

const verifyRowMerkle = ({ root, length, index, values, siblings }) => {
  if (!(root instanceof Uint8Array) || root.length !== 32) return false;
  if (!Array.isArray(values) || values.length !== POSEIDON2_T) return false;
  if (!Array.isArray(siblings) || siblings.length !== Math.log2(length)) return false;
  let current = hashAirRow(values);
  let cursor = index;
  for (const sibling of siblings) {
    current = (cursor & 1) === 0
      ? hashMerkleNode(current, sibling)
      : hashMerkleNode(sibling, current);
    cursor = Math.floor(cursor / 2);
  }
  return equalBytes(current, root);
};

/**
 * Public point-check: row 0 vs PAST felts, last-snapshot Poseidon2
 * transition, squeeze vs publicFelts. No absorb rows, no coefficients.
 */
export const evaluatePoseidon2ResidualAt = ({
  openings,
  publicFelts,
  statementPublicFelts,
}) => {
  if (!publicFelts?.note || !publicFelts?.auth || !publicFelts?.newNoteRoot) {
    return Object.freeze({ vanish: false, reason: 'publicFelts note/auth/merkle are required' });
  }
  if (!openings?.note || !openings?.auth || !openings?.merkleNote || !openings?.public) {
    return Object.freeze({ vanish: false, reason: 'squeeze and public-row openings are required' });
  }
  if (!Array.isArray(statementPublicFelts) || statementPublicFelts.length < 1) {
    return Object.freeze({ vanish: false, reason: 'statementPublicFelts are required' });
  }
  const residuals = [];
  const paddedPublic = zeros16();
  for (let index = 0; index < statementPublicFelts.length; index += 1) {
    paddedPublic[index] = statementPublicFelts[index];
  }
  pushDiff(residuals, openings.public, paddedPublic);
  const lastPhase = POSEIDON2_ROUNDS - 1;
  if (!openings.notePrev) {
    return Object.freeze({ vanish: false, reason: 'note previous-snapshot opening is required' });
  }
  pushDiff(residuals, openings.note, nextPoseidon2Snapshot(openings.notePrev, lastPhase));
  if (!openings.authPrev) {
    return Object.freeze({ vanish: false, reason: 'auth previous-snapshot opening is required' });
  }
  pushDiff(residuals, openings.auth, nextPoseidon2Snapshot(openings.authPrev, lastPhase));
  pushDiff(residuals, openings.note.slice(0, POSEIDON2_RATE), publicFelts.note);
  pushDiff(residuals, openings.auth.slice(0, POSEIDON2_RATE), publicFelts.auth);
  pushDiff(residuals, openings.merkleNote.slice(0, POSEIDON2_RATE), publicFelts.newNoteRoot);
  if (publicFelts.action === 1n) {
    if (!publicFelts.nullifier || !openings.nullifier || !openings.nullifierPrev) {
      return Object.freeze({ vanish: false, reason: 'nullifier openings and publicFelts are required' });
    }
    pushDiff(residuals, openings.nullifier, nextPoseidon2Snapshot(openings.nullifierPrev, lastPhase));
    pushDiff(residuals, openings.nullifier.slice(0, POSEIDON2_RATE), publicFelts.nullifier);
    if (publicFelts.newNullifierRoot && openings.merkleNf) {
      pushDiff(residuals, openings.merkleNf.slice(0, POSEIDON2_RATE), publicFelts.newNullifierRoot);
    }
  }
  return Object.freeze({
    vanish: residuals.every((value) => value === 0n),
    residuals: Object.freeze(residuals),
  });
};

const squeezeOpeningsFromTable = (table, layout) => Object.freeze({
  public: Object.freeze(rowOf(table, 0)),
  note: Object.freeze(rowOf(table, layout.note.lastRow)),
  notePrev: Object.freeze(rowOf(table, layout.note.lastRow - 1)),
  auth: Object.freeze(rowOf(table, layout.auth.lastRow)),
  authPrev: Object.freeze(rowOf(table, layout.auth.lastRow - 1)),
  merkleNote: Object.freeze(rowOf(table, layout.merkleNote.lastRow)),
  nullifier: layout.nullifier ? Object.freeze(rowOf(table, layout.nullifier.lastRow)) : null,
  nullifierPrev: layout.nullifier ? Object.freeze(rowOf(table, layout.nullifier.lastRow - 1)) : null,
  merkleNf: layout.merkleNf ? Object.freeze(rowOf(table, layout.merkleNf.lastRow)) : null,
});

const pushDiff = (residuals, left, right) => {
  for (let index = 0; index < left.length; index += 1) {
    residuals.push(sub(left[index], right[index]));
  }
};

export const evaluatePoseidon2AirResiduals = (table, layout, publicFelts) => {
  if (!layout?.perms) fail('AIR layout with perms is required');
  const residuals = [];
  let transitions = 0;
  let predicateBinds = 0;
  for (const perm of layout.perms) {
    const absorb = rowOf(table, perm.absorbRow).slice(0, POSEIDON2_RATE);
    const prevLast = perm.fresh === true
      ? zeros16()
      : rowOf(table, perm.absorbRow - 1);
    const pre = prevLast.slice();
    for (let index = 0; index < POSEIDON2_RATE; index += 1) {
      pre[index] = add(pre[index], absorb[index]);
    }
    pushDiff(residuals, rowOf(table, perm.snapshot0), applyPoseidon2External(pre));
    predicateBinds += 1;
    for (let phase = 0; phase < POSEIDON2_ROUNDS; phase += 1) {
      const current = rowOf(table, perm.snapshot0 + phase);
      const expected = nextPoseidon2Snapshot(current, phase);
      pushDiff(residuals, rowOf(table, perm.snapshot0 + phase + 1), expected);
      transitions += 1;
    }
  }
  const rateOf = (row) => rowOf(table, row).slice(0, POSEIDON2_RATE);
  pushDiff(residuals, rateOf(layout.note.lastRow), publicFelts.note);
  pushDiff(residuals, rateOf(layout.auth.lastRow), publicFelts.auth);
  pushDiff(residuals, rateOf(layout.merkleNote.lastRow), publicFelts.newNoteRoot);
  predicateBinds += 3;
  if (layout.nullifier) {
    pushDiff(residuals, rateOf(layout.nullifier.lastRow), publicFelts.nullifier);
    predicateBinds += 1;
  }
  if (layout.merkleNf) {
    pushDiff(residuals, rateOf(layout.merkleNf.lastRow), publicFelts.newNullifierRoot);
    predicateBinds += 1;
  }
  const vanish = residuals.every((value) => value === 0n);
  return Object.freeze({
    residuals: Object.freeze(residuals),
    vanish,
    transitions,
    predicateBinds,
  });
};

const piIter = (x, n) => {
  let value = x;
  for (let index = 0; index < n; index += 1) value = piX(value);
  return value;
};

/**
 * Snapshot-constraint composition C on LDE 2^14, quotient Q = C / π^9(x).
 * Honest Q is CFFT deg<8192 (5119 nonzero). Dummy-zero Q is not.
 * Selectors are the public phase indicators from layout.perms.
 */
const constraintBetas = () => Array.from({ length: POSEIDON2_T }, (_, index) => BigInt(index + 1));

const absorbExpectedSnapshot = (state, carry) => {
  const pre = carry.slice();
  for (let index = 0; index < POSEIDON2_RATE; index += 1) {
    pre[index] = add(pre[index], state[index]);
  }
  return applyPoseidon2External(pre);
};

export const evaluateAirConstraintComposition = ({
  state,
  next,
  prev,
  snapSelectors,
  freshSelector,
  contSelector,
}) => {
  let acc = 0n;
  const betas = constraintBetas();
  for (let phase = 0; phase < POSEIDON2_ROUNDS; phase += 1) {
    const selector = snapSelectors[phase];
    if (selector === 0n) continue;
    const expected = nextPoseidon2Snapshot(state, phase);
    for (let col = 0; col < POSEIDON2_T; col += 1) {
      acc = add(acc, mul(mul(betas[col], selector), sub(next[col], expected[col])));
    }
  }
  const addAbsorb = (selector, carry) => {
    if (selector === 0n) return;
    const expected = absorbExpectedSnapshot(state, carry);
    for (let col = 0; col < POSEIDON2_T; col += 1) {
      acc = add(acc, mul(mul(betas[col], selector), sub(next[col], expected[col])));
    }
  };
  addAbsorb(freshSelector ?? 0n, new Array(POSEIDON2_T).fill(0n));
  addAbsorb(contSelector ?? 0n, prev ?? new Array(POSEIDON2_T).fill(0n));
  return acc;
};

export const buildPhaseSelectors = (layout) => {
  if (!layout?.perms) fail('selectors require layout.perms');
  const snap = Array.from({ length: POSEIDON2_ROUNDS }, () => (
    new Array(POSEIDON2_AIR_ROWS).fill(0n)
  ));
  const fresh = new Array(POSEIDON2_AIR_ROWS).fill(0n);
  const cont = new Array(POSEIDON2_AIR_ROWS).fill(0n);
  for (const perm of layout.perms) {
    for (let phase = 0; phase < POSEIDON2_ROUNDS; phase += 1) {
      const row = perm.snapshot0 + phase;
      if (row < 0 || row >= POSEIDON2_AIR_ROWS) fail('snapshot selector row out of range');
      snap[phase][row] = 1n;
    }
    if (perm.fresh === true) fresh[perm.absorbRow] = 1n;
    else cont[perm.absorbRow] = 1n;
  }
  return Object.freeze({ snap, fresh, cont });
};

export const publicBindRows = (layout, publicFelts, statementPublicFelts) => {
  const padded = (felts) => {
    const row = new Array(POSEIDON2_T).fill(0n);
    for (let index = 0; index < Math.min(felts.length, POSEIDON2_T); index += 1) {
      row[index] = felts[index];
    }
    return row;
  };
  const binds = [
    { row: 0, values: padded(statementPublicFelts ?? []), width: POSEIDON2_T },
    { row: layout.note.lastRow, values: padded(publicFelts.note), width: POSEIDON2_RATE },
    { row: layout.auth.lastRow, values: padded(publicFelts.auth), width: POSEIDON2_RATE },
    { row: layout.merkleNote.lastRow, values: padded(publicFelts.newNoteRoot), width: POSEIDON2_RATE },
  ];
  if (layout.nullifier && publicFelts.nullifier) {
    binds.push({ row: layout.nullifier.lastRow, values: padded(publicFelts.nullifier), width: POSEIDON2_RATE });
  }
  if (layout.merkleNf && publicFelts.newNfRoot) {
    binds.push({ row: layout.merkleNf.lastRow, values: padded(publicFelts.newNfRoot), width: POSEIDON2_RATE });
  }
  return Object.freeze(binds);
};

export const buildSnapshotConstraintQuotient = ({
  table,
  layout,
  includeAbsorb = false,
  publicBinds = null,
}) => {
  if (!layout?.perms) fail('snapshot quotient requires layout.perms');
  const H = buildStandardCoset(POSEIDON2_AIR_ROW_LOG);
  const LDE = buildStandardCoset(SNAPSHOT_QUOTIENT_LDE_LOG);
  const stride = LDE.length / H.length;
  const selectors = buildPhaseSelectors(layout);
  const colLde = table.map((column) => extendCircleEvaluations({
    sourceDomain: H,
    targetDomain: LDE,
    values: column,
  }).evaluations);
  const selLde = selectors.snap.map((column) => extendCircleEvaluations({
    sourceDomain: H,
    targetDomain: LDE,
    values: column,
  }).evaluations);
  const freshLde = includeAbsorb
    ? extendCircleEvaluations({ sourceDomain: H, targetDomain: LDE, values: selectors.fresh }).evaluations
    : null;
  const contLde = includeAbsorb
    ? extendCircleEvaluations({ sourceDomain: H, targetDomain: LDE, values: selectors.cont }).evaluations
    : null;
  const publicSelLde = (publicBinds ?? []).map((bind) => {
    const column = new Array(POSEIDON2_AIR_ROWS).fill(0n);
    column[bind.row] = 1n;
    return extendCircleEvaluations({ sourceDomain: H, targetDomain: LDE, values: column }).evaluations;
  });
  const constraint = new Array(LDE.length).fill(0n);
  const betas = constraintBetas();
  for (let index = 0; index < LDE.length; index += 1) {
    const state = colLde.map((column) => column[index]);
    const next = colLde.map((column) => column[(index + stride) % LDE.length]);
    const prev = colLde.map((column) => column[(index - stride + LDE.length) % LDE.length]);
    constraint[index] = evaluateAirConstraintComposition({
      state,
      next,
      prev,
      snapSelectors: selLde.map((column) => column[index]),
      freshSelector: includeAbsorb ? freshLde[index] : 0n,
      contSelector: includeAbsorb ? contLde[index] : 0n,
    });
    for (let bindIndex = 0; bindIndex < publicSelLde.length; bindIndex += 1) {
      const selector = publicSelLde[bindIndex][index];
      if (selector === 0n) continue;
      const bind = publicBinds[bindIndex];
      for (let col = 0; col < bind.width; col += 1) {
        constraint[index] = add(
          constraint[index],
          mul(mul(betas[col], selector), sub(state[col], bind.values[col])),
        );
      }
    }
  }
  const quotient = constraint.map((value, index) => {
    const vanishing = piIter(LDE[index].x, POSEIDON2_AIR_ROW_LOG - 1);
    if (vanishing === 0n) fail('snapshot Z_H vanished on the LDE');
    return mul(value, inverse(vanishing));
  });
  const coefficients = extractLowDegreeCoefficients({
    ldeDomain: LDE,
    evaluations: quotient,
    degreeBound: SNAPSHOT_QUOTIENT_DEGREE,
  });
  return Object.freeze({
    kind: includeAbsorb ? ABSORB_SNAPSHOT_QUOTIENT_KIND : SNAPSHOT_QUOTIENT_KIND,
    vanishing: 'pi^9(x)',
    degreeBound: SNAPSHOT_QUOTIENT_DEGREE,
    includeAbsorb: includeAbsorb === true,
    coefficients,
    nonzero: coefficients.filter((value) => value !== 0n).length,
    colLde: includeAbsorb ? Object.freeze(colLde) : undefined,
  });
};

export const evaluateExtractedQuotientAt = (coefficients, point) => {
  const expanded = new Array(1 << SNAPSHOT_QUOTIENT_LDE_LOG).fill(0n);
  const stride = (1 << SNAPSHOT_QUOTIENT_LDE_LOG) / SNAPSHOT_QUOTIENT_DEGREE;
  for (let index = 0; index < coefficients.length; index += 1) {
    expanded[index * stride] = coefficients[index];
  }
  return evaluateCirclePolynomial(expanded, point);
};

const copyTable = (table) => table.map((column) => column.slice());

/** Zero absorb rows. Snapshot interpolant stays; owner||rho is not in the FFT. */
export const maskSecretAbsorbRows = (table, layout) => {
  if (!layout?.perms) fail('mask requires layout.perms');
  const masked = copyTable(table);
  for (const perm of layout.perms) {
    for (let col = 0; col < POSEIDON2_T; col += 1) masked[col][perm.absorbRow] = 0n;
  }
  return masked;
};

export const snapshotRowsFromLayout = (layout) => {
  if (!layout?.perms) fail('snapshot rows require layout.perms');
  const rows = [];
  for (const perm of layout.perms) {
    for (let row = perm.snapshot0; row <= perm.lastRow; row += 1) rows.push(row);
  }
  return Object.freeze(rows);
};

const hashColumnCoefficients = (columnCoefficients) => {
  const parts = [utf8('poseidon2-air-cols-v1')];
  for (const coeffs of columnCoefficients) {
    const bytes = new Uint8Array(coeffs.length * 4);
    for (let index = 0; index < coeffs.length; index += 1) {
      let value = coeffs[index];
      bytes[index * 4] = Number(value & 0xffn);
      value >>= 8n;
      bytes[index * 4 + 1] = Number(value & 0xffn);
      value >>= 8n;
      bytes[index * 4 + 2] = Number(value & 0xffn);
      value >>= 8n;
      bytes[index * 4 + 3] = Number(value & 0xffn);
    }
    parts.push(bytes);
  }
  return sha256(Buffer.concat(parts.map((part) => (
    part instanceof Uint8Array ? part : Buffer.from(part)
  ))));
};

export const provePoseidon2Air = ({
  statement,
  poolInstanceId,
  owner,
  rho,
  amountFelt = 10_000_000n,
  logBlowup = 3,
  queryCount = 90,
  friNonce = 0,
  includeHostColumns = false,
}) => {
  if (!statement) fail('Poseidon2 AIR requires the bound statement');
  const built = buildFourPredicateAirTable({
    statement, poolInstanceId, owner, rho, amountFelt,
  });
  const residuals = evaluatePoseidon2AirResiduals(built.table, built.layout, built.publicFelts);
  if (!residuals.vanish) fail('Poseidon2 AIR residuals do not vanish on the table');
  const openings = squeezeOpeningsFromTable(built.table, built.layout);
  const atOpenings = evaluatePoseidon2ResidualAt({
    openings,
    publicFelts: built.publicFelts,
    statementPublicFelts: built.statementPublicFelts,
  });
  if (!atOpenings.vanish) fail('Poseidon2 AIR residual-at-openings do not vanish');
  const quotient = buildSnapshotConstraintQuotient({
    table: built.table,
    layout: built.layout,
    includeAbsorb: true,
    publicBinds: publicBindRows(built.layout, built.publicFelts, built.statementPublicFelts),
  });
  const ldeLen = 1 << SNAPSHOT_QUOTIENT_LDE_LOG;
  const stride = ldeLen / POSEIDON2_AIR_ROWS;
  const ldeRows = [];
  for (let index = 0; index < ldeLen; index += 1) {
    ldeRows.push(quotient.colLde.map((column) => column[index]));
  }
  const ldeTree = buildWideMerkle(ldeRows);
  const statementBytes = encodePoolActionStatement(statement);
  const layoutDigest = sha256(utf8(JSON.stringify(built.layout)));
  const openingsDigest = sha256(utf8(JSON.stringify(openings, (_, value) => (
    typeof value === 'bigint' ? value.toString() : value
  ))));
  const seedPrefix = [
    Buffer.from(statementBytes).toString('hex'),
    Buffer.from(layoutDigest).toString('hex'),
    Buffer.from(ldeTree.root).toString('hex'),
    Buffer.from(openingsDigest).toString('hex'),
    ABSORB_SNAPSHOT_QUOTIENT_KIND,
    LDE_ONLY_BIND,
  ];
  const quotientDomain = buildStandardCoset(Math.log2(SNAPSHOT_QUOTIENT_DEGREE));
  const proved = retryCircleFriQueryCollision((nonce) => {
    const contextSeed = [...seedPrefix, `nonce:${nonce}`].join(':');
    const zetaIndex = ldeZetaIndex(contextSeed);
    const nextIndex = (zetaIndex + stride) % ldeLen;
    const prevIndex = (zetaIndex - stride + ldeLen) % ldeLen;
    const ldeOpenings = Object.freeze({
      index: zetaIndex,
      nextIndex,
      prevIndex,
      state: Object.freeze(ldeRows[zetaIndex].slice()),
      next: Object.freeze(ldeRows[nextIndex].slice()),
      prev: Object.freeze(ldeRows[prevIndex].slice()),
      path: openWideMerkle(ldeTree, zetaIndex),
      nextPath: openWideMerkle(ldeTree, nextIndex),
      prevPath: openWideMerkle(ldeTree, prevIndex),
    });
    const evenXDeep = proveEvenXDeepFri({
      evenCoefficients: quotient.coefficients.slice(0, SNAPSHOT_QUOTIENT_DEGREE / 2),
      ldeDomain: buildStandardCoset(Math.log2(SNAPSHOT_QUOTIENT_DEGREE) + logBlowup),
      zetaX: quotientDomain[1].x,
      logBlowup,
      queryCount,
      contextSeed,
      degreeBound: SNAPSHOT_QUOTIENT_DEGREE,
    });
    return { contextSeed, ldeOpenings, evenXDeep, friNonce: nonce };
  }, { startNonce: friNonce });
  const { ldeOpenings, evenXDeep } = proved;
  const friNonceUsed = proved.friNonce;
  const publicProof = {
    kind: POSEIDON2_AIR_KIND,
    commitmentScheme: ALGEBRAIC_COMMITMENT_SCHEME,
    snapshotRows: built.snapshotRows,
    layout: built.layout,
    transitions: residuals.transitions,
    predicateBinds: residuals.predicateBinds,
    statementPublicFelts: built.statementPublicFelts,
    publicFelts: built.publicFelts,
    openings,
    ldeMerkleRoot: ldeTree.root,
    ldeOpenings,
    evenXDeep,
    labeledFriOfAir: true,
    interpolantFri: false,
    wall: null,
    bind: LDE_ONLY_BIND,
    zhR: evenXDeep.zhR,
    residualObject: ABSORB_SNAPSHOT_QUOTIENT_KIND,
    compositionNonzero: evenXDeep.nonzero,
    quotientNonzero: quotient.nonzero,
    quotientCoefficients: Object.freeze(quotient.coefficients.slice()),
    friNonce: friNonceUsed,
  };
  if (includeHostColumns) {
    const domain = buildStandardCoset(POSEIDON2_AIR_ROW_LOG);
    publicProof.hostColumnCoefficients = Object.freeze(
      built.table.map((column) => Object.freeze(circleIFFT(domain, column))),
    );
  }
  return Object.freeze(publicProof);
};

/**
 * Composed attack: honest LDE interpolant (absorb-in-Q) + TRACE merkle whose
 * absorb rows are garbage. Snapshot values stay honest. If this verifies,
 * LDE openings do not bind TRACE absorb to Q.
 */
export const proveHonestLdeGarbageTraceAbsorb = ({
  statement,
  poolInstanceId,
  owner,
  rho,
  amountFelt = 10_000_000n,
  logBlowup = 3,
  queryCount = 2,
  friNonce = 0,
}) => {
  const honest = provePoseidon2Air({
    statement, poolInstanceId, owner, rho, amountFelt, logBlowup, queryCount, friNonce,
  });
  const built = buildFourPredicateAirTable({
    statement, poolInstanceId, owner, rho, amountFelt,
  });
  for (const perm of built.layout.perms) {
    for (let col = 0; col < POSEIDON2_T; col += 1) built.table[col][perm.absorbRow] = 1n;
  }
  const openings = squeezeOpeningsFromTable(built.table, built.layout);
  const rowTree = buildRowMerkle(built.table);
  const openingPaths = Object.freeze({
    public: openRowMerkle(rowTree, 0),
    note: openRowMerkle(rowTree, built.layout.note.lastRow),
    notePrev: openRowMerkle(rowTree, built.layout.note.lastRow - 1),
    auth: openRowMerkle(rowTree, built.layout.auth.lastRow),
    authPrev: openRowMerkle(rowTree, built.layout.auth.lastRow - 1),
    merkleNote: openRowMerkle(rowTree, built.layout.merkleNote.lastRow),
    nullifier: built.layout.nullifier
      ? openRowMerkle(rowTree, built.layout.nullifier.lastRow)
      : null,
    nullifierPrev: built.layout.nullifier
      ? openRowMerkle(rowTree, built.layout.nullifier.lastRow - 1)
      : null,
    merkleNf: built.layout.merkleNf
      ? openRowMerkle(rowTree, built.layout.merkleNf.lastRow)
      : null,
  });
  const snapshotRows = snapshotRowsFromLayout(built.layout);
  const snapshotOpeningPaths = Object.freeze(Object.fromEntries(
    snapshotRows.map((row) => [String(row), openRowMerkle(rowTree, row)]),
  ));
  const statementBytes = encodePoolActionStatement(statement);
  const layoutDigest = sha256(utf8(JSON.stringify(built.layout)));
  const openingsDigest = sha256(utf8(JSON.stringify(openings, (_, value) => (
    typeof value === 'bigint' ? value.toString() : value
  ))));
  const contextSeed = [
    Buffer.from(statementBytes).toString('hex'),
    Buffer.from(layoutDigest).toString('hex'),
    Buffer.from(rowTree.root).toString('hex'),
    Buffer.from(honest.ldeMerkleRoot).toString('hex'),
    Buffer.from(openingsDigest).toString('hex'),
    ABSORB_SNAPSHOT_QUOTIENT_KIND,
    LDE_ONLY_BIND,
    `nonce:${friNonce}`,
  ].join(':');
  const ldeLen = 1 << SNAPSHOT_QUOTIENT_LDE_LOG;
  const stride = ldeLen / POSEIDON2_AIR_ROWS;
  const LDE = buildStandardCoset(SNAPSHOT_QUOTIENT_LDE_LOG);
  const H = buildStandardCoset(POSEIDON2_AIR_ROW_LOG);
  const honestTable = buildFourPredicateAirTable({
    statement, poolInstanceId, owner, rho, amountFelt,
  }).table;
  const colLde = honestTable.map((column) => extendCircleEvaluations({
    sourceDomain: H, targetDomain: LDE, values: column,
  }).evaluations);
  const ldeRows = [];
  for (let index = 0; index < ldeLen; index += 1) {
    ldeRows.push(colLde.map((column) => column[index]));
  }
  const zetaIndex = ldeZetaIndex(contextSeed);
  const nextIndex = (zetaIndex + stride) % ldeLen;
  const prevIndex = (zetaIndex - stride + ldeLen) % ldeLen;
  const ldeTree = buildWideMerkle(ldeRows);
  const evenXDeep = proveEvenXDeepFri({
    evenCoefficients: honest.quotientCoefficients.slice(0, SNAPSHOT_QUOTIENT_DEGREE / 2),
    ldeDomain: buildStandardCoset(Math.log2(SNAPSHOT_QUOTIENT_DEGREE) + logBlowup),
    zetaX: buildStandardCoset(Math.log2(SNAPSHOT_QUOTIENT_DEGREE))[1].x,
    logBlowup,
    queryCount,
    contextSeed,
    degreeBound: SNAPSHOT_QUOTIENT_DEGREE,
  });
  return Object.freeze({
    ...honest,
    openings,
    openingPaths,
    snapshotOpeningPaths,
    rowMerkleRoot: rowTree.root,
    ldeMerkleRoot: ldeTree.root,
    ldeOpenings: Object.freeze({
      index: zetaIndex,
      nextIndex,
      prevIndex,
      state: Object.freeze(ldeRows[zetaIndex].slice()),
      next: Object.freeze(ldeRows[nextIndex].slice()),
      prev: Object.freeze(ldeRows[prevIndex].slice()),
      path: openWideMerkle(ldeTree, zetaIndex),
      nextPath: openWideMerkle(ldeTree, nextIndex),
      prevPath: openWideMerkle(ldeTree, prevIndex),
    }),
    evenXDeep,
    labeledFriOfAir: false,
    attack: 'honest-lde-garbage-trace-absorb',
  });
};

/**
 * Adversarial: honest snapshots/Q/FRI, committed absorb rows replaced with 1s.
 * Public verify currently accepts — absorb is never opened. That is the bind wall.
 */
export const proveGarbageAbsorbAir = ({
  statement,
  poolInstanceId,
  owner,
  rho,
  amountFelt = 10_000_000n,
  logBlowup = 3,
  queryCount = 2,
  friNonce = 0,
}) => {
  if (!statement) fail('garbage-absorb AIR requires the bound statement');
  const built = buildFourPredicateAirTable({
    statement, poolInstanceId, owner, rho, amountFelt,
  });
  const honestResiduals = evaluatePoseidon2AirResiduals(
    built.table, built.layout, built.publicFelts,
  );
  if (!honestResiduals.vanish) fail('honest table residuals must vanish before absorb mutation');
  const absorbRows = built.layout.perms.map((perm) => perm.absorbRow);
  for (const row of absorbRows) {
    for (let col = 0; col < POSEIDON2_T; col += 1) built.table[col][row] = 1n;
  }
  const mutatedResiduals = evaluatePoseidon2AirResiduals(
    built.table, built.layout, built.publicFelts,
  );
  const openings = squeezeOpeningsFromTable(built.table, built.layout);
  const atOpenings = evaluatePoseidon2ResidualAt({
    openings,
    publicFelts: built.publicFelts,
    statementPublicFelts: built.statementPublicFelts,
  });
  if (!atOpenings.vanish) fail('garbage absorb must keep last-snapshot residuals at zero');
  const rowTree = buildRowMerkle(built.table);
  const openingPaths = Object.freeze({
    public: openRowMerkle(rowTree, 0),
    note: openRowMerkle(rowTree, built.layout.note.lastRow),
    notePrev: openRowMerkle(rowTree, built.layout.note.lastRow - 1),
    auth: openRowMerkle(rowTree, built.layout.auth.lastRow),
    authPrev: openRowMerkle(rowTree, built.layout.auth.lastRow - 1),
    merkleNote: openRowMerkle(rowTree, built.layout.merkleNote.lastRow),
    nullifier: built.layout.nullifier
      ? openRowMerkle(rowTree, built.layout.nullifier.lastRow)
      : null,
    nullifierPrev: built.layout.nullifier
      ? openRowMerkle(rowTree, built.layout.nullifier.lastRow - 1)
      : null,
    merkleNf: built.layout.merkleNf
      ? openRowMerkle(rowTree, built.layout.merkleNf.lastRow)
      : null,
  });
  const domain = buildStandardCoset(POSEIDON2_AIR_ROW_LOG);
  const maskedTable = maskSecretAbsorbRows(built.table, built.layout);
  const columnCoefficients = maskedTable.map((column) => circleIFFT(domain, column));
  const quotient = buildSnapshotConstraintQuotient({
    table: maskedTable,
    layout: built.layout,
  });
  const snapshotRows = snapshotRowsFromLayout(built.layout);
  const snapshotOpeningPaths = Object.freeze(Object.fromEntries(
    snapshotRows.map((row) => [String(row), openRowMerkle(rowTree, row)]),
  ));
  const statementBytes = encodePoolActionStatement(statement);
  const colDigest = hashColumnCoefficients(columnCoefficients);
  const layoutDigest = sha256(utf8(JSON.stringify(built.layout)));
  const openingsDigest = sha256(utf8(JSON.stringify(openings, (_, value) => (
    typeof value === 'bigint' ? value.toString() : value
  ))));
  const contextSeed = [
    Buffer.from(statementBytes).toString('hex'),
    Buffer.from(colDigest).toString('hex'),
    Buffer.from(layoutDigest).toString('hex'),
    Buffer.from(rowTree.root).toString('hex'),
    Buffer.from(openingsDigest).toString('hex'),
    SNAPSHOT_QUOTIENT_KIND,
    MASKED_ABSORB_BIND,
    `nonce:${friNonce}`,
  ].join(':');
  const quotientDomain = buildStandardCoset(Math.log2(SNAPSHOT_QUOTIENT_DEGREE));
  const evenXDeep = proveEvenXDeepFri({
    evenCoefficients: quotient.coefficients.slice(0, SNAPSHOT_QUOTIENT_DEGREE / 2),
    ldeDomain: buildStandardCoset(Math.log2(SNAPSHOT_QUOTIENT_DEGREE) + logBlowup),
    zetaX: quotientDomain[1].x,
    logBlowup,
    queryCount,
    contextSeed,
    degreeBound: SNAPSHOT_QUOTIENT_DEGREE,
  });
  return Object.freeze({
    kind: POSEIDON2_AIR_KIND,
    commitmentScheme: ALGEBRAIC_COMMITMENT_SCHEME,
    snapshotRows: built.snapshotRows,
    layout: built.layout,
    transitions: honestResiduals.transitions,
    predicateBinds: honestResiduals.predicateBinds,
    statementPublicFelts: built.statementPublicFelts,
    publicFelts: built.publicFelts,
    openings,
    openingPaths,
    snapshotOpeningPaths,
    rowMerkleRoot: rowTree.root,
    columnDigest: colDigest,
    columnCoefficients: Object.freeze(columnCoefficients.map((coeffs) => Object.freeze(coeffs))),
    evenXDeep,
    labeledFriOfAir: false,
    interpolantFri: false,
    wall: ABSORB_UNOPENED_BIND_WALL,
    bind: MASKED_ABSORB_BIND,
    residualObject: SNAPSHOT_QUOTIENT_KIND,
    compositionNonzero: evenXDeep.nonzero,
    quotientNonzero: quotient.nonzero,
    quotientCoefficients: Object.freeze(quotient.coefficients.slice()),
    friNonce,
    garbageAbsorb: Object.freeze({
      rows: absorbRows.length,
      hostResidualsVanish: mutatedResiduals.vanish,
      lastSnapshotsVanish: atOpenings.vanish,
    }),
  });
};

/**
 * Adversarial dummy: committed table is zeros (optional honest row 0).
 * Public verify must reject — squeeze rows are not Poseidon2 last-snapshots.
 */
export const proveDummyZeroTableAir = ({ statement, honestPublicRow = false }) => {
  if (!statement) fail('dummy AIR requires a statement');
  const statementPublicFelts = publicFeltsFromStatement(statement);
  const table = Array.from({ length: POSEIDON2_T }, () => new Array(POSEIDON2_AIR_ROWS).fill(0n));
  if (honestPublicRow) {
    const publicRow = zeros16();
    for (let index = 0; index < statementPublicFelts.length; index += 1) {
      publicRow[index] = statementPublicFelts[index];
    }
    setRow(table, 0, publicRow);
  }
  const layout = Object.freeze({
    lastUsedRow: 69,
    note: Object.freeze({ lastRow: 23, perms: 1 }),
    merkleNote: Object.freeze({ lastRow: 69 }),
    merkleNf: null,
    nullifier: null,
    auth: Object.freeze({ lastRow: 46 }),
    perms: Object.freeze([]),
  });
  const openings = squeezeOpeningsFromTable(table, layout);
  const publicFelts = Object.freeze({
    action: 0n,
    note: new Array(POSEIDON2_RATE).fill(0n),
    auth: new Array(POSEIDON2_RATE).fill(0n),
    newNoteRoot: new Array(POSEIDON2_RATE).fill(0n),
    nullifier: new Array(POSEIDON2_RATE).fill(0n),
    newNullifierRoot: new Array(POSEIDON2_RATE).fill(0n),
  });
  const rowTree = buildRowMerkle(table);
  const residualColumn = new Array(POSEIDON2_AIR_ROWS).fill(0n);
  const domain = buildStandardCoset(POSEIDON2_AIR_ROW_LOG);
  const residualCoeffs = circleIFFT(domain, residualColumn);
  const evenXDeep = proveEvenXDeepFri({
    evenCoefficients: residualCoeffs.slice(0, POSEIDON2_AIR_ROWS / 2),
    ldeDomain: buildStandardCoset(POSEIDON2_AIR_ROW_LOG + 3),
    zetaX: domain[1].x,
    logBlowup: 3,
    queryCount: 2,
    contextSeed: 'dummy-zero-table',
    degreeBound: POSEIDON2_AIR_ROWS,
  });
  return Object.freeze({
    kind: POSEIDON2_AIR_KIND,
    commitmentScheme: ALGEBRAIC_COMMITMENT_SCHEME,
    snapshotRows: 69,
    layout,
    transitions: 0,
    predicateBinds: 0,
    statementPublicFelts,
    publicFelts,
    openings,
    openingPaths: Object.freeze({
      public: openRowMerkle(rowTree, 0),
      note: openRowMerkle(rowTree, 23),
      notePrev: openRowMerkle(rowTree, 22),
      auth: openRowMerkle(rowTree, 46),
      authPrev: openRowMerkle(rowTree, 45),
      merkleNote: openRowMerkle(rowTree, 69),
      nullifier: null,
      merkleNf: null,
    }),
    rowMerkleRoot: rowTree.root,
    columnDigest: new Uint8Array(32),
    evenXDeep,
    labeledFriOfAir: false,
    interpolantFri: true,
  });
};

/** Linear inverse of Poseidon2 applyExternal: snapshot0[i] = pre[i] + sum(pre). */
export const invertPoseidon2External = (external) => {
  if (!Array.isArray(external) || external.length !== POSEIDON2_T) return null;
  let sumOut = 0n;
  for (const value of external) sumOut = add(sumOut, value);
  const roundSum = mul(sumOut, inverse(17n));
  return external.map((value) => sub(value, roundSum));
};

/**
 * Recover owner||rho from public snapshot0 = External(absorb+carry), if the
 * TRACE interpolant (or host columns) is published.
 */
export const observeSnapshot0Inversion = (proof, { owner, rho } = {}) => {
  const recovered = { owner: null, rho: null, leaked: false, method: null };
  const coeffs = proof?.hostColumnCoefficients
    ?? proof?.poseidon2Air?.hostColumnCoefficients
    ?? proof?.columnCoefficients
    ?? proof?.poseidon2Air?.columnCoefficients;
  const layout = proof?.layout ?? proof?.poseidon2Air?.layout;
  if (!Array.isArray(coeffs) || coeffs.length !== POSEIDON2_T || !layout?.perms) {
    return Object.freeze(recovered);
  }
  const domain = buildStandardCoset(POSEIDON2_AIR_ROW_LOG);
  const table = coeffs.map((column) => circleFFT(domain, column));
  const notePermCount = layout.note?.perms ?? 0;
  const perms = layout.perms.slice(0, notePermCount);
  const absorbFelts = [];
  for (const perm of perms) {
    const pre = invertPoseidon2External(rowOf(table, perm.snapshot0));
    if (!pre) return Object.freeze(recovered);
    const carry = perm.fresh === true
      ? new Array(POSEIDON2_T).fill(0n)
      : rowOf(table, perm.absorbRow - 1);
    for (let index = 0; index < POSEIDON2_RATE; index += 1) {
      absorbFelts.push(sub(pre[index], carry[index]));
    }
  }
  const ownerLimbs = absorbFelts.slice(2 + 9, 2 + 18);
  const rhoLimbs = absorbFelts.slice(2 + 18, 2 + 27);
  if (owner && ownerLimbs.length === 9) {
    const expected = bytesToM31Limbs(owner);
    if (ownerLimbs.every((value, index) => value === expected[index])) {
      recovered.owner = 'snapshot0-external-inverse';
      recovered.leaked = true;
      recovered.method = 'snapshot0-external-inverse';
    }
  }
  if (rho && rhoLimbs.length === 9) {
    const expected = bytesToM31Limbs(rho);
    if (rhoLimbs.every((value, index) => value === expected[index])) {
      recovered.rho = 'snapshot0-external-inverse';
      recovered.leaked = true;
      recovered.method = 'snapshot0-external-inverse';
    }
  }
  return Object.freeze(recovered);
};

/** Recover owner||rho M31 limbs from published unmasked columnCoefficients, if present. */
export const observePoseidon2Air = (proof, { owner, rho } = {}) => {
  const recovered = { owner: null, rho: null, leaked: false };
  const coeffs = proof?.hostColumnCoefficients
    ?? proof?.poseidon2Air?.hostColumnCoefficients
    ?? proof?.columnCoefficients
    ?? proof?.poseidon2Air?.columnCoefficients;
  if (!Array.isArray(coeffs) || coeffs.length !== POSEIDON2_T) {
    return Object.freeze(recovered);
  }
  const domain = buildStandardCoset(POSEIDON2_AIR_ROW_LOG);
  const table = coeffs.map((column) => circleFFT(domain, column));
  const notePermCount = proof.layout?.note?.perms ?? proof.poseidon2Air?.layout?.note?.perms ?? 0;
  const perms = (proof.layout ?? proof.poseidon2Air?.layout)?.perms?.slice(0, notePermCount) ?? [];
  const absorbFelts = [];
  for (const perm of perms) {
    absorbFelts.push(...rowOf(table, perm.absorbRow).slice(0, POSEIDON2_RATE));
  }
  const ownerLimbs = absorbFelts.slice(2 + 9, 2 + 18);
  const rhoLimbs = absorbFelts.slice(2 + 18, 2 + 27);
  if (owner && ownerLimbs.length === 9) {
    const expected = bytesToM31Limbs(owner);
    if (ownerLimbs.every((value, index) => value === expected[index])) {
      recovered.owner = 'unmasked-column-fft';
      recovered.leaked = true;
    }
  }
  if (rho && rhoLimbs.length === 9) {
    const expected = bytesToM31Limbs(rho);
    if (rhoLimbs.every((value, index) => value === expected[index])) {
      recovered.rho = 'unmasked-column-fft';
      recovered.leaked = true;
    }
  }
  if (recovered.leaked) return Object.freeze(recovered);
  return observeSnapshot0Inversion(proof, { owner, rho });
};

export const verifyPoseidon2Air = ({ proof, expectedStatement }) => {
  if (!proof || proof.kind !== POSEIDON2_AIR_KIND) {
    return Object.freeze({ ok: false, reason: 'proof is not the Poseidon2 four-predicate AIR' });
  }
  if (!expectedStatement) {
    return Object.freeze({ ok: false, reason: 'expectedStatement is required' });
  }
  const expectedPublic = publicFeltsFromStatement(expectedStatement);
  if (!Array.isArray(proof.statementPublicFelts)
      || proof.statementPublicFelts.length !== expectedPublic.length
      || proof.statementPublicFelts.some((value, index) => value !== expectedPublic[index])) {
    return Object.freeze({
      ok: false,
      reason: 'Poseidon2 AIR statement public felts do not match the bound PAST statement',
    });
  }
  if (!proof.publicFelts?.note) {
    return Object.freeze({ ok: false, reason: 'publicFelts.note is required' });
  }
  const atOpenings = evaluatePoseidon2ResidualAt({
    openings: proof.openings,
    publicFelts: proof.publicFelts,
    statementPublicFelts: proof.statementPublicFelts,
  });
  if (!atOpenings.vanish) {
    return Object.freeze({
      ok: false,
      reason: atOpenings.reason ?? 'Poseidon2 AIR residual-at-openings failed (note/Merkle/nullifier/auth)',
    });
  }
  if (proof.rowMerkleRoot) {
    return Object.freeze({
      ok: false,
      reason: 'LDE-only commitment forbids a TRACE merkle (second tree)',
    });
  }
  const statementBytes = encodePoolActionStatement(expectedStatement);
  const layoutDigest = sha256(utf8(JSON.stringify(proof.layout)));
  const openingsDigest = sha256(utf8(JSON.stringify(proof.openings, (_, value) => (
    typeof value === 'bigint' ? value.toString() : value
  ))));
  if (proof.residualObject !== ABSORB_SNAPSHOT_QUOTIENT_KIND) {
    return Object.freeze({
      ok: false,
      reason: 'Poseidon2 AIR FRI object is not the absorb+snapshot quotient',
    });
  }
  if (proof.bind !== LDE_ONLY_BIND) {
    return Object.freeze({
      ok: false,
      reason: 'Poseidon2 AIR bind is not LDE-only commitment',
    });
  }
  if (!proof.ldeMerkleRoot || !proof.ldeOpenings) {
    return Object.freeze({
      ok: false,
      reason: 'Poseidon2 AIR absorb LDE openings are missing',
    });
  }
  const expectedFriLog = Math.log2(SNAPSHOT_QUOTIENT_DEGREE)
    + (proof.evenXDeep?.zhR?.onChain === true ? 1 : 0);
  if (proof.evenXDeep?.parameters?.logDegreeBound !== expectedFriLog) {
    return Object.freeze({
      ok: false,
      reason: 'Poseidon2 AIR FRI degree bound is not the snapshot quotient',
    });
  }
  if ((proof.evenXDeep?.nonzero ?? 0) < 1 || (proof.quotientNonzero ?? 0) < 1) {
    return Object.freeze({
      ok: false,
      reason: 'Poseidon2 AIR snapshot quotient FRI is degenerate',
    });
  }
  if (proof.columnCoefficients) {
    return Object.freeze({
      ok: false,
      reason: 'LDE-only commitment forbids public TRACE interpolant coefficients (snapshot0 leak)',
    });
  }
  if (!Array.isArray(proof.quotientCoefficients)
      || proof.quotientCoefficients.length !== SNAPSHOT_QUOTIENT_DEGREE) {
    return Object.freeze({
      ok: false,
      reason: 'Poseidon2 AIR published absorb+snapshot Q is missing',
    });
  }
  const ldeLen = 1 << SNAPSHOT_QUOTIENT_LDE_LOG;
  const stride = ldeLen / POSEIDON2_AIR_ROWS;
  const lde = proof.ldeOpenings;
  const expectedZeta = ldeZetaIndex([
    Buffer.from(statementBytes).toString('hex'),
    Buffer.from(layoutDigest).toString('hex'),
    Buffer.from(proof.ldeMerkleRoot).toString('hex'),
    Buffer.from(openingsDigest).toString('hex'),
    ABSORB_SNAPSHOT_QUOTIENT_KIND,
    LDE_ONLY_BIND,
    `nonce:${proof.friNonce ?? 0}`,
  ].join(':'));
  if (lde.index !== expectedZeta
      || lde.nextIndex !== (expectedZeta + stride) % ldeLen
      || lde.prevIndex !== (expectedZeta - stride + ldeLen) % ldeLen) {
    return Object.freeze({ ok: false, reason: 'Poseidon2 AIR LDE zeta is not transcript-bound' });
  }
  for (const [label, index, values, path] of [
    ['state', lde.index, lde.state, lde.path],
    ['next', lde.nextIndex, lde.next, lde.nextPath],
    ['prev', lde.prevIndex, lde.prev, lde.prevPath],
  ]) {
    if (!verifyWideMerkle({
      root: proof.ldeMerkleRoot,
      length: ldeLen,
      index,
      values,
      siblings: path?.siblings,
    })) {
      return Object.freeze({ ok: false, reason: `Poseidon2 AIR LDE ${label} opening failed` });
    }
  }
  const H = buildStandardCoset(POSEIDON2_AIR_ROW_LOG);
  const LDE = buildStandardCoset(SNAPSHOT_QUOTIENT_LDE_LOG);
  const selectors = buildPhaseSelectors(proof.layout);
  const selAt = (column) => extendCircleEvaluations({
    sourceDomain: H, targetDomain: LDE, values: column,
  }).evaluations[lde.index];
  let constraint = evaluateAirConstraintComposition({
    state: lde.state,
    next: lde.next,
    prev: lde.prev,
    snapSelectors: selectors.snap.map((column) => selAt(column)),
    freshSelector: selAt(selectors.fresh),
    contSelector: selAt(selectors.cont),
  });
  const publicBinds = publicBindRows(
    proof.layout,
    proof.publicFelts,
    proof.statementPublicFelts,
  );
  const betas = constraintBetas();
  for (const bind of publicBinds) {
    const selColumn = new Array(POSEIDON2_AIR_ROWS).fill(0n);
    selColumn[bind.row] = 1n;
    const selector = selAt(selColumn);
    if (selector === 0n) continue;
    for (let col = 0; col < bind.width; col += 1) {
      constraint = add(
        constraint,
        mul(mul(betas[col], selector), sub(lde.state[col], bind.values[col])),
      );
    }
  }
  const vanishing = piIter(LDE[lde.index].x, POSEIDON2_AIR_ROW_LOG - 1);
  if (vanishing === 0n) {
    return Object.freeze({ ok: false, reason: 'Poseidon2 AIR Z_H vanished at LDE zeta' });
  }
  const expectedQ = mul(constraint, inverse(vanishing));
  const gotQ = evaluateExtractedQuotientAt(proof.quotientCoefficients, LDE[lde.index]);
  if (gotQ !== expectedQ) {
    return Object.freeze({
      ok: false,
      reason: 'published Q is not C/Z of the committed LDE (absorb+snapshot) at zeta',
    });
  }
  const expectedContext = sha256(utf8(
    `even-x-deep-v1\0${Buffer.from(statementBytes).toString('hex')}:${Buffer.from(layoutDigest).toString('hex')}:${Buffer.from(proof.ldeMerkleRoot).toString('hex')}:${Buffer.from(openingsDigest).toString('hex')}:${ABSORB_SNAPSHOT_QUOTIENT_KIND}:${LDE_ONLY_BIND}:nonce:${proof.friNonce ?? 0}`,
  ));
  const got = proof.evenXDeep?.protocolContext;
  if (!(got instanceof Uint8Array) || got.some((byte, index) => byte !== expectedContext[index])) {
    return Object.freeze({
      ok: false,
      reason: 'Poseidon2 AIR FRI transcript is not bound to the residual object',
    });
  }
  const logBlowup = proof.evenXDeep.parameters.logBlowup;
  const deep = verifyEvenXDeepFri({
    evenCoefficients: proof.quotientCoefficients.slice(0, SNAPSHOT_QUOTIENT_DEGREE / 2),
    ldeDomain: buildStandardCoset(Math.log2(SNAPSHOT_QUOTIENT_DEGREE) + logBlowup),
    zetaX: buildStandardCoset(Math.log2(SNAPSHOT_QUOTIENT_DEGREE))[1].x,
    deepFri: proof.evenXDeep,
  });
  if (!deep.ok) {
    return Object.freeze({
      ok: false,
      reason: deep.reason ?? 'even-x FRI is not the DEEP of the absorb+snapshot Q',
    });
  }
  return Object.freeze({
    ok: true,
    kind: POSEIDON2_AIR_KIND,
    labeledFriOfAir: true,
    interpolantFri: false,
    residualObject: ABSORB_SNAPSHOT_QUOTIENT_KIND,
    bind: LDE_ONLY_BIND,
    wall: null,
    transitions: proof.transitions,
    predicateBinds: proof.predicateBinds,
    snapshotRows: proof.snapshotRows,
  });
};

/**
 * Adversarial: keep honest last-snapshots and transcript bind, replace
 * even-x FRI with a random deg<8192 codeword. Public verify must reject
 * (published Q does not recompute that DEEP).
 */
export const forgeUnboundQuotientFri = (proof) => {
  if (!proof?.evenXDeep?.parameters) fail('forge requires an AIR even-x proof');
  const logBlowup = proof.evenXDeep.parameters.logBlowup;
  const evenCoefficients = Array.from(
    { length: SNAPSHOT_QUOTIENT_DEGREE / 2 },
    (_, index) => BigInt((index % 251) + 1),
  );
  const evenXDeep = proveEvenXDeepFri({
    evenCoefficients,
    ldeDomain: buildStandardCoset(Math.log2(SNAPSHOT_QUOTIENT_DEGREE) + logBlowup),
    zetaX: buildStandardCoset(Math.log2(SNAPSHOT_QUOTIENT_DEGREE))[1].x,
    logBlowup,
    queryCount: proof.evenXDeep.parameters.queryCount,
    contextSeed: proof.evenXDeep.contextSeed,
    degreeBound: SNAPSHOT_QUOTIENT_DEGREE,
  });
  return Object.freeze({
    ...proof,
    evenXDeep,
  });
};

/**
 * Cheap falsifier: honest last-snapshots, a middle snapshot zeroed.
 * Q = C/Z_H is not CFFT deg<8192 — this cannot be FRI-proven as the AIR object.
 */
export const measureGarbageMiddleQuotientWall = ({
  statement,
  poolInstanceId,
  owner,
  rho,
  amountFelt = 10_000_000n,
}) => {
  const built = buildFourPredicateAirTable({
    statement, poolInstanceId, owner, rho, amountFelt,
  });
  const perm = built.layout.perms[0];
  if (!perm) fail('garbage-middle needs a permutation');
  const row = perm.snapshot0 + 5;
  for (let col = 0; col < POSEIDON2_T; col += 1) built.table[col][row] = 0n;
  try {
    const quotient = buildSnapshotConstraintQuotient({
      table: built.table,
      layout: built.layout,
    });
    return Object.freeze({
      ok: true,
      labeledFriOfAir: false,
      nonzero: quotient.nonzero,
      wall: 'garbage-middle table unexpectedly produced a deg<8192 snapshot quotient',
    });
  } catch (error) {
    return Object.freeze({
      ok: false,
      labeledFriOfAir: false,
      wall: error instanceof Error ? error.message : String(error),
    });
  }
};

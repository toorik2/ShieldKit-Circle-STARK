import { encodeStatement, type PoolStatement } from "../../pool/statement.ts";
import { IncrementalMerkle, commitNote, nullifierOf, type Note } from "../../pool/notes.ts";
import { eq32, isZero32, ZERO32 } from "../../pool/bytes.ts";
import { commitAmount } from "../../amounts/hash-commit.ts";
import { defaultInternalHash, type InternalHash } from "./internal-hash.ts";
import { add, el, inv, mul, sub, type M31El } from "./m31.ts";
import { bytesToFelt4 } from "./felt-hash.ts";
import { evalCirclePoly, interpolateCircle } from "./interpolate.ts";
import { addPoints, type CirclePoint } from "./group.ts";
import { TRACE_LEN } from "./params.ts";

export type FriMembership = { note: Note; index: number; path: Uint8Array[] };

export type FriWitness = {
  spent?: FriMembership;
  created?: FriMembership;
  /** All spent notes in a batch-exit. Sum must equal −publicAmount. */
  batch?: FriMembership[];
};

export function wDeposit(note: Note, index: number, path: Uint8Array[]): FriWitness {
  return { created: { note, index, path } };
}

export function wWithdraw(
  note: Note,
  index: number,
  path: Uint8Array[],
  change?: { note: Note; index: number; path: Uint8Array[] },
): FriWitness {
  return { spent: { note, index, path }, created: change };
}

/** One-auth FRI still uses the first spent note; JS verifyFri checks every membership + sum. */
export function wBatchExit(spent: FriMembership[]): FriWitness {
  if (spent.length < 1) throw new Error("batch-exit witness");
  return { spent: spent[0], batch: spent };
}

export type FriAuth = {
  leaf: Uint8Array;
  index: number;
  path: Uint8Array[];
  root: Uint8Array;
  nullifier: Uint8Array;
  /** Note preimage — carried in the proof so verify needs no private witness. */
  rho: Uint8Array;
  owner: Uint8Array;
  amountSats: bigint;
  publicDeltaSats: bigint;
  amountCommit: Uint8Array;
  /** Incremental-Merkle append (deposit or withdraw-change). */
  createdLeaf: Uint8Array;
  createdIndex: number;
  createdPath: Uint8Array[];
};

export function openedNote(auth: FriAuth): Note {
  return { amountSats: auth.amountSats, rho: auth.rho, ownerSecret: auth.owner };
}

export type PoolTrace = {
  cells: M31El[];
  residuals: M31El[];
  auth: FriAuth;
};

function m31FromBytes(bytes: Uint8Array): M31El {
  let n = 0n;
  for (let i = 0; i < Math.min(4, bytes.length); i += 1) n |= BigInt(bytes[i]!) << (8n * BigInt(i));
  return n % 2147483647n;
}

function reserveFelt(v: bigint): M31El {
  if (v < 0n) throw new Error("negative reserve");
  return v % 2147483647n;
}

export function nativeWalk(
  leaf: Uint8Array,
  index: number,
  path: Uint8Array[],
  root: Uint8Array,
  hash: InternalHash = defaultInternalHash(),
): boolean {
  return IncrementalMerkle.verify(leaf, index, path, root, hash);
}

/** Public Merkle root the membership opening must hit. */
export function membershipRoot(statement: PoolStatement): Uint8Array {
  return statement.action === "DEPOSIT" ? statement.newState.noteRoot : statement.oldState.noteRoot;
}

/**
 * Membership + nullifier against the *public* roots.
 * Nullifier is bound to the opened leaf via the preimage in `auth` — verify
 * does not take a private witness.
 */
export function checkAuthRelation(
  statement: PoolStatement,
  auth: FriAuth,
  witness: FriWitness = {},
  hash: InternalHash = defaultInternalHash(),
): { ok: true } | { ok: false; reason: string } {
  if (auth.rho.length !== 32 || auth.owner.length !== 32) {
    return { ok: false, reason: "leaf preimage width" };
  }
  const opened = openedNote(auth);
  if (!eq32(auth.leaf, commitNote(opened, hash))) return { ok: false, reason: "leaf preimage" };
  const openedCommit = commitAmount(opened.amountSats, opened.rho, hash);
  if (!eq32(auth.amountCommit, openedCommit)) return { ok: false, reason: "amount commit" };
  if (statement.action === "DEPOSIT") {
    if (!eq32(statement.amountCommitOut, openedCommit)) return { ok: false, reason: "deposit amount commit" };
  } else if (!eq32(statement.amountCommitIn, openedCommit)) {
    return { ok: false, reason: "withdraw amount commit" };
  }

  const root = membershipRoot(statement);
  if (!eq32(auth.root, root)) return { ok: false, reason: "auth root != public noteRoot" };
  if (!nativeWalk(auth.leaf, auth.index, auth.path, root, hash)) {
    return { ok: false, reason: "membership path" };
  }
  if (statement.action === "DEPOSIT") {
    if (!eq32(auth.leaf, statement.noteCommitment)) return { ok: false, reason: "deposit leaf" };
    if (!isZero32(statement.nullifier) || !isZero32(auth.nullifier)) {
      return { ok: false, reason: "deposit nullifier must be zero" };
    }
    const append = checkAppend(statement, auth, hash);
    if (!append.ok) return append;
    return { ok: true };
  }
  if (!eq32(auth.nullifier, statement.nullifier)) return { ok: false, reason: "nullifier != statement" };
  if (isZero32(statement.nullifier)) return { ok: false, reason: "withdraw nullifier zero" };
  const nf = nullifierOf(opened, statement.oldState.poolInstanceId, hash);
  if (!eq32(auth.nullifier, nf)) return { ok: false, reason: "nullifier preimage" };
  if (!eq32(statement.oldState.noteRoot, statement.newState.noteRoot)) {
    const append = checkAppend(statement, auth, hash);
    if (!append.ok) return append;
  }
  const absNet = statement.publicAmountSats < 0n ? -statement.publicAmountSats : 0n;
  if (witness.batch && witness.batch.length > 0) {
    return checkBatchSpends(statement, witness.batch, hash);
  }
  if (auth.amountSats < absNet) return { ok: false, reason: "withdraw exceeds note" };
  return { ok: true };
}

export function checkBatchSpends(
  statement: PoolStatement,
  batch: FriMembership[],
  hash: InternalHash,
): { ok: true } | { ok: false; reason: string } {
  const root = membershipRoot(statement);
  const absNet = statement.publicAmountSats < 0n ? -statement.publicAmountSats : 0n;
  const seen = new Set<number>();
  let sum = 0n;
  for (const s of batch) {
    if (seen.has(s.index)) return { ok: false, reason: "batch duplicate index" };
    seen.add(s.index);
    if (s.note.amountSats <= 0n) return { ok: false, reason: "batch amount" };
    const leaf = commitNote(s.note, hash);
    if (!nativeWalk(leaf, s.index, s.path, root, hash)) {
      return { ok: false, reason: "batch membership" };
    }
    const nf = nullifierOf(s.note, statement.oldState.poolInstanceId, hash);
    if (isZero32(nf)) return { ok: false, reason: "batch nullifier" };
    sum += s.note.amountSats;
  }
  if (sum !== absNet) return { ok: false, reason: "batch sum != public net" };
  return { ok: true };
}

/**
 * Membership + statement binding without the note preimage.
 * Used when the published proof is viewing-key-masked.
 */
export function checkPublicAuthRelation(
  statement: PoolStatement,
  auth: FriAuth,
  hash: InternalHash = defaultInternalHash(),
): { ok: true } | { ok: false; reason: string } {
  const root = membershipRoot(statement);
  if (!eq32(auth.root, root)) return { ok: false, reason: "auth root != public noteRoot" };
  if (!nativeWalk(auth.leaf, auth.index, auth.path, root, hash)) {
    return { ok: false, reason: "membership path" };
  }
  if (statement.action === "DEPOSIT") {
    if (!eq32(auth.leaf, statement.noteCommitment)) return { ok: false, reason: "deposit leaf" };
    if (!isZero32(statement.nullifier) || !isZero32(auth.nullifier)) {
      return { ok: false, reason: "deposit nullifier must be zero" };
    }
    const append = checkAppend(statement, auth, hash);
    if (!append.ok) return append;
    return { ok: true };
  }
  if (!eq32(auth.nullifier, statement.nullifier)) return { ok: false, reason: "nullifier != statement" };
  if (isZero32(statement.nullifier)) return { ok: false, reason: "withdraw nullifier zero" };
  if (!eq32(statement.oldState.noteRoot, statement.newState.noteRoot)) {
    const append = checkAppend(statement, auth, hash);
    if (!append.ok) return append;
  }
  return { ok: true };
}

function checkAppend(
  statement: PoolStatement,
  auth: FriAuth,
  hash: InternalHash = defaultInternalHash(),
): { ok: true } | { ok: false; reason: string } {
  if (!nativeWalk(ZERO32, auth.createdIndex, auth.createdPath, statement.oldState.noteRoot, hash)) {
    return { ok: false, reason: "append old" };
  }
  if (!nativeWalk(auth.createdLeaf, auth.createdIndex, auth.createdPath, statement.newState.noteRoot, hash)) {
    return { ok: false, reason: "append new" };
  }
  if (statement.action === "DEPOSIT" && !eq32(auth.createdLeaf, auth.leaf)) {
    return { ok: false, reason: "deposit created leaf" };
  }
  return { ok: true };
}

export function authFromWitness(
  statement: PoolStatement,
  witness: FriWitness,
  hash: InternalHash = defaultInternalHash(),
): FriAuth {
  if (statement.action === "DEPOSIT") {
    const c = witness.created;
    if (!c) throw new Error("deposit requires created membership witness");
    return {
      leaf: statement.noteCommitment,
      index: c.index,
      path: c.path,
      root: statement.newState.noteRoot,
      nullifier: new Uint8Array(32),
      rho: c.note.rho,
      owner: c.note.ownerSecret,
      amountSats: c.note.amountSats,
      publicDeltaSats: statement.publicAmountSats < 0n ? -statement.publicAmountSats : statement.publicAmountSats,
      amountCommit: statement.amountCommitOut,
      createdLeaf: statement.noteCommitment,
      createdIndex: c.index,
      createdPath: c.path,
    };
  }
  const s = witness.spent;
  if (!s) throw new Error("withdraw requires spent membership witness");
  const change = witness.created;
  return {
    leaf: commitNote(s.note, hash),
    index: s.index,
    path: s.path,
    root: statement.oldState.noteRoot,
    nullifier: nullifierOf(s.note, statement.oldState.poolInstanceId, hash),
    rho: s.note.rho,
    owner: s.note.ownerSecret,
    amountSats: s.note.amountSats,
    publicDeltaSats: statement.publicAmountSats < 0n ? -statement.publicAmountSats : statement.publicAmountSats,
    amountCommit: statement.amountCommitIn,
    createdLeaf: change ? commitNote(change.note, hash) : new Uint8Array(32),
    createdIndex: change ? change.index : 0,
    createdPath: change ? change.path : [],
  };
}

const lagrangeCache = new Map<number, ReturnType<typeof interpolateCircle>>();

function lagrangeAt(k: number, small: CirclePoint[], p: CirclePoint): M31El {
  let interp = lagrangeCache.get(k);
  if (!interp) {
    const e = small.map((_, i) => (i === k ? 1n : 0n));
    interp = interpolateCircle(small, e);
    lagrangeCache.set(k, interp);
  }
  return evalCirclePoly(interp, p);
}

/**
 * AIR numerator on the LDE: N(z) = L_0(z)·cons(T,z) + L_23(z)·seq(T,z).
 * Vanishes on the trace iff conservation and sequence hold; off-domain N is
 * not the zero function, so Q=N/Z is a non-trivial quotient.
 */
/**
 * Cells that may appear on-chain (NFT/kernel-bound). Never reserves, delta,
 * noteCommitment limbs, amount-commit, or nullifier — those stay in verifyFri.
 */
export function onChainCells(statement: PoolStatement, hash: InternalHash = defaultInternalHash()): M31El[] {
  const cells: M31El[] = Array.from({ length: TRACE_LEN }, () => 0n);
  const absNet = statement.publicAmountSats < 0n ? -statement.publicAmountSats : statement.publicAmountSats;
  cells[3] = statement.action === "DEPOSIT" ? 1n : 2n;
  cells[5] = reserveFelt(absNet);
  cells[18] = m31FromBytes(hash.digest(encodeStatement(statement, hash)));
  cells[19] = m31FromBytes(statement.oldState.noteRoot);
  cells[20] = m31FromBytes(statement.newState.noteRoot);
  cells[21] = m31FromBytes(statement.oldState.nullifierRoot);
  cells[22] = m31FromBytes(statement.newState.nullifierRoot);
  cells[23] = reserveFelt(statement.oldState.sequence);
  cells[24] = reserveFelt(statement.newState.sequence);
  const payout = statement.payoutLockingDigest.length === 32 ? statement.payoutLockingDigest : new Uint8Array(32);
  cells[6] = m31FromBytes(payout);
  return cells;
}

export function airNumeratorLde(
  statement: PoolStatement,
  smallDomain: CirclePoint[],
  bigDomain: CirclePoint[],
  hash: InternalHash = defaultInternalHash(),
): M31El[] {
  const cells = onChainCells(statement, hash);
  const tInterp = interpolateCircle(smallDomain, cells);
  const gen = smallDomain[1]!;
  const deposit = statement.action === "DEPOSIT";
  return bigDomain.map((p) => {
    const tp = evalCirclePoly(tInterp, p);
    const tgp = evalCirclePoly(tInterp, addPoints(p, gen));
    const tg2 = evalCirclePoly(tInterp, addPoints(addPoints(p, gen), gen));
    const cons = deposit ? sub(sub(tgp, tp), tg2) : sub(sub(tp, tgp), tg2);
    const seq = sub(sub(tgp, tp), 1n);
    return add(mul(lagrangeAt(0, smallDomain, p), cons), mul(lagrangeAt(23, smallDomain, p), seq));
  });
}

export function airQuotientLde(
  statement: PoolStatement,
  smallDomain: CirclePoint[],
  bigDomain: CirclePoint[],
  hash: InternalHash = defaultInternalHash(),
): { qLde: M31El[]; nLde: M31El[]; zLde: M31El[] } {
  const nLde = airNumeratorLde(statement, smallDomain, bigDomain, hash);
  const zLde = vanishingOnTrace(bigDomain, smallDomain);
  const qLde = nLde.map((n, i) => {
    const z = zLde[i]!;
    if (z === 0n) return 0n;
    return mul(n, inv(z));
  });
  return { qLde, nLde, zLde };
}

/**
 * FRI target (FRI_VERSION 9): C = interpolant(algebraicC residuals), Q = C/Z.
 * Honest residuals vanish, so C is the zero polynomial and Q = 0.
 * Off-trace airNumerator (FRI_VERSION 8) is prior art, not this statement.
 */
export function algebraicCQuotientLde(
  statement: PoolStatement,
  smallDomain: CirclePoint[],
  bigDomain: CirclePoint[],
  hash: InternalHash = defaultInternalHash(),
): { qLde: M31El[]; nLde: M31El[]; zLde: M31El[] } {
  const residuals = algebraicC(publicCells(statement, hash), statement, hash);
  const { qLde, cLde, zLde } = quotientAtDomain(residuals, smallDomain, bigDomain);
  return { qLde, nLde: cLde, zLde };
}

/** C = interpolant(residuals); Q = C/Z on the LDE. Honest residuals vanish ⇒ Q = 0. */
export function quotientAtDomain(
  residuals: M31El[],
  smallDomain: CirclePoint[],
  bigDomain: CirclePoint[],
): { qLde: M31El[]; cLde: M31El[]; zLde: M31El[] } {
  const interp = interpolateCircle(smallDomain, residuals);
  const cLde = bigDomain.map((p) => evalCirclePoly(interp, p));
  const zLde = vanishingOnTrace(bigDomain, smallDomain);
  const qLde = cLde.map((c, i) => {
    const z = zLde[i]!;
    if (z === 0n) return 0n;
    return mul(c, inv(z));
  });
  return { qLde, cLde, zLde };
}

export function publicCells(statement: PoolStatement, hash: InternalHash = defaultInternalHash()): M31El[] {
  const cells: M31El[] = Array.from({ length: TRACE_LEN }, () => 0n);
  const delta = statement.publicAmountSats;
  const absDelta = delta < 0n ? -delta : delta;
  cells[0] = reserveFelt(statement.oldState.reserveSats);
  cells[1] = reserveFelt(statement.newState.reserveSats);
  cells[2] = reserveFelt(absDelta);
  cells[3] = statement.action === "DEPOSIT" ? 1n : 2n;
  const leaf = bytesToFelt4(statement.noteCommitment);
  cells[4] = leaf[0];
  cells[5] = leaf[1];
  cells[6] = leaf[2];
  cells[7] = leaf[3];
  cells[16] = m31FromBytes(
    statement.action === "DEPOSIT" ? statement.amountCommitOut : statement.amountCommitIn,
  );
  cells[17] = m31FromBytes(statement.nullifier);
  cells[18] = m31FromBytes(hash.digest(encodeStatement(statement, hash)));
  cells[19] = m31FromBytes(statement.oldState.noteRoot);
  cells[20] = m31FromBytes(statement.newState.noteRoot);
  cells[21] = m31FromBytes(statement.oldState.nullifierRoot);
  cells[22] = m31FromBytes(statement.newState.nullifierRoot);
  cells[23] = reserveFelt(statement.oldState.sequence);
  cells[24] = reserveFelt(statement.newState.sequence);
  return cells;
}

/** Field-only transition constraints. No Merkle / JS boolean flags. */
export function algebraicC(
  cells: M31El[],
  statement: PoolStatement,
  hash: InternalHash = defaultInternalHash(),
): M31El[] {
  const r = Array.from({ length: TRACE_LEN }, () => 0n);
  const oldR = cells[0]!;
  const newR = cells[1]!;
  const absD = cells[2]!;
  const expectNew = statement.action === "DEPOSIT" ? add(oldR, absD) : sub(oldR, absD);
  r[0] = sub(newR, expectNew);
  r[1] = sub(cells[3]!, statement.action === "DEPOSIT" ? 1n : 2n);
  r[2] = sub(oldR, reserveFelt(statement.oldState.reserveSats));
  r[3] = sub(newR, reserveFelt(statement.newState.reserveSats));
  r[4] = sub(cells[24]!, add(cells[23]!, 1n));
  r[5] = sub(cells[18]!, m31FromBytes(hash.digest(encodeStatement(statement, hash))));
  r[6] =
    statement.action === "DEPOSIT"
      ? sub(absD, reserveFelt(statement.publicAmountSats))
      : sub(absD, reserveFelt(-statement.publicAmountSats));
  return r;
}

/** @deprecated use algebraicC — kept so old imports compile. */
export function constraintResiduals(
  cells: M31El[],
  statement: PoolStatement,
  _auth?: FriAuth,
  _witness?: FriWitness,
): M31El[] {
  return algebraicC(cells, statement);
}

export function buildTrace(
  statement: PoolStatement,
  witness: FriWitness = {},
  hash: InternalHash = defaultInternalHash(),
): PoolTrace {
  const auth = authFromWitness(statement, witness, hash);
  const mem = checkAuthRelation(statement, auth, witness, hash);
  if (!mem.ok) throw new Error(`unsatisfiable pool AIR: ${mem.reason}`);
  const cells = publicCells(statement, hash);
  const residuals = algebraicC(cells, statement, hash);
  return { cells, residuals, auth };
}

export function assertSatisfied(trace: PoolTrace): void {
  for (let i = 0; i < trace.residuals.length; i += 1) {
    if (trace.residuals[i] !== 0n) {
      throw new Error(`unsatisfiable pool AIR at cell ${i}`);
    }
  }
}

export function ldeOfTrace(
  trace: PoolTrace,
  smallDomain: CirclePoint[],
  bigDomain: CirclePoint[],
): M31El[] {
  if (smallDomain.length !== TRACE_LEN) throw new Error("small domain");
  const interp = interpolateCircle(smallDomain, trace.cells);
  return bigDomain.map((p) => evalCirclePoly(interp, p));
}

export function publicEvals(statement: PoolStatement, smallDomain: CirclePoint[], bigDomain: CirclePoint[]): M31El[] {
  const interp = interpolateCircle(smallDomain, publicCells(statement));
  return bigDomain.map((p) => evalCirclePoly(interp, p));
}

export function vanishingOnTrace(bigDomain: CirclePoint[], smallDomain: CirclePoint[]): M31El[] {
  const xs = smallDomain.slice(0, smallDomain.length / 2).map((p) => p.x);
  return bigDomain.map((p) => {
    let acc = 1n;
    for (const x of xs) acc = mul(acc, sub(p.x, x));
    return el(acc);
  });
}

export function checkPublicConservation(statement: PoolStatement): { ok: true } | { ok: false; reason: string } {
  const expect = statement.oldState.reserveSats + statement.publicAmountSats;
  if (statement.newState.reserveSats !== expect) return { ok: false, reason: "conservation" };
  if (statement.newState.sequence <= statement.oldState.sequence) return { ok: false, reason: "sequence" };
  return { ok: true };
}

export { reserveFelt };

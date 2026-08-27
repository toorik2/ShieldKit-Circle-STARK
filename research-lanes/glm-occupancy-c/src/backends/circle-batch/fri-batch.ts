/**
 * FRI_VERSION 10 backend: the same Circle FRI as `../circle/fri.ts`, carrying
 * **N auths** instead of one so a batch-exit round can walk every waiter's note.
 *
 * This is a COPY, deliberately. FRI9 is landed and has on-chain artifacts
 * (A 614b7077, B 81bb2cef, C 06a6078a + 18 tape hops); editing it in place would
 * invalidate them the moment this work has a bug. See FRI10-BATCH-EXIT.md.
 *
 * The AIR, trace and FRI layers are UNCHANGED and shared from ../circle. Auths
 * are side data checked against the statement (`checkAuthRelation`: leaf
 * preimage, amount commit, root == public noteRoot, nativeWalk membership), not
 * AIR constraints - air.ts:34 says so. Carrying N of them is a count change.
 */
import {
  bytesToHex,
  concatBytes,
  eq32,
  readU16BE,
  readU32BE,
  readU64BE,
  writeU16BE,
  writeU32BE,
  writeU64BE,
} from "../../pool/bytes.ts";
import {
  defaultInternalHash,
  resolveInternalHash,
  type InternalHash,
  type InternalHashId,
} from "../circle/internal-hash.ts";
import { commitNote, nullifierOf } from "../../pool/notes.ts";
import { isZero32 } from "../../pool/bytes.ts";
import {
  freshViewingKey,
  maskAuth,
  unmaskAuth,
  viewingCommit,
  openingMaskAt,
  openingMaskCoeffs,
  openingMaskFelt,
  evalMaskPoly,
  VIEWING_PAD_LEN,
} from "../circle/witness-mask.ts";
import { maskAuths, unmaskAuths } from "./auth-pad.ts";
import { encodeStatement, type PoolStatement } from "../../pool/statement.ts";
import { foldPair } from "../circle/fold.ts";
import { addPoints, CIRCLE_GEN, scalarMul, type CirclePoint } from "../circle/group.ts";
import { add, encodeLe, M31, mul, sub, type M31El } from "../circle/m31.ts";
import { MerkleTree } from "../circle/merkle.ts";
import {
  COMMITTED_LAYERS,
  FRI_FINAL,
  FRI_LOG_N,
  FRI_N,
  FRI_QUERIES,
  FRI_VERSION,
  GRIND_BITS,
  TRACE_LEN,
  assertSoundParams,
} from "../circle/params.ts";
import { uniqueQueryIndices } from "../circle/query-sample.ts";
import {
  algebraicC,
  algebraicCQuotientLde,
  assertSatisfied,
  buildTrace,
  checkAuthRelation,
  checkBatchSpends,
  checkPublicAuthRelation,
  checkPublicConservation,
  nativeWalk,
  onChainCells,
  openedNote,
  publicCells,
  publicEvals,
  quotientAtDomain,
  type FriAuth,
  type FriWitness,
} from "../circle/air.ts";
import { evalCirclePoly, interpolateCircle } from "../circle/interpolate.ts";

assertSoundParams();

export type FriQueryLayer = {
  value: M31El;
  partner: M31El;
  path: Uint8Array[];
  partnerPath: Uint8Array[];
};

export type FriQuery = {
  index: number;
  layers: FriQueryLayer[];
  traceValue: M31El;
  tracePath: Uint8Array[];
};

export type FriProof = {
  version: number;
  grindNonce: number;
  layerRoots: Uint8Array[];
  traceRoot: Uint8Array;
  final: M31El[];
  queries: FriQuery[];
  /**
   * All spent notes. auths[0] is the primary spend (what FRI9 calls `auth`);
   * auths[1..] are the batch-exit extras that FRI9 left in verifyFri. Masked with
   * PER-AUTH pads - see auth-pad.ts. Masking them all under one key would be a
   * two-time pad.
   */
  auths: FriAuth[];
  /** In-memory only. Never written by encodeFriProof. */
  viewingKey?: Uint8Array;
  viewingCommit?: Uint8Array;
  authMasked?: boolean;
};

export type ProveFriOpts = { hash?: InternalHashId | InternalHash };
export type VerifyFriOpts = { viewingKey?: Uint8Array; hash?: InternalHashId | InternalHash };

function friHash(opts?: { hash?: InternalHashId | InternalHash }): InternalHash {
  return resolveInternalHash(opts?.hash);
}

function log2n(n: number): number {
  return Math.round(Math.log2(n));
}

function subgroupGen(n: number): CirclePoint {
  const log = log2n(n);
  return scalarMul(CIRCLE_GEN, 2n ** BigInt(31 - log));
}

const domainCache = new Map<number, CirclePoint[]>();

export function circleDomain(n: number = FRI_N): CirclePoint[] {
  const hit = domainCache.get(n);
  if (hit) return hit;
  const g = subgroupGen(n);
  const out: CirclePoint[] = [scalarMul(g, 0n)];
  let acc = g;
  out.push(acc);
  for (let i = 2; i < n; i += 1) {
    acc = addPoints(acc, g);
    out.push(acc);
  }
  domainCache.set(n, out);
  return out;
}

function hashToM31(hash: InternalHash, ...parts: Uint8Array[]): M31El {
  const h = hash.digest(concatBytes(...parts));
  let n = 0n;
  for (let i = 0; i < 8; i += 1) n = (n << 8n) | BigInt(h[i]!);
  return n % M31;
}

function partnerIndex(i: number, n: number): number {
  return (i + n / 2) % n;
}

/** Lay out (i, i+n/2) as merkle siblings so each query sends one shared path. */
function pairOrder(evals: M31El[]): M31El[] {
  const n = evals.length;
  const out: M31El[] = [];
  for (let i = 0; i < n / 2; i += 1) {
    out.push(evals[i]!, evals[i + n / 2]!);
  }
  return out;
}

function pairMerkleIndex(i: number, n: number): number {
  return i < n / 2 ? 2 * i : 2 * (i - n / 2) + 1;
}

function foldLayer(
  domain: CirclePoint[],
  evals: M31El[],
  lambda: M31El,
): { domain: CirclePoint[]; evals: M31El[] } {
  const nextN = evals.length / 2;
  const nextE: M31El[] = [];
  const nextD: CirclePoint[] = [];
  for (let i = 0; i < nextN; i += 1) {
    const j = partnerIndex(i, evals.length);
    const folded = foldPair(domain[i]!, evals[i]!, evals[j]!, lambda);
    nextE.push(folded.value);
    nextD.push(folded.domain);
  }
  return { domain: nextD, evals: nextE };
}

function queryIndices(hash: InternalHash, seed: Uint8Array, n: number, count: number): number[] {
  return uniqueQueryIndices(hash, seed, n, count);
}

function encodeNewtonBlob(vals: M31El[]): Uint8Array {
  const out = new Uint8Array(33 * 4);
  for (let i = 0; i < 33; i += 1) out.set(encodeLe(vals[i] ?? 0n), i * 4);
  return out;
}

function newtonFsBlobs(
  statement: PoolStatement,
  commit: Uint8Array,
  hash: InternalHash,
): { even: Uint8Array; odd: Uint8Array } {
  const maskC = openingMaskFelt(commit, hash);
  const cells = onChainCells(statement, hash).map((v) => add(v, maskC));
  const interp = interpolateCircle(circleDomain(TRACE_LEN), cells);
  return { even: encodeNewtonBlob(interp.even), odd: encodeNewtonBlob(interp.odd) };
}

function queryGrindSeed(
  hash: InternalHash,
  digest: Uint8Array,
  traceRoot: Uint8Array,
  layerRoots: Uint8Array[],
  even: Uint8Array,
  odd: Uint8Array,
): Uint8Array {
  return hash.digest(concatBytes(digest, traceRoot, ...layerRoots, even, odd));
}

function grindOk(hash: InternalHash, digest: Uint8Array, nonce: number): boolean {
  const h = hash.digest(concatBytes(digest, writeU32BE(nonce), new TextEncoder().encode("grind")));
  let bits = 0;
  for (const b of h) {
    for (let i = 7; i >= 0; i -= 1) {
      if (((b >> i) & 1) !== 0) return bits >= GRIND_BITS;
      bits += 1;
      if (bits >= GRIND_BITS) return true;
    }
  }
  return bits >= GRIND_BITS;
}

function findGrind(hash: InternalHash, digest: Uint8Array): number {
  for (let nonce = 0; nonce < 1 << 24; nonce += 1) {
    if (grindOk(hash, digest, nonce)) return nonce;
  }
  throw new Error("grind failed");
}

export function statementToEvals(statement: PoolStatement, domain: CirclePoint[]): M31El[] {
  return publicEvals(statement, circleDomain(TRACE_LEN), domain);
}

export function proveFri(statement: PoolStatement, witness: FriWitness = {}, opts: ProveFriOpts = {}): FriProof {
  const hash = friHash(opts);
  const trace = buildTrace(statement, witness, hash);
  assertSatisfied(trace);
  const digest = hash.digest(encodeStatement(statement, hash));
  const small = circleDomain(TRACE_LEN);
  const big = circleDomain(FRI_N);
  const viewingKey = freshViewingKey();
  const vCommit = viewingCommit(viewingKey, hash);
  const { qLde, zLde } = algebraicCQuotientLde(statement, small, big, hash);
  const onC = openingMaskCoeffs(vCommit, hash, "on");
  const offC = openingMaskCoeffs(vCommit, hash, "off");
  const tLde = qLde.map((q, i) => add(q, add(evalMaskPoly(onC, i), mul(zLde[i]!, evalMaskPoly(offC, i)))));
  const traceTree = new MerkleTree(tLde, hash);

  let domain = big;
  let evals = tLde.slice();
  const trees: MerkleTree[] = [];
  const layers: M31El[][] = [];
  const domains: CirclePoint[][] = [];

  const stopAt = FRI_FINAL;
  while (evals.length > stopAt) {
    const tree = new MerkleTree(pairOrder(evals), hash);
    trees.push(tree);
    layers.push(evals);
    domains.push(domain);
    const lambda = hashToM31(hash, digest, Uint8Array.of(trees.length - 1), tree.root, new TextEncoder().encode("lambda"));
    const next = foldLayer(domain, evals, lambda);
    evals = next.evals;
    domain = next.domain;
  }

  const layerRoots = trees.map((t) => t.root);
  const newton = newtonFsBlobs(statement, vCommit, hash);
  const grindSeed = queryGrindSeed(hash, digest, traceTree.root, layerRoots, newton.even, newton.odd);
  const grindNonce = findGrind(hash, grindSeed);
  const qIdx = queryIndices(
    hash,
    hash.digest(concatBytes(grindSeed, writeU32BE(grindNonce), new TextEncoder().encode("queries"))),
    FRI_N,
    FRI_QUERIES,
  );

  const queries = qIdx.map((start) => {
    const qLayers: FriQueryLayer[] = [];
    let index = start;
    for (let r = 0; r < trees.length; r += 1) {
      const n = layers[r]!.length;
      const i = index % n;
      const j = partnerIndex(i, n);
      qLayers.push({
        value: layers[r]![i]!,
        partner: layers[r]![j]!,
        path: trees[r]!.path(pairMerkleIndex(i, n)).slice(1),
        partnerPath: [],
      });
      index = i % (n / 2);
    }
    return {
      index: start,
      layers: qLayers,
      traceValue: tLde[start]!,
      tracePath: traceTree.path(start),
    };
  });

  return {
    version: FRI_VERSION,
    grindNonce,
    layerRoots,
    traceRoot: traceTree.root,
    final: evals,
    queries,
    auths: [
      trace.auth,
      ...(witness.batch ?? [])
        .filter((m) => !eq32(commitNote(m.note, hash), trace.auth.leaf))
        .map((m) => authFromMembership(statement, m, hash)),
    ],
    viewingKey,
    viewingCommit: vCommit,
    authMasked: false,
  };
}

/** FRI of a caller-supplied quotient LDE (mutation / cheat tests). Still carries auth. */
export function proveFromTLde(
  statement: PoolStatement,
  tLde: M31El[],
  auth: FriAuth,
  opts: ProveFriOpts = {},
): FriProof {
  const hash = friHash(opts);
  const digest = hash.digest(encodeStatement(statement, hash));
  const viewingKey = freshViewingKey();
  const vCommit = viewingCommit(viewingKey, hash);
  const big = circleDomain(FRI_N);
  const small = circleDomain(TRACE_LEN);
  const { zLde } = algebraicCQuotientLde(statement, small, big, hash);
  const onC = openingMaskCoeffs(vCommit, hash, "on");
  const offC = openingMaskCoeffs(vCommit, hash, "off");
  const masked = tLde.map((q, i) => add(q, add(evalMaskPoly(onC, i), mul(zLde[i]!, evalMaskPoly(offC, i)))));
  const traceTree = new MerkleTree(masked, hash);
  let domain = big;
  let evals = masked.slice();
  const trees: MerkleTree[] = [];
  const layers: M31El[][] = [];
  while (evals.length > FRI_FINAL) {
    const tree = new MerkleTree(pairOrder(evals), hash);
    trees.push(tree);
    layers.push(evals);
    const lambda = hashToM31(hash, digest, Uint8Array.of(trees.length - 1), tree.root, new TextEncoder().encode("lambda"));
    const next = foldLayer(domain, evals, lambda);
    evals = next.evals;
    domain = next.domain;
  }
  const layerRoots = trees.map((t) => t.root);
  const newton = newtonFsBlobs(statement, vCommit, hash);
  const grindSeed = queryGrindSeed(hash, digest, traceTree.root, layerRoots, newton.even, newton.odd);
  const grindNonce = findGrind(hash, grindSeed);
  const qIdx = queryIndices(
    hash,
    hash.digest(concatBytes(grindSeed, writeU32BE(grindNonce), new TextEncoder().encode("queries"))),
    FRI_N,
    FRI_QUERIES,
  );
  const queries = qIdx.map((start) => {
    const qLayers: FriQueryLayer[] = [];
    let index = start;
    for (let r = 0; r < trees.length; r += 1) {
      const n = layers[r]!.length;
      const i = index % n;
      const j = partnerIndex(i, n);
      qLayers.push({
        value: layers[r]![i]!,
        partner: layers[r]![j]!,
        path: trees[r]!.path(pairMerkleIndex(i, n)).slice(1),
        partnerPath: [],
      });
      index = i % (n / 2);
    }
    return {
      index: start,
      layers: qLayers,
      traceValue: masked[start]!,
      tracePath: traceTree.path(start),
    };
  });
  return {
    version: FRI_VERSION,
    grindNonce,
    layerRoots,
    traceRoot: traceTree.root,
    final: evals,
    queries,
    auths: [auth],
    viewingKey,
    viewingCommit: vCommit,
    authMasked: false,
  };
}

export function mutateTraceAndProve(statement: PoolStatement, bumpIndex: number, witness: FriWitness): FriProof {
  const small = circleDomain(TRACE_LEN);
  const big = circleDomain(FRI_N);
  const trace = buildTrace(statement, witness);
  assertSatisfied(trace);
  const { qLde } = algebraicCQuotientLde(statement, small, big, defaultInternalHash());
  const bumped = qLde.map((x, i) => (i === bumpIndex % qLde.length ? add(x, 1n) : add(x, 1n)));
  return proveFromTLde(statement, bumped, trace.auth);
}

function authPreimageOpen(auth: FriAuth, hash: InternalHash): boolean {
  try {
    return eq32(auth.leaf, commitNote(openedNote(auth), hash));
  } catch {
    return false;
  }
}

function resolveAuthForVerify(
  statement: PoolStatement,
  proof: FriProof,
  witness: FriWitness,
  opts: VerifyFriOpts,
  hash: InternalHash,
): { ok: true } | { ok: false; reason: string } {
  // A batch proof publishes every spent note, so the batch relation can be
  // satisfied without a witness. Merge the published auths in, or
  // checkAuthRelation takes the single-note branch and rejects an honest batch
  // with "withdraw exceeds note" (air.ts:144) - auths[0] only covers its own
  // amount, not the whole public net.
  const effective: FriWitness =
    !proof.authMasked && proof.auths.length > 1 && !witness.batch
      ? {
          ...witness,
          batch: proof.auths.map((a) => ({ note: openedNote(a), index: a.index, path: a.path })),
        }
      : witness;
  const key = opts.viewingKey ?? (proof.authMasked ? undefined : proof.viewingKey);
  if (key) {
    if (key.length !== VIEWING_PAD_LEN) return { ok: false, reason: "viewing key" };
    const commit = proof.viewingCommit ?? viewingCommit(key, hash);
    if (!eq32(viewingCommit(key, hash), commit)) return { ok: false, reason: "viewing key" };
    const opened = proof.authMasked ? unmaskAuths(proof.auths, key)[0]! : proof.auths[0]!;
    return checkAuthRelation(statement, opened, effective, hash);
  }
  if (authPreimageOpen(proof.auths[0]!, hash)) {
    return checkAuthRelation(statement, proof.auths[0]!, effective, hash);
  }
  return checkPublicAuthRelation(statement, proof.auths[0]!, hash);
}

/**
 * Opening-only verifier. FRI target is C/Z where C interpolates algebraicC
 * residuals (FRI_VERSION 9). Membership is a sibling nativeWalk.
 * Published encodings mask the note preimage; pass `viewingKey` to open it.
 */
export function verifyFri(
  statement: PoolStatement,
  proof: FriProof,
  witness: FriWitness = {},
  opts: VerifyFriOpts = {},
): { ok: true } | { ok: false; reason: string } {
  if (proof.version !== FRI_VERSION) return { ok: false, reason: "version" };
  if (proof.queries.length !== FRI_QUERIES) return { ok: false, reason: "query count" };
  if (proof.final.length !== FRI_FINAL) return { ok: false, reason: "final width" };
  if (!proof.auths || proof.auths.length === 0) return { ok: false, reason: "missing auth" };
  // INVARIANT 3: N is pinned by withdrawalCount, which lives in PAA1 (state.ts:74)
  // and is bound on chain by the covenant. Truncating or padding the list fails.
  const declared = declaredAuthCount(statement);
  if (proof.auths.length !== declared) {
    return { ok: false, reason: `auth count ${proof.auths.length} != declared ${declared}` };
  }

  const hash = friHash(opts);
  const cons = checkPublicConservation(statement);
  if (!cons.ok) return cons;

  // INVARIANT 2: every published auth is checked.
  //
  // The auths are OTP-masked in the published encoding, so they can only be read
  // with the viewing key. Resolve them ONCE here; everything below works from the
  // opened list. The previous gate was `!proof.authMasked`, which is never true
  // for a published proof - so these checks were unreachable exactly where they
  // mattered, key or no key.
  const key = opts.viewingKey ?? (proof.authMasked ? undefined : proof.viewingKey);
  const opened: FriAuth[] | undefined = proof.authMasked
    ? key
      ? unmaskAuths(proof.auths, key, hash)
      : undefined
    : proof.auths;

  // Public checks run ALWAYS, masked or not: leaf, index, path and nullifier are
  // never masked, so membership, duplicates and the root fold need no key. This
  // is what a verifier reading only the published proof can establish.
  const pub = checkAuthsPublicly(statement, proof.auths, hash);
  if (!pub.ok) return pub;

  // Hand FRI9's own audited path the batch, so its single-note fallthrough
  // ("withdraw exceeds note") cannot fire on an honest batch.
  const fromProof: FriWitness | undefined = opened
    ? {
        spent: {
          note: openedNote(opened[0]!),
          index: opened[0]!.index,
          path: opened[0]!.path,
        },
        batch: opened.map((a) => ({ note: openedNote(a), index: a.index, path: a.path })),
      }
    : undefined;

  const auth = resolveAuthForVerify(statement, proof, fromProof ?? witness, opts, hash);
  if (!auth.ok) return auth;

  if (opened && fromProof) {
    const all = checkBatchSpends(statement, fromProof.batch!, hash);
    if (!all.ok) return all;
    // and with the key: leaf opens to its preimage, the nullifier derives from
    // it, amounts are positive, and the sum equals the public net
    const strict = checkAuthsAgainstStatement(statement, opened, hash);
    if (!strict.ok) return strict;
  }
  if (witness.batch && witness.batch.length > 0) {
    const batch = checkBatchSpends(statement, witness.batch, hash);
    if (!batch.ok) return batch;
  }

  const cVec = algebraicC(publicCells(statement, hash), statement, hash);
  if (cVec.some((r) => r !== 0n)) return { ok: false, reason: "algebraicC" };
  const { nLde, zLde } = algebraicCQuotientLde(statement, circleDomain(TRACE_LEN), circleDomain(FRI_N), hash);

  const digest = hash.digest(encodeStatement(statement, hash));
  const commit = proof.viewingCommit && proof.viewingCommit.length === 32 ? proof.viewingCommit : new Uint8Array(32);
  const newton = newtonFsBlobs(statement, commit, hash);
  const grindSeed = queryGrindSeed(hash, digest, proof.traceRoot, proof.layerRoots, newton.even, newton.odd);
  if (!grindOk(hash, grindSeed, proof.grindNonce)) return { ok: false, reason: "grind" };
  const expectedIdx = queryIndices(
    hash,
    hash.digest(concatBytes(grindSeed, writeU32BE(proof.grindNonce), new TextEncoder().encode("queries"))),
    FRI_N,
    FRI_QUERIES,
  );

  for (let q = 0; q < proof.queries.length; q += 1) {
    const query = proof.queries[q]!;
    if (query.index !== expectedIdx[q]) return { ok: false, reason: `query ${q} index` };
    if (!MerkleTree.verify(query.traceValue, query.index, query.tracePath, proof.traceRoot, hash)) {
      return { ok: false, reason: "trace merkle" };
    }
    const nAt = nLde[query.index]!;
    const zAt = zLde[query.index]!;
    const openMask = proof.viewingCommit
      ? openingMaskAt(proof.viewingCommit, query.index, hash, zAt)
      : 0n;
    if (mul(sub(query.traceValue, openMask), zAt) !== nAt) {
      return { ok: false, reason: "N != Q*Z" };
    }
    if (query.layers[0]!.value !== query.traceValue) {
      return { ok: false, reason: "FRI layer0 != Q(z)" };
    }

    let domain = circleDomain(FRI_N);
    let index = query.index;
    for (let r = 0; r < query.layers.length; r += 1) {
      const n = FRI_N >> r;
      const i = index % n;
      const j = partnerIndex(i, n);
      const layer = query.layers[r]!;
      if (!MerkleTree.verifyPaired(layer.value, layer.partner, i, n, layer.path, proof.layerRoots[r]!, hash)) {
        return { ok: false, reason: `merkle T L${r}` };
      }
      const lambda = hashToM31(
        hash,
        digest,
        Uint8Array.of(r),
        proof.layerRoots[r]!,
        new TextEncoder().encode("lambda"),
      );
      const lo = Math.min(i, j);
      const valLo = i === lo ? layer.value : layer.partner;
      const valHi = i === lo ? layer.partner : layer.value;
      const folded = foldPair(domain[lo]!, valLo, valHi, lambda);
      if (r + 1 === query.layers.length) {
        const fi = i % (n / 2);
        if (fi >= proof.final.length || proof.final[fi] !== folded.value) {
          return { ok: false, reason: "final fold" };
        }
      } else {
        const nxt = query.layers[r + 1]!;
        if (nxt.value !== folded.value && nxt.partner !== folded.value) {
          return { ok: false, reason: `fold mismatch L${r}` };
        }
      }
      const nextDomain: CirclePoint[] = [];
      for (let k = 0; k < n / 2; k += 1) {
        nextDomain.push(foldPair(domain[k]!, 0n, 0n, 0n).domain);
      }
      domain = nextDomain;
      index = i % (n / 2);
    }
  }
  return { ok: true };
}

function encodeAuth(a: FriAuth, commit: Uint8Array): Uint8Array {
  return concatBytes(
    writeU16BE(a.index),
    Uint8Array.of(a.path.length),
    a.leaf,
    a.root,
    a.nullifier,
    a.amountCommit,
    writeU16BE(a.createdIndex),
    Uint8Array.of(a.createdPath.length),
    a.createdLeaf,
    commit.length === 32 ? commit : new Uint8Array(32),
    a.rho,
    a.owner,
    writeU64BE(a.amountSats),
    writeU64BE(a.publicDeltaSats),
    ...a.path,
    ...a.createdPath,
  );
}

function decodeAuth(bytes: Uint8Array, start: number): { auth: FriAuth; viewingCommit: Uint8Array; next: number } {
  let o = start;
  const index = readU16BE(bytes, o);
  o += 2;
  const nP = bytes[o++]!;
  const leaf = bytes.slice(o, o + 32);
  o += 32;
  const root = bytes.slice(o, o + 32);
  o += 32;
  const nullifier = bytes.slice(o, o + 32);
  o += 32;
  const amountCommit = bytes.slice(o, o + 32);
  o += 32;
  const createdIndex = readU16BE(bytes, o);
  o += 2;
  const nC = bytes[o++]!;
  const createdLeaf = bytes.slice(o, o + 32);
  o += 32;
  const commit = bytes.slice(o, o + 32);
  o += 32;
  const rho = bytes.slice(o, o + 32);
  o += 32;
  const owner = bytes.slice(o, o + 32);
  o += 32;
  const amountSats = readU64BE(bytes, o);
  o += 8;
  const publicDeltaSats = readU64BE(bytes, o);
  o += 8;
  const path: Uint8Array[] = [];
  for (let i = 0; i < nP; i += 1) {
    path.push(bytes.slice(o, o + 32));
    o += 32;
  }
  const createdPath: Uint8Array[] = [];
  for (let i = 0; i < nC; i += 1) {
    createdPath.push(bytes.slice(o, o + 32));
    o += 32;
  }
  return {
    auth: { leaf, index, path, root, nullifier, rho, owner, amountSats, publicDeltaSats, amountCommit, createdLeaf, createdIndex, createdPath },
    viewingCommit: commit,
    next: o,
  };
}

/**
 * INVARIANT 2: validate EVERY auth against the statement, not just auths[0].
 * Mirrors checkBatchSpends, but reads the auths carried in the PUBLISHED proof
 * rather than needing the witness - that is the whole point of FRI10. Returns on
 * the first failure, but only after every auth has been reached in turn: the loop
 * never short-circuits on success.
 */
/**
 * The checks a verifier can run with NO viewing key.
 *
 * maskAuth (witness-mask.ts:31) masks rho, owner, amountSats and publicDeltaSats
 * and nothing else, so leaf, index, path and nullifier are public. That is enough
 * for membership, duplicate detection and the nullifier-root fold. It is NOT
 * enough for amounts, so the sum check lives in the keyed function below.
 */
export function checkAuthsPublicly(
  statement: PoolStatement,
  auths: readonly FriAuth[],
  hash: InternalHash,
): { ok: true } | { ok: false; reason: string } {
  if (auths.length === 0) return { ok: false, reason: "no auths" };
  const root = statement.oldState.noteRoot;
  const seen = new Set<number>();
  for (const [i, a] of auths.entries()) {
    if (seen.has(a.index)) return { ok: false, reason: `duplicate note index at auth ${i}` };
    seen.add(a.index);
    if (!nativeWalk(a.leaf, a.index, a.path, root, hash)) {
      return { ok: false, reason: `auth ${i} membership` };
    }
    if (isZero32(a.nullifier)) return { ok: false, reason: `auth ${i} nullifier zero` };
  }
  // The accumulator must advance by exactly these nullifiers, in insertion order.
  let acc = statement.oldState.nullifierRoot;
  for (const a of auths) acc = hash.digest(concatBytes(acc, a.nullifier));
  if (!eq32(acc, statement.newState.nullifierRoot)) {
    return { ok: false, reason: "nullifier root is not the fold of these auths" };
  }
  return { ok: true };
}

export function checkAuthsAgainstStatement(
  statement: PoolStatement,
  auths: readonly FriAuth[],
  hash: InternalHash,
): { ok: true } | { ok: false; reason: string } {
  if (auths.length === 0) return { ok: false, reason: "no auths" };
  const root = statement.oldState.noteRoot;
  const absNet = statement.publicAmountSats < 0n ? -statement.publicAmountSats : 0n;
  const seen = new Set<number>();
  let sum = 0n;
  for (const [i, a] of auths.entries()) {
    if (seen.has(a.index)) return { ok: false, reason: `duplicate note index at auth ${i}` };
    seen.add(a.index);
    if (a.amountSats <= 0n) return { ok: false, reason: `auth ${i} amount` };
    // leaf must open to the preimage carried in the auth
    if (!eq32(a.leaf, commitNote(openedNote(a), hash))) {
      return { ok: false, reason: `auth ${i} leaf preimage` };
    }
    if (!nativeWalk(a.leaf, a.index, a.path, root, hash)) {
      return { ok: false, reason: `auth ${i} membership` };
    }
    const nf = nullifierOf(openedNote(a), statement.oldState.poolInstanceId, hash);
    if (isZero32(nf)) return { ok: false, reason: `auth ${i} nullifier` };
    if (!eq32(nf, a.nullifier)) return { ok: false, reason: `auth ${i} nullifier mismatch` };
    sum += a.amountSats;
  }
  if (absNet > 0n && sum !== absNet) {
    return { ok: false, reason: `auth sum ${sum} != public net ${absNet}` };
  }
  // The nullifier accumulator must ACTUALLY advance by these nullifiers.
  //
  // Without this a prover sets newState.nullifierRoot to anything they like and
  // the spends are never recorded - a double-spend across transactions. Nothing
  // else covers it: checkBatchSpends does not fold, AIR cells 21/22 hold both
  // roots but appear in no constraint, and FRI9's published proof carries one
  // auth so it cannot fold N. On chain the audited note-auth kernel enforces one
  // step, which is why landed single-note withdrawals are safe - but a batch has
  // no such kernel, and a pool that does not walk notes on chain at all has none
  // either. Publishing every auth is what makes this checkable here.
  //
  // Order matters: NullifierSet.root is a running fold in INSERTION order, so the
  // auths must be in the order the pool inserted them.
  let acc = statement.oldState.nullifierRoot;
  for (const a of auths) acc = hash.digest(concatBytes(acc, a.nullifier));
  if (!eq32(acc, statement.newState.nullifierRoot)) {
    return { ok: false, reason: "nullifier root is not the fold of these auths" };
  }
  return { ok: true };
}

/** A batch entry as a FriAuth. Mirrors authFromWitness's withdraw branch. */
export function authFromMembership(
  statement: PoolStatement,
  m: { note: { rho: Uint8Array; ownerSecret: Uint8Array; amountSats: bigint }; index: number; path: Uint8Array[] },
  hash: InternalHash,
): FriAuth {
  return {
    leaf: commitNote(m.note as never, hash),
    index: m.index,
    path: m.path,
    root: statement.oldState.noteRoot,
    nullifier: nullifierOf(m.note as never, statement.oldState.poolInstanceId, hash),
    rho: m.note.rho,
    owner: m.note.ownerSecret,
    amountSats: m.note.amountSats,
    publicDeltaSats:
      statement.publicAmountSats < 0n ? -statement.publicAmountSats : statement.publicAmountSats,
    amountCommit: statement.amountCommitIn,
    createdLeaf: new Uint8Array(32),
    createdIndex: 0,
    createdPath: [],
  } as FriAuth;
}

/** Spent-note count the statement commits to: withdrawalCount delta, inside PAA1. */
export function declaredAuthCount(statement: PoolStatement): number {
  const d = statement.newState.withdrawalCount - statement.oldState.withdrawalCount;
  return d > 0n ? Number(d) : 1;
}

export function encodeFriProof(p: FriProof): Uint8Array {
  const key = p.viewingKey && p.viewingKey.length === VIEWING_PAD_LEN ? p.viewingKey : freshViewingKey();
  const commit = p.viewingCommit && p.viewingCommit.length === 32 ? p.viewingCommit : viewingCommit(key);
  const published = p.authMasked ? p.auths : maskAuths(p.auths, key);
  const parts: Uint8Array[] = [
    Uint8Array.of(p.version, p.layerRoots.length, p.final.length, p.queries.length),
    writeU32BE(p.grindNonce),
    p.traceRoot,
    // auth count then each auth. The count is checked against withdrawalCount at
    // verify, so this length prefix is a framing aid, not the binding.
    Uint8Array.of(published.length & 0xff),
    ...published.map((a) => encodeAuth(a, commit)),
  ];
  for (const r of p.layerRoots) parts.push(r);
  for (const f of p.final) parts.push(encodeLe(f));
  for (const q of p.queries) {
    parts.push(writeU16BE(q.index));
    parts.push(encodeLe(q.traceValue));
    parts.push(Uint8Array.of(q.tracePath.length));
    for (const node of q.tracePath) parts.push(node);
    parts.push(Uint8Array.of(q.layers.length));
    for (const layer of q.layers) {
      parts.push(encodeLe(layer.value), encodeLe(layer.partner));
      parts.push(Uint8Array.of(layer.path.length));
      for (const node of layer.path) parts.push(node);
      parts.push(Uint8Array.of(layer.partnerPath.length));
      for (const node of layer.partnerPath) parts.push(node);
    }
  }
  return concatBytes(...parts);
}

export function decodeFriProof(bytes: Uint8Array): FriProof {
  let o = 0;
  const version = bytes[o++]!;
  const nRoots = bytes[o++]!;
  const nFinal = bytes[o++]!;
  const nQ = bytes[o++]!;
  const grindNonce = readU32BE(bytes, o);
  o += 4;
  const traceRoot = bytes.slice(o, o + 32);
  o += 32;
  const nAuths = bytes[o++]!;
  if (nAuths === 0) throw new Error("proof carries no auth");
  const auths: FriAuth[] = [];
  let commit = new Uint8Array(32);
  for (let i = 0; i < nAuths; i += 1) {
    const d = decodeAuth(bytes, o);
    auths.push(d.auth);
    commit = d.viewingCommit;
    o = d.next;
  }
  const layerRoots: Uint8Array[] = [];
  for (let i = 0; i < nRoots; i += 1) {
    layerRoots.push(bytes.slice(o, o + 32));
    o += 32;
  }
  const readEl = (): M31El => {
    let v = 0n;
    for (let k = 3; k >= 0; k -= 1) v = (v << 8n) | BigInt(bytes[o + k]!);
    o += 4;
    return v;
  };
  const final: M31El[] = [];
  for (let i = 0; i < nFinal; i += 1) final.push(readEl());
  const queries: FriQuery[] = [];
  for (let q = 0; q < nQ; q += 1) {
    const index = readU16BE(bytes, o);
    o += 2;
    const traceValue = readEl();
    const nTP = bytes[o++]!;
    const tracePath: Uint8Array[] = [];
    for (let i = 0; i < nTP; i += 1) {
      tracePath.push(bytes.slice(o, o + 32));
      o += 32;
    }
    const nL = bytes[o++]!;
    const layers: FriQueryLayer[] = [];
    for (let r = 0; r < nL; r += 1) {
      const value = readEl();
      const partner = readEl();
      const nP = bytes[o++]!;
      const path: Uint8Array[] = [];
      for (let i = 0; i < nP; i += 1) {
        path.push(bytes.slice(o, o + 32));
        o += 32;
      }
      const nPP = bytes[o++]!;
      const partnerPath: Uint8Array[] = [];
      for (let i = 0; i < nPP; i += 1) {
        partnerPath.push(bytes.slice(o, o + 32));
        o += 32;
      }
      layers.push({ value, partner, path, partnerPath });
    }
    queries.push({ index, layers, traceValue, tracePath });
  }
  return {
    version,
    grindNonce,
    layerRoots,
    traceRoot,
    final,
    queries,
    auths,
    viewingCommit: commit,
    authMasked: true,
  };
}

export function unmaskFriProof(
  proof: FriProof,
  key: Uint8Array,
  hash: InternalHash = defaultInternalHash(),
): FriProof {
  if (key.length !== VIEWING_PAD_LEN) throw new Error("viewing key width");
  if (proof.viewingCommit && !eq32(viewingCommit(key, hash), proof.viewingCommit)) {
    throw new Error("viewing key");
  }
  return {
    ...proof,
    auths: proof.authMasked ? unmaskAuths(proof.auths, key, hash) : proof.auths,
    viewingKey: key,
    authMasked: false,
  };
}

export function proofByteLength(p: FriProof): number {
  return encodeFriProof(p).length;
}

export { add, bytesToHex, COMMITTED_LAYERS, FRI_LOG_N, FRI_N, FRI_QUERIES, TRACE_LEN };
export { firstFoldOrbit, sampleUniqueQueryIndices, uniqueQueryIndices } from "../circle/query-sample.ts";
export {
  freshViewingKey,
  unmaskAuth,
  viewingCommit,
  openingMaskFelt,
  openingMaskAt,
  openingMaskCoeffs,
  evalMaskPoly,
  OPEN_MASK_DEGREE,
  OPEN_MASK_OFF_DEGREE,
  VIEWING_PAD_LEN,
} from "../circle/witness-mask.ts";
export {
  DEFAULT_INTERNAL_HASH_ID,
  INTERNAL_HASH_IDS,
  defaultInternalHash,
  internalHash,
  resolveInternalHash,
  type InternalHash,
  type InternalHashId,
} from "../circle/internal-hash.ts";
export type { FriWitness, FriAuth };
export { airQuotientLde, algebraicC, algebraicCQuotientLde, buildTrace, nativeWalk, publicCells, publicEvals, quotientAtDomain, wBatchExit, wDeposit, wWithdraw } from "../circle/air.ts";
export { interpolateCircle, evalCirclePoly } from "../circle/interpolate.ts";

/**
 * Named exports for the batch family, so callers cannot accidentally reach for
 * FRI9's verifyFri and get single-auth semantics.
 */
export const proveFriBatch = proveFri;
export const verifyFriBatch = verifyFri;
export const encodeFriBatchProof = encodeFriProof;
export const decodeFriBatchProof = decodeFriProof;

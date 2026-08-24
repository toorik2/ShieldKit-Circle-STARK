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
} from "./internal-hash.ts";
import { commitNote } from "../../pool/notes.ts";
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
} from "./witness-mask.ts";
import { encodeStatement, type PoolStatement } from "../../pool/statement.ts";
import { foldPair, foldPairQm31, foldPairSecure } from "./fold.ts";
import { addPoints, CIRCLE_GEN, scalarMul, type CirclePoint } from "./group.ts";
import { add, encodeLe, M31, mul, sub, type M31El } from "./m31.ts";
import {
  decodeQm31,
  encodeQm31,
  hashBytesToQm31,
  qmEq,
  type QM31El,
} from "./qm31.ts";
import { MerkleTree } from "./merkle.ts";
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
} from "./params.ts";
import { uniqueQueryIndices } from "./query-sample.ts";
import {
  algebraicCQuotientLde,
  algebraicC,
  assertSatisfied,
  buildTrace,
  checkAuthRelation,
  checkBatchSpends,
  checkPublicAuthRelation,
  checkPublicConservation,
  onChainCells,
  openedNote,
  publicCells,
  publicEvals,
  quotientAtDomain,
  type FriAuth,
  type FriWitness,
} from "./air.ts";
import { evalCirclePoly, interpolateCircle } from "./interpolate.ts";

assertSoundParams();

export type FriLayerFelt = M31El | QM31El;

export type FriQueryLayer = {
  value: FriLayerFelt;
  partner: FriLayerFelt;
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
  final: QM31El[];
  queries: FriQuery[];
  auth: FriAuth;
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

function hashToQm31(hash: InternalHash, ...parts: Uint8Array[]): QM31El {
  return hashBytesToQm31(hash.digest(concatBytes(...parts)));
}

export function isQm31(v: FriLayerFelt): v is QM31El {
  return Array.isArray(v);
}

function encodeLayerFelt(v: FriLayerFelt): Uint8Array {
  return isQm31(v) ? encodeQm31(v) : encodeLe(v);
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

function foldLayerSecure(
  domain: CirclePoint[],
  evals: M31El[],
  lambda: QM31El,
): { domain: CirclePoint[]; evals: QM31El[] } {
  const nextN = evals.length / 2;
  const nextE: QM31El[] = [];
  const nextD: CirclePoint[] = [];
  for (let i = 0; i < nextN; i += 1) {
    const j = partnerIndex(i, evals.length);
    const folded = foldPairSecure(domain[i]!, evals[i]!, evals[j]!, lambda);
    nextE.push(folded.value);
    nextD.push(folded.domain);
  }
  return { domain: nextD, evals: nextE };
}

function foldLayerQm31(
  domain: CirclePoint[],
  evals: QM31El[],
  lambda: QM31El,
): { domain: CirclePoint[]; evals: QM31El[] } {
  const nextN = evals.length / 2;
  const nextE: QM31El[] = [];
  const nextD: CirclePoint[] = [];
  for (let i = 0; i < nextN; i += 1) {
    const j = partnerIndex(i, evals.length);
    const folded = foldPairQm31(domain[i]!, evals[i]!, evals[j]!, lambda);
    nextE.push(folded.value);
    nextD.push(folded.domain);
  }
  return { domain: nextD, evals: nextE };
}

function commitAndFold(
  hash: InternalHash,
  digest: Uint8Array,
  domain0: CirclePoint[],
  evals0: M31El[],
): {
  trees: MerkleTree[];
  layer0: M31El[];
  qmLayers: QM31El[][];
  final: QM31El[];
  domains: CirclePoint[][];
} {
  const trees: MerkleTree[] = [];
  const domains: CirclePoint[][] = [];
  const qmLayers: QM31El[][] = [];
  const tree0 = new MerkleTree(pairOrder(evals0), hash);
  trees.push(tree0);
  domains.push(domain0);
  const λ0 = hashToQm31(hash, digest, Uint8Array.of(0), tree0.root, new TextEncoder().encode("lambda"));
  let folded = foldLayerSecure(domain0, evals0, λ0);
  let domain = folded.domain;
  let evalsQ = folded.evals;
  while (evalsQ.length > FRI_FINAL) {
    const tree = new MerkleTree(pairOrderQm(evalsQ), hash);
    trees.push(tree);
    qmLayers.push(evalsQ);
    domains.push(domain);
    const lambda = hashToQm31(
      hash,
      digest,
      Uint8Array.of(trees.length - 1),
      tree.root,
      new TextEncoder().encode("lambda"),
    );
    const next = foldLayerQm31(domain, evalsQ, lambda);
    evalsQ = next.evals;
    domain = next.domain;
  }
  return { trees, layer0: evals0, qmLayers, final: evalsQ, domains };
}

function openQuery(
  start: number,
  tLde: M31El[],
  layer0: M31El[],
  qmLayers: QM31El[][],
  trees: MerkleTree[],
  traceTree: MerkleTree,
): FriQuery {
  const qLayers: FriQueryLayer[] = [];
  let index = start;
  const n0 = layer0.length;
  const i0 = index % n0;
  const j0 = partnerIndex(i0, n0);
  qLayers.push({
    value: layer0[i0]!,
    partner: layer0[j0]!,
    path: trees[0]!.path(pairMerkleIndex(i0, n0)).slice(1),
    partnerPath: [],
  });
  index = i0 % (n0 / 2);
  for (let r = 0; r < qmLayers.length; r += 1) {
    const layer = qmLayers[r]!;
    const n = layer.length;
    const i = index % n;
    const j = partnerIndex(i, n);
    qLayers.push({
      value: layer[i]!,
      partner: layer[j]!,
      path: trees[r + 1]!.path(pairMerkleIndex(i, n)).slice(1),
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
}

function pairOrderQm(evals: QM31El[]): Uint8Array[] {
  const n = evals.length;
  const out: Uint8Array[] = [];
  for (let i = 0; i < n / 2; i += 1) {
    out.push(encodeQm31(evals[i]!), encodeQm31(evals[i + n / 2]!));
  }
  return out;
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

  const folded = commitAndFold(hash, digest, big, tLde.slice());
  const trees = folded.trees;
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

  const queries = qIdx.map((start) =>
    openQuery(start, tLde, folded.layer0, folded.qmLayers, trees, traceTree),
  );

  return {
    version: FRI_VERSION,
    grindNonce,
    layerRoots,
    traceRoot: traceTree.root,
    final: folded.final,
    queries,
    auth: trace.auth,
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
  const folded = commitAndFold(hash, digest, big, masked);
  const trees = folded.trees;
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
  const queries = qIdx.map((start) =>
    openQuery(start, masked, folded.layer0, folded.qmLayers, trees, traceTree),
  );
  return {
    version: FRI_VERSION,
    grindNonce,
    layerRoots,
    traceRoot: traceTree.root,
    final: folded.final,
    queries,
    auth,
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
  const key = opts.viewingKey ?? (proof.authMasked ? undefined : proof.viewingKey);
  if (key) {
    if (key.length !== VIEWING_PAD_LEN) return { ok: false, reason: "viewing key" };
    const commit = proof.viewingCommit ?? viewingCommit(key, hash);
    if (!eq32(viewingCommit(key, hash), commit)) return { ok: false, reason: "viewing key" };
    const opened = proof.authMasked ? unmaskAuth(proof.auth, key) : proof.auth;
    return checkAuthRelation(statement, opened, witness, hash);
  }
  if (authPreimageOpen(proof.auth, hash)) {
    return checkAuthRelation(statement, proof.auth, witness, hash);
  }
  return checkPublicAuthRelation(statement, proof.auth, hash);
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
  if (!proof.auth) return { ok: false, reason: "missing auth" };

  const hash = friHash(opts);
  const cons = checkPublicConservation(statement);
  if (!cons.ok) return cons;
  const auth = resolveAuthForVerify(statement, proof, witness, opts, hash);
  if (!auth.ok) return auth;
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
      if (r === 0) {
        if (isQm31(layer.value) || isQm31(layer.partner)) return { ok: false, reason: "layer0 not M31" };
        if (!MerkleTree.verifyPaired(layer.value, layer.partner, i, n, layer.path, proof.layerRoots[r]!, hash)) {
          return { ok: false, reason: `merkle T L${r}` };
        }
      } else {
        if (!isQm31(layer.value) || !isQm31(layer.partner)) return { ok: false, reason: `layer${r} not QM31` };
        if (
          !MerkleTree.verifyPairedRaw(
            encodeQm31(layer.value),
            encodeQm31(layer.partner),
            i,
            n,
            layer.path,
            proof.layerRoots[r]!,
            hash,
          )
        ) {
          return { ok: false, reason: `merkle T L${r}` };
        }
      }
      const lambda = hashToQm31(
        hash,
        digest,
        Uint8Array.of(r),
        proof.layerRoots[r]!,
        new TextEncoder().encode("lambda"),
      );
      const lo = Math.min(i, j);
      const valLo = i === lo ? layer.value : layer.partner;
      const valHi = i === lo ? layer.partner : layer.value;
      const folded =
        r === 0
          ? foldPairSecure(domain[lo]!, valLo as M31El, valHi as M31El, lambda)
          : foldPairQm31(domain[lo]!, valLo as QM31El, valHi as QM31El, lambda);
      if (r + 1 === query.layers.length) {
        const fi = i % (n / 2);
        if (fi >= proof.final.length || !qmEq(proof.final[fi]!, folded.value)) {
          return { ok: false, reason: "final fold" };
        }
      } else {
        const nxt = query.layers[r + 1]!;
        if (!isQm31(nxt.value) || !isQm31(nxt.partner)) return { ok: false, reason: `fold next L${r}` };
        if (!qmEq(nxt.value, folded.value) && !qmEq(nxt.partner, folded.value)) {
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

export function encodeFriProof(p: FriProof): Uint8Array {
  const key = p.viewingKey && p.viewingKey.length === VIEWING_PAD_LEN ? p.viewingKey : freshViewingKey();
  const commit = p.viewingCommit && p.viewingCommit.length === 32 ? p.viewingCommit : viewingCommit(key);
  const published = p.authMasked ? p.auth : maskAuth(p.auth, key);
  const parts: Uint8Array[] = [
    Uint8Array.of(p.version, p.layerRoots.length, p.final.length, p.queries.length),
    writeU32BE(p.grindNonce),
    p.traceRoot,
    encodeAuth(published, commit),
  ];
  for (const r of p.layerRoots) parts.push(r);
  for (const f of p.final) parts.push(encodeQm31(f));
  for (const q of p.queries) {
    parts.push(writeU16BE(q.index));
    parts.push(encodeLe(q.traceValue));
    parts.push(Uint8Array.of(q.tracePath.length));
    for (const node of q.tracePath) parts.push(node);
    parts.push(Uint8Array.of(q.layers.length));
    for (let r = 0; r < q.layers.length; r += 1) {
      const layer = q.layers[r]!;
      parts.push(encodeLayerFelt(layer.value), encodeLayerFelt(layer.partner));
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
  const decodedAuth = decodeAuth(bytes, o);
  const auth = decodedAuth.auth;
  const commit = decodedAuth.viewingCommit;
  o = decodedAuth.next;
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
  const readQm = (): QM31El => {
    const v = decodeQm31(bytes, o);
    o += 16;
    return v;
  };
  const final: QM31El[] = [];
  for (let i = 0; i < nFinal; i += 1) final.push(readQm());
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
      const value = r === 0 ? readEl() : readQm();
      const partner = r === 0 ? readEl() : readQm();
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
    auth,
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
    auth: proof.authMasked ? unmaskAuth(proof.auth, key) : proof.auth,
    viewingKey: key,
    authMasked: false,
  };
}

export function proofByteLength(p: FriProof): number {
  return encodeFriProof(p).length;
}

export { add, bytesToHex, COMMITTED_LAYERS, FRI_LOG_N, FRI_N, FRI_QUERIES, TRACE_LEN };
export { firstFoldOrbit, sampleUniqueQueryIndices, uniqueQueryIndices } from "./query-sample.ts";
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
} from "./witness-mask.ts";
export {
  DEFAULT_INTERNAL_HASH_ID,
  INTERNAL_HASH_IDS,
  defaultInternalHash,
  internalHash,
  resolveInternalHash,
  type InternalHash,
  type InternalHashId,
} from "./internal-hash.ts";
export type { FriWitness, FriAuth };
export { airQuotientLde, algebraicC, algebraicCQuotientLde, buildTrace, nativeWalk, publicCells, publicEvals, quotientAtDomain, wBatchExit, wDeposit, wWithdraw } from "./air.ts";
export { interpolateCircle, evalCirclePoly } from "./interpolate.ts";

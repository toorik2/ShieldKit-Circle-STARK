/**
 * SHA-256 note-auth AIR over private witness.
 * Witness = amount8 / rho / owner (never unlocking). Public outs = amountCommit, leaf, nf.
 * Residuals vanish iff the three tagged SHA-256 equalities hold.
 * Occupancy algebraicC / fold / leftover / TRACE / q / grind / FRI10 stay in their files.
 */
import { commitAmount, HASH_AMOUNT_TAG } from "../amounts/hash-commit.ts";
import { encodeLe, type M31El } from "../backends/circle/m31.ts";
import { TRACE_LEN } from "../backends/circle/params.ts";
import { concatBytes, sha256, writeI64LE, ZERO32 } from "../pool/bytes.ts";
import { commitNote, nullifierOf, type Note } from "../pool/notes.ts";
import type { NoteAuthOpens } from "./note-auth-bind.ts";

export type NoteAuthWitness = {
  amountSats: bigint;
  rho: Uint8Array;
  owner: Uint8Array;
  poolInstanceId: Uint8Array;
  action: "DEPOSIT" | "WITHDRAW";
};

/** a, e, w as 32 LSB-first bits. 96 bits × 6 compressions = 576 columns. */
export const HASH_COMPRESSIONS = 6;
export const BITS_PER_GROUP = 96;
export const HASH_BIT_COLUMNS = HASH_COMPRESSIONS * BITS_PER_GROUP;

const SHA256_K = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const SHA256_IV = [
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

function rotr(x: number, n: number): number {
  return ((x >>> n) | (x << (32 - n))) >>> 0;
}

function ch(e: number, f: number, g: number): number {
  return ((e & f) ^ (~e & g)) >>> 0;
}

function maj(a: number, b: number, c: number): number {
  return ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
}

function Sigma0(x: number): number {
  return (rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)) >>> 0;
}

function Sigma1(x: number): number {
  return (rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)) >>> 0;
}

function sigma0(x: number): number {
  return (rotr(x, 7) ^ rotr(x, 18) ^ (x >>> 3)) >>> 0;
}

function sigma1(x: number): number {
  return (rotr(x, 17) ^ rotr(x, 19) ^ (x >>> 10)) >>> 0;
}

function add32(...xs: number[]): number {
  let s = 0;
  for (const x of xs) s = (s + (x >>> 0)) >>> 0;
  return s;
}

export function sha256Pad(msg: Uint8Array): Uint8Array {
  const withOne = concatBytes(msg, Uint8Array.of(0x80));
  const mod = withOne.length % 64;
  const zeros = mod <= 56 ? 56 - mod : 120 - mod;
  const out = new Uint8Array(withOne.length + zeros + 8);
  out.set(withOne);
  const bitLen = msg.length * 8;
  out.set(writeU64BE(BigInt(bitLen)), out.length - 8);
  return out;
}

function writeU64BE(value: bigint): Uint8Array {
  const out = new Uint8Array(8);
  let n = value;
  for (let i = 7; i >= 0; i -= 1) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
}

function wordBe(block: Uint8Array, i: number): number {
  const o = i * 4;
  return ((block[o]! << 24) | (block[o + 1]! << 16) | (block[o + 2]! << 8) | block[o + 3]!) >>> 0;
}

export type ShaRound = { a: number; e: number; w: number; h: number[] };

export function sha256CompressRounds(iv: number[], block: Uint8Array): { rounds: ShaRound[]; out: number[] } {
  if (block.length !== 64) throw new Error("sha256 block");
  const w = new Array<number>(64);
  for (let t = 0; t < 16; t += 1) w[t] = wordBe(block, t);
  for (let t = 16; t < 64; t += 1) {
    w[t] = add32(sigma1(w[t - 2]!), w[t - 7]!, sigma0(w[t - 15]!), w[t - 16]!);
  }
  let a = iv[0]!,
    b = iv[1]!,
    c = iv[2]!,
    d = iv[3]!,
    e = iv[4]!,
    f = iv[5]!,
    g = iv[6]!,
    hh = iv[7]!;
  const rounds: ShaRound[] = [];
  for (let t = 0; t < 64; t += 1) {
    rounds.push({ a, e, w: w[t]!, h: [a, b, c, d, e, f, g, hh] });
    const t1 = add32(hh, Sigma1(e), ch(e, f, g), SHA256_K[t]!, w[t]!);
    const t2 = add32(Sigma0(a), maj(a, b, c));
    hh = g;
    g = f;
    f = e;
    e = add32(d, t1);
    d = c;
    c = b;
    b = a;
    a = add32(t1, t2);
  }
  const out = [
    add32(a, iv[0]!),
    add32(b, iv[1]!),
    add32(c, iv[2]!),
    add32(d, iv[3]!),
    add32(e, iv[4]!),
    add32(f, iv[5]!),
    add32(g, iv[6]!),
    add32(hh, iv[7]!),
  ];
  return { rounds, out };
}

export function wordsToHash(words: number[]): Uint8Array {
  const out = new Uint8Array(32);
  for (let i = 0; i < 8; i += 1) {
    const x = words[i]!;
    out[i * 4] = (x >>> 24) & 0xff;
    out[i * 4 + 1] = (x >>> 16) & 0xff;
    out[i * 4 + 2] = (x >>> 8) & 0xff;
    out[i * 4 + 3] = x & 0xff;
  }
  return out;
}

export function sha256Blocks(msg: Uint8Array): { rounds: ShaRound[][]; out: number[] } {
  const padded = sha256Pad(msg);
  let iv = SHA256_IV.slice();
  const all: ShaRound[][] = [];
  for (let i = 0; i < padded.length; i += 64) {
    const { rounds, out } = sha256CompressRounds(iv, padded.subarray(i, i + 64));
    all.push(rounds);
    iv = out;
  }
  return { rounds: all, out: iv };
}

function u32Bits(x: number): number[] {
  const out = new Array<number>(32);
  for (let i = 0; i < 32; i += 1) out[i] = (x >>> i) & 1;
  return out;
}

export function witnessMessages(w: NoteAuthWitness): {
  amountCommitMsg: Uint8Array;
  leafMsg: Uint8Array;
  nfMsg: Uint8Array;
} {
  const amount8 = writeI64LE(w.amountSats);
  const amountCommit = commitAmount(w.amountSats, w.rho);
  return {
    amountCommitMsg: concatBytes(HASH_AMOUNT_TAG, amount8, w.rho),
    leafMsg: concatBytes(amountCommit, w.rho, w.owner),
    nfMsg: concatBytes(w.poolInstanceId, w.owner, w.rho),
  };
}

export function noteAuthPublicsFromWitness(w: NoteAuthWitness): NoteAuthOpens {
  const note: Note = { amountSats: w.amountSats, rho: w.rho, ownerSecret: w.owner };
  const leaf = commitNote(note);
  const amountCommit = commitAmount(w.amountSats, w.rho);
  if (w.action === "DEPOSIT") {
    return { leaf, nf: new Uint8Array(ZERO32), amountCommit, createdLeaf: leaf };
  }
  return {
    leaf,
    nf: nullifierOf(note, w.poolInstanceId),
    amountCommit,
    createdLeaf: new Uint8Array(ZERO32),
  };
}

/** Sixteen u16 limbs. Each is < M31, so the 32-byte hash is 1-1 in the residual. */
export function hashLimbs(h: Uint8Array): M31El[] {
  if (h.length !== 32) throw new Error("hash limbs");
  const out: M31El[] = [];
  for (let i = 0; i < 32; i += 2) {
    out.push(BigInt(h[i]!) | (BigInt(h[i + 1]!) << 8n));
  }
  return out;
}

export function noteAuthResiduals(w: NoteAuthWitness, pubs: NoteAuthOpens): M31El[] {
  const expect = noteAuthPublicsFromWitness(w);
  const r: M31El[] = Array.from({ length: TRACE_LEN }, () => 0n);
  const pairs: Array<[Uint8Array, Uint8Array]> = [
    [expect.amountCommit, pubs.amountCommit],
    [expect.leaf, pubs.leaf],
    [expect.nf, pubs.nf],
  ];
  let k = 0;
  for (const [a, b] of pairs) {
    const la = hashLimbs(a);
    const lb = hashLimbs(b);
    for (let i = 0; i < 16; i += 1) {
      r[k] = (la[i]! - lb[i]! + 2147483647n) % 2147483647n;
      k += 1;
    }
  }
  return r;
}

export function noteAuthResidualsVanish(w: NoteAuthWitness, pubs: NoteAuthOpens): boolean {
  return noteAuthResiduals(w, pubs).every((x) => x === 0n);
}

/** Statement publics the SHA AIR is bound to — never auth vs hashLeaves. */
export type ShaStatementPubs = {
  action: "DEPOSIT" | "WITHDRAW";
  amountCommitIn: Uint8Array;
  amountCommitOut: Uint8Array;
  noteCommitment: Uint8Array;
  nullifier: Uint8Array;
};

export function statementShaOpens(statement: ShaStatementPubs, spentLeaf?: Uint8Array): NoteAuthOpens {
  const amountCommit =
    statement.action === "DEPOSIT" ? statement.amountCommitOut : statement.amountCommitIn;
  const leaf =
    statement.action === "DEPOSIT"
      ? statement.noteCommitment
      : spentLeaf && spentLeaf.length === 32
        ? spentLeaf
        : statement.noteCommitment;
  return {
    amountCommit: amountCommit.length === 32 ? amountCommit : new Uint8Array(32),
    leaf: leaf.length === 32 ? leaf : new Uint8Array(32),
    nf: statement.nullifier.length === 32 ? statement.nullifier : new Uint8Array(32),
    createdLeaf: statement.action === "DEPOSIT" ? statement.noteCommitment : new Uint8Array(32),
  };
}

export function shaPubsAcc(pubs: { amountCommit: Uint8Array; leaf: Uint8Array; nf: Uint8Array }): M31El {
  let s = 0n;
  for (const h of [pubs.amountCommit, pubs.leaf, pubs.nf]) {
    if (h.length !== 32) continue;
    for (const limb of hashLimbs(h)) s = (s + limb) % 2147483647n;
  }
  return s;
}

export function shaTraceAcc(shaTrace: HashBitTrace, action: "DEPOSIT" | "WITHDRAW"): M31El {
  const rows = hashBitRows(shaTrace);
  const msgs = messagesFromHashBitRows(rows);
  const amountCommit = sha256(msgs.amountCommitMsg);
  const leaf = sha256(msgs.leafMsg);
  const nf = action === "DEPOSIT" ? new Uint8Array(32) : sha256(msgs.nfMsg);
  return shaPubsAcc({ amountCommit, leaf, nf });
}

/** N at occupancy query i: statement pubs minus one batched TRACE opening. Missing opening fail-closed. */
export function shaCAtQuery(
  statement: ShaStatementPubs,
  batchedOpening: M31El | undefined,
  _i: number,
  spentLeaf?: Uint8Array,
): M31El {
  const acc = shaPubsAcc(statementShaOpens(statement, spentLeaf));
  if (batchedOpening === undefined) return acc === 0n ? 1n : acc;
  return (acc - batchedOpening + 2147483647n) % 2147483647n;
}

function emptyShaTrace(): HashBitTrace {
  return hashBitTraceFromRows(Array.from({ length: TRACE_LEN }, () => new Uint8Array(HASH_BIT_ROW_BYTES)));
}

function limbDiffResiduals(expect: Uint8Array[], claimed: Uint8Array[]): M31El[] {
  const r: M31El[] = Array.from({ length: TRACE_LEN }, () => 0n);
  let k = 0;
  for (let p = 0; p < expect.length; p += 1) {
    const la = hashLimbs(expect[p]!);
    const lb = hashLimbs(claimed[p]!);
    for (let i = 0; i < 16; i += 1) {
      r[k] = (la[i]! - lb[i]! + 2147483647n) % 2147483647n;
      k += 1;
    }
  }
  return r;
}

function bitsToU32(columns: M31El[][], base: number, row: number): number {
  let x = 0;
  for (let b = 0; b < 32; b += 1) {
    if (columns[base + b]![row] === 1n) x |= 1 << b;
  }
  return x >>> 0;
}

/**
 * Occupancy-C mix: SHA output limbs vs publics, plus booleanity and round
 * match of the 576-col TRACE against the witness SHA. Honest vanishes.
 * Mixed publics (victim witness + attacker tags) do not.
 */
export function shaAirResiduals(w: NoteAuthWitness, pubs: NoteAuthOpens): M31El[] {
  const r = noteAuthResiduals(w, pubs);
  const trace = buildHashBitTrace(w);
  const msgs = witnessMessages(w);
  const commit = sha256Blocks(msgs.amountCommitMsg);
  const leaf = sha256Blocks(msgs.leafMsg);
  const nf =
    w.action === "DEPOSIT"
      ? { rounds: [emptyRounds(), emptyRounds()] }
      : sha256Blocks(msgs.nfMsg);
  const groups = [
    commit.rounds[0] ?? emptyRounds(),
    commit.rounds[1] ?? emptyRounds(),
    leaf.rounds[0] ?? emptyRounds(),
    leaf.rounds[1] ?? emptyRounds(),
    nf.rounds[0] ?? emptyRounds(),
    nf.rounds[1] ?? emptyRounds(),
  ];
  let boolAcc = 0n;
  let roundAcc = 0n;
  for (let g = 0; g < HASH_COMPRESSIONS; g += 1) {
    const base = g * BITS_PER_GROUP;
    const rounds = groups[g]!;
    for (let t = 0; t < TRACE_LEN; t += 1) {
      for (let b = 0; b < BITS_PER_GROUP; b += 1) {
        const bit = trace.columns[base + b]![t]!;
        boolAcc = (boolAcc + ((bit * ((bit + 2147483646n) % 2147483647n)) % 2147483647n)) % 2147483647n;
      }
      const row = rounds[t]!;
      const a = bitsToU32(trace.columns, base, t);
      const e = bitsToU32(trace.columns, base + 32, t);
      const ww = bitsToU32(trace.columns, base + 64, t);
      const da = (BigInt(a ^ row.a) + 2147483647n) % 2147483647n;
      const de = (BigInt(e ^ row.e) + 2147483647n) % 2147483647n;
      const dw = (BigInt(ww ^ row.w) + 2147483647n) % 2147483647n;
      roundAcc = (roundAcc + da + de + dw) % 2147483647n;
    }
  }
  r[62] = boolAcc;
  r[63] = roundAcc;
  return r;
}

export function encodeShaResiduals(r: M31El[]): Uint8Array {
  const out = new Uint8Array(TRACE_LEN * 4);
  for (let i = 0; i < TRACE_LEN; i += 1) out.set(encodeLe(r[i] ?? 0n), i * 4);
  return out;
}

export function decodeShaResiduals(bytes: Uint8Array): M31El[] {
  const r: M31El[] = Array.from({ length: TRACE_LEN }, () => 0n);
  if (bytes.length < TRACE_LEN * 4) return r;
  for (let i = 0; i < TRACE_LEN; i += 1) {
    let n = 0n;
    for (let k = 0; k < 4; k += 1) n |= BigInt(bytes[i * 4 + k]!) << (8n * BigInt(k));
    r[i] = n % 2147483647n;
  }
  return r;
}

export const SHA_RESIDUAL_BYTES = TRACE_LEN * 4;

/** 64×4-byte LE leaves: residual+public u16 limbs. Honest residual is 0. */
export function encodeHashLeaves(w: NoteAuthWitness, pubs: NoteAuthOpens): Uint8Array {
  const r = noteAuthResiduals(w, pubs);
  const limbs = [
    ...hashLimbs(pubs.amountCommit),
    ...hashLimbs(pubs.leaf),
    ...hashLimbs(pubs.nf),
  ];
  const out = new Uint8Array(TRACE_LEN * 4);
  for (let i = 0; i < TRACE_LEN; i += 1) {
    const ri = r[i] ?? 0n;
    const li = limbs[i % limbs.length] ?? 0n;
    out.set(encodeLe((ri + li) % 2147483647n), i * 4);
  }
  return out;
}

/** SHA256 of the 256-byte leaf blob. Miner OP_SHA256 + EQUALVERIFY. */
export function hashResidualRoot(w: NoteAuthWitness, pubs: NoteAuthOpens): Uint8Array {
  return sha256(encodeHashLeaves(w, pubs));
}

export function hashResidualRootFromAuth(
  amountSats: bigint,
  rho: Uint8Array,
  owner: Uint8Array,
  poolInstanceId: Uint8Array,
  action: "DEPOSIT" | "WITHDRAW",
  pubs: NoteAuthOpens,
): Uint8Array {
  return hashResidualRoot({ amountSats, rho, owner, poolInstanceId, action }, pubs);
}

export type HashBitTrace = {
  /** columns × TRACE_LEN bits as 0/1 M31. */
  columns: M31El[][];
  publics: NoteAuthOpens;
  /** 6 compression round witnesses (amountCommit 2, leaf 2, nf 2). Empty compressions are IV-passthrough zeros. */
  groups: ShaRound[][];
};

function emptyRounds(): ShaRound[] {
  const ivh = SHA256_IV.slice();
  return Array.from({ length: 64 }, () => ({ a: 0, e: 0, w: 0, h: ivh.slice() }));
}

export function buildHashBitTrace(w: NoteAuthWitness): HashBitTrace {
  const msgs = witnessMessages(w);
  const commit = sha256Blocks(msgs.amountCommitMsg);
  const leaf = sha256Blocks(msgs.leafMsg);
  const nf =
    w.action === "DEPOSIT"
      ? { rounds: [emptyRounds(), emptyRounds()], out: SHA256_IV.slice() }
      : sha256Blocks(msgs.nfMsg);
  const groups = [
    commit.rounds[0] ?? emptyRounds(),
    commit.rounds[1] ?? emptyRounds(),
    leaf.rounds[0] ?? emptyRounds(),
    leaf.rounds[1] ?? emptyRounds(),
    nf.rounds[0] ?? emptyRounds(),
    nf.rounds[1] ?? emptyRounds(),
  ];
  const columns: M31El[][] = Array.from({ length: HASH_BIT_COLUMNS }, () =>
    Array.from({ length: TRACE_LEN }, () => 0n),
  );
  for (let g = 0; g < HASH_COMPRESSIONS; g += 1) {
    const rounds = groups[g]!;
    for (let r = 0; r < TRACE_LEN; r += 1) {
      const row = rounds[r]!;
      const pack = [u32Bits(row.a), u32Bits(row.e), u32Bits(row.w)];
      for (let wdi = 0; wdi < 3; wdi += 1) {
        for (let b = 0; b < 32; b += 1) {
          columns[g * BITS_PER_GROUP + wdi * 32 + b]![r] = BigInt(pack[wdi]![b]!);
        }
      }
    }
  }
  const publics = noteAuthPublicsFromWitness(w);
  return { columns, publics, groups };
}

export function assertHashTraceConstraints(trace: HashBitTrace, w: NoteAuthWitness): void {
  const pubs = noteAuthPublicsFromWitness(w);
  if (!noteAuthResidualsVanish(w, pubs)) throw new Error("note-auth residuals");
  const msgs = witnessMessages(w);
  const gotCommit = sha256(msgs.amountCommitMsg);
  const gotLeaf = sha256(msgs.leafMsg);
  const gotNf = w.action === "DEPOSIT" ? new Uint8Array(ZERO32) : sha256(msgs.nfMsg);
  if (!eq32(gotCommit, pubs.amountCommit)) throw new Error("amountCommit SHA-256");
  if (!eq32(gotLeaf, pubs.leaf)) throw new Error("leaf SHA-256");
  if (!eq32(gotNf, pubs.nf)) throw new Error("nf SHA-256");
  for (let c = 0; c < HASH_BIT_COLUMNS; c += 1) {
    for (let r = 0; r < TRACE_LEN; r += 1) {
      const b = trace.columns[c]![r]!;
      if (b !== 0n && b !== 1n) throw new Error(`bit ${c},${r}`);
    }
  }
}

function eq32(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === 32 && b.length === 32 && a.every((x, i) => x === b[i]);
}

/** One query opening of all hash-bit columns (no partner). */
export function hashOpeningBytes(columns = HASH_BIT_COLUMNS): number {
  return columns * 4;
}

/** 36 extra inputs × (41 + opening + 9-node path). Openings only; redeem is extra. Lab meter, not a dummy pad. */
export function hashAir36InputBytes(columns = HASH_BIT_COLUMNS): {
  perUnlocking: number;
  extraInputs: number;
  extraTxBytes: number;
} {
  const path = 9 * 32;
  const perUnlocking = 41 + hashOpeningBytes(columns) + path;
  const extraInputs = 36;
  return { perUnlocking, extraInputs, extraTxBytes: extraInputs * perUnlocking };
}

export function encodeHashRow(columns: M31El[][], row: number): Uint8Array {
  const out = new Uint8Array(columns.length * 4);
  for (let c = 0; c < columns.length; c += 1) out.set(encodeLe(columns[c]![row]!), c * 4);
  return out;
}

/** Bit-packed TRACE row: 576 bits → 72 bytes. LSB of byte 0 is column 0. */
export const HASH_BIT_ROW_BYTES = HASH_BIT_COLUMNS / 8;

export function packHashBitRow(columns: M31El[][], row: number): Uint8Array {
  const out = new Uint8Array(HASH_BIT_ROW_BYTES);
  for (let c = 0; c < HASH_BIT_COLUMNS; c += 1) {
    if (columns[c]![row] === 1n) out[c >> 3]! |= 1 << (c & 7);
  }
  return out;
}

export function unpackHashBitRow(row: Uint8Array): M31El[] {
  const cols: M31El[] = Array.from({ length: HASH_BIT_COLUMNS }, () => 0n);
  for (let c = 0; c < HASH_BIT_COLUMNS; c += 1) {
    if ((row[c >> 3]! >> (c & 7)) & 1) cols[c] = 1n;
  }
  return cols;
}

/** Rebuild SHA TRACE from packed rows (encoded proof). Groups from a/e/w bits. */
export function hashBitTraceFromRows(rows: Uint8Array[]): HashBitTrace {
  if (rows.length !== TRACE_LEN) throw new Error("hash-bit rows");
  const columns: M31El[][] = Array.from({ length: HASH_BIT_COLUMNS }, () =>
    Array.from({ length: TRACE_LEN }, () => 0n),
  );
  for (let r = 0; r < TRACE_LEN; r += 1) {
    const bits = unpackHashBitRow(rows[r]!);
    for (let c = 0; c < HASH_BIT_COLUMNS; c += 1) columns[c]![r] = bits[c]!;
  }
  const groups: ShaRound[][] = [];
  for (let g = 0; g < HASH_COMPRESSIONS; g += 1) {
    const base = g * BITS_PER_GROUP;
    const rounds: ShaRound[] = [];
    for (let t = 0; t < TRACE_LEN; t += 1) {
      const a = bitsToU32(columns, base, t);
      const e = bitsToU32(columns, base + 32, t);
      const w = bitsToU32(columns, base + 64, t);
      rounds.push({ a, e, w, h: [a, 0, 0, 0, e, 0, 0, 0] });
    }
    groups.push(rounds);
  }
  return { columns, publics: { leaf: new Uint8Array(32), nf: new Uint8Array(32), amountCommit: new Uint8Array(32), createdLeaf: new Uint8Array(32) }, groups };
}

export function hashBitRows(trace: HashBitTrace): Uint8Array[] {
  return Array.from({ length: TRACE_LEN }, (_, r) => packHashBitRow(trace.columns, r));
}

export function hashBitRootOf(rows: Uint8Array[]): Uint8Array {
  return sha256(concatBytes(...rows));
}

/** W-word of compression `g` at a TRACE row: 32 LSB-first bits at byte 8+12g. */
export function wWordFromRow(row: Uint8Array, g: number): number {
  const o = 8 + g * 12;
  return (row[o]! | (row[o + 1]! << 8) | (row[o + 2]! << 16) | (row[o + 3]! << 24)) >>> 0;
}

function be4(w: number): Uint8Array {
  return Uint8Array.of((w >>> 24) & 0xff, (w >>> 16) & 0xff, (w >>> 8) & 0xff, w & 0xff);
}

/** First `nBytes` of SHA-256 message from compression `gStart` (16 words/block). */
export function messageFromRows(rows: Uint8Array[], gStart: number, nBytes: number): Uint8Array {
  const out = new Uint8Array(nBytes);
  let o = 0;
  let g = gStart;
  let t = 0;
  while (o < nBytes) {
    const b = be4(wWordFromRow(rows[t]!, g));
    const n = Math.min(4, nBytes - o);
    out.set(b.subarray(0, n), o);
    o += n;
    t += 1;
    if (t === 16) {
      t = 0;
      g += 1;
    }
  }
  return out;
}

export function messagesFromHashBitRows(rows: Uint8Array[]): {
  amountCommitMsg: Uint8Array;
  leafMsg: Uint8Array;
  nfMsg: Uint8Array;
} {
  return {
    amountCommitMsg: messageFromRows(rows, 0, HASH_MSG_AMOUNT_LEN),
    leafMsg: messageFromRows(rows, 2, HASH_MSG_LEAF_LEN),
    nfMsg: messageFromRows(rows, 4, HASH_MSG_NF_LEN),
  };
}

/**
 * Statement-bound SHA residuals mixed into occupancy C.
 * TRACE present: SHA-256 of reconstructed W-schedule vs statement pubs.
 * Missing TRACE is empty rows (fail-closed vs a real statement) unless occupancyOnly.
 */
export function shaStatementResiduals(
  statement: ShaStatementPubs,
  shaTrace?: HashBitTrace,
  _hashLeaves?: Uint8Array,
  spentLeaf?: Uint8Array,
  occupancyOnly = false,
): M31El[] {
  if (occupancyOnly) return Array.from({ length: TRACE_LEN }, () => 0n);
  const pubs = statementShaOpens(
    statement,
    spentLeaf ?? (shaTrace && shaTrace.publics.leaf.length === 32 ? shaTrace.publics.leaf : undefined),
  );
  if (!shaTrace) return shaStatementResiduals(statement, emptyShaTrace(), _hashLeaves, spentLeaf, false);
  const rows = hashBitRows(shaTrace);
  const msgs = messagesFromHashBitRows(rows);
  const gotCommit = sha256(msgs.amountCommitMsg);
  const gotLeaf = sha256(msgs.leafMsg);
  const gotNf = statement.action === "DEPOSIT" ? new Uint8Array(32) : sha256(msgs.nfMsg);
  const r = limbDiffResiduals(
    [gotCommit, gotLeaf, gotNf],
    [pubs.amountCommit, pubs.leaf, pubs.nf],
  );
  let boolAcc = 0n;
  for (let g = 0; g < HASH_COMPRESSIONS; g += 1) {
    const base = g * BITS_PER_GROUP;
    for (let t = 0; t < TRACE_LEN; t += 1) {
      for (let b = 0; b < BITS_PER_GROUP; b += 1) {
        const bit = shaTrace.columns[base + b]![t]!;
        boolAcc = (boolAcc + ((bit * ((bit + 2147483646n) % 2147483647n)) % 2147483647n)) % 2147483647n;
      }
    }
  }
  r[62] = boolAcc;
  const commit = sha256Blocks(msgs.amountCommitMsg);
  const leaf = sha256Blocks(msgs.leafMsg);
  const nf =
    statement.action === "DEPOSIT"
      ? { rounds: [emptyRounds(), emptyRounds()] }
      : sha256Blocks(msgs.nfMsg);
  const groups = [
    commit.rounds[0] ?? emptyRounds(),
    commit.rounds[1] ?? emptyRounds(),
    leaf.rounds[0] ?? emptyRounds(),
    leaf.rounds[1] ?? emptyRounds(),
    nf.rounds[0] ?? emptyRounds(),
    nf.rounds[1] ?? emptyRounds(),
  ];
  let roundAcc = 0n;
  for (let g = 0; g < HASH_COMPRESSIONS; g += 1) {
    const base = g * BITS_PER_GROUP;
    const rounds = groups[g]!;
    for (let t = 0; t < TRACE_LEN; t += 1) {
      const row = rounds[t]!;
      const a = bitsToU32(shaTrace.columns, base, t);
      const e = bitsToU32(shaTrace.columns, base + 32, t);
      const ww = bitsToU32(shaTrace.columns, base + 64, t);
      const da = (BigInt(a ^ row.a) + 2147483647n) % 2147483647n;
      const de = (BigInt(e ^ row.e) + 2147483647n) % 2147483647n;
      const dw = (BigInt(ww ^ row.w) + 2147483647n) % 2147483647n;
      roundAcc = (roundAcc + da + de + dw) % 2147483647n;
    }
  }
  r[63] = roundAcc;
  return r;
}

/** TRACE SHA-256 outputs as 96 bytes. Missing TRACE is empty rows (fail-closed). */
export function traceOut96(statement: ShaStatementPubs, shaTrace?: HashBitTrace): Uint8Array {
  const trace = shaTrace ?? emptyShaTrace();
  const msgs = messagesFromHashBitRows(hashBitRows(trace));
  const nf = statement.action === "DEPOSIT" ? new Uint8Array(32) : sha256(msgs.nfMsg);
  return concatBytes(sha256(msgs.amountCommitMsg), sha256(msgs.leafMsg), nf);
}

/** Six 1200-byte fold shards. Concat 64×72 rows, then hashBitRoot copies. */
export const HASH_BIT_SHARD_BYTES = 1200;
export const HASH_BIT_SHARD_COUNT = 6;
export const HASH_BIT_ROWS_BYTES = TRACE_LEN * HASH_BIT_ROW_BYTES;
export const HASH_BIT_CHUNK = HASH_BIT_ROWS_BYTES / HASH_BIT_SHARD_COUNT;
export const HASH_MSG_AMOUNT_LEN = 16 + 8 + 32;
export const HASH_MSG_LEAF_LEN = 96;
export const HASH_MSG_NF_LEN = 96;
export const HASH_MSG_BYTES = HASH_MSG_AMOUNT_LEN + HASH_MSG_LEAF_LEN + HASH_MSG_NF_LEN;

export function encodeHashBitShards(rows: Uint8Array[], root: Uint8Array): Uint8Array[] {
  if (rows.length !== TRACE_LEN) throw new Error("hash-bit rows");
  if (root.length !== 32) throw new Error("hash-bit root");
  const blob = concatBytes(...rows);
  if (blob.length !== HASH_BIT_ROWS_BYTES) throw new Error("hash-bit blob");
  const shards: Uint8Array[] = [];
  for (let s = 0; s < HASH_BIT_SHARD_COUNT; s += 1) {
    const shard = new Uint8Array(HASH_BIT_SHARD_BYTES);
    shard.set(blob.subarray(s * HASH_BIT_CHUNK, (s + 1) * HASH_BIT_CHUNK), 0);
    for (let o = HASH_BIT_CHUNK; o + 32 <= HASH_BIT_SHARD_BYTES; o += 32) shard.set(root, o);
    shards.push(shard);
  }
  return shards;
}

export function decodeHashBitRows(shards: Uint8Array[]): Uint8Array[] {
  if (shards.length !== HASH_BIT_SHARD_COUNT) throw new Error("hash-bit shards");
  const blob = concatBytes(...shards.map((s) => s.subarray(0, HASH_BIT_CHUNK)));
  const rows: Uint8Array[] = [];
  for (let i = 0; i < TRACE_LEN; i += 1) {
    rows.push(blob.subarray(i * HASH_BIT_ROW_BYTES, (i + 1) * HASH_BIT_ROW_BYTES));
  }
  return rows;
}

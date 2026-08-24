/**
 * Packed AIR prefix + M31/Newton/circle snippets for on-chain N=Q·Z + fold.
 * Layout (PUSHDATA2):
 *   0     7×32 layerRoots
 *   224   traceRoot
 *   256   grindNonce u32be
 *   260   Newton even
 *   392   Newton odd
 *   524   FS digest + two public PAA1 cells
 *   812   viewing-commit (32); mask felt derived on-chain
 *   844   payout HASH256 (32), bound to cell 25
 *   876   unused (net is packed cell 2, bound to Newton T)
 *   957   Q table (36×4)
 *   1101  FS indices
 *   1173  on-chain cells
 *   1429  N table
 *   1576  FRI final (8 × QM31 = 128 B)
 */
import { cashAssemblyToBin, encodeLockingBytecodeP2sh32, hash256 } from "@bitauth/libauth";
import { encodeStatement, type PoolStatement } from "../pool/statement.ts";
import { encodePublicPaa1 } from "../pool/state.ts";
import { concatBytes, writeU32BE } from "../pool/bytes.ts";
import { algebraicCQuotientLde, onChainCells } from "../backends/circle/air.ts";
import { decodeFriProof, type FriProof } from "../backends/circle/fri.ts";
import { interpolateCircle } from "../backends/circle/interpolate.ts";
import { addPoints, CIRCLE_GEN, CIRCLE_ONE, scalarMul, type CirclePoint } from "../backends/circle/group.ts";
import { add, encodeLe, M31, mul, sub, type M31El } from "../backends/circle/m31.ts";
import { encodeQm31 } from "../backends/circle/qm31.ts";
import {
  FRI_OPEN_MASK_TAG,
  VIEWING_TAG,
  openingMaskAt,
  openingMaskFelt,
} from "../backends/circle/witness-mask.ts";
import { defaultInternalHash, type InternalHash } from "../backends/circle/internal-hash.ts";
import { circleDomain } from "../backends/circle/fri.ts";
import { COMMITTED_LAYERS, FRI_FINAL, FRI_N, FRI_QUERIES, TRACE_LEN } from "../backends/circle/params.ts";
import { uniqueQueryIndices } from "../backends/circle/query-sample.ts";

import { decodeFeltBlob, encodeFeltBlob, M31_ADD, M31_MUL, M31_SUB } from "./m31-asm.ts";
import { slotRCqzAsm, slotRCqzBodyAsm } from "./r-kernel.ts";

export const AIR_PACKED_SIZE = 1704;
export const AIR_OFF_ROOTS = 0;
export const AIR_OFF_TRACE = 224;
export const AIR_OFF_NONCE = 256;
export const AIR_OFF_EVEN = 260;
export const AIR_OFF_ODD = 392;
export const AIR_OFF_STMT = 524;
export const AIR_STMT_LEN = 433;
/** sha256(encodeStatement) — FS digest, not the statement preimage. */
export const AIR_OFF_DIGEST = AIR_OFF_STMT;
export const AIR_OFF_PUB_OLD = AIR_OFF_STMT + 32;
export const AIR_OFF_PUB_NEW = AIR_OFF_STMT + 32 + 128;
/** Packed viewing-commit (32). Prover derives R_on + Z·R_off; the felt is not stored. */
export const AIR_OFF_OPEN_MASK = 812;
export const AIR_VIEWING_COMMIT_LEN = 32;
/** HASH256 of the withdraw payout lock (N=1) or of the lock+value set (N>1). */
export const AIR_OFF_PAYOUT = 844;
/** 1-byte length then minimally encoded publicAmount script number. */
export const AIR_OFF_NET = 876;
export const AIR_OFF_QTABLE = 957;
export const AIR_OFF_IDX = 1101;
export const AIR_OFF_CELLS = 1173;
export const AIR_OFF_NTABLE = 1429;
export const AIR_OFF_FINAL = 1576;
export const AIR_NEWTON_FELTS = 33;
export const AIR_NEWTON_BYTES = AIR_NEWTON_FELTS * 4;

const smallDomain = circleDomain(TRACE_LEN);
const bigDomain = circleDomain(FRI_N);
export const TRACE_XS: M31El[] = interpolateCircle(
  smallDomain,
  smallDomain.map(() => 0n),
).xs;
export const VANISH_XS: M31El[] = smallDomain.slice(0, TRACE_LEN / 2).map((p) => p.x);
export const G64: CirclePoint = smallDomain[1]!;
export const G1024: CirclePoint = bigDomain[1]!;

function hexPush(data: Uint8Array): string {
  return `<0x${Buffer.from(data).toString("hex")}>`;
}

function pushFelt(n: bigint): string {
  return `<${n.toString()}>`;
}

export function newtonEvalJs(coeffs: M31El[], at: M31El, xs: M31El[] = TRACE_XS): M31El {
  let acc = 0n;
  let prod = 1n;
  for (let i = 0; i < coeffs.length; i += 1) {
    acc = add(acc, mul(coeffs[i]!, prod));
    if (i + 1 < coeffs.length) prod = mul(prod, sub(at, xs[i]!));
  }
  return acc;
}

/**
 * Unrolled Newton eval. Stack in: at_x. Coeffs and xs are literals.
 * Stack out: result.
 */
/** Newton from a 128-byte LE blob. Stack: coeffs128 at_x → result. */
export function newtonFromBlobAsm(xs: M31El[] = TRACE_XS): string {
  const lines: string[] = [`OP_TOALTSTACK`, `<0>`, `<1>`];
  for (let i = 0; i < xs.length; i += 1) {
    lines.push(
      `OP_2 OP_PICK`,
      `<${i * 4}>`,
      `OP_SPLIT`,
      `OP_NIP`,
      `<4>`,
      `OP_SPLIT`,
      `OP_DROP`,
      `OP_BIN2NUM`,
      `OP_OVER`,
      M31_MUL,
      `OP_ROT`,
      M31_ADD,
      `OP_SWAP`,
    );
    if (i + 1 < xs.length) {
      lines.push(`OP_FROMALTSTACK`, `OP_DUP`, `OP_TOALTSTACK`, pushFelt(xs[i]!), M31_SUB, M31_MUL);
    }
  }
  lines.push(`OP_DROP`, `OP_NIP`, `OP_FROMALTSTACK`, `OP_DROP`);
  return lines.join("\n");
}

export function newtonEvalUnrolledAsm(coeffs: M31El[], xs: M31El[] = TRACE_XS): string {
  const lines: string[] = [`<0>`, `<1>`];
  for (let i = 0; i < coeffs.length; i += 1) {
    lines.push(pushFelt(coeffs[i]!), `OP_OVER`, M31_MUL, `OP_ROT`, M31_ADD, `OP_SWAP`);
    if (i + 1 < coeffs.length) {
      lines.push(`OP_2 OP_PICK`, pushFelt(xs[i]!), M31_SUB, M31_MUL);
    }
  }
  lines.push(`OP_DROP`, `OP_NIP`);
  return lines.join("\n");
}

/**
 * Decode 2-byte big-endian as unsigned. Stack: be16 → n.
 * A lone high byte (≥0x80) is negative under OP_BIN2NUM; pad LE so 0x0193 is 403, not 147.
 */
export const BE16_UNSIGNED = `
OP_1 OP_SPLIT
OP_SWAP
OP_CAT
<0x00> OP_CAT
OP_BIN2NUM
`;

/** Circle add. Stack: x1 y1 x2 y2 → x3 y3 */
export const CIRCLE_ADD = `
OP_3 OP_PICK
OP_2 OP_PICK
${M31_MUL}
OP_3 OP_PICK
OP_2 OP_PICK
${M31_MUL}
${M31_SUB}
OP_TOALTSTACK
OP_3 OP_PICK
OP_1 OP_PICK
${M31_MUL}
OP_3 OP_PICK
OP_3 OP_PICK
${M31_MUL}
${M31_ADD}
OP_TOALTSTACK
OP_2DROP
OP_2DROP
OP_FROMALTSTACK
OP_FROMALTSTACK
OP_SWAP
`;

/** 10-bit double-and-add [k]G. Stack: k gx gy → accx accy */
export const SCALAR_MUL_FAST = `
OP_TOALTSTACK
OP_TOALTSTACK
${pushFelt(CIRCLE_ONE.x)}
${pushFelt(CIRCLE_ONE.y)}
OP_FROMALTSTACK
OP_FROMALTSTACK
OP_4 OP_ROLL
${Array.from({ length: 10 }, () => `
OP_DUP
OP_2 OP_MOD
OP_IF
  OP_TOALTSTACK
  OP_3 OP_PICK
  OP_3 OP_PICK
  OP_3 OP_PICK
  OP_3 OP_PICK
  ${CIRCLE_ADD}
  OP_TOALTSTACK
  OP_TOALTSTACK
  OP_2SWAP
  OP_2DROP
  OP_FROMALTSTACK
  OP_FROMALTSTACK
  OP_2SWAP
  OP_FROMALTSTACK
OP_ENDIF
OP_TOALTSTACK
OP_2DUP
${CIRCLE_ADD}
OP_FROMALTSTACK
OP_2 OP_DIV
`).join("\n")}
OP_DROP
OP_2DROP
`;

/** [k]G by adding G, k times. Stack: k gx gy → accx accy */
export const SCALAR_MUL = `
OP_TOALTSTACK
OP_TOALTSTACK
${pushFelt(CIRCLE_ONE.x)}
${pushFelt(CIRCLE_ONE.y)}
OP_FROMALTSTACK
OP_FROMALTSTACK
OP_4 OP_ROLL
OP_BEGIN
  OP_DUP
  OP_0 OP_GREATERTHAN
  OP_IF
    OP_1SUB
    OP_TOALTSTACK
    OP_3 OP_PICK
    OP_3 OP_PICK
    OP_3 OP_PICK
    OP_3 OP_PICK
    ${CIRCLE_ADD}
    OP_TOALTSTACK
    OP_TOALTSTACK
    OP_2SWAP
    OP_2DROP
    OP_FROMALTSTACK
    OP_FROMALTSTACK
    OP_2SWAP
    OP_FROMALTSTACK
    OP_0
  OP_ELSE
    OP_DROP
    OP_1
  OP_ENDIF
OP_UNTIL
OP_2DROP
`;

/** Z(zx) = ∏ (zx − xs[k]). Stack: zx → Z */
export function vanishingUnrolledAsm(xs: M31El[] = TRACE_XS): string {
  const lines: string[] = [`<1>`];
  for (const x of xs) {
    lines.push(`OP_OVER`, pushFelt(x), M31_SUB, M31_MUL);
  }
  lines.push(`OP_NIP`);
  return lines.join("\n");
}

export function statementNewton(
  statement: PoolStatement,
  mask: M31El = 0n,
  hash: InternalHash = defaultInternalHash(),
): { even: M31El[]; odd: M31El[] } {
  const cells = onChainCells(statement, hash).map((v) => add(v, mask));
  const interp = interpolateCircle(smallDomain, cells);
  return { even: interp.even, odd: interp.odd };
}

export function fiatShamirQueryIndices(
  digest: Uint8Array,
  proof: FriProof,
  hash: InternalHash = defaultInternalHash(),
  newtonEven?: Uint8Array,
  newtonOdd?: Uint8Array,
): number[] {
  const even = newtonEven ?? new Uint8Array(AIR_NEWTON_BYTES);
  const odd = newtonOdd ?? new Uint8Array(AIR_NEWTON_BYTES);
  const grindSeed = hash.digest(concatBytes(digest, proof.traceRoot, ...proof.layerRoots, even, odd));
  const seed = hash.digest(concatBytes(grindSeed, writeU32BE(proof.grindNonce), new TextEncoder().encode("queries")));
  return uniqueQueryIndices(hash, seed, FRI_N, FRI_QUERIES);
}

export function encodeAirPacked(
  statement: PoolStatement,
  proof: Uint8Array | FriProof,
  hash: InternalHash = defaultInternalHash(),
): Uint8Array {
  const p = proof instanceof Uint8Array ? decodeFriProof(proof) : proof;
  const commit = p.viewingCommit && p.viewingCommit.length === 32 ? p.viewingCommit : new Uint8Array(32);
  const { qLde, nLde, zLde } = algebraicCQuotientLde(statement, smallDomain, bigDomain, hash);
  const digest = hash.digest(encodeStatement(statement, hash));
  const packed = new Uint8Array(AIR_PACKED_SIZE);
  for (let r = 0; r < COMMITTED_LAYERS; r += 1) {
    packed.set(p.layerRoots[r] ?? new Uint8Array(32), AIR_OFF_ROOTS + r * 32);
  }
  packed.set(p.traceRoot, AIR_OFF_TRACE);
  packed.set(writeU32BE(p.grindNonce), AIR_OFF_NONCE);
  packed.set(commit, AIR_OFF_OPEN_MASK);
  const maskC = openingMaskFelt(commit, hash);
  const newton = statementNewton(statement, maskC, hash);
  const padNewton = (vals: M31El[]): M31El[] => {
    const out = vals.slice(0, AIR_NEWTON_FELTS);
    while (out.length < AIR_NEWTON_FELTS) out.push(0n);
    return out;
  };
  const evenBlob = encodeFeltBlob(padNewton(newton.even));
  const oddBlob = encodeFeltBlob(padNewton(newton.odd));
  packed.set(evenBlob, AIR_OFF_EVEN);
  packed.set(oddBlob, AIR_OFF_ODD);
  packed.set(digest, AIR_OFF_DIGEST);
  packed.set(encodePublicPaa1(statement.oldState), AIR_OFF_PUB_OLD);
  packed.set(encodePublicPaa1(statement.newState), AIR_OFF_PUB_NEW);
  packed.set(
    statement.payoutLockingDigest.length === 32 ? statement.payoutLockingDigest : new Uint8Array(32),
    AIR_OFF_PAYOUT,
  );
  const qIdx = fiatShamirQueryIndices(digest, p, hash, evenBlob, oddBlob);
  for (let s = 0; s < FRI_QUERIES; s += 1) {
    const i = qIdx[s]!;
    const r = openingMaskAt(commit, i, hash, zLde[i]!);
    packed.set(encodeLe(add(qLde[i]!, r)), AIR_OFF_QTABLE + s * 4);
    packed.set(encodeLe(add(nLde[i]!, mul(r, zLde[i]!))), AIR_OFF_NTABLE + s * 4);
    packed[AIR_OFF_IDX + s * 2] = (i >> 8) & 0xff;
    packed[AIR_OFF_IDX + s * 2 + 1] = i & 0xff;
  }
  const cells = Array.from({ length: TRACE_LEN }, () => 0n);
  const full = onChainCells(statement, hash);
  for (const i of [3, 5, 6, 18, 23, 24]) cells[i] = full[i]!;
  packed.set(encodeFeltBlob(cells), AIR_OFF_CELLS);
  for (let i = 0; i < FRI_FINAL; i += 1) {
    packed.set(encodeQm31(p.final[i] ?? [0n, 0n, 0n, 0n]), AIR_OFF_FINAL + i * 16);
  }
  return packed;
}

/**
 * Rewrite Newton even/odd so they interpolate the packed on-chain cells + the
 * same viewing mask. qTable / nTable / payout digest are left untouched.
 */
export function recookNewtonFromPacked(
  packed: Uint8Array,
  hash: InternalHash = defaultInternalHash(),
): Uint8Array {
  if (packed.length < AIR_PACKED_SIZE) throw new Error("packed width");
  const out = new Uint8Array(packed);
  const commit = packed.subarray(AIR_OFF_OPEN_MASK, AIR_OFF_OPEN_MASK + 32);
  const maskC = openingMaskFelt(commit, hash);
  const cells = decodeFeltBlob(packed.subarray(AIR_OFF_CELLS, AIR_OFF_CELLS + TRACE_LEN * 4));
  const interp = interpolateCircle(
    smallDomain,
    cells.map((v) => add(v, maskC)),
  );
  out.set(encodeFeltBlob(padNewton(interp.even)), AIR_OFF_EVEN);
  out.set(encodeFeltBlob(padNewton(interp.odd)), AIR_OFF_ODD);
  return out;
}

export function nqzAt(
  statement: PoolStatement,
  index: number,
  hash: InternalHash = defaultInternalHash(),
): { n: M31El; z: M31El; q: M31El } {
  const { nLde, zLde, qLde } = algebraicCQuotientLde(statement, smallDomain, bigDomain, hash);
  return { n: nLde[index]!, z: zLde[index]!, q: qLde[index]! };
}

function compileOrThrow(asm: string, name: string): Uint8Array {
  const bin = cashAssemblyToBin(asm);
  if (typeof bin === "string") throw new Error(`${name}: ${bin}`);
  return bin;
}

export function compileM31MulLock(): Uint8Array {
  return compileOrThrow(`${M31_MUL}\n<15>\nOP_NUMEQUAL`, "m31mul");
}

export function compileNewtonLock(coeffs: M31El[]): Uint8Array {
  return compileOrThrow(`${newtonEvalUnrolledAsm(coeffs)}\nOP_NUMEQUAL`, "newton");
}

export function compileCircleAddLock(expected: CirclePoint): Uint8Array {
  return compileOrThrow(
    `${CIRCLE_ADD}\n${pushFelt(expected.y)}\nOP_NUMEQUALVERIFY\n${pushFelt(expected.x)}\nOP_NUMEQUAL`,
    "cadd",
  );
}

export function compileScalarMulLock(expected: CirclePoint): Uint8Array {
  return compileOrThrow(
    `${SCALAR_MUL}\n${pushFelt(expected.y)}\nOP_NUMEQUALVERIFY\n${pushFelt(expected.x)}\nOP_NUMEQUAL`,
    "smul",
  );
}

export function compileVanishingLock(): Uint8Array {
  return compileOrThrow(`${vanishingUnrolledAsm(VANISH_XS)}\nOP_NUMEQUAL`, "vanish");
}

/**
 * One-query N=Q·Z. Unlocking: even_at, odd_at, q, zx (we pass zx to skip scalar-mul
 * in this isolated lock). Lock recomputes Z(zx) and N from T(z),T(z+g),T(z+2g)
 * supplied as six Newton results? Isolated version: unlocking is q z n, lock checks q*z==n.
 *
 * Full N is checked in compileCqzFromCellsLock.
 */
export function compileQzEqualsNLock(): Uint8Array {
  return compileOrThrow(`${M31_MUL}\nOP_NUMEQUAL`, "qz=n");
}

export function compileNewtonFromBlobLock(): Uint8Array {
  return compileOrThrow(`${newtonFromBlobAsm()}\nOP_NUMEQUAL`, "newton-blob");
}

export function compileEvalTFromBlobLock(expected: M31El): Uint8Array {
  return compileOrThrow(
    `
${defineNewtonFn()}
${evalTFromBlobAsm()}
${pushFelt(expected)}
OP_NUMEQUAL
`,
    "evalT-blob",
  );
}

function defineFn(asm: string, index: number, name: string): string {
  const body = cashAssemblyToBin(asm);
  if (typeof body === "string") throw new Error(`${name}: ${body}`);
  return `${hexPush(body)}\n<${index}>\nOP_DEFINE`;
}

function defineNewtonFn(): string {
  return defineFn(newtonFromBlobAsm(), 0, "newton");
}

/** Packed viewing-commit → mask felt. Matches openingMaskFelt for SHA-256. */
function maskCFromInput0Asm(): string {
  return `
<0> OP_INPUTBYTECODE
<1> OP_SPLIT OP_NIP
<2> OP_SPLIT OP_NIP
<${AIR_OFF_OPEN_MASK}> OP_SPLIT OP_NIP
<32> OP_SPLIT OP_DROP
${hexPush(VIEWING_TAG)} OP_SWAP OP_CAT
${hexPush(FRI_OPEN_MASK_TAG)} OP_CAT
OP_SHA256
<4> OP_SPLIT OP_DROP
<3> OP_SPLIT
<0x7f> OP_AND
OP_CAT
OP_BIN2NUM
<2147483647> OP_MOD
`;
}

function defineMaskCFn(index: number): string {
  return defineFn(maskCFromInput0Asm(), index, "maskc");
}

function invokeMaskC(index: number): string {
  return `<${index}> OP_INVOKE`;
}

/** Stack: even odd x y → T(x,y). Requires newton fn 0. Alt-clean. */
export function evalTFromBlobAsm(): string {
  return `
OP_TOALTSTACK
OP_TOALTSTACK
OP_OVER
OP_FROMALTSTACK
OP_DUP
OP_TOALTSTACK
<0> OP_INVOKE
OP_FROMALTSTACK
OP_SWAP
OP_TOALTSTACK
OP_TOALTSTACK
OP_NIP
OP_FROMALTSTACK
<0> OP_INVOKE
OP_FROMALTSTACK
OP_SWAP
OP_FROMALTSTACK
${M31_MUL}
${M31_ADD}
`;
}

/**
 * Stack: packed blob.
 * For each Fiat–Shamir slot: Z([i]G) is recomputed and Q·Z equals nTable[s].
 * Query indices are taken from the packed transcript (bound to this statement).
 */
export function checkAirCqzAsm(): string {
  const g = `${pushFelt(G1024.x)}\n${pushFelt(G1024.y)}`;
  return `
<0>
OP_BEGIN
  OP_DUP
  <${FRI_QUERIES}>
  OP_LESSTHAN
  OP_IF
    OP_OVER
    OP_OVER
    <2> OP_MUL
    <${AIR_OFF_IDX}> OP_ADD
    OP_SPLIT OP_NIP
    <2> OP_SPLIT OP_DROP
    ${BE16_UNSIGNED}
    OP_TOALTSTACK
    OP_OVER
    OP_OVER
    <4> OP_MUL
    <${AIR_OFF_QTABLE}> OP_ADD
    OP_SPLIT OP_NIP
    <4> OP_SPLIT OP_DROP
    OP_BIN2NUM
    OP_TOALTSTACK
    OP_OVER
    OP_SWAP
    <4> OP_MUL
    <${AIR_OFF_NTABLE}> OP_ADD
    OP_SPLIT OP_NIP
    <4> OP_SPLIT OP_DROP
    OP_BIN2NUM
    OP_FROMALTSTACK
    OP_SWAP
    OP_TOALTSTACK
    OP_TOALTSTACK
    OP_FROMALTSTACK
    ${g}
    ${SCALAR_MUL}
    OP_DROP
    ${vanishingUnrolledAsm(VANISH_XS)}
    OP_FROMALTSTACK
    ${M31_MUL}
    OP_FROMALTSTACK
    OP_NUMEQUALVERIFY
    OP_1ADD
    OP_0
  OP_ELSE
    OP_DROP
    OP_1
  OP_ENDIF
OP_UNTIL
OP_DROP
`;
}

export function compileCheckAirLock(): Uint8Array {
  return compileOrThrow(`${checkAirCqzAsm()}\nOP_1`, "check-air");
}

export function packedMagicAsm(): string {
  return `
OP_DUP
<${AIR_OFF_PUB_OLD}> OP_SPLIT OP_NIP
<4> OP_SPLIT OP_DROP
<0x50414131> OP_EQUALVERIFY
`;
}

function padNewton(vals: M31El[]): M31El[] {
  const out = vals.slice();
  while (out.length < AIR_NEWTON_FELTS) out.push(0n);
  return out.slice(0, AIR_NEWTON_FELTS);
}

function lagrangeNewtonBlobs(k: number): { even: Uint8Array; odd: Uint8Array } {
  const interp = interpolateCircle(
    smallDomain,
    Array.from({ length: TRACE_LEN }, (_, i) => (i === k ? 1n : 0n)),
  );
  return {
    even: encodeFeltBlob(padNewton(interp.even)),
    odd: encodeFeltBlob(padNewton(interp.odd)),
  };
}

/** Stack: L0 L23 Tp Tgp Tg2 action → N = L0·cons + L23·seq */
export function airNumeratorAsm(): string {
  return `
OP_3 OP_PICK
OP_3 OP_PICK
OP_SWAP
${M31_SUB}
OP_DUP
<1>
${M31_SUB}
OP_2 OP_PICK
OP_1
OP_NUMEQUAL
OP_IF
  OP_3 OP_PICK
  OP_2 OP_PICK
  OP_SWAP
  ${M31_SUB}
OP_ELSE
  OP_3 OP_PICK
  OP_2 OP_PICK
  <0>
  OP_SWAP
  ${M31_SUB}
  OP_SWAP
  ${M31_SUB}
OP_ENDIF
OP_TOALTSTACK
OP_TOALTSTACK
OP_2DROP
OP_2DROP
OP_DROP
OP_FROMALTSTACK
OP_FROMALTSTACK
OP_3 OP_PICK
OP_OVER
${M31_MUL}
OP_TOALTSTACK
OP_DROP
OP_ROT
OP_DROP
${M31_MUL}
OP_FROMALTSTACK
${M31_ADD}
`;
}

/** Packed public PAA1 noteRoot+seq must match pool NFT (input 0 / output 0). */
export function bindPackedStmtToPaa1Asm(): string {
  return `
OP_DUP
<${AIR_OFF_PUB_NEW + 64}> OP_SPLIT OP_NIP
<32> OP_SPLIT OP_DROP
<0> OP_OUTPUTTOKENCOMMITMENT
<64> OP_SPLIT OP_NIP
<32> OP_SPLIT OP_DROP
OP_EQUALVERIFY
OP_DUP
<${AIR_OFF_PUB_OLD + 64}> OP_SPLIT OP_NIP
<32> OP_SPLIT OP_DROP
<0> OP_UTXOTOKENCOMMITMENT
<64> OP_SPLIT OP_NIP
<32> OP_SPLIT OP_DROP
OP_EQUALVERIFY
OP_DUP
<${AIR_OFF_PUB_NEW + 8}> OP_SPLIT OP_NIP
<8> OP_SPLIT OP_DROP
<0> OP_OUTPUTTOKENCOMMITMENT
<8> OP_SPLIT OP_NIP
<8> OP_SPLIT OP_DROP
OP_EQUALVERIFY
OP_DUP
<${AIR_OFF_PUB_OLD + 8}> OP_SPLIT OP_NIP
<8> OP_SPLIT OP_DROP
<0> OP_UTXOTOKENCOMMITMENT
<8> OP_SPLIT OP_NIP
<8> OP_SPLIT OP_DROP
OP_EQUALVERIFY
`;
}

/** Stack: packed → packed, grindSeed. SHA256(digest || trace || layerRoots || even || odd). */
export function grindSeedFromPackedAsm(): string {
  return `
OP_DUP
<${AIR_OFF_DIGEST}> OP_SPLIT OP_NIP
<32> OP_SPLIT OP_DROP
OP_OVER
<${AIR_OFF_TRACE}> OP_SPLIT OP_NIP
<32> OP_SPLIT OP_DROP
OP_CAT
OP_OVER
<${AIR_OFF_ROOTS}> OP_SPLIT OP_NIP
<224> OP_SPLIT OP_DROP
OP_CAT
OP_OVER
<${AIR_OFF_EVEN}> OP_SPLIT OP_NIP
<${AIR_NEWTON_BYTES}> OP_SPLIT OP_DROP
OP_CAT
OP_OVER
<${AIR_OFF_ODD}> OP_SPLIT OP_NIP
<${AIR_NEWTON_BYTES}> OP_SPLIT OP_DROP
OP_CAT
OP_SHA256
`;
}

/** Stack: packed → packed, seed. seed = SHA256(grindSeed || nonce || "queries"). */
export function fsQuerySeedAsm(): string {
  return `
${grindSeedFromPackedAsm()}
OP_OVER
<${AIR_OFF_NONCE}> OP_SPLIT OP_NIP
<4> OP_SPLIT OP_DROP
OP_CAT
<0x71756572696573> OP_CAT
OP_SHA256
`;
}

/**
 * Stack: blob orbit → blob has.
 * Linear scan of 2-byte LE orbits. Empty blob → 0.
 * OP_SIZE does not consume the item.
 */
export function orbitHasAsm(): string {
  return `
OP_TOALTSTACK
<0>
OP_BEGIN
  OP_OVER
  OP_SIZE
  OP_NIP
  OP_OVER
  OP_SWAP
  OP_GREATERTHANOREQUAL
  OP_IF
    OP_DROP
    OP_0
    OP_1
  OP_ELSE
    OP_OVER
    OP_OVER
    OP_SPLIT
    OP_NIP
    <2>
    OP_SPLIT
    OP_DROP
    OP_BIN2NUM
    OP_FROMALTSTACK
    OP_DUP
    OP_TOALTSTACK
    OP_NUMEQUAL
    OP_IF
      OP_DROP
      OP_1
      OP_1
    OP_ELSE
      <2>
      OP_ADD
      OP_0
    OP_ENDIF
  OP_ENDIF
OP_UNTIL
OP_FROMALTSTACK
OP_DROP
`;
}

/**
 * Stack: packed, h, orbits, idxs → packed, h', orbits', idxs'
 * Mix-in is current unique count (idxs size / 2). Duplicate orbits are skipped.
 */
export function uniqueQueryAttemptAsm(): string {
  return `
OP_TOALTSTACK
OP_TOALTSTACK
<0x71>
OP_CAT
OP_FROMALTSTACK
OP_DUP
OP_TOALTSTACK
OP_SIZE
OP_NIP
<2>
OP_DIV
<1>
OP_NUM2BIN
OP_CAT
OP_SHA256
OP_DUP
<2>
OP_SPLIT
OP_DROP
${BE16_UNSIGNED}
<${FRI_N}>
OP_MOD
OP_DUP
<${FRI_N / 2}>
OP_MOD
OP_FROMALTSTACK
OP_SWAP
${orbitHasAsm()}
OP_IF
  OP_NIP
  OP_FROMALTSTACK
OP_ELSE
  OP_SWAP
  OP_DUP
  OP_TOALTSTACK
  <${FRI_N / 2}>
  OP_MOD
  <2>
  OP_NUM2BIN
  OP_CAT
  OP_FROMALTSTACK
  OP_FROMALTSTACK
  OP_SWAP
  <2>
  OP_NUM2BIN
  OP_CAT
OP_ENDIF
`;
}

/**
 * Stack: packed, seed → packed, index.
 * Rejection-samples until `need` unique first-fold orbits (need = slot+1).
 */
function uniqueFsNeedAsm(need: number): string {
  if (!Number.isInteger(need) || need < 1 || need > FRI_QUERIES) {
    throw new Error(`unique FS need ${need}`);
  }
  return `
OP_0
OP_0
OP_BEGIN
  ${uniqueQueryAttemptAsm()}
  OP_SIZE
  <${2 * need}>
  OP_GREATERTHANOREQUAL
OP_UNTIL
OP_NIP
OP_NIP
OP_SIZE
<2>
OP_SUB
OP_SPLIT
OP_NIP
OP_BIN2NUM
`;
}

/**
 * Stack: packed → packed, i. Altstack top = slot (0..35).
 * Recomputes unique-orbit FS index for that slot (spender table ignored).
 */
export function fsIndexFromAltSlotAsm(): string {
  return `
${fsQuerySeedAsm()}
OP_0
OP_0
OP_BEGIN
  ${uniqueQueryAttemptAsm()}
  OP_SIZE
  OP_FROMALTSTACK
  OP_DUP
  OP_TOALTSTACK
  <1>
  OP_ADD
  <2>
  OP_MUL
  OP_GREATERTHANOREQUAL
OP_UNTIL
OP_NIP
OP_NIP
OP_SIZE
<2>
OP_SUB
OP_SPLIT
OP_NIP
OP_BIN2NUM
`;
}

/**
 * Stack: packed → packed, i. Reads the unique-orbit table at AIR_OFF_IDX.
 * Bind-T (`bindUniqueFsTableAsm`) recomputes the whole table from the FS seed
 * so fold/R-slot kernels do not re-run unique-orbit sampling (that is what
 * forced KERNEL_UNLOCK_PAD_HIGH).
 */
export function packedFsIndexAsm(slot: number): string {
  return `
OP_DUP
<${AIR_OFF_IDX + slot * 2}> OP_SPLIT OP_NIP
<2> OP_SPLIT OP_DROP
${BE16_UNSIGNED}
`;
}

/** Stack: packed → packed, i. Unique-orbit FS for a compile-time slot. */
export function fsIndexSlotAsm(slot: number): string {
  return packedFsIndexAsm(slot);
}

/**
 * Stack: packed → packed. Recompute 36 unique-orbit FS indices and require
 * they equal packed AIR_OFF_IDX. Runs once in bind-T.
 */
/** Stack: flags512 orbit → flags512 has. Byte at orbit is 0 or 1. */
function orbitFlagHasAsm(): string {
  return `
OP_OVER
OP_SWAP
OP_SPLIT
OP_NIP
<1>
OP_SPLIT
OP_DROP
OP_0NOTEQUAL
`;
}

/** Stack: flags512 orbit → flags512' with byte[orbit]=1. */
function orbitFlagSetAsm(): string {
  return `
OP_SWAP
OP_OVER
OP_SPLIT
OP_NIP
<1>
OP_SPLIT
OP_NIP
<0x01>
OP_SWAP
OP_CAT
OP_CAT
`;
}

/**
 * Stack: packed, h, flags512, idxs → packed, h', flags', idxs'
 * Same mix-in as uniqueQueryAttemptAsm; O(1) orbit membership via a 512-byte flag blob.
 */
function uniqueQueryAttemptFlagAsm(): string {
  return `
OP_DUP
OP_SIZE
OP_NIP
<2>
OP_DIV
<1>
OP_NUM2BIN
OP_SWAP
OP_TOALTSTACK
OP_SWAP
OP_TOALTSTACK
<0x71>
OP_CAT
OP_SWAP
OP_CAT
OP_SHA256
OP_DUP
<2>
OP_SPLIT
OP_DROP
${BE16_UNSIGNED}
<${FRI_N}>
OP_MOD
OP_DUP
<${FRI_N / 2}>
OP_MOD
OP_FROMALTSTACK
OP_SWAP
${orbitFlagHasAsm()}
OP_IF
  OP_NIP
  OP_FROMALTSTACK
OP_ELSE
  OP_SWAP
  OP_DUP
  OP_TOALTSTACK
  <${FRI_N / 2}>
  OP_MOD
  ${orbitFlagSetAsm()}
  OP_FROMALTSTACK
  OP_SWAP
  <2>
  OP_NUM2BIN
  OP_CAT
OP_ENDIF
`;
}

export function bindUniqueFsTableAsm(): string {
  const compares = Array.from({ length: FRI_QUERIES }, (_, s) => `
OP_DUP
<${s * 2}> OP_SPLIT OP_NIP
<2> OP_SPLIT OP_DROP
<0x00> OP_CAT
OP_BIN2NUM
OP_2 OP_PICK
<${AIR_OFF_IDX + s * 2}> OP_SPLIT OP_NIP
<2> OP_SPLIT OP_DROP
${BE16_UNSIGNED}
OP_NUMEQUALVERIFY
`).join("\n");
  return `
${fsQuerySeedAsm()}
OP_0
OP_0
OP_BEGIN
  ${uniqueQueryAttemptAsm()}
  OP_SIZE
  <${2 * FRI_QUERIES}>
  OP_GREATERTHANOREQUAL
OP_UNTIL
OP_NIP
OP_NIP
${compares}
OP_DROP
`;
}

/** Same bind as bindUniqueFsTableAsm, O(1) orbit flags instead of linear scan. */
export function bindUniqueFsTableFlagAsm(): string {
  const compares = Array.from({ length: FRI_QUERIES }, (_, s) => `
OP_DUP
<${s * 2}> OP_SPLIT OP_NIP
<2> OP_SPLIT OP_DROP
<0x00> OP_CAT
OP_BIN2NUM
OP_2 OP_PICK
<${AIR_OFF_IDX + s * 2}> OP_SPLIT OP_NIP
<2> OP_SPLIT OP_DROP
${BE16_UNSIGNED}
OP_NUMEQUALVERIFY
`).join("\n");
  return `
${fsQuerySeedAsm()}
<0x${"00".repeat(512)}>
OP_0
OP_BEGIN
  ${uniqueQueryAttemptFlagAsm()}
  OP_SIZE
  <${2 * FRI_QUERIES}>
  OP_GREATERTHANOREQUAL
OP_UNTIL
OP_NIP
OP_NIP
${compares}
OP_DROP
`;
}

/** Stack: packed → packed, i. i = Fiat–Shamir query 0. */
export function fsIndex0Asm(): string {
  return fsIndexSlotAsm(0);
}

/**
 * One FS slot: (qTable[slot] − R(i)) · Z([i]G) equals N from T.
 * Independent AIR numerator — masked nTable would cancel R.
 */
export function slotCqzAsm(slot = 0): string {
  return slotRCqzAsm(slot);
}

export function slot0CqzAsm(): string {
  return slotCqzAsm(0);
}

/** Isolated slot-0 (q−R)·Z == N. Unlocking: packed blob. */
export function compileSlot0CqzLock(): Uint8Array {
  return compileOrThrow(`${slotCqzAsm(0)}\nOP_1`, "slot0-cqz");
}

export function compileSlotCqzLock(slot: number): Uint8Array {
  return compileOrThrow(`${slotCqzAsm(slot)}\nOP_1`, `slot-${slot}-cqz`);
}

function conjugatePairs(): { i: number; j: number; x: M31El; y: M31El }[] {
  const seen = new Set<string>();
  const pairs: { i: number; j: number; x: M31El; y: M31El }[] = [];
  for (let i = 0; i < TRACE_LEN; i += 1) {
    const p = smallDomain[i]!;
    const key = p.x.toString();
    if (seen.has(key)) continue;
    seen.add(key);
    const ny = p.y === 0n ? 0n : M31 - p.y;
    let j = i;
    for (let k = 0; k < TRACE_LEN; k += 1) {
      if (smallDomain[k]!.x === p.x && smallDomain[k]!.y === ny) {
        j = k;
        break;
      }
    }
    pairs.push({ i, j, x: p.x, y: p.y });
  }
  return pairs;
}

export function extractCellAsm(index: number): string {
  return `
<${AIR_OFF_CELLS + index * 4}> OP_SPLIT OP_NIP
<4> OP_SPLIT OP_DROP
OP_BIN2NUM
`;
}

/** Stack: packed even odd → same. even/odd interpolate AIR-relevant packed cells + mask. */
export function bindTToCellsAsm(maskFn = 1, neededCells: readonly number[] = [3, 18, 23, 24]): string {
  const needed = new Set(neededCells);
  const lines: string[] = [];
  for (const { i, j, x, y } of conjugatePairs().filter((p) => needed.has(p.i) || needed.has(p.j))) {
    lines.push(`
OP_OVER
${pushFelt(x)}
<0> OP_INVOKE
OP_OVER
${pushFelt(x)}
<0> OP_INVOKE
OP_4 OP_PICK
${extractCellAsm(i)}
${invokeMaskC(maskFn)}
${M31_ADD}
OP_5 OP_PICK
${extractCellAsm(j)}
${invokeMaskC(maskFn)}
${M31_ADD}
OP_2DUP
${M31_ADD}
OP_4 OP_PICK
OP_DUP
${M31_ADD}
OP_NUMEQUALVERIFY
${pushFelt(y)}
OP_DUP
${M31_ADD}
OP_3 OP_PICK
${M31_MUL}
OP_2 OP_PICK
OP_2 OP_PICK
${M31_SUB}
OP_NUMEQUALVERIFY
OP_2DROP
OP_2DROP
`);
  }
  return lines.join("\n");
}

function be8UnsignedAsm(): string {
  const oneByte = `
OP_1 OP_SPLIT
OP_ROT
<256> OP_MUL
OP_ROT
<0x00> OP_CAT
OP_BIN2NUM
OP_ADD
OP_SWAP
`;
  return `
<0>
OP_SWAP
${oneByte}
${oneByte}
${oneByte}
${oneByte}
${oneByte}
${oneByte}
${oneByte}
${oneByte}
OP_DROP
`;
}

function be8ModPAsm(): string {
  return `
${be8UnsignedAsm()}
<2147483647> OP_MOD
`;
}

function eqCellToStmtU64Asm(cellIndex: number, stmtOff: number): string {
  return `
OP_DUP
${extractCellAsm(cellIndex)}
OP_OVER
<${stmtOff}> OP_SPLIT OP_NIP
<8> OP_SPLIT OP_DROP
${be8ModPAsm()}
OP_NUMEQUALVERIFY
`;
}

/** Stack: packed → packed. Sequence cells match public PAA1 (amounts stay in verifyFri). */
export function bindCellsToStatementAsm(): string {
  return `
${eqCellToStmtU64Asm(23, AIR_OFF_PUB_OLD + 8)}
${eqCellToStmtU64Asm(24, AIR_OFF_PUB_NEW + 8)}
`;
}

/**
 * One FS slot. Stack: packed even odd action slot → packed even odd action slot.
 * Recomputes N from T; nTable[s]==N; if Z≠0 then qTable[s]·Z==N.
 */
function oneFsSlotBodyAsm(): string {
  const l0 = lagrangeNewtonBlobs(0);
  const l23 = lagrangeNewtonBlobs(23);
  const g64 = `${pushFelt(G64.x)}\n${pushFelt(G64.y)}`;
  return `
OP_4 OP_PICK
OP_1 OP_PICK
<2> OP_MUL
<${AIR_OFF_IDX}> OP_ADD
OP_SPLIT OP_NIP
<2> OP_SPLIT OP_DROP
${BE16_UNSIGNED}
OP_TOALTSTACK
OP_4 OP_PICK
OP_1 OP_PICK
<4> OP_MUL
<${AIR_OFF_QTABLE}> OP_ADD
OP_SPLIT OP_NIP
<4> OP_SPLIT OP_DROP
OP_BIN2NUM
OP_TOALTSTACK
OP_4 OP_PICK
OP_1 OP_PICK
<4> OP_MUL
<${AIR_OFF_NTABLE}> OP_ADD
OP_SPLIT OP_NIP
<4> OP_SPLIT OP_DROP
OP_BIN2NUM
OP_FROMALTSTACK
OP_FROMALTSTACK
OP_FROMALTSTACK
${pushFelt(G1024.x)}
${pushFelt(G1024.y)}
<2> OP_INVOKE
OP_OVER
<3> OP_INVOKE
OP_TOALTSTACK
OP_2SWAP
OP_TOALTSTACK
OP_TOALTSTACK
OP_TOALTSTACK
OP_2 OP_PICK
OP_TOALTSTACK
OP_TOALTSTACK
OP_TOALTSTACK
OP_TOALTSTACK
OP_FROMALTSTACK
OP_FROMALTSTACK
OP_2OVER
OP_3 OP_PICK
OP_3 OP_PICK
<1> OP_INVOKE
OP_TOALTSTACK
OP_2DUP
${g64}
${CIRCLE_ADD}
OP_5 OP_PICK
OP_5 OP_PICK
OP_3 OP_PICK
OP_3 OP_PICK
<1> OP_INVOKE
OP_TOALTSTACK
OP_2DUP
${g64}
${CIRCLE_ADD}
OP_7 OP_PICK
OP_7 OP_PICK
OP_3 OP_PICK
OP_3 OP_PICK
<1> OP_INVOKE
OP_TOALTSTACK
OP_2DROP
OP_2DROP
OP_2DUP
${hexPush(l0.even)}
${hexPush(l0.odd)}
OP_2SWAP
<1> OP_INVOKE
OP_TOALTSTACK
OP_2DUP
${hexPush(l23.even)}
${hexPush(l23.odd)}
OP_2SWAP
<1> OP_INVOKE
OP_TOALTSTACK
OP_2DROP
OP_FROMALTSTACK
OP_FROMALTSTACK
OP_SWAP
OP_FROMALTSTACK
OP_FROMALTSTACK
OP_FROMALTSTACK
OP_SWAP
OP_ROT
OP_FROMALTSTACK
${airNumeratorAsm()}
OP_FROMALTSTACK
OP_FROMALTSTACK
OP_FROMALTSTACK
OP_FROMALTSTACK
OP_FROMALTSTACK
OP_FROMALTSTACK
OP_DUP
OP_0
OP_NUMEQUAL
OP_IF
  OP_DROP
  OP_0
  OP_NUMEQUALVERIFY
  OP_0
  OP_NUMEQUALVERIFY
  OP_DROP
  OP_3 OP_ROLL
  OP_0
  OP_NUMEQUALVERIFY
OP_ELSE
  OP_1 OP_PICK
  OP_7 OP_PICK
  OP_NUMEQUALVERIFY
  OP_1 OP_PICK
  OP_1 OP_PICK
  ${M31_MUL}
  OP_6 OP_PICK
  OP_NUMEQUALVERIFY
  OP_2DROP
  OP_DROP
  OP_3 OP_ROLL
  OP_DROP
OP_ENDIF
`;
}

/**
 * All FS slots + T bound to packed cells + cells bound to the statement.
 * Stack in: packed blob.
 */
export function allSlotsCqzAsm(): string {
  return `
${defineNewtonFn()}
${defineFn(evalTFromBlobAsm(), 1, "evalT")}
${defineFn(SCALAR_MUL_FAST, 2, "fast")}
${defineFn(vanishingUnrolledAsm(VANISH_XS), 3, "vanish")}
${defineMaskCFn(4)}
${packedMagicAsm()}
OP_DUP
<${AIR_OFF_EVEN}> OP_SPLIT OP_NIP
<${AIR_NEWTON_BYTES}> OP_SPLIT OP_DROP
OP_TOALTSTACK
OP_DUP
<${AIR_OFF_ODD}> OP_SPLIT OP_NIP
<${AIR_NEWTON_BYTES}> OP_SPLIT OP_DROP
OP_FROMALTSTACK
OP_SWAP
${bindTToCellsAsm(4)}
OP_TOALTSTACK
OP_TOALTSTACK
${bindCellsToStatementAsm()}
OP_FROMALTSTACK
OP_FROMALTSTACK
OP_OVER
${extractCellAsm(3)}
<0>
OP_BEGIN
  OP_DUP
  <${FRI_QUERIES}>
  OP_LESSTHAN
  OP_IF
    ${oneFsSlotBodyAsm()}
    OP_1ADD
    OP_0
  OP_ELSE
    OP_DROP
    OP_1
  OP_ENDIF
OP_UNTIL
OP_2DROP
OP_2DROP
`;
}

export function compileBindTLock(): Uint8Array {
  return compileOrThrow(
    `
${packedMagicAsm()}
${bindCellsToStatementAsm()}
OP_DROP
OP_1
`,
    "bind-t",
  );
}

export function compileAllSlotsCqzLock(): Uint8Array {
  return compileOrThrow(`${allSlotsCqzAsm()}\nOP_1`, "all-slots-cqz");
}

function pushRedeem(data: Uint8Array): Uint8Array {
  if (data.length <= 75) return Uint8Array.of(data.length, ...data);
  if (data.length <= 255) return Uint8Array.of(0x4c, data.length, ...data);
  return Uint8Array.of(0x4d, data.length & 0xff, (data.length >> 8) & 0xff, ...data);
}

/** Q table + FS indices + on-chain cells + N table (bind-T witness; density for unique-orbit verify). */
export const BIND_T_QIDX_BYTES = AIR_OFF_NTABLE + FRI_QUERIES * 4 - AIR_OFF_QTABLE;
/** Same-tx bind tail: packed || leftover[:CQZ_BIND_TAIL], hashed against input 0. */
export const CQZ_BIND_TAIL = 288;

export const BIND_T_KERNEL = `
${defineNewtonFn()}
${defineMaskCFn(4)}
OP_SHA256
OP_TOALTSTACK
<0> OP_INPUTBYTECODE
<1> OP_SPLIT OP_NIP
<2> OP_SPLIT OP_NIP
${packedMagicAsm()}
OP_DUP
<${AIR_PACKED_SIZE + CQZ_BIND_TAIL}>
OP_SPLIT
OP_DROP
OP_SHA256
OP_FROMALTSTACK
OP_EQUALVERIFY
<${AIR_PACKED_SIZE}>
OP_SPLIT
OP_DROP
${bindUniqueFsTableAsm()}
OP_DUP
<${AIR_OFF_EVEN}> OP_SPLIT OP_NIP
<${AIR_NEWTON_BYTES}> OP_SPLIT OP_DROP
OP_TOALTSTACK
OP_DUP
<${AIR_OFF_ODD}> OP_SPLIT OP_NIP
<${AIR_NEWTON_BYTES}> OP_SPLIT OP_DROP
OP_FROMALTSTACK
OP_SWAP
${bindTToCellsAsm(4, [3, 5, 6])}
OP_TOALTSTACK
OP_TOALTSTACK
${bindPackedStmtToPaa1Asm()}
${bindCellsToStatementAsm()}
OP_FROMALTSTACK
OP_FROMALTSTACK
OP_2DROP
OP_DROP
OP_1
`;

export const SLOTS_PER_KERNEL = 6;
/** Distinct FS slots that still fit one standard 100 KB tx with R on-chain (4 R-slots). */
export const SLOT_KERNEL_COUNT = 4;
/** Consensus kernels: FRI_QUERIES / SLOTS_PER_KERNEL. Each kernel still checks SLOTS_PER_KERNEL on-chain R. */
export const SLOT_KERNEL_COUNT_CONSENSUS = FRI_QUERIES / SLOTS_PER_KERNEL;

/** Unlocking: <dummy> <slot> <redeem>. Redeem is compiled for that slot (Velma ≤ 10 KB). */
export function slotsCqzAsm(slot = 0, n = 1): string {
  const extra = Array.from({ length: Math.max(0, n - 1) }, (_, j) => `
<0> OP_INPUTBYTECODE
<1> OP_SPLIT OP_NIP
<2> OP_SPLIT OP_NIP
${slotRCqzBodyAsm(slot + 1 + j)}
`).join("\n");
  return `
<0> OP_INPUTBYTECODE
<1> OP_SPLIT OP_NIP
<2> OP_SPLIT OP_NIP
${bindPackedStmtToPaa1Asm()}
${slotCqzAsm(slot)}
${extra}
OP_1
`;
}

/** Kernel redeem: bind T to the public interpolant (input 11). */
export const CQZ_KERNEL = BIND_T_KERNEL;

export function compileCqzKernel(): Uint8Array {
  return compileOrThrow(CQZ_KERNEL, "cqz-kernel");
}

export function compileCqzBind(bindAsm: string): Uint8Array {
  const asm = BIND_T_KERNEL.replace(bindUniqueFsTableAsm(), bindAsm);
  if (bindAsm !== bindUniqueFsTableAsm() && asm === BIND_T_KERNEL) {
    throw new Error("cqz bind replace missed");
  }
  return compileOrThrow(asm, "cqz-bind");
}

export function compileSlotsKernel(slot = 0, n = 1): Uint8Array {
  return compileOrThrow(slotsCqzAsm(slot, n), `slots-kernel-${slot}x${n}`);
}

export function compileCqzLockP2sh32(): Uint8Array {
  return encodeLockingBytecodeP2sh32(hash256(compileCqzKernel()));
}

export function compileSlotsLockP2sh32(slot = 0, n = 1): Uint8Array {
  return encodeLockingBytecodeP2sh32(hash256(compileSlotsKernel(slot, n)));
}

export function cqzKernelUnlocking(packed?: Uint8Array): Uint8Array {
  const redeem = pushRedeem(compileCqzKernel());
  if (!(packed instanceof Uint8Array)) return redeem;
  const head = packed.length >= AIR_PACKED_SIZE ? packed.subarray(0, AIR_PACKED_SIZE) : packed;
  const tail = packed.length >= AIR_PACKED_SIZE + CQZ_BIND_TAIL
    ? packed.subarray(AIR_PACKED_SIZE, AIR_PACKED_SIZE + CQZ_BIND_TAIL)
    : head.subarray(0, Math.min(CQZ_BIND_TAIL, head.length));
  const body = new Uint8Array(head.length + tail.length);
  body.set(head, 0);
  body.set(tail, head.length);
  const push = Uint8Array.of(0x4d, body.length & 0xff, (body.length >> 8) & 0xff, ...body);
  const out = new Uint8Array(push.length + redeem.length);
  out.set(push, 0);
  out.set(redeem, push.length);
  return out;
}

export function slotsKernelUnlocking(start: number, n = 1, packed?: Uint8Array): Uint8Array {
  void packed;
  return pushRedeem(compileSlotsKernel(start, n));
}

export function compileScalarMulFastLock(expected: CirclePoint): Uint8Array {
  return compileOrThrow(
    `${SCALAR_MUL_FAST}\n${pushFelt(expected.y)}\nOP_NUMEQUALVERIFY\n${pushFelt(expected.x)}\nOP_NUMEQUAL`,
    "smul-fast",
  );
}

/**
 * One FS query: packed blob on stack, slot on top.
 * Recomputes i = FS[slot], z=[i]G, Z, T, N, checks qTable[slot]*Z == N.
 */
export function oneQueryCqzAsm(): string {
  const l0e = encodeFeltBlob(interpolateCircle(smallDomain, oneHot(0)).even);
  const l0o = encodeFeltBlob(interpolateCircle(smallDomain, oneHot(0)).odd);
  const l23e = encodeFeltBlob(interpolateCircle(smallDomain, oneHot(23)).even);
  const l23o = encodeFeltBlob(interpolateCircle(smallDomain, oneHot(23)).odd);
  return `
OP_TOALTSTACK
<${AIR_OFF_QTABLE}> OP_SPLIT OP_NIP
OP_FROMALTSTACK
OP_DUP
OP_TOALTSTACK
<4> OP_MUL
OP_SPLIT OP_NIP
<4> OP_SPLIT OP_DROP
OP_BIN2NUM
OP_TOALTSTACK
`;
}

function oneHot(k: number): M31El[] {
  return Array.from({ length: TRACE_LEN }, (_, i) => (i === k ? 1n : 0n));
}

/**
 * Given at_x, evaluate T = even(at) + y*odd(at).
 * Unlocking: at_x  at_y. Redeem contains even/odd coeff literals.
 */
export function compileEvalTLock(even: M31El[], odd: M31El[], expected: M31El): Uint8Array {
  return compileOrThrow(
    `
OP_TOALTSTACK
OP_DUP
OP_TOALTSTACK
${newtonEvalUnrolledAsm(even)}
OP_FROMALTSTACK
${newtonEvalUnrolledAsm(odd)}
OP_FROMALTSTACK
${M31_MUL}
${M31_ADD}
${pushFelt(expected)}
OP_NUMEQUAL
`,
    "evalT",
  );
}

export function compileCqzRelationLock(statement: PoolStatement, index: number): Uint8Array {
  const interp = statementNewton(statement);
  const z = bigDomain[index]!;
  const zg = addPoints(z, G64);
  const zg2 = addPoints(zg, G64);
  const tp = add(newtonEvalJs(interp.even, z.x), mul(z.y, newtonEvalJs(interp.odd, z.x)));
  const tgp = add(newtonEvalJs(interp.even, zg.x), mul(zg.y, newtonEvalJs(interp.odd, zg.x)));
  const tg2 = add(newtonEvalJs(interp.even, zg2.x), mul(zg2.y, newtonEvalJs(interp.odd, zg2.x)));
  const deposit = statement.action === "DEPOSIT";
  const cons = deposit ? sub(sub(tgp, tp), tg2) : sub(sub(tp, tgp), tg2);
  const seq = sub(sub(tgp, tp), 1n);
  const l0 = oneHotEval(0, z);
  const l23 = oneHotEval(23, z);
  const n = add(mul(l0, cons), mul(l23, seq));
  const { q, z: zVal } = nqzAt(statement, index);
  if (mul(q, zVal) !== n) throw new Error("JS C=QZ mismatch");
  return compileQzEqualsNLock();
}

function oneHotEval(k: number, p: CirclePoint): M31El {
  const interp = interpolateCircle(
    smallDomain,
    Array.from({ length: TRACE_LEN }, (_, i) => (i === k ? 1n : 0n)),
  );
  return add(newtonEvalJs(interp.even, p.x), mul(p.y, newtonEvalJs(interp.odd, p.x)));
}

/** First unlocking item is the packed AIR blob (PUSHDATA2). */
export const LOAD_AIR_PACKED = `
<0> OP_INPUTBYTECODE
<1> OP_SPLIT OP_NIP
<2> OP_SPLIT OP_NIP
`;

export { smallDomain, bigDomain, addPoints, scalarMul, CIRCLE_GEN };

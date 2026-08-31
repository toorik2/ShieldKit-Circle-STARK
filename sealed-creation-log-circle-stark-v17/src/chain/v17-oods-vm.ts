/** BCH-2026 lowering for the v17 degree-corrected OODS point primitives. */
import { binToHex, cashAssemblyToBin } from "@bitauth/libauth";
import {
  V17_OODS_DOMAIN,
  V17_OODS_MAX_ATTEMPTS,
  V17_OODS_REJECTION_LIMIT,
  V17_QM31_CARDINALITY,
  type V17OodsChallenge,
} from "../backends/circle/v17-oods.ts";
import { M31 } from "../backends/circle/m31.ts";
import { encodeQm31 } from "../backends/circle/qm31.ts";
import { bytesToHex } from "../pool/bytes.ts";
import { M31_P, M31_SUB } from "./m31-asm.ts";
import {
  BLOB_TO_QM31_ASM,
  QM31_ADD_ASM,
  QM31_MUL_ASM,
  QM31_TO_BLOB_ASM,
} from "./qm31-asm.ts";

const CANDIDATE_ACCEPTS = 0;
const READ_CANONICAL_QM31 = 1;
const QM31_MUL = 2;
const QM31_ADD = 3;
const QM31_SUB = 4;
const QM31_TO_BLOB = 5;
const QM31_BLOB_MUL = 6;
const QM31_BLOB_ADD = 7;
const QM31_BLOB_SUB = 8;

/** Stable function-table contract shared by theorem-facing v17 VM roles. */
export const V17_OODS_VM_FUNCTION_IDS = Object.freeze({
  candidateAccepts: CANDIDATE_ACCEPTS,
  readCanonicalQm31: READ_CANONICAL_QM31,
  qm31Mul: QM31_MUL,
  qm31Add: QM31_ADD,
  qm31Sub: QM31_SUB,
  qm31ToBlob: QM31_TO_BLOB,
});

function compile(assembly: string, label: string): Uint8Array {
  const result = cashAssemblyToBin(assembly);
  if (typeof result === "string") throw new Error(`${label}: ${result}`);
  return result;
}

function define(assembly: string, identifier: number, label: string): string {
  return `<0x${binToHex(compile(assembly, label))}> <${identifier}> OP_DEFINE`;
}

function hexPush(bytes: Uint8Array): string {
  return `<0x${bytesToHex(bytes)}>`;
}

function decodeAcceptedIntegerAssembly(): string {
  return `OP_REVERSEBYTES <0x00> OP_CAT OP_BIN2NUM
OP_DUP <${V17_OODS_REJECTION_LIMIT}> OP_LESSTHAN OP_VERIFY
<${V17_QM31_CARDINALITY}> OP_MOD
${Array.from({ length: 3 }, () => `OP_DUP <${M31}> OP_MOD
OP_SWAP <${M31}> OP_DIV`).join("\n")}`;
}

function candidateLimbsValidAssembly(): string {
  // Stack throughout: a0 a1 a2 a3. Compute `not(base || +/-i)` without
  // consuming the limbs, then drop them after preserving the result.
  return `<2> OP_PICK OP_0 OP_NUMEQUAL
<2> OP_PICK OP_0 OP_NUMEQUAL OP_BOOLAND
OP_1 OP_PICK OP_0 OP_NUMEQUAL OP_BOOLAND
OP_TOALTSTACK
<3> OP_PICK OP_0 OP_NUMEQUAL
<2> OP_PICK OP_0 OP_NUMEQUAL OP_BOOLAND
OP_1 OP_PICK OP_0 OP_NUMEQUAL OP_BOOLAND
<3> OP_PICK
OP_DUP OP_1 OP_NUMEQUAL
OP_SWAP <${M31 - 1n}> OP_NUMEQUAL OP_BOOLOR
OP_BOOLAND
OP_FROMALTSTACK OP_BOOLOR OP_NOT
OP_TOALTSTACK OP_2DROP OP_2DROP OP_FROMALTSTACK`;
}

/** Stack: digest32 -> boolean. No modulo-bias repair and no abort on rejection. */
export function v17OodsCandidateAcceptanceAssembly(): string {
  return `OP_SIZE <32> OP_NUMEQUALVERIFY
OP_REVERSEBYTES <0x00> OP_CAT OP_BIN2NUM
OP_DUP <${V17_OODS_REJECTION_LIMIT}> OP_LESSTHAN
OP_IF
  <${V17_QM31_CARDINALITY}> OP_MOD
  ${Array.from({ length: 3 }, () => `OP_DUP <${M31}> OP_MOD
  OP_SWAP <${M31}> OP_DIV`).join("\n")}
  ${candidateLimbsValidAssembly()}
OP_ELSE
  OP_DROP OP_0
OP_ENDIF`;
}

/** Stack: accepted digest32 -> canonical a0 a1 a2 a3. */
export function v17OodsDigestToTAssembly(): string {
  return `OP_DUP
${v17OodsCandidateAcceptanceAssembly()}
OP_VERIFY
${decodeAcceptedIntegerAssembly()}`;
}

/**
 * Stack: transcriptDigest32 -> selectedDigest32.
 * Both SHA attempts are fixed and the first accepted digest wins. Exhaustion
 * rejects. There is no prover-supplied retry counter or arithmetic hint.
 */
export function v17OodsSelectDigestAssembly(
  candidateFunction = CANDIDATE_ACCEPTS,
): string {
  if (V17_OODS_MAX_ATTEMPTS !== 2) throw new Error("v17 OODS VM attempt schedule");
  const domain = hexPush(V17_OODS_DOMAIN);
  return `OP_SIZE <32> OP_NUMEQUALVERIFY
OP_DUP
${domain} OP_SWAP OP_CAT <0x00> OP_CAT OP_SHA256
OP_DUP <${candidateFunction}> OP_INVOKE
OP_IF
  OP_NIP
OP_ELSE
  OP_DROP
  ${domain} OP_SWAP OP_CAT <0x01> OP_CAT OP_SHA256
  OP_DUP <${candidateFunction}> OP_INVOKE OP_VERIFY
OP_ENDIF`;
}

function canonicalQm31Assembly(): string {
  const check = (depth: number): string => `<${depth}> OP_PICK
OP_DUP OP_0 OP_GREATERTHANOREQUAL OP_VERIFY
OP_DUP <${M31_P}> OP_LESSTHAN OP_VERIFY OP_DROP`;
  return `${BLOB_TO_QM31_ASM}
${Array.from({ length: 4 }, (_, depth) => check(depth)).join("\n")}`;
}

function qm31SubtractAssembly(): string {
  return `<4> OP_PICK OP_1 OP_PICK ${M31_SUB} OP_TOALTSTACK
<5> OP_PICK <2> OP_PICK ${M31_SUB} OP_TOALTSTACK
<6> OP_PICK <3> OP_PICK ${M31_SUB} OP_TOALTSTACK
<7> OP_PICK <4> OP_PICK ${M31_SUB} OP_TOALTSTACK
OP_2DROP OP_2DROP OP_2DROP OP_2DROP
OP_FROMALTSTACK OP_FROMALTSTACK OP_FROMALTSTACK OP_FROMALTSTACK`;
}

class BlobAssembly {
  readonly lines: string[] = [];
  extra = 0;

  constructor(readonly baseCount: number) {}

  private depth(base: number): number {
    return this.baseCount + this.extra - 1 - base;
  }

  read(base: number): void {
    this.lines.push(`<${this.depth(base)}> OP_PICK <${READ_CANONICAL_QM31}> OP_INVOKE`);
    this.extra += 4;
  }

  binary(operation: number): void {
    this.lines.push(`<${operation}> OP_INVOKE`);
    this.extra -= 4;
  }

  encode(): void {
    this.lines.push(`<${QM31_TO_BLOB}> OP_INVOKE`);
    this.extra -= 3;
  }
}

function qm31BlobBinaryAssembly(operation: number): string {
  const body = new BlobAssembly(2);
  body.read(0);
  body.read(1);
  body.binary(operation);
  body.encode();
  if (body.extra !== 1) throw new Error("v17 OODS QM31 blob binary stack");
  return `${body.lines.join("\n")}
OP_TOALTSTACK OP_2DROP OP_FROMALTSTACK`;
}

class ElementAssembly {
  readonly lines: string[] = [];

  constructor(readonly stack: string[]) {}

  private depth(name: string): number {
    const index = this.stack.lastIndexOf(name);
    if (index < 0) throw new Error(`v17 OODS VM missing ${name}`);
    return this.stack.length - 1 - index;
  }

  copy(name: string, copy: string): void {
    this.lines.push(`<${this.depth(name)}> OP_PICK`);
    this.stack.push(copy);
  }

  constant(bytes: Uint8Array, name: string): void {
    this.lines.push(hexPush(bytes));
    this.stack.push(name);
  }

  call(identifier: number, inputs: readonly string[], result: string): void {
    inputs.forEach((input, index) => this.copy(input, `${result}:arg${index}`));
    this.lines.push(`<${identifier}> OP_INVOKE`);
    this.stack.splice(this.stack.length - inputs.length, inputs.length, result);
  }

  equal(left: string, right: string): void {
    this.copy(left, `${left}:check`);
    this.copy(right, `${right}:check`);
    this.lines.push("OP_EQUALVERIFY");
    this.stack.splice(this.stack.length - 2, 2);
  }

  nonzero(name: string): void {
    this.copy(name, `${name}:check`);
    this.lines.push(`<0x${"00".repeat(16)}> OP_EQUAL OP_NOT OP_VERIFY`);
    this.stack.pop();
  }

  finish(): string {
    this.lines.push(...Array.from({ length: this.stack.length }, () => "OP_DROP"), "OP_1");
    this.stack.splice(0);
    return this.lines.join("\n");
  }
}

/** Stack: tBlob xBlob yBlob -> true iff the unique Cayley identities hold. */
export function v17OodsCayleyIdentityAssembly(): string {
  const body = new ElementAssembly(["t", "x", "y"]);
  body.constant(encodeQm31([1n, 0n, 0n, 0n]), "one");
  body.call(QM31_BLOB_MUL, ["t", "t"], "t2");
  body.call(QM31_BLOB_ADD, ["one", "t2"], "denominator");
  body.nonzero("denominator");
  body.call(QM31_BLOB_SUB, ["one", "t2"], "xNumerator");
  body.call(QM31_BLOB_MUL, ["denominator", "x"], "xProduct");
  body.equal("xProduct", "xNumerator");
  body.call(QM31_BLOB_ADD, ["t", "t"], "yNumerator");
  body.call(QM31_BLOB_MUL, ["denominator", "y"], "yProduct");
  body.equal("yProduct", "yNumerator");
  return body.finish();
}

export function v17OodsDefinitions(): string {
  return `${define(v17OodsCandidateAcceptanceAssembly(), CANDIDATE_ACCEPTS, "v17 OODS candidate")}
${define(canonicalQm31Assembly(), READ_CANONICAL_QM31, "v17 OODS canonical QM31")}
${define(QM31_MUL_ASM, QM31_MUL, "v17 OODS QM31 multiply")}
${define(QM31_ADD_ASM, QM31_ADD, "v17 OODS QM31 add")}
${define(qm31SubtractAssembly(), QM31_SUB, "v17 OODS QM31 subtract")}
${define(QM31_TO_BLOB_ASM, QM31_TO_BLOB, "v17 OODS QM31 encode")}
${define(qm31BlobBinaryAssembly(QM31_MUL), QM31_BLOB_MUL, "v17 OODS blob multiply")}
${define(qm31BlobBinaryAssembly(QM31_ADD), QM31_BLOB_ADD, "v17 OODS blob add")}
${define(qm31BlobBinaryAssembly(QM31_SUB), QM31_BLOB_SUB, "v17 OODS blob subtract")}`;
}

/**
 * Fixed-vector lock for cross-language/VM KATs. Every expected byte is supplied
 * by the test vector, while the VM independently performs both transcript
 * hashing/rejection and the Cayley identities.
 */
export function compileV17OodsKatLock(
  transcriptDigest: Uint8Array,
  expected: V17OodsChallenge,
): Uint8Array {
  if (transcriptDigest.length !== 32 || expected.digest.length !== 32) {
    throw new Error("v17 OODS KAT width");
  }
  const tBlob = encodeQm31(expected.t);
  const pointX = encodeQm31(expected.point.x);
  const pointY = encodeQm31(expected.point.y);
  const assembly = `${v17OodsDefinitions()}
${hexPush(transcriptDigest)}
${v17OodsSelectDigestAssembly()}
OP_DUP ${hexPush(expected.digest)} OP_EQUALVERIFY
${v17OodsDigestToTAssembly()}
<${QM31_TO_BLOB}> OP_INVOKE
OP_DUP ${hexPush(tBlob)} OP_EQUALVERIFY
${hexPush(pointX)} ${hexPush(pointY)}
${v17OodsCayleyIdentityAssembly()}`;
  return compile(assembly, "v17 OODS KAT");
}

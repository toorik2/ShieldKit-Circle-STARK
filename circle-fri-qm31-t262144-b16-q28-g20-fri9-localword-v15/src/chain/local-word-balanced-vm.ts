import { cashAssemblyToBin } from "@bitauth/libauth";
import {
  LOCAL_WORD_CARRIER_INPUTS,
  LOCAL_WORD_CARRIER_JUMP_WIDTH,
  LOCAL_WORD_CARRIER_MIN_PROOF_BYTES,
  LOCAL_WORD_CARRIER_SEQUENCE_PAYLOAD_BASE,
  LOCAL_WORD_CARRIER_TOTAL_WEIGHT,
  LOCAL_WORD_CARRIER_VALUE_BASE,
  LOCAL_WORD_P2SH32_LOCKING_BYTES,
  LOCAL_WORD_VERIFIER_BANK_SEED,
  type LocalWordVerifierBankDigests,
} from "./local-word-proof-carriers.ts";
import {
  LOCAL_WORD_MATRIX_NAMES,
  LOCAL_WORD_PROOF_FIXED_PREFIX_BYTES,
  LOCAL_WORD_PROOF_LENGTH_OFFSET,
  LOCAL_WORD_PROOF_MAX_BYTES,
  LOCAL_WORD_PROOF_VERSION,
  localWordProofStaticOffsets,
  type LocalWordProofStaticOffsets,
} from "../backends/circle/local-word-sealed-proof.ts";
import {
  LOCAL_WORD_CONSTRUCTION_ID_BYTES,
  LOCAL_WORD_INITIAL_DOMAIN,
  LOCAL_WORD_PUBLIC_STATEMENT_BYTES,
  LOCAL_WORD_PUBLIC_STATEMENT_VERSION,
  LOCAL_WORD_STATEMENT_MAGIC,
} from "../backends/circle/local-word-public-statement.ts";
import { SUCCESSOR_TRANSCRIPT_DOMAIN } from "../backends/circle/successor-transcript.ts";
import {
  LOCAL_WORD_BOUNDARY_CHALLENGE_COUNT,
  LOCAL_WORD_BOUNDARY_CHALLENGE_START,
  LOCAL_WORD_INTERACTION_CHALLENGE_COUNT,
} from
  "../backends/circle/local-word-transcript.ts";
import { encodeQm31, type QM31El } from "../backends/circle/qm31.ts";
import {
  LOCAL_WORD_PRODUCTION_PARAMETERS,
  localWordFriFoldCounts,
  validateLocalWordProofParameters,
  type LocalWordProofParameters,
} from "../backends/circle/local-word-successor-params.ts";
import { SUCCESSOR_DIGEST_TO_M31_ASM } from "./transcript-vm-primitives.ts";
import {
  BLOB_TO_QM31_ASM,
  QM31_ADD_ASM,
  QM31_MUL_ASM,
  QM31_MUL_M31_ASM,
  QM31_TO_BLOB_ASM,
} from "./qm31-asm.ts";
import { M31_P } from "./m31-asm.ts";
import {
  LOCAL_WORD_NULLIFIER_DATA_LOCKING_BYTES,
  LOCAL_WORD_NULLIFIER_DATA_OUTPUT,
  LOCAL_WORD_NULLIFIER_DATA_PAYLOAD_BYTES,
  LOCAL_WORD_NULLIFIER_PATH_OFFSET,
  LOCAL_WORD_PAYOUT_OUTPUT,
} from "./local-word-envelope.ts";
import { ANY_STATE_BYTES, STATE_BASE_SATS } from "../pool/state.ts";
import { concatBytes, writeU32BE, writeU32LE } from "../pool/bytes.ts";
import {
  NULLIFIER_USED_TAG,
  SPARSE_NULLIFIER_MID_LEVEL,
  SPARSE_NULLIFIER_SEGMENT_BYTES,
} from "../pool/sparse-nullifiers.ts";

function compile(assembly: string, label: string): Uint8Array {
  const result = cashAssemblyToBin(assembly);
  if (typeof result === "string") throw new Error(`${label}: ${result}`);
  if (result.length > 10_000) throw new Error(`${label} locking limit ${result.length}`);
  return result;
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

/** Stack: inputIndex -> first pushed proof chunk; trailing P2SH redeem bytes are excluded. */
function localWordCarrierChunkAssembly(): string {
  return `OP_INPUTBYTECODE
<1> OP_SPLIT OP_SWAP <0x4d> OP_EQUALVERIFY
<2> OP_SPLIT OP_SWAP OP_BIN2NUM
OP_DUP <256> OP_GREATERTHANOREQUAL OP_VERIFY
OP_SPLIT OP_DROP`;
}

/** Read the sequence-committed canonical proof length without copying input zero. */
export function localWordProofLengthAssembly(): string {
  return `OP_0 OP_INPUTSEQUENCENUMBER
<${LOCAL_WORD_CARRIER_SEQUENCE_PAYLOAD_BASE}> OP_SUB
OP_DUP <${LOCAL_WORD_CARRIER_MIN_PROOF_BYTES}> OP_GREATERTHANOREQUAL OP_VERIFY
OP_DUP <${LOCAL_WORD_PROOF_MAX_BYTES}> OP_LESSTHANOREQUAL OP_VERIFY`;
}

function localWordReadAssembly(multipleCarrierBoundaries: boolean): string {
  const continuation = multipleCarrierBoundaries
    ? `OP_BEGIN
  <2> OP_PICK OP_1ADD OP_DUP ${localWordCarrierChunkAssembly()}
  OP_DUP OP_SIZE OP_NIP
  <3> OP_PICK OP_OVER OP_LESSTHANOREQUAL
  OP_IF
    OP_DROP <2> OP_PICK OP_SPLIT OP_DROP
    <3> OP_ROLL OP_SWAP OP_CAT
    OP_TOALTSTACK OP_2DROP OP_DROP OP_FROMALTSTACK OP_1
  OP_ELSE
    <3> OP_PICK OP_SWAP OP_SUB OP_TOALTSTACK
    <3> OP_ROLL OP_SWAP OP_CAT
    OP_TOALTSTACK OP_TOALTSTACK OP_2DROP
    OP_FROMALTSTACK OP_FROMALTSTACK OP_FROMALTSTACK OP_0
  OP_ENDIF
OP_UNTIL`
    : `<2> OP_PICK OP_1ADD OP_DUP ${localWordCarrierChunkAssembly()}
<2> OP_PICK OP_SPLIT OP_DROP
<3> OP_ROLL OP_SWAP OP_CAT
OP_TOALTSTACK OP_2DROP OP_DROP OP_FROMALTSTACK`;
  return `OP_TOALTSTACK
OP_DUP OP_1ADD <${LOCAL_WORD_CARRIER_TOTAL_WEIGHT}> OP_MUL
<2> OP_PICK OP_1SUB OP_ADD <2> OP_PICK OP_DIV
OP_DUP OP_1SUB <${LOCAL_WORD_CARRIER_JUMP_WIDTH}> OP_DIV
OP_1ADD OP_INPUTSEQUENCENUMBER <${0x8000_0000}> OP_SUB
OP_BEGIN
  OP_DUP OP_1ADD OP_DUP <${LOCAL_WORD_CARRIER_INPUTS}> OP_NUMEQUAL
  OP_IF
    OP_DROP <${LOCAL_WORD_CARRIER_TOTAL_WEIGHT}>
  OP_ELSE
    OP_UTXOVALUE <${LOCAL_WORD_CARRIER_VALUE_BASE}> OP_SUB
  OP_ENDIF
  <2> OP_PICK OP_SWAP OP_LESSTHANOREQUAL
  OP_IF OP_1 OP_ELSE OP_1ADD OP_0 OP_ENDIF
OP_UNTIL
OP_SWAP OP_DROP
OP_DUP OP_DUP OP_0 OP_NUMEQUAL
OP_IF OP_DROP OP_0 OP_ELSE OP_UTXOVALUE <${LOCAL_WORD_CARRIER_VALUE_BASE}> OP_SUB OP_ENDIF
<3> OP_PICK OP_MUL <${LOCAL_WORD_CARRIER_TOTAL_WEIGHT}> OP_DIV
OP_OVER OP_DUP <${LOCAL_WORD_CARRIER_INPUTS - 1}> OP_NUMEQUAL
OP_IF
  OP_DROP <${LOCAL_WORD_CARRIER_TOTAL_WEIGHT}>
OP_ELSE
  OP_1ADD OP_UTXOVALUE <${LOCAL_WORD_CARRIER_VALUE_BASE}> OP_SUB
OP_ENDIF
<4> OP_PICK OP_MUL <${LOCAL_WORD_CARRIER_TOTAL_WEIGHT}> OP_DIV
OP_TOALTSTACK OP_TOALTSTACK OP_TOALTSTACK
OP_FROMALTSTACK OP_FROMALTSTACK OP_FROMALTSTACK
<2> OP_PICK ${localWordCarrierChunkAssembly()}
<4> OP_PICK <3> OP_PICK OP_SUB OP_SPLIT OP_NIP
OP_TOALTSTACK OP_2DROP OP_SWAP OP_DROP
OP_FROMALTSTACK OP_FROMALTSTACK
OP_OVER OP_SIZE OP_NIP
OP_2DUP OP_LESSTHANOREQUAL
OP_IF
  OP_DROP OP_SPLIT OP_DROP OP_SWAP OP_DROP
OP_ELSE
  OP_SUB
${continuation}
OP_ENDIF`;
}

/** Stack: proofLength proofOffset width -> proofLength bytes across canonical carriers. */
export function localWordReadDynamicAssembly(): string {
  return localWordReadAssembly(true);
}

/** Stack: proofLength proofOffset width -> proofLength bytes, across any canonical carriers. */
export function localWordReadWideAssembly(): string {
  return localWordReadAssembly(true);
}

export function compileLocalWordReadGate(args: {
  readonly proofOffset: number;
  readonly expected: Uint8Array;
}): Uint8Array {
  if (!Number.isSafeInteger(args.proofOffset) || args.proofOffset < 0 ||
    args.expected.length < 1 || args.expected.length > 1_000 ||
    args.proofOffset + args.expected.length > LOCAL_WORD_PROOF_MAX_BYTES) {
    throw new Error("local-word read gate shape");
  }
  return compile(`OP_DROP
${localWordProofLengthAssembly()}
<${args.proofOffset}> <${args.expected.length}>
${localWordReadWideAssembly()}
<0x${hex(args.expected)}> OP_EQUAL
OP_NIP`, "local-word proof reader");
}

/** The first consensus gate: proof identity and fixed preprocessing are VK-owned. */
export function compileLocalWordHeaderGate(args: {
  readonly profile: 0 | 1 | 2;
  readonly constructionDigest: Uint8Array;
  readonly expectedPreprocessedRoot: Uint8Array;
  readonly publicWordCount: number;
}): Uint8Array {
  if (args.constructionDigest.length !== 32 || args.expectedPreprocessedRoot.length !== 32 ||
    !Number.isInteger(args.publicWordCount) || args.publicWordCount < 1 || args.publicWordCount > 1024) {
    throw new Error("local-word header verifier key");
  }
  const compare = (offset: number, expected: Uint8Array): string => `<${offset}> <${expected.length}>
${localWordReadDynamicAssembly()}
<0x${hex(expected)}> OP_EQUALVERIFY`;
  const compareLength = `<${LOCAL_WORD_PROOF_LENGTH_OFFSET}> <4>
${localWordReadDynamicAssembly()}
OP_REVERSEBYTES OP_BIN2NUM OP_OVER OP_NUMEQUALVERIFY`;
  const preprocessedRootOffset = localWordProofStaticOffsets(args.publicWordCount).matrixRoots;
  return compile(`OP_DROP
${localWordProofLengthAssembly()}
${compare(0, new TextEncoder().encode("SKLW"))}
${compare(4, Uint8Array.of(LOCAL_WORD_PROOF_VERSION))}
${compareLength}
${compare(5, Uint8Array.of(args.profile))}
${compare(6, args.constructionDigest)}
${compare(preprocessedRootOffset, args.expectedPreprocessedRoot)}
OP_DROP OP_1`, "local-word proof header");
}

function stateSlice(source: "input" | "output", offset: number, width: number): string {
  const opcode = source === "input" ? "OP_UTXOTOKENCOMMITMENT" : "OP_OUTPUTTOKENCOMMITMENT";
  return `<0> ${opcode}
<${offset}> OP_SPLIT OP_NIP
<${width}> OP_SPLIT OP_DROP`;
}

function stateNumber(source: "input" | "output", offset: number, width: number): string {
  return `${stateSlice(source, offset, width)} OP_REVERSEBYTES OP_BIN2NUM`;
}

function sumInputValuesAssembly(): string {
  return `OP_0 OP_0
OP_BEGIN
  OP_DUP OP_UTXOVALUE OP_ROT OP_ADD OP_SWAP
  OP_1ADD OP_DUP OP_TXINPUTCOUNT OP_NUMEQUAL
OP_UNTIL
OP_DROP`;
}

function sumOutputValuesAssembly(): string {
  return `OP_0 OP_0
OP_BEGIN
  OP_DUP OP_OUTPUTVALUE OP_ROT OP_ADD OP_SWAP
  OP_1ADD OP_DUP OP_TXOUTPUTCOUNT OP_NUMEQUAL
OP_UNTIL
OP_DROP`;
}

function minerFeeAssembly(): string {
  return `${sumInputValuesAssembly()}
${sumOutputValuesAssembly()}
OP_SUB
OP_DUP OP_0 OP_GREATERTHANOREQUAL OP_VERIFY`;
}

function proofProfileAssembly(): string {
  return `${localWordProofLengthAssembly()}
<5> <1>
${localWordReadDynamicAssembly()}
OP_BIN2NUM
OP_SWAP OP_DROP`;
}

function stateWithPublicReserveAssembly(source: "input" | "output"): string {
  const commitment = source === "input" ? "OP_UTXOTOKENCOMMITMENT" : "OP_OUTPUTTOKENCOMMITMENT";
  const value = source === "input" ? "OP_UTXOVALUE" : "OP_OUTPUTVALUE";
  return `<0> ${commitment}
<16> OP_SPLIT <8> OP_SPLIT OP_NIP
<0> ${value} <${STATE_BASE_SATS}> OP_SUB <8> OP_NUM2BIN OP_REVERSEBYTES
OP_SWAP OP_CAT OP_CAT`;
}

/**
 * Stack: -> SHA256(SuccessorTranscriptDomain || len || exact transaction
 * statement). Every later Fiat-Shamir role begins from this same assembly.
 */
export function localWordTransactionTranscriptInitialAssembly(
  constructionId: Uint8Array,
): string {
  if (constructionId.length !== LOCAL_WORD_CONSTRUCTION_ID_BYTES) {
    throw new Error("local-word transaction construction id");
  }
  const initialLength = LOCAL_WORD_INITIAL_DOMAIN.length + constructionId.length + 4 +
    LOCAL_WORD_PUBLIC_STATEMENT_BYTES;
  const prefix = concatBytes(
    SUCCESSOR_TRANSCRIPT_DOMAIN,
    writeU32LE(initialLength),
    LOCAL_WORD_INITIAL_DOMAIN,
    constructionId,
    writeU32BE(LOCAL_WORD_PUBLIC_STATEMENT_BYTES),
    LOCAL_WORD_STATEMENT_MAGIC,
    Uint8Array.of(LOCAL_WORD_PUBLIC_STATEMENT_VERSION),
  );
  const zero32 = new Uint8Array(32);
  return `<0x${hex(prefix)}>
${proofProfileAssembly()}
OP_DUP OP_TOALTSTACK <1> OP_NUM2BIN OP_CAT
<0> OP_OUTPUTVALUE <0> OP_UTXOVALUE OP_SUB <8> OP_NUM2BIN OP_CAT
${minerFeeAssembly()} <8> OP_NUM2BIN OP_CAT
${stateWithPublicReserveAssembly("input")} OP_CAT
${stateWithPublicReserveAssembly("output")} OP_CAT
OP_FROMALTSTACK
OP_DUP OP_0 OP_NUMEQUAL
OP_IF
  OP_DROP <0x${hex(zero32)}> OP_CAT <0x${hex(zero32)}> OP_CAT
OP_ELSE
  OP_DUP OP_1 OP_NUMEQUAL OP_SWAP <2> OP_NUMEQUAL OP_BOOLOR OP_VERIFY
  <${LOCAL_WORD_NULLIFIER_DATA_OUTPUT}> OP_OUTPUTBYTECODE
  <9> OP_SPLIT OP_NIP <32> OP_SPLIT OP_DROP OP_CAT
  <${LOCAL_WORD_PAYOUT_OUTPUT}> OP_OUTPUTBYTECODE OP_HASH256 OP_CAT
OP_ENDIF
OP_SHA256`;
}

/** Executable KAT wrapper for the transaction-derived transcript seam. */
export function compileLocalWordTranscriptInitialKatGate(args: {
  readonly constructionId: Uint8Array;
  readonly expectedDigest: Uint8Array;
}): Uint8Array {
  if (args.expectedDigest.length !== 32) throw new Error("local-word transcript KAT digest");
  return compile(`OP_DROP
${localWordTransactionTranscriptInitialAssembly(args.constructionId)}
<0x${hex(args.expectedDigest)}> OP_EQUAL`, "local-word transaction transcript initial");
}

function localWordReadProofSliceAssembly(offset: number, width: number): string {
  if (!Number.isSafeInteger(offset) || offset < 0 || !Number.isSafeInteger(width) || width < 1 ||
    offset + width > LOCAL_WORD_PROOF_MAX_BYTES) {
    throw new Error("local-word transcript proof slice");
  }
  const reader = width > 256 ? localWordReadWideAssembly() : localWordReadDynamicAssembly();
  return `${localWordProofLengthAssembly()}
<${offset}> <${width}> ${reader}
OP_NIP`;
}

/** Function stack: digest label data -> SHA256(tag || digest || label || length || data). */
function localWordTranscriptAbsorbFunctionAssembly(): string {
  return `OP_DUP OP_TOALTSTACK
OP_SIZE OP_NIP <4> OP_NUM2BIN OP_TOALTSTACK
OP_DUP OP_SIZE OP_NIP <1> OP_NUM2BIN
OP_SWAP
<0x00> <3> OP_ROLL OP_CAT
<2> OP_ROLL OP_CAT
OP_SWAP OP_CAT
OP_FROMALTSTACK OP_CAT
OP_FROMALTSTACK OP_CAT
OP_SHA256`;
}

/** Stack: digest data -> digest'; the shared function derives the exact data length. */
function localWordTranscriptAbsorbAssembly(label: string, width: number): string {
  const raw = new TextEncoder().encode(label);
  if (raw.length < 1 || raw.length > 96 || width < 1) throw new Error("local-word transcript absorb");
  return `<0x${hex(raw)}> <1> OP_ROLL <5> OP_INVOKE`;
}

/** Function stack: digest label -> digest' challengeBlob. */
function localWordTranscriptChallengeFunctionAssembly(): string {
  const coordinate = (index: number): string => `<2> OP_PICK
<0x01> OP_SWAP OP_CAT
<2> OP_PICK OP_SIZE OP_NIP <1> OP_NUM2BIN OP_CAT
<2> OP_PICK OP_CAT
<0x${hex(Uint8Array.of(index))}> OP_CAT
OP_SHA256 <0> OP_INVOKE <4> OP_NUM2BIN OP_CAT`;
  return `OP_0
${Array.from({ length: 4 }, (_, index) => coordinate(index)).join("\n")}
OP_DUP OP_TOALTSTACK
<2> OP_PICK
<0x02> OP_SWAP OP_CAT
<2> OP_PICK OP_SIZE OP_NIP <1> OP_NUM2BIN OP_CAT
<2> OP_PICK OP_CAT
<1> OP_PICK OP_CAT OP_SHA256
OP_TOALTSTACK
OP_2DROP OP_DROP
OP_FROMALTSTACK OP_FROMALTSTACK`;
}

/** Stack: digest -> digest'; retained challenge blobs are pushed to altstack. */
function localWordTranscriptChallengeAssembly(label: string, retain: boolean): string {
  const raw = new TextEncoder().encode(label);
  if (raw.length < 1 || raw.length > 96) throw new Error("local-word transcript challenge");
  return `<0x${hex(raw)}> <4> OP_INVOKE ${retain ? "OP_TOALTSTACK" : "OP_DROP"}`;
}

function localWordTranscriptFunctionPreludeAssembly(): string {
  const reducer = cashAssemblyToBin(SUCCESSOR_DIGEST_TO_M31_ASM);
  if (typeof reducer === "string") throw new Error(`local-word transcript reducer: ${reducer}`);
  return `<0x${hex(reducer)}> <0> OP_DEFINE
${defineVmFunction(localWordTranscriptChallengeFunctionAssembly(), 4, "local-word transcript challenge")}
${defineVmFunction(localWordTranscriptAbsorbFunctionAssembly(), 5, "local-word transcript absorb")}`;
}

/**
 * Replay through the public-boundary challenges. Stack result: final digest;
 * altstack: gamma, identity, limb0..limb7 challenge blobs.
 */
export function localWordInteractionTranscriptAssembly(args: {
  readonly constructionId: Uint8Array;
  readonly publicWordCount: number;
  readonly retainBoundaryChallenges?: boolean;
  readonly expectedChallengesOffset?: number;
}): string {
  if (!Number.isInteger(args.publicWordCount) || args.publicWordCount < 1 || args.publicWordCount > 1024) {
    throw new Error("local-word transcript public words");
  }
  const rootOffset = localWordProofStaticOffsets(args.publicWordCount).matrixRoots;
  const absorbProof = (label: string, offset: number): string =>
    `${localWordReadProofSliceAssembly(offset, 32)}\n${localWordTranscriptAbsorbAssembly(label, 32)}`;
  const absorbOriginalRoots = `${localWordReadProofSliceAssembly(rootOffset, 64)}
<32> OP_SPLIT OP_TOALTSTACK
${localWordTranscriptAbsorbAssembly("local-word-v15-preprocessed-root", 32)}
OP_FROMALTSTACK
${localWordTranscriptAbsorbAssembly("local-word-v15-original-root", 32)}`;
  const retainBoundary = args.retainBoundaryChallenges ?? true;
  let challengeIndex = 0;
  const checkedManifest = args.expectedChallengesOffset === undefined ? "" :
    `${localWordReadProofSliceAssembly(
      args.expectedChallengesOffset,
      LOCAL_WORD_INTERACTION_CHALLENGE_COUNT * 16,
    )} OP_TOALTSTACK`;
  if (args.expectedChallengesOffset !== undefined && retainBoundary) {
    throw new Error("local-word checked interaction challenge retention");
  }
  const challenge = (label: string, retain = false): string => {
    const raw = new TextEncoder().encode(label);
    if (raw.length < 1 || raw.length > 96) throw new Error("local-word transcript challenge");
    challengeIndex += 1;
    const derived = `<0x${hex(raw)}> <4> OP_INVOKE`;
    if (args.expectedChallengesOffset === undefined) {
      return `${derived} ${retain ? "OP_TOALTSTACK" : "OP_DROP"}`;
    }
    return `${derived}
OP_FROMALTSTACK <16> OP_SPLIT OP_TOALTSTACK
OP_EQUALVERIFY`;
  };
  const body = `${localWordTranscriptFunctionPreludeAssembly()}
${localWordTransactionTranscriptInitialAssembly(args.constructionId)}
${absorbProof("local-word-v15-descriptor", 6)}
${absorbOriginalRoots}
${checkedManifest}
${challenge("local-word-v15-lookup-gamma")}
${Array.from({ length: 6 }, (_, index) => challenge(`local-word-v15-lookup-tuple-${index}`)).join("\n")}
${challenge("local-word-v15-copy-gamma")}
${challenge("local-word-v15-copy-identity")}
${Array.from({ length: 8 }, (_, limb) => challenge(`local-word-v15-copy-limb-${limb}`)).join("\n")}
${challenge("local-word-v15-boundary-gamma", retainBoundary)}
${challenge("local-word-v15-boundary-identity", retainBoundary)}
${Array.from({ length: 8 }, (_, limb) =>
    challenge(`local-word-v15-boundary-limb-${limb}`, retainBoundary)).join("\n")}
${args.expectedChallengesOffset === undefined ? "" : "OP_FROMALTSTACK OP_0 OP_EQUALVERIFY"}`;
  if (challengeIndex !== LOCAL_WORD_INTERACTION_CHALLENGE_COUNT) {
    throw new Error("local-word interaction challenge count");
  }
  return body;
}

/** Executable pin for the transaction-derived interaction transcript. */
export function compileLocalWordInteractionTranscriptKatGate(args: {
  readonly constructionId: Uint8Array;
  readonly publicWordCount: number;
  readonly expectedDigest: Uint8Array;
  readonly boundaryChallenges: {
    readonly gamma: QM31El;
    readonly identity: QM31El;
    readonly limbs: readonly QM31El[];
  };
}): Uint8Array {
  const challenges = [
    args.boundaryChallenges.gamma,
    args.boundaryChallenges.identity,
    ...args.boundaryChallenges.limbs,
  ];
  if (args.expectedDigest.length !== 32 || challenges.length !== 10) {
    throw new Error("local-word interaction transcript KAT");
  }
  return compile(`OP_DROP
${localWordInteractionTranscriptAssembly(args)}
OP_DUP <0x${hex(args.expectedDigest)}> OP_EQUALVERIFY OP_DROP
${[...challenges].reverse().map((value) =>
    `OP_FROMALTSTACK <0x${hex(encodeQm31(value))}> OP_EQUALVERIFY`).join("\n")}
OP_1`, "local-word interaction transcript");
}

export function localWordPublicWordCount(profile: 0 | 1 | 2): number {
  return profile === 0 ? 18 : profile === 1 ? 26 : 34;
}

/** Push the exact four SHA-message bytes for one ordered public boundary word. */
function localWordPublicWordBytesAssembly(profile: 0 | 1 | 2, index: number): string {
  const sliceWord = (source: string, word: number): string => `${source}
<${word * 4}> OP_SPLIT OP_NIP <4> OP_SPLIT OP_DROP`;
  if (profile === 0) {
    if (index < 2) {
      return sliceWord(`<0> OP_OUTPUTVALUE <0> OP_UTXOVALUE OP_SUB <8> OP_NUM2BIN`, index);
    }
    if (index < 10) return stateSlice("input", 64 + (index - 2) * 4, 4);
    return stateSlice("output", 64 + (index - 10) * 4, 4);
  }
  if (index < 8) return stateSlice("input", 32 + index * 4, 4);
  if (index < 16) {
    return `<${LOCAL_WORD_NULLIFIER_DATA_OUTPUT}> OP_OUTPUTBYTECODE
<${9 + (index - 8) * 4}> OP_SPLIT OP_NIP <4> OP_SPLIT OP_DROP`;
  }
  if (index < 24) return stateSlice("input", 64 + (index - 16) * 4, 4);
  if (profile === 2 && index < 32) return stateSlice("output", 64 + (index - 24) * 4, 4);
  const withdrawalWord = index - (profile === 1 ? 24 : 32);
  return sliceWord(`<0> OP_UTXOVALUE <0> OP_OUTPUTVALUE OP_SUB <8> OP_NUM2BIN`, withdrawalWord);
}

function localWordCanonicalQm31Assembly(): string {
  const check = (depth: number): string => `<${depth}> OP_PICK
OP_DUP OP_0 OP_GREATERTHANOREQUAL OP_VERIFY
OP_DUP <${M31_P}> OP_LESSTHAN OP_VERIFY OP_DROP`;
  return `${BLOB_TO_QM31_ASM}
${Array.from({ length: 4 }, (_, depth) => check(depth)).join("\n")}`;
}

function defineVmFunction(assembly: string, id: number, label: string): string {
  const bytecode = cashAssemblyToBin(assembly);
  if (typeof bytecode === "string") throw new Error(`${label}: ${bytecode}`);
  return `<0x${hex(bytecode)}> <${id}> OP_DEFINE`;
}

function localWordPublicBoundaryInverseFunctionsAssembly(): string {
  return [
    defineVmFunction(localWordCanonicalQm31Assembly(), 0, "local-word canonical QM31"),
    defineVmFunction(QM31_MUL_M31_ASM, 1, "local-word QM31 scalar multiply"),
    defineVmFunction(QM31_ADD_ASM, 2, "local-word QM31 add"),
    defineVmFunction(QM31_MUL_ASM, 3, "local-word QM31 multiply"),
    defineVmFunction(localWordReadDynamicAssembly(), 4, "local-word public inverse reader"),
  ].join("\n");
}

function localWordPublicBoundaryProofSliceAssembly(offset: number, width: number): string {
  return `${localWordProofLengthAssembly()}
<${offset}> <${width}> <4> OP_INVOKE OP_NIP`;
}

function localWordPublicBoundaryInverseCheckAssembly(
  profile: 0 | 1 | 2,
  publicWordIndex: number,
): string {
  const count = localWordPublicWordCount(profile);
  const addChallengeTerm = (scalarAssembly: string, first: boolean): string => `OP_FROMALTSTACK
<0> OP_INVOKE
${scalarAssembly}
<1> OP_INVOKE
${first ? "" : "<2> OP_INVOKE"}`;
  const limbTerms = Array.from({ length: 8 }, (_, reverse) => 7 - reverse).map((limb, at) =>
    addChallengeTerm(
      `<${at === 0 ? 4 : 8}> OP_PICK <${2 ** (limb * 4)}> OP_DIV <16> OP_MOD`,
      at === 0,
    )).join("\n");
  const inverseOffset = LOCAL_WORD_PROOF_FIXED_PREFIX_BYTES + publicWordIndex * 16;
  const transcriptOffsets = localWordProofTranscriptOffsets(count);
  const boundaryChallenges = `${localWordPublicBoundaryProofSliceAssembly(
    transcriptOffsets.interactionChallenges + LOCAL_WORD_BOUNDARY_CHALLENGE_START * 16,
    LOCAL_WORD_BOUNDARY_CHALLENGE_COUNT * 16,
  )}
${Array.from({ length: LOCAL_WORD_BOUNDARY_CHALLENGE_COUNT - 1 }, () =>
    "<16> OP_SPLIT OP_SWAP OP_TOALTSTACK").join("\n")}
OP_TOALTSTACK`;
  return `${boundaryChallenges}
${localWordPublicWordBytesAssembly(profile, publicWordIndex)}
OP_REVERSEBYTES <0x00> OP_CAT OP_BIN2NUM
${limbTerms}
${addChallengeTerm(`<${publicWordIndex + 1}>`, false)}
OP_FROMALTSTACK <0> OP_INVOKE <2> OP_INVOKE
<4> OP_ROLL OP_DROP
${localWordPublicBoundaryProofSliceAssembly(inverseOffset, 16)}
<0> OP_INVOKE
<3> OP_INVOKE
OP_0 OP_NUMEQUALVERIFY
OP_0 OP_NUMEQUALVERIFY
OP_0 OP_NUMEQUALVERIFY
OP_1 OP_NUMEQUAL`;
}

/**
 * One ordered statement word owns one serialized public inverse. Replaying the
 * transaction transcript makes `inverse * factor(id, value) == 1` the binding
 * between settlement bytes and the sealed relation's public access column.
 */
export function compileLocalWordPublicBoundaryInverseGate(args: {
  readonly profile: 0 | 1 | 2;
  readonly publicWordIndex: number;
}): Uint8Array {
  const count = localWordPublicWordCount(args.profile);
  if (!Number.isInteger(args.publicWordIndex) || args.publicWordIndex < 0 ||
    args.publicWordIndex >= count) {
    throw new Error("local-word public inverse index");
  }
  return compile(`OP_DROP
${localWordPublicBoundaryInverseFunctionsAssembly()}
${localWordProofLengthAssembly()}
<5> <1> <4> OP_INVOKE OP_BIN2NUM OP_SWAP OP_DROP <${args.profile}> OP_NUMEQUALVERIFY
${localWordPublicBoundaryInverseCheckAssembly(args.profile, args.publicWordIndex)}`,
  `local-word public inverse ${args.profile}:${args.publicWordIndex}`);
}

/** Share one arithmetic prelude across a contiguous public-inverse segment. */
export function compileLocalWordPublicBoundaryInverseBatchGate(args: {
  readonly profile: 0 | 1 | 2;
  readonly start: number;
  readonly count: number;
}): Uint8Array {
  const total = localWordPublicWordCount(args.profile);
  if (!Number.isInteger(args.start) || !Number.isInteger(args.count) || args.start < 0 ||
    args.count < 1 || args.start + args.count > total) {
    throw new Error("local-word public inverse batch");
  }
  return compile(`OP_DROP
${localWordPublicBoundaryInverseFunctionsAssembly()}
${localWordProofLengthAssembly()}
<5> <1> <4> OP_INVOKE OP_BIN2NUM OP_SWAP OP_DROP <${args.profile}> OP_NUMEQUALVERIFY
${Array.from({ length: args.count }, (_, local) => {
    const check = localWordPublicBoundaryInverseCheckAssembly(args.profile, args.start + local);
    return local + 1 === args.count ? check : `${check} OP_VERIFY`;
  }).join("\n")}`, `local-word public inverse batch ${args.profile}:${args.start}:${args.count}`);
}

/** One owner for the public inverse sum cached in the canonical proof prefix. */
export function compileLocalWordPublicBoundarySumGate(profile: 0 | 1 | 2): Uint8Array {
  const count = localWordPublicWordCount(profile);
  const offsets = localWordProofTranscriptOffsets(count);
  const functions = [
    defineVmFunction(localWordCanonicalQm31Assembly(), 0, "local-word canonical QM31"),
    defineVmFunction(QM31_ADD_ASM, 1, "local-word QM31 add"),
    defineVmFunction(QM31_TO_BLOB_ASM, 2, "local-word QM31 encode"),
  ].join("\n");
  const splitInverses = Array.from({ length: count }, () =>
    "<16> OP_SPLIT OP_SWAP OP_TOALTSTACK").join("\n");
  const addInverses = Array.from({ length: count }, () =>
    "OP_FROMALTSTACK <0> OP_INVOKE <1> OP_INVOKE").join("\n");
  return compile(`OP_DROP
${functions}
${localWordReadProofSliceAssembly(offsets.publicInverses, (count + 1) * 16)}
${splitInverses}
OP_TOALTSTACK
OP_FROMALTSTACK
OP_0 OP_0 OP_0 OP_0
${addInverses}
<2> OP_INVOKE OP_EQUAL`, `local-word public inverse sum ${profile}`);
}

export type LocalWordProofTranscriptOffsets = LocalWordProofStaticOffsets;

export function localWordProofTranscriptOffsets(
  publicWordCount: number,
  parameters: LocalWordProofParameters = LOCAL_WORD_PRODUCTION_PARAMETERS,
): LocalWordProofTranscriptOffsets {
  return localWordProofStaticOffsets(publicWordCount, parameters);
}

function localWordLeadingZeroBitsAssembly(bits: number): string {
  if (!Number.isInteger(bits) || bits < 0 || bits > 32) throw new Error("local-word grind bits");
  const whole = Math.floor(bits / 8);
  const remainder = bits % 8;
  const wholeCheck = whole === 0 ? "" : `OP_DUP <${whole}> OP_SPLIT OP_DROP
<0x${hex(new Uint8Array(whole))}> OP_EQUALVERIFY`;
  const partialMask = (0xff << (8 - remainder)) & 0xff;
  const partialCheck = remainder === 0 ? "" : `OP_DUP <${whole}> OP_SPLIT OP_NIP
<1> OP_SPLIT OP_DROP <0x${partialMask.toString(16).padStart(2, "0")}> OP_AND
<0x00> OP_EQUALVERIFY`;
  return `${wholeCheck}\n${partialCheck}\nOP_DROP`;
}

function localWordExpectedTranscriptChallengeAssembly(label: string, expectedOffset: number): string {
  const raw = new TextEncoder().encode(label);
  if (raw.length < 1 || raw.length > 96) throw new Error("local-word expected transcript challenge");
  return `<0x${hex(raw)}> <4> OP_INVOKE
${localWordReadProofSliceAssembly(expectedOffset, 16)} OP_EQUALVERIFY`;
}

function localWordTranscriptAbsorbBatchAssembly(
  offset: number,
  records: readonly {
    readonly label: string;
    readonly width: number;
    readonly challengeLabel?: string;
    readonly challengeOffset?: number;
  }[],
): string {
  if (records.length < 1 || records.some((record) =>
    (record.challengeLabel === undefined) !== (record.challengeOffset === undefined))) {
    throw new Error("local-word transcript batch records");
  }
  const total = records.reduce((sum, record) => sum + record.width, 0);
  return `${localWordReadProofSliceAssembly(offset, total)}
${records.map((record, index) => {
    const more = index + 1 < records.length;
    return `${more ? `<${record.width}> OP_SPLIT OP_TOALTSTACK` : ""}
${localWordTranscriptAbsorbAssembly(record.label, record.width)}
${record.challengeLabel === undefined ? "" : localWordExpectedTranscriptChallengeAssembly(
      record.challengeLabel,
      record.challengeOffset!,
    )}
${more ? "OP_FROMALTSTACK" : ""}`;
  }).join("\n")}`;
}

export type LocalWordTranscriptManifestPart =
  | "interaction"
  | "composition"
  | "batch"
  | "fri-first"
  | "fri-second"
  | "final";

/** Six local roles prove that one serialized manifest is exactly one transcript. */
export function compileLocalWordTranscriptManifestGate(args: {
  readonly constructionId: Uint8Array;
  readonly publicWordCount: number;
  readonly part: LocalWordTranscriptManifestPart;
  readonly parameters?: LocalWordProofParameters;
}): Uint8Array {
  const parameters = validateLocalWordProofParameters(args.parameters ?? LOCAL_WORD_PRODUCTION_PARAMETERS);
  const offsets = localWordProofTranscriptOffsets(args.publicWordCount, parameters);
  const matrixRoot = (index: number): number => offsets.matrixRoots + index * 32;
  const compareDigest = (offset: number): string =>
    `${localWordReadProofSliceAssembly(offset, 32)} OP_EQUAL`;
  const prelude = `OP_DROP\n${localWordTranscriptFunctionPreludeAssembly()}`;
  const interaction = `${localWordInteractionTranscriptAssembly({
    constructionId: args.constructionId,
    publicWordCount: args.publicWordCount,
    retainBoundaryChallenges: false,
    expectedChallengesOffset: offsets.interactionChallenges,
  })}
${localWordReadProofSliceAssembly(offsets.publicInverses, args.publicWordCount * 16)}
${localWordTranscriptAbsorbAssembly("local-word-v15-public-boundary", args.publicWordCount * 16)}
${compareDigest(offsets.interactionDigest)}`;
  const composition = `${localWordReadProofSliceAssembly(offsets.interactionDigest, 32)}
${localWordTranscriptAbsorbBatchAssembly(matrixRoot(2), [
    { label: "local-word-v15-interaction-root", width: 32 },
    { label: "local-word-v15-interaction-global-root", width: 32 },
  ])}
${localWordExpectedTranscriptChallengeAssembly("local-word-v15-constraint-alpha", offsets.constraintAlpha)}
${compareDigest(offsets.compositionDigest)}`;
  const batch = `${localWordReadProofSliceAssembly(offsets.compositionDigest, 32)}
${localWordTranscriptAbsorbBatchAssembly(matrixRoot(4), [
    { label: "local-word-quotient-and-fri-mask-root", width: 32 },
  ])}
${localWordExpectedTranscriptChallengeAssembly("local-word-batch-beta", offsets.batchBeta)}
${compareDigest(offsets.batchDigest)}`;
  const friSplit = Math.ceil(offsets.friLayerCount / 2);
  const friPart = (first: boolean): string => {
    const startRound = first ? 0 : friSplit;
    const endRound = first ? friSplit : offsets.friLayerCount;
    const startDigest = first ? offsets.batchDigest : offsets.friMidDigest;
    const endDigest = first ? offsets.friMidDigest : offsets.friRootsDigest;
    return `${localWordReadProofSliceAssembly(startDigest, 32)}
${localWordTranscriptAbsorbBatchAssembly(
      offsets.friRoots + startRound * 32,
      Array.from({ length: endRound - startRound }, (_, local) => {
        const round = startRound + local;
        return {
          label: `fri-root:${round}`,
          width: 32,
          challengeLabel: `fri-alpha:${round}`,
          challengeOffset: offsets.friAlphas + round * 16,
        };
      }),
    )}
${compareDigest(endDigest)}`;
  };
  const bitsByte = Uint8Array.of(parameters.fri.grindBits);
  const final = `${localWordReadProofSliceAssembly(offsets.friRootsDigest, 32)}
${localWordReadProofSliceAssembly(offsets.finalCoefficients, offsets.finalCoefficientCount * 16 + 4)}
<${offsets.finalCoefficientCount * 16}> OP_SPLIT OP_TOALTSTACK
${localWordTranscriptAbsorbAssembly("fri-final", offsets.finalCoefficientCount * 16)}
OP_FROMALTSTACK OP_REVERSEBYTES
<1> OP_PICK <0x03> OP_SWAP OP_CAT <0x${hex(bitsByte)}> OP_CAT <1> OP_PICK OP_CAT OP_SHA256
${localWordLeadingZeroBitsAssembly(parameters.fri.grindBits)}
<0x${hex(bitsByte)}> OP_SWAP OP_CAT
${localWordTranscriptAbsorbAssembly("pow", 5)}
${compareDigest(offsets.queryDigest)}`;
  const body = args.part === "interaction" ? `OP_DROP\n${interaction}`
    : args.part === "composition" ? `${prelude}\n${composition}`
      : args.part === "batch" ? `${prelude}\n${batch}`
        : args.part === "fri-first" ? `${prelude}\n${friPart(true)}`
          : args.part === "fri-second" ? `${prelude}\n${friPart(false)}`
            : `${prelude}\n${final}`;
  return compile(body, `local-word transcript manifest ${args.part}`);
}

/**
 * Canonical deep-orbit sampling without replacement. A compact bitmap makes
 * every skipped hash counter miner-visible, so the prover cannot choose a
 * favorable unique subset. Expected queries are KAT-only.
 */
export function compileLocalWordQueryScheduleGate(args: {
  readonly publicWordCount: number;
  readonly parameters?: LocalWordProofParameters;
  readonly expectedQueries?: readonly number[];
}): Uint8Array {
  const parameters = validateLocalWordProofParameters(args.parameters ?? LOCAL_WORD_PRODUCTION_PARAMETERS);
  const rowCount = 2 ** parameters.evalLog;
  const orbitSize = 2 ** parameters.fri.queryOrbitLog;
  const orbitCount = rowCount / orbitSize;
  if (args.expectedQueries !== undefined && (args.expectedQueries.length !== parameters.fri.queries ||
    args.expectedQueries.some((query) => !Number.isInteger(query) || query < 0 || query >= rowCount))) {
    throw new Error("local-word expected queries");
  }
  if (parameters.fri.queryOrbitLog === 1 || orbitCount > 128) {
    throw new Error("local-word deep query sampler geometry");
  }
  const count = parameters.fri.queries;
  const offsets = localWordProofTranscriptOffsets(args.publicWordCount, parameters);
  const reader = defineVmFunction(
    localWordReadDynamicAssembly(),
    0,
    "local-word query schedule reader",
  );
  const bitmap = localWordRankBitmap(orbitCount);
  const zeroBitmap = new Uint8Array(bitmap.width);
  const candidate = (item: number): string => `OP_BEGIN
  OP_DUP <4> OP_NUM2BIN
  <4> OP_PICK <0x04> OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SHA256
  <4> OP_SPLIT OP_DROP <0x${hex(writeU32LE(rowCount - 1))}> OP_AND
  <0x00> OP_CAT OP_BIN2NUM
  OP_DUP <${orbitSize}> OP_DIV <${bitmap.width}> OP_MUL
  <4> OP_PICK OP_SWAP OP_SPLIT OP_NIP
  <${bitmap.width}> OP_SPLIT OP_DROP
  <3> OP_PICK OP_OVER OP_AND <0x${hex(zeroBitmap)}> OP_EQUAL
  OP_IF
    <3> OP_PICK OP_OR
    OP_TOALTSTACK OP_TOALTSTACK OP_TOALTSTACK OP_DROP
    OP_FROMALTSTACK OP_FROMALTSTACK OP_FROMALTSTACK OP_ROT OP_ROT
    ${args.expectedQueries === undefined ? "" :
      `OP_DUP <${args.expectedQueries[item]!}> OP_NUMEQUALVERIFY`}
    <5> OP_PICK <${offsets.queries + item * 4}> <4> <0> OP_INVOKE OP_NIP
    OP_REVERSEBYTES OP_BIN2NUM OP_NUMEQUALVERIFY
    OP_1ADD OP_1
  OP_ELSE
    OP_2DROP OP_1ADD OP_0
  OP_ENDIF
OP_UNTIL`;
  return compile(`OP_DROP
${reader}
${localWordProofLengthAssembly()}
OP_DUP <${offsets.queryDigest}> <32> <0> OP_INVOKE OP_NIP
<0x${hex(bitmap.table)}>
<0x${hex(zeroBitmap)}>
OP_0
${Array.from({ length: count }, (_, item) => candidate(item)).join("\n")}
OP_DROP OP_2DROP OP_2DROP OP_1`, "local-word query schedule");
}

export type LocalWordOpeningScheduleGateArgs = {
  readonly publicWordCount: number;
  readonly parameters?: LocalWordProofParameters;
  /** Production global ownership: two semantic maps and one canonical-list shape gate. */
  readonly stage?: "complete" | "current" | "previous" | "shape";
} & (
  | { readonly opening: "current" | "global" }
  | { readonly opening: "fri"; readonly friLayer: number }
);

function localWordBitReverseAssembly(bits: number): string {
  if (!Number.isInteger(bits) || bits < 1 || bits > 30) throw new Error("local-word bit reverse");
  return `OP_0 OP_SWAP
${Array.from({ length: bits }, () => `OP_DUP <2> OP_MOD
<2> OP_ROLL <2> OP_MUL OP_ADD
OP_SWAP <2> OP_DIV`).join("\n")}
OP_DROP`;
}

function localWordRankBitmap(slots: number): {
  readonly table: Uint8Array;
  readonly full: Uint8Array;
  readonly width: number;
} {
  if (!Number.isInteger(slots) || slots < 1 || slots > 128) {
    throw new Error("local-word rank bitmap");
  }
  const width = Math.ceil(slots / 8);
  const table = new Uint8Array(slots * width);
  const full = new Uint8Array(width);
  for (let slot = 0; slot < slots; slot += 1) {
    table[slot * width + Math.floor(slot / 8)] = 1 << (slot % 8);
    full[Math.floor(slot / 8)] |= 1 << (slot % 8);
  }
  return { table, full, width };
}

/**
 * Bind every sorted opening index to the one transcript-derived schedule.
 * Rank manifests are checked as exact permutations with a compact 64-bit
 * bitmap, so no prover-selected extra row can hide in an otherwise valid list.
 */
export function compileLocalWordOpeningScheduleGate(
  args: LocalWordOpeningScheduleGateArgs,
): Uint8Array {
  const parameters = validateLocalWordProofParameters(
    args.parameters ?? LOCAL_WORD_PRODUCTION_PARAMETERS,
  );
  const stage = args.stage ?? "complete";
  if (stage !== "complete" && args.opening !== "global") {
    throw new Error("local-word opening schedule stage");
  }
  if (!Number.isInteger(args.publicWordCount) || args.publicWordCount < 1 ||
    args.publicWordCount > 1024) {
    throw new Error("local-word opening schedule verifier key");
  }
  const offsets = localWordProofStaticOffsets(args.publicWordCount, parameters);
  const queryCount = parameters.fri.queries;
  const foldCounts = localWordFriFoldCounts(parameters);
  const friLayer = args.opening === "fri" ? args.friLayer : undefined;
  if (friLayer !== undefined && (!Number.isInteger(friLayer) || friLayer < 0 ||
    friLayer >= foldCounts.length)) {
    throw new Error("local-word FRI opening schedule");
  }
  const arity = friLayer === undefined ? 1 : 2 ** foldCounts[friLayer]!;
  const completedFolds = friLayer === undefined
    ? 0
    : foldCounts.slice(0, friLayer).reduce((sum, count) => sum + count, 0);
  const indexCount = args.opening === "global" ? 2 * queryCount : queryCount * arity;
  const rankSlots = args.opening === "global" ? 2 * queryCount : queryCount;
  if (rankSlots > 128) throw new Error("local-word opening schedule rank width");
  const openingIndex = args.opening === "current"
    ? undefined
    : args.opening === "global"
      ? LOCAL_WORD_MATRIX_NAMES.indexOf("interactionGlobal")
      : LOCAL_WORD_MATRIX_NAMES.length + friLayer!;
  const directoryOffset = openingIndex === undefined
    ? undefined
    : offsets.openingDirectory + openingIndex * 20;
  const reader = defineVmFunction(
    localWordReadDynamicAssembly(),
    0,
    "local-word opening schedule reader",
  );
  const bitReverse = args.opening === "global" && (stage === "complete" || stage === "previous")
    ? defineVmFunction(
      localWordBitReverseAssembly(parameters.evalLog),
      1,
      "local-word opening schedule bit reverse",
    )
    : "";
  const start = directoryOffset === undefined
    ? `<${offsets.currentIndices}>`
    : `OP_DUP <${directoryOffset}> <8> <0> OP_INVOKE OP_NIP
<4> OP_SPLIT
OP_REVERSEBYTES OP_BIN2NUM OP_TOALTSTACK
OP_REVERSEBYTES OP_BIN2NUM
OP_FROMALTSTACK OP_OVER OP_SUB <${indexCount * 4}> OP_NUMEQUALVERIFY`;
  const bitmap = localWordRankBitmap(rankSlots);
  const zeroBitmap = new Uint8Array(bitmap.width);
  const updateBitmap = (rankDivisor: number): string => `OP_DUP OP_TOALTSTACK
OP_DUP OP_0 OP_GREATERTHANOREQUAL OP_VERIFY
${rankDivisor === 1 ? "" : `OP_DUP <${rankDivisor}> OP_MOD OP_0 OP_NUMEQUALVERIFY
<${rankDivisor}> OP_DIV`}
OP_DUP <${rankSlots}> OP_LESSTHAN OP_VERIFY
<${bitmap.width}> OP_MUL <2> OP_PICK OP_SWAP OP_SPLIT OP_NIP
<${bitmap.width}> OP_SPLIT OP_DROP
OP_2DUP OP_AND <0x${hex(zeroBitmap)}> OP_EQUALVERIFY OP_OR
OP_FROMALTSTACK`;
  const readFixed = (offset: number, width: number): string =>
    `<4> OP_PICK <${offset}> <${width}> <0> OP_INVOKE OP_NIP`;
  const predecessor = `<1> OP_INVOKE
OP_DUP <${2 ** (parameters.evalLog - 1)}> OP_LESSTHAN
OP_IF
  <${2 ** (parameters.evalLog - parameters.relationLog - 1)}> OP_SUB
  <${2 ** (parameters.evalLog - 1)}> OP_ADD
  <${2 ** (parameters.evalLog - 1)}> OP_MOD
OP_ELSE
  <${2 ** (parameters.evalLog - 1)}> OP_SUB
  <${2 ** (parameters.evalLog - parameters.relationLog - 1)}> OP_ADD
  <${2 ** (parameters.evalLog - 1)}> OP_MOD
  <${2 ** (parameters.evalLog - 1)}> OP_ADD
OP_ENDIF
<1> OP_INVOKE`;
  const predecessorDefinition = args.opening === "global" &&
    (stage === "complete" || stage === "previous")
    ? defineVmFunction(predecessor, 2, "local-word opening schedule predecessor")
    : "";
  const expected = (item: number, previous: boolean, proofDepth = 4): string =>
    `<${proofDepth}> OP_PICK <${offsets.queries + item * 4}> <4> <0> OP_INVOKE OP_NIP
OP_REVERSEBYTES OP_BIN2NUM
${previous ? "<2> OP_INVOKE" : friLayer === undefined ? "" :
    `<${2 ** completedFolds}> OP_DIV <${arity}> OP_DIV <${arity}> OP_MUL`}`;
  const mapping = (rankOffset: number, item: number, previous = false): string =>
    `${readFixed(rankOffset, 1)} <0x00> OP_CAT OP_BIN2NUM
${updateBitmap(arity)}
<4> OP_MUL <3> OP_PICK OP_SWAP OP_SPLIT OP_NIP
<4> OP_SPLIT OP_DROP
OP_REVERSEBYTES OP_BIN2NUM OP_TOALTSTACK
${expected(item, previous)}
OP_FROMALTSTACK OP_NUMEQUALVERIFY`;
  const mapBatchedPair = (previous = false): string =>
    `<1> OP_SPLIT OP_SWAP <0x00> OP_CAT OP_BIN2NUM
OP_TOALTSTACK
OP_SWAP <4> OP_SPLIT OP_SWAP OP_REVERSEBYTES OP_BIN2NUM
${previous ? "<2> OP_INVOKE" : ""}
OP_FROMALTSTACK <4> OP_MUL <4> OP_PICK OP_SWAP OP_SPLIT OP_NIP
<4> OP_SPLIT OP_DROP OP_REVERSEBYTES OP_BIN2NUM OP_NUMEQUALVERIFY
OP_SWAP`;
  const batchedRankMappings = (rankOffset: number, previous = false): string =>
    `<2> OP_PICK <${offsets.queries}> <${queryCount * 4}> <0> OP_INVOKE OP_NIP
<3> OP_PICK <${rankOffset}> <${queryCount}> <0> OP_INVOKE OP_NIP
${Array.from({ length: queryCount }, () => mapBatchedPair(previous)).join("\n")}
OP_2DROP OP_DROP`;
  const mappings = args.opening === "current"
    ? Array.from({ length: queryCount }, (_, item) =>
      mapping(offsets.currentRanks + item, item)).join("\n")
    : args.opening === "global"
      ? [
        ...Array.from({ length: queryCount }, (_, item) =>
          mapping(offsets.globalCurrentRanks + item, item)),
        ...Array.from({ length: queryCount }, (_, item) =>
          mapping(offsets.globalPreviousRanks + item, item, true)),
      ].join("\n")
      : Array.from({ length: queryCount }, (_, item) =>
        mapping(offsets.friCosetRanks + friLayer! * queryCount + item, item)).join("\n");
  const nextSorted = `OP_SWAP <4> OP_SPLIT OP_TOALTSTACK
OP_REVERSEBYTES OP_BIN2NUM
OP_2DUP OP_LESSTHAN OP_VERIFY OP_NIP
OP_FROMALTSTACK OP_SWAP`;
  const sorted = `<4> OP_SPLIT OP_SWAP OP_REVERSEBYTES OP_BIN2NUM
${Array.from({ length: indexCount - 1 }, () => nextSorted).join("\n")}
OP_DROP OP_0 OP_EQUALVERIFY`;
  const mappingBody = `<0x${hex(bitmap.table)}>
<0x${hex(zeroBitmap)}>
${mappings}
<0x${hex(bitmap.full)}> OP_EQUALVERIFY
OP_DROP`;
  const shapeRanks = args.opening === "global"
    ? [
      ...Array.from({ length: queryCount }, (_, item) => offsets.globalCurrentRanks + item),
      ...Array.from({ length: queryCount }, (_, item) => offsets.globalPreviousRanks + item),
    ].map((rankOffset) => `${readFixed(rankOffset, 1)} <0x00> OP_CAT OP_BIN2NUM
${updateBitmap(1)} OP_DROP`).join("\n")
    : "";
  const stageBody = stage === "complete"
    ? `${mappingBody}\n${sorted}`
    : stage === "current"
      // The shape role owns rank range and exact-permutation checks once;
      // current and previous roles own only their ordered semantic mappings.
      ? batchedRankMappings(offsets.globalCurrentRanks)
      : stage === "previous"
        ? batchedRankMappings(offsets.globalPreviousRanks, true)
        : `<0x${hex(bitmap.table)}>
<0x${hex(zeroBitmap)}>
${shapeRanks}
<0x${hex(bitmap.full)}> OP_EQUALVERIFY
OP_DROP
${sorted}`;
  return compile(`OP_DROP
${reader}
${bitReverse}
${predecessorDefinition}
${localWordProofLengthAssembly()}
${start}
OP_2DUP <${indexCount * 4}> <0> OP_INVOKE OP_NIP
${stageBody}
OP_2DROP OP_1`, `local-word ${args.opening} opening schedule`);
}

/**
 * Public money/state half of the final pool input. Carrier zero is the pool
 * covenant; inputs/outputs 1..127 are exact value-neutral verifier rollovers.
 * The private relation is checked by other roles over the same proof bytes.
 */
export function compileLocalWordValueSettlementGate(
  authorizedBankDigests: LocalWordVerifierBankDigests,
): Uint8Array {
  if (authorizedBankDigests.some((digest) => digest.length !== 32)) {
    throw new Error("local-word settlement verifier bank digests");
  }
  const statePrefix = new Uint8Array(8);
  statePrefix.set(new TextEncoder().encode("PAA1"));
  statePrefix[4] = 1;
  const sameStateBytes = (offset: number, width: number): string => `${stateSlice("input", offset, width)}
${stateSlice("output", offset, width)}
OP_EQUALVERIFY`;
  const sameStateNumber = (offset: number, width: number): string => `${stateNumber("input", offset, width)}
${stateNumber("output", offset, width)}
OP_NUMEQUALVERIFY`;
  const profile = proofProfileAssembly();
  const verifierBanks = concatBytes(...authorizedBankDigests);
  return compile(`OP_DROP
OP_INPUTINDEX OP_0 OP_NUMEQUALVERIFY
<0> OP_UTXOBYTECODE <0> OP_OUTPUTBYTECODE OP_EQUALVERIFY
<0> OP_UTXOTOKENCATEGORY <0> OP_OUTPUTTOKENCATEGORY OP_EQUALVERIFY
<0> OP_UTXOTOKENAMOUNT <0> OP_OUTPUTTOKENAMOUNT OP_NUMEQUALVERIFY
<0> OP_UTXOTOKENCOMMITMENT OP_SIZE <${ANY_STATE_BYTES}> OP_NUMEQUALVERIFY OP_DROP
<0> OP_OUTPUTTOKENCOMMITMENT OP_SIZE <${ANY_STATE_BYTES}> OP_NUMEQUALVERIFY OP_DROP
${stateSlice("input", 0, 8)} <0x${hex(statePrefix)}> OP_EQUALVERIFY
${stateSlice("output", 0, 8)} <0x${hex(statePrefix)}> OP_EQUALVERIFY
${stateSlice("input", 16, 8)} <0x0000000000000000> OP_EQUALVERIFY
${stateSlice("output", 16, 8)} <0x0000000000000000> OP_EQUALVERIFY
${sameStateBytes(32, 32)}
${stateNumber("input", 8, 8)} OP_1ADD
${stateNumber("output", 8, 8)} OP_NUMEQUALVERIFY

<0x${hex(LOCAL_WORD_VERIFIER_BANK_SEED)}> OP_1
OP_BEGIN
  OP_DUP OP_UTXOBYTECODE
  OP_SIZE <${LOCAL_WORD_P2SH32_LOCKING_BYTES}> OP_NUMEQUALVERIFY
  OP_OVER OP_UTXOVALUE OP_CAT
  OP_OVER OP_INPUTSEQUENCENUMBER OP_CAT
  OP_ROT OP_SWAP OP_CAT OP_SHA256 OP_SWAP
  OP_1ADD OP_DUP <${LOCAL_WORD_CARRIER_INPUTS}> OP_NUMEQUAL
OP_UNTIL
OP_DROP
<0x${hex(verifierBanks)}>
${profile} <32> OP_MUL OP_SPLIT OP_NIP <32> OP_SPLIT OP_DROP
OP_EQUALVERIFY

<1>
OP_BEGIN
  OP_DUP OP_UTXOVALUE <1> OP_PICK OP_OUTPUTVALUE OP_NUMEQUALVERIFY
  OP_DUP OP_UTXOBYTECODE <1> OP_PICK OP_OUTPUTBYTECODE OP_EQUALVERIFY
  OP_DUP OP_UTXOTOKENCATEGORY <1> OP_PICK OP_OUTPUTTOKENCATEGORY OP_EQUALVERIFY
  OP_DUP OP_UTXOTOKENCOMMITMENT <1> OP_PICK OP_OUTPUTTOKENCOMMITMENT OP_EQUALVERIFY
  OP_DUP OP_UTXOTOKENAMOUNT <1> OP_PICK OP_OUTPUTTOKENAMOUNT OP_NUMEQUALVERIFY
  OP_1ADD OP_DUP <${LOCAL_WORD_CARRIER_INPUTS}> OP_NUMEQUAL
OP_UNTIL
OP_DROP

<0> OP_OUTPUTVALUE <0> OP_UTXOVALUE OP_SUB
OP_DUP OP_0 OP_GREATERTHAN
OP_IF
  OP_DROP
  OP_TXINPUTCOUNT <${LOCAL_WORD_CARRIER_INPUTS + 1}> OP_NUMEQUALVERIFY
  OP_TXOUTPUTCOUNT <${LOCAL_WORD_CARRIER_INPUTS}> OP_NUMEQUALVERIFY
  ${stateNumber("input", 24, 4)} OP_1ADD
  ${stateNumber("output", 24, 4)} OP_NUMEQUALVERIFY
  ${sameStateNumber(28, 4)}
  ${sameStateBytes(96, 32)}
  ${profile} OP_0 OP_NUMEQUALVERIFY
  <${LOCAL_WORD_CARRIER_INPUTS}> OP_UTXOVALUE
  <0> OP_OUTPUTVALUE <0> OP_UTXOVALUE OP_SUB
  ${minerFeeAssembly()} OP_ADD
  OP_NUMEQUALVERIFY
OP_ELSE
  OP_0 OP_LESSTHAN OP_VERIFY
  OP_TXINPUTCOUNT <${LOCAL_WORD_CARRIER_INPUTS}> OP_NUMEQUALVERIFY
  OP_TXOUTPUTCOUNT <${LOCAL_WORD_CARRIER_INPUTS + 2}> OP_NUMEQUALVERIFY
  ${sameStateNumber(24, 4)}
  ${stateNumber("input", 28, 4)} OP_1ADD
  ${stateNumber("output", 28, 4)} OP_NUMEQUALVERIFY
  ${profile}
  ${stateSlice("input", 64, 32)} ${stateSlice("output", 64, 32)} OP_EQUAL
  OP_IF OP_1 OP_ELSE <2> OP_ENDIF
  OP_NUMEQUALVERIFY
  <${LOCAL_WORD_PAYOUT_OUTPUT}> OP_OUTPUTVALUE OP_DUP OP_0 OP_GREATERTHAN OP_VERIFY
  ${minerFeeAssembly()} OP_ADD
  <0> OP_UTXOVALUE <0> OP_OUTPUTVALUE OP_SUB
  OP_NUMEQUALVERIFY
  <${LOCAL_WORD_NULLIFIER_DATA_OUTPUT}> OP_OUTPUTVALUE OP_0 OP_NUMEQUALVERIFY
  <${LOCAL_WORD_NULLIFIER_DATA_OUTPUT}> OP_OUTPUTTOKENCATEGORY OP_0 OP_EQUALVERIFY
  <${LOCAL_WORD_NULLIFIER_DATA_OUTPUT}> OP_OUTPUTTOKENCOMMITMENT OP_0 OP_EQUALVERIFY
  <${LOCAL_WORD_NULLIFIER_DATA_OUTPUT}> OP_OUTPUTTOKENAMOUNT OP_0 OP_NUMEQUALVERIFY
OP_ENDIF
OP_1`, "local-word value settlement");
}

/**
 * One half of the public 256-level sparse-nullifier update. Two independent
 * carrier roles share the exact path: `absence` authenticates the zero old
 * leaf, while `used` authenticates SHA256(tag || nullifier) at the new root.
 * Keeping one accumulator per role stays inside the real per-input VM budget.
 */
export function compileLocalWordSparseNullifierGate(
  root: "absence" | "used",
  segment: 0 | 1,
): Uint8Array {
  const header = Uint8Array.of(
    0x6a,
    0x4d,
    LOCAL_WORD_NULLIFIER_DATA_PAYLOAD_BYTES & 0xff,
    LOCAL_WORD_NULLIFIER_DATA_PAYLOAD_BYTES >>> 8,
    ...new TextEncoder().encode("SKNF"),
    1,
  );
  const zero32 = new Uint8Array(32);
  const midpointOffset = root === "absence" ? 41 : 73;
  const chooseSegment = segment === 0
    ? `<${SPARSE_NULLIFIER_SEGMENT_BYTES}> OP_SPLIT OP_DROP OP_SWAP`
    : `<${SPARSE_NULLIFIER_SEGMENT_BYTES}> OP_SPLIT OP_NIP OP_SWAP`;
  const initial = segment === 1
    ? "OP_FROMALTSTACK"
    : root === "absence"
      ? `<0x${hex(zero32)}>`
      : `OP_DUP <0x${hex(NULLIFIER_USED_TAG)}> OP_SWAP OP_CAT OP_SHA256`;
  const expectedCheck = segment === 0
    ? "OP_FROMALTSTACK OP_EQUALVERIFY"
    : `${stateSlice(root === "absence" ? "input" : "output", 96, 32)} OP_EQUALVERIFY`;
  const startLevel = segment * SPARSE_NULLIFIER_MID_LEVEL;
  const endLevel = startLevel + SPARSE_NULLIFIER_MID_LEVEL;
  return compile(`OP_DROP
${proofProfileAssembly()}
OP_DUP OP_0 OP_NUMEQUAL
OP_IF
  OP_DROP
  OP_TXOUTPUTCOUNT <${LOCAL_WORD_CARRIER_INPUTS}> OP_NUMEQUALVERIFY
  ${stateSlice("input", 96, 32)} ${stateSlice("output", 96, 32)} OP_EQUALVERIFY
OP_ELSE
  OP_DUP OP_1 OP_NUMEQUAL
  OP_SWAP <2> OP_NUMEQUAL
  OP_BOOLOR OP_VERIFY
  OP_TXOUTPUTCOUNT <${LOCAL_WORD_CARRIER_INPUTS + 2}> OP_NUMEQUALVERIFY
  <${LOCAL_WORD_NULLIFIER_DATA_OUTPUT}> OP_OUTPUTBYTECODE
  OP_SIZE <${LOCAL_WORD_NULLIFIER_DATA_LOCKING_BYTES}> OP_NUMEQUALVERIFY
  <${LOCAL_WORD_NULLIFIER_PATH_OFFSET}> OP_SPLIT
  OP_SWAP
  OP_DUP <9> OP_SPLIT OP_DROP <0x${hex(header)}> OP_EQUALVERIFY
  OP_DUP <9> OP_SPLIT OP_NIP <32> OP_SPLIT OP_DROP
  OP_DUP <0x${hex(zero32)}> OP_EQUAL OP_NOT OP_VERIFY
  <1> OP_PICK <${midpointOffset}> OP_SPLIT OP_NIP <32> OP_SPLIT OP_DROP
  OP_ROT OP_DROP OP_TOALTSTACK
  OP_SWAP ${chooseSegment}
  ${initial}
  <${startLevel}> <3> OP_ROLL
  OP_BEGIN
    <32> OP_SPLIT
    OP_TOALTSTACK
    <3> OP_PICK <2> OP_PICK <8> OP_DIV
    OP_SPLIT OP_NIP <1> OP_SPLIT OP_DROP <0x00> OP_CAT OP_BIN2NUM
    <2> OP_PICK <8> OP_MOD
    OP_DUP OP_0 OP_GREATERTHAN
    OP_IF
      OP_BEGIN
        OP_SWAP <2> OP_DIV OP_SWAP
        OP_1SUB OP_DUP OP_0 OP_NUMEQUAL
      OP_UNTIL
    OP_ENDIF
    OP_DROP <2> OP_MOD

    <3> OP_PICK <2> OP_PICK <2> OP_PICK
    OP_IF OP_SWAP OP_ENDIF OP_CAT OP_SHA256
    OP_TOALTSTACK
    OP_2DROP
    OP_TOALTSTACK OP_DROP
    OP_FROMALTSTACK OP_FROMALTSTACK OP_FROMALTSTACK
    <2> OP_ROLL OP_1ADD OP_SWAP
    <1> OP_PICK <${endLevel}> OP_NUMEQUAL
  OP_UNTIL
  OP_SIZE OP_0 OP_NUMEQUALVERIFY OP_DROP
  OP_DROP
  ${expectedCheck}
  OP_DROP
OP_ENDIF
OP_1`, `local-word sparse nullifier ${root} ${segment}`);
}

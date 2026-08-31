import { cashAssemblyToBin } from "@bitauth/libauth";
import {
  LOCAL_WORD_CARRIER_ELASTIC_SCALE,
  LOCAL_WORD_CARRIER_INPUTS,
  LOCAL_WORD_CARRIER_SEQUENCE_PAYLOAD_BASE,
  LOCAL_WORD_CARRIER_SEQUENCE_RADIX,
  LOCAL_WORD_CARRIER_VALUE_BASE,
  LOCAL_WORD_P2SH32_LOCKING_BYTES,
  LOCAL_WORD_VERIFIER_BANK_SEEDS,
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
  LOCAL_WORD_RELATION_STATEMENT_DIGEST_WORDS,
  LOCAL_WORD_RELATION_STATEMENT_MAGIC,
  LOCAL_WORD_RELATION_STATEMENT_VERSION,
  LOCAL_WORD_STATEMENT_MAGIC,
} from "../backends/circle/local-word-public-statement.ts";
import { SUCCESSOR_TRANSCRIPT_DOMAIN } from "../backends/circle/successor-transcript.ts";
import {
  LOCAL_WORD_BOUNDARY_CHALLENGE_COUNT,
  LOCAL_WORD_BOUNDARY_CHALLENGE_START,
  LOCAL_WORD_INTERACTION_CHALLENGE_COUNT,
  validateLocalWordQuerySamplerGeometry,
} from
  "../backends/circle/local-word-transcript.ts";
import { encodeQm31, type QM31El } from "../backends/circle/qm31.ts";
import {
  LOCAL_WORD_PRODUCTION_PARAMETERS,
  localWordFriFoldCounts,
  validateLocalWordProofParameters,
  type LocalWordProofParameters,
} from "../backends/circle/local-word-successor-params.ts";
import {
  V17_PROOF_PROTOCOL_ID,
  v17ProofFrame,
  v17ProofFrameOffset,
  type V17GeneratedProofFrameId,
} from "../backends/circle/v17-proof-layout.ts";
import {
  V17_THEOREM_ROUND_IDS,
  type V17TheoremRoundId,
} from "../backends/circle/v17-round-transcript.ts";
import { V17_PRODUCTION_ROUND_GRINDING } from "../construction/v17-graph.ts";
import { V17_BANK_NUMBER_BYTES } from "../construction/v17-bank-identity.ts";
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
  LOCAL_WORD_EDGE_DATA_LOCKING_BYTES,
  LOCAL_WORD_EDGE_DATA_PAYLOAD_BYTES,
  LOCAL_WORD_EDGE_INDEX_OFFSET,
  LOCAL_WORD_EDGE_OFFSET,
  LOCAL_WORD_EDGE_PATH_OFFSET,
  LOCAL_WORD_NULLIFIER_DATA_LOCKING_BYTES,
  LOCAL_WORD_NULLIFIER_DATA_PAYLOAD_BYTES,
  LOCAL_WORD_NULLIFIER_PATH_OFFSET,
} from "./local-word-envelope.ts";
import { ANY_STATE_BYTES } from "../pool/state.ts";
import { concatBytes, writeU32BE, writeU32LE } from "../pool/bytes.ts";
import { EDGE_HISTORY_DEPTH } from "../pool/edge-history.ts";
import {
  NULLIFIER_USED_TAG,
  SPARSE_NULLIFIER_MID_LEVEL,
  SPARSE_NULLIFIER_SEGMENT_BYTES,
} from "../pool/sparse-nullifiers.ts";
import {
  v17OodsCandidateAcceptanceAssembly,
  v17OodsDigestToTAssembly,
  v17OodsSelectDigestAssembly,
} from "./v17-oods-vm.ts";

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
OP_DUP <1> OP_UTXOVALUE <${LOCAL_WORD_CARRIER_VALUE_BASE}> OP_SUB
OP_GREATERTHANOREQUAL OP_VERIFY
OP_DUP <${LOCAL_WORD_PROOF_MAX_BYTES}> OP_LESSTHANOREQUAL OP_VERIFY`;
}

/**
 * Stack: proofLength boundaryIndex -> boundary.
 *
 * Every internal boundary is authenticated in that input's disabled sequence as
 * `B * 4096 + Q`; input one authenticates the affine origin `R` in its UTXO
 * value. The terminal boundaries are topology, so they need no metadata.
 */
function localWordAffineBoundaryAssembly(): string {
  return `OP_DUP OP_0 OP_NUMEQUAL
OP_IF
  OP_2DROP OP_0
OP_ELSE
  OP_DUP <${LOCAL_WORD_CARRIER_INPUTS}> OP_NUMEQUAL
  OP_IF
    OP_DROP
  OP_ELSE
    OP_INPUTSEQUENCENUMBER
    <${LOCAL_WORD_CARRIER_SEQUENCE_PAYLOAD_BASE}> OP_SUB
    OP_DUP <${LOCAL_WORD_CARRIER_SEQUENCE_RADIX}> OP_MOD
    OP_SWAP <${LOCAL_WORD_CARRIER_SEQUENCE_RADIX}> OP_DIV
    <2> OP_PICK <1> OP_UTXOVALUE <${LOCAL_WORD_CARRIER_VALUE_BASE}> OP_SUB OP_SUB
    OP_ROT OP_MUL <${LOCAL_WORD_CARRIER_ELASTIC_SCALE}> OP_DIV OP_ADD
    OP_NIP
  OP_ENDIF
OP_ENDIF`;
}

function localWordReadAssembly(): string {
  const boundary = localWordAffineBoundaryAssembly();
  return `OP_TOALTSTACK
OP_0 <${LOCAL_WORD_CARRIER_INPUTS - 1}>
OP_BEGIN
  OP_2DUP OP_ADD <2> OP_DIV
  OP_DUP OP_1ADD
  <5> OP_PICK OP_SWAP
  ${boundary}
  <4> OP_PICK OP_SWAP OP_LESSTHAN
  OP_IF
    OP_SWAP OP_DROP
  OP_ELSE
    OP_1ADD OP_ROT OP_DROP OP_SWAP
  OP_ENDIF
  OP_2DUP OP_NUMEQUAL
OP_UNTIL
OP_DROP
<2> OP_PICK OP_OVER
${boundary}
OP_OVER ${localWordCarrierChunkAssembly()}
<3> OP_PICK <2> OP_PICK OP_SUB OP_SPLIT OP_NIP
OP_TOALTSTACK OP_DROP OP_TOALTSTACK OP_DROP
OP_FROMALTSTACK OP_FROMALTSTACK OP_FROMALTSTACK
OP_OVER OP_SIZE OP_NIP
OP_2DUP OP_LESSTHANOREQUAL
OP_IF
  OP_DROP OP_SPLIT OP_DROP OP_SWAP OP_DROP
OP_ELSE
  OP_SUB
  OP_BEGIN
    <2> OP_PICK OP_1ADD OP_DUP ${localWordCarrierChunkAssembly()}
    OP_DUP OP_SIZE OP_NIP
    <3> OP_PICK OP_SWAP OP_LESSTHANOREQUAL
    OP_IF
      <2> OP_PICK OP_SPLIT OP_DROP
      <3> OP_ROLL OP_SWAP OP_CAT
      OP_TOALTSTACK OP_2DROP OP_DROP OP_FROMALTSTACK OP_1
    OP_ELSE
      OP_DUP OP_SIZE OP_NIP
      <3> OP_PICK OP_SWAP OP_SUB OP_TOALTSTACK
      <3> OP_ROLL OP_SWAP OP_CAT
      OP_TOALTSTACK OP_TOALTSTACK OP_2DROP
      OP_FROMALTSTACK OP_FROMALTSTACK OP_FROMALTSTACK OP_0
    OP_ENDIF
  OP_UNTIL
OP_ENDIF
`;
}

/**
 * Construction-selected proof reader. The production implementation is the
 * allocation-specialized affine reader; the generic reader remains only as an
 * independent differential oracle and for legacy/KAT callers.
 */
export type LocalWordProofReader = {
  readonly planDigestHex: string;
  readonly assembly: string;
};

/** Stack: proofLength proofOffset width -> proofLength bytes across canonical carriers. */
export function localWordReadDynamicAssembly(reader?: LocalWordProofReader): string {
  return reader?.assembly ?? localWordReadAssembly();
}

/** Stack: proofLength proofOffset width -> proofLength bytes, across any canonical carriers. */
export function localWordReadWideAssembly(reader?: LocalWordProofReader): string {
  return reader?.assembly ?? localWordReadAssembly();
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
  readonly protocolId: Uint8Array;
  readonly expectedPreprocessedRoot: Uint8Array;
  readonly publicWordCount: number;
  readonly reader?: LocalWordProofReader;
}): Uint8Array {
  if (args.protocolId.length !== 32 || args.expectedPreprocessedRoot.length !== 32 ||
    !Number.isInteger(args.publicWordCount) || args.publicWordCount < 1 || args.publicWordCount > 1024) {
    throw new Error("local-word header verifier key");
  }
  const readerFunctionId = 0;
  const compare = (offset: number, expected: Uint8Array): string => `<${offset}> <${expected.length}>
<${readerFunctionId}> OP_INVOKE
<0x${hex(expected)}> OP_EQUALVERIFY`;
  const compareLength = `<${LOCAL_WORD_PROOF_LENGTH_OFFSET}> <4>
<${readerFunctionId}> OP_INVOKE
OP_REVERSEBYTES OP_BIN2NUM OP_OVER OP_NUMEQUALVERIFY`;
  const preprocessedRootOffset = localWordProofStaticOffsets(args.publicWordCount).matrixRoots;
  return compile(`OP_DROP
${defineVmFunction(localWordReadDynamicAssembly(args.reader), readerFunctionId,
    "local-word proof header reader")}
${localWordProofLengthAssembly()}
${compare(0, new TextEncoder().encode("SKLW"))}
${compare(4, Uint8Array.of(LOCAL_WORD_PROOF_VERSION))}
${compareLength}
${compare(5, Uint8Array.of(args.profile))}
${compare(6, args.protocolId)}
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

function sameStateFieldAssembly(offset: number, width: number): string {
  return `${stateSlice("input", offset, width)}
${stateSlice("output", offset, width)} OP_EQUALVERIFY`;
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

function proofProfileAssembly(
  reader?: LocalWordProofReader,
  readerFunctionId?: number,
): string {
  const read = readerFunctionId === undefined
    ? localWordReadDynamicAssembly(reader)
    : `<${readerFunctionId}> OP_INVOKE`;
  return `${localWordProofLengthAssembly()}
<5> <1>
${read}
OP_BIN2NUM
OP_SWAP OP_DROP`;
}

function stateCommitmentAssembly(source: "input" | "output"): string {
  return source === "input"
    ? "<0> OP_UTXOTOKENCOMMITMENT"
    : "<0> OP_OUTPUTTOKENCOMMITMENT";
}

/** UI-order category: split the mutable suffix, then reverse VM-internal bytes. */
function poolCategoryAssembly(): string {
  return `<0> OP_UTXOTOKENCATEGORY
<32> OP_SPLIT OP_DROP OP_REVERSEBYTES`;
}

function outputIndexAssembly(outputIndex: number | string): string {
  return typeof outputIndex === "number" ? `<${outputIndex}>` : outputIndex;
}

function edgeFromOutputAssembly(outputIndex: number | string): string {
  return `${outputIndexAssembly(outputIndex)} OP_OUTPUTBYTECODE
<${LOCAL_WORD_EDGE_OFFSET}> OP_SPLIT OP_NIP <32> OP_SPLIT OP_DROP`;
}

/** SHA-256 of the exact 412-byte, word-aligned public relation statement. */
function localWordRelationStatementDigestAssembly(
  reader?: LocalWordProofReader,
  readerFunctionId?: number,
): string {
  const prefix = concatBytes(
    LOCAL_WORD_RELATION_STATEMENT_MAGIC,
    Uint8Array.of(LOCAL_WORD_RELATION_STATEMENT_VERSION),
  );
  const zero32 = new Uint8Array(32);
  return `<0x${hex(prefix)}>
${proofProfileAssembly(reader, readerFunctionId)}
OP_DUP OP_TOALTSTACK <1> OP_NUM2BIN OP_CAT
<0x0000> OP_CAT
OP_FROMALTSTACK OP_DUP OP_TOALTSTACK
OP_DUP OP_0 OP_NUMEQUAL
OP_IF
  OP_DROP <0> OP_OUTPUTVALUE <0> OP_UTXOVALUE OP_SUB
OP_ELSE
  OP_DUP OP_1 OP_NUMEQUAL OP_SWAP <2> OP_NUMEQUAL OP_BOOLOR OP_VERIFY
  <0> OP_UTXOVALUE <0> OP_OUTPUTVALUE OP_SUB
OP_ENDIF
<8> OP_NUM2BIN OP_CAT
${minerFeeAssembly()} <8> OP_NUM2BIN OP_CAT
${poolCategoryAssembly()} OP_CAT
${stateCommitmentAssembly("input")} OP_CAT
${stateCommitmentAssembly("output")} OP_CAT
OP_FROMALTSTACK
OP_DUP OP_TOALTSTACK
OP_DUP OP_0 OP_NUMEQUAL
OP_IF
  OP_DROP
  ${edgeFromOutputAssembly("OP_TXOUTPUTCOUNT OP_1SUB")} OP_CAT
OP_ELSE
  OP_DUP OP_1 OP_NUMEQUAL
  OP_IF
    OP_DROP <0x${hex(zero32)}> OP_CAT
  OP_ELSE
    <2> OP_NUMEQUALVERIFY
    ${edgeFromOutputAssembly("OP_TXOUTPUTCOUNT OP_1SUB")} OP_CAT
  OP_ENDIF
OP_ENDIF
OP_FROMALTSTACK
OP_DUP OP_0 OP_NUMEQUAL
OP_IF
  OP_DROP <0x${hex(zero32)}> OP_CAT <0x${hex(zero32)}> OP_CAT
OP_ELSE
  OP_DUP OP_1 OP_NUMEQUAL OP_SWAP <2> OP_NUMEQUAL OP_BOOLOR OP_VERIFY
  OP_TXINPUTCOUNT OP_1ADD OP_OUTPUTBYTECODE
  <9> OP_SPLIT OP_NIP <32> OP_SPLIT OP_DROP OP_CAT
  OP_TXINPUTCOUNT OP_OUTPUTBYTECODE OP_HASH256 OP_CAT
OP_ENDIF
OP_SHA256`;
}

/**
 * Stack: -> SHA256(SuccessorTranscriptDomain || len || exact transaction
 * statement). Every later Fiat-Shamir role begins from this same assembly.
 */
export function localWordTransactionTranscriptInitialAssembly(
  constructionId: Uint8Array,
  reader?: LocalWordProofReader,
  readerFunctionId?: number,
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
${proofProfileAssembly(reader, readerFunctionId)}
OP_DUP OP_TOALTSTACK <1> OP_NUM2BIN OP_CAT
<0> OP_OUTPUTVALUE <0> OP_UTXOVALUE OP_SUB <8> OP_NUM2BIN OP_CAT
${minerFeeAssembly()} <8> OP_NUM2BIN OP_CAT
${poolCategoryAssembly()} OP_CAT
${stateCommitmentAssembly("input")} OP_CAT
${stateCommitmentAssembly("output")} OP_CAT
OP_FROMALTSTACK
OP_DUP OP_TOALTSTACK
OP_DUP OP_0 OP_NUMEQUAL
OP_IF
  OP_DROP
  ${edgeFromOutputAssembly("OP_TXOUTPUTCOUNT OP_1SUB")} OP_CAT
OP_ELSE
  OP_DUP OP_1 OP_NUMEQUAL
  OP_IF
    OP_DROP
    <0x${hex(zero32)}> OP_CAT
  OP_ELSE
    <2> OP_NUMEQUALVERIFY
    ${edgeFromOutputAssembly("OP_TXOUTPUTCOUNT OP_1SUB")} OP_CAT
  OP_ENDIF
OP_ENDIF
OP_FROMALTSTACK
OP_DUP OP_0 OP_NUMEQUAL
OP_IF
  OP_DROP <0x${hex(zero32)}> OP_CAT <0x${hex(zero32)}> OP_CAT
OP_ELSE
  OP_DUP OP_1 OP_NUMEQUAL OP_SWAP <2> OP_NUMEQUAL OP_BOOLOR OP_VERIFY
  OP_TXINPUTCOUNT OP_1ADD OP_OUTPUTBYTECODE
  <9> OP_SPLIT OP_NIP <32> OP_SPLIT OP_DROP OP_CAT
  OP_TXINPUTCOUNT OP_OUTPUTBYTECODE OP_HASH256 OP_CAT
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

function localWordReadProofSliceAssembly(
  offset: number,
  width: number,
  reader?: LocalWordProofReader,
  readerFunctionId?: number,
): string {
  if (!Number.isSafeInteger(offset) || offset < 0 || !Number.isSafeInteger(width) || width < 1 ||
    offset + width > LOCAL_WORD_PROOF_MAX_BYTES) {
    throw new Error("local-word transcript proof slice");
  }
  const read = readerFunctionId === undefined
    ? width > 256 ? localWordReadWideAssembly(reader) : localWordReadDynamicAssembly(reader)
    : `<${readerFunctionId}> OP_INVOKE`;
  return `${localWordProofLengthAssembly()}
<${offset}> <${width}> ${read}
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
  readonly reader?: LocalWordProofReader;
}): string {
  if (!Number.isInteger(args.publicWordCount) || args.publicWordCount < 1 || args.publicWordCount > 1024) {
    throw new Error("local-word transcript public words");
  }
  const rootOffset = localWordProofStaticOffsets(args.publicWordCount).matrixRoots;
  const absorbProof = (label: string, offset: number): string =>
    `${localWordReadProofSliceAssembly(offset, 32, args.reader)}\n${localWordTranscriptAbsorbAssembly(label, 32)}`;
  const absorbOriginalRoots = `${localWordReadProofSliceAssembly(rootOffset, 64, args.reader)}
<32> OP_SPLIT OP_TOALTSTACK
${localWordTranscriptAbsorbAssembly("local-word-v16-preprocessed-root", 32)}
OP_FROMALTSTACK
${localWordTranscriptAbsorbAssembly("local-word-v16-original-root", 32)}`;
  const retainBoundary = args.retainBoundaryChallenges ?? true;
  let challengeIndex = 0;
  const checkedManifest = args.expectedChallengesOffset === undefined ? "" :
    `${localWordReadProofSliceAssembly(
      args.expectedChallengesOffset,
      LOCAL_WORD_INTERACTION_CHALLENGE_COUNT * 16,
      args.reader,
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
${localWordTransactionTranscriptInitialAssembly(args.constructionId, args.reader)}
${absorbProof("local-word-v16-descriptor", 6)}
${absorbOriginalRoots}
${checkedManifest}
${challenge("local-word-v16-lookup-gamma")}
${Array.from({ length: 6 }, (_, index) => challenge(`local-word-v16-lookup-tuple-${index}`)).join("\n")}
${challenge("local-word-v16-copy-gamma")}
${challenge("local-word-v16-copy-identity")}
${Array.from({ length: 8 }, (_, limb) => challenge(`local-word-v16-copy-limb-${limb}`)).join("\n")}
${challenge("local-word-v16-boundary-gamma", retainBoundary)}
${challenge("local-word-v16-boundary-identity", retainBoundary)}
${Array.from({ length: 8 }, (_, limb) =>
    challenge(`local-word-v16-boundary-limb-${limb}`, retainBoundary)).join("\n")}
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
<0x${hex(args.expectedDigest)}> OP_EQUALVERIFY
${[...challenges].reverse().map((value) =>
    `OP_FROMALTSTACK <0x${hex(encodeQm31(value))}> OP_EQUALVERIFY`).join("\n")}
OP_1`, "local-word interaction transcript");
}

export function localWordPublicWordCount(profile: 0 | 1 | 2): number {
  if (profile !== 0 && profile !== 1 && profile !== 2) {
    throw new Error("local-word public profile");
  }
  return LOCAL_WORD_RELATION_STATEMENT_DIGEST_WORDS;
}

/** Push one exact four-byte word of the transaction-derived relation digest. */
function localWordPublicWordBytesAssembly(
  profile: 0 | 1 | 2,
  index: number,
  reader?: LocalWordProofReader,
  readerFunctionId?: number,
): string {
  if (profile !== 0 && profile !== 1 && profile !== 2 ||
    index < 0 || index >= LOCAL_WORD_RELATION_STATEMENT_DIGEST_WORDS) {
    throw new Error("local-word relation digest word");
  }
  return `${localWordRelationStatementDigestAssembly(reader, readerFunctionId)}
<${index * 4}> OP_SPLIT OP_NIP <4> OP_SPLIT OP_DROP`;
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

function localWordPublicBoundaryInverseFunctionsAssembly(reader?: LocalWordProofReader): string {
  return [
    defineVmFunction(localWordCanonicalQm31Assembly(), 0, "local-word canonical QM31"),
    defineVmFunction(QM31_MUL_M31_ASM, 1, "local-word QM31 scalar multiply"),
    defineVmFunction(QM31_ADD_ASM, 2, "local-word QM31 add"),
    defineVmFunction(QM31_MUL_ASM, 3, "local-word QM31 multiply"),
    defineVmFunction(localWordReadDynamicAssembly(reader), 4, "local-word public inverse reader"),
  ].join("\n");
}

function localWordPublicBoundaryProofSliceAssembly(offset: number, width: number): string {
  return `${localWordProofLengthAssembly()}
<${offset}> <${width}> <4> OP_INVOKE OP_NIP`;
}

function localWordPublicBoundaryInverseCheckAssembly(
  profile: 0 | 1 | 2,
  publicWordIndex: number,
  valueAssembly = localWordPublicWordBytesAssembly(profile, publicWordIndex),
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
  const transcriptOffsets = localWordProofTranscriptOffsets(count);
  const inverseOffset = transcriptOffsets.publicInverses + publicWordIndex * 16;
  const boundaryChallenges = `${localWordPublicBoundaryProofSliceAssembly(
    transcriptOffsets.interactionChallenges + LOCAL_WORD_BOUNDARY_CHALLENGE_START * 16,
    LOCAL_WORD_BOUNDARY_CHALLENGE_COUNT * 16,
  )}
${Array.from({ length: LOCAL_WORD_BOUNDARY_CHALLENGE_COUNT - 1 }, () =>
    "<16> OP_SPLIT OP_SWAP OP_TOALTSTACK").join("\n")}
OP_TOALTSTACK`;
  return `${valueAssembly}
${boundaryChallenges}
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
  readonly reader?: LocalWordProofReader;
}): Uint8Array {
  const count = localWordPublicWordCount(args.profile);
  if (!Number.isInteger(args.publicWordIndex) || args.publicWordIndex < 0 ||
    args.publicWordIndex >= count) {
    throw new Error("local-word public inverse index");
  }
  return compile(`OP_DROP
${localWordPublicBoundaryInverseFunctionsAssembly(args.reader)}
${localWordProofLengthAssembly()}
<5> <1> <4> OP_INVOKE OP_BIN2NUM OP_SWAP OP_DROP <${args.profile}> OP_NUMEQUALVERIFY
${localWordPublicBoundaryInverseCheckAssembly(
    args.profile,
    args.publicWordIndex,
    localWordPublicWordBytesAssembly(args.profile, args.publicWordIndex, args.reader, 4),
  )}`,
  `local-word public inverse ${args.profile}:${args.publicWordIndex}`);
}

/** Share one arithmetic prelude across a contiguous public-inverse segment. */
export function compileLocalWordPublicBoundaryInverseBatchGate(args: {
  readonly profile: 0 | 1 | 2;
  readonly start: number;
  readonly count: number;
  readonly reader?: LocalWordProofReader;
}): Uint8Array {
  const total = localWordPublicWordCount(args.profile);
  if (!Number.isInteger(args.start) || !Number.isInteger(args.count) || args.start < 0 ||
    args.count < 1 || args.start + args.count > total) {
    throw new Error("local-word public inverse batch");
  }
  const digestWord = (index: number): string => `OP_FROMALTSTACK OP_DUP OP_TOALTSTACK
<${index * 4}> OP_SPLIT OP_NIP <4> OP_SPLIT OP_DROP`;
  return compile(`OP_DROP
${localWordPublicBoundaryInverseFunctionsAssembly(args.reader)}
${localWordProofLengthAssembly()}
<5> <1> <4> OP_INVOKE OP_BIN2NUM OP_SWAP OP_DROP <${args.profile}> OP_NUMEQUALVERIFY
${localWordRelationStatementDigestAssembly(args.reader, 4)} OP_TOALTSTACK
${Array.from({ length: args.count }, (_, local) => {
    const index = args.start + local;
    const check = localWordPublicBoundaryInverseCheckAssembly(args.profile, index, digestWord(index));
    return local + 1 === args.count ? check : `${check} OP_VERIFY`;
  }).join("\n")}
OP_FROMALTSTACK OP_DROP`, `local-word public inverse batch ${args.profile}:${args.start}:${args.count}`);
}

/** One owner for the public inverse sum cached in the canonical proof prefix. */
export function compileLocalWordPublicBoundarySumGate(
  profile: 0 | 1 | 2,
  reader?: LocalWordProofReader,
): Uint8Array {
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
${localWordReadProofSliceAssembly(offsets.publicInverses, (count + 1) * 16, reader)}
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

type V17TranscriptGrinding = readonly {
  readonly id: V17TheoremRoundId;
  readonly bits: number;
}[];

const V17_TRANSCRIPT_OODS_CANDIDATE = 6;

function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((byte, index) => byte === right[index]);
}

function v17TranscriptRoundBytes(id: V17TheoremRoundId): Uint8Array {
  const ordinal = V17_THEOREM_ROUND_IDS.indexOf(id);
  const name = new TextEncoder().encode(id);
  if (ordinal < 0 || ordinal > 0xff || name.length > 0xff) {
    throw new Error("local-word v17 transcript round");
  }
  return Uint8Array.of(17, ordinal, name.length, ...name);
}

function validateV17TranscriptGrinding(
  grinding: V17TranscriptGrinding,
  maximumBits = 32,
): V17TranscriptGrinding {
  if (grinding.length !== V17_THEOREM_ROUND_IDS.length || grinding.some((round, index) =>
    round.id !== V17_THEOREM_ROUND_IDS[index] || !Number.isInteger(round.bits) ||
    round.bits < 0 || round.bits > maximumBits)) {
    throw new Error("local-word v17 transcript grinding schedule");
  }
  return grinding;
}

function v17ProofSliceAssembly(
  id: V17GeneratedProofFrameId,
  readerFunctionId: number,
): string {
  const frame = v17ProofFrame(id);
  return localWordReadProofSliceAssembly(
    frame.offsetBytes,
    frame.totalBytes,
    undefined,
    readerFunctionId,
  );
}

function v17TranscriptAbsorbFrameAssembly(
  id: V17GeneratedProofFrameId,
  label: string,
  readerFunctionId: number,
  expected?: Uint8Array,
): string {
  const frame = v17ProofFrame(id);
  if (expected !== undefined && expected.length !== frame.totalBytes) {
    throw new Error(`local-word v17 transcript fixed frame ${id}`);
  }
  return `${v17ProofSliceAssembly(id, readerFunctionId)}
${expected === undefined ? "" : `OP_DUP <0x${hex(expected)}> OP_EQUALVERIFY`}
${localWordTranscriptAbsorbAssembly(label, frame.totalBytes)}`;
}

/**
 * Consume one proof-u32be nonce exactly once. The transcript sees u32le,
 * matching SuccessorTranscript.acceptGrind; the cache bytes are never absorbed.
 */
function v17NamedRoundAssembly(
  id: V17TheoremRoundId,
  grinding: V17TranscriptGrinding,
  readerFunctionId: number,
): string {
  const round = grinding[V17_THEOREM_ROUND_IDS.indexOf(id)];
  if (!round || round.id !== id) throw new Error(`local-word v17 missing round ${id}`);
  const roundBytes = v17TranscriptRoundBytes(id);
  const bitsByte = Uint8Array.of(round.bits);
  return `<0x${hex(roundBytes)}>
${localWordTranscriptAbsorbAssembly("v17-theorem-round", roundBytes.length)}
${v17ProofSliceAssembly(`roundNonce:${id}`, readerFunctionId)} OP_REVERSEBYTES
<1> OP_PICK <0x03> OP_SWAP OP_CAT <0x${hex(bitsByte)}> OP_CAT <1> OP_PICK OP_CAT OP_SHA256
${localWordLeadingZeroBitsAssembly(round.bits)}
<0x${hex(bitsByte)}> OP_SWAP OP_CAT
${localWordTranscriptAbsorbAssembly("pow", 5)}`;
}

function v17ExpectedChallengeAssembly(
  label: string,
  id: V17GeneratedProofFrameId,
  readerFunctionId: number,
  item = 0,
): string {
  const frame = v17ProofFrame(id);
  if (frame.itemBytes !== 16 || !Number.isInteger(item) || item < 0 || item >= frame.itemCount) {
    throw new Error(`local-word v17 challenge frame ${id}:${item}`);
  }
  return `<0x${hex(new TextEncoder().encode(label))}> <4> OP_INVOKE
${localWordReadProofSliceAssembly(
    frame.offsetBytes + item * 16,
    16,
    undefined,
    readerFunctionId,
  )} OP_EQUALVERIFY`;
}

function v17ExpectedChallengeVectorAssembly(
  labels: readonly string[],
  id: V17GeneratedProofFrameId,
  readerFunctionId: number,
): string {
  const frame = v17ProofFrame(id);
  if (frame.itemBytes !== 16 || labels.length !== frame.itemCount) {
    throw new Error(`local-word v17 challenge vector ${id}`);
  }
  return `${v17ProofSliceAssembly(id, readerFunctionId)} OP_TOALTSTACK
${labels.map((label) => `<0x${hex(new TextEncoder().encode(label))}> <4> OP_INVOKE
OP_FROMALTSTACK <16> OP_SPLIT OP_TOALTSTACK
OP_EQUALVERIFY`).join("\n")}
OP_FROMALTSTACK OP_0 OP_EQUALVERIFY`;
}

function v17InteractionChallengeLabels(): readonly string[] {
  return [
    "local-word-v17-lookup-gamma",
    ...Array.from({ length: 6 }, (_, index) => `local-word-v17-lookup-tuple-${index}`),
    "local-word-v17-copy-gamma",
    "local-word-v17-copy-identity",
    ...Array.from({ length: 8 }, (_, index) => `local-word-v17-copy-limb-${index}`),
    "local-word-v17-boundary-gamma",
    "local-word-v17-boundary-identity",
    ...Array.from({ length: 8 }, (_, index) => `local-word-v17-boundary-limb-${index}`),
  ];
}

function v17ProductionTranscriptManifestAssembly(args: {
  readonly part: LocalWordTranscriptManifestPart;
  readonly grinding: V17TranscriptGrinding;
  readonly reader?: LocalWordProofReader;
}): string {
  const grinding = validateV17TranscriptGrinding(args.grinding);
  const readerFunctionId = 31;
  const compareDigest = (id: V17GeneratedProofFrameId): string =>
    `${v17ProofSliceAssembly(id, readerFunctionId)} OP_EQUAL`;
  const prelude = `OP_DROP
${defineVmFunction(localWordReadDynamicAssembly(args.reader), readerFunctionId,
    "local-word v17 transcript proof reader")}
${localWordTranscriptFunctionPreludeAssembly()}`;
  const header = `${localWordTransactionTranscriptInitialAssembly(
    V17_PROOF_PROTOCOL_ID,
    args.reader,
    readerFunctionId,
  )}
${v17TranscriptAbsorbFrameAssembly(
    "magic",
    "local-word-v17-magic",
    readerFunctionId,
    new TextEncoder().encode("SKLW"),
  )}
${v17TranscriptAbsorbFrameAssembly(
    "proofVersion",
    "local-word-v17-proof-version",
    readerFunctionId,
    Uint8Array.of(17),
  )}
${v17TranscriptAbsorbFrameAssembly("profile", "local-word-v17-profile", readerFunctionId)}
${v17TranscriptAbsorbFrameAssembly(
    "protocolId",
    "local-word-v17-protocol-id",
    readerFunctionId,
    V17_PROOF_PROTOCOL_ID,
  )}
${v17TranscriptAbsorbFrameAssembly(
    "matrixRoot:preprocessed",
    "local-word-v17-preprocessed-root",
    readerFunctionId,
  )}
${v17TranscriptAbsorbFrameAssembly(
    "matrixRoot:original",
    "local-word-v17-original-root",
    readerFunctionId,
  )}`;
  const challengeLabels = v17InteractionChallengeLabels();
  if (challengeLabels.length !== LOCAL_WORD_INTERACTION_CHALLENGE_COUNT) {
    throw new Error("local-word v17 interaction challenge count");
  }
  const interaction = `${header}
${v17NamedRoundAssembly("air:logup", grinding, readerFunctionId)}
${v17ExpectedChallengeVectorAssembly(challengeLabels, "interactionChallenges", readerFunctionId)}
${v17TranscriptAbsorbFrameAssembly(
    "publicInverses",
    "local-word-v17-public-boundary-inverses",
    readerFunctionId,
  )}
${v17TranscriptAbsorbFrameAssembly(
    "publicClaimedSum",
    "local-word-v17-public-boundary-claimed-sum",
    readerFunctionId,
  )}
${v17TranscriptAbsorbFrameAssembly(
    "matrixRoot:interaction",
    "local-word-v17-interaction-root",
    readerFunctionId,
  )}
${v17TranscriptAbsorbFrameAssembly(
    "matrixRoot:interactionGlobal",
    "local-word-v17-interaction-global-root",
    readerFunctionId,
  )}
${compareDigest("interactionDigest")}`;
  const composition = `${v17ProofSliceAssembly("interactionDigest", readerFunctionId)}
${v17NamedRoundAssembly("air:composition", grinding, readerFunctionId)}
${v17ExpectedChallengeAssembly(
    "local-word-v17-constraint-alpha",
    "constraintAlpha",
    readerFunctionId,
  )}
${compareDigest("compositionDigest")}`;
  const batch = `${v17ProofSliceAssembly("compositionDigest", readerFunctionId)}
${v17TranscriptAbsorbFrameAssembly(
    "matrixRoot:quotientAndFriMask",
    "local-word-v17-quotient-and-fri-mask-root",
    readerFunctionId,
  )}
${v17NamedRoundAssembly("air:ood", grinding, readerFunctionId)}
OP_DUP ${v17OodsSelectDigestAssembly(V17_TRANSCRIPT_OODS_CANDIDATE)}
${v17OodsDigestToTAssembly()}
OP_2DROP OP_2DROP
${v17TranscriptAbsorbFrameAssembly(
    "oodValues",
    "local-word-v17-ood-values",
    readerFunctionId,
  )}
${v17NamedRoundAssembly("fri:batch", grinding, readerFunctionId)}
${v17ExpectedChallengeAssembly("local-word-v17-batch-beta", "batchBeta", readerFunctionId)}
${compareDigest("batchDigest")}`;
  const fri = (first: boolean): string => {
    const start = first ? 0 : 5;
    const end = first ? 5 : 9;
    const startDigest: V17GeneratedProofFrameId = first ? "batchDigest" : "friMidDigest";
    const endDigest: V17GeneratedProofFrameId = first ? "friMidDigest" : "friRootsDigest";
    return `${v17ProofSliceAssembly(startDigest, readerFunctionId)}
${Array.from({ length: end - start }, (_, local) => {
      const round = start + local;
      const count = round < 8 ? 2 : 1;
      return `${v17TranscriptAbsorbFrameAssembly(
        `friRoot:${round}` as V17GeneratedProofFrameId,
        `local-word-v17-fri-root-${round}`,
        readerFunctionId,
      )}
${v17NamedRoundAssembly(
        `fri:fold:${round}` as V17TheoremRoundId,
        grinding,
        readerFunctionId,
      )}
${Array.from({ length: count }, (_, subfold) => v17ExpectedChallengeAssembly(
        `local-word-v17-fri-alpha-${round}-${subfold}`,
        `friAlpha:${round}:${subfold}` as V17GeneratedProofFrameId,
        readerFunctionId,
      )).join("\n")}`;
    }).join("\n")}
${compareDigest(endDigest)}`;
  };
  const final = `${v17ProofSliceAssembly("friRootsDigest", readerFunctionId)}
${v17TranscriptAbsorbFrameAssembly(
    "finalCoefficients",
    "local-word-v17-fri-final",
    readerFunctionId,
  )}
${v17NamedRoundAssembly("fri:query", grinding, readerFunctionId)}
${compareDigest("queryDigest")}`;
  return args.part === "interaction" ? `${prelude}\n${interaction}`
    : args.part === "composition" ? `${prelude}\n${composition}`
      : args.part === "batch" ? `${prelude}
${defineVmFunction(
    v17OodsCandidateAcceptanceAssembly(),
    V17_TRANSCRIPT_OODS_CANDIDATE,
    "local-word v17 transcript OODS candidate",
  )}\n${batch}`
        : args.part === "fri-first" ? `${prelude}\n${fri(true)}`
          : args.part === "fri-second" ? `${prelude}\n${fri(false)}`
            : `${prelude}\n${final}`;
}

function compileLegacyLocalWordTranscriptManifestGate(args: {
  readonly constructionId: Uint8Array;
  readonly publicWordCount: number;
  readonly part: LocalWordTranscriptManifestPart;
  readonly parameters: LocalWordProofParameters;
}): Uint8Array {
  const parameters = args.parameters;
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
${localWordTranscriptAbsorbAssembly("local-word-v16-public-boundary", args.publicWordCount * 16)}
${compareDigest(offsets.interactionDigest)}`;
  const composition = `${localWordReadProofSliceAssembly(offsets.interactionDigest, 32)}
${localWordTranscriptAbsorbBatchAssembly(matrixRoot(2), [
    { label: "local-word-v16-interaction-root", width: 32 },
    { label: "local-word-v16-interaction-global-root", width: 32 },
  ])}
${localWordExpectedTranscriptChallengeAssembly("local-word-v16-constraint-alpha", offsets.constraintAlpha)}
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
${localWordReadProofSliceAssembly(offsets.finalCoefficients, offsets.finalCoefficientCount * 16)}
${localWordTranscriptAbsorbAssembly("fri-final", offsets.finalCoefficientCount * 16)}
${localWordReadProofSliceAssembly(offsets.grindNonce, 4)} OP_REVERSEBYTES
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
 * Six production roles replay the graph-generated v17 transcript. Serialized
 * challenges and digests are checked snapshots, never transcript messages;
 * totalLength, ranks, the terminal directory, and opening bodies are absent.
 * A non-v17 construction ID selects only the frozen experimental v16 codec.
 */
export function compileLocalWordTranscriptManifestGate(args: {
  readonly constructionId: Uint8Array;
  readonly publicWordCount: number;
  readonly part: LocalWordTranscriptManifestPart;
  readonly parameters?: LocalWordProofParameters;
  readonly reader?: LocalWordProofReader;
}): Uint8Array {
  const parameters = validateLocalWordProofParameters(args.parameters ?? LOCAL_WORD_PRODUCTION_PARAMETERS);
  if (sameBytes(args.constructionId, V17_PROOF_PROTOCOL_ID)) {
    const offsets = localWordProofTranscriptOffsets(args.publicWordCount, parameters);
    if (args.publicWordCount !== 8 || offsets.openingBodies !== LOCAL_WORD_PROOF_FIXED_PREFIX_BYTES) {
      throw new Error("local-word v17 transcript production geometry");
    }
    return compile(v17ProductionTranscriptManifestAssembly({
      part: args.part,
      grinding: V17_PRODUCTION_ROUND_GRINDING,
      reader: args.reader,
    }), `local-word v17 transcript manifest ${args.part}`);
  }
  return compileLegacyLocalWordTranscriptManifestGate({ ...args, parameters });
}

/**
 * Test-only compiler for fixed, low-work transcript vectors. It uses the exact
 * production frames, labels, and protocol ID but rejects schedules above eight
 * bits, so it cannot silently replace a production role.
 */
export function compileV17LocalWordTranscriptManifestKatGate(args: {
  readonly part: LocalWordTranscriptManifestPart;
  readonly roundGrinding: V17TranscriptGrinding;
  readonly reader?: LocalWordProofReader;
}): Uint8Array {
  const grinding = validateV17TranscriptGrinding(args.roundGrinding, 8);
  return compile(v17ProductionTranscriptManifestAssembly({
    part: args.part,
    grinding,
    reader: args.reader,
  }), `local-word v17 transcript KAT ${args.part}`);
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
  readonly reader?: LocalWordProofReader;
}): Uint8Array {
  const parameters = validateLocalWordProofParameters(args.parameters ?? LOCAL_WORD_PRODUCTION_PARAMETERS);
  const geometry = validateLocalWordQuerySamplerGeometry(parameters);
  const { rowCount, orbitSize, orbitCount } = geometry;
  if (args.expectedQueries !== undefined && (args.expectedQueries.length !== parameters.fri.queries ||
    args.expectedQueries.some((query) => !Number.isInteger(query) || query < 0 || query >= rowCount))) {
    throw new Error("local-word expected queries");
  }
  if (orbitCount > 128) {
    throw new Error("local-word deep query sampler geometry");
  }
  const count = parameters.fri.queries;
  const offsets = localWordProofTranscriptOffsets(args.publicWordCount, parameters);
  const reader = defineVmFunction(
    localWordReadDynamicAssembly(args.reader),
    0,
    "local-word query schedule reader",
  );
  const bitReverse = defineVmFunction(
    localWordBitReverseAssembly(parameters.evalLog),
    1,
    "local-word query schedule bit reverse",
  );
  const predecessor = defineVmFunction(
    localWordPredecessorAssembly(parameters),
    2,
    "local-word query schedule predecessor",
  );
  // One query slot and two predecessor slots (one per circle half) per orbit.
  const queryTableSlots = orbitCount;
  const tableSlots = 3 * orbitCount;
  const lookup = defineVmFunction(`<4> OP_MUL OP_SPLIT OP_NIP
<4> OP_SPLIT OP_DROP OP_BIN2NUM`, 3, "local-word query schedule table lookup");
  const insert = defineVmFunction(`OP_TOALTSTACK <4> OP_MUL OP_SPLIT
<4> OP_SPLIT OP_SWAP OP_BIN2NUM OP_0 OP_NUMEQUALVERIFY
OP_FROMALTSTACK <4> OP_NUM2BIN OP_SWAP OP_CAT OP_CAT`, 4,
  "local-word query schedule table insert");
  const bitmap = localWordRankBitmap(orbitCount);
  const zeroBitmap = new Uint8Array(bitmap.width);
  const collision = defineVmFunction(`OP_TOALTSTACK OP_2DUP OP_NUMNOTEQUAL
  OP_FROMALTSTACK OP_DUP OP_TOALTSTACK
  <3> OP_PICK <${orbitSize}> OP_DIV <2> OP_MUL <${queryTableSlots}> OP_ADD
  <3> OP_INVOKE <3> OP_PICK OP_1ADD OP_NUMNOTEQUAL OP_BOOLAND
  OP_FROMALTSTACK OP_DUP OP_TOALTSTACK
  <3> OP_PICK <${orbitSize}> OP_DIV <2> OP_MUL <${queryTableSlots + 1}> OP_ADD
  <3> OP_INVOKE <3> OP_PICK OP_1ADD OP_NUMNOTEQUAL OP_BOOLAND
  OP_FROMALTSTACK OP_DUP OP_TOALTSTACK
  <2> OP_PICK <${orbitSize}> OP_DIV
  <3> OP_INVOKE <2> OP_PICK OP_1ADD OP_NUMNOTEQUAL OP_BOOLAND
  OP_FROMALTSTACK OP_DROP`, 5, "local-word query schedule collision check");
  const insertPair = defineVmFunction(`<2> OP_PICK <${orbitSize}> OP_DIV
<3> OP_PICK OP_1ADD <4> OP_INVOKE
<1> OP_PICK <${orbitSize}> OP_DIV <2> OP_MUL <${queryTableSlots}> OP_ADD
<3> OP_PICK <2> OP_MOD OP_ADD
<2> OP_PICK OP_1ADD <4> OP_INVOKE`, 6, "local-word query schedule pair insert");
  // During candidate execution, the alternate stack is:
  //   remaining serialized queries, candidate ordinal, collision table (top).
  // Peek the ordinal without moving either persistent byte string.
  const peekCandidateOrdinal = `OP_FROMALTSTACK OP_FROMALTSTACK
OP_DUP OP_TOALTSTACK OP_SWAP OP_TOALTSTACK`;
  const expectedTable = args.expectedQueries === undefined
    ? undefined
    : concatBytes(...args.expectedQueries.map(writeU32BE));
  const expectedCheck = expectedTable === undefined ? "" : `OP_DUP
${peekCandidateOrdinal}
<4> OP_MUL
<0x${hex(expectedTable)}> OP_SWAP OP_SPLIT OP_NIP
<4> OP_SPLIT OP_DROP OP_REVERSEBYTES OP_BIN2NUM
OP_NUMEQUALVERIFY`;
  // Consume exactly one preloaded big-endian query while restoring the two
  // execution values above it on the alternate stack. This replaces forty-four
  // full cross-carrier proof searches with one canonical up-front read.
  const consumeSerializedQuery = `OP_FROMALTSTACK OP_FROMALTSTACK OP_FROMALTSTACK
<4> OP_SPLIT
OP_TOALTSTACK
OP_SWAP OP_TOALTSTACK
OP_SWAP OP_TOALTSTACK
OP_REVERSEBYTES OP_BIN2NUM OP_NUMEQUALVERIFY`;
  const representative = `OP_0 OP_SWAP
OP_BEGIN
  OP_DUP <2> OP_INVOKE
  OP_FROMALTSTACK OP_DUP OP_TOALTSTACK <5> OP_INVOKE
  OP_IF
    OP_FROMALTSTACK <6> OP_INVOKE OP_TOALTSTACK
    OP_DROP
    ${expectedCheck}
    ${consumeSerializedQuery}
    OP_DROP OP_1
  OP_ELSE
    OP_DROP
    OP_DUP <${orbitSize}> OP_MOD <${orbitSize - 1}> OP_NUMEQUAL
    OP_IF <${orbitSize - 1}> OP_SUB OP_ELSE OP_1ADD OP_ENDIF
    OP_SWAP OP_1ADD OP_SWAP
    OP_OVER
    ${peekCandidateOrdinal}
    OP_0 OP_NUMEQUAL
    OP_IF OP_1 OP_ELSE <${geometry.maxScanAttempts}> OP_ENDIF
    OP_LESSTHAN OP_VERIFY OP_0
  OP_ENDIF
OP_UNTIL
OP_1ADD OP_1`;
  const candidateBody = `OP_FROMALTSTACK OP_SWAP OP_TOALTSTACK OP_TOALTSTACK
OP_BEGIN
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
    ${representative}
  OP_ELSE
    OP_2DROP OP_1ADD OP_0
  OP_ENDIF
OP_UNTIL
OP_FROMALTSTACK OP_FROMALTSTACK OP_DROP OP_TOALTSTACK`;
  const candidate = defineVmFunction(
    candidateBody,
    7,
    "local-word query schedule candidate",
  );
return compile(`OP_DROP
${reader}
${bitReverse}
${predecessor}
${lookup}
${insert}
${collision}
${insertPair}
${candidate}
${localWordProofLengthAssembly()}
OP_DUP <${offsets.queryDigest}> <32> <0> OP_INVOKE OP_NIP
OP_OVER <${offsets.queries}> <${count * 4}> <0> OP_INVOKE OP_NIP
OP_TOALTSTACK
<0x${hex(bitmap.table)}>
<0x${hex(zeroBitmap)}>
OP_0 <${tableSlots * 4}> OP_NUM2BIN OP_TOALTSTACK
OP_0
${Array.from({ length: count }, (_, item) => `<${item}> <7> OP_INVOKE`).join("\n")}
OP_FROMALTSTACK OP_DROP
OP_FROMALTSTACK OP_0 OP_EQUALVERIFY
OP_DROP OP_2DROP OP_2DROP OP_1`, "local-word query schedule");
}

export type LocalWordOpeningScheduleGateArgs = {
  readonly publicWordCount: number;
  readonly parameters?: LocalWordProofParameters;
  readonly reader?: LocalWordProofReader;
  /** Production ownership: semantic map(s) plus one canonical-list shape gate. */
  readonly mappingShard?: number;
  readonly mappingShards?: number;
} & (
  | { readonly opening: "current"; readonly stage?: never }
  | { readonly opening: "global"; readonly stage: "current" | "previous" | "shape" }
  | { readonly opening: "fri"; readonly friLayer: number; readonly stage: "current" | "shape" }
);

function localWordBitReverseAssembly(bits: number): string {
  if (!Number.isInteger(bits) || bits < 1 || bits > 30) throw new Error("local-word bit reverse");
  return `OP_0 OP_SWAP
${Array.from({ length: bits }, () => `OP_DUP <2> OP_MOD
<2> OP_ROLL <2> OP_MUL OP_ADD
OP_SWAP <2> OP_DIV`).join("\n")}
OP_DROP`;
}

/** Stack: bit-reversed row -> relation predecessor in the same representation. */
function localWordPredecessorAssembly(parameters: LocalWordProofParameters): string {
  const halfRows = 2 ** (parameters.evalLog - 1);
  const step = 2 ** (parameters.evalLog - parameters.relationLog - 1);
  return `<1> OP_INVOKE
OP_DUP <${halfRows}> OP_LESSTHAN
OP_IF
  <${step}> OP_SUB <${halfRows}> OP_ADD <${halfRows}> OP_MOD
OP_ELSE
  <${halfRows}> OP_SUB <${step}> OP_ADD <${halfRows}> OP_MOD <${halfRows}> OP_ADD
OP_ENDIF
<1> OP_INVOKE`;
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
 * Bind every sorted opening index to the one transcript-derived schedule and
 * to the mandatory level-zero Merkle frontier. Rank manifests are exact
 * permutations; the equality with the serialized frontier makes that frontier
 * checked shared evidence rather than a prover-selected geometry channel.
 */
export function compileLocalWordOpeningScheduleGate(
  args: LocalWordOpeningScheduleGateArgs,
): Uint8Array {
  const parameters = validateLocalWordProofParameters(
    args.parameters ?? LOCAL_WORD_PRODUCTION_PARAMETERS,
  );
  const stage = args.opening === "current" ? "current" : args.stage;
  const mappingShards = args.mappingShards ?? 1;
  const mappingShard = args.mappingShard ?? 0;
  if (!Number.isInteger(mappingShards) || mappingShards < 1 ||
    !Number.isInteger(mappingShard) || mappingShard < 0 || mappingShard >= mappingShards ||
    ((args.opening !== "fri" || stage === "shape") &&
      (mappingShards !== 1 || mappingShard !== 0))) {
    throw new Error("local-word opening schedule shard");
  }
  if ((args.opening === "global" && stage !== "current" &&
      stage !== "previous" && stage !== "shape") ||
    (args.opening === "fri" && stage !== "current" && stage !== "shape")) {
    throw new Error("local-word FRI opening schedule stage");
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
    localWordReadDynamicAssembly(args.reader),
    0,
    "local-word opening schedule reader",
  );
  const bitReverse = args.opening === "global" && stage === "previous"
    ? defineVmFunction(
      localWordBitReverseAssembly(parameters.evalLog),
      1,
      "local-word opening schedule bit reverse",
    )
    : "";
  const derivedIndexBlob = directoryOffset !== undefined;
  const start = directoryOffset === undefined
    ? `<${offsets.currentIndices}>`
    : `OP_DUP <${directoryOffset}> <8> <0> OP_INVOKE OP_NIP
<4> OP_SPLIT OP_EQUALVERIFY
OP_0`;
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
  const predecessorDefinition = args.opening === "global" && stage === "previous"
    ? defineVmFunction(
      localWordPredecessorAssembly(parameters),
      2,
      "local-word opening schedule predecessor",
    )
    : "";
  const frontierSliceDefinition = derivedIndexBlob
    ? defineVmFunction(`OP_DUP <${directoryOffset! + 12}> <4> <0> OP_INVOKE OP_NIP
OP_REVERSEBYTES OP_BIN2NUM <4> OP_ADD
<1> OP_PICK OP_SWAP <4> <0> OP_INVOKE OP_NIP
OP_REVERSEBYTES OP_BIN2NUM
<1> OP_PICK OP_SWAP <${indexCount * 36}> <0> OP_INVOKE OP_NIP`, 3,
      "local-word level-zero frontier slice")
    : "";
  /**
   * Consume one rank/query pair from two preloaded byte strings and bind it to
   * the corresponding level-zero opening record. The body is invoked with the
   * same stack shape for fixed current indices and 36-byte Merkle-frontier
   * records; only graph-fixed geometry is compiled into the body.
   */
  const mapBatchedPair = (args: {
    readonly recordWidth: 4 | 36;
    readonly openingArity: number;
    readonly foldDivisor: number;
    readonly previous: boolean;
  }): string =>
    `<1> OP_SPLIT OP_SWAP <0x00> OP_CAT OP_BIN2NUM
OP_TOALTSTACK
OP_SWAP <4> OP_SPLIT OP_SWAP OP_REVERSEBYTES OP_BIN2NUM
${args.previous
    ? "<2> OP_INVOKE"
    : args.foldDivisor === 1 && args.openingArity === 1
      ? ""
      : `<${args.foldDivisor}> OP_DIV <${args.openingArity}> OP_DIV ` +
        `<${args.openingArity}> OP_MUL`}
OP_FROMALTSTACK
OP_DUP OP_0 OP_GREATERTHANOREQUAL OP_VERIFY
${args.openingArity === 1 ? "" :
    `OP_DUP <${args.openingArity}> OP_MOD OP_0 OP_NUMEQUALVERIFY`}
OP_DUP <${indexCount}> OP_LESSTHAN OP_VERIFY
${Array.from({ length: args.openingArity }, (_, child) => `OP_OVER
${child === 0 ? "" : `<${child}> OP_ADD`}
OP_TOALTSTACK
OP_DUP ${child === 0 ? "" : `<${child}> OP_ADD `}<${args.recordWidth}> OP_MUL
<5> OP_PICK OP_SWAP OP_SPLIT OP_NIP
<4> OP_SPLIT OP_DROP OP_REVERSEBYTES OP_BIN2NUM
OP_FROMALTSTACK OP_NUMEQUALVERIFY`).join("\n")}
OP_2DROP
OP_SWAP`;
  const batchedRankMappings = (args: {
    readonly rankOffset: number;
    readonly first: number;
    readonly count: number;
    readonly functionId: number;
  }): string =>
    `<2> OP_PICK <${offsets.queries + args.first * 4}> <${args.count * 4}> ` +
    `<0> OP_INVOKE OP_NIP
<3> OP_PICK <${args.rankOffset + args.first}> <${args.count}> <0> OP_INVOKE OP_NIP
${Array.from({ length: args.count }, () => `<${args.functionId}> OP_INVOKE`).join("\n")}
OP_0 OP_EQUALVERIFY OP_0 OP_EQUALVERIFY`;
  const nextSorted = `OP_SWAP <4> OP_SPLIT OP_TOALTSTACK
OP_REVERSEBYTES OP_BIN2NUM
OP_2DUP OP_LESSTHAN OP_VERIFY OP_NIP
OP_FROMALTSTACK OP_SWAP`;
  const sorted = `<4> OP_SPLIT OP_SWAP OP_REVERSEBYTES OP_BIN2NUM
${Array.from({ length: indexCount - 1 }, () => nextSorted).join("\n")}
OP_DROP OP_0 OP_EQUALVERIFY`;
  const currentPairDefinition = args.opening === "current"
    ? defineVmFunction(mapBatchedPair({
      recordWidth: 4,
      openingArity: 1,
      foldDivisor: 1,
      previous: false,
    }), 4, "local-word opening pair")
    : "";
  if (derivedIndexBlob) {
    const frontierSetup = `<1> OP_PICK <3> OP_INVOKE OP_NIP`;
    if (stage === "shape") {
      const shapeRankOffset = args.opening === "global"
        ? offsets.globalCurrentRanks
        : offsets.friCosetRanks + friLayer! * queryCount;
      const shapeRankCount = args.opening === "global" ? 2 * queryCount : queryCount;
      const rankStep = defineVmFunction(`<2> OP_ROLL
<1> OP_SPLIT OP_SWAP <0x00> OP_CAT OP_BIN2NUM
OP_SWAP OP_TOALTSTACK
${updateBitmap(arity)} OP_DROP
OP_FROMALTSTACK OP_ROT OP_ROT`, 4, "local-word opening rank step");
      const frontierStep = defineVmFunction(`<1> OP_ROLL
<36> OP_SPLIT OP_SWAP <4> OP_SPLIT OP_DROP
<2> OP_ROLL OP_SWAP OP_CAT`, 5, "local-word opening frontier step");
      const rankChecks = `<2> OP_PICK <${shapeRankOffset}> <${shapeRankCount}> ` +
        `<0> OP_INVOKE OP_NIP
<0x${hex(bitmap.table)}>
<0x${hex(zeroBitmap)}>
${Array.from({ length: shapeRankCount }, () => "<4> OP_INVOKE").join("\n")}
<0x${hex(bitmap.full)}> OP_EQUALVERIFY OP_DROP
OP_0 OP_EQUALVERIFY`;
      const frontierIndexBlob = `${Array.from({ length: indexCount }, () =>
        `<5> OP_INVOKE`).join("\n")}
<1> OP_ROLL OP_DUP OP_SIZE OP_NIP OP_0 OP_NUMEQUALVERIFY OP_DROP`;
      return compile(`OP_DROP
${reader}
${frontierSliceDefinition}
${rankStep}
${frontierStep}
${localWordProofLengthAssembly()}
${start}
${frontierSetup}
${rankChecks}
OP_0
${frontierIndexBlob}
${sorted}
OP_2DROP OP_1`, `local-word ${args.opening} opening shape`);
    }
    const firstMapping = Math.floor(mappingShard * queryCount / mappingShards);
    const endMapping = Math.floor((mappingShard + 1) * queryCount / mappingShards);
    const rankOffset = args.opening === "global"
      ? stage === "previous" ? offsets.globalPreviousRanks : offsets.globalCurrentRanks
      : offsets.friCosetRanks + friLayer! * queryCount;
    const openingPair = defineVmFunction(mapBatchedPair({
      recordWidth: 36,
      openingArity: arity,
      foldDivisor: 2 ** completedFolds,
      previous: stage === "previous",
    }), 4, "local-word opening pair");
    const directMappings = batchedRankMappings({
      rankOffset,
      first: firstMapping,
      count: endMapping - firstMapping,
      functionId: 4,
    });
    return compile(`OP_DROP
${reader}
${bitReverse}
${predecessorDefinition}
${frontierSliceDefinition}
${openingPair}
${localWordProofLengthAssembly()}
${start}
${frontierSetup}
${directMappings}
OP_2DROP OP_DROP OP_1`,
    `local-word ${args.opening} opening ${stage} ${mappingShard}/${mappingShards}`);
  }
  return compile(`OP_DROP
${reader}
${bitReverse}
${predecessorDefinition}
${frontierSliceDefinition}
${currentPairDefinition}
${localWordProofLengthAssembly()}
${start}
OP_2DUP <${indexCount * 4}> <0> OP_INVOKE OP_NIP
${batchedRankMappings({
    rankOffset: offsets.currentRanks,
    first: 0,
    count: queryCount,
    functionId: 4,
  })}
${sorted}
OP_2DROP OP_1`, `local-word ${args.opening} opening schedule`);
}

/**
 * Public money/state half of the final pool input. Carrier zero is the pool
 * covenant; the contiguous infrastructure suffix contains the exact verifier
 * bank followed by any authenticated ROM pages, all rolled value-neutrally.
 * The private relation is checked by the verifier roles over the same proof.
 */
export function compileLocalWordValueSettlementGate(
  authorizedBankDigests: LocalWordVerifierBankDigests,
  reader?: LocalWordProofReader,
): Uint8Array {
  if (authorizedBankDigests.some((digest) => digest.length !== 32)) {
    throw new Error("local-word settlement verifier bank digests");
  }
  const statePrefix = new Uint8Array(8);
  statePrefix.set(new TextEncoder().encode("PAA2"));
  statePrefix[4] = 2;
  const sameStateBytes = (offset: number, width: number): string => `${stateSlice("input", offset, width)}
${stateSlice("output", offset, width)}
OP_EQUALVERIFY`;
  const sameStateNumber = (offset: number, width: number): string => `${stateNumber("input", offset, width)}
${stateNumber("output", offset, width)}
OP_NUMEQUALVERIFY`;
  const profile = proofProfileAssembly(reader);
  const verifierBanks = concatBytes(...authorizedBankDigests);
  const infrastructureEnd = `<0> OP_OUTPUTVALUE <0> OP_UTXOVALUE OP_GREATERTHAN
OP_IF OP_TXINPUTCOUNT OP_1SUB OP_ELSE OP_TXINPUTCOUNT OP_ENDIF
OP_DUP <${LOCAL_WORD_CARRIER_INPUTS}> OP_GREATERTHANOREQUAL OP_VERIFY`;
  const tokenlessInput = (index: number | string): string =>
    `${outputIndexAssembly(index)} OP_UTXOTOKENCATEGORY OP_0 OP_EQUALVERIFY
${outputIndexAssembly(index)} OP_UTXOTOKENCOMMITMENT OP_0 OP_EQUALVERIFY
${outputIndexAssembly(index)} OP_UTXOTOKENAMOUNT OP_0 OP_NUMEQUALVERIFY`;
  const tokenlessOutput = (index: number | string): string =>
    `${outputIndexAssembly(index)} OP_OUTPUTTOKENCATEGORY OP_0 OP_EQUALVERIFY
${outputIndexAssembly(index)} OP_OUTPUTTOKENCOMMITMENT OP_0 OP_EQUALVERIFY
${outputIndexAssembly(index)} OP_OUTPUTTOKENAMOUNT OP_0 OP_NUMEQUALVERIFY`;
  return compile(`OP_DROP
OP_INPUTINDEX OP_0 OP_NUMEQUALVERIFY
<0> OP_UTXOBYTECODE <0> OP_OUTPUTBYTECODE OP_EQUALVERIFY
<0> OP_UTXOTOKENCATEGORY <0> OP_OUTPUTTOKENCATEGORY OP_EQUALVERIFY
<0> OP_UTXOTOKENCATEGORY
OP_SIZE <33> OP_NUMEQUALVERIFY
<32> OP_SPLIT <0x01> OP_EQUALVERIFY OP_DROP
<0> OP_UTXOTOKENAMOUNT OP_0 OP_NUMEQUALVERIFY
<0> OP_OUTPUTTOKENAMOUNT OP_0 OP_NUMEQUALVERIFY
<0> OP_UTXOTOKENCOMMITMENT OP_SIZE <${ANY_STATE_BYTES}> OP_NUMEQUALVERIFY OP_DROP
<0> OP_OUTPUTTOKENCOMMITMENT OP_SIZE <${ANY_STATE_BYTES}> OP_NUMEQUALVERIFY OP_DROP
${stateSlice("input", 0, 8)} <0x${hex(statePrefix)}> OP_EQUALVERIFY
${stateSlice("output", 0, 8)} <0x${hex(statePrefix)}> OP_EQUALVERIFY
${stateSlice("input", 24, 8)} <0x0000000000000000> OP_EQUALVERIFY
${stateSlice("output", 24, 8)} <0x0000000000000000> OP_EQUALVERIFY
${stateNumber("input", 16, 8)} <${2 ** EDGE_HISTORY_DEPTH}> OP_LESSTHANOREQUAL OP_VERIFY
${stateNumber("output", 16, 8)} <${2 ** EDGE_HISTORY_DEPTH}> OP_LESSTHANOREQUAL OP_VERIFY
${stateNumber("input", 8, 8)} OP_1ADD
${stateNumber("output", 8, 8)} OP_NUMEQUALVERIFY

${infrastructureEnd} OP_TOALTSTACK
<0x${hex(concatBytes(...LOCAL_WORD_VERIFIER_BANK_SEEDS))}>
${profile} <32> OP_MUL OP_SPLIT OP_NIP <32> OP_SPLIT OP_DROP
OP_1
OP_BEGIN
  OP_DUP OP_UTXOBYTECODE
  OP_SIZE <${LOCAL_WORD_P2SH32_LOCKING_BYTES}> OP_NUMEQUALVERIFY
  OP_OVER OP_UTXOVALUE <${V17_BANK_NUMBER_BYTES}> OP_NUM2BIN OP_CAT
  OP_OVER OP_INPUTSEQUENCENUMBER <${V17_BANK_NUMBER_BYTES}> OP_NUM2BIN OP_CAT
  OP_ROT OP_SWAP OP_CAT OP_SHA256 OP_SWAP
  OP_1ADD OP_DUP OP_FROMALTSTACK OP_DUP OP_TOALTSTACK OP_NUMEQUAL
OP_UNTIL
OP_DROP
OP_FROMALTSTACK OP_DROP
<0x${hex(verifierBanks)}>
${profile} <32> OP_MUL OP_SPLIT OP_NIP <32> OP_SPLIT OP_DROP
OP_EQUALVERIFY

${infrastructureEnd} OP_TOALTSTACK
<1>
OP_BEGIN
  OP_DUP OP_UTXOVALUE <1> OP_PICK OP_OUTPUTVALUE OP_NUMEQUALVERIFY
  OP_DUP OP_UTXOBYTECODE <1> OP_PICK OP_OUTPUTBYTECODE OP_EQUALVERIFY
  OP_DUP OP_UTXOTOKENCATEGORY OP_0 OP_EQUALVERIFY
  OP_DUP OP_UTXOTOKENCOMMITMENT OP_0 OP_EQUALVERIFY
  OP_DUP OP_UTXOTOKENAMOUNT OP_0 OP_NUMEQUALVERIFY
  OP_DUP OP_OUTPUTTOKENCATEGORY OP_0 OP_EQUALVERIFY
  OP_DUP OP_OUTPUTTOKENCOMMITMENT OP_0 OP_EQUALVERIFY
  OP_DUP OP_OUTPUTTOKENAMOUNT OP_0 OP_NUMEQUALVERIFY
  OP_1ADD OP_DUP OP_FROMALTSTACK OP_DUP OP_TOALTSTACK OP_NUMEQUAL
OP_UNTIL
OP_DROP
OP_FROMALTSTACK OP_DROP

<0> OP_OUTPUTVALUE <0> OP_UTXOVALUE OP_SUB
OP_DUP OP_0 OP_GREATERTHAN
OP_IF
  OP_DROP
  OP_TXINPUTCOUNT OP_TXOUTPUTCOUNT OP_NUMEQUALVERIFY
  ${stateNumber("input", 16, 8)} OP_1ADD
  ${stateNumber("output", 16, 8)} OP_NUMEQUALVERIFY
  ${stateSlice("input", 32, 32)} ${stateSlice("output", 32, 32)} OP_EQUAL OP_NOT OP_VERIFY
  ${stateSlice("input", 64, 32)} ${stateSlice("output", 64, 32)} OP_EQUAL OP_NOT OP_VERIFY
  ${sameStateBytes(96, 32)}
  ${profile} OP_0 OP_NUMEQUALVERIFY
  ${tokenlessInput("OP_TXINPUTCOUNT OP_1SUB")}
  OP_TXOUTPUTCOUNT OP_1SUB OP_OUTPUTVALUE OP_0 OP_NUMEQUALVERIFY
  ${tokenlessOutput("OP_TXOUTPUTCOUNT OP_1SUB")}
  OP_TXINPUTCOUNT OP_1SUB OP_UTXOVALUE
  <0> OP_OUTPUTVALUE <0> OP_UTXOVALUE OP_SUB
  ${minerFeeAssembly()} OP_ADD
  OP_NUMEQUALVERIFY
OP_ELSE
  OP_0 OP_LESSTHAN OP_VERIFY
  ${profile}
  OP_DUP OP_1 OP_NUMEQUAL
  OP_IF
    OP_DROP
    OP_TXOUTPUTCOUNT OP_TXINPUTCOUNT <2> OP_ADD OP_NUMEQUALVERIFY
    ${sameStateNumber(16, 8)}
    ${sameStateBytes(32, 32)}
    ${sameStateBytes(64, 32)}
  OP_ELSE
    <2> OP_NUMEQUALVERIFY
    OP_TXOUTPUTCOUNT OP_TXINPUTCOUNT <3> OP_ADD OP_NUMEQUALVERIFY
    ${stateNumber("input", 16, 8)} OP_1ADD
    ${stateNumber("output", 16, 8)} OP_NUMEQUALVERIFY
    ${stateSlice("input", 32, 32)} ${stateSlice("output", 32, 32)} OP_EQUAL OP_NOT OP_VERIFY
    ${stateSlice("input", 64, 32)} ${stateSlice("output", 64, 32)} OP_EQUAL OP_NOT OP_VERIFY
    OP_TXOUTPUTCOUNT OP_1SUB OP_OUTPUTVALUE OP_0 OP_NUMEQUALVERIFY
    ${tokenlessOutput("OP_TXOUTPUTCOUNT OP_1SUB")}
  OP_ENDIF
  ${stateSlice("input", 96, 32)} ${stateSlice("output", 96, 32)} OP_EQUAL OP_NOT OP_VERIFY
  OP_TXINPUTCOUNT OP_OUTPUTVALUE OP_DUP OP_0 OP_GREATERTHAN OP_VERIFY
  ${tokenlessOutput("OP_TXINPUTCOUNT")}
  ${minerFeeAssembly()} OP_ADD
  <0> OP_UTXOVALUE <0> OP_OUTPUTVALUE OP_SUB
  OP_NUMEQUALVERIFY
  OP_TXINPUTCOUNT OP_1ADD OP_OUTPUTVALUE OP_0 OP_NUMEQUALVERIFY
  ${tokenlessOutput("OP_TXINPUTCOUNT OP_1ADD")}
OP_ENDIF
OP_1`, "local-word value settlement");
}

function localWordEdgeRootAssembly(outputIndex: number | string, leaf: string): string {
  const pathWord = (level: number): string => `${outputIndexAssembly(outputIndex)} OP_OUTPUTBYTECODE
<${LOCAL_WORD_EDGE_PATH_OFFSET + level * 32}> OP_SPLIT OP_NIP <32> OP_SPLIT OP_DROP`;
  return `${stateNumber("input", 16, 8)} OP_TOALTSTACK
${leaf}
${Array.from({ length: EDGE_HISTORY_DEPTH }, (_, level) => `${pathWord(level)}
OP_FROMALTSTACK OP_DUP OP_TOALTSTACK
<${2 ** level}> OP_DIV <2> OP_MOD
OP_IF OP_SWAP OP_ENDIF OP_CAT OP_SHA256`).join("\n")}
OP_FROMALTSTACK OP_DROP`;
}

/**
 * Public depth-32 creation-edge append. The OP_RETURN carries only the
 * canonical public edge, its sequential index, and the shared Merkle path.
 * One role verifies both the old empty leaf and the new edge against PAA2.
 */
export function compileLocalWordEdgeAppendGate(
  reader?: LocalWordProofReader,
): Uint8Array {
  const header = Uint8Array.of(
    0x6a,
    0x4d,
    LOCAL_WORD_EDGE_DATA_PAYLOAD_BYTES & 0xff,
    LOCAL_WORD_EDGE_DATA_PAYLOAD_BYTES >>> 8,
    ...new TextEncoder().encode("SKEG"),
    1,
    0,
    0,
    0,
  );
  const zero32 = new Uint8Array(32);
  const append = (outputIndex: string, countCheck: string): string => `
${countCheck}
${outputIndexAssembly(outputIndex)} OP_OUTPUTBYTECODE
OP_SIZE <${LOCAL_WORD_EDGE_DATA_LOCKING_BYTES}> OP_NUMEQUALVERIFY
OP_DUP <12> OP_SPLIT OP_DROP <0x${hex(header)}> OP_EQUALVERIFY
OP_DUP <${LOCAL_WORD_EDGE_INDEX_OFFSET}> OP_SPLIT OP_NIP <8> OP_SPLIT OP_DROP
OP_DUP <4> OP_SPLIT OP_DROP <0x00000000> OP_EQUALVERIFY
${stateSlice("input", 16, 8)} OP_EQUALVERIFY
<${LOCAL_WORD_EDGE_OFFSET}> OP_SPLIT OP_NIP <32> OP_SPLIT OP_DROP
OP_DUP <0x${hex(zero32)}> OP_EQUAL OP_NOT OP_VERIFY OP_DROP
${stateNumber("input", 16, 8)} OP_1ADD
${stateNumber("output", 16, 8)} OP_NUMEQUALVERIFY
${stateSlice("input", 32, 32)} ${stateSlice("output", 32, 32)} OP_EQUAL OP_NOT OP_VERIFY
${localWordEdgeRootAssembly(outputIndex, `<0x${hex(zero32)}>`)}
${stateSlice("input", 64, 32)} OP_EQUALVERIFY
${localWordEdgeRootAssembly(outputIndex, edgeFromOutputAssembly(outputIndex))}
${stateSlice("output", 64, 32)} OP_EQUALVERIFY`;
  return compile(`OP_DROP
${proofProfileAssembly(reader)}
OP_DUP OP_1 OP_NUMEQUAL
OP_IF
  OP_DROP
  OP_TXOUTPUTCOUNT OP_TXINPUTCOUNT <2> OP_ADD OP_NUMEQUALVERIFY
  ${sameStateFieldAssembly(16, 8)}
  ${sameStateFieldAssembly(32, 32)}
  ${sameStateFieldAssembly(64, 32)}
OP_ELSE
  OP_DUP OP_0 OP_NUMEQUAL
  OP_IF
    OP_DROP
    ${append("OP_TXOUTPUTCOUNT OP_1SUB", "OP_TXOUTPUTCOUNT OP_TXINPUTCOUNT OP_NUMEQUALVERIFY")}
  OP_ELSE
    <2> OP_NUMEQUALVERIFY
    ${append("OP_TXOUTPUTCOUNT OP_1SUB", "OP_TXOUTPUTCOUNT OP_TXINPUTCOUNT <3> OP_ADD OP_NUMEQUALVERIFY")}
  OP_ENDIF
OP_ENDIF
OP_1`, "local-word edge append");
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
  reader?: LocalWordProofReader,
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
${proofProfileAssembly(reader)}
OP_DUP OP_0 OP_NUMEQUAL
OP_IF
  OP_DROP
  OP_TXOUTPUTCOUNT OP_TXINPUTCOUNT OP_NUMEQUALVERIFY
  ${stateSlice("input", 96, 32)} ${stateSlice("output", 96, 32)} OP_EQUALVERIFY
OP_ELSE
  OP_DUP OP_1 OP_NUMEQUAL
  OP_IF
    OP_DROP
    OP_TXOUTPUTCOUNT OP_TXINPUTCOUNT <2> OP_ADD OP_NUMEQUALVERIFY
  OP_ELSE
    <2> OP_NUMEQUALVERIFY
    OP_TXOUTPUTCOUNT OP_TXINPUTCOUNT <3> OP_ADD OP_NUMEQUALVERIFY
  OP_ENDIF
  OP_TXINPUTCOUNT OP_1ADD OP_OUTPUTBYTECODE
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

import {
  cashAssemblyToBin,
  encodeLockingBytecodeP2sh32,
  encodeTransaction,
  hash256,
} from "@bitauth/libauth";
import {
  LOCAL_WORD_PROOF_LENGTH_OFFSET,
  LOCAL_WORD_PROOF_MAX_BYTES,
  LOCAL_WORD_PROOF_VERSION,
} from "../backends/circle/local-word-sealed-proof.ts";
import { concatBytes, readU32BE } from "../pool/bytes.ts";
import {
  V17_BANK_DIGEST_SEEDS,
  V17_BANK_LOCKING_BYTES,
  v17BankDigestBytes,
} from "../construction/v17-bank-identity.ts";
import { CONSENSUS_TX_BYTES, UNLOCKING_MAX_BYTES } from "./envelope.ts";
import { LOCAL_WORD_CARRIER_BUDGETS } from "./local-word-carrier-allocation.ts";
import { V17_PRODUCTION_ROLE_LAYOUT } from "./v17-role-layout.ts";
import {
  V17_AFFINE_SEQUENCE_BASE,
  V17_AFFINE_SEQUENCE_RADIX,
  V17_AFFINE_VALUE_BASE,
  V17_BOOTSTRAP_AFFINE_ALLOCATION,
  v17AffineBoundarySequence,
  v17AffineCarrierBounds,
  v17AffineVerifierValue,
  type V17AffineAllocation,
} from "./v17-affine-allocation.ts";
import { V17_BATCH_LEADER_CELL_BYTES } from
  "../backends/circle/v17-batch-leader-cell.ts";

/** One settlement owner and one complete, role-balanced verifier bank. */
export const LOCAL_WORD_CARRIER_INPUTS = LOCAL_WORD_CARRIER_BUDGETS.length;
export const LOCAL_WORD_PRIMARY_CARRIER_INPUTS =
  V17_PRODUCTION_ROLE_LAYOUT.find(({ kind }) => kind === "proof-header")!.logicalInputIndex;
/**
 * Canonical proof bytes are distributed by verifier work, not duplicated as
 * density ballast. One cumulative table gives every semantic role its exact
 * measured share; all slice lengths scale with the one canonical proof.
 */
export const LOCAL_WORD_CARRIER_BUDGET_QUANTUM = 8;
export const LOCAL_WORD_CARRIER_WEIGHTS = LOCAL_WORD_CARRIER_BUDGETS.map((budget) =>
  Math.ceil(budget / LOCAL_WORD_CARRIER_BUDGET_QUANTUM));
export const LOCAL_WORD_CARRIER_PREFIXES = LOCAL_WORD_CARRIER_WEIGHTS.reduce<readonly number[]>(
  (prefixes, weight) => [...prefixes, prefixes[prefixes.length - 1]! + weight],
  [0],
);
export const LOCAL_WORD_CARRIER_TOTAL_WEIGHT = LOCAL_WORD_CARRIER_WEIGHTS.reduce(
  (sum, weight) => sum + weight,
  0,
);
export const LOCAL_WORD_CARRIER_MIN_PROOF_BYTES =
  V17_BOOTSTRAP_AFFINE_ALLOCATION.minimumProofBytes;
export const LOCAL_WORD_CARRIER_VALUE_BASE = V17_AFFINE_VALUE_BASE;
export const LOCAL_WORD_CARRIER_JUMP_WIDTH = 256;
export const LOCAL_WORD_CARRIER_JUMP_ENTRIES = Math.ceil(
  LOCAL_WORD_CARRIER_TOTAL_WEIGHT / LOCAL_WORD_CARRIER_JUMP_WIDTH,
);
export const LOCAL_WORD_CARRIER_SEQUENCE_PAYLOAD_BASE = V17_AFFINE_SEQUENCE_BASE;
export const LOCAL_WORD_CARRIER_ELASTIC_SCALE =
  V17_BOOTSTRAP_AFFINE_ALLOCATION.elasticScaleUnits;
export const LOCAL_WORD_CARRIER_SEQUENCE_RADIX = V17_AFFINE_SEQUENCE_RADIX;
export const LOCAL_WORD_BOOTSTRAP_ALLOCATION = V17_BOOTSTRAP_AFFINE_ALLOCATION;
if (LOCAL_WORD_CARRIER_PREFIXES.length !== LOCAL_WORD_CARRIER_INPUTS + 1 ||
  LOCAL_WORD_CARRIER_INPUTS < LOCAL_WORD_PRIMARY_CARRIER_INPUTS) {
  throw new Error("local-word carrier budget geometry");
}
export const LOCAL_WORD_VERIFIER_BANK_ROLES = LOCAL_WORD_CARRIER_INPUTS - 1;
export const LOCAL_WORD_P2SH32_LOCKING_BYTES = V17_BANK_LOCKING_BYTES;
export const LOCAL_WORD_VERIFIER_BANK_SEEDS = V17_BANK_DIGEST_SEEDS;

export type LocalWordVerifierBankDigests = readonly [Uint8Array, Uint8Array, Uint8Array];

export type LocalWordVerifierBankInput = {
  readonly lockingBytecode: Uint8Array;
  readonly valueSatoshis: bigint;
  readonly sequenceNumber: number;
};

export type LocalWordProofCarrier = {
  readonly index: number;
  readonly start: number;
  readonly end: number;
  readonly proofLength: number;
  readonly budget: number;
  readonly weight: number;
  readonly chunk: Uint8Array;
  readonly unlockingBytecode: Uint8Array;
};

export type LocalWordCarrierLocation = {
  readonly carrierIndex: number;
  readonly chunkOffset: number;
  readonly chunkLength: number;
};

export const LOCAL_WORD_BATCH_LEADER_ROLE_ID = "batch-link-query:0";
const localWordBatchLeaderInputIndex = V17_PRODUCTION_ROLE_LAYOUT.find(
  ({ id }) => id === LOCAL_WORD_BATCH_LEADER_ROLE_ID,
)?.logicalInputIndex;
if (localWordBatchLeaderInputIndex !== 2) {
  throw new Error("local-word batch leader input placement");
}
export const LOCAL_WORD_BATCH_LEADER_INPUT_INDEX: number = localWordBatchLeaderInputIndex;

function equal(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((byte, index) => byte === right[index]);
}

function pushedData2(data: Uint8Array): Uint8Array {
  if (data.length < 1 || data.length > 0xffff) throw new Error("local-word carrier element width");
  return concatBytes(Uint8Array.of(0x4d, data.length & 0xff, data.length >>> 8), data);
}

function pushedCanonical(data: Uint8Array): Uint8Array {
  if (data.length < 1 || data.length > 0xffff) throw new Error("local-word carrier element width");
  if (data.length <= 75) return concatBytes(Uint8Array.of(data.length), data);
  if (data.length <= 0xff) return concatBytes(Uint8Array.of(0x4c, data.length), data);
  return pushedData2(data);
}

/** Exact standard product layout: one proof slice followed by its P2SH32 redeem. */
export function encodeLocalWordP2shCarrierUnlocking(
  chunk: Uint8Array,
  redeem: Uint8Array,
): Uint8Array {
  if (chunk.length < 256 || redeem.length < 1 || redeem.length > UNLOCKING_MAX_BYTES) {
    throw new Error("local-word P2SH carrier element width");
  }
  const unlockingBytecode = concatBytes(pushedData2(chunk), pushedCanonical(redeem));
  if (unlockingBytecode.length > UNLOCKING_MAX_BYTES) {
    throw new Error("local-word P2SH carrier unlocking limit");
  }
  return unlockingBytecode;
}

/** Query-zero transport: proof slice, one authenticated 216-byte cell, redeem. */
export function encodeLocalWordP2shBatchLeaderUnlocking(
  chunk: Uint8Array,
  cell: Uint8Array,
  redeem: Uint8Array,
): Uint8Array {
  if (chunk.length < 256 || cell.length !== V17_BATCH_LEADER_CELL_BYTES ||
    redeem.length < 256 || redeem.length > UNLOCKING_MAX_BYTES) {
    throw new Error("local-word batch leader element width");
  }
  const unlockingBytecode = concatBytes(
    encodeLocalWordBatchLeaderUnlockingPrefix(chunk, cell),
    pushedCanonical(redeem),
  );
  if (unlockingBytecode.length > UNLOCKING_MAX_BYTES) {
    throw new Error("local-word batch leader unlocking limit");
  }
  return unlockingBytecode;
}

/** The exact two-item unlocking prefix shared by sizing and materialization. */
export function encodeLocalWordBatchLeaderUnlockingPrefix(
  chunk: Uint8Array,
  cell: Uint8Array,
): Uint8Array {
  if (chunk.length < 256 || cell.length !== V17_BATCH_LEADER_CELL_BYTES) {
    throw new Error("local-word batch leader prefix width");
  }
  return concatBytes(pushedData2(chunk), pushedCanonical(cell));
}

/** Preserve one persistent verifier carrier at its active input/output index. */
function localWordCarrierSelfRolloverAssembly(): string {
  // INT-001 and TOK-005: use the lane's existing three-field tokenless idiom.
  return `OP_INPUTINDEX OP_UTXOBYTECODE
OP_INPUTINDEX OP_OUTPUTBYTECODE OP_EQUALVERIFY
OP_INPUTINDEX OP_UTXOVALUE
OP_INPUTINDEX OP_OUTPUTVALUE OP_NUMEQUALVERIFY
OP_INPUTINDEX OP_UTXOTOKENCATEGORY OP_0 OP_EQUALVERIFY
OP_INPUTINDEX OP_UTXOTOKENCOMMITMENT OP_0 OP_EQUALVERIFY
OP_INPUTINDEX OP_UTXOTOKENAMOUNT OP_0 OP_NUMEQUALVERIFY
OP_INPUTINDEX OP_OUTPUTTOKENCATEGORY OP_0 OP_EQUALVERIFY
OP_INPUTINDEX OP_OUTPUTTOKENCOMMITMENT OP_0 OP_EQUALVERIFY
OP_INPUTINDEX OP_OUTPUTTOKENAMOUNT OP_0 OP_NUMEQUALVERIFY`;
}

function localWordCarrierRedeemBindingAssembly(index: number): string {
  const proofLength = `OP_0 OP_INPUTSEQUENCENUMBER
<${LOCAL_WORD_CARRIER_SEQUENCE_PAYLOAD_BASE}> OP_SUB`;
  const minimum = `<1> OP_UTXOVALUE <${LOCAL_WORD_CARRIER_VALUE_BASE}> OP_SUB`;
  const boundary = (at: number): string => {
    if (at === 0) return "OP_0";
    if (at === LOCAL_WORD_CARRIER_INPUTS) return proofLength;
    return `<${at}> OP_INPUTSEQUENCENUMBER
<${LOCAL_WORD_CARRIER_SEQUENCE_PAYLOAD_BASE}> OP_SUB
OP_DUP <${LOCAL_WORD_CARRIER_SEQUENCE_RADIX}> OP_MOD
OP_SWAP <${LOCAL_WORD_CARRIER_SEQUENCE_RADIX}> OP_DIV
${proofLength} ${minimum} OP_SUB
OP_ROT OP_MUL <${LOCAL_WORD_CARRIER_ELASTIC_SCALE}> OP_DIV OP_ADD`;
  };
  return `OP_INPUTINDEX <${index}> OP_NUMEQUALVERIFY
${localWordCarrierSelfRolloverAssembly()}
OP_SIZE OP_TOALTSTACK
${minimum}
${proofLength}
OP_2DUP OP_SWAP OP_GREATERTHANOREQUAL OP_VERIFY
OP_DUP <${LOCAL_WORD_PROOF_MAX_BYTES}> OP_LESSTHANOREQUAL OP_VERIFY
OP_2DROP
${boundary(index + 1)}
${boundary(index)} OP_SUB
OP_FROMALTSTACK OP_NUMEQUALVERIFY`;
}

/**
 * Bind one verifier redeem to its exact index and canonical dynamic slice.
 * The proof length is committed by input zero's sequence, so verifier locks
 * remain stable across every canonical proof length. BCH P2SH clean-stack
 * enforcement already rejects any extra unlocking-stack item.
 */
export function compileLocalWordCarrierRedeem(args: {
  readonly index: number;
  readonly verifier: Uint8Array;
}): Uint8Array {
  if (!Number.isInteger(args.index) || args.index < 0 || args.index >= LOCAL_WORD_CARRIER_INPUTS ||
    args.verifier.length < 1 || args.verifier.length > UNLOCKING_MAX_BYTES) {
    throw new Error("local-word carrier redeem binding");
  }
  const prefix = cashAssemblyToBin(localWordCarrierRedeemBindingAssembly(args.index));
  if (typeof prefix === "string") throw new Error(`local-word carrier redeem binding: ${prefix}`);
  const redeem = concatBytes(prefix, args.verifier);
  if (redeem.length > UNLOCKING_MAX_BYTES) {
    throw new Error(`local-word carrier redeem limit ${redeem.length}/${UNLOCKING_MAX_BYTES}`);
  }
  return redeem;
}

/**
 * Query-zero carrier binding. The unlocking bytecode itself is miner-checked
 * as exactly PUSHDATA2(chunk) || PUSHDATA1(216-byte cell) || canonical redeem.
 * The common carrier binding then measures the original proof slice, leaving
 * `cell, chunk` for the verifier's initial OP_DROP.
 */
export function compileLocalWordBatchLeaderCarrierRedeem(args: {
  readonly index: number;
  readonly verifier: Uint8Array;
}): Uint8Array {
  if (args.index !== LOCAL_WORD_BATCH_LEADER_INPUT_INDEX ||
    args.verifier.length < 1 || args.verifier.length > UNLOCKING_MAX_BYTES) {
    throw new Error("local-word batch leader redeem binding");
  }
  const canonicalUnlocking = `OP_INPUTINDEX OP_INPUTBYTECODE
<1> OP_SPLIT OP_SWAP <0x4d> OP_EQUALVERIFY
<2> OP_SPLIT OP_SWAP OP_BIN2NUM
OP_DUP <256> OP_GREATERTHANOREQUAL OP_VERIFY
OP_DUP <${UNLOCKING_MAX_BYTES}> OP_LESSTHANOREQUAL OP_VERIFY
OP_SPLIT OP_SWAP <3> OP_PICK OP_EQUALVERIFY
<1> OP_SPLIT OP_SWAP <0x4c> OP_EQUALVERIFY
<1> OP_SPLIT OP_SWAP <0x${V17_BATCH_LEADER_CELL_BYTES.toString(16)}> OP_EQUALVERIFY
<${V17_BATCH_LEADER_CELL_BYTES}> OP_SPLIT OP_SWAP <2> OP_PICK OP_EQUALVERIFY
OP_ACTIVEBYTECODE OP_SIZE <2> OP_NUM2BIN
<0x4d> OP_SWAP OP_CAT OP_SWAP OP_CAT OP_EQUALVERIFY
OP_SWAP`;
  const prefix = cashAssemblyToBin(`${canonicalUnlocking}
${localWordCarrierRedeemBindingAssembly(args.index)}`);
  if (typeof prefix === "string") {
    throw new Error(`local-word batch leader redeem binding: ${prefix}`);
  }
  const redeem = concatBytes(prefix, args.verifier);
  if (redeem.length < 256 || redeem.length > UNLOCKING_MAX_BYTES) {
    throw new Error("local-word batch leader redeem limit");
  }
  return redeem;
}

/**
 * The pool is the only carrier whose proof-slice width varies across profiles.
 * Derive its exact first slice from the canonical header so one covenant lock
 * can select any of the three persistent verifier banks.
 */
export function compileLocalWordPoolCarrierRedeem(verifier: Uint8Array): Uint8Array {
  if (verifier.length < 1 || verifier.length > UNLOCKING_MAX_BYTES) {
    throw new Error("local-word pool carrier redeem binding");
  }
  const proofLength = `OP_0 OP_INPUTSEQUENCENUMBER
<${LOCAL_WORD_CARRIER_SEQUENCE_PAYLOAD_BASE}> OP_SUB`;
  const minimum = `<1> OP_UTXOVALUE <${LOCAL_WORD_CARRIER_VALUE_BASE}> OP_SUB`;
  const firstBoundary = `<1> OP_INPUTSEQUENCENUMBER
<${LOCAL_WORD_CARRIER_SEQUENCE_PAYLOAD_BASE}> OP_SUB
OP_DUP <${LOCAL_WORD_CARRIER_SEQUENCE_RADIX}> OP_MOD
OP_SWAP <${LOCAL_WORD_CARRIER_SEQUENCE_RADIX}> OP_DIV
${proofLength} ${minimum} OP_SUB
OP_ROT OP_MUL <${LOCAL_WORD_CARRIER_ELASTIC_SCALE}> OP_DIV OP_ADD`;
  const prefix = cashAssemblyToBin(`OP_INPUTINDEX OP_0 OP_NUMEQUALVERIFY
OP_SIZE OP_TOALTSTACK
OP_DUP <${LOCAL_WORD_PROOF_LENGTH_OFFSET}> OP_SPLIT OP_NIP
<4> OP_SPLIT OP_DROP OP_REVERSEBYTES OP_BIN2NUM
${minimum}
OP_2DUP OP_GREATERTHANOREQUAL OP_VERIFY
OP_OVER <${LOCAL_WORD_PROOF_MAX_BYTES}> OP_LESSTHANOREQUAL OP_VERIFY
OP_OVER ${proofLength} OP_NUMEQUALVERIFY
OP_2DROP
${firstBoundary}
OP_FROMALTSTACK OP_NUMEQUALVERIFY`);
  if (typeof prefix === "string") throw new Error(`local-word pool carrier redeem binding: ${prefix}`);
  const redeem = concatBytes(prefix, verifier);
  if (redeem.length > UNLOCKING_MAX_BYTES) throw new Error("local-word pool carrier redeem limit");
  return redeem;
}

export function localWordP2sh32Lock(redeem: Uint8Array): Uint8Array {
  const lockingBytecode = encodeLockingBytecodeP2sh32(hash256(redeem));
  if (lockingBytecode.length !== LOCAL_WORD_P2SH32_LOCKING_BYTES) {
    throw new Error("local-word P2SH32 locking width");
  }
  return lockingBytecode;
}

/** Canonical value-neutral metadata value for verifier inputs and outputs. */
export function localWordVerifierCarrierValue(
  index: number,
  allocation: V17AffineAllocation = V17_BOOTSTRAP_AFFINE_ALLOCATION,
): bigint {
  if (!Number.isInteger(index) || index < 1 || index >= LOCAL_WORD_CARRIER_INPUTS) {
    throw new Error("local-word verifier carrier value");
  }
  return v17AffineVerifierValue(allocation, index);
}

const LOCAL_WORD_CARRIER_JUMP_TABLE = Array.from(
  { length: LOCAL_WORD_CARRIER_JUMP_ENTRIES },
  (_, bucket) => {
    const target = bucket * LOCAL_WORD_CARRIER_JUMP_WIDTH + 1;
    const index = LOCAL_WORD_CARRIER_PREFIXES.findIndex((prefix, at) =>
      at > 0 && target <= prefix) - 1;
    if (index < 0 || index >= LOCAL_WORD_CARRIER_INPUTS) {
      throw new Error("local-word carrier jump table");
    }
    return index;
  },
);

/** One direct-lookup entry in each BIP68-disabled carrier sequence. */
export function localWordVerifierCarrierSequence(
  index: number,
  allocation: V17AffineAllocation = V17_BOOTSTRAP_AFFINE_ALLOCATION,
): number {
  if (!Number.isInteger(index) || index < 1 || index >= LOCAL_WORD_CARRIER_INPUTS) {
    throw new Error("local-word verifier carrier sequence");
  }
  return v17AffineBoundarySequence(allocation, index);
}

/** Input-zero sequence commits the canonical proof length with BIP68 disabled. */
export function localWordPoolCarrierSequence(
  proofLength: number,
  allocation: V17AffineAllocation = V17_BOOTSTRAP_AFFINE_ALLOCATION,
): number {
  if (!Number.isSafeInteger(proofLength) || proofLength < allocation.minimumProofBytes ||
    proofLength > allocation.maximumProofBytes) {
    throw new Error("local-word pool carrier sequence");
  }
  return LOCAL_WORD_CARRIER_SEQUENCE_PAYLOAD_BASE + proofLength;
}

/** Commitment to the exact verifier inputs observed by the settlement covenant. */
export function localWordVerifierBankDigestFromInputs(
  profile: 0 | 1 | 2,
  inputs: readonly LocalWordVerifierBankInput[],
): Uint8Array {
  if (inputs.length < LOCAL_WORD_VERIFIER_BANK_ROLES || inputs.some((input) =>
    input.lockingBytecode.length !== LOCAL_WORD_P2SH32_LOCKING_BYTES ||
    input.valueSatoshis < 0n || !Number.isSafeInteger(input.sequenceNumber) ||
    input.sequenceNumber < 0 || input.sequenceNumber > 0xffff_ffff)) {
    throw new Error("local-word verifier bank shape");
  }
  return v17BankDigestBytes(profile, inputs.map((input, local) => ({
    index: local + 1,
    ...input,
  })));
}

/** Construction helper: derive exact verifier inputs from one affine allocation. */
export function localWordVerifierBankDigestFromLockingBytecodes(
  profile: 0 | 1 | 2,
  lockingBytecodes: readonly Uint8Array[],
  allocation: V17AffineAllocation = V17_BOOTSTRAP_AFFINE_ALLOCATION,
): Uint8Array {
  return localWordVerifierBankDigestFromInputs(profile, lockingBytecodes.map((lockingBytecode, local) => ({
    lockingBytecode,
    valueSatoshis: localWordVerifierCarrierValue(local + 1, allocation),
    sequenceNumber: localWordVerifierCarrierSequence(local + 1, allocation),
  })));
}

export function localWordVerifierBankDigestFromRedeems(
  profile: 0 | 1 | 2,
  redeems: readonly Uint8Array[],
  allocation: V17AffineAllocation = V17_BOOTSTRAP_AFFINE_ALLOCATION,
): Uint8Array {
  return localWordVerifierBankDigestFromLockingBytecodes(
    profile, redeems.map(localWordP2sh32Lock), allocation,
  );
}

function validateCanonicalHeader(
  proofBytes: Uint8Array,
  allocation: V17AffineAllocation,
): void {
  if (proofBytes.length < allocation.minimumProofBytes ||
    proofBytes.length > allocation.maximumProofBytes ||
    proofBytes[0] !== 0x53 || proofBytes[1] !== 0x4b || proofBytes[2] !== 0x4c || proofBytes[3] !== 0x57 ||
    proofBytes[4] !== LOCAL_WORD_PROOF_VERSION ||
    readU32BE(proofBytes, LOCAL_WORD_PROOF_LENGTH_OFFSET) !== proofBytes.length) {
    throw new Error("local-word canonical proof header");
  }
}

function carrierBounds(
  proofLength: number,
  index: number,
  allocation: V17AffineAllocation = V17_BOOTSTRAP_AFFINE_ALLOCATION,
): readonly [number, number] {
  if (!Number.isSafeInteger(proofLength) || proofLength < allocation.minimumProofBytes ||
    proofLength > allocation.maximumProofBytes ||
    !Number.isInteger(index) || index < 0 || index >= LOCAL_WORD_CARRIER_INPUTS) {
    throw new Error("local-word carrier bounds");
  }
  return v17AffineCarrierBounds(allocation, proofLength, index);
}

/**
 * The only carrier operation: slice one canonical byte string contiguously.
 * Every byte appears once, in order; no frame is decoded or repacked here.
 */
export function partitionLocalWordProofBytes(
  proofBytes: Uint8Array,
  allocation: V17AffineAllocation = V17_BOOTSTRAP_AFFINE_ALLOCATION,
): LocalWordProofCarrier[] {
  validateCanonicalHeader(proofBytes, allocation);
  const carriers = Array.from({ length: LOCAL_WORD_CARRIER_INPUTS }, (_, index): LocalWordProofCarrier => {
    const [start, end] = carrierBounds(proofBytes.length, index, allocation);
    const chunk = proofBytes.slice(start, end);
    const unlockingBytecode = pushedData2(chunk);
    if (chunk.length < 1 || unlockingBytecode.length > UNLOCKING_MAX_BYTES) {
      throw new Error("local-word carrier unlocking limit");
    }
    return {
      index,
      start,
      end,
      proofLength: proofBytes.length,
      budget: LOCAL_WORD_CARRIER_BUDGETS[index]!,
      weight: LOCAL_WORD_CARRIER_WEIGHTS[index]!,
      chunk,
      unlockingBytecode,
    };
  });
  if (carriers[0]!.start !== 0 || carriers.at(-1)!.end !== proofBytes.length ||
    carriers.some((carrier, index) => index > 0 && carriers[index - 1]!.end !== carrier.start)) {
    throw new Error("local-word carrier coverage");
  }
  return carriers;
}

export function reassembleLocalWordProofBytes(
  carriers: readonly LocalWordProofCarrier[],
  allocation: V17AffineAllocation = V17_BOOTSTRAP_AFFINE_ALLOCATION,
): Uint8Array {
  if (carriers.length !== LOCAL_WORD_CARRIER_INPUTS) throw new Error("local-word carrier count");
  const proofLength = carriers[0]!.proofLength;
  let cursor = 0;
  for (let index = 0; index < carriers.length; index += 1) {
    const carrier = carriers[index]!;
    const [expectedStart, expectedEnd] = carrierBounds(proofLength, index, allocation);
    if (carrier.index !== index || carrier.start !== expectedStart || carrier.end !== expectedEnd ||
      carrier.start !== cursor || carrier.proofLength !== proofLength ||
      carrier.budget !== LOCAL_WORD_CARRIER_BUDGETS[index] ||
      carrier.weight !== LOCAL_WORD_CARRIER_WEIGHTS[index] ||
      carrier.chunk.length !== carrier.end - carrier.start ||
      carrier.unlockingBytecode.length !== carrier.chunk.length + 3 ||
      carrier.unlockingBytecode[0] !== 0x4d ||
      carrier.unlockingBytecode[1] !== (carrier.chunk.length & 0xff) ||
      carrier.unlockingBytecode[2] !== (carrier.chunk.length >>> 8) ||
      !equal(carrier.unlockingBytecode.subarray(3), carrier.chunk)) {
      throw new Error("local-word carrier placement");
    }
    cursor = carrier.end;
  }
  if (cursor !== proofLength) throw new Error("local-word carrier coverage");
  const proofBytes = concatBytes(...carriers.map((carrier) => carrier.chunk));
  validateCanonicalHeader(proofBytes, allocation);
  return proofBytes;
}

/** Locate one canonical byte under the exact role-balanced partition. */
export function locateLocalWordProofByte(
  proofLength: number,
  proofOffset: number,
  allocation: V17AffineAllocation = V17_BOOTSTRAP_AFFINE_ALLOCATION,
): LocalWordCarrierLocation {
  if (!Number.isSafeInteger(proofOffset) || proofOffset < 0 || proofOffset >= proofLength) {
    throw new Error("local-word proof byte location");
  }
  let low = 0;
  let high = LOCAL_WORD_CARRIER_INPUTS - 1;
  while (low < high) {
    const middle = Math.floor((low + high) / 2);
    if (proofOffset < carrierBounds(proofLength, middle, allocation)[1]) high = middle;
    else low = middle + 1;
  }
  const carrierIndex = low;
  const [start, end] = carrierBounds(proofLength, carrierIndex, allocation);
  return { carrierIndex, chunkOffset: proofOffset - start, chunkLength: end - start };
}

export type LocalWordCarrierMeasurement = {
  readonly proofBytes: number;
  readonly carrierInputs: number;
  readonly carrierChunkMin: number;
  readonly carrierChunkMax: number;
  readonly budgetWeight: number;
  readonly unlockingSum: number;
  readonly transactionBytes: number;
  readonly remainingConsensusBytes: number;
};

/** Exact serialization of all proof carriers and one value-neutral refund. */
export function measureLocalWordProofCarriers(
  proofBytes: Uint8Array,
  allocation: V17AffineAllocation = V17_BOOTSTRAP_AFFINE_ALLOCATION,
): LocalWordCarrierMeasurement {
  const carriers = partitionLocalWordProofBytes(proofBytes, allocation);
  const raw = encodeTransaction({
    version: 2,
    locktime: 0,
    inputs: carriers.map((carrier, index) => ({
      outpointTransactionHash: new Uint8Array(32).fill((index + 1) & 0xff),
      outpointIndex: index,
      sequenceNumber: index === 0
        ? localWordPoolCarrierSequence(proofBytes.length, allocation)
        : localWordVerifierCarrierSequence(index, allocation),
      unlockingBytecode: carrier.unlockingBytecode,
    })),
    outputs: [{ lockingBytecode: Uint8Array.of(0x51), valueSatoshis: BigInt(carriers.length) }],
  });
  return {
    proofBytes: proofBytes.length,
    carrierInputs: carriers.length,
    carrierChunkMin: Math.min(...carriers.map((carrier) => carrier.chunk.length)),
    carrierChunkMax: Math.max(...carriers.map((carrier) => carrier.chunk.length)),
    budgetWeight: LOCAL_WORD_CARRIER_TOTAL_WEIGHT,
    unlockingSum: carriers.reduce((sum, carrier) => sum + carrier.unlockingBytecode.length, 0),
    transactionBytes: raw.length,
    remainingConsensusBytes: CONSENSUS_TX_BYTES - raw.length,
  };
}

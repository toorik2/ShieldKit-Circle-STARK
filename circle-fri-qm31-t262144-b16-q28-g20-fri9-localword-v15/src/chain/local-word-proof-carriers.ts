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
import { concatBytes, encodeVmNumber, readU32BE, sha256 } from "../pool/bytes.ts";
import { CONSENSUS_TX_BYTES, UNLOCKING_MAX_BYTES } from "./envelope.ts";
import { LOCAL_WORD_CARRIER_BUDGETS } from "./local-word-carrier-allocation.ts";

/** One settlement owner and one complete, role-balanced verifier bank. */
export const LOCAL_WORD_CARRIER_INPUTS = 168;
export const LOCAL_WORD_PRIMARY_CARRIER_INPUTS = 32;
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
export const LOCAL_WORD_CARRIER_MIN_PROOF_BYTES = LOCAL_WORD_CARRIER_TOTAL_WEIGHT *
  LOCAL_WORD_CARRIER_BUDGET_QUANTUM;
export const LOCAL_WORD_CARRIER_VALUE_BASE = 1_000n;
export const LOCAL_WORD_CARRIER_JUMP_WIDTH = 256;
export const LOCAL_WORD_CARRIER_JUMP_ENTRIES = Math.ceil(
  LOCAL_WORD_CARRIER_TOTAL_WEIGHT / LOCAL_WORD_CARRIER_JUMP_WIDTH,
);
export const LOCAL_WORD_CARRIER_SEQUENCE_PAYLOAD_BASE = 0x8000_0000;
if (LOCAL_WORD_CARRIER_BUDGETS.length !== LOCAL_WORD_CARRIER_INPUTS ||
  LOCAL_WORD_CARRIER_PREFIXES.length !== LOCAL_WORD_CARRIER_INPUTS + 1 ||
  LOCAL_WORD_CARRIER_TOTAL_WEIGHT !== 40_643 ||
  LOCAL_WORD_CARRIER_MIN_PROOF_BYTES !== 325_144) {
  throw new Error("local-word carrier budget geometry");
}
export const LOCAL_WORD_VERIFIER_BANK_ROLES = LOCAL_WORD_CARRIER_INPUTS - 1;
export const LOCAL_WORD_P2SH32_LOCKING_BYTES = 35;
export const LOCAL_WORD_VERIFIER_BANK_SEED = sha256(
  new TextEncoder().encode("ShieldKit/LocalWordVerifierBank/v1"),
);

export type LocalWordVerifierBankDigests = readonly [Uint8Array, Uint8Array, Uint8Array];

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
  const prefix = cashAssemblyToBin(`OP_INPUTINDEX <${args.index}> OP_NUMEQUALVERIFY
OP_SIZE OP_TOALTSTACK
OP_0 OP_INPUTSEQUENCENUMBER <${LOCAL_WORD_CARRIER_SEQUENCE_PAYLOAD_BASE}> OP_SUB
OP_DUP <${LOCAL_WORD_CARRIER_MIN_PROOF_BYTES}> OP_GREATERTHANOREQUAL OP_VERIFY
OP_DUP <${LOCAL_WORD_PROOF_MAX_BYTES}> OP_LESSTHANOREQUAL OP_VERIFY
OP_DUP <${LOCAL_WORD_CARRIER_PREFIXES[args.index + 1]}> OP_MUL
<${LOCAL_WORD_CARRIER_TOTAL_WEIGHT}> OP_DIV
OP_SWAP <${LOCAL_WORD_CARRIER_PREFIXES[args.index]}> OP_MUL
<${LOCAL_WORD_CARRIER_TOTAL_WEIGHT}> OP_DIV OP_SUB
OP_FROMALTSTACK OP_NUMEQUALVERIFY`);
  if (typeof prefix === "string") throw new Error(`local-word carrier redeem binding: ${prefix}`);
  const redeem = concatBytes(prefix, args.verifier);
  if (redeem.length > UNLOCKING_MAX_BYTES) throw new Error("local-word carrier redeem limit");
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
  const prefix = cashAssemblyToBin(`OP_INPUTINDEX OP_0 OP_NUMEQUALVERIFY
OP_SIZE OP_TOALTSTACK
OP_DUP <${LOCAL_WORD_PROOF_LENGTH_OFFSET}> OP_SPLIT OP_NIP
<4> OP_SPLIT OP_DROP OP_REVERSEBYTES OP_BIN2NUM
OP_DUP <${LOCAL_WORD_CARRIER_MIN_PROOF_BYTES}> OP_GREATERTHANOREQUAL OP_VERIFY
OP_DUP <${LOCAL_WORD_PROOF_MAX_BYTES}> OP_LESSTHANOREQUAL OP_VERIFY
OP_DUP OP_0 OP_INPUTSEQUENCENUMBER
<${LOCAL_WORD_CARRIER_SEQUENCE_PAYLOAD_BASE}> OP_SUB OP_NUMEQUALVERIFY
<${LOCAL_WORD_CARRIER_WEIGHTS[0]}> OP_MUL
<${LOCAL_WORD_CARRIER_TOTAL_WEIGHT}> OP_DIV
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

/** Canonical value-neutral metadata value for verifier input/output 1..167. */
export function localWordVerifierCarrierValue(index: number): bigint {
  if (!Number.isInteger(index) || index < 1 || index >= LOCAL_WORD_CARRIER_INPUTS) {
    throw new Error("local-word verifier carrier value");
  }
  return LOCAL_WORD_CARRIER_VALUE_BASE + BigInt(LOCAL_WORD_CARRIER_PREFIXES[index]!);
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
export function localWordVerifierCarrierSequence(index: number): number {
  if (!Number.isInteger(index) || index < 1 || index >= LOCAL_WORD_CARRIER_INPUTS) {
    throw new Error("local-word verifier carrier sequence");
  }
  const payload = LOCAL_WORD_CARRIER_JUMP_TABLE[index - 1] ?? 0;
  return LOCAL_WORD_CARRIER_SEQUENCE_PAYLOAD_BASE + payload;
}

/** Input-zero sequence commits the canonical proof length with BIP68 disabled. */
export function localWordPoolCarrierSequence(proofLength: number): number {
  if (!Number.isSafeInteger(proofLength) || proofLength < LOCAL_WORD_CARRIER_MIN_PROOF_BYTES ||
    proofLength > LOCAL_WORD_PROOF_MAX_BYTES) {
    throw new Error("local-word pool carrier sequence");
  }
  return LOCAL_WORD_CARRIER_SEQUENCE_PAYLOAD_BASE + proofLength;
}

/** Commitment to locks and allocation values for inputs 1..167 in exact order. */
export function localWordVerifierBankDigestFromLockingBytecodes(
  lockingBytecodes: readonly Uint8Array[],
): Uint8Array {
  if (lockingBytecodes.length !== LOCAL_WORD_VERIFIER_BANK_ROLES ||
    lockingBytecodes.some((lockingBytecode) =>
      lockingBytecode.length !== LOCAL_WORD_P2SH32_LOCKING_BYTES)) {
    throw new Error("local-word verifier bank shape");
  }
  return lockingBytecodes.reduce(
    (digest, lockingBytecode, local) => sha256(concatBytes(
      digest,
      lockingBytecode,
      encodeVmNumber(localWordVerifierCarrierValue(local + 1)),
      encodeVmNumber(BigInt(localWordVerifierCarrierSequence(local + 1))),
    )),
    LOCAL_WORD_VERIFIER_BANK_SEED,
  );
}

export function localWordVerifierBankDigestFromRedeems(
  redeems: readonly Uint8Array[],
): Uint8Array {
  return localWordVerifierBankDigestFromLockingBytecodes(redeems.map(localWordP2sh32Lock));
}

function validateCanonicalHeader(proofBytes: Uint8Array): void {
  if (proofBytes.length < LOCAL_WORD_CARRIER_MIN_PROOF_BYTES ||
    proofBytes.length > LOCAL_WORD_PROOF_MAX_BYTES ||
    proofBytes[0] !== 0x53 || proofBytes[1] !== 0x4b || proofBytes[2] !== 0x4c || proofBytes[3] !== 0x57 ||
    proofBytes[4] !== LOCAL_WORD_PROOF_VERSION ||
    readU32BE(proofBytes, LOCAL_WORD_PROOF_LENGTH_OFFSET) !== proofBytes.length) {
    throw new Error("local-word canonical proof header");
  }
}

function carrierBounds(proofLength: number, index: number): readonly [number, number] {
  if (!Number.isSafeInteger(proofLength) || proofLength < LOCAL_WORD_CARRIER_MIN_PROOF_BYTES ||
    !Number.isInteger(index) || index < 0 || index >= LOCAL_WORD_CARRIER_INPUTS) {
    throw new Error("local-word carrier bounds");
  }
  return [
    Math.floor(proofLength * LOCAL_WORD_CARRIER_PREFIXES[index]! /
      LOCAL_WORD_CARRIER_TOTAL_WEIGHT),
    Math.floor(proofLength * LOCAL_WORD_CARRIER_PREFIXES[index + 1]! /
      LOCAL_WORD_CARRIER_TOTAL_WEIGHT),
  ];
}

/**
 * The only carrier operation: slice one canonical byte string contiguously.
 * Every byte appears once, in order; no frame is decoded or repacked here.
 */
export function partitionLocalWordProofBytes(proofBytes: Uint8Array): LocalWordProofCarrier[] {
  validateCanonicalHeader(proofBytes);
  const carriers = Array.from({ length: LOCAL_WORD_CARRIER_INPUTS }, (_, index): LocalWordProofCarrier => {
    const [start, end] = carrierBounds(proofBytes.length, index);
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

export function reassembleLocalWordProofBytes(carriers: readonly LocalWordProofCarrier[]): Uint8Array {
  if (carriers.length !== LOCAL_WORD_CARRIER_INPUTS) throw new Error("local-word carrier count");
  const proofLength = carriers[0]!.proofLength;
  let cursor = 0;
  for (let index = 0; index < carriers.length; index += 1) {
    const carrier = carriers[index]!;
    const [expectedStart, expectedEnd] = carrierBounds(proofLength, index);
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
  validateCanonicalHeader(proofBytes);
  return proofBytes;
}

/** Locate one canonical byte under the exact role-balanced partition. */
export function locateLocalWordProofByte(
  proofLength: number,
  proofOffset: number,
): LocalWordCarrierLocation {
  if (!Number.isSafeInteger(proofOffset) || proofOffset < 0 || proofOffset >= proofLength) {
    throw new Error("local-word proof byte location");
  }
  let low = 0;
  let high = LOCAL_WORD_CARRIER_INPUTS - 1;
  while (low < high) {
    const middle = Math.floor((low + high) / 2);
    if (proofOffset < carrierBounds(proofLength, middle)[1]) high = middle;
    else low = middle + 1;
  }
  const carrierIndex = low;
  const [start, end] = carrierBounds(proofLength, carrierIndex);
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
export function measureLocalWordProofCarriers(proofBytes: Uint8Array): LocalWordCarrierMeasurement {
  const carriers = partitionLocalWordProofBytes(proofBytes);
  const raw = encodeTransaction({
    version: 2,
    locktime: 0,
    inputs: carriers.map((carrier, index) => ({
      outpointTransactionHash: new Uint8Array(32).fill((index + 1) & 0xff),
      outpointIndex: index,
      sequenceNumber: index === 0
        ? localWordPoolCarrierSequence(proofBytes.length)
        : localWordVerifierCarrierSequence(index),
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

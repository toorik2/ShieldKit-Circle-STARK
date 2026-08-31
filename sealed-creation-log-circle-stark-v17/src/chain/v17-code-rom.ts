import { createHash } from "node:crypto";
import {
  binToHex,
  cashAssemblyToBin,
  encodeLockingBytecodeP2sh32,
  hash256,
} from "@bitauth/libauth";

/** BCHN v29 / May-2026 constants (bch-constants source 864c53ee3492). */
export const V17_MAX_SCRIPT_BYTES = 10_000 as const;
export const V17_MAX_SCRIPT_ELEMENT_BYTES = 10_000 as const;
export const V17_MAX_STACK_ITEMS = 1_000 as const;
export const V17_MAX_CONTROL_DEPTH = 100 as const;
export const V17_MAX_FUNCTION_ID_BYTES = 7 as const;
export const V17_ROM_P2SH32_LOCK_BYTES = 35 as const;
export const V17_ROM_PAGE_MAGIC = Uint8Array.of(0x53, 0x4b, 0x52, 0x31); // SKR1
export const V17_ROM_PAGE_VERSION = 1 as const;
export const V17_ROM_VALUE_BASE_SATOSHIS = 1_000n;
export const V17_ROM_SEQUENCE_NUMBER = 0xffff_fffe;

const PAGE_HEADER_BYTES = 9;
const PAGE_DIRECTORY_ENTRY_BYTES = 44;

export type V17RomEntryInput = {
  readonly functionId: Uint8Array;
  readonly body: Uint8Array;
};

export type V17RomEntry = V17RomEntryInput & {
  readonly functionIdHex: string;
  readonly bodySha256Hex: string;
  readonly bodyOffset: number;
  readonly bodyLength: number;
};

export type V17RomPage = {
  readonly schema: "ShieldKit/V17RomPage/v1";
  readonly pageIndex: number;
  readonly inputIndex: number;
  readonly outputIndex: number;
  readonly valueSatoshis: bigint;
  readonly sequenceNumber: number;
  readonly entries: readonly V17RomEntry[];
  readonly payload: Uint8Array;
  readonly payloadSha256Hex: string;
  readonly redeemBytecode: Uint8Array;
  readonly lockingBytecode: Uint8Array;
  readonly unlockingBytecode: Uint8Array;
  readonly serializedInputBytes: number;
  readonly serializedOutputBytes: number;
};

function concat(...parts: readonly Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function u16be(value: number): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff) {
    throw new Error("v17 ROM u16");
  }
  return Uint8Array.of(value >>> 8, value & 0xff);
}

function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function compile(assembly: string, label: string): Uint8Array {
  const result = cashAssemblyToBin(assembly);
  if (typeof result === "string") throw new Error(`v17 ROM ${label}: ${result}`);
  return result;
}

function equal(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((byte, index) => byte === right[index]);
}

/** Canonical push encoding used by every v17 ROM witness and worker import. */
export function encodeV17CanonicalPush(data: Uint8Array): Uint8Array {
  if (data.length > V17_MAX_SCRIPT_ELEMENT_BYTES) {
    throw new Error("v17 ROM element exceeds 10000 bytes");
  }
  if (data.length === 0) return Uint8Array.of(0x00);
  if (data.length <= 75) return concat(Uint8Array.of(data.length), data);
  if (data.length <= 0xff) return concat(Uint8Array.of(0x4c, data.length), data);
  return concat(Uint8Array.of(0x4d, data.length & 0xff, data.length >>> 8), data);
}

export function v17CompactUintBytes(value: number): number {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error("v17 compact uint");
  if (value <= 0xfc) return 1;
  if (value <= 0xffff) return 3;
  if (value <= 0xffff_ffff) return 5;
  return 9;
}

export function v17SerializedInputBytes(unlockingBytecode: Uint8Array): number {
  return 32 + 4 + v17CompactUintBytes(unlockingBytecode.length) + unlockingBytecode.length + 4;
}

export function v17SerializedOutputBytes(lockingBytecode: Uint8Array): number {
  return 8 + v17CompactUintBytes(lockingBytecode.length) + lockingBytecode.length;
}

function normalizeEntries(entries: readonly V17RomEntryInput[]): readonly V17RomEntryInput[] {
  if (entries.length < 1 || entries.length > V17_MAX_STACK_ITEMS) {
    throw new Error("v17 ROM page entry count");
  }
  const normalized = entries.map((entry) => ({
    functionId: entry.functionId.slice(),
    body: entry.body.slice(),
  })).sort((left, right) => {
    // Function identifiers come from stable semantic occurrence anchors. Keep
    // page layout in that order so a same-size, allocation-specialized body
    // cannot move unrelated functions merely because its hash crossed a
    // lexical boundary. Bodies remain byte-authenticated below.
    const widthOrder = left.functionId.length - right.functionId.length;
    const identifierOrder = widthOrder !== 0
      ? widthOrder
      : Buffer.compare(left.functionId, right.functionId);
    return identifierOrder !== 0 ? identifierOrder : Buffer.compare(left.body, right.body);
  });
  const identifiers = new Set<string>();
  const bodies = new Set<string>();
  for (const entry of normalized) {
    if (entry.functionId.length < 1 || entry.functionId.length > V17_MAX_FUNCTION_ID_BYTES) {
      throw new Error("v17 ROM function identifier width");
    }
    if (entry.functionId[0] === 0) {
      throw new Error("v17 ROM function identifier must be minimal positive unsigned big-endian");
    }
    if (entry.body.length > V17_MAX_SCRIPT_BYTES) throw new Error("v17 ROM function body width");
    const identifierHex = binToHex(entry.functionId);
    const bodyHex = binToHex(entry.body);
    if (identifiers.has(identifierHex)) throw new Error(`v17 ROM duplicate function identifier ${identifierHex}`);
    if (bodies.has(bodyHex)) throw new Error("v17 ROM duplicate exact body");
    identifiers.add(identifierHex);
    bodies.add(bodyHex);
  }
  return normalized;
}

function encodePayload(pageIndex: number, rawEntries: readonly V17RomEntryInput[]): {
  readonly payload: Uint8Array;
  readonly entries: readonly V17RomEntry[];
} {
  if (!Number.isSafeInteger(pageIndex) || pageIndex < 0 || pageIndex > 0xffff) {
    throw new Error("v17 ROM page index");
  }
  const entries = normalizeEntries(rawEntries);
  let bodyOffset = PAGE_HEADER_BYTES + entries.length * PAGE_DIRECTORY_ENTRY_BYTES;
  const placed: V17RomEntry[] = entries.map((entry) => {
    if (bodyOffset > 0xffff || entry.body.length > 0xffff || bodyOffset + entry.body.length > 0xffff) {
      throw new Error("v17 ROM payload offset");
    }
    const placedEntry: V17RomEntry = {
      ...entry,
      functionIdHex: binToHex(entry.functionId),
      bodySha256Hex: sha256Hex(entry.body),
      bodyOffset,
      bodyLength: entry.body.length,
    };
    bodyOffset += entry.body.length;
    return placedEntry;
  });
  const directory = placed.map((entry) => {
    const paddedIdentifier = new Uint8Array(V17_MAX_FUNCTION_ID_BYTES);
    paddedIdentifier.set(entry.functionId);
    return concat(
      Uint8Array.of(entry.functionId.length),
      paddedIdentifier,
      new Uint8Array(Buffer.from(entry.bodySha256Hex, "hex")),
      u16be(entry.bodyOffset),
      u16be(entry.bodyLength),
    );
  });
  const payload = concat(
    V17_ROM_PAGE_MAGIC,
    Uint8Array.of(V17_ROM_PAGE_VERSION),
    u16be(pageIndex),
    u16be(placed.length),
    ...directory,
    ...placed.map((entry) => entry.body),
  );
  if (payload.length > V17_MAX_SCRIPT_ELEMENT_BYTES) throw new Error("v17 ROM payload limit");
  return { payload, entries: placed };
}

function compilePageRedeem(args: {
  readonly inputIndex: number;
  readonly outputIndex: number;
  readonly valueSatoshis: bigint;
  readonly sequenceNumber: number;
  readonly payloadSha256Hex: string;
}): Uint8Array {
  const { inputIndex, outputIndex, valueSatoshis, sequenceNumber, payloadSha256Hex } = args;
  if (!Number.isSafeInteger(inputIndex) || inputIndex < 0 ||
    !Number.isSafeInteger(outputIndex) || outputIndex < 0 ||
    valueSatoshis < 0n || valueSatoshis > 0x7fff_ffff_ffff_ffffn ||
    !Number.isSafeInteger(sequenceNumber) || sequenceNumber < 0 || sequenceNumber > 0xffff_ffff ||
    !/^[0-9a-f]{64}$/.test(payloadSha256Hex)) {
    throw new Error("v17 ROM redeem binding");
  }
  // INT-001 and LIM-001/LIM-005/LIM-006 from the pinned CashScript Next briefing.
  return compile(`OP_INPUTINDEX <${inputIndex}> OP_NUMEQUALVERIFY
OP_DUP OP_SHA256 <0x${payloadSha256Hex}> OP_EQUALVERIFY OP_DROP
<${inputIndex}> OP_UTXOBYTECODE <${outputIndex}> OP_OUTPUTBYTECODE OP_EQUALVERIFY
<${inputIndex}> OP_UTXOVALUE <${valueSatoshis}> OP_NUMEQUALVERIFY
<${outputIndex}> OP_OUTPUTVALUE <${valueSatoshis}> OP_NUMEQUALVERIFY
<${inputIndex}> OP_INPUTSEQUENCENUMBER <${sequenceNumber}> OP_NUMEQUALVERIFY
<${inputIndex}> OP_UTXOTOKENCATEGORY OP_0 OP_EQUALVERIFY
<${inputIndex}> OP_UTXOTOKENCOMMITMENT OP_0 OP_EQUALVERIFY
<${inputIndex}> OP_UTXOTOKENAMOUNT OP_0 OP_NUMEQUALVERIFY
<${outputIndex}> OP_OUTPUTTOKENCATEGORY OP_0 OP_EQUALVERIFY
<${outputIndex}> OP_OUTPUTTOKENCOMMITMENT OP_0 OP_EQUALVERIFY
<${outputIndex}> OP_OUTPUTTOKENAMOUNT OP_0 OP_NUMEQUALVERIFY
OP_1`, "page redeem");
}

/** Build one exact authenticated, tokenless, value-neutral P2SH32 ROM rollover. */
export function createV17RomPage(args: {
  readonly pageIndex: number;
  readonly inputIndex: number;
  readonly outputIndex: number;
  readonly entries: readonly V17RomEntryInput[];
  readonly valueSatoshis?: bigint;
  readonly sequenceNumber?: number;
}): V17RomPage {
  const valueSatoshis = args.valueSatoshis ?? V17_ROM_VALUE_BASE_SATOSHIS + BigInt(args.pageIndex);
  const sequenceNumber = args.sequenceNumber ?? V17_ROM_SEQUENCE_NUMBER;
  const encoded = encodePayload(args.pageIndex, args.entries);
  const payloadSha256Hex = sha256Hex(encoded.payload);
  const redeemBytecode = compilePageRedeem({
    inputIndex: args.inputIndex,
    outputIndex: args.outputIndex,
    valueSatoshis,
    sequenceNumber,
    payloadSha256Hex,
  });
  if (redeemBytecode.length > V17_MAX_SCRIPT_BYTES) throw new Error("v17 ROM redeem limit");
  const lockingBytecode = encodeLockingBytecodeP2sh32(hash256(redeemBytecode));
  if (lockingBytecode.length !== V17_ROM_P2SH32_LOCK_BYTES) throw new Error("v17 ROM P2SH32 lock width");
  const unlockingBytecode = concat(
    encodeV17CanonicalPush(encoded.payload),
    encodeV17CanonicalPush(redeemBytecode),
  );
  if (unlockingBytecode.length > V17_MAX_SCRIPT_BYTES) throw new Error("v17 ROM unlocking limit");
  return {
    schema: "ShieldKit/V17RomPage/v1",
    pageIndex: args.pageIndex,
    inputIndex: args.inputIndex,
    outputIndex: args.outputIndex,
    valueSatoshis,
    sequenceNumber,
    entries: encoded.entries,
    payload: encoded.payload,
    payloadSha256Hex,
    redeemBytecode,
    lockingBytecode,
    unlockingBytecode,
    serializedInputBytes: v17SerializedInputBytes(unlockingBytecode),
    serializedOutputBytes: v17SerializedOutputBytes(lockingBytecode),
  };
}

/** Recompute every byte and reject any descriptor/payload/redeem/lock drift. */
export function validateV17RomPage(page: V17RomPage): V17RomPage {
  const rebuilt = createV17RomPage({
    pageIndex: page.pageIndex,
    inputIndex: page.inputIndex,
    outputIndex: page.outputIndex,
    valueSatoshis: page.valueSatoshis,
    sequenceNumber: page.sequenceNumber,
    entries: page.entries,
  });
  const scalarKeys = [
    "schema", "pageIndex", "inputIndex", "outputIndex", "valueSatoshis", "sequenceNumber",
    "payloadSha256Hex", "serializedInputBytes", "serializedOutputBytes",
  ] as const;
  for (const key of scalarKeys) {
    if (rebuilt[key] !== page[key]) throw new Error(`v17 ROM page ${key}`);
  }
  for (const key of ["payload", "redeemBytecode", "lockingBytecode", "unlockingBytecode"] as const) {
    if (!equal(rebuilt[key], page[key])) throw new Error(`v17 ROM page ${key}`);
  }
  if (rebuilt.entries.length !== page.entries.length || rebuilt.entries.some((entry, index) => {
    const actual = page.entries[index];
    return actual === undefined || entry.functionIdHex !== actual.functionIdHex ||
      entry.bodySha256Hex !== actual.bodySha256Hex || entry.bodyOffset !== actual.bodyOffset ||
      entry.bodyLength !== actual.bodyLength || !equal(entry.body, actual.body) ||
      !equal(entry.functionId, actual.functionId);
  })) throw new Error("v17 ROM page entries");
  return page;
}

/**
 * Load one authenticated page body from the sibling input bytecode. The ROM
 * input's own P2SH32 redeem authenticates the payload; this loader only slices
 * the already-committed canonical witness.
 */
export function compileV17RomBodyLoader(page: V17RomPage, functionIdHex: string): Uint8Array {
  validateV17RomPage(page);
  const entry = page.entries.find((candidate) => candidate.functionIdHex === functionIdHex);
  if (entry === undefined) throw new Error(`v17 ROM missing function ${functionIdHex}`);
  const payloadPushPrefixBytes = encodeV17CanonicalPush(page.payload).length - page.payload.length;
  const absoluteBodyOffset = payloadPushPrefixBytes + entry.bodyOffset;
  return compile(`<${page.inputIndex}> OP_INPUTBYTECODE
<${absoluteBodyOffset}> OP_SPLIT OP_NIP
<${entry.bodyLength}> OP_SPLIT OP_DROP`, "body loader");
}

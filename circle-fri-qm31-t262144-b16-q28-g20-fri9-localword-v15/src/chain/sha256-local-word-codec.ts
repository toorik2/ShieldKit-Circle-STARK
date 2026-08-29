import { sha256 } from "../pool/bytes.ts";
import {
  LOCAL_WORD_GLOBAL_INTERACTION_COLUMNS,
  LOCAL_WORD_INTERACTION_GROUPS,
  validateLocalWordInteractionLayout,
} from "../backends/circle/local-word-oracle-layout.ts";
import type {
  LocalShaCopyAlias,
  LocalShaOperationKind,
  LocalShaProgram,
  LocalShaRow,
  LocalShaWordAlias,
} from "./sha256-local-word-machine.ts";
import {
  LOCAL_SHA_LOOKUP_TABLE_ROWS,
  LOCAL_SHA_ORIGINAL_COLUMNS,
  localShaGeometry,
} from "./sha256-local-word-machine.ts";
import {
  LOCAL_SHA_WORD_INTERACTION_QM31_COLUMNS,
  LOCAL_SHA_WORD_PREPROCESSED_COLUMNS,
} from "./sha256-local-word-permutation.ts";
import type {
  PoolLocalShaGraph,
  PoolLocalShaPublicField,
} from "./pool-relation-local-word-machine.ts";

const MAGIC = [0x53, 0x4c, 0x57, 0x50] as const; // SLWP
const VERSION = 2;
const LEGACY_VERSION = 1;

const CONSTRUCTION_MAGIC = [0x50, 0x4c, 0x57, 0x43] as const; // PLWC
/** Version 15 is the sealed local-word relation used by proof format 15. */
export const LOCAL_WORD_RELATION_CONSTRUCTION_VERSION = 15;

const PROFILE_ID: Readonly<Record<PoolLocalShaGraph["profile"], number>> = {
  deposit: 0,
  "withdraw-full": 1,
  "withdraw-change": 2,
};

const PUBLIC_FIELD_ID: Readonly<Record<PoolLocalShaPublicField, number>> = {
  // IDs 0..2 belonged to public amount tags and note identity in the
  // superseded layout. They stay retired rather than being silently reused.
  "deposit-amount": 3,
  "withdraw-amount": 4,
  "pool-instance-id": 5,
  nullifier: 6,
  "old-note-root": 7,
  "new-note-root": 8,
};

const OPERATION_ID: Readonly<Record<LocalShaOperationKind, number>> = {
  input: 0,
  mask: 1,
  constant: 2,
  rotr: 3,
  xor: 4,
  and: 5,
  add: 6,
  nonzero: 7,
};

const ID_OPERATION = Object.fromEntries(
  Object.entries(OPERATION_ID).map(([operation, id]) => [id, operation]),
) as Readonly<Record<number, LocalShaOperationKind>>;

function u32(out: number[], value: number): void {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff_ffff) throw new Error("local SHA codec u32");
  out.push(value >>> 24, value >>> 16 & 0xff, value >>> 8 & 0xff, value & 0xff);
}

function u16(out: number[], value: number): void {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff) throw new Error("local SHA codec u16");
  out.push(value >>> 8, value & 0xff);
}

/** Canonical constraint-program bytes. Debug labels and output names are excluded. */
function encodeLocalShaProgramVersion(program: LocalShaProgram, version: 1 | 2): Uint8Array {
  if (program.rows.length < 1 || program.rows.length > 1 << 18 || program.inputLabels.length > 1 << 20 ||
    program.copyAliases.length > 1 << 20 || program.wordAliases.length > 1 << 20 ||
    (version === LEGACY_VERSION && program.wordAliases.length !== 0)) {
    throw new Error("local SHA program codec geometry");
  }
  const out: number[] = [...MAGIC, version];
  u32(out, program.rows.length);
  u32(out, program.inputLabels.length);
  u32(out, program.copyAliases.length);
  if (version === VERSION) u32(out, program.wordAliases.length);
  for (const row of program.rows) {
    out.push(OPERATION_ID[row.operation]);
    if (row.operation === "input" || row.operation === "mask") u32(out, row.input!);
    else if (row.operation === "constant") u32(out, row.literal!);
    else if (row.operation === "rotr") {
      u32(out, row.a!);
      out.push(row.shift!);
    } else if (row.operation === "nonzero") u32(out, row.a!);
    else {
      u32(out, row.a!);
      u32(out, row.b!);
    }
  }
  for (const [left, right] of program.copyAliases) {
    u32(out, left.wire);
    out.push(left.limb);
    u32(out, right.wire);
    out.push(right.limb);
  }
  if (version === VERSION) {
    for (const [left, right] of program.wordAliases) {
      u32(out, left);
      u32(out, right);
    }
  }
  return Uint8Array.from(out);
}

export function encodeLocalShaProgram(program: LocalShaProgram): Uint8Array {
  return encodeLocalShaProgramVersion(program, VERSION);
}

class Cursor {
  offset = 0;
  constructor(readonly bytes: Uint8Array) {}
  u8(): number {
    if (this.offset >= this.bytes.length) throw new Error("truncated local SHA program");
    return this.bytes[this.offset++]!;
  }
  u32(): number {
    return ((this.u8() << 24) | (this.u8() << 16) | (this.u8() << 8) | this.u8()) >>> 0;
  }
}

function assertCell(rowCount: number, wire: number, limb: number): void {
  if (wire >= rowCount || limb >= 8) throw new Error("local SHA program alias");
}

export function decodeLocalShaProgram(bytes: Uint8Array): LocalShaProgram {
  const cursor = new Cursor(bytes);
  if (!MAGIC.every((byte) => cursor.u8() === byte)) {
    throw new Error("local SHA program codec");
  }
  const version = cursor.u8();
  if (version !== LEGACY_VERSION && version !== VERSION) throw new Error("local SHA program codec");
  const rowCount = cursor.u32();
  const inputCount = cursor.u32();
  const aliasCount = cursor.u32();
  const wordAliasCount = version === VERSION ? cursor.u32() : 0;
  if (rowCount < 1 || rowCount > 1 << 18 || inputCount > 1 << 20 || aliasCount > 1 << 20 ||
    wordAliasCount > 1 << 20) {
    throw new Error("local SHA program geometry");
  }
  const rows: LocalShaRow[] = [];
  const inputWires: number[] = [];
  let nextInput = 0;
  for (let out = 0; out < rowCount; out += 1) {
    const operation = ID_OPERATION[cursor.u8()];
    if (!operation) throw new Error("local SHA program operation");
    const base = { operation, out, label: `row:${out}` } as const;
    if (operation === "input" || operation === "mask") {
      const input = cursor.u32();
      if (input !== nextInput || input >= inputCount) throw new Error("local SHA program input order");
      rows.push({ ...base, input });
      inputWires.push(out);
      nextInput += 1;
    } else if (operation === "constant") {
      rows.push({ ...base, literal: cursor.u32() });
    } else if (operation === "rotr") {
      const a = cursor.u32();
      const shift = cursor.u8();
      if (a >= out || shift < 1 || shift > 31) throw new Error("local SHA program rotation");
      rows.push({ ...base, a, shift });
    } else if (operation === "nonzero") {
      const a = cursor.u32();
      if (a >= out) throw new Error("local SHA program unary wire");
      rows.push({ ...base, a });
    } else {
      const a = cursor.u32();
      const b = cursor.u32();
      if (a >= out || b >= out) throw new Error("local SHA program binary wire");
      rows.push({ ...base, a, b });
    }
  }
  if (nextInput !== inputCount) throw new Error("local SHA program input count");
  const copyAliases: LocalShaCopyAlias[] = [];
  for (let alias = 0; alias < aliasCount; alias += 1) {
    const left = { wire: cursor.u32(), limb: cursor.u8() };
    const right = { wire: cursor.u32(), limb: cursor.u8() };
    assertCell(rowCount, left.wire, left.limb);
    assertCell(rowCount, right.wire, right.limb);
    copyAliases.push([left, right]);
  }
  const wordAliases: LocalShaWordAlias[] = [];
  for (let alias = 0; alias < wordAliasCount; alias += 1) {
    const left = cursor.u32();
    const right = cursor.u32();
    if (left >= rowCount || right >= rowCount) throw new Error("local SHA program word alias");
    wordAliases.push([left, right]);
  }
  if (cursor.offset !== bytes.length) throw new Error("trailing local SHA program bytes");
  const program: LocalShaProgram = {
    rows,
    inputLabels: Array.from({ length: inputCount }, (_, input) => `input:${input}`),
    inputWires,
    outputs: [],
    jobBlockCounts: [],
    copyAliases,
    wordAliases,
  };
  if (!encodeLocalShaProgramVersion(program, version).every((byte, index) => byte === bytes[index])) {
    throw new Error("non-canonical local SHA program");
  }
  return program;
}

export function localShaProgramDigest(program: LocalShaProgram): Uint8Array {
  return sha256(encodeLocalShaProgram(program));
}

/**
 * Witness-independent component descriptor for the final construction hash.
 * It pins the exact constraint program and typed statement-to-row ownership;
 * statement values themselves remain public inputs, never construction data.
 */
export function encodePoolLocalShaConstruction(graph: PoolLocalShaGraph): Uint8Array {
  validateLocalWordInteractionLayout();
  const publicWords = graph.inputLayout.filter((input) => input.visibility === "public");
  if (publicWords.some((input) => input.publicField === undefined || input.word === undefined)) {
    throw new Error("pool local SHA typed public input");
  }
  const geometry = localShaGeometry(graph.program);
  const out: number[] = [
    ...CONSTRUCTION_MAGIC,
    LOCAL_WORD_RELATION_CONSTRUCTION_VERSION,
    PROFILE_ID[graph.profile],
  ];
  u16(out, LOCAL_SHA_LOOKUP_TABLE_ROWS);
  u32(out, graph.program.rows.length);
  u32(out, geometry.relationRows);
  u16(out, LOCAL_SHA_ORIGINAL_COLUMNS);
  u16(out, LOCAL_SHA_WORD_PREPROCESSED_COLUMNS + 3);
  u16(out, LOCAL_SHA_WORD_INTERACTION_QM31_COLUMNS + 2);
  out.push(LOCAL_WORD_INTERACTION_GROUPS.length);
  for (const group of LOCAL_WORD_INTERACTION_GROUPS) out.push(group.length, ...group);
  out.push(LOCAL_WORD_GLOBAL_INTERACTION_COLUMNS.length, ...LOCAL_WORD_GLOBAL_INTERACTION_COLUMNS);
  out.push(...localShaProgramDigest(graph.program));
  u16(out, publicWords.length);
  for (const input of publicWords) {
    out.push(PUBLIC_FIELD_ID[input.publicField!], input.word!);
    u32(out, input.wire);
  }
  return Uint8Array.from(out);
}

export function poolLocalShaConstructionDigest(graph: PoolLocalShaGraph): Uint8Array {
  return sha256(encodePoolLocalShaConstruction(graph));
}

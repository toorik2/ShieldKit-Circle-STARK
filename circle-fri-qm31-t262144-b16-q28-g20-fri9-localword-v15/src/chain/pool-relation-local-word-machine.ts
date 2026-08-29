import { HASH_AMOUNT_TAG } from "../amounts/hash-commit.ts";
import type { RelationMembership, RelationWitness } from "../pool/relation-witness.ts";
import { readU16LE, writeI64LE } from "../pool/bytes.ts";
import { MERKLE_DEPTH, type Note } from "../pool/notes.ts";
import type { PoolStatement } from "../pool/statement.ts";
import {
  LocalShaCircuitBuilder,
  localShaHashWords,
  localShaWordsFromBytes,
  type LocalShaProgram,
} from "./sha256-local-word-machine.ts";

/** One input row of the complete local-word pool graph. */
export type PoolLocalShaInput = {
  readonly input: number;
  readonly wire: number;
  readonly label: string;
  readonly visibility: "private" | "public";
  readonly value: number;
  readonly publicField?: PoolLocalShaPublicField;
  readonly word?: number;
};

export type PoolLocalShaPublicField =
  | "deposit-amount"
  | "withdraw-amount"
  | "pool-instance-id"
  | "nullifier"
  | "old-note-root"
  | "new-note-root";

/** A digest or word plane joined to a public statement field by the copy ledger. */
export type PoolLocalShaBoundary = {
  readonly label: string;
  readonly computedWires: readonly number[];
  readonly publicWires: readonly number[];
  readonly expected: Uint8Array;
};

export type PoolLocalShaHash = {
  readonly label: string;
  readonly digestWires: readonly number[];
  readonly blocks: number;
};

export type PoolLocalShaAmountWires = {
  readonly primary: readonly number[];
  readonly change?: readonly number[];
  readonly relation: "deposit-public-equality" | "full-withdraw-public-equality" | "withdraw-change-sum";
};

export type PoolLocalShaGraph = {
  readonly profile: "deposit" | "withdraw-full" | "withdraw-change";
  readonly program: LocalShaProgram;
  readonly inputs: readonly number[];
  readonly inputLayout: readonly PoolLocalShaInput[];
  readonly boundaries: readonly PoolLocalShaBoundary[];
  readonly hashes: readonly PoolLocalShaHash[];
  readonly amountWires: PoolLocalShaAmountWires;
  readonly compressions: number;
  readonly hasChange: boolean;
  /** Public fee bound by settlement; the note funds it only on withdrawal. */
  readonly minerFeeSats: bigint;
};

type NoteWires = {
  readonly amount: readonly number[];
  readonly rho: readonly number[];
  readonly owner: readonly number[];
  readonly amountCommit: readonly number[];
  readonly leaf: readonly number[];
};

type AmountChunks = {
  readonly wires: readonly number[];
  readonly values: readonly number[];
};

function assertWidth(bytes: Uint8Array, width: number, label: string): void {
  if (bytes.length !== width) throw new Error(`${label} width`);
}

function hashBlocks(messageBytes: number): number {
  return Math.ceil((messageBytes + 1 + 8) / 64);
}

/**
 * Compiles semantic data directly into one static SHA/copy graph. There is no
 * message bus: a digest wire is reused as the next message wire, shared Merkle
 * siblings and directions are single sources, and public boundaries are copy
 * classes over public input rows.
 */
class PoolLocalShaCompiler {
  readonly builder = new LocalShaCircuitBuilder();
  readonly inputs: number[] = [];
  readonly inputLayout: PoolLocalShaInput[] = [];
  readonly boundaries: PoolLocalShaBoundary[] = [];
  readonly hashes: PoolLocalShaHash[] = [];
  readonly publicWordsByField = new Map<PoolLocalShaPublicField, readonly number[]>();

  constructor(readonly minerFeeSats: bigint) {
    if (minerFeeSats < 0n || minerFeeSats > 0x7fff_ffff_ffff_ffffn) {
      throw new Error("pool local SHA miner fee");
    }
  }

  private inputWord(
    value: number,
    label: string,
    visibility: "private" | "public",
    mask = false,
    publicField?: PoolLocalShaPublicField,
    word?: number,
  ): number {
    const input = this.inputs.length;
    const wire = mask ? this.builder.mask(label) : this.builder.input(label);
    if (this.builder.inputLabels.length !== input + 1) throw new Error("pool local SHA input order");
    const canonical = value >>> 0;
    this.inputs.push(canonical);
    this.inputLayout.push({ input, wire, label, visibility, value: canonical, publicField, word });
    return wire;
  }

  private words(bytes: Uint8Array, label: string, visibility: "private" | "public"): readonly number[] {
    return localShaWordsFromBytes(bytes).map((value, word) =>
      this.inputWord(value, `${label}:word:${word}`, visibility));
  }

  private privateWords(bytes: Uint8Array, label: string): readonly number[] {
    return this.words(bytes, label, "private");
  }

  private publicWords(bytes: Uint8Array, field: PoolLocalShaPublicField): readonly number[] {
    const existing = this.publicWordsByField.get(field);
    if (existing) return existing;
    const words = localShaWordsFromBytes(bytes).map((value, word) =>
      this.inputWord(value, `public:${field}:word:${word}`, "public", false, field, word));
    this.publicWordsByField.set(field, words);
    return words;
  }

  private constantWords(bytes: Uint8Array): readonly number[] {
    return localShaWordsFromBytes(bytes).map((word) => this.builder.constant(word));
  }

  /**
   * Build a sparse word from selected source nibbles using the ordinary ALU.
   * This is deliberately computation, not a private input plus cell aliases:
   * the amount relation therefore has no exceptional nibble-copy doorway.
   */
  private viewWord(
    label: string,
    sources: readonly { readonly targetLimb: number; readonly wire: number; readonly limb: number }[],
  ): number {
    const targets = new Set<number>();
    let result = this.builder.constant(0);
    for (const source of sources) {
      if (source.targetLimb < 0 || source.targetLimb >= 8 || source.limb < 0 || source.limb >= 8) {
        throw new Error(`${label} view limb`);
      }
      if (targets.has(source.targetLimb)) throw new Error(`${label} duplicate view limb`);
      targets.add(source.targetLimb);
      const isolated = this.builder.and(
        source.wire,
        this.builder.constant((0xf << (source.limb * 4)) >>> 0),
        `${label}:limb:${source.targetLimb}:isolate`,
      );
      const shift = ((source.limb - source.targetLimb + 8) % 8) * 4;
      const placed = shift === 0
        ? isolated
        : this.builder.rotate(isolated, shift, `${label}:limb:${source.targetLimb}:place`);
      // Target limbs are unique, hence XOR is exactly sparse-word assembly.
      result = this.builder.xor(result, placed, `${label}:limb:${source.targetLimb}:merge`);
    }
    return result;
  }

  /** Four little-endian u16 views of the canonical 8-byte SHA message plane. */
  private amountChunks(
    words: readonly number[],
    bytes: Uint8Array,
    label: string,
  ): AmountChunks {
    if (words.length !== 2 || bytes.length !== 8) throw new Error(`${label} amount geometry`);
    const maps = [
      [6, 7, 4, 5],
      [2, 3, 0, 1],
      [6, 7, 4, 5],
      [2, 3, 0, 1],
    ] as const;
    const values = Array.from({ length: 4 }, (_, chunk) => readU16LE(bytes, chunk * 2));
    const wires = maps.map((limbs, chunk) => this.viewWord(
      `${label}:chunk:${chunk}`,
      limbs.map((limb, targetLimb) => ({ targetLimb, wire: words[Math.floor(chunk / 2)]!, limb })),
    ));
    return { wires, values };
  }

  private split16(value: number, source: number, label: string): { low: number; carry: number } {
    const low = this.viewWord(`${label}:low`, Array.from({ length: 4 }, (_, limb) => ({
      targetLimb: limb,
      wire: source,
      limb,
    })));
    const carry = this.viewWord(`${label}:carry`, [{ targetLimb: 0, wire: source, limb: 4 }]);
    return { low, carry };
  }

  private assertNonNegative(chunks: AmountChunks, label: string): void {
    const sign = this.builder.and(chunks.wires[3]!, this.builder.constant(0x8000), `${label}:sign`);
    this.builder.equalWord(sign, this.builder.constant(0));
  }

  private conserveAmounts(
    spent: AmountChunks,
    withdrawal: AmountChunks,
    change: AmountChunks,
    label: string,
  ): void {
    this.assertNonNegative(spent, `${label}:spent`);
    this.assertNonNegative(withdrawal, `${label}:withdrawal`);
    this.assertNonNegative(change, `${label}:change`);
    this.builder.assertSomeNonzero(spent.wires, `${label}:spent-nonzero`);
    this.builder.assertSomeNonzero(change.wires, `${label}:change-nonzero`);

    let carryWire = this.builder.constant(0);
    let carryValue = 0;
    for (let chunk = 0; chunk < 4; chunk += 1) {
      const partial = this.builder.add(withdrawal.wires[chunk]!, change.wires[chunk]!, `${label}:${chunk}:partial`);
      const sum = this.builder.add(partial, carryWire, `${label}:${chunk}:carry-in`);
      const value = withdrawal.values[chunk]! + change.values[chunk]! + carryValue;
      const split = this.split16(value, sum, `${label}:${chunk}`);
      this.builder.equalWord(split.low, spent.wires[chunk]!);
      carryWire = split.carry;
      carryValue = value >>> 16;
    }
    this.builder.equalWord(carryWire, this.builder.constant(0));
  }

  private privateMask(value: 0 | 1, label: string): number {
    return this.inputWord(value === 0 ? 0 : 0xffff_ffff, label, "private", true);
  }

  private hash(message: readonly number[], messageBytes: number, label: string): readonly number[] {
    const digestWires = localShaHashWords(this.builder, message, messageBytes, label);
    const blocks = hashBlocks(messageBytes);
    this.hashes.push({ label, digestWires, blocks });
    return digestWires;
  }

  private bind(
    computedWires: readonly number[],
    expected: Uint8Array,
    field: PoolLocalShaPublicField,
  ): readonly number[] {
    assertWidth(expected, computedWires.length * 4, field);
    const publicWires = this.publicWords(expected, field);
    this.builder.equalWords(computedWires, publicWires);
    this.boundaries.push({ label: field, computedWires, publicWires, expected: new Uint8Array(expected) });
    return publicWires;
  }

  private note(
    note: Note,
    label: string,
    ownerWires?: readonly number[],
  ): NoteWires {
    assertWidth(note.rho, 32, `${label} rho`);
    assertWidth(note.ownerSecret, 32, `${label} owner`);
    const amount = this.privateWords(writeI64LE(note.amountSats), `${label}:amount`);
    const rho = this.privateWords(note.rho, `${label}:rho`);
    const owner = ownerWires ?? this.privateWords(note.ownerSecret, `${label}:owner`);
    if (owner.length !== 8) throw new Error(`${label} owner words`);
    const amountCommit = this.hash([
      ...this.constantWords(HASH_AMOUNT_TAG),
      ...amount,
      ...rho,
    ], HASH_AMOUNT_TAG.length + 8 + 32, `${label}:amount-commit`);
    const leaf = this.hash([...amountCommit, ...rho, ...owner], 96, `${label}:leaf`);
    return { amount, rho, owner, amountCommit, leaf };
  }

  private step(
    accumulator: readonly number[],
    sibling: readonly number[],
    direction: number,
    label: string,
  ): readonly number[] {
    if (accumulator.length !== 8 || sibling.length !== 8) throw new Error(`${label} Merkle word width`);
    const left = accumulator.map((word, index) =>
      this.builder.select(direction, word, sibling[index]!, `${label}:left:${index}`));
    const right = accumulator.map((word, index) =>
      this.builder.select(direction, sibling[index]!, word, `${label}:right:${index}`));
    return this.hash([...left, ...right], 64, label);
  }

  private pathSources(membership: RelationMembership, label: string): {
    readonly siblings: readonly (readonly number[])[];
    readonly directions: readonly number[];
  } {
    if (!Number.isInteger(membership.index) || membership.index < 0 || membership.index >= 2 ** MERKLE_DEPTH ||
      membership.path.length !== MERKLE_DEPTH) {
      throw new Error(`${label} Merkle path shape`);
    }
    const siblings = membership.path.map((sibling, level) => {
      assertWidth(sibling, 32, `${label} sibling ${level}`);
      return this.privateWords(sibling, `${label}:sibling:${level}`);
    });
    const directions = membership.path.map((_, level) =>
      this.privateMask(((membership.index >>> level) & 1) as 0 | 1, `${label}:direction:${level}`));
    return { siblings, directions };
  }

  private membership(
    leaf: readonly number[],
    membership: RelationMembership,
    expectedRoot: Uint8Array,
    label: string,
  ): void {
    const sources = this.pathSources(membership, label);
    let accumulator = leaf;
    for (let level = 0; level < MERKLE_DEPTH; level += 1) {
      accumulator = this.step(accumulator, sources.siblings[level]!, sources.directions[level]!, `${label}:${level}`);
    }
    this.bind(accumulator, expectedRoot, "old-note-root");
  }

  private append(
    createdLeaf: readonly number[],
    membership: RelationMembership,
    oldRoot: Uint8Array,
    newRoot: Uint8Array,
    label: string,
  ): void {
    const sources = this.pathSources(membership, label);
    const zero = Array.from({ length: 8 }, () => this.builder.constant(0));
    let oldAccumulator: readonly number[] = zero;
    let newAccumulator: readonly number[] = createdLeaf;
    for (let level = 0; level < MERKLE_DEPTH; level += 1) {
      oldAccumulator = this.step(
        oldAccumulator,
        sources.siblings[level]!,
        sources.directions[level]!,
        `${label}:old:${level}`,
      );
      newAccumulator = this.step(
        newAccumulator,
        sources.siblings[level]!,
        sources.directions[level]!,
        `${label}:new:${level}`,
      );
    }
    this.bind(oldAccumulator, oldRoot, "old-note-root");
    this.bind(newAccumulator, newRoot, "new-note-root");
  }

  deposit(statement: PoolStatement, created: RelationMembership): PoolLocalShaAmountWires {
    const note = this.note(created.note, "deposit-note");
    this.bind(note.amount, writeI64LE(statement.publicAmountSats), "deposit-amount");
    this.append(
      note.leaf,
      created,
      statement.oldState.noteRoot,
      statement.newState.noteRoot,
      "deposit-append",
    );
    return { primary: note.amount, relation: "deposit-public-equality" };
  }

  withdraw(
    statement: PoolStatement,
    spent: RelationMembership,
    change?: RelationMembership,
  ): PoolLocalShaAmountWires {
    const note = this.note(spent.note, "spent-note");
    const poolInstance = this.publicWords(statement.oldState.poolInstanceId, "pool-instance-id");
    const nullifier = this.hash([...poolInstance, ...note.owner, ...note.rho], 96, "spent-note:nullifier");
    this.bind(nullifier, statement.nullifier, "nullifier");
    this.membership(note.leaf, spent, statement.oldState.noteRoot, "spent-membership");

    if (!change) {
      const withdrawal = -statement.publicAmountSats;
      if (withdrawal <= this.minerFeeSats) throw new Error("withdraw payout after fee");
      this.bind(note.amount, writeI64LE(withdrawal), "withdraw-amount");
      return { primary: note.amount, relation: "full-withdraw-public-equality" };
    }

    // No-transfer v1: change reuses the spent ownership wire. Its leaf and
    // allocation remain private; only the resulting public note root is bound.
    const changed = this.note(change.note, "change-note", note.owner);
    this.append(
      changed.leaf,
      change,
      statement.oldState.noteRoot,
      statement.newState.noteRoot,
      "change-append",
    );
    const spentAmountBytes = writeI64LE(spent.note.amountSats);
    const changeAmountBytes = writeI64LE(change.note.amountSats);
    const withdrawal = -statement.publicAmountSats;
    if (withdrawal <= this.minerFeeSats) throw new Error("withdraw payout after fee");
    const withdrawalBytes = writeI64LE(withdrawal);
    const spentChunks = this.amountChunks(note.amount, spentAmountBytes, "spent-amount");
    const changeChunks = this.amountChunks(changed.amount, changeAmountBytes, "change-amount");
    const withdrawalWords = this.publicWords(withdrawalBytes, "withdraw-amount");
    const withdrawalChunks = this.amountChunks(withdrawalWords, withdrawalBytes, "withdraw-amount");
    this.conserveAmounts(spentChunks, withdrawalChunks, changeChunks, "withdraw-conservation");
    const rhoDifferences = note.rho.map((word, index) =>
      this.builder.xor(word, changed.rho[index]!, `change-rho-fresh:${index}`));
    this.builder.assertSomeNonzero(rhoDifferences, "change-rho-fresh");
    return {
      primary: note.amount,
      change: changed.amount,
      relation: "withdraw-change-sum",
    };
  }

  finish(
    amountWires: PoolLocalShaAmountWires,
    profile: PoolLocalShaGraph["profile"],
  ): PoolLocalShaGraph {
    const program = this.builder.finish(
      this.hashes.map((hash) => hash.digestWires),
      this.hashes.map((hash) => hash.blocks),
    );
    const compressions = this.hashes.reduce((sum, hash) => sum + hash.blocks, 0);
    return {
      profile,
      program,
      inputs: this.inputs,
      inputLayout: this.inputLayout,
      boundaries: this.boundaries,
      hashes: this.hashes,
      amountWires,
      compressions,
      hasChange: profile === "withdraw-change",
      minerFeeSats: this.minerFeeSats,
    };
  }
}

/** Compile the complete private SHA and note-tree portion of pool relation v1. */
export function compilePoolLocalShaGraph(
  statement: PoolStatement,
  witness: RelationWitness,
  minerFeeSats = 0n,
): PoolLocalShaGraph {
  const compiler = new PoolLocalShaCompiler(minerFeeSats);
  if (statement.action === "DEPOSIT") {
    if (!witness.created) throw new Error("deposit created witness");
    return compiler.finish(compiler.deposit(statement, witness.created), "deposit");
  }
  if (!witness.spent) throw new Error("withdraw spent witness");
  const amountWires = compiler.withdraw(statement, witness.spent, witness.created);
  return compiler.finish(amountWires, witness.created ? "withdraw-change" : "withdraw-full");
}

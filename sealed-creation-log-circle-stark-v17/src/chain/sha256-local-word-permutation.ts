import { M31, type M31El } from "../backends/circle/m31.ts";
import {
  QM31_FIELD_BITS,
  QM31_ONE,
  QM31_ZERO,
  qmAdd,
  qmEq,
  qmInv,
  qmMul,
  qmMulM31,
  type QM31El,
} from "../backends/circle/qm31.ts";
import { LOCAL_WORD_QUERY_CONJECTURE_BITS } from "../backends/circle/local-word-successor-params.ts";
import {
  LOCAL_SHA_COPY_INACTIVE_ID,
  LOCAL_SHA_LIMB_BITS,
  LOCAL_SHA_LIMBS,
  LOCAL_SHA_LOOKUP_TABLE_ROWS,
  LOCAL_SHA_MAX_LOOKUPS_PER_ROW,
  LOCAL_SHA_ORIGINAL_COLUMNS,
  type LocalShaPort,
  type LocalShaProgram,
  type LocalShaExecution,
  type LocalShaRelationFrame,
  type LocalShaRow,
  type LocalShaTrace,
  type LocalShaTraceRow,
  localShaGeometry,
  localShaInstructionLookupTag,
  localShaLookupTable,
  localShaTraceRowAt,
  localShaWordLimbs,
} from "./sha256-local-word-machine.ts";

/**
 * Production replacement for the nibble-copy LogUp. One slot represents one
 * complete source word.
 */

export const LOCAL_SHA_WORD_COPY_SLOTS_PER_ROW = 3;
export const LOCAL_SHA_WORD_COPY_COMPRESSED_QM31_COLUMNS = 3;
export const LOCAL_SHA_WORD_COPY_PRODUCT_QM31_COLUMNS = 3;
export const LOCAL_SHA_WORD_COPY_QM31_COLUMNS =
  LOCAL_SHA_WORD_COPY_COMPRESSED_QM31_COLUMNS + LOCAL_SHA_WORD_COPY_PRODUCT_QM31_COLUMNS;
export const LOCAL_SHA_WORD_LOOKUP_QM31_COLUMNS = 9;
export const LOCAL_SHA_WORD_INTERACTION_QM31_COLUMNS =
  LOCAL_SHA_WORD_LOOKUP_QM31_COLUMNS + LOCAL_SHA_WORD_COPY_QM31_COLUMNS;
export const LOCAL_SHA_WORD_INTERACTION_PREVIOUS_QM31_COLUMNS = 2;
export const LOCAL_SHA_WORD_SHIFT_SELECTOR_M31_COLUMNS = 2 * LOCAL_SHA_LIMBS;
export const LOCAL_SHA_WORD_MASK_SELECTOR_M31_COLUMNS = 1;
export const LOCAL_SHA_WORD_LAST_SELECTOR_M31_COLUMNS = 1;
/**
 * Tag, literal limbs, A/B one-hot source shifts, identity/sigma pairs, active,
 * mask and last-row selectors, and the universal-table tuple.
 */
export const LOCAL_SHA_WORD_PREPROCESSED_COLUMNS = 1 + LOCAL_SHA_LIMBS +
  LOCAL_SHA_WORD_SHIFT_SELECTOR_M31_COLUMNS + LOCAL_SHA_WORD_COPY_SLOTS_PER_ROW * 2 +
  1 + LOCAL_SHA_WORD_MASK_SELECTOR_M31_COLUMNS + LOCAL_SHA_WORD_LAST_SELECTOR_M31_COLUMNS + 6;
export const LOCAL_SHA_WORD_AIR_CONSTRAINTS = LOCAL_SHA_WORD_LOOKUP_QM31_COLUMNS +
  LOCAL_SHA_WORD_COPY_COMPRESSED_QM31_COLUMNS + LOCAL_SHA_WORD_COPY_PRODUCT_QM31_COLUMNS +
  1 + (LOCAL_SHA_LIMBS - 1) + 2;

const PORTS: readonly LocalShaPort[] = ["a", "b", "out"];

export type LocalShaWordCopyPermutation = {
  /** Row-major A/B/out word slots; inactive slots use the reserved self-loop. */
  readonly identities: Uint32Array;
  readonly sigmas: Uint32Array;
  readonly relationRows: number;
  readonly activeSlots: number;
};

export type LocalShaWordCopyChallenges = {
  readonly gamma: QM31El;
  readonly identity: QM31El;
  /** Independent coefficients for the eight canonical source-word nibbles. */
  readonly limbs: readonly [QM31El, QM31El, QM31El, QM31El, QM31El, QM31El, QM31El, QM31El];
};

export type LocalShaWordCopyTrace = {
  readonly relationRows: number;
  readonly compressed: readonly [readonly QM31El[], readonly QM31El[], readonly QM31El[]];
  readonly products: readonly [readonly QM31El[], readonly QM31El[], readonly QM31El[]];
};

export type LocalShaWordCopyViolation = {
  readonly row: number;
  readonly constraint: string;
};

export type LocalShaWordCopyOccurrenceViolation = LocalShaWordCopyViolation & {
  readonly port?: LocalShaPort;
  readonly value?: number;
  readonly targetRow?: number;
  readonly targetPort?: LocalShaPort;
  readonly targetValue?: number;
};

export type LocalShaWordCopyGeometry = {
  readonly relationRows: number;
  readonly activeWordSlots: number;
  readonly legacyNibbleCopyQm31Columns: number;
  readonly wordCopyQm31Columns: number;
  readonly preprocessedM31Columns: number;
  readonly interactionQm31Columns: number;
  readonly previousQm31Columns: number;
  readonly openedM31ValuesPerQuery: number;
  readonly openedM31ValuesPerQueryWithPoolBoundary: number;
};

export type LocalShaWordCopySoundness = {
  readonly fieldBits: number;
  readonly permutationPolynomialDegree: number;
  readonly permutationBits: number;
  readonly permutationDenominatorTerms: number;
  readonly permutationDenominatorBits: number;
  readonly lookupTerms: number;
  readonly lookupBits: number;
  readonly publicBoundaryTerms: number;
  readonly publicBoundaryBits: number;
  readonly constraintMixingTerms: number;
  readonly constraintMixingBits: number;
  readonly oracleBatchingTerms: number;
  readonly oracleBatchingBits: number;
  readonly friQueryConjectureBits: number;
  readonly classicalHashCollisionBits: number;
  readonly conservativeUnionBits: number;
  readonly meetsFloor: boolean;
  readonly claimBoundary: "fri-query-term-conjectural-classical-rom";
};

function normalizeCellAlias(leftWire: number, leftLimb: number, rightWire: number, rightLimb: number): string {
  const left = leftWire * LOCAL_SHA_LIMBS + leftLimb;
  const right = rightWire * LOCAL_SHA_LIMBS + rightLimb;
  return left < right ? `${left}:${right}` : `${right}:${left}`;
}

/**
 * Individual aliases are permitted only for the seven redundant mask-limb
 * equalities. The AIR checks
 * those equalities locally and does not put them in the word permutation.
 */
export function assertLocalShaOnlyLegacyMaskCellAliases(program: LocalShaProgram): void {
  const expected = new Set<string>();
  for (const row of program.rows) {
    if (row.operation !== "mask") continue;
    for (let limb = 1; limb < LOCAL_SHA_LIMBS; limb += 1) {
      expected.add(normalizeCellAlias(row.out, 0, row.out, limb));
    }
  }
  if (program.copyAliases.length !== expected.size) {
    throw new Error("local SHA word copy unsupported cell alias");
  }
  for (const [left, right] of program.copyAliases) {
    if (!expected.delete(normalizeCellAlias(left.wire, left.limb, right.wire, right.limb))) {
      throw new Error("local SHA word copy unsupported cell alias");
    }
  }
  if (expected.size !== 0) throw new Error("local SHA word copy missing mask alias");
}

function wordForPort(instruction: LocalShaRow, port: LocalShaPort): number | undefined {
  if (port === "out") return instruction.out;
  if (port === "a") return instruction.a;
  if (instruction.operation === "rotr") {
    return instruction.shift! % LOCAL_SHA_LIMB_BITS === 0 ? undefined : instruction.a;
  }
  return instruction.b;
}

function wordShiftForPort(instruction: LocalShaRow, port: "a" | "b"): number | undefined {
  if (wordForPort(instruction, port) === undefined) return undefined;
  if (instruction.operation !== "rotr") return 0;
  return (Math.floor(instruction.shift! / LOCAL_SHA_LIMB_BITS) + (port === "b" ? 1 : 0)) % LOCAL_SHA_LIMBS;
}

/** Compile the fixed three-slot word permutation, including semantic aliases. */
export function compileLocalShaWordCopyPermutation(program: LocalShaProgram): LocalShaWordCopyPermutation {
  assertLocalShaOnlyLegacyMaskCellAliases(program);
  const relationRows = localShaGeometry(program).relationRows;
  const slotCount = relationRows * LOCAL_SHA_WORD_COPY_SLOTS_PER_ROW;
  const parent = Int32Array.from({ length: program.rows.length }, (_, wire) => wire);
  const find = (wire: number): number => {
    let root = wire;
    while (parent[root] !== root) root = parent[root]!;
    while (parent[wire] !== wire) {
      const next = parent[wire]!;
      parent[wire] = root;
      wire = next;
    }
    return root;
  };
  for (const [left, right] of program.wordAliases) {
    if (left < 0 || right < 0 || left >= program.rows.length || right >= program.rows.length) {
      throw new Error("local SHA word alias");
    }
    const leftRoot = find(left);
    const rightRoot = find(right);
    if (leftRoot !== rightRoot) parent[rightRoot] = leftRoot;
  }

  const identities = new Uint32Array(slotCount);
  const sigmas = new Uint32Array(slotCount);
  identities.fill(Number(LOCAL_SHA_COPY_INACTIVE_ID));
  sigmas.fill(Number(LOCAL_SHA_COPY_INACTIVE_ID));
  const firstIdentity = new Uint32Array(program.rows.length);
  const lastSlot = new Int32Array(program.rows.length);
  lastSlot.fill(-1);
  let identity = 1;
  let activeSlots = 0;
  for (let row = 0; row < program.rows.length; row += 1) {
    const instruction = program.rows[row]!;
    for (let port = 0; port < PORTS.length; port += 1) {
      const wire = wordForPort(instruction, PORTS[port]!);
      if (wire === undefined) continue;
      const root = find(wire);
      const slot = row * LOCAL_SHA_WORD_COPY_SLOTS_PER_ROW + port;
      identities[slot] = identity;
      const previous = lastSlot[root]!;
      if (previous < 0) firstIdentity[root] = identity;
      else sigmas[previous] = identity;
      lastSlot[root] = slot;
      identity += 1;
      activeSlots += 1;
    }
  }
  if (identity >= Number(M31)) throw new Error("local SHA word copy identities exceed M31");
  for (let root = 0; root < lastSlot.length; root += 1) {
    const slot = lastSlot[root]!;
    if (slot >= 0) sigmas[slot] = firstIdentity[root]!;
  }
  return { identities, sigmas, relationRows, activeSlots };
}

/** Exact 34/40-column relation frame for the candidate word-copy AIR. */
export function localShaWordRelationFrameAt(
  program: LocalShaProgram,
  execution: LocalShaExecution,
  permutation: LocalShaWordCopyPermutation,
  multiplicities: Uint32Array,
  row: number,
): LocalShaRelationFrame {
  const relationRows = localShaGeometry(program).relationRows;
  if (!Number.isInteger(row) || row < 0 || row >= relationRows ||
    execution.wireValues.length !== program.rows.length ||
    permutation.relationRows !== relationRows ||
    permutation.identities.length !== relationRows * LOCAL_SHA_WORD_COPY_SLOTS_PER_ROW ||
    permutation.sigmas.length !== permutation.identities.length ||
    multiplicities.length !== LOCAL_SHA_LOOKUP_TABLE_ROWS) {
    throw new Error("local SHA word relation frame geometry");
  }
  const instruction = program.rows[row];
  const trace = instruction ? localShaTraceRowAt(program, execution, row) : {
    a: Array<M31El>(LOCAL_SHA_LIMBS).fill(0n),
    b: Array<M31El>(LOCAL_SHA_LIMBS).fill(0n),
    out: Array<M31El>(LOCAL_SHA_LIMBS).fill(0n),
    carry: Array<M31El>(LOCAL_SHA_LIMBS + 1).fill(0n),
  };
  const original = [
    ...trace.a,
    ...trace.b,
    ...trace.out,
    ...trace.carry,
    BigInt(multiplicities[row] ?? 0),
  ];
  const literal = instruction?.operation === "constant"
    ? localShaWordLimbs(instruction.literal!)
    : Array<M31El>(LOCAL_SHA_LIMBS).fill(0n);
  const shiftSelectors = (["a", "b"] as const).flatMap((port) => {
    const shift = instruction ? wordShiftForPort(instruction, port) : undefined;
    return Array.from({ length: LOCAL_SHA_LIMBS }, (_, candidate) => shift === candidate ? 1n : 0n);
  });
  const copy: M31El[] = [];
  const slotStart = row * LOCAL_SHA_WORD_COPY_SLOTS_PER_ROW;
  for (let slot = 0; slot < LOCAL_SHA_WORD_COPY_SLOTS_PER_ROW; slot += 1) {
    const index = slotStart + slot;
    copy.push(BigInt(permutation.identities[index]!), BigInt(permutation.sigmas[index]!));
  }
  const table = localShaLookupTable()[row];
  const preprocessed = [
    BigInt(instruction ? localShaInstructionLookupTag(instruction) : 0),
    ...literal,
    ...shiftSelectors,
    ...copy,
    instruction ? 1n : 0n,
    instruction?.operation === "mask" ? 1n : 0n,
    row === relationRows - 1 ? 1n : 0n,
    ...(table
      ? [BigInt(table.tag), table.a, table.b, table.carryIn, table.out, table.carryOut]
      : Array<M31El>(6).fill(0n)),
  ];
  if (original.length !== LOCAL_SHA_ORIGINAL_COLUMNS ||
    preprocessed.length !== LOCAL_SHA_WORD_PREPROCESSED_COLUMNS) {
    throw new Error("local SHA word relation frame width");
  }
  return { row, original, preprocessed };
}

function tracePort(row: LocalShaTraceRow, port: LocalShaPort): readonly M31El[] {
  return row[port];
}

function sourceLimb(instruction: LocalShaRow, port: LocalShaPort, traceLimb: number): number {
  if (instruction.operation !== "rotr" || port === "out") return traceLimb;
  const wholeLimbShift = Math.floor(instruction.shift! / LOCAL_SHA_LIMB_BITS);
  return (traceLimb + wholeLimbShift + (port === "b" ? 1 : 0)) % LOCAL_SHA_LIMBS;
}

function compressPort(
  instruction: LocalShaRow | undefined,
  traceRow: LocalShaTraceRow | undefined,
  port: LocalShaPort,
  challenges: LocalShaWordCopyChallenges,
): QM31El {
  if (!instruction || !traceRow || wordForPort(instruction, port) === undefined) return QM31_ZERO;
  let result = QM31_ZERO;
  const values = tracePort(traceRow, port);
  for (let limb = 0; limb < LOCAL_SHA_LIMBS; limb += 1) {
    result = qmAdd(result, qmMulM31(challenges.limbs[sourceLimb(instruction, port, limb)]!, values[limb]!));
  }
  return result;
}

/**
 * Challenge-free check that every compiled sigma edge carries one canonical
 * source word. This is the cheapest exact falsifier for the grand product: if
 * it passes, random limb compression cannot make an honest permutation fail.
 */
export function verifyLocalShaWordCopyOccurrences(
  program: LocalShaProgram,
  execution: LocalShaExecution,
  permutation = compileLocalShaWordCopyPermutation(program),
): LocalShaWordCopyOccurrenceViolation | undefined {
  const slotCount = permutation.relationRows * LOCAL_SHA_WORD_COPY_SLOTS_PER_ROW;
  if (execution.wireValues.length !== program.rows.length ||
    permutation.identities.length !== slotCount || permutation.sigmas.length !== slotCount) {
    return { row: -1, constraint: "word-occurrence-shape" };
  }

  const values = new Uint32Array(slotCount);
  const slotsByIdentity = new Int32Array(permutation.activeSlots + 1);
  slotsByIdentity.fill(-1);
  for (let row = 0; row < program.rows.length; row += 1) {
    const instruction = program.rows[row]!;
    const trace = localShaTraceRowAt(program, execution, row);
    for (let portIndex = 0; portIndex < PORTS.length; portIndex += 1) {
      const port = PORTS[portIndex]!;
      const slot = row * LOCAL_SHA_WORD_COPY_SLOTS_PER_ROW + portIndex;
      const wire = wordForPort(instruction, port);
      if (wire === undefined) continue;
      const limbs = tracePort(trace, port);
      let normalized = 0;
      let seen = 0;
      for (let traceLimb = 0; traceLimb < LOCAL_SHA_LIMBS; traceLimb += 1) {
        const canonicalLimb = sourceLimb(instruction, port, traceLimb);
        const bit = 1 << canonicalLimb;
        if ((seen & bit) !== 0) {
          return { row, port, constraint: "word-occurrence-duplicate-limb" };
        }
        seen |= bit;
        normalized = (normalized | (Number(limbs[traceLimb]!) << (canonicalLimb * LOCAL_SHA_LIMB_BITS))) >>> 0;
      }
      if (seen !== (1 << LOCAL_SHA_LIMBS) - 1) {
        return { row, port, constraint: "word-occurrence-missing-limb" };
      }
      const canonical = execution.wireValues[wire]!;
      if (normalized !== canonical) {
        return { row, port, value: normalized, targetValue: canonical, constraint: "word-occurrence-normalization" };
      }
      values[slot] = normalized;
      const identity = permutation.identities[slot]!;
      if (identity < 1 || identity > permutation.activeSlots || slotsByIdentity[identity] !== -1) {
        return { row, port, constraint: "word-occurrence-identity" };
      }
      slotsByIdentity[identity] = slot;
    }
  }

  for (let slot = 0; slot < slotCount; slot += 1) {
    const identity = permutation.identities[slot]!;
    const sigma = permutation.sigmas[slot]!;
    if (identity === Number(LOCAL_SHA_COPY_INACTIVE_ID)) {
      if (sigma !== identity) return { row: Math.floor(slot / 3), constraint: "word-occurrence-inactive" };
      continue;
    }
    if (sigma < 1 || sigma > permutation.activeSlots) {
      return { row: Math.floor(slot / 3), port: PORTS[slot % 3], constraint: "word-occurrence-sigma" };
    }
    const targetSlot = slotsByIdentity[sigma]!;
    if (targetSlot < 0 || values[slot] === values[targetSlot]) continue;
    return {
      row: Math.floor(slot / 3),
      port: PORTS[slot % 3],
      value: values[slot],
      targetRow: Math.floor(targetSlot / 3),
      targetPort: PORTS[targetSlot % 3],
      targetValue: values[targetSlot],
      constraint: "word-occurrence-sigma-value",
    };
  }
  return undefined;
}

function productTerm(
  id: number,
  compressed: QM31El,
  challenges: LocalShaWordCopyChallenges,
): QM31El {
  return qmAdd(
    challenges.gamma,
    qmAdd(qmMulM31(challenges.identity, BigInt(id)), compressed),
  );
}

/** Build the six candidate interaction columns on the relation domain. */
export function buildLocalShaWordCopyTrace(
  program: LocalShaProgram,
  trace: LocalShaTrace,
  challenges: LocalShaWordCopyChallenges,
  permutation = compileLocalShaWordCopyPermutation(program),
): LocalShaWordCopyTrace {
  if (trace.rows.length !== program.rows.length || permutation.relationRows !== localShaGeometry(program).relationRows ||
    challenges.limbs.length !== LOCAL_SHA_LIMBS) {
    throw new Error("local SHA word copy trace shape");
  }
  const compressed: [QM31El[], QM31El[], QM31El[]] = [[], [], []];
  const products: [QM31El[], QM31El[], QM31El[]] = [[], [], []];
  let accumulator = QM31_ONE;
  for (let row = 0; row < permutation.relationRows; row += 1) {
    const instruction = program.rows[row];
    const traceRow = trace.rows[row];
    for (let port = 0; port < PORTS.length; port += 1) {
      const slot = row * LOCAL_SHA_WORD_COPY_SLOTS_PER_ROW + port;
      const value = compressPort(instruction, traceRow, PORTS[port]!, challenges);
      compressed[port].push(value);
      const numerator = productTerm(permutation.identities[slot]!, value, challenges);
      const denominator = productTerm(permutation.sigmas[slot]!, value, challenges);
      accumulator = qmMul(qmMul(accumulator, numerator), qmInv(denominator));
      products[port].push(accumulator);
    }
  }
  return { relationRows: permutation.relationRows, compressed, products };
}

/** Reference verifier for the exact local compression and grand-product identities. */
export function verifyLocalShaWordCopyTrace(
  program: LocalShaProgram,
  trace: LocalShaTrace,
  interaction: LocalShaWordCopyTrace,
  challenges: LocalShaWordCopyChallenges,
): LocalShaWordCopyViolation | undefined {
  const permutation = compileLocalShaWordCopyPermutation(program);
  if (trace.rows.length !== program.rows.length || interaction.relationRows !== permutation.relationRows ||
    interaction.compressed.length !== 3 || interaction.products.length !== 3 ||
    [...interaction.compressed, ...interaction.products].some((column) => column.length !== permutation.relationRows)) {
    return { row: -1, constraint: "word-copy-shape" };
  }
  let previous = QM31_ONE;
  for (let row = 0; row < permutation.relationRows; row += 1) {
    const instruction = program.rows[row];
    const traceRow = trace.rows[row];
    if (instruction?.operation === "mask" && traceRow) {
      for (let limb = 1; limb < LOCAL_SHA_LIMBS; limb += 1) {
        if (traceRow.out[limb] !== traceRow.out[0]) return { row, constraint: `mask-limb:${limb}` };
      }
    }
    for (let port = 0; port < PORTS.length; port += 1) {
      const slot = row * LOCAL_SHA_WORD_COPY_SLOTS_PER_ROW + port;
      const compressed = interaction.compressed[port]![row]!;
      const expectedCompressed = compressPort(instruction, traceRow, PORTS[port]!, challenges);
      if (!qmEq(compressed, expectedCompressed)) return { row, constraint: `word-compress:${PORTS[port]}` };
      const numerator = productTerm(permutation.identities[slot]!, compressed, challenges);
      const denominator = productTerm(permutation.sigmas[slot]!, compressed, challenges);
      const current = interaction.products[port]![row]!;
      if (!qmEq(qmMul(current, denominator), qmMul(previous, numerator))) {
        return { row, constraint: `word-product:${PORTS[port]}` };
      }
      previous = current;
    }
  }
  if (!qmEq(previous, QM31_ONE)) {
    return { row: permutation.relationRows - 1, constraint: "word-product-boundary" };
  }
  return undefined;
}

export function localShaWordCopyGeometry(program: LocalShaProgram): LocalShaWordCopyGeometry {
  const permutation = compileLocalShaWordCopyPermutation(program);
  const openedM31ValuesPerQuery = LOCAL_SHA_ORIGINAL_COLUMNS + LOCAL_SHA_WORD_PREPROCESSED_COLUMNS +
    LOCAL_SHA_WORD_INTERACTION_QM31_COLUMNS * 4 + LOCAL_SHA_WORD_INTERACTION_PREVIOUS_QM31_COLUMNS * 4;
  // Pool boundary adds three preprocessed M31 and two current QM31 columns.
  return {
    relationRows: permutation.relationRows,
    activeWordSlots: permutation.activeSlots,
    legacyNibbleCopyQm31Columns: 2 * LOCAL_SHA_LIMBS * 3 * 2,
    wordCopyQm31Columns: LOCAL_SHA_WORD_COPY_QM31_COLUMNS,
    preprocessedM31Columns: LOCAL_SHA_WORD_PREPROCESSED_COLUMNS,
    interactionQm31Columns: LOCAL_SHA_WORD_INTERACTION_QM31_COLUMNS,
    previousQm31Columns: LOCAL_SHA_WORD_INTERACTION_PREVIOUS_QM31_COLUMNS,
    openedM31ValuesPerQuery,
    openedM31ValuesPerQueryWithPoolBoundary: openedM31ValuesPerQuery + 3 + 2 * 4,
  };
}

function unionBits(bits: readonly number[]): number {
  return -Math.log2(bits.reduce((probability, security) => probability + 2 ** -security, 0));
}

/**
 * Conservative v16 root-bound worksheet for the worst profile. Every entry is
 * a named event from the implemented transcript; there are no inherited
 * placeholder bits. Lookup and permutation are each charged once for a false
 * rational identity and once again for a zero denominator. The latter bounds
 * deliberately count all possible terms rather than only distinct factors.
 *
 * The FRI term remains the construction's explicitly named query conjecture,
 * and SHA-256 is charged at its classical collision level in the ROM. This is
 * therefore a worksheet, not a reduction or a QROM claim.
 */
export function localShaWordCopySoundness(
  program: LocalShaProgram,
  floorBits = 100,
): LocalShaWordCopySoundness {
  const geometry = localShaWordCopyGeometry(program);
  const fieldBits = 4 * Math.log2(Number(M31));
  const permutationPolynomialDegree = geometry.activeWordSlots;
  const permutationBits = fieldBits - Math.log2(permutationPolynomialDegree);
  const permutationDenominatorTerms = geometry.relationRows * LOCAL_SHA_WORD_COPY_SLOTS_PER_ROW;
  const permutationDenominatorBits = fieldBits - Math.log2(permutationDenominatorTerms);
  const lookupTerms = program.rows.length * LOCAL_SHA_MAX_LOOKUPS_PER_ROW + LOCAL_SHA_LOOKUP_TABLE_ROWS;
  const lookupBits = fieldBits - Math.log2(lookupTerms);
  // Every profile exposes exactly one SHA-256 relation-statement digest.
  const publicBoundaryTerms = 8;
  const publicBoundaryBits = fieldBits - Math.log2(publicBoundaryTerms);
  // Twenty-five AIR residuals are mixed by one Horner challenge.
  const constraintMixingTerms = LOCAL_SHA_WORD_AIR_CONSTRAINTS - 1;
  const constraintMixingBits = fieldBits - Math.log2(constraintMixingTerms);
  // 9 packed original + 17 packed interaction + 1 quotient values.
  const oracleBatchingTerms = 27 - 1;
  const oracleBatchingBits = fieldBits - Math.log2(oracleBatchingTerms);
  const friQueryConjectureBits = LOCAL_WORD_QUERY_CONJECTURE_BITS;
  const classicalHashCollisionBits = 128;
  const conservativeUnionBits = unionBits([
    permutationBits,
    permutationDenominatorBits,
    lookupBits,
    lookupBits,
    publicBoundaryBits,
    publicBoundaryBits,
    constraintMixingBits,
    oracleBatchingBits,
    friQueryConjectureBits,
    classicalHashCollisionBits,
  ]);
  return {
    fieldBits: Math.min(fieldBits, QM31_FIELD_BITS),
    permutationPolynomialDegree,
    permutationBits,
    permutationDenominatorTerms,
    permutationDenominatorBits,
    lookupTerms,
    lookupBits,
    publicBoundaryTerms,
    publicBoundaryBits,
    constraintMixingTerms,
    constraintMixingBits,
    oracleBatchingTerms,
    oracleBatchingBits,
    friQueryConjectureBits,
    classicalHashCollisionBits,
    conservativeUnionBits,
    meetsFloor: conservativeUnionBits >= floorBits,
    claimBoundary: "fri-query-term-conjectural-classical-rom",
  };
}

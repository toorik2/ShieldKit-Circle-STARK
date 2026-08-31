import { M31, type M31El } from "../backends/circle/m31.ts";
import {
  QM31_ZERO,
  liftM31,
  qmAdd,
  qmEq,
  qmInv,
  qmMul,
  qmNeg,
  type QM31El,
} from "../backends/circle/qm31.ts";
import type { LocalWordInteractionChallenges } from "../backends/circle/local-word-transcript.ts";
import {
  LOCAL_SHA_LIMBS,
  LOCAL_SHA_LOOKUP_TABLE_ROWS,
  type LocalShaLookupEntry,
  type LocalShaProgram,
  type LocalShaTrace,
  localShaGeometry,
  localShaLookupEntries,
  localShaLookupTable,
} from "./sha256-local-word-machine.ts";
import {
  LOCAL_SHA_WORD_INTERACTION_QM31_COLUMNS,
  buildLocalShaWordCopyTrace,
  compileLocalShaWordCopyPermutation,
} from "./sha256-local-word-permutation.ts";

export type LocalShav16InteractionTrace = {
  readonly relationRows: number;
  readonly tableMultiplicities: readonly M31El[];
  /** Lookup 0..8, compressed words 9..11, word products 12..14. */
  readonly columns: readonly (readonly QM31El[])[];
  readonly lookupClaimedSum: QM31El;
};

function lookupKey(entry: LocalShaLookupEntry): string {
  return `${entry.tag}:${entry.a}:${entry.b}:${entry.carryIn}:${entry.out}:${entry.carryOut}`;
}

function linear(
  gamma: QM31El,
  challenges: readonly QM31El[],
  values: readonly M31El[],
): QM31El {
  if (challenges.length !== values.length) throw new Error("local SHA lookup arity");
  let result = gamma;
  for (let index = 0; index < values.length; index += 1) {
    result = qmAdd(result, qmMul(challenges[index]!, liftM31(values[index]!)));
  }
  return result;
}

function denominator(entry: LocalShaLookupEntry, challenges: LocalWordInteractionChallenges["lookup"]): QM31El {
  return linear(challenges.gamma, challenges.tuple, [
    BigInt(entry.tag),
    entry.a,
    entry.b,
    entry.carryIn,
    entry.out,
    entry.carryOut,
  ]);
}

/** Build the exact fifteen candidate core interaction columns. */
export function buildLocalShaInteractionTrace(
  program: LocalShaProgram,
  trace: LocalShaTrace,
  challenges: LocalWordInteractionChallenges,
): LocalShav16InteractionTrace {
  if (trace.rows.length !== program.rows.length) throw new Error("local SHA interaction trace shape");
  const relationRows = localShaGeometry(program).relationRows;
  const table = localShaLookupTable();
  const tableIndex = new Map(table.map((entry, index) => [lookupKey(entry), index]));
  const accesses = localShaLookupEntries(program, trace);
  if (accesses.length !== program.rows.length * LOCAL_SHA_LIMBS) {
    throw new Error("local SHA lookup access geometry");
  }
  const tableMultiplicities = Array<M31El>(LOCAL_SHA_LOOKUP_TABLE_ROWS).fill(0n);
  for (const entry of accesses) {
    const index = tableIndex.get(lookupKey(entry));
    if (index === undefined) throw new Error("local SHA invalid lookup access");
    tableMultiplicities[index] = tableMultiplicities[index]! + 1n;
  }
  if (tableMultiplicities.some((value) => value >= M31)) {
    throw new Error("local SHA table multiplicity M31");
  }

  const lookupColumns = Array.from({ length: 9 }, () =>
    Array<QM31El>(relationRows).fill(QM31_ZERO));
  let lookupClaimedSum = QM31_ZERO;
  for (let row = 0; row < relationRows; row += 1) {
    let rowCumulative = QM31_ZERO;
    for (let limb = 0; limb < LOCAL_SHA_LIMBS; limb += 1) {
      if (row < program.rows.length) {
        const entry = accesses[row * LOCAL_SHA_LIMBS + limb]!;
        rowCumulative = qmAdd(rowCumulative, qmInv(denominator(entry, challenges.lookup)));
      }
      lookupColumns[limb]![row] = rowCumulative;
    }
    const tableEntry = table[row];
    if (tableEntry) {
      rowCumulative = qmAdd(
        rowCumulative,
        qmMul(qmNeg(liftM31(tableMultiplicities[row]!)), qmInv(denominator(tableEntry, challenges.lookup))),
      );
    }
    lookupClaimedSum = qmAdd(lookupClaimedSum, rowCumulative);
    lookupColumns[8]![row] = lookupClaimedSum;
  }
  if (!qmEq(lookupClaimedSum, QM31_ZERO)) throw new Error("local SHA lookup claimed sum");

  const wordCopy = buildLocalShaWordCopyTrace(
    program,
    trace,
    challenges.wordCopy,
    compileLocalShaWordCopyPermutation(program),
  );
  const columns = [
    ...lookupColumns,
    ...wordCopy.compressed,
    ...wordCopy.products,
  ];
  if (columns.length !== LOCAL_SHA_WORD_INTERACTION_QM31_COLUMNS ||
    columns.some((column) => column.length !== relationRows)) {
    throw new Error("local SHA interaction column geometry");
  }
  return { relationRows, tableMultiplicities, columns, lookupClaimedSum };
}

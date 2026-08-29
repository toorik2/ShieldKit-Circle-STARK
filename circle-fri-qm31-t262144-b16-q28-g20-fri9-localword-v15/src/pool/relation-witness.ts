import type { Note } from "./notes.ts";

/** Private note membership owned by the relation compiler, never a proof field. */
export type RelationMembership = {
  readonly note: Note;
  readonly index: number;
  readonly path: Uint8Array[];
};

/** The complete private relation input for one deposit or one withdrawal. */
export type RelationWitness = {
  readonly spent?: RelationMembership;
  readonly created?: RelationMembership;
  /** Historical batch callers only; v15 rejects batching at its relation boundary. */
  readonly batch?: RelationMembership[];
};

export function wDeposit(
  note: Note,
  index: number,
  path: Uint8Array[],
): RelationWitness {
  return { created: { note, index, path } };
}

export function wWithdraw(
  note: Note,
  index: number,
  path: Uint8Array[],
  change?: RelationMembership,
): RelationWitness {
  return { spent: { note, index, path }, created: change };
}

export function wBatchExit(spent: RelationMembership[]): RelationWitness {
  if (spent.length < 1) throw new Error("batch-exit witness");
  return { spent: spent[0], batch: spent };
}

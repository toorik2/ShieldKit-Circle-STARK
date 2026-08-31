import type { Note } from "./notes.ts";
import type { CreatedNoteRecord } from "./edge-history.ts";

/**
 * Private evidence that an owned note was created at one public edge.
 *
 * The edge itself and the linked head are deliberately absent: the relation
 * derives both from these irreducible inputs. The path authenticates that
 * derived edge in the current public history root.
 */
export type RelationMembership = CreatedNoteRecord & {
  readonly path: readonly Uint8Array[];
};

/** A new note needs no private tree position or append path. */
export type RelationCreation = {
  readonly note: Note;
};

/** The complete private relation input for one v16 transition. */
export type RelationWitness = {
  readonly spent?: RelationMembership;
  readonly created?: RelationCreation;
};

export function wDeposit(note: Note): RelationWitness {
  return { created: { note } };
}

export function wWithdraw(
  spent: RelationMembership,
  change?: Note,
): RelationWitness {
  return { spent, created: change === undefined ? undefined : { note: change } };
}

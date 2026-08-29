/**
 * Canonical QM31-column ownership for the four interaction commitments.
 * Group 3 contains the only columns also opened at the cyclic predecessor.
 */
export const LOCAL_WORD_INTERACTION_GROUPS: readonly (readonly number[])[] = [
  [0, 1, 2, 3, 4],
  [5, 6, 7, 9, 10],
  [11, 12, 13, 15],
  [8, 14, 16],
];

export const LOCAL_WORD_GLOBAL_INTERACTION_COLUMNS = LOCAL_WORD_INTERACTION_GROUPS[3]!;

export function validateLocalWordInteractionLayout(): void {
  const flattened = LOCAL_WORD_INTERACTION_GROUPS.flat();
  if (flattened.length !== 17 || new Set(flattened).size !== 17 ||
    flattened.some((column) => !Number.isInteger(column) || column < 0 || column >= 17)) {
    throw new Error("local-word interaction oracle layout");
  }
}

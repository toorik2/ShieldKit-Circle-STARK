/** May-2026 BCH VM limits, pinned from BCHN script/vm_limits.h. */
export const LOCAL_WORD_OPCOST_PER_INPUT_BYTE = 800;
export const LOCAL_WORD_INPUT_FIXED_CREDIT = 41;

/** Every canonical carrier is encoded as one minimally encoded OP_PUSHDATA2. */
export const LOCAL_WORD_CARRIER_PUSH_OVERHEAD = 3;

export function localWordMaximumOperationCost(chunkBytes: number): number {
  if (!Number.isSafeInteger(chunkBytes) || chunkBytes < 1) {
    throw new Error("local-word carrier chunk budget");
  }
  return (chunkBytes + LOCAL_WORD_CARRIER_PUSH_OVERHEAD + LOCAL_WORD_INPUT_FIXED_CREDIT) *
    LOCAL_WORD_OPCOST_PER_INPUT_BYTE;
}

/** Smallest useful canonical-proof slice that owns the requested input-local budget. */
export function localWordRequiredChunkBytes(operationCost: number): number {
  if (!Number.isSafeInteger(operationCost) || operationCost < 0) {
    throw new Error("local-word operation cost budget");
  }
  return Math.max(1, Math.ceil(operationCost / LOCAL_WORD_OPCOST_PER_INPUT_BYTE) -
    LOCAL_WORD_INPUT_FIXED_CREDIT - LOCAL_WORD_CARRIER_PUSH_OVERHEAD);
}

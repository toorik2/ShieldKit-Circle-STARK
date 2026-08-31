import {
  concatBytes,
  eq32,
  readU64BE,
  writeU64BE,
  ZERO32,
} from "../pool/bytes.ts";
import {
  ANY_STATE_BYTES,
  STATE_BASE_SATS,
  decodeState,
  encodePublicPaa2,
  type AnyAmountState,
} from "../pool/state.ts";
import {
  EDGE_HISTORY_DEPTH,
  verifyEdgeAppend,
} from "../pool/edge-history.ts";
import type { PoolStatement } from "../pool/statement.ts";
import {
  foldSparseNullifierPathSegment,
  SPARSE_NULLIFIER_DEPTH,
  SPARSE_NULLIFIER_MID_LEVEL,
  SPARSE_NULLIFIER_PATH_BYTES,
  usedNullifierLeaf,
  verifySparseNullifierInsertion,
} from "../pool/sparse-nullifiers.ts";
import { hashPayoutLocking } from "./payout.ts";
import {
  LOCAL_WORD_CARRIER_INPUTS,
  localWordVerifierBankDigestFromInputs,
  type LocalWordVerifierBankDigests,
} from "./local-word-proof-carriers.ts";

const NULLIFIER_DATA_MAGIC = new TextEncoder().encode("SKNF");
const EDGE_DATA_MAGIC = new TextEncoder().encode("SKEG");
export const LOCAL_WORD_NULLIFIER_DATA_VERSION = 1;
export const LOCAL_WORD_EDGE_DATA_VERSION = 1;
export const LOCAL_WORD_POOL_INPUT = 0;
export const LOCAL_WORD_POOL_OUTPUT = 0;
export const LOCAL_WORD_PAYOUT_OUTPUT = LOCAL_WORD_CARRIER_INPUTS;
export const LOCAL_WORD_NULLIFIER_DATA_OUTPUT = LOCAL_WORD_CARRIER_INPUTS + 1;
export const LOCAL_WORD_DEPOSIT_EDGE_DATA_OUTPUT = LOCAL_WORD_CARRIER_INPUTS;
export const LOCAL_WORD_CHANGE_EDGE_DATA_OUTPUT = LOCAL_WORD_CARRIER_INPUTS + 2;
export const LOCAL_WORD_NULLIFIER_DATA_PAYLOAD_BYTES = 4 + 1 + 32 + 32 + 32 + SPARSE_NULLIFIER_PATH_BYTES;
export const LOCAL_WORD_NULLIFIER_DATA_LOCKING_BYTES = 4 + LOCAL_WORD_NULLIFIER_DATA_PAYLOAD_BYTES;
export const LOCAL_WORD_NULLIFIER_PATH_OFFSET = 4 + 4 + 1 + 32 + 32 + 32;
// SKEG || version || reserved[3] || creationIndex_u64be || edge || path[32]
export const LOCAL_WORD_EDGE_DATA_PAYLOAD_BYTES = 4 + 1 + 3 + 8 + 32 + EDGE_HISTORY_DEPTH * 32;
export const LOCAL_WORD_EDGE_DATA_LOCKING_BYTES = 4 + LOCAL_WORD_EDGE_DATA_PAYLOAD_BYTES;
export const LOCAL_WORD_EDGE_INDEX_OFFSET = 4 + 4 + 1 + 3;
export const LOCAL_WORD_EDGE_OFFSET = LOCAL_WORD_EDGE_INDEX_OFFSET + 8;
export const LOCAL_WORD_EDGE_PATH_OFFSET = LOCAL_WORD_EDGE_OFFSET + 32;

export type LocalWordToken = {
  readonly category: Uint8Array;
  readonly amount: bigint;
  readonly nft?: {
    readonly capability: string;
    readonly commitment: Uint8Array;
  };
};

export type LocalWordSourceOutput = {
  readonly lockingBytecode: Uint8Array;
  readonly valueSatoshis: bigint;
  readonly token?: LocalWordToken;
};

export type LocalWordTransactionOutput = LocalWordSourceOutput;

export type LocalWordEnvelopeView = {
  readonly sourceOutputs: readonly LocalWordSourceOutput[];
  readonly inputSequenceNumbers: readonly number[];
  readonly outputs: readonly LocalWordTransactionOutput[];
};

export type LocalWordPublicSettlement = {
  readonly statement: PoolStatement;
  readonly minerFeeSats: bigint;
  readonly profile: "deposit" | "withdraw-full" | "withdraw-change";
  readonly nullifierPath: readonly Uint8Array[];
  readonly edgePath: readonly Uint8Array[];
};

function equal(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((byte, index) => byte === right[index]);
}

function stateFromPoolOutput(output: LocalWordSourceOutput): AnyAmountState {
  const commitment = output.token?.nft?.commitment;
  if (!commitment || commitment.length !== ANY_STATE_BYTES || output.valueSatoshis < STATE_BASE_SATS ||
    output.token?.category.length !== 32 || output.token.amount !== 0n ||
    output.token.nft?.capability !== "mutable") {
    throw new Error("local-word pool state output");
  }
  return decodeState(commitment, output.valueSatoshis - STATE_BASE_SATS);
}

function samePublicStateEncoding(output: LocalWordSourceOutput, state: AnyAmountState): boolean {
  return output.token?.nft !== undefined && equal(output.token.nft.commitment, encodePublicPaa2(state));
}

function tokenless(output: LocalWordSourceOutput | undefined): output is LocalWordSourceOutput {
  return output !== undefined && output.token === undefined;
}

export function localWordEdgeDataOutputIndex(
  profile: LocalWordPublicSettlement["profile"],
  infrastructureInputs = LOCAL_WORD_CARRIER_INPUTS,
): number | undefined {
  if (!Number.isSafeInteger(infrastructureInputs) ||
    infrastructureInputs < LOCAL_WORD_CARRIER_INPUTS) {
    throw new Error("local-word infrastructure input count");
  }
  return profile === "deposit"
    ? infrastructureInputs
    : profile === "withdraw-change"
      ? infrastructureInputs + 2
      : undefined;
}

export function localWordPayoutOutputIndex(
  infrastructureInputs = LOCAL_WORD_CARRIER_INPUTS,
): number {
  if (!Number.isSafeInteger(infrastructureInputs) ||
    infrastructureInputs < LOCAL_WORD_CARRIER_INPUTS) {
    throw new Error("local-word infrastructure input count");
  }
  return infrastructureInputs;
}

export function localWordNullifierDataOutputIndex(
  infrastructureInputs = LOCAL_WORD_CARRIER_INPUTS,
): number {
  return localWordPayoutOutputIndex(infrastructureInputs) + 1;
}

export function encodeLocalWordEdgeData(args: {
  readonly creationIndex: bigint;
  readonly edge: Uint8Array;
  readonly path: readonly Uint8Array[];
}): Uint8Array {
  if (args.creationIndex < 0n || args.creationIndex >= (1n << BigInt(EDGE_HISTORY_DEPTH)) ||
    args.edge.length !== 32 || args.edge.every((byte) => byte === 0) ||
    args.path.length !== EDGE_HISTORY_DEPTH || args.path.some((node) => node.length !== 32)) {
    throw new Error("local-word edge data");
  }
  const payload = concatBytes(
    EDGE_DATA_MAGIC,
    Uint8Array.of(LOCAL_WORD_EDGE_DATA_VERSION, 0, 0, 0),
    writeU64BE(args.creationIndex),
    args.edge,
    ...args.path,
  );
  if (payload.length !== LOCAL_WORD_EDGE_DATA_PAYLOAD_BYTES) {
    throw new Error("local-word edge payload width");
  }
  return concatBytes(
    Uint8Array.of(0x6a, 0x4d, payload.length & 0xff, payload.length >>> 8),
    payload,
  );
}

export function decodeLocalWordEdgeData(lockingBytecode: Uint8Array): {
  readonly creationIndex: bigint;
  readonly edge: Uint8Array;
  readonly path: readonly Uint8Array[];
} {
  if (lockingBytecode.length !== LOCAL_WORD_EDGE_DATA_LOCKING_BYTES ||
    lockingBytecode[0] !== 0x6a || lockingBytecode[1] !== 0x4d ||
    lockingBytecode[2] !== (LOCAL_WORD_EDGE_DATA_PAYLOAD_BYTES & 0xff) ||
    lockingBytecode[3] !== (LOCAL_WORD_EDGE_DATA_PAYLOAD_BYTES >>> 8) ||
    !EDGE_DATA_MAGIC.every((byte, index) => lockingBytecode[4 + index] === byte) ||
    lockingBytecode[8] !== LOCAL_WORD_EDGE_DATA_VERSION ||
    lockingBytecode[9] !== 0 || lockingBytecode[10] !== 0 || lockingBytecode[11] !== 0) {
    throw new Error("local-word edge data encoding");
  }
  const creationIndex = readU64BE(lockingBytecode, LOCAL_WORD_EDGE_INDEX_OFFSET);
  if (creationIndex >= (1n << BigInt(EDGE_HISTORY_DEPTH))) {
    throw new Error("local-word edge index");
  }
  const edge = lockingBytecode.slice(LOCAL_WORD_EDGE_OFFSET, LOCAL_WORD_EDGE_OFFSET + 32);
  if (edge.every((byte) => byte === 0)) throw new Error("local-word zero edge");
  const path = Array.from({ length: EDGE_HISTORY_DEPTH }, (_, level) =>
    lockingBytecode.slice(
      LOCAL_WORD_EDGE_PATH_OFFSET + level * 32,
      LOCAL_WORD_EDGE_PATH_OFFSET + (level + 1) * 32,
    ));
  return { creationIndex, edge, path };
}

export function decodeLocalWordEdgeDataForProfile(
  view: LocalWordEnvelopeView,
  profile: LocalWordPublicSettlement["profile"],
  infrastructureInputs = LOCAL_WORD_CARRIER_INPUTS,
): ReturnType<typeof decodeLocalWordEdgeData> | undefined {
  const index = localWordEdgeDataOutputIndex(profile, infrastructureInputs);
  if (index === undefined) return undefined;
  const output = view.outputs[index];
  if (!tokenless(output) || output.valueSatoshis !== 0n) {
    throw new Error("local-word edge output neutrality");
  }
  return decodeLocalWordEdgeData(output.lockingBytecode);
}

export function encodeLocalWordNullifierData(args: {
  readonly nullifier: Uint8Array;
  readonly path: readonly Uint8Array[];
}): Uint8Array {
  if (args.nullifier.length !== 32 || args.nullifier.every((byte) => byte === 0) ||
    args.path.length !== SPARSE_NULLIFIER_DEPTH || args.path.some((node) => node.length !== 32)) {
    throw new Error("local-word nullifier data");
  }
  const lowerPath = args.path.slice(0, SPARSE_NULLIFIER_MID_LEVEL);
  const oldMid = foldSparseNullifierPathSegment(ZERO32, args.nullifier, lowerPath, 0);
  const newMid = foldSparseNullifierPathSegment(usedNullifierLeaf(args.nullifier), args.nullifier, lowerPath, 0);
  const payload = concatBytes(
    NULLIFIER_DATA_MAGIC,
    Uint8Array.of(LOCAL_WORD_NULLIFIER_DATA_VERSION),
    args.nullifier,
    oldMid,
    newMid,
    ...args.path,
  );
  if (payload.length !== LOCAL_WORD_NULLIFIER_DATA_PAYLOAD_BYTES) {
    throw new Error("local-word nullifier payload width");
  }
  return concatBytes(
    Uint8Array.of(0x6a, 0x4d, payload.length & 0xff, payload.length >>> 8),
    payload,
  );
}

export function decodeLocalWordNullifierData(lockingBytecode: Uint8Array): {
  readonly nullifier: Uint8Array;
  readonly oldMid: Uint8Array;
  readonly newMid: Uint8Array;
  readonly path: readonly Uint8Array[];
} {
  if (lockingBytecode.length !== LOCAL_WORD_NULLIFIER_DATA_LOCKING_BYTES || lockingBytecode[0] !== 0x6a ||
    lockingBytecode[1] !== 0x4d ||
    lockingBytecode[2] !== (LOCAL_WORD_NULLIFIER_DATA_PAYLOAD_BYTES & 0xff) ||
    lockingBytecode[3] !== (LOCAL_WORD_NULLIFIER_DATA_PAYLOAD_BYTES >>> 8) ||
    !NULLIFIER_DATA_MAGIC.every((byte, index) => lockingBytecode[4 + index] === byte) ||
    lockingBytecode[8] !== LOCAL_WORD_NULLIFIER_DATA_VERSION) {
    throw new Error("local-word nullifier data encoding");
  }
  const nullifier = lockingBytecode.slice(9, 41);
  if (nullifier.every((byte) => byte === 0)) throw new Error("local-word zero nullifier");
  const oldMid = lockingBytecode.slice(41, 73);
  const newMid = lockingBytecode.slice(73, 105);
  const path = Array.from({ length: SPARSE_NULLIFIER_DEPTH }, (_, level) =>
    lockingBytecode.slice(LOCAL_WORD_NULLIFIER_PATH_OFFSET + level * 32,
      LOCAL_WORD_NULLIFIER_PATH_OFFSET + (level + 1) * 32));
  const lowerPath = path.slice(0, SPARSE_NULLIFIER_MID_LEVEL);
  if (!eq32(oldMid, foldSparseNullifierPathSegment(ZERO32, nullifier, lowerPath, 0)) ||
    !eq32(newMid, foldSparseNullifierPathSegment(usedNullifierLeaf(nullifier), nullifier, lowerPath, 0))) {
    throw new Error("local-word nullifier midpoint encoding");
  }
  return { nullifier, oldMid, newMid, path };
}

function assertCarrierRollForward(
  view: LocalWordEnvelopeView,
  infrastructureInputs: number,
): void {
  for (let index = 1; index < infrastructureInputs; index += 1) {
    const source = view.sourceOutputs[index];
    const output = view.outputs[index];
    if (!source || !output || source.valueSatoshis !== output.valueSatoshis ||
      !equal(source.lockingBytecode, output.lockingBytecode) ||
      source.token !== undefined || output.token !== undefined) {
      throw new Error(`local-word carrier value neutrality ${index}`);
    }
  }
}

function sumValues(outputs: readonly LocalWordSourceOutput[]): bigint {
  return outputs.reduce((sum, output) => sum + output.valueSatoshis, 0n);
}

/**
 * Reference semantics for the exact one-transaction envelope. The VM lock must
 * implement this function, field for field; this function is not consensus.
 */
export function deriveLocalWordPublicSettlement(
  view: LocalWordEnvelopeView,
  authorizedBankDigests: LocalWordVerifierBankDigests,
): LocalWordPublicSettlement {
  if (authorizedBankDigests.some((digest) => digest.length !== 32)) {
    throw new Error("local-word verifier bank digests");
  }
  if (view.sourceOutputs.length < LOCAL_WORD_CARRIER_INPUTS ||
    view.inputSequenceNumbers.length !== view.sourceOutputs.length ||
    view.outputs.length < LOCAL_WORD_CARRIER_INPUTS) {
    throw new Error("local-word envelope count");
  }
  const oldPool = view.sourceOutputs[LOCAL_WORD_POOL_INPUT]!;
  const newPool = view.outputs[LOCAL_WORD_POOL_OUTPUT]!;
  if (!equal(oldPool.lockingBytecode, newPool.lockingBytecode) ||
    oldPool.token?.nft === undefined || newPool.token?.nft === undefined ||
    oldPool.token.nft.capability !== "mutable" || newPool.token.nft.capability !== "mutable" ||
    oldPool.token.category.length !== 32 || newPool.token.category.length !== 32 ||
    !equal(oldPool.token.category, newPool.token.category) ||
    oldPool.token.amount !== 0n || newPool.token.amount !== 0n) {
    throw new Error("local-word pool covenant roll-forward");
  }
  const oldState = stateFromPoolOutput(oldPool);
  const newState = stateFromPoolOutput(newPool);
  if (!samePublicStateEncoding(oldPool, oldState) || !samePublicStateEncoding(newPool, newState) ||
    newState.sequence !== oldState.sequence + 1n) {
    throw new Error("local-word public state transition");
  }
  const publicAmountSats = newState.reserveSats - oldState.reserveSats;
  if (publicAmountSats === 0n) throw new Error("local-word zero reserve transition");
  const infrastructureInputs = publicAmountSats > 0n
    ? view.sourceOutputs.length - 1
    : view.sourceOutputs.length;
  if (infrastructureInputs < LOCAL_WORD_CARRIER_INPUTS) {
    throw new Error("local-word infrastructure input count");
  }
  assertCarrierRollForward(view, infrastructureInputs);
  const minerFeeSats = sumValues(view.sourceOutputs) - sumValues(view.outputs);
  if (minerFeeSats < 0n) throw new Error("local-word negative miner fee");

  let action: PoolStatement["action"];
  let nullifier = new Uint8Array(ZERO32);
  let payoutLockingDigest = new Uint8Array(ZERO32);
  let nullifierPath: readonly Uint8Array[] = [];
  let createdEdge = new Uint8Array(ZERO32);
  let edgePath: readonly Uint8Array[] = [];
  let profile: LocalWordPublicSettlement["profile"];
  if (publicAmountSats > 0n) {
    action = "DEPOSIT";
    if (infrastructureInputs < LOCAL_WORD_CARRIER_INPUTS ||
      view.outputs.length !== infrastructureInputs + 1 ||
      newState.creationCount !== oldState.creationCount + 1n ||
      eq32(oldState.creationHead, newState.creationHead) ||
      eq32(oldState.edgeHistoryRoot, newState.edgeHistoryRoot) ||
      !eq32(oldState.nullifierRoot, newState.nullifierRoot) ||
      !tokenless(view.sourceOutputs[infrastructureInputs]) ||
      view.sourceOutputs[infrastructureInputs]!.valueSatoshis !== publicAmountSats + minerFeeSats) {
      throw new Error("local-word deposit settlement");
    }
    profile = "deposit";
    const edgeData = decodeLocalWordEdgeDataForProfile(view, profile, infrastructureInputs)!;
    if (edgeData.creationIndex !== oldState.creationCount || !verifyEdgeAppend({
      index: edgeData.creationIndex,
      edge: edgeData.edge,
      path: edgeData.path,
      oldRoot: oldState.edgeHistoryRoot,
      newRoot: newState.edgeHistoryRoot,
    })) {
      throw new Error("local-word deposit edge append");
    }
    createdEdge = edgeData.edge;
    edgePath = edgeData.path;
  } else if (publicAmountSats < 0n) {
    action = "WITHDRAW";
    if (infrastructureInputs < LOCAL_WORD_CARRIER_INPUTS ||
      eq32(oldState.nullifierRoot, newState.nullifierRoot)) {
      throw new Error("local-word withdrawal settlement");
    }
    const unchangedCreation = newState.creationCount === oldState.creationCount &&
      eq32(oldState.creationHead, newState.creationHead) &&
      eq32(oldState.edgeHistoryRoot, newState.edgeHistoryRoot);
    const appendedCreation = newState.creationCount === oldState.creationCount + 1n &&
      !eq32(oldState.creationHead, newState.creationHead) &&
      !eq32(oldState.edgeHistoryRoot, newState.edgeHistoryRoot);
    if (unchangedCreation) {
      profile = "withdraw-full";
      if (view.outputs.length !== infrastructureInputs + 2) {
        throw new Error("local-word full withdrawal geometry");
      }
    } else if (appendedCreation) {
      profile = "withdraw-change";
      if (view.outputs.length !== infrastructureInputs + 3) {
        throw new Error("local-word change withdrawal geometry");
      }
      const edgeData = decodeLocalWordEdgeDataForProfile(view, profile, infrastructureInputs)!;
      if (edgeData.creationIndex !== oldState.creationCount || !verifyEdgeAppend({
        index: edgeData.creationIndex,
        edge: edgeData.edge,
        path: edgeData.path,
        oldRoot: oldState.edgeHistoryRoot,
        newRoot: newState.edgeHistoryRoot,
      })) {
        throw new Error("local-word change edge append");
      }
      createdEdge = edgeData.edge;
      edgePath = edgeData.path;
    } else {
      throw new Error("local-word withdrawal creation transition");
    }
    const payout = view.outputs[localWordPayoutOutputIndex(infrastructureInputs)]!;
    if (!tokenless(payout) || payout.valueSatoshis <= 0n ||
      -publicAmountSats !== payout.valueSatoshis + minerFeeSats) {
      throw new Error("local-word withdrawal value relation");
    }
    payoutLockingDigest = hashPayoutLocking(payout.lockingBytecode);
    const dataOutput = view.outputs[localWordNullifierDataOutputIndex(infrastructureInputs)]!;
    const decoded = decodeLocalWordNullifierData(dataOutput.lockingBytecode);
    if (dataOutput.valueSatoshis !== 0n || dataOutput.token !== undefined ||
      !verifySparseNullifierInsertion({
        nullifier: decoded.nullifier,
        path: decoded.path,
        oldRoot: oldState.nullifierRoot,
        newRoot: newState.nullifierRoot,
      })) {
      throw new Error("local-word sparse nullifier insertion");
    }
    nullifier = decoded.nullifier;
    nullifierPath = decoded.path;
  } else {
    throw new Error("local-word unreachable reserve transition");
  }

  const profileIndex: 0 | 1 | 2 = profile === "deposit"
    ? 0
    : profile === "withdraw-full"
      ? 1
      : 2;
  const bankDigest = localWordVerifierBankDigestFromInputs(
    profileIndex,
    view.sourceOutputs.slice(1, infrastructureInputs).map((output, local) => ({
      lockingBytecode: output.lockingBytecode,
      valueSatoshis: output.valueSatoshis,
      sequenceNumber: view.inputSequenceNumbers[local + 1]!,
    })),
  );
  if (!eq32(bankDigest, authorizedBankDigests[profileIndex])) {
    throw new Error("local-word unauthorized verifier bank");
  }
  return {
    minerFeeSats,
    profile,
    nullifierPath,
    edgePath,
    statement: {
      profile: "sealed-creation-log-v1",
      action,
      publicAmountSats,
      poolCategory: oldPool.token.category.slice(),
      oldState,
      newState,
      createdEdge,
      nullifier,
      payoutLockingDigest,
    },
  };
}

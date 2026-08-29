import { eq32, ZERO32, concatBytes } from "../pool/bytes.ts";
import {
  ANY_STATE_BYTES,
  STATE_BASE_SATS,
  decodeState,
  encodePublicPaa1,
  type AnyAmountState,
} from "../pool/state.ts";
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
  localWordVerifierBankDigestFromLockingBytecodes,
  type LocalWordVerifierBankDigests,
} from "./local-word-proof-carriers.ts";

const NULLIFIER_DATA_MAGIC = new TextEncoder().encode("SKNF");
export const LOCAL_WORD_NULLIFIER_DATA_VERSION = 1;
export const LOCAL_WORD_POOL_INPUT = 0;
export const LOCAL_WORD_POOL_OUTPUT = 0;
export const LOCAL_WORD_PAYOUT_OUTPUT = LOCAL_WORD_CARRIER_INPUTS;
export const LOCAL_WORD_NULLIFIER_DATA_OUTPUT = LOCAL_WORD_CARRIER_INPUTS + 1;
export const LOCAL_WORD_NULLIFIER_DATA_PAYLOAD_BYTES = 4 + 1 + 32 + 32 + 32 + SPARSE_NULLIFIER_PATH_BYTES;
export const LOCAL_WORD_NULLIFIER_DATA_LOCKING_BYTES = 4 + LOCAL_WORD_NULLIFIER_DATA_PAYLOAD_BYTES;
export const LOCAL_WORD_NULLIFIER_PATH_OFFSET = 4 + 4 + 1 + 32 + 32 + 32;

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
  readonly outputs: readonly LocalWordTransactionOutput[];
};

export type LocalWordPublicSettlement = {
  readonly statement: PoolStatement;
  readonly minerFeeSats: bigint;
  readonly profile: "deposit" | "withdraw-full" | "withdraw-change";
  readonly nullifierPath: readonly Uint8Array[];
};

function equal(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((byte, index) => byte === right[index]);
}

function sameToken(left: LocalWordToken | undefined, right: LocalWordToken | undefined): boolean {
  if (!left || !right) return left === right;
  return equal(left.category, right.category) && left.amount === right.amount &&
    left.nft?.capability === right.nft?.capability &&
    (left.nft === undefined || right.nft === undefined
      ? left.nft === right.nft
      : equal(left.nft.commitment, right.nft.commitment));
}

function stateFromPoolOutput(output: LocalWordSourceOutput): AnyAmountState {
  const commitment = output.token?.nft?.commitment;
  if (!commitment || commitment.length !== ANY_STATE_BYTES || output.valueSatoshis < STATE_BASE_SATS) {
    throw new Error("local-word pool state output");
  }
  return {
    ...decodeState(commitment),
    reserveSats: output.valueSatoshis - STATE_BASE_SATS,
  };
}

function samePublicStateEncoding(output: LocalWordSourceOutput, state: AnyAmountState): boolean {
  return output.token?.nft !== undefined && equal(output.token.nft.commitment, encodePublicPaa1(state));
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

function assertCarrierRollForward(view: LocalWordEnvelopeView): void {
  for (let index = 1; index < LOCAL_WORD_CARRIER_INPUTS; index += 1) {
    const source = view.sourceOutputs[index];
    const output = view.outputs[index];
    if (!source || !output || source.valueSatoshis !== output.valueSatoshis ||
      !equal(source.lockingBytecode, output.lockingBytecode) || !sameToken(source.token, output.token)) {
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
  if (view.sourceOutputs.length < LOCAL_WORD_CARRIER_INPUTS || view.outputs.length < LOCAL_WORD_CARRIER_INPUTS) {
    throw new Error("local-word envelope count");
  }
  const oldPool = view.sourceOutputs[LOCAL_WORD_POOL_INPUT]!;
  const newPool = view.outputs[LOCAL_WORD_POOL_OUTPUT]!;
  if (!equal(oldPool.lockingBytecode, newPool.lockingBytecode) ||
    oldPool.token?.nft === undefined || newPool.token?.nft === undefined ||
    oldPool.token.nft.capability !== newPool.token.nft.capability ||
    !equal(oldPool.token.category, newPool.token.category) || oldPool.token.amount !== newPool.token.amount) {
    throw new Error("local-word pool covenant roll-forward");
  }
  assertCarrierRollForward(view);
  const oldState = stateFromPoolOutput(oldPool);
  const newState = stateFromPoolOutput(newPool);
  if (!samePublicStateEncoding(oldPool, oldState) || !samePublicStateEncoding(newPool, newState) ||
    !eq32(oldState.poolInstanceId, newState.poolInstanceId) || newState.sequence !== oldState.sequence + 1n) {
    throw new Error("local-word public state transition");
  }
  const minerFeeSats = sumValues(view.sourceOutputs) - sumValues(view.outputs);
  if (minerFeeSats < 0n) throw new Error("local-word negative miner fee");
  const publicAmountSats = newState.reserveSats - oldState.reserveSats;

  let action: PoolStatement["action"];
  let nullifier = new Uint8Array(ZERO32);
  let payoutLockingDigest = new Uint8Array(ZERO32);
  let nullifierPath: readonly Uint8Array[] = [];
  if (publicAmountSats > 0n) {
    action = "DEPOSIT";
    if (view.sourceOutputs.length !== LOCAL_WORD_CARRIER_INPUTS + 1 ||
      view.outputs.length !== LOCAL_WORD_CARRIER_INPUTS ||
      newState.depositCount !== oldState.depositCount + 1n ||
      newState.withdrawalCount !== oldState.withdrawalCount ||
      !eq32(oldState.nullifierRoot, newState.nullifierRoot) ||
      view.sourceOutputs[LOCAL_WORD_CARRIER_INPUTS]!.valueSatoshis !== publicAmountSats + minerFeeSats) {
      throw new Error("local-word deposit settlement");
    }
  } else if (publicAmountSats < 0n) {
    action = "WITHDRAW";
    if (view.sourceOutputs.length !== LOCAL_WORD_CARRIER_INPUTS ||
      view.outputs.length !== LOCAL_WORD_CARRIER_INPUTS + 2 ||
      newState.depositCount !== oldState.depositCount ||
      newState.withdrawalCount !== oldState.withdrawalCount + 1n) {
      throw new Error("local-word withdrawal settlement");
    }
    const payout = view.outputs[LOCAL_WORD_PAYOUT_OUTPUT]!;
    if (payout.token !== undefined || payout.valueSatoshis <= 0n ||
      -publicAmountSats !== payout.valueSatoshis + minerFeeSats) {
      throw new Error("local-word withdrawal value relation");
    }
    payoutLockingDigest = hashPayoutLocking(payout.lockingBytecode);
    const dataOutput = view.outputs[LOCAL_WORD_NULLIFIER_DATA_OUTPUT]!;
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
    throw new Error("local-word zero reserve transition");
  }

  const profile = action === "DEPOSIT"
    ? "deposit"
    : eq32(oldState.noteRoot, newState.noteRoot)
      ? "withdraw-full"
      : "withdraw-change";
  const profileIndex = { deposit: 0, "withdraw-full": 1, "withdraw-change": 2 }[profile];
  const bankDigest = localWordVerifierBankDigestFromLockingBytecodes(
    view.sourceOutputs.slice(1, LOCAL_WORD_CARRIER_INPUTS).map((output) => output.lockingBytecode),
  );
  if (!eq32(bankDigest, authorizedBankDigests[profileIndex])) {
    throw new Error("local-word unauthorized verifier bank");
  }
  return {
    minerFeeSats,
    profile,
    nullifierPath,
    statement: {
      profile: "any-amount-v0",
      action,
      publicAmountSats,
      netBlind: new Uint8Array(32),
      oldState,
      newState,
      // These legacy host fields are intentionally absent from the successor
      // public encoding and relation boundary.
      noteCommitment: new Uint8Array(32),
      nullifier,
      payoutLockingDigest,
      amountCommitIn: new Uint8Array(32),
      amountCommitOut: new Uint8Array(32),
    },
  };
}

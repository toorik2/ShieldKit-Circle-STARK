import {
  LOCAL_WORD_FRI_MERKLE_STAGE_GEOMETRY,
  LOCAL_WORD_MATRIX_NAMES,
  localWordMatrixMerkleStageGeometry,
  localWordMerkleFrontierLevels,
} from "../backends/circle/local-word-sealed-proof.ts";
import {
  LOCAL_WORD_PRODUCTION_PARAMETERS,
  localWordFriLayerLogs,
} from "../backends/circle/local-word-successor-params.ts";
import {
  compileLocalWordHeaderGate,
  compileLocalWordOpeningScheduleGate,
  compileLocalWordPublicBoundaryInverseBatchGate,
  compileLocalWordPublicBoundarySumGate,
  compileLocalWordQueryScheduleGate,
  compileLocalWordSparseNullifierGate,
  compileLocalWordTranscriptManifestGate,
  compileLocalWordValueSettlementGate,
  localWordPublicWordCount,
} from "./local-word-balanced-vm.ts";
import {
  compileLocalWordCompositionBatchGate,
  compileLocalWordFriFoldGate,
} from "./local-word-algebra-vm.ts";
import {
  compileLocalWordCurrentMatrixMerkleGate,
  compileLocalWordFriMerkleGate,
  compileLocalWordInteractionLeafGate,
  LOCAL_WORD_INTERACTION_LEAF_SHARDS,
} from "./local-word-merkle-vm.ts";
import {
  compileLocalWordCarrierRedeem,
  compileLocalWordPoolCarrierRedeem,
  encodeLocalWordP2shCarrierUnlocking,
  LOCAL_WORD_CARRIER_INPUTS,
  LOCAL_WORD_PRIMARY_CARRIER_INPUTS,
  localWordVerifierBankDigestFromRedeems,
  partitionLocalWordProofBytes,
  type LocalWordProofCarrier,
  type LocalWordVerifierBankDigests,
} from "./local-word-proof-carriers.ts";
import {
  LOCAL_WORD_CARRIER_BUDGETS,
  localWordVerifierRoleBudget,
} from "./local-word-carrier-allocation.ts";
import { compileLocalWordAirPartsGate } from "./sha256-local-word-vm.ts";

export type LocalWordVerifierRole = {
  readonly index: number;
  readonly name: string;
  readonly carrier: LocalWordProofCarrier;
  readonly verifier: Uint8Array;
  readonly redeem: Uint8Array;
  readonly unlockingBytecode: Uint8Array;
};

export type LocalWordVerifierBankArgs = {
  readonly profile: 0 | 1 | 2;
  readonly proofBytes: Uint8Array;
  readonly constructionId: Uint8Array;
  readonly constructionDigest: Uint8Array;
  readonly expectedPreprocessedRoot: Uint8Array;
};

export type LocalWordVerifierManifestArgs = LocalWordVerifierBankArgs & {
  readonly authorizedBankDigests: LocalWordVerifierBankDigests;
};

/**
 * Compile one persistent profile-specific verifier bank. Roles remain in
 * semantic order; the canonical budget table gives each one exactly one
 * contiguous proof slice. Input zero is the universal pool lock and is
 * compiled only after all three bank commitments.
 */
export function compileLocalWordVerifierBank(
  args: LocalWordVerifierBankArgs,
): readonly LocalWordVerifierRole[] {
  if (args.constructionId.length !== 32 || args.constructionDigest.length !== 32 ||
    args.expectedPreprocessedRoot.length !== 32 || args.proofBytes[5] !== args.profile) {
    throw new Error("local-word verifier manifest identity");
  }
  const carriers = partitionLocalWordProofBytes(args.proofBytes);
  const publicWordCount = localWordPublicWordCount(args.profile);
  const parameters = LOCAL_WORD_PRODUCTION_PARAMETERS;
  const raw: { readonly name: string; readonly verifier: Uint8Array }[] = [];
  const add = (name: string, verifier: Uint8Array): void => {
    raw.push({ name, verifier });
  };

  for (let query = 0; query < parameters.fri.queries; query += 1) {
    add(`query:${query}:air`, compileLocalWordAirPartsGate({
      profile: args.profile,
      query,
      parts: [0, 1, 2],
    }));
  }
  const boundaryBatchWidth = Math.ceil(publicWordCount / 3);
  for (let start = 0; start < publicWordCount; start += boundaryBatchWidth) {
    const count = Math.min(boundaryBatchWidth, publicWordCount - start);
    add(`boundary:${start}-${start + count - 1}`, compileLocalWordPublicBoundaryInverseBatchGate({
      profile: args.profile,
      start,
      count,
    }));
  }
  if (raw.length !== LOCAL_WORD_PRIMARY_CARRIER_INPUTS - 1) {
    throw new Error("local-word primary verifier manifest");
  }

  add("header", compileLocalWordHeaderGate({
    profile: args.profile,
    constructionDigest: args.constructionDigest,
    expectedPreprocessedRoot: args.expectedPreprocessedRoot,
    publicWordCount,
  }));
  for (const root of ["absence", "used"] as const) {
    for (const segment of [0, 1] as const) {
      add(`nullifier:${root}:${segment}`, compileLocalWordSparseNullifierGate(root, segment));
    }
  }
  add("boundary:sum", compileLocalWordPublicBoundarySumGate(args.profile));
  for (const part of ["interaction", "composition", "batch", "fri-first", "fri-second", "final"] as const) {
    add(`transcript:${part}`, compileLocalWordTranscriptManifestGate({
      constructionId: args.constructionId,
      publicWordCount,
      part,
    }));
  }
  add("query-schedule", compileLocalWordQueryScheduleGate({ publicWordCount }));
  add("opening:current", compileLocalWordOpeningScheduleGate({
    publicWordCount,
    opening: "current",
  }));
  for (const stage of ["current", "previous", "shape"] as const) {
    add(`opening:global-${stage}`, compileLocalWordOpeningScheduleGate({
      publicWordCount,
      opening: "global",
      stage,
    }));
  }
  for (let friLayer = 0; friLayer < localWordFriLayerLogs(parameters).length; friLayer += 1) {
    add(`opening:fri:${friLayer}`, compileLocalWordOpeningScheduleGate({
      publicWordCount,
      opening: "fri",
      friLayer,
    }));
  }

  for (let query = 0; query < parameters.fri.queries; query += 1) {
    add(`query:${query}:algebra`, compileLocalWordCompositionBatchGate({
      profile: args.profile,
      query,
    }));
    add(`query:${query}:fri`, compileLocalWordFriFoldGate({ profile: args.profile, query }));
  }

  const treeLevels = parameters.evalLog / 2;
  for (const matrix of ["preprocessed", "original", "interaction", "quotientAndFriMask"] as const) {
    const levels = localWordMerkleFrontierLevels(
      treeLevels,
      localWordMatrixMerkleStageGeometry(matrix),
    );
    if (matrix === "interaction") {
      for (let shard = 0; shard < LOCAL_WORD_INTERACTION_LEAF_SHARDS; shard += 1) {
        add(`merkle:${matrix}:leaf:${shard}`, compileLocalWordInteractionLeafGate({
          shard,
          publicWordCount,
        }));
      }
      for (let stage = 1; stage <= levels.length; stage += 1) {
        add(`merkle:${matrix}:${stage}`, compileLocalWordCurrentMatrixMerkleGate({
          matrix,
          publicWordCount,
          stage,
        }));
      }
    } else {
      for (let stage = 0; stage <= levels.length; stage += 1) {
        add(`merkle:${matrix}:${stage}`, compileLocalWordCurrentMatrixMerkleGate({
          matrix,
          publicWordCount,
          stage,
        }));
      }
    }
  }
  const globalLevels = localWordMerkleFrontierLevels(
    treeLevels,
    localWordMatrixMerkleStageGeometry("interactionGlobal"),
  );
  for (let stage = 0; stage <= globalLevels.length; stage += 1) {
    add(`merkle:interactionGlobal:${stage}`, compileLocalWordCurrentMatrixMerkleGate({
      matrix: "interactionGlobal",
      publicWordCount,
      stage,
    }));
  }
  for (const [layer, logRows] of localWordFriLayerLogs(parameters).entries()) {
    const levels = localWordMerkleFrontierLevels(
      logRows / 2,
      LOCAL_WORD_FRI_MERKLE_STAGE_GEOMETRY,
    );
    for (let stage = 0; stage <= levels.length; stage += 1) {
      add(`merkle:fri:${layer}:${stage}`, compileLocalWordFriMerkleGate({
        layer,
        publicWordCount,
        stage,
      }));
    }
  }

  if (raw.length !== LOCAL_WORD_CARRIER_INPUTS - 1 || carriers.length !== raw.length + 1) {
    throw new Error(`local-word verifier manifest count ${raw.length}`);
  }
  return raw.map((role, local): LocalWordVerifierRole => {
    const index = local + 1;
    const carrier = carriers[index]!;
    if (carrier.budget !== LOCAL_WORD_CARRIER_BUDGETS[index] ||
      carrier.budget !== localWordVerifierRoleBudget(role.name)) {
      throw new Error(`local-word verifier budget placement ${role.name}`);
    }
    const redeem = compileLocalWordCarrierRedeem({
      index,
      verifier: role.verifier,
    });
    let unlockingBytecode: Uint8Array;
    try {
      unlockingBytecode = encodeLocalWordP2shCarrierUnlocking(carrier.chunk, redeem);
    } catch (error) {
      throw new Error(`local-word verifier carrier ${role.name}: ${String(error)}`);
    }
    return {
      index,
      name: role.name,
      carrier,
      verifier: role.verifier,
      redeem,
      unlockingBytecode,
    };
  });
}

export function localWordVerifierBankDigest(
  bank: readonly LocalWordVerifierRole[],
): Uint8Array {
  if (bank.length !== LOCAL_WORD_CARRIER_INPUTS - 1 ||
    bank.some((role, local) => role.index !== local + 1)) {
    throw new Error("local-word verifier bank order");
  }
  return localWordVerifierBankDigestFromRedeems(bank.map((role) => role.redeem));
}

/** The sole ordered transaction inventory: one universal pool plus one bank. */
export function compileLocalWordVerifierManifest(
  args: LocalWordVerifierManifestArgs,
): readonly LocalWordVerifierRole[] {
  return compileLocalWordVerifierManifestFromBank(args, compileLocalWordVerifierBank(args));
}

export function compileLocalWordVerifierManifestFromBank(
  args: LocalWordVerifierManifestArgs,
  bank: readonly LocalWordVerifierRole[],
): readonly LocalWordVerifierRole[] {
  if (args.authorizedBankDigests.some((digest) => digest.length !== 32)) {
    throw new Error("local-word verifier manifest bank digests");
  }
  if (bank.length !== LOCAL_WORD_CARRIER_INPUTS - 1 ||
    bank.some((role, local) => role.index !== local + 1 ||
      role.carrier.proofLength !== args.proofBytes.length)) {
    throw new Error("local-word verifier manifest bank");
  }
  const carrier = partitionLocalWordProofBytes(args.proofBytes)[0]!;
  if (carrier.budget !== LOCAL_WORD_CARRIER_BUDGETS[0]) {
    throw new Error("local-word settlement budget");
  }
  const verifier = compileLocalWordValueSettlementGate(args.authorizedBankDigests);
  const redeem = compileLocalWordPoolCarrierRedeem(verifier);
  const settlement: LocalWordVerifierRole = {
    index: 0,
    name: "settlement",
    carrier,
    verifier,
    redeem,
    unlockingBytecode: encodeLocalWordP2shCarrierUnlocking(carrier.chunk, redeem),
  };
  const manifest = [settlement, ...bank];
  if (manifest.length !== LOCAL_WORD_CARRIER_INPUTS) {
    throw new Error("local-word verifier manifest count");
  }
  return manifest;
}

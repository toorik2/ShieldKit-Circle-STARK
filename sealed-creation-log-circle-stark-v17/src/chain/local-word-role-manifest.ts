import {
  compileLocalWordHeaderGate,
  compileLocalWordEdgeAppendGate,
  compileLocalWordOpeningScheduleGate,
  compileLocalWordPublicBoundaryInverseBatchGate,
  compileLocalWordPublicBoundarySumGate,
  compileLocalWordQueryScheduleGate,
  compileLocalWordSparseNullifierGate,
  compileLocalWordTranscriptManifestGate,
  compileLocalWordValueSettlementGate,
  localWordPublicWordCount,
} from "./local-word-balanced-vm.ts";
import type { LocalWordProofReader } from "./local-word-balanced-vm.ts";
import {
  compileLocalWordFriBatchGate,
  compileV17LocalWordFriFoldGate,
} from "./local-word-algebra-vm.ts";
import {
  compileLocalWordCurrentMatrixMerkleGate,
  compileLocalWordFriMerkleGate,
  compileLocalWordMerkleLeafGate,
} from "./local-word-merkle-vm.ts";
import {
  compileLocalWordBatchLeaderCarrierRedeem,
  compileLocalWordCarrierRedeem,
  compileLocalWordPoolCarrierRedeem,
  encodeLocalWordP2shBatchLeaderUnlocking,
  encodeLocalWordP2shCarrierUnlocking,
  LOCAL_WORD_BATCH_LEADER_ROLE_ID,
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
import { compileV17OodAirQuotientGate } from "./v17-ood-air-vm.ts";
import { V17_PRODUCTION_ROLE_LAYOUT } from "./v17-role-layout.ts";
import {
  V17_BOOTSTRAP_AFFINE_ALLOCATION,
  type V17AffineAllocation,
} from "./v17-affine-allocation.ts";
import {
  compileV17AffineReaderConstruction,
  type V17AffineReaderConstruction,
} from "./v17-affine-reader-vm.ts";
import { encodeV17BatchLeaderCell } from
  "../backends/circle/v17-batch-leader-cell.ts";

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
  readonly allocation?: V17AffineAllocation;
};

export type LocalWordVerifierProgramArgs = Omit<
  LocalWordVerifierBankArgs,
  "proofBytes" | "allocation"
> & {
  readonly affineReader: V17AffineReaderConstruction;
};

export type LocalWordVerifierProgram = {
  readonly index: number;
  readonly name: string;
  readonly verifier: Uint8Array;
  readonly redeem: Uint8Array;
};

export type LocalWordVerifierManifestArgs = LocalWordVerifierBankArgs & {
  readonly authorizedBankDigests: LocalWordVerifierBankDigests;
};

/** Single production selection point; the legacy gate remains a test oracle. */
export function compileLocalWordProductionFriFoldGate(args: {
  readonly profile: 0 | 1 | 2;
  readonly query: number;
  readonly reader?: LocalWordProofReader;
}): Uint8Array {
  return compileV17LocalWordFriFoldGate(args);
}

/**
 * Compile the carrier-independent verifier programs. This is the pre-link
 * surface: it deliberately does not partition a proof or claim that the
 * resulting unlinked programs fit beside a production-sized carrier slice.
 */
export function compileLocalWordVerifierPrograms(
  args: LocalWordVerifierProgramArgs,
): readonly LocalWordVerifierProgram[] {
  if (args.constructionId.length !== 32 || args.constructionDigest.length !== 32 ||
    args.expectedPreprocessedRoot.length !== 32) {
    throw new Error("local-word verifier program identity");
  }
  const publicWordCount = localWordPublicWordCount(args.profile);
  const reader = args.affineReader.vm;
  const raw: { readonly name: string; readonly verifier: Uint8Array }[] = [];
  const add = (name: string, verifier: Uint8Array): void => {
    raw.push({ name, verifier });
  };

  for (const role of V17_PRODUCTION_ROLE_LAYOUT.slice(1)) {
    switch (role.kind) {
      case "settlement": throw new Error("local-word duplicate settlement role");
      case "ood-air":
        add(role.id, compileV17OodAirQuotientGate({ profile: args.profile, reader }));
        break;
      case "batch-link-query":
        add(role.id, compileLocalWordFriBatchGate({
          profile: args.profile, query: role.query, reader,
        }));
        break;
      case "public-boundary-inverses":
        add(role.id, compileLocalWordPublicBoundaryInverseBatchGate({
          profile: args.profile, start: 0, count: publicWordCount, reader,
        }));
        break;
      case "proof-header":
        add(role.id, compileLocalWordHeaderGate({
          profile: args.profile,
          protocolId: args.constructionId,
          expectedPreprocessedRoot: args.expectedPreprocessedRoot,
          publicWordCount,
          reader,
        }));
        break;
      case "edge-append":
        add(role.id, compileLocalWordEdgeAppendGate(reader));
        break;
      case "sparse-nullifier":
        add(role.id, compileLocalWordSparseNullifierGate(role.root, role.segment, reader));
        break;
      case "public-boundary-sum":
        add(role.id, compileLocalWordPublicBoundarySumGate(args.profile, reader));
        break;
      case "transcript":
        add(role.id, compileLocalWordTranscriptManifestGate({
          constructionId: args.constructionId, publicWordCount, part: role.part, reader,
        }));
        break;
      case "query-schedule":
        add(role.id, compileLocalWordQueryScheduleGate({ publicWordCount, reader }));
        break;
      case "opening-current":
        add(role.id, compileLocalWordOpeningScheduleGate({
          publicWordCount, opening: "current", reader,
        }));
        break;
      case "opening-global":
        add(role.id, compileLocalWordOpeningScheduleGate({
          publicWordCount, opening: "global", stage: role.stage, reader,
        }));
        break;
      case "opening-fri":
        add(role.id, compileLocalWordOpeningScheduleGate({
          publicWordCount,
          opening: "fri",
          friLayer: role.layer,
          stage: role.stage,
          reader,
          ...(role.stage === "current"
            ? { mappingShard: role.mappingShard!, mappingShards: 2 }
            : {}),
        }));
        break;
      case "fri-fold-query":
        add(role.id, compileLocalWordProductionFriFoldGate({
          profile: args.profile, query: role.query, reader,
        }));
        break;
      case "matrix-merkle-leaf":
        add(role.id, compileLocalWordMerkleLeafGate({
          matrix: role.matrix, shard: role.shard, shards: role.shards, publicWordCount, reader,
        }));
        break;
      case "matrix-merkle-parent":
        add(role.id, compileLocalWordCurrentMatrixMerkleGate({
          matrix: role.matrix, publicWordCount, stage: role.stage, reader,
        }));
        break;
      case "fri-merkle-leaf":
        add(role.id, compileLocalWordMerkleLeafGate({
          friLayer: role.layer, shard: role.shard, shards: role.shards, publicWordCount, reader,
        }));
        break;
      case "fri-merkle-parent":
        add(role.id, compileLocalWordFriMerkleGate({
          layer: role.layer, publicWordCount, stage: role.stage, reader,
        }));
        break;
    }
  }

  if (raw[LOCAL_WORD_PRIMARY_CARRIER_INPUTS - 1]?.name !== "proof-header") {
    throw new Error("local-word primary verifier manifest");
  }

  if (raw.length !== LOCAL_WORD_CARRIER_INPUTS - 1) {
    throw new Error(`local-word verifier program count ${raw.length}`);
  }
  return raw.map((role, local): LocalWordVerifierProgram => {
    const index = local + 1;
    let redeem: Uint8Array;
    try {
      redeem = role.name === LOCAL_WORD_BATCH_LEADER_ROLE_ID
        ? compileLocalWordBatchLeaderCarrierRedeem({ index, verifier: role.verifier })
        : compileLocalWordCarrierRedeem({ index, verifier: role.verifier });
    } catch (error) {
      throw new Error(`local-word verifier program ${role.name}: ${String(error)}`);
    }
    return { index, name: role.name, verifier: role.verifier, redeem };
  });
}

/**
 * Compile one persistent profile-specific verifier bank. Roles remain in
 * semantic order; the canonical budget table gives each one exactly one
 * contiguous proof slice. Input zero is the universal pool lock and is
 * compiled only after all three bank commitments.
 */
export function compileLocalWordVerifierBank(
  args: LocalWordVerifierBankArgs,
): readonly LocalWordVerifierRole[] {
  if (args.proofBytes[5] !== args.profile) {
    throw new Error("local-word verifier manifest identity");
  }
  const allocation = args.allocation ?? V17_BOOTSTRAP_AFFINE_ALLOCATION;
  const carriers = partitionLocalWordProofBytes(args.proofBytes, allocation);
  const programs = compileLocalWordVerifierPrograms({
    ...args,
    affineReader: compileV17AffineReaderConstruction(allocation),
  });
  const batchLeaderCell = encodeV17BatchLeaderCell(args.proofBytes);
  if (carriers.length !== programs.length + 1) {
    throw new Error(`local-word verifier manifest count ${programs.length}`);
  }
  return programs.map((role, local): LocalWordVerifierRole => {
    const carrier = carriers[role.index]!;
    if (carrier.budget !== LOCAL_WORD_CARRIER_BUDGETS[role.index] ||
      carrier.budget !== localWordVerifierRoleBudget(role.name)) {
      throw new Error(`local-word verifier budget placement ${role.name}`);
    }
    let unlockingBytecode: Uint8Array;
    try {
      unlockingBytecode = role.name === LOCAL_WORD_BATCH_LEADER_ROLE_ID
        ? encodeLocalWordP2shBatchLeaderUnlocking(carrier.chunk, batchLeaderCell, role.redeem)
        : encodeLocalWordP2shCarrierUnlocking(carrier.chunk, role.redeem);
    } catch (error) {
      throw new Error(`local-word verifier carrier ${role.name}: ${String(error)}`);
    }
    return {
      ...role,
      carrier,
      unlockingBytecode,
    };
  });
}

export function localWordVerifierBankDigest(
  bank: readonly LocalWordVerifierRole[],
  profile: 0 | 1 | 2,
  allocation: V17AffineAllocation = V17_BOOTSTRAP_AFFINE_ALLOCATION,
): Uint8Array {
  if (bank.length !== LOCAL_WORD_CARRIER_INPUTS - 1 ||
    bank.some((role, local) => role.index !== local + 1)) {
    throw new Error("local-word verifier bank order");
  }
  return localWordVerifierBankDigestFromRedeems(
    profile, bank.map((role) => role.redeem), allocation,
  );
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
  const carrier = partitionLocalWordProofBytes(
    args.proofBytes, args.allocation ?? V17_BOOTSTRAP_AFFINE_ALLOCATION,
  )[0]!;
  if (carrier.budget !== LOCAL_WORD_CARRIER_BUDGETS[0]) {
    throw new Error("local-word settlement budget");
  }
  const verifier = compileLocalWordValueSettlementGate(
    args.authorizedBankDigests,
    compileV17AffineReaderConstruction(
      args.allocation ?? V17_BOOTSTRAP_AFFINE_ALLOCATION,
    ).vm,
  );
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

import { encodeLocalWordProverBundle } from
  "../backends/circle/local-word-prover-bundle.ts";
import { localWordTranscriptInitial } from
  "../backends/circle/local-word-public-statement.ts";
import { V17_PROOF_PROTOCOL_ID } from
  "../backends/circle/v17-proof-layout.ts";
import {
  encodeLocalWordEdgeData,
  encodeLocalWordNullifierData,
} from "../chain/local-word-envelope.ts";
import { LAB_PAYOUT_DIGEST, LAB_PAYOUT_LOCKING } from "../chain/payout.ts";
import { compilePoolLocalShaGraph } from
  "../chain/pool-relation-local-word-machine.ts";
import { encodePoolLocalShaConstruction } from
  "../chain/sha256-local-word-codec.ts";
import { executeLocalShaProgram } from
  "../chain/sha256-local-word-machine.ts";
import { verifyLocalShaWordCopyOccurrences } from
  "../chain/sha256-local-word-permutation.ts";
import { EdgeHistory } from "../pool/edge-history.ts";
import type { Note } from "../pool/notes.ts";
import { wDeposit, wWithdraw } from "../pool/relation-witness.ts";
import { SparseNullifierTree } from "../pool/sparse-nullifiers.ts";
import { emptyState } from "../pool/state.ts";
import { applyDeposit, applyWithdraw, type PoolMachine } from "../pool/transition.ts";
import { eq32, sha256 } from "../pool/bytes.ts";
import {
  V17_CONSTRUCTION_GRAPH,
  v17ProtocolIdHex,
  type V17Profile,
} from "./v17-graph.ts";
import type { V17PublicSettlementFixture } from "./v17-settlement-transaction.ts";

export const V17_LAB_MINER_FEE_SATOSHIS = 1_000n;
export const V17_LAB_POOL_CATEGORY = new Uint8Array(32).fill(0x42);

const SPENT_NOTE: Note = {
  amountSats: 20_041n,
  rho: new Uint8Array(32).fill(0x41),
  ownerSecret: new Uint8Array(32).fill(0xbe),
};

function machine(): PoolMachine {
  return {
    state: emptyState(),
    poolCategory: V17_LAB_POOL_CATEGORY,
    history: new EdgeHistory(),
    nullifiers: new SparseNullifierTree(),
  };
}

function bytes32(hex: string, label: string): Uint8Array {
  if (!/^[0-9a-f]{64}$/.test(hex)) throw new Error(`v17 lab fixture ${label}`);
  return Uint8Array.from(Buffer.from(hex, "hex"));
}

function profileTransition(profile: V17Profile) {
  if (profile === 0) {
    const deposited = applyDeposit(machine(), SPENT_NOTE);
    return {
      statement: deposited.statement,
      witness: wDeposit(SPENT_NOTE),
      append: deposited.append,
      nullifierPath: undefined,
    };
  }
  const deposited = applyDeposit(machine(), SPENT_NOTE);
  if (profile === 1) {
    const withdrawn = applyWithdraw(
      deposited.machine,
      deposited.created,
      LAB_PAYOUT_DIGEST,
      SPENT_NOTE.amountSats,
    );
    return {
      statement: withdrawn.statement,
      witness: wWithdraw({
        ...deposited.created,
        path: withdrawn.membership.path,
      }),
      append: undefined,
      nullifierPath: withdrawn.nullifierPath,
    };
  }
  const withdrawn = applyWithdraw(
    deposited.machine,
    deposited.created,
    LAB_PAYOUT_DIGEST,
    7_777n,
    { changeRho: new Uint8Array(32).fill(0x43) },
  );
  if (withdrawn.change === undefined || withdrawn.append === undefined) {
    throw new Error("v17 lab fixture missing change");
  }
  return {
    statement: withdrawn.statement,
    witness: wWithdraw({
      ...deposited.created,
      path: withdrawn.membership.path,
    }, withdrawn.change.note),
    append: withdrawn.append,
    nullifierPath: withdrawn.nullifierPath,
  };
}

export function buildV17LabProductFixture(profile: V17Profile) {
  const transition = profileTransition(profile);
  const graph = compilePoolLocalShaGraph(
    transition.statement,
    transition.witness,
    V17_LAB_MINER_FEE_SATOSHIS,
  );
  const execution = executeLocalShaProgram(graph.program, graph.inputs);
  const occurrenceViolation = verifyLocalShaWordCopyOccurrences(graph.program, execution);
  if (occurrenceViolation !== undefined) {
    throw new Error(`v17 lab fixture word-copy ${JSON.stringify(occurrenceViolation)}`);
  }
  const constructionDescriptor = encodePoolLocalShaConstruction(graph);
  const constructionDigest = sha256(constructionDescriptor);
  const key = V17_CONSTRUCTION_GRAPH.verifierKeyDigests[profile];
  if (key?.profile !== profile || key.status !== "derived-v17" ||
    !eq32(constructionDigest, bytes32(key.relationConstructionDigestHex, "construction digest")) ||
    Buffer.from(V17_PROOF_PROTOCOL_ID).toString("hex") !== v17ProtocolIdHex()) {
    throw new Error(`v17 lab fixture verifier key ${profile}`);
  }
  const publicWords = graph.inputLayout
    .filter((input) => input.visibility === "public")
    .map((input, index) => ({
      id: BigInt(index + 1),
      row: input.wire,
      expected: input.value,
    }));
  if (publicWords.length !== 8) throw new Error(`v17 lab fixture public words ${profile}`);
  const settlementFixture: V17PublicSettlementFixture = profile === 0
    ? {
      profile,
      statement: transition.statement,
      minerFeeSatoshis: V17_LAB_MINER_FEE_SATOSHIS,
      edgeDataLockingBytecode: encodeLocalWordEdgeData({
        creationIndex: transition.append!.index,
        edge: transition.append!.edge,
        path: transition.append!.path,
      }),
      funding: {
        // An explicit transparent OP_TRUE lab coin. This is an offline fixture,
        // not a real UTXO or funding claim.
        lockingBytecode: Uint8Array.of(0x51),
        unlockingBytecode: new Uint8Array(),
      },
    }
    : {
      profile,
      statement: transition.statement,
      minerFeeSatoshis: V17_LAB_MINER_FEE_SATOSHIS,
      payoutLockingBytecode: LAB_PAYOUT_LOCKING,
      nullifierDataLockingBytecode: encodeLocalWordNullifierData({
        nullifier: transition.statement.nullifier,
        path: transition.nullifierPath!,
      }),
      ...(profile === 2 ? {
        edgeDataLockingBytecode: encodeLocalWordEdgeData({
          creationIndex: transition.append!.index,
          edge: transition.append!.edge,
          path: transition.append!.path,
        }),
      } : {}),
    } as V17PublicSettlementFixture;
  return {
    profile,
    statement: transition.statement,
    relationGraph: graph,
    constructionDescriptor,
    constructionDigest,
    expectedPreprocessedRoot: bytes32(key.preprocessedRootHex, "preprocessed root"),
    publicWords,
    transcriptInitial: localWordTranscriptInitial(
      transition.statement,
      V17_PROOF_PROTOCOL_ID,
      V17_LAB_MINER_FEE_SATOSHIS,
    ),
    bundle: encodeLocalWordProverBundle({
      statement: transition.statement,
      constructionId: V17_PROOF_PROTOCOL_ID,
      graph,
      minerFeeSats: V17_LAB_MINER_FEE_SATOSHIS,
    }),
    settlementFixture,
  } as const;
}

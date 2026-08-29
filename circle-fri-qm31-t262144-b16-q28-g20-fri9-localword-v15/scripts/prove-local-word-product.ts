import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import {
  createInstructionSetBch2026,
  createVirtualMachine,
  createVirtualMachineBch2026,
  decodeAuthenticationInstructions,
  encodeLockingBytecodeP2sh32,
  encodeTransaction,
  hash256,
  OpcodesBch,
} from "@bitauth/libauth";
import { wWithdraw } from "../src/pool/relation-witness.ts";
import { encodeLocalWordProverBundle } from
  "../src/backends/circle/local-word-prover-bundle.ts";
import { localWordTranscriptInitial } from
  "../src/backends/circle/local-word-public-statement.ts";
import { verifyLocalWordSealedProofBytes } from
  "../src/backends/circle/local-word-verifier.ts";
import {
  LOCAL_WORD_V15_CONSTRUCTION_ID,
  LOCAL_WORD_V15_CONSTRUCTION_ID_HEX,
} from "../src/backends/circle/local-word-construction-v15.ts";
import {
  decodeLocalWordSealedProof,
  localWordProofDirectory,
  localWordProofStaticOffsets,
  LOCAL_WORD_MATRIX_NAMES,
  LOCAL_WORD_MATRIX_ROW_WIDTHS,
  LOCAL_WORD_PROOF_VERSION,
} from "../src/backends/circle/local-word-sealed-proof.ts";
import { localWordV15VerifierKey } from
  "../src/backends/circle/local-word-verifier-keys-v15.ts";
import { analyzeLocalWordObserverTransaction } from
  "../src/backends/circle/local-word-observer-view.ts";
import {
  compilePoolLocalShaGraph,
} from "../src/chain/pool-relation-local-word-machine.ts";
import { encodePoolLocalShaConstruction } from
  "../src/chain/sha256-local-word-codec.ts";
import { executeLocalShaProgram } from
  "../src/chain/sha256-local-word-machine.ts";
import { verifyLocalShaWordCopyOccurrences } from
  "../src/chain/sha256-local-word-permutation.ts";
import {
  deriveLocalWordPublicSettlement,
  encodeLocalWordNullifierData,
  type LocalWordSourceOutput,
} from "../src/chain/local-word-envelope.ts";
import {
  locateLocalWordProofByte,
  localWordVerifierCarrierValue,
  localWordVerifierCarrierSequence,
  localWordPoolCarrierSequence,
  partitionLocalWordProofBytes,
  reassembleLocalWordProofBytes,
} from "../src/chain/local-word-proof-carriers.ts";
import {
  compileLocalWordVerifierBank,
  compileLocalWordVerifierManifestFromBank,
  localWordVerifierBankDigest,
} from
  "../src/chain/local-word-role-manifest.ts";
import { LOCAL_WORD_V15_VERIFIER_BANK_DIGESTS } from
  "../src/chain/local-word-verifier-bank-digests-v15.ts";
import { LAB_PAYOUT_DIGEST, LAB_PAYOUT_LOCKING } from "../src/chain/payout.ts";
import { eq32, sha256, ZERO32 } from "../src/pool/bytes.ts";
import {
  IncrementalMerkle,
  commitNote,
  nullifierOf,
  type Note,
} from "../src/pool/notes.ts";
import { SparseNullifierTree } from "../src/pool/sparse-nullifiers.ts";
import { emptyState, encodePublicPaa1, STATE_BASE_SATS } from "../src/pool/state.ts";
import type { PoolStatement } from "../src/pool/statement.ts";

const constructionId = LOCAL_WORD_V15_CONSTRUCTION_ID;
const constructionIdHex = LOCAL_WORD_V15_CONSTRUCTION_ID_HEX;
const minerFeeSats = 1_000n;
const withdrawalSats = 7_777n;
const category = new Uint8Array(32).fill(0x42);
const spent: Note = {
  amountSats: 20_041n,
  rho: new Uint8Array(32).fill(0x41),
  ownerSecret: new Uint8Array(32).fill(0xbe),
};
const change: Note = {
  amountSats: spent.amountSats - withdrawalSats,
  rho: new Uint8Array(32).fill(0x52),
  ownerSecret: spent.ownerSecret,
};

const notes = new IncrementalMerkle();
const deposited = notes.append(commitNote(spent));
const oldBase = {
  ...emptyState(new Uint8Array(32).fill(0x42)),
  sequence: 1n,
  reserveSats: spent.amountSats,
  depositCount: 1n,
  noteRoot: deposited.root,
};
const spentPath = notes.authPath(deposited.index);
const created = notes.append(commitNote(change));
const nullifier = nullifierOf(spent, oldBase.poolInstanceId);
const nullifiers = new SparseNullifierTree();
const inserted = nullifiers.insert(nullifier);
const oldState = { ...oldBase, nullifierRoot: inserted.oldRoot };
const newState = {
  ...oldState,
  sequence: oldState.sequence + 1n,
  reserveSats: oldState.reserveSats - withdrawalSats,
  withdrawalCount: oldState.withdrawalCount + 1n,
  noteRoot: created.root,
  nullifierRoot: inserted.newRoot,
};
const withdrawalWitness = wWithdraw(spent, deposited.index, spentPath, {
  note: change,
  index: created.index,
  path: created.path,
});
const statement: PoolStatement = {
  profile: "any-amount-v0",
  action: "WITHDRAW",
  publicAmountSats: -withdrawalSats,
  netBlind: new Uint8Array(32),
  oldState,
  newState,
  noteCommitment: new Uint8Array(32),
  nullifier,
  payoutLockingDigest: LAB_PAYOUT_DIGEST,
  amountCommitIn: new Uint8Array(ZERO32),
  amountCommitOut: new Uint8Array(ZERO32),
};
const graph = compilePoolLocalShaGraph(
  statement,
  withdrawalWitness,
  minerFeeSats,
);
const occurrenceViolation = verifyLocalShaWordCopyOccurrences(
  graph.program,
  executeLocalShaProgram(graph.program, graph.inputs),
);
assert.equal(occurrenceViolation, undefined, JSON.stringify(occurrenceViolation));
const constructionDescriptor = encodePoolLocalShaConstruction(graph);
const constructionDigest = sha256(constructionDescriptor);
const bundle = encodeLocalWordProverBundle({
  statement,
  constructionId,
  graph,
  minerFeeSats,
});
const dryRun = process.argv.includes("--dry-run");
const proofCacheArgument = process.argv.find((argument) => argument.startsWith("--proof-cache="));
const proofCachePath = resolve(
  proofCacheArgument?.slice("--proof-cache=".length) ?? ".local/local-word-product-v15-proof.json",
);
let interactionPreflight = false;
if (!dryRun || process.argv.includes("--preflight")) {
  const preflight = spawnSync(
    "cargo",
    [
      "+nightly-2026-01-15",
      "run",
      "--release",
      "--quiet",
      "--manifest-path",
      "crates/circle-fri-worker/Cargo.toml",
    ],
    {
      cwd: process.cwd(),
      input: JSON.stringify({
        cmd: "local-word-bundle-kat",
        bundleHex: Buffer.from(bundle).toString("hex"),
      }),
      encoding: "utf8",
      maxBuffer: 64 * 1024 * 1024,
    },
  );
  if (preflight.status !== 0) throw new Error(preflight.stderr || preflight.stdout);
  const checked = JSON.parse(preflight.stdout.trim()) as {
    readonly ok: boolean;
    readonly interactionPreflight: boolean;
    readonly activeWordSlots: number;
  };
  assert.equal(checked.ok, true);
  assert.equal(checked.interactionPreflight, true);
  assert.ok(checked.activeWordSlots > 0);
  interactionPreflight = true;
}

if (dryRun) {
  console.log("local-word-product-dry-run", JSON.stringify({
    profile: graph.profile,
    bundleBytes: bundle.length,
    constructionBytes: constructionDescriptor.length,
    constructionId: constructionIdHex,
    constructionDigest: Buffer.from(constructionDigest).toString("hex"),
    programRows: graph.program.rows.length,
    relationInputs: graph.inputs.length,
    publicWords: graph.inputLayout.filter((input) => input.visibility === "public").length,
    compressions: graph.compressions,
    hasChange: graph.hasChange,
    minerFeeSats: minerFeeSats.toString(),
    interactionPreflight,
  }));
  process.exit(0);
}

type ProvedProduct = {
  readonly ok: boolean;
  readonly profile: number;
  readonly proofHex: string;
  readonly proofBytes: number;
  readonly constructionDigestHex: string;
  readonly constructionIdHex?: string;
  readonly proofVersion?: number;
  readonly expectedPreprocessedRootHex: string;
  readonly publicWords: number;
  readonly quotientDegreeBound: number;
};
const constructionDigestHex = Buffer.from(constructionDigest).toString("hex");
let proofSource: "cache" | "generated" = "generated";
let proved: ProvedProduct | undefined;
if (!process.argv.includes("--fresh-proof") && existsSync(proofCachePath)) {
  const cached = JSON.parse(readFileSync(proofCachePath, "utf8")) as ProvedProduct & {
    readonly cacheVersion?: number;
  };
  if (cached.cacheVersion === 2 && cached.ok === true && cached.profile === 2 &&
    cached.publicWords === 34 && cached.proofVersion === LOCAL_WORD_PROOF_VERSION &&
    cached.constructionIdHex === constructionIdHex &&
    cached.constructionDigestHex === constructionDigestHex) {
    proved = cached;
    proofSource = "cache";
  }
}
if (proved === undefined) {
  const worker = spawnSync(
    "cargo",
    [
      "+nightly-2026-01-15",
      "run",
      "--release",
      "--quiet",
      "--manifest-path",
      "crates/circle-fri-worker/Cargo.toml",
    ],
    {
      cwd: process.cwd(),
      input: JSON.stringify({
        cmd: "local-word-prove",
        bundleHex: Buffer.from(bundle).toString("hex"),
      }),
      encoding: "utf8",
      maxBuffer: 64 * 1024 * 1024,
    },
  );
  if (worker.status !== 0) throw new Error(worker.stderr || worker.stdout);
  proved = JSON.parse(worker.stdout.trim()) as ProvedProduct;
}
assert.equal(proved.ok, true);
assert.equal(proved.profile, 2);
assert.equal(proved.publicWords, 34);
assert.equal(proved.constructionDigestHex, constructionDigestHex);
const proofBytes = new Uint8Array(Buffer.from(proved.proofHex, "hex"));
assert.equal(proofBytes.length, proved.proofBytes);
const expectedPreprocessedRoot = new Uint8Array(
  Buffer.from(proved.expectedPreprocessedRootHex, "hex"),
);
const profileKey = localWordV15VerifierKey(2);
assert.deepEqual(constructionDigest, profileKey.constructionDigest);
assert.deepEqual(expectedPreprocessedRoot, profileKey.preprocessedRoot);
const publicWords = graph.inputLayout
  .filter((input) => input.visibility === "public")
  .map((input, index) => ({
    id: BigInt(index + 1),
    row: input.wire,
    expected: input.value,
  }));
const transcriptInitial = localWordTranscriptInitial(statement, constructionId, minerFeeSats);
const proofContext = {
  profile: 2,
  transcriptInitial,
  constructionDescriptor,
  publicWords,
  expectedPreprocessedRoot,
} as const;
const reference = verifyLocalWordSealedProofBytes(proofBytes, proofContext);
assert.equal(reference.ok, true, reference.ok ? undefined : reference.reason);
if (proofSource === "generated") {
  mkdirSync(dirname(proofCachePath), { recursive: true });
  const temporary = `${proofCachePath}.tmp`;
  writeFileSync(temporary, `${JSON.stringify({
    cacheVersion: 2,
    constructionIdHex,
    proofVersion: LOCAL_WORD_PROOF_VERSION,
    ...proved,
  })}\n`, { mode: 0o600 });
  renameSync(temporary, proofCachePath);
  console.error(`local-word-proof-cache saved ${proofCachePath}`);
} else {
  console.error(`local-word-proof-cache reused ${proofCachePath}`);
}

const verifierKey = {
  profile: 2,
  proofBytes,
  constructionId,
  constructionDigest,
  expectedPreprocessedRoot,
} as const;
const bank = compileLocalWordVerifierBank(verifierKey);
const bankDigest = localWordVerifierBankDigest(bank);
const authorizedBankDigests = LOCAL_WORD_V15_VERIFIER_BANK_DIGESTS;
assert.deepEqual(bankDigest, authorizedBankDigests[2]);
const roles = compileLocalWordVerifierManifestFromBank(
  { ...verifierKey, authorizedBankDigests },
  bank,
);
const roleLocks = roles.map((role) => encodeLockingBytecodeP2sh32(hash256(role.redeem)));
const poolToken = (commitment: Uint8Array) => ({
  category,
  amount: 0n,
  nft: { capability: "mutable" as const, commitment },
});
const sourceOutputs: LocalWordSourceOutput[] = roles.map((_, index) => index === 0
  ? {
    lockingBytecode: roleLocks[0]!,
    valueSatoshis: STATE_BASE_SATS + oldState.reserveSats,
    token: poolToken(encodePublicPaa1(oldState)),
  }
  : { lockingBytecode: roleLocks[index]!, valueSatoshis: localWordVerifierCarrierValue(index) });
const outputs = [
  {
    lockingBytecode: roleLocks[0]!,
    valueSatoshis: STATE_BASE_SATS + newState.reserveSats,
    token: poolToken(encodePublicPaa1(newState)),
  },
  ...roles.slice(1).map((_, index) => ({
    lockingBytecode: roleLocks[index + 1]!,
    valueSatoshis: localWordVerifierCarrierValue(index + 1),
  })),
  {
    lockingBytecode: LAB_PAYOUT_LOCKING,
    valueSatoshis: withdrawalSats - minerFeeSats,
  },
  {
    lockingBytecode: encodeLocalWordNullifierData({ nullifier, path: inserted.path }),
    valueSatoshis: 0n,
  },
];
const transaction = {
  version: 2,
  locktime: 0,
  inputs: roles.map((role, index) => ({
    outpointTransactionHash: new Uint8Array(32).fill((index + 1) & 0xff),
    outpointIndex: index,
    sequenceNumber: index === 0
      ? localWordPoolCarrierSequence(proofBytes.length)
      : localWordVerifierCarrierSequence(index),
    unlockingBytecode: role.unlockingBytecode,
  })),
  outputs,
};
const settlement = deriveLocalWordPublicSettlement(
  { sourceOutputs, outputs },
  authorizedBankDigests,
);
assert.equal(settlement.profile, "withdraw-change");
assert.equal(settlement.minerFeeSats, minerFeeSats);
assert.equal(settlement.statement.publicAmountSats, statement.publicAmountSats);
assert.equal(eq32(settlement.statement.nullifier, statement.nullifier), true);
assert.deepEqual(
  localWordTranscriptInitial(settlement.statement, constructionId, settlement.minerFeeSats),
  transcriptInitial,
);
const raw = encodeTransaction(transaction);
assert.ok(raw.length <= 1_000_000, `local-word transaction bytes ${raw.length}`);
assert.ok(roles.every((role) => role.redeem.length <= 10_000));
assert.ok(roles.every((role) => role.unlockingBytecode.length <= 10_000));
const observer = analyzeLocalWordObserverTransaction(raw, {
  profile: 2,
  transcriptInitial,
  constructionDescriptor,
  publicWords,
  expectedPreprocessedRoot,
});
assert.equal(observer.carrierUnionExact, true);
assert.equal(observer.protectedTraceRecovery.recovered, false);

type ArtifactAuditRejection = {
  readonly label: string;
  readonly reference: string;
  readonly vmRole: { readonly index: number; readonly name: string };
};
let artifactAudit:
  | {
    readonly proofMutations: readonly ArtifactAuditRejection[];
    readonly falseStatement: ArtifactAuditRejection;
    readonly carrierPlacement: {
      readonly reference: string;
      readonly vmRole: { readonly index: number; readonly name: string };
    };
  }
  | undefined;
if (process.argv.includes("--audit")) {
  const vm = createVirtualMachineBch2026(false);
  const firstVmRejection = (
    candidate: typeof transaction,
    preferred: (role: typeof roles[number]) => boolean,
  ): { readonly index: number; readonly name: string } => {
    const ordered = [
      ...roles.filter(preferred),
      ...roles.filter((role) => !preferred(role)),
    ];
    for (const role of ordered) {
      const state = vm.evaluate({ inputIndex: role.index, sourceOutputs, transaction: candidate } as never);
      if (vm.stateSuccess(state) !== true) return { index: role.index, name: role.name };
    }
    throw new Error("local-word adversarial transaction accepted by every role");
  };
  const decoded = decodeLocalWordSealedProof(proofBytes, proofContext);
  const directory = localWordProofDirectory(decoded.queries, publicWords.length);
  const offsets = localWordProofStaticOffsets(publicWords.length);
  const proofMutationCases = [
    {
      label: "root",
      offset: offsets.matrixRoots + 32,
      preferred: (role: typeof roles[number]) => role.name.startsWith("merkle:original:"),
    },
    {
      label: "opening",
      offset: directory.openings[1]!.rowsStart,
      preferred: (role: typeof roles[number]) => role.name.startsWith("merkle:original:"),
    },
    {
      label: "mask",
      offset: directory.openings[4]!.rowsStart + LOCAL_WORD_MATRIX_ROW_WIDTHS[4] - 16,
      preferred: (role: typeof roles[number]) =>
        role.name.startsWith("merkle:quotientAndFriMask:") || role.name.endsWith(":algebra"),
    },
    {
      label: "fold",
      offset: directory.openings[LOCAL_WORD_MATRIX_NAMES.length]!.rowsStart,
      preferred: (role: typeof roles[number]) =>
        role.name.startsWith("merkle:fri:0:") || role.name.endsWith(":fri"),
    },
  ] as const;
  const proofMutations = proofMutationCases.map(({ label, offset, preferred }) => {
    const alteredProof = proofBytes.slice();
    alteredProof[offset] ^= 1;
    const rejected = verifyLocalWordSealedProofBytes(alteredProof, proofContext);
    assert.equal(rejected.ok, false, `${label} mutation reference-accepted`);
    const alteredTransaction = structuredClone(transaction);
    const location = locateLocalWordProofByte(proofBytes.length, offset);
    const unlocking = alteredTransaction.inputs[location.carrierIndex]!.unlockingBytecode;
    assert.equal(unlocking[0], 0x4d);
    unlocking[3 + location.chunkOffset] ^= 1;
    return {
      label,
      reference: rejected.ok ? "accepted" : rejected.reason,
      vmRole: firstVmRejection(alteredTransaction, preferred),
    };
  });

  const falseState = { ...newState, reserveSats: newState.reserveSats + 1n };
  const falseTransaction = structuredClone(transaction);
  falseTransaction.outputs[0] = {
    lockingBytecode: roleLocks[0]!,
    valueSatoshis: STATE_BASE_SATS + falseState.reserveSats,
    token: poolToken(encodePublicPaa1(falseState)),
  };
  const falseSettlement = deriveLocalWordPublicSettlement(
    { sourceOutputs, outputs: falseTransaction.outputs },
    authorizedBankDigests,
  );
  const falseGraph = compilePoolLocalShaGraph(
    falseSettlement.statement,
    withdrawalWitness,
    falseSettlement.minerFeeSats,
  );
  assert.equal(
    eq32(sha256(encodePoolLocalShaConstruction(falseGraph)), constructionDigest),
    true,
  );
  const falsePublicWords = falseGraph.inputLayout
    .filter((input) => input.visibility === "public")
    .map((input, index) => ({ id: BigInt(index + 1), row: input.wire, expected: input.value }));
  const falseReference = verifyLocalWordSealedProofBytes(proofBytes, {
    ...proofContext,
    transcriptInitial: localWordTranscriptInitial(
      falseSettlement.statement,
      constructionId,
      falseSettlement.minerFeeSats,
    ),
    publicWords: falsePublicWords,
  });
  assert.equal(falseReference.ok, false, "false statement reference-accepted");
  const falseStatement = {
    label: "false-statement",
    reference: falseReference.ok ? "accepted" : falseReference.reason,
    vmRole: firstVmRejection(
      falseTransaction,
      (role) => role.name === "settlement" || role.name.startsWith("boundary:") ||
        role.name === "header" || role.name.startsWith("transcript:"),
    ),
  };

  const misplaced = [...partitionLocalWordProofBytes(proofBytes)];
  [misplaced[1], misplaced[2]] = [misplaced[2]!, misplaced[1]!];
  let carrierReference = "accepted";
  assert.throws(() => reassembleLocalWordProofBytes(misplaced), (error) => {
    carrierReference = String(error);
    return /carrier placement/.test(carrierReference);
  });
  const misplacedTransaction = structuredClone(transaction);
  [misplacedTransaction.inputs[1]!.unlockingBytecode,
    misplacedTransaction.inputs[2]!.unlockingBytecode] = [
    misplacedTransaction.inputs[2]!.unlockingBytecode,
    misplacedTransaction.inputs[1]!.unlockingBytecode,
  ];
  artifactAudit = {
    proofMutations,
    falseStatement,
    carrierPlacement: {
      reference: carrierReference,
      vmRole: firstVmRejection(
        misplacedTransaction,
        (role) => role.index === 1 || role.index === 2,
      ),
    },
  };
  console.error("local-word-artifact-audit", JSON.stringify(artifactAudit));
}

let vmMeasurement:
  | {
    readonly checkedInputs: number;
    readonly maximumOperationCost: number;
    readonly maximumOperationCostRole?: { readonly index: number; readonly name: string };
  }
  | undefined;
let vmRoleMeasurements:
  | readonly {
    readonly index: number;
    readonly name: string;
    readonly operationCost: number;
    readonly maximumOperationCost: number;
    readonly hashDigestIterations: number;
    readonly maximumHashDigestIterations: number;
    readonly redeemBytes: number;
    readonly unlockingBytes: number;
  }[]
  | undefined;
if (process.argv.includes("--vm-unbounded")) {
  const instructionSet = createInstructionSetBch2026(false);
  const every = instructionSet.every!;
  const vm = createVirtualMachine({
    ...instructionSet,
    every: (state) => {
      state.metrics.maximumOperationCost = 1_000_000_000;
      return every(state);
    },
  });
  const measurements = roles.map((role) => {
    const state = vm.evaluate({ inputIndex: role.index, sourceOutputs, transaction } as never);
    assert.equal(vm.stateSuccess(state), true,
      `${role.index}:${role.name}: ${String(state.error)}`);
    return {
      index: role.index,
      name: role.name,
      operationCost: Number(state.metrics.operationCost),
      densityControlLength: Number(state.metrics.densityControlLength),
      requiredDensityBytes: Math.ceil(Number(state.metrics.operationCost) / 800),
      chunkBytes: role.carrier.chunk.length,
      redeemBytes: role.redeem.length,
      requiredChunkBytes: Math.max(
        256,
        Math.ceil(Number(state.metrics.operationCost) / 800) -
          (Number(state.metrics.densityControlLength) - role.carrier.chunk.length),
      ),
    };
  });
  mkdirSync(resolve(".local"), { recursive: true });
  writeFileSync(
    resolve(".local/local-word-vm-unbounded.json"),
    `${JSON.stringify(measurements, null, 2)}\n`,
    { mode: 0o600 },
  );
  console.error("local-word-vm-unbounded-all saved .local/local-word-vm-unbounded.json");
  const thresholds = [500, 1_000, 1_500, 2_500, 3_500, 4_500, 5_500, 6_500, 7_500];
  const sortedRequirements = [...measurements].sort((left, right) =>
    left.requiredChunkBytes - right.requiredChunkBytes);
  let densityCursor = 0;
  const densityClasses = [50, 50, 40, 20, 21].map((roles) => {
    const members = sortedRequirements.slice(densityCursor, densityCursor + roles);
    densityCursor += roles;
    return {
      maximum: Math.max(...members.map(({ requiredChunkBytes }) => requiredChunkBytes)),
      members: members.map(({ index, name }) => ({ index, name })),
    };
  });
  const optimalClasses = (classCount: number) => {
    const count = sortedRequirements.length;
    const costs = Array.from({ length: classCount + 1 }, () =>
      new Array<number>(count + 1).fill(Number.POSITIVE_INFINITY));
    const cuts = Array.from({ length: classCount + 1 }, () => new Array<number>(count + 1).fill(-1));
    costs[0]![0] = 0;
    for (let classes = 1; classes <= classCount; classes += 1) {
      for (let end = classes; end <= count; end += 1) {
        for (let start = classes - 1; start < end; start += 1) {
          const cost = costs[classes - 1]![start]! +
            (end - start) * sortedRequirements[end - 1]!.requiredChunkBytes;
          if (cost < costs[classes]![end]!) {
            costs[classes]![end] = cost;
            cuts[classes]![end] = start;
          }
        }
      }
    }
    const groups: { readonly roles: number; readonly maximum: number }[] = [];
    let end = count;
    for (let classes = classCount; classes > 0; classes -= 1) {
      const start = cuts[classes]![end]!;
      groups.push({ roles: end - start, maximum: sortedRequirements[end - 1]!.requiredChunkBytes });
      end = start;
    }
    return { classes: classCount, bytes: costs[classCount]![count]!, groups: groups.reverse() };
  };
  console.error("local-word-density-allocation", JSON.stringify({
    proofBytes: proofBytes.length,
    minimumChunkBytes: measurements.reduce((sum, role) => sum + role.requiredChunkBytes, 0),
    thresholds: thresholds.map((maximum, threshold) => ({
      maximum,
      roles: measurements.filter(({ requiredChunkBytes }) =>
        requiredChunkBytes > (threshold === 0 ? 0 : thresholds[threshold - 1]!) &&
        requiredChunkBytes <= maximum).length,
    })),
    above: measurements.filter(({ requiredChunkBytes }) =>
      requiredChunkBytes > thresholds.at(-1)!).map(({ index, name, requiredChunkBytes }) => ({
      index, name, requiredChunkBytes,
    })),
    heaviest: [...measurements].sort((left, right) =>
      right.requiredChunkBytes - left.requiredChunkBytes).slice(0, 32).map(
      ({ index, name, requiredChunkBytes }) => ({ index, name, requiredChunkBytes }),
    ),
    optimalClasses: [3, 4, 5, 6, 7, 8].map(optimalClasses),
    densityClasses,
  }));
  vmMeasurement = {
    checkedInputs: roles.length,
    maximumOperationCost: Math.max(...measurements.map(({ operationCost }) => operationCost)),
  };
} else if (process.argv.includes("--vm")) {
  const vm = createVirtualMachineBch2026(false);
  let maximumOperationCost = 0;
  let maximumOperationCostRole: { readonly index: number; readonly name: string } | undefined;
  const measuredRoles: NonNullable<typeof vmRoleMeasurements>[number][] = [];
  for (const role of roles) {
    if (role.index % 20 === 0) {
      console.error(`local-word-vm-progress ${role.index}/${roles.length}`);
    }
    const state = vm.evaluate({ inputIndex: role.index, sourceOutputs, transaction } as never);
    if (vm.stateSuccess(state) !== true) {
      const instructions = decodeAuthenticationInstructions(role.redeem);
      const names = new Map(Object.entries(OpcodesBch).map(([name, opcode]) => [opcode, name]));
      const first = Math.max(0, state.ip - 6);
      console.error("local-word-vm-failure", JSON.stringify({
        index: role.index,
        name: role.name,
        error: state.error,
        ip: state.ip,
        stackDepth: state.stack.length,
        alternateDepth: state.alternateStack.length,
        stack: state.stack.slice(-10).map((item) => Buffer.from(item).toString("hex")),
        instructions: instructions.slice(first, state.ip + 4).map((instruction, offset) => ({
          at: first + offset,
          op: "data" in instruction ? `push:${instruction.data.length}` : names.get(instruction.opcode),
        })),
        metrics: state.metrics,
      }));
      if (String(state.error).includes("operation cost density")) {
        const instructionSet = createInstructionSetBch2026(false);
        const every = instructionSet.every!;
        const diagnosticVm = createVirtualMachine({
          ...instructionSet,
          every: (diagnosticState) => {
            diagnosticState.metrics.maximumOperationCost = 1_000_000_000;
            return every(diagnosticState);
          },
        });
        const diagnostic = diagnosticVm.evaluate(
          { inputIndex: role.index, sourceOutputs, transaction } as never,
        );
        console.error("local-word-vm-unbounded", JSON.stringify({
          index: role.index,
          name: role.name,
          accepted: diagnosticVm.stateSuccess(diagnostic),
          error: diagnostic.error,
          metrics: diagnostic.metrics,
        }));
      }
    }
    assert.equal(vm.stateSuccess(state), true,
      `${role.index}:${role.name}: ${String(state.error)}`);
    const operationCost = Number(state.metrics.operationCost);
    if (operationCost > maximumOperationCost) {
      maximumOperationCost = operationCost;
      maximumOperationCostRole = { index: role.index, name: role.name };
    }
    measuredRoles.push({
      index: role.index,
      name: role.name,
      operationCost,
      maximumOperationCost: Number(state.metrics.maximumOperationCost),
      hashDigestIterations: Number(state.metrics.hashDigestIterations),
      maximumHashDigestIterations: Number(state.metrics.maximumHashDigestIterations),
      redeemBytes: role.redeem.length,
      unlockingBytes: role.unlockingBytecode.length,
    });
  }
  console.error(`local-word-vm-progress ${roles.length}/${roles.length}`);
  vmRoleMeasurements = measuredRoles;
  vmMeasurement = { checkedInputs: roles.length, maximumOperationCost, maximumOperationCostRole };
}

const candidate = {
  profile: 2,
  proofBytes: proofBytes.length,
  proofSha256: Buffer.from(sha256(proofBytes)).toString("hex"),
  constructionId: constructionIdHex,
  constructionDigest: Buffer.from(constructionDigest).toString("hex"),
  expectedPreprocessedRoot: Buffer.from(expectedPreprocessedRoot).toString("hex"),
  quotientDegreeBound: proved.quotientDegreeBound,
  proofSource,
  roles: roles.length,
  transactionBytes: raw.length,
  transactionSha256: Buffer.from(sha256(raw)).toString("hex"),
  remainingConsensusBytes: 1_000_000 - raw.length,
  bankDigests: authorizedBankDigests.map((digest) => Buffer.from(digest).toString("hex")),
  maxVerifierBytes: Math.max(...roles.map((role) => role.verifier.length)),
  maxRedeemBytes: Math.max(...roles.map((role) => role.redeem.length)),
  maxUnlockingBytes: Math.max(...roles.map((role) => role.unlockingBytecode.length)),
  observer,
  artifactAudit,
  vm: vmMeasurement,
  vmRoles: vmRoleMeasurements,
};
const artifactDirectory = resolve(".local");
mkdirSync(artifactDirectory, { recursive: true });
const reportPath = resolve(artifactDirectory, "local-word-product-v15-report.json");
const proofPath = resolve(artifactDirectory, "local-word-product-v15.proof");
const transactionPath = resolve(artifactDirectory, "local-word-product-v15.tx");
for (const [path, bytes] of [[proofPath, proofBytes], [transactionPath, raw]] as const) {
  const temporary = `${path}.tmp`;
  writeFileSync(temporary, bytes, { mode: 0o600 });
  renameSync(temporary, path);
}
const reportTemporary = `${reportPath}.tmp`;
writeFileSync(reportTemporary, `${JSON.stringify(candidate, null, 2)}\n`, { mode: 0o600 });
renameSync(reportTemporary, reportPath);
console.error("local-word-product-artifacts", JSON.stringify({ reportPath, proofPath, transactionPath }));
const { vmRoles: _vmRoles, ...summary } = candidate;
console.log("local-word-product-candidate", JSON.stringify(summary));

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
import { wDeposit, wWithdraw } from "../src/pool/relation-witness.ts";
import { encodeLocalWordProverBundle } from
  "../src/backends/circle/local-word-prover-bundle.ts";
import { localWordTranscriptInitial } from
  "../src/backends/circle/local-word-public-statement.ts";
import { verifyLocalWordSealedProofBytes } from
  "../src/backends/circle/local-word-verifier.ts";
import {
  V17_PROOF_PROTOCOL_ID,
} from "../src/backends/circle/v17-proof-layout.ts";
import {
  decodeLocalWordSealedProof,
  localWordProofDirectory,
  localWordProofStaticOffsets,
  LOCAL_WORD_MATRIX_NAMES,
  LOCAL_WORD_MATRIX_ROW_WIDTHS,
  LOCAL_WORD_PROOF_VERSION,
} from "../src/backends/circle/local-word-sealed-proof.ts";
import { analyzeLegacyLocalWordObserverTransaction } from
  "../src/backends/circle/local-word-observer-view.ts";
import {
  compilePoolLocalShaGraph,
} from "../src/chain/pool-relation-local-word-machine.ts";
import { encodePoolLocalShaConstruction } from
  "../src/chain/sha256-local-word-codec.ts";
import { executeLocalShaProgram } from
  "../src/chain/sha256-local-word-machine.ts";
import { localShaWordCopySoundness, verifyLocalShaWordCopyOccurrences } from
  "../src/chain/sha256-local-word-permutation.ts";
import {
  deriveLocalWordPublicSettlement,
  encodeLocalWordEdgeData,
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
  type LocalWordVerifierBankDigests,
} from "../src/chain/local-word-proof-carriers.ts";
import {
  compileLocalWordVerifierBank,
  compileLocalWordVerifierManifestFromBank,
  localWordVerifierBankDigest,
} from
  "../src/chain/local-word-role-manifest.ts";
import { V17_PRODUCTION_ROLE_LAYOUT } from "../src/chain/v17-role-layout.ts";
import {
  V17_CONSTRUCTION_GRAPH,
  V17_PROFILES,
  type V17Profile,
} from "../src/construction/v17-graph.ts";
import { LAB_PAYOUT_DIGEST, LAB_PAYOUT_LOCKING } from "../src/chain/payout.ts";
import { eq32, sha256, writeU32BE } from "../src/pool/bytes.ts";
import { EdgeHistory } from "../src/pool/edge-history.ts";
import type { Note } from "../src/pool/notes.ts";
import { SparseNullifierTree } from "../src/pool/sparse-nullifiers.ts";
import { emptyState, encodePublicPaa2, STATE_BASE_SATS } from "../src/pool/state.ts";
import { applyDeposit, applyWithdraw, type PoolMachine } from "../src/pool/transition.ts";
import {
  aggregateV17P2shMeasurements,
  readV17P2shProfileMeasurement,
  validateV17P2shProfileMeasurement,
  v17CarrierCapacityProofBytes,
  v17ResidualProofBytes,
  V17_P2SH_PROFILE_MEASUREMENT_SCHEMA,
  type V17P2shProfileMeasurement,
  type V17P2shRoleMeasurement,
} from "./v17-p2sh-measurements.ts";

const constructionId = V17_PROOF_PROTOCOL_ID;
const constructionIdHex = Buffer.from(constructionId).toString("hex");
const minerFeeSats = 1_000n;
const category = new Uint8Array(32).fill(0x42);
const spent: Note = {
  amountSats: 20_041n,
  rho: new Uint8Array(32).fill(0x41),
  ownerSecret: new Uint8Array(32).fill(0xbe),
};
function machine(): PoolMachine {
  return {
    state: emptyState(),
    poolCategory: category,
    history: new EdgeHistory(),
    nullifiers: new SparseNullifierTree(),
  };
}

function parseProfile(): V17Profile {
  const value = process.argv.find((argument) => argument.startsWith("--profile="))
    ?.slice("--profile=".length) ?? "2";
  const profile = Number(value);
  if (!V17_PROFILES.includes(profile as V17Profile)) {
    throw new Error("--profile must be 0, 1, or 2");
  }
  return profile as V17Profile;
}

const profile = parseProfile();

function productFixture(selected: V17Profile) {
  if (selected === 0) {
    const deposited = applyDeposit(machine(), spent);
    return {
      profile: selected,
      statement: deposited.statement,
      witness: wDeposit(spent),
      append: deposited.append,
      nullifierPath: undefined,
    };
  }
  const deposited = applyDeposit(machine(), spent);
  if (selected === 1) {
    const withdrawn = applyWithdraw(
      deposited.machine,
      deposited.created,
      LAB_PAYOUT_DIGEST,
      spent.amountSats,
    );
    return {
      profile: selected,
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
  assert.ok(withdrawn.change && withdrawn.append, "profile 2 must create one change edge");
  return {
    profile: selected,
    statement: withdrawn.statement,
    witness: wWithdraw({
      ...deposited.created,
      path: withdrawn.membership.path,
    }, withdrawn.change.note),
    append: withdrawn.append,
    nullifierPath: withdrawn.nullifierPath,
  };
}

const fixture = productFixture(profile);
const statement = fixture.statement;
const oldState = statement.oldState;
const newState = statement.newState;
const relationGraph = compilePoolLocalShaGraph(
  statement,
  fixture.witness,
  minerFeeSats,
);
const occurrenceViolation = verifyLocalShaWordCopyOccurrences(
  relationGraph.program,
  executeLocalShaProgram(relationGraph.program, relationGraph.inputs),
);
assert.equal(occurrenceViolation, undefined, JSON.stringify(occurrenceViolation));
const constructionDescriptor = encodePoolLocalShaConstruction(relationGraph);
const constructionDigest = sha256(constructionDescriptor);
const soundnessWorksheet = localShaWordCopySoundness(relationGraph.program);
const bundle = encodeLocalWordProverBundle({
  statement,
  constructionId,
  graph: relationGraph,
  minerFeeSats,
});
const dryRun = process.argv.includes("--dry-run");
const vmUnboundedDiagnostic = process.argv.includes("--vm-unbounded");
const proofCacheArgument = process.argv.find((argument) => argument.startsWith("--proof-cache="));
const proofCachePath = resolve(
  proofCacheArgument?.slice("--proof-cache=".length) ??
    `.local/local-word-product-v17-profile-${profile}-proof.json`,
);
if (process.argv.includes("--aggregate-measurements")) {
  const measurements = V17_PROFILES.map((item) => {
    const argument = process.argv.find((value) =>
      value.startsWith(`--measurement-profile-${item}=`));
    const path = resolve(argument?.slice(`--measurement-profile-${item}=`.length) ??
      `.local/local-word-v17-vm-unbounded-profile-${item}.json`);
    return readV17P2shProfileMeasurement(path);
  });
  const aggregate = aggregateV17P2shMeasurements(measurements);
  const path = resolve(".local/local-word-v17-vm-unbounded-all-profiles.json");
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(aggregate, null, 2)}\n`, { mode: 0o600 });
  console.log("local-word-v17-vm-unbounded-all-profiles", JSON.stringify({
    path,
    profiles: aggregate.profiles.length,
    roles: aggregate.roleCount,
    minimumProofBytesBeforeQuantizationGuards:
      aggregate.minimumProofBytesBeforeQuantizationGuards,
  }));
  process.exit(0);
}
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
    profile: relationGraph.profile,
    bundleBytes: bundle.length,
    constructionBytes: constructionDescriptor.length,
    constructionId: constructionIdHex,
    constructionDigest: Buffer.from(constructionDigest).toString("hex"),
    programRows: relationGraph.program.rows.length,
    relationInputs: relationGraph.inputs.length,
    publicWords: relationGraph.inputLayout.filter((input) => input.visibility === "public").length,
    compressions: relationGraph.compressions,
    hasChange: relationGraph.hasChange,
    minerFeeSats: minerFeeSats.toString(),
    soundnessWorksheet,
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
  if (cached.cacheVersion === 2 && cached.ok === true && cached.profile === profile &&
    cached.publicWords === 8 && cached.proofVersion === LOCAL_WORD_PROOF_VERSION &&
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
  if (worker.status !== 0) {
    throw new Error([worker.stderr, worker.stdout].filter((value) => value.length > 0).join("\n"));
  }
  proved = JSON.parse(worker.stdout.trim()) as ProvedProduct;
}
assert.equal(proved.ok, true);
assert.equal(proved.profile, profile);
assert.equal(proved.publicWords, 8);
assert.equal(proved.constructionDigestHex, constructionDigestHex);
const proofBytes = new Uint8Array(Buffer.from(proved.proofHex, "hex"));
assert.equal(proofBytes.length, proved.proofBytes);
const expectedPreprocessedRoot = new Uint8Array(
  Buffer.from(proved.expectedPreprocessedRootHex, "hex"),
);
function hex32(value: string): Uint8Array {
  if (!/^[0-9a-f]{64}$/.test(value)) throw new Error("v17 verifier-key hex32");
  return Uint8Array.from(Buffer.from(value, "hex"));
}

function verifierKeyFor(selected: V17Profile) {
  const key = V17_CONSTRUCTION_GRAPH.verifierKeyDigests[selected];
  if (key?.profile !== selected) throw new Error(`v17 verifier-key profile ${selected}`);
  return {
    constructionDigest: hex32(key.relationConstructionDigestHex),
    preprocessedRoot: hex32(key.preprocessedRootHex),
  };
}

const profileKey = verifierKeyFor(profile);
assert.deepEqual(constructionDigest, profileKey.constructionDigest);
assert.deepEqual(expectedPreprocessedRoot, profileKey.preprocessedRoot);
const publicWords = relationGraph.inputLayout
  .filter((input) => input.visibility === "public")
  .map((input, index) => ({
    id: BigInt(index + 1),
    row: input.wire,
    expected: input.value,
  }));
const transcriptInitial = localWordTranscriptInitial(statement, constructionId, minerFeeSats);
const proofContext = {
  profile,
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
  profile,
  proofBytes,
  constructionId,
  constructionDigest,
  expectedPreprocessedRoot,
} as const;
const bankProof = (selected: V17Profile): Uint8Array => {
  const candidate = proofBytes.slice();
  candidate[5] = selected;
  return candidate;
};
const banks = V17_PROFILES.map((selected) => {
  const key = verifierKeyFor(selected);
  return compileLocalWordVerifierBank({
    profile: selected,
    proofBytes: bankProof(selected),
    constructionId,
    constructionDigest: key.constructionDigest,
    expectedPreprocessedRoot: key.preprocessedRoot,
  });
});
const authorizedBankDigests = V17_PROFILES.map((selected) =>
  localWordVerifierBankDigest(banks[selected]!, selected)) as unknown as LocalWordVerifierBankDigests;
const bank = banks[profile]!;
const bankDigest = localWordVerifierBankDigest(bank, profile);
assert.deepEqual(bankDigest, authorizedBankDigests[profile]);
const roles = compileLocalWordVerifierManifestFromBank(
  { ...verifierKey, authorizedBankDigests },
  bank,
);
assert.equal(roles.length, V17_PRODUCTION_ROLE_LAYOUT.length);
roles.forEach((role, index) => {
  assert.equal(role.index, index);
  assert.equal(role.name, V17_PRODUCTION_ROLE_LAYOUT[index]!.id);
});
const semanticRole = (role: typeof roles[number]) => {
  const semantic = V17_PRODUCTION_ROLE_LAYOUT[role.index];
  if (semantic === undefined || semantic.id !== role.name) {
    throw new Error(`v17 production role layout ${role.index}:${role.name}`);
  }
  return semantic;
};
const isMatrixRole = (role: typeof roles[number], matrix: typeof LOCAL_WORD_MATRIX_NAMES[number]) => {
  const semantic = semanticRole(role);
  return (semantic.kind === "matrix-merkle-leaf" ||
    semantic.kind === "matrix-merkle-parent") && semantic.matrix === matrix;
};
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
    token: poolToken(encodePublicPaa2(oldState)),
  }
  : { lockingBytecode: roleLocks[index]!, valueSatoshis: localWordVerifierCarrierValue(index) });
const outputs = [
  {
    lockingBytecode: roleLocks[0]!,
    valueSatoshis: STATE_BASE_SATS + newState.reserveSats,
    token: poolToken(encodePublicPaa2(newState)),
  },
  ...roles.slice(1).map((_, index) => ({
    lockingBytecode: roleLocks[index + 1]!,
    valueSatoshis: localWordVerifierCarrierValue(index + 1),
  })),
];
const inputs = roles.map((role, index) => ({
    outpointTransactionHash: new Uint8Array(32).fill((index + 1) & 0xff),
    outpointIndex: index,
    sequenceNumber: index === 0
      ? localWordPoolCarrierSequence(proofBytes.length)
      : localWordVerifierCarrierSequence(index),
    unlockingBytecode: role.unlockingBytecode,
  }));
if (profile === 0) {
  assert.ok(fixture.append, "deposit edge append");
  sourceOutputs.push({
    lockingBytecode: Uint8Array.of(0x51),
    valueSatoshis: statement.publicAmountSats + minerFeeSats,
  });
  inputs.push({
    outpointTransactionHash: new Uint8Array(32).fill(0xa0),
    outpointIndex: roles.length,
    sequenceNumber: 0xffff_fffe,
    unlockingBytecode: new Uint8Array(),
  });
  outputs.push({
    lockingBytecode: encodeLocalWordEdgeData({
      creationIndex: fixture.append.index,
      edge: fixture.append.edge,
      path: fixture.append.path,
    }),
    valueSatoshis: 0n,
  });
} else {
  assert.ok(fixture.nullifierPath, `profile ${profile} nullifier path`);
  outputs.push({
    lockingBytecode: LAB_PAYOUT_LOCKING,
    valueSatoshis: statement.publicAmountSats - minerFeeSats,
  }, {
    lockingBytecode: encodeLocalWordNullifierData({
      nullifier: statement.nullifier,
      path: fixture.nullifierPath,
    }),
    valueSatoshis: 0n,
  });
  if (profile === 2) {
    assert.ok(fixture.append, "change edge append");
    outputs.push({
      lockingBytecode: encodeLocalWordEdgeData({
        creationIndex: fixture.append.index,
        edge: fixture.append.edge,
        path: fixture.append.path,
      }),
      valueSatoshis: 0n,
    });
  }
}
const transaction = {
  version: 2,
  locktime: 0,
  inputs,
  outputs,
};
const settlement = deriveLocalWordPublicSettlement(
  {
    sourceOutputs,
    inputSequenceNumbers: transaction.inputs.map((input) => input.sequenceNumber),
    outputs,
  },
  authorizedBankDigests,
);
assert.equal(settlement.profile,
  profile === 0 ? "deposit" : profile === 1 ? "withdraw-full" : "withdraw-change");
assert.equal(settlement.minerFeeSats, minerFeeSats);
assert.equal(settlement.statement.publicAmountSats, statement.publicAmountSats);
assert.equal(eq32(settlement.statement.nullifier, statement.nullifier), true);
assert.deepEqual(
  localWordTranscriptInitial(settlement.statement, constructionId, settlement.minerFeeSats),
  transcriptInitial,
);
const raw = encodeTransaction(transaction);
if (!vmUnboundedDiagnostic) {
  assert.ok(raw.length <= 1_000_000, `local-word transaction bytes ${raw.length}`);
}
assert.ok(roles.every((role) => role.redeem.length <= 10_000));
assert.ok(roles.every((role) => role.unlockingBytecode.length <= 10_000));
// This one-profile pre-link diagnostic is intentionally legacy-only. The
// production v17 path observes the final transaction with its certified
// measured allocation.
const observer = analyzeLegacyLocalWordObserverTransaction(raw, {
  profile,
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
      preferred: (role: typeof roles[number]) => isMatrixRole(role, "original"),
    },
    {
      label: "opening",
      offset: directory.openings[1]!.rowsStart,
      preferred: (role: typeof roles[number]) => isMatrixRole(role, "original"),
    },
    {
      label: "mask",
      offset: directory.openings[4]!.rowsStart + LOCAL_WORD_MATRIX_ROW_WIDTHS[4] - 16,
      preferred: (role: typeof roles[number]) => {
        const semantic = semanticRole(role);
        return isMatrixRole(role, "quotientAndFriMask") || semantic.kind === "ood-air" ||
          semantic.kind === "batch-link-query";
      },
    },
    {
      label: "fold",
      offset: directory.openings[LOCAL_WORD_MATRIX_NAMES.length]!.rowsStart,
      preferred: (role: typeof roles[number]) => {
        const semantic = semanticRole(role);
        return ((semantic.kind === "fri-merkle-leaf" ||
          semantic.kind === "fri-merkle-parent") && semantic.layer === 0) ||
          semantic.kind === "fri-fold-query";
      },
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
    token: poolToken(encodePublicPaa2(falseState)),
  };
  const falseSettlement = deriveLocalWordPublicSettlement(
    {
      sourceOutputs,
      inputSequenceNumbers: falseTransaction.inputs.map((input) => input.sequenceNumber),
      outputs: falseTransaction.outputs,
    },
    authorizedBankDigests,
  );
  const falseGraph = compilePoolLocalShaGraph(
    falseSettlement.statement,
    fixture.witness,
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
      (role) => {
        const semantic = semanticRole(role);
        return semantic.kind === "settlement" || semantic.kind === "proof-header" ||
          semantic.kind === "public-boundary-inverses" ||
          semantic.kind === "public-boundary-sum" || semantic.kind === "transcript";
      },
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
let vmUnboundedProfileMeasurement: V17P2shProfileMeasurement | undefined;
if (vmUnboundedDiagnostic) {
  const instructionSet = createInstructionSetBch2026(false);
  const every = instructionSet.every!;
  let maximumMemorySlots = 1;
  let maximumControlDepth = 0;
  let maximumStackItemBytes = 1;
  const observe = (state: Parameters<typeof every>[0]): void => {
    maximumMemorySlots = Math.max(maximumMemorySlots,
      state.stack.length + state.alternateStack.length + state.functionCount);
    maximumControlDepth = Math.max(maximumControlDepth, state.controlStack.length);
    maximumStackItemBytes = Math.max(maximumStackItemBytes,
      ...state.stack.map((item) => item.length),
      ...state.alternateStack.map((item) => item.length));
  };
  const vm = createVirtualMachine({
    ...instructionSet,
    every: (state) => {
      state.metrics.maximumOperationCost = 1_000_000_000;
      observe(state);
      const result = every(state);
      observe(result);
      return result;
    },
  });
  const measurements = roles.map((role): V17P2shRoleMeasurement => {
    maximumMemorySlots = 1;
    maximumControlDepth = 0;
    maximumStackItemBytes = 1;
    const state = vm.evaluate({ inputIndex: role.index, sourceOutputs, transaction } as never);
    observe(state);
    assert.equal(vm.stateSuccess(state), true,
      `${role.index}:${role.name}: ${String(state.error)}`);
    const semantic = semanticRole(role);
    const operationCost = Number(state.metrics.operationCost);
    const densityControlLength = Number(state.metrics.densityControlLength);
    const proofCarrierBytes = role.carrier.chunk.length;
    return {
      logicalInputIndex: role.index,
      roleId: role.name,
      familyId: semantic.familyId,
      kind: semantic.kind,
      operationCost,
      densityControlLength,
      proofCarrierBytes,
      nonProofDensityBytes: densityControlLength - proofCarrierBytes,
      requiredProofBytes: v17ResidualProofBytes({
        operationCost,
        densityControlLength,
        proofCarrierBytes,
      }),
      capacityProofBytes: v17CarrierCapacityProofBytes(role.redeem.length, role.name),
      redeemBytes: role.redeem.length,
      unlockingBytes: role.unlockingBytecode.length,
      maximumMemorySlots,
      maximumControlDepth,
      maximumStackItemBytes,
      hashDigestIterations: Number(state.metrics.hashDigestIterations),
      evaluatedInstructions: Number(state.metrics.evaluatedInstructionCount),
    };
  });
  vmUnboundedProfileMeasurement = validateV17P2shProfileMeasurement({
    schema: V17_P2SH_PROFILE_MEASUREMENT_SCHEMA,
    status: "measured-unbounded-opcost-diagnostic",
    operationCostEngine: "libauth-3.1.0-next.8-bch2026-diagnostic",
    protocolIdHex: constructionIdHex,
    profile,
    proofBytes: proofBytes.length,
    proofSha256Hex: Buffer.from(sha256(proofBytes)).toString("hex"),
    transactionBytes: raw.length,
    transactionSha256Hex: Buffer.from(sha256(raw)).toString("hex"),
    roleCount: measurements.length,
    roles: measurements,
  });
  const measurementPath = resolve(
    `.local/local-word-v17-vm-unbounded-profile-${profile}.json`,
  );
  mkdirSync(dirname(measurementPath), { recursive: true });
  const temporary = `${measurementPath}.tmp`;
  writeFileSync(temporary, `${JSON.stringify(vmUnboundedProfileMeasurement, null, 2)}\n`,
    { mode: 0o600 });
  renameSync(temporary, measurementPath);
  console.error("local-word-v17-vm-unbounded-profile", JSON.stringify({
    path: measurementPath,
    profile,
    roles: measurements.length,
    minimumProofBytes: measurements.reduce((sum, role) => sum + role.requiredProofBytes, 0),
    heaviest: [...measurements].sort((left, right) =>
      right.requiredProofBytes - left.requiredProofBytes).slice(0, 12).map((role) => ({
      index: role.logicalInputIndex,
      roleId: role.roleId,
      requiredProofBytes: role.requiredProofBytes,
    })),
  }));
  const profilePaths = V17_PROFILES.map((item) => resolve(
    `.local/local-word-v17-vm-unbounded-profile-${item}.json`,
  ));
  if (profilePaths.every(existsSync)) {
    const aggregate = aggregateV17P2shMeasurements(
      profilePaths.map(readV17P2shProfileMeasurement),
    );
    const aggregatePath = resolve(".local/local-word-v17-vm-unbounded-all-profiles.json");
    const aggregateTemporary = `${aggregatePath}.tmp`;
    writeFileSync(aggregateTemporary, `${JSON.stringify(aggregate, null, 2)}\n`, { mode: 0o600 });
    renameSync(aggregateTemporary, aggregatePath);
    console.error("local-word-v17-vm-unbounded-all-profiles", JSON.stringify({
      path: aggregatePath,
      profiles: aggregate.profiles.length,
      roles: aggregate.roleCount,
      minimumProofBytesBeforeQuantizationGuards:
        aggregate.minimumProofBytesBeforeQuantizationGuards,
    }));
  }
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
  profile,
  proofBytes: proofBytes.length,
  proofSha256: Buffer.from(sha256(proofBytes)).toString("hex"),
  constructionId: constructionIdHex,
  constructionDigest: Buffer.from(constructionDigest).toString("hex"),
  expectedPreprocessedRoot: Buffer.from(expectedPreprocessedRoot).toString("hex"),
  quotientDegreeBound: proved.quotientDegreeBound,
  soundnessWorksheet,
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
  vmUnbounded: vmUnboundedProfileMeasurement,
};
const artifactDirectory = resolve(".local");
mkdirSync(artifactDirectory, { recursive: true });
const reportPath = resolve(artifactDirectory,
  `local-word-product-v17-profile-${profile}-report.json`);
const proofPath = resolve(artifactDirectory,
  `local-word-product-v17-profile-${profile}.proof`);
const transactionPath = resolve(artifactDirectory,
  `local-word-product-v17-profile-${profile}.tx`);
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

import {
  concatBytes,
  readU16BE,
  readU32BE,
  writeU16BE,
  writeU32BE,
} from "../../pool/bytes.ts";
import { CanonicalMerkleTree, CanonicalMerkleTree4 } from "./canonical-merkle.ts";
import {
  v17MerkleOpeningRoot,
  type V17MerkleDescriptor,
} from "./v17-merkle.ts";
import {
  bitReverseIndex,
  successorCirclePointAtBitReversed,
  successorLineXAtBitReversed,
} from "./successor-domain.ts";
import { add, inv, mul, sub } from "./m31.ts";
import {
  decodeQm31,
  encodeQm31,
  qmAdd,
  qmEq,
  qmMul,
  qmMulM31,
  qmSub,
  type QM31El,
} from "./qm31.ts";
import { SuccessorTranscript } from "./successor-transcript.ts";

const MAGIC = new TextEncoder().encode("SKFR");
const CODEC_VERSION = 1;

export type SuccessorFriConfig = {
  readonly logBlowup: number;
  readonly finalLogDegree: number;
  /** Number of binary folds represented by one commitment (default 1). */
  readonly foldLog?: 1 | 2;
  /** Reject schedules that collide after this many binary folds. */
  readonly queryOrbitLog?: number;
  readonly queries: number;
  readonly grindBits: number;
};

export const PRODUCTION_SUCCESSOR_FRI_CONFIG: SuccessorFriConfig = {
  logBlowup: 5,
  finalLogDegree: 3,
  foldLog: 1,
  queryOrbitLog: 1,
  queries: 21,
  grindBits: 20,
};

export type SuccessorFriLayerProof = {
  readonly root: Uint8Array;
  readonly indices: readonly number[];
  readonly values: readonly QM31El[];
  readonly siblings: readonly Uint8Array[];
};

export type SuccessorFriProof = {
  readonly layers: readonly SuccessorFriLayerProof[];
  readonly finalCoefficients: readonly QM31El[];
  readonly grindNonce: number;
};

class Cursor {
  offset = 0;
  constructor(readonly bytes: Uint8Array) {}

  take(count: number): Uint8Array {
    if (!Number.isSafeInteger(count) || count < 0 || this.offset + count > this.bytes.length) {
      throw new Error("truncated successor FRI proof");
    }
    const value = this.bytes.slice(this.offset, this.offset + count);
    this.offset += count;
    return value;
  }

  u8(): number {
    return this.take(1)[0]!;
  }

  u16(): number {
    const start = this.offset;
    this.take(2);
    return readU16BE(this.bytes, start);
  }

  u32(): number {
    const start = this.offset;
    this.take(4);
    return readU32BE(this.bytes, start);
  }

  qm31(): QM31El {
    return decodeQm31(this.take(16));
  }
}

export function decodeSuccessorFriProof(bytes: Uint8Array): SuccessorFriProof {
  const cursor = new Cursor(bytes);
  if (!cursor.take(4).every((byte, index) => byte === MAGIC[index]) || cursor.u8() !== CODEC_VERSION) {
    throw new Error("successor FRI codec");
  }
  const layerCount = cursor.u8();
  const grindNonce = cursor.u32();
  const finalCount = cursor.u16();
  if (layerCount < 1 || finalCount < 1 || (finalCount & (finalCount - 1)) !== 0 || finalCount > 1024) {
    throw new Error("successor FRI shape");
  }
  const finalCoefficients = Array.from({ length: finalCount }, () => cursor.qm31());
  const layers: SuccessorFriLayerProof[] = [];
  for (let layer = 0; layer < layerCount; layer += 1) {
    const root = cursor.take(32);
    const openingCount = cursor.u16();
    if (openingCount < 1 || openingCount > 4096) throw new Error("successor FRI opening");
    const indices: number[] = [];
    const values: QM31El[] = [];
    for (let opening = 0; opening < openingCount; opening += 1) {
      indices.push(cursor.u32());
      values.push(cursor.qm31());
    }
    const siblingCount = cursor.u16();
    if (siblingCount > 4096) throw new Error("successor FRI sibling count");
    const siblings = Array.from({ length: siblingCount }, () => cursor.take(32));
    layers.push({ root, indices, values, siblings });
  }
  if (cursor.offset !== bytes.length) throw new Error("trailing successor FRI bytes");
  return { layers, finalCoefficients, grindNonce };
}

export function encodeSuccessorFriProof(proof: SuccessorFriProof): Uint8Array {
  if (proof.layers.length > 0xff || proof.finalCoefficients.length > 0xffff) throw new Error("successor FRI shape");
  const parts: Uint8Array[] = [
    MAGIC,
    Uint8Array.of(CODEC_VERSION, proof.layers.length),
    writeU32BE(proof.grindNonce),
    writeU16BE(proof.finalCoefficients.length),
    ...proof.finalCoefficients.map(encodeQm31),
  ];
  for (const layer of proof.layers) {
    if (layer.root.length !== 32 || layer.indices.length !== layer.values.length) throw new Error("successor FRI layer");
    parts.push(layer.root, writeU16BE(layer.indices.length));
    for (let index = 0; index < layer.indices.length; index += 1) {
      parts.push(writeU32BE(layer.indices[index]!), encodeQm31(layer.values[index]!));
    }
    parts.push(writeU16BE(layer.siblings.length), ...layer.siblings);
  }
  return concatBytes(...parts);
}

function friFoldCounts(inputLog: number, finalLogDomain: number, foldLog: number): number[] {
  if (!Number.isInteger(inputLog) || finalLogDomain >= inputLog || (foldLog !== 1 && foldLog !== 2)) {
    throw new Error("FRI config");
  }
  let remaining = inputLog - finalLogDomain;
  const counts: number[] = [];
  while (remaining > 0) {
    const count = Math.min(foldLog, remaining);
    counts.push(count);
    remaining -= count;
  }
  return counts;
}

function openingIndices(initialQueries: readonly number[], foldCounts: readonly number[]): number[][] {
  let queries = [...initialQueries];
  const result: number[][] = [];
  for (const folds of foldCounts) {
    const arity = 2 ** folds;
    result.push([...new Set(queries.flatMap((index) => {
      const base = index & ~(arity - 1);
      return Array.from({ length: arity }, (_, offset) => base + offset);
    }))].sort((a, b) => a - b));
    queries = [...new Set(queries.map((index) => index >> folds))].sort((a, b) => a - b);
  }
  return result;
}

function foldPair(left: QM31El, right: QM31El, twiddle: bigint, alpha: QM31El): QM31El {
  const f0 = qmAdd(left, right);
  const f1 = qmMulM31(qmSub(left, right), inv(twiddle));
  return qmAdd(f0, qmMul(alpha, f1));
}

function bitReverseValues<T>(values: readonly T[]): T[] {
  const logSize = Math.log2(values.length);
  if (!Number.isInteger(logSize)) throw new Error("bit reverse values");
  return values.map((_, index) => values[bitReverseIndex(index, logSize)]!);
}

function doubleX(x: bigint): bigint {
  return sub(mul(2n, mul(x, x)), 1n);
}

function foldCoefficients(values: readonly QM31El[], factors: readonly bigint[]): QM31El {
  if (values.length === 1) return values[0]!;
  const half = values.length / 2;
  const left = foldCoefficients(values.slice(0, half), factors.slice(1));
  const right = foldCoefficients(values.slice(half), factors.slice(1));
  return qmAdd(left, qmMulM31(right, factors[0]!));
}

function evaluateFinal(coefficients: readonly QM31El[], x: bigint): QM31El {
  const bitReversed = bitReverseValues(coefficients);
  const factors: bigint[] = [];
  let current = x;
  for (let i = 0; i < Math.log2(coefficients.length); i += 1) {
    factors.push(current);
    current = doubleX(current);
  }
  return foldCoefficients(bitReversed, factors);
}

export type SuccessorFriVerifyResult = { readonly ok: true } | { readonly ok: false; readonly reason: string };

export type SuccessorFriVerifierTranscript = Pick<
  SuccessorTranscript,
  "absorb" | "challengeQm31" | "acceptGrind" | "queryIndices"
>;

type SuccessorFriOpeningVerification = {
  readonly proof: SuccessorFriProof;
  readonly inputLog: number;
  readonly config: SuccessorFriConfig;
  readonly challenges: readonly (readonly QM31El[])[];
  readonly queries: readonly number[];
  readonly v17Descriptors?: readonly V17MerkleDescriptor[];
};

/** Shared fold/opening kernel; transcript policy is deliberately outside. */
function verifySuccessorFriOpenings(
  args: SuccessorFriOpeningVerification,
): SuccessorFriVerifyResult {
  const { proof, inputLog, config, challenges, queries, v17Descriptors } = args;
  const finalLogDomain = config.finalLogDegree + config.logBlowup;
  const foldCounts = friFoldCounts(inputLog, finalLogDomain, config.foldLog ?? 1);
  if (proof.layers.length !== foldCounts.length || challenges.length !== foldCounts.length) {
    return { ok: false, reason: "FRI shape" };
  }
  if (challenges.some((round, index) => round.length !== foldCounts[index])) {
    return { ok: false, reason: "FRI challenge shape" };
  }
  if (v17Descriptors !== undefined && v17Descriptors.length !== foldCounts.length) {
    return { ok: false, reason: "FRI v17 descriptor shape" };
  }
  if (proof.finalCoefficients.length !== 2 ** config.finalLogDegree) {
    return { ok: false, reason: "FRI final width" };
  }
  const rowCount = 2 ** inputLog;
  if (queries.length !== config.queries || queries.some((query) =>
    !Number.isSafeInteger(query) || query < 0 || query >= rowCount)) {
    return { ok: false, reason: "FRI query shape" };
  }
  const expectedOpenings = openingIndices(queries, foldCounts);
  let queryPositions = [...queries];
  let foldedValues: QM31El[] | undefined;

  let completedFolds = 0;
  for (let round = 0; round < proof.layers.length; round += 1) {
    const layer = proof.layers[round]!;
    const folds = foldCounts[round]!;
    const arity = 2 ** folds;
    if (layer.indices.length !== expectedOpenings[round]!.length ||
      layer.indices.some((index, position) => index !== expectedOpenings[round]![position])) {
      return { ok: false, reason: "FRI opening shape" };
    }
    const rows = layer.indices.map((index, position) => ({
      index,
      raw: encodeQm31(layer.values[position]!),
    }));
    if (v17Descriptors !== undefined) {
      const descriptor = v17Descriptors[round]!;
      if (descriptor.logRows !== inputLog - completedFolds || descriptor.rowWidth !== 16 ||
        descriptor.label !== `fri:layer:${round}` ||
        descriptor.shape !== (folds === 2 ? "quartet-first" : "binary")) {
        return { ok: false, reason: "FRI v17 descriptor" };
      }
      const root = v17MerkleOpeningRoot({ descriptor, rows, siblings: layer.siblings });
      if (!root.every((byte, index) => byte === layer.root[index])) {
        return { ok: false, reason: "FRI Merkle" };
      }
    } else {
      const MerkleTree = (config.foldLog ?? 1) === 2
        ? CanonicalMerkleTree4
        : CanonicalMerkleTree;
      if (!MerkleTree.verifyMany(
        `fri:layer:${round}`,
        rows,
        layer.siblings,
        rowCount >> completedFolds,
        layer.root,
      )) return { ok: false, reason: "FRI Merkle" };
    }
    const opened = new Map(layer.indices.map((index, position) => [index, layer.values[position]!]));
    if (foldedValues && queryPositions.some((position, query) =>
      !qmEq(opened.get(position)!, foldedValues![query]!))) {
      return { ok: false, reason: "FRI fold link" };
    }
    foldedValues = queryPositions.map((position) => {
      const base = position & ~(arity - 1);
      let values = Array.from({ length: arity }, (_, offset) => opened.get(base + offset)!);
      for (let subfold = 0; subfold < folds; subfold += 1) {
        const challenge = challenges[round]![subfold]!;
        values = Array.from({ length: values.length / 2 }, (_, pair) => {
          const pairBase = (base >> subfold) + pair * 2;
          const totalFold = completedFolds + subfold;
          const twiddle = totalFold === 0
            ? successorCirclePointAtBitReversed(inputLog, pairBase).y
            : successorLineXAtBitReversed(inputLog - totalFold, pairBase);
          return foldPair(values[pair * 2]!, values[pair * 2 + 1]!, twiddle, challenge);
        });
      }
      return values[0]!;
    });
    queryPositions = queryPositions.map((position) => position >> folds);
    completedFolds += folds;
  }
  for (let query = 0; query < queryPositions.length; query += 1) {
    const x = successorLineXAtBitReversed(finalLogDomain, queryPositions[query]!);
    if (!qmEq(evaluateFinal(proof.finalCoefficients, x), foldedValues![query]!)) {
      return { ok: false, reason: "FRI final evaluation" };
    }
  }
  return { ok: true };
}

/** V17 path: all 17 challenges and the collision-free schedule are pre-bound. */
export function verifyV17SuccessorFri(args: {
  readonly proof: SuccessorFriProof;
  readonly inputLog: number;
  readonly config: SuccessorFriConfig;
  readonly challenges: readonly (readonly QM31El[])[];
  readonly queries: readonly number[];
  readonly descriptors: readonly V17MerkleDescriptor[];
}): SuccessorFriVerifyResult {
  try {
    return verifySuccessorFriOpenings({
      proof: args.proof,
      inputLog: args.inputLog,
      config: args.config,
      challenges: args.challenges,
      queries: args.queries,
      v17Descriptors: args.descriptors,
    });
  } catch (error) {
    return { ok: false, reason: error instanceof Error ? error.message : "FRI exception" };
  }
}

export function verifySuccessorFri(
  proof: SuccessorFriProof,
  inputLog: number,
  transcript: SuccessorFriVerifierTranscript,
  config: SuccessorFriConfig,
  v17Descriptors?: readonly V17MerkleDescriptor[],
): SuccessorFriVerifyResult {
  try {
    const finalLogDomain = config.finalLogDegree + config.logBlowup;
    const foldCounts = friFoldCounts(inputLog, finalLogDomain, config.foldLog ?? 1);
    const alphas: QM31El[] = [];
    for (let round = 0; round < proof.layers.length; round += 1) {
      transcript.absorb(`fri-root:${round}`, proof.layers[round]!.root);
      alphas.push(transcript.challengeQm31(`fri-alpha:${round}`));
    }
    transcript.absorb("fri-final", concatBytes(...proof.finalCoefficients.map(encodeQm31)));
    if (!transcript.acceptGrind(config.grindBits, proof.grindNonce)) return { ok: false, reason: "FRI grind" };
    const rowCount = 2 ** inputLog;
    const originalQueries = transcript.queryIndices(rowCount, config.queries, config.queryOrbitLog ?? 1);
    return verifySuccessorFriOpenings({
      proof,
      inputLog,
      config,
      challenges: alphas.map((alpha, round) => foldCounts[round] === 2
        ? [alpha, qmMul(alpha, alpha)]
        : [alpha]),
      queries: originalQueries,
      v17Descriptors,
    });
  } catch (error) {
    return { ok: false, reason: error instanceof Error ? error.message : "FRI exception" };
  }
}

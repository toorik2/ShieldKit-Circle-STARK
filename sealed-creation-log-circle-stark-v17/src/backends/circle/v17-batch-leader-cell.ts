import {
  LOCAL_WORD_MATRIX_NAMES,
  LOCAL_WORD_PROOF_LENGTH_OFFSET,
  LOCAL_WORD_PROOF_VERSION,
  localWordProofStaticOffsets,
} from "./local-word-sealed-proof.ts";
import { LOCAL_WORD_PRODUCTION_PARAMETERS } from "./local-word-successor-params.ts";
import {
  QM31_ONE,
  decodeQm31,
  encodeQm31,
  qmAdd,
  qmMul,
  qmSquare,
  qmSub,
  type QM31El,
} from "./qm31.ts";
import { deriveV17OodsChallenge } from "./v17-oods.ts";
import { v17ProofFrameOffset } from "./v17-proof-layout.ts";
import { V17_THEOREM_ROUND_IDS } from "./v17-round-transcript.ts";
import { V17_PRODUCTION_ROUND_GRINDING } from "../../construction/v17-graph.ts";
import {
  concatBytes,
  readU32BE,
  sha256,
  writeU32LE,
} from "../../pool/bytes.ts";

export const V17_BATCH_LEADER_CELL_MAGIC = new TextEncoder().encode("SKBC");
export const V17_BATCH_LEADER_CELL_VERSION = 1;
export const V17_BATCH_LEADER_CELL_FIELD_COUNT = 13;
export const V17_BATCH_LEADER_CELL_FLAGS = 0;
export const V17_BATCH_LEADER_CELL_HEADER_BYTES = 8;
export const V17_BATCH_LEADER_CELL_BYTES =
  V17_BATCH_LEADER_CELL_HEADER_BYTES + V17_BATCH_LEADER_CELL_FIELD_COUNT * 16;

if (V17_BATCH_LEADER_CELL_BYTES !== 216) {
  throw new Error("v17 batch leader cell geometry");
}

function absorb(state: Uint8Array, label: string, data: Uint8Array): Uint8Array {
  const labelBytes = new TextEncoder().encode(label);
  if (labelBytes.length < 1 || labelBytes.length > 96) {
    throw new Error("v17 batch leader transcript label");
  }
  return sha256(concatBytes(
    Uint8Array.of(0),
    state,
    Uint8Array.of(labelBytes.length),
    labelBytes,
    writeU32LE(data.length),
    data,
  ));
}

function namedRoundBytes(id: typeof V17_THEOREM_ROUND_IDS[number]): Uint8Array {
  const ordinal = V17_THEOREM_ROUND_IDS.indexOf(id);
  const name = new TextEncoder().encode(id);
  if (ordinal < 0 || ordinal > 0xff || name.length > 0xff) {
    throw new Error("v17 batch leader theorem round");
  }
  return Uint8Array.of(17, ordinal, name.length, ...name);
}

function leadingZeroBits(bytes: Uint8Array): number {
  let bits = 0;
  for (const byte of bytes) {
    if (byte === 0) bits += 8;
    else return bits + Math.clz32(byte) - 24;
  }
  return bits;
}

function qmPow(base: QM31El, exponent: number): QM31El {
  if (!Number.isSafeInteger(exponent) || exponent < 0) {
    throw new Error("v17 batch leader exponent");
  }
  let result = QM31_ONE;
  let factor = base;
  let remaining = exponent;
  while (remaining > 0) {
    if ((remaining & 1) === 1) result = qmMul(result, factor);
    remaining = Math.floor(remaining / 2);
    if (remaining > 0) factor = qmSquare(factor);
  }
  return result;
}

function betaLinearCombination(values: readonly QM31El[], beta: QM31El): QM31El {
  return [...values].reverse().reduce(
    (sum, value) => qmAdd(value, qmMul(beta, sum)),
    [0n, 0n, 0n, 0n] as QM31El,
  );
}

/**
 * Derive the 216-byte public cache authenticated by batch-link query zero.
 * This helper performs no new proof check: it merely prepares transaction
 * unlocking data. Query zero independently recomputes every field in CashVM.
 */
export function encodeV17BatchLeaderCell(proofBytes: Uint8Array): Uint8Array {
  const parameters = LOCAL_WORD_PRODUCTION_PARAMETERS;
  const offsets = localWordProofStaticOffsets(8, parameters);
  const profile = proofBytes[5];
  if (proofBytes.length < offsets.openingBodies ||
    proofBytes[0] !== 0x53 || proofBytes[1] !== 0x4b ||
    proofBytes[2] !== 0x4c || proofBytes[3] !== 0x57 ||
    proofBytes[4] !== LOCAL_WORD_PROOF_VERSION ||
    (profile !== 0 && profile !== 1 && profile !== 2) ||
    readU32BE(proofBytes, LOCAL_WORD_PROOF_LENGTH_OFFSET) !== proofBytes.length) {
    throw new Error("v17 batch leader proof header");
  }

  const beta = decodeQm31(proofBytes, offsets.batchBeta);
  const claims = Array.from({ length: 98 }, (_, item) =>
    decodeQm31(proofBytes, offsets.oodValues + item * 16));
  const betaPowers: QM31El[] = [];
  let power = beta;
  for (let exponent = 2; exponent <= 9; exponent += 1) {
    power = qmMul(power, beta);
    betaPowers.push(power);
  }
  const batchAtQ = betaLinearCombination(claims, beta);

  const quotientRootOffset = offsets.matrixRoots +
    LOCAL_WORD_MATRIX_NAMES.indexOf("quotientAndFriMask") * 32;
  let transcript = absorb(
    proofBytes.slice(offsets.compositionDigest, offsets.compositionDigest + 32),
    "local-word-v17-quotient-and-fri-mask-root",
    proofBytes.slice(quotientRootOffset, quotientRootOffset + 32),
  );
  transcript = absorb(transcript, "v17-theorem-round", namedRoundBytes("air:ood"));
  const round = V17_PRODUCTION_ROUND_GRINDING.find(({ id }) => id === "air:ood");
  if (!round || round.bits !== 3) throw new Error("v17 batch leader OODS round");
  const nonce = readU32BE(proofBytes, v17ProofFrameOffset("roundNonce:air:ood"));
  const nonceLe = writeU32LE(nonce);
  const candidate = sha256(concatBytes(
    Uint8Array.of(3), transcript, Uint8Array.of(round.bits), nonceLe,
  ));
  if (leadingZeroBits(candidate) < round.bits) {
    throw new Error("v17 batch leader OODS nonce");
  }
  transcript = absorb(transcript, "pow", concatBytes(Uint8Array.of(round.bits), nonceLe));
  const t = deriveV17OodsChallenge(transcript).t;
  const t2 = qmSquare(t);
  const denominator = qmAdd(QM31_ONE, t2);
  const numeratorX = qmSub(QM31_ONE, t2);
  const numeratorY = qmAdd(t, t);
  const k = qmMul(qmPow(beta, 99), denominator);
  const header = concatBytes(
    V17_BATCH_LEADER_CELL_MAGIC,
    Uint8Array.of(
      V17_BATCH_LEADER_CELL_VERSION,
      profile,
      V17_BATCH_LEADER_CELL_FIELD_COUNT,
      V17_BATCH_LEADER_CELL_FLAGS,
    ),
  );
  const cell = concatBytes(
    header,
    ...betaPowers.map(encodeQm31),
    encodeQm31(batchAtQ),
    encodeQm31(denominator),
    encodeQm31(numeratorX),
    encodeQm31(numeratorY),
    encodeQm31(k),
  );
  if (cell.length !== V17_BATCH_LEADER_CELL_BYTES) {
    throw new Error("v17 batch leader cell width");
  }
  return cell;
}

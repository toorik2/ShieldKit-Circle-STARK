/**
 * V17 out-of-domain point primitives for the degree-corrected Circle-FRI
 * evaluation proof (S-two, Protocol 4).
 *
 * The challenge sampler is deliberately separate from the ordinary QM31
 * challenge reducer. Each SHA-256 attempt is rejection-sampled into QM31,
 * then base-field t values and the two Cayley poles are rejected. Conditioned
 * on success in the random-oracle model, t is exactly uniform over
 * QM31 \ (M31 union {+i,-i}), hence its Cayley image is exactly uniform over
 * the affine circle points outside the M31 circle. Two failed attempts are a
 * named, exact fail-closed event; they are never repaired or reduced modulo a
 * convenient subset.
 */
import { CIRCLE_GEN, scalarMul, type CirclePoint } from "./group.ts";
import { M31, type M31El } from "./m31.ts";
import {
  QM31_ONE,
  QM31_ZERO,
  encodeQm31,
  liftM31,
  qm31,
  qmAdd,
  qmEq,
  qmInv,
  qmMul,
  qmNeg,
  qmSquare,
  qmSub,
  type QM31El,
} from "./qm31.ts";
import { concatBytes, readU256BE, sha256 } from "../../pool/bytes.ts";

export type V17Qm31CirclePoint = {
  readonly x: QM31El;
  readonly y: QM31El;
};

export type V17OodsCandidateRejection = "range" | "base-field" | "cayley-pole";

export type V17OodsCandidate = {
  readonly attempt: number;
  readonly digest: Uint8Array;
  readonly integer: bigint;
  readonly rejection?: V17OodsCandidateRejection;
  readonly t?: QM31El;
};

export type V17OodsChallenge = {
  readonly attempt: number;
  readonly digest: Uint8Array;
  readonly t: QM31El;
  readonly point: V17Qm31CirclePoint;
};

export const V17_OODS_DOMAIN = new TextEncoder().encode("ShieldKit/OODS/v17");
export const V17_OODS_MAX_ATTEMPTS = 2;
export const V17_QM31_CARDINALITY = M31 ** 4n;
export const V17_OODS_SHA_SPACE = 1n << 256n;
export const V17_OODS_SHA_QUOTIENT = V17_OODS_SHA_SPACE / V17_QM31_CARDINALITY;
export const V17_OODS_REJECTION_LIMIT = V17_OODS_SHA_QUOTIENT * V17_QM31_CARDINALITY;
export const V17_OODS_VALID_T_COUNT = V17_QM31_CARDINALITY - M31 - 2n;
export const V17_QM31_I: QM31El = [0n, 1n, 0n, 0n];

const V17_OODS_REJECTED_DIGESTS =
  V17_OODS_SHA_SPACE - V17_OODS_REJECTION_LIMIT + V17_OODS_SHA_QUOTIENT * (M31 + 2n);

/** Exact per-attempt and two-attempt failure counts in the SHA-256 sample space. */
export const V17_OODS_FAILURE_CERTIFICATE = Object.freeze({
  shaSpace: V17_OODS_SHA_SPACE,
  qm31Cardinality: V17_QM31_CARDINALITY,
  acceptedDigestCountPerValidT: V17_OODS_SHA_QUOTIENT,
  validTCount: V17_OODS_VALID_T_COUNT,
  rangeTailCount: V17_OODS_SHA_SPACE - V17_OODS_REJECTION_LIMIT,
  invalidTCount: M31 + 2n,
  rejectedDigestCountPerAttempt: V17_OODS_REJECTED_DIGESTS,
  attempts: V17_OODS_MAX_ATTEMPTS,
  exhaustionProbabilityNumerator: V17_OODS_REJECTED_DIGESTS ** BigInt(V17_OODS_MAX_ATTEMPTS),
  exhaustionProbabilityDenominator: V17_OODS_SHA_SPACE ** BigInt(V17_OODS_MAX_ATTEMPTS),
  uniformity: "exact-conditioned-on-success-in-the-random-oracle-model" as const,
});

function isZero(value: QM31El): boolean {
  return qmEq(value, QM31_ZERO);
}

export function isM31Subfield(value: QM31El): boolean {
  return value[1] === 0n && value[2] === 0n && value[3] === 0n;
}

export function isV17CayleyPole(value: QM31El): boolean {
  return value[0] === 0n && value[2] === 0n && value[3] === 0n &&
    (value[1] === 1n || value[1] === M31 - 1n);
}

/** Big-endian base-p decoding after the unbiased 256-bit rejection gate. */
export function v17OodsDigestToQm31(digest: Uint8Array): QM31El {
  if (digest.length !== 32) throw new Error("v17 OODS digest width");
  const integer = readU256BE(digest);
  if (integer >= V17_OODS_REJECTION_LIMIT) throw new Error("v17 OODS range rejection");
  let value = integer % V17_QM31_CARDINALITY;
  const limbs: M31El[] = [];
  for (let coordinate = 0; coordinate < 4; coordinate += 1) {
    limbs.push(value % M31);
    value /= M31;
  }
  if (value !== 0n) throw new Error("v17 OODS base-p overflow");
  return qm31(limbs[0]!, limbs[1]!, limbs[2]!, limbs[3]!);
}

export function v17OodsAttemptDigest(transcriptDigest: Uint8Array, attempt: number): Uint8Array {
  if (transcriptDigest.length !== 32) throw new Error("v17 OODS transcript digest width");
  if (!Number.isInteger(attempt) || attempt < 0 || attempt >= V17_OODS_MAX_ATTEMPTS) {
    throw new Error("v17 OODS attempt");
  }
  return sha256(concatBytes(V17_OODS_DOMAIN, transcriptDigest, Uint8Array.of(attempt)));
}

export function inspectV17OodsCandidate(
  transcriptDigest: Uint8Array,
  attempt: number,
): V17OodsCandidate {
  const digest = v17OodsAttemptDigest(transcriptDigest, attempt);
  const integer = readU256BE(digest);
  if (integer >= V17_OODS_REJECTION_LIMIT) {
    return { attempt, digest, integer, rejection: "range" };
  }
  const t = v17OodsDigestToQm31(digest);
  if (isM31Subfield(t)) return { attempt, digest, integer, t, rejection: "base-field" };
  if (isV17CayleyPole(t)) return { attempt, digest, integer, t, rejection: "cayley-pole" };
  return { attempt, digest, integer, t };
}

/**
 * Canonical, bounded OODS challenge derivation. Failure after both attempts is
 * part of the construction error budget and is never silently remapped.
 */
export function deriveV17OodsChallenge(transcriptDigest: Uint8Array): V17OodsChallenge {
  for (let attempt = 0; attempt < V17_OODS_MAX_ATTEMPTS; attempt += 1) {
    const candidate = inspectV17OodsCandidate(transcriptDigest, attempt);
    if (!candidate.rejection && candidate.t) {
      return {
        attempt,
        digest: candidate.digest,
        t: candidate.t,
        point: v17CayleyPoint(candidate.t),
      };
    }
  }
  throw new Error("v17 OODS challenge exhausted");
}

/** Q=((1-t^2)/(1+t^2), 2t/(1+t^2)). */
export function v17CayleyPoint(t: QM31El): V17Qm31CirclePoint {
  if (isM31Subfield(t)) throw new Error("v17 OODS t is in M31");
  const square = qmSquare(t);
  const denominator = qmAdd(QM31_ONE, square);
  if (isZero(denominator)) throw new Error("v17 OODS Cayley denominator is zero");
  const inverse = qmInv(denominator);
  return {
    x: qmMul(qmSub(QM31_ONE, square), inverse),
    y: qmMul(qmAdd(t, t), inverse),
  };
}

export function v17Qm31CircleOnCurve(point: V17Qm31CirclePoint): boolean {
  return qmEq(qmAdd(qmSquare(point.x), qmSquare(point.y)), QM31_ONE);
}

export function v17Qm31CirclePointIsBase(point: V17Qm31CirclePoint): boolean {
  return isM31Subfield(point.x) && isM31Subfield(point.y);
}

/** Inverse Cayley map, used to certify that a non-base t cannot map to a base point. */
export function v17InverseCayley(point: V17Qm31CirclePoint): QM31El {
  const denominator = qmAdd(QM31_ONE, point.x);
  if (isZero(denominator)) throw new Error("v17 OODS inverse Cayley antipode");
  return qmMul(point.y, qmInv(denominator));
}

export function v17Qm31CircleAdd(
  left: V17Qm31CirclePoint,
  right: V17Qm31CirclePoint,
): V17Qm31CirclePoint {
  return {
    x: qmSub(qmMul(left.x, right.x), qmMul(left.y, right.y)),
    y: qmAdd(qmMul(left.x, right.y), qmMul(left.y, right.x)),
  };
}

export function v17Qm31CircleNegate(point: V17Qm31CirclePoint): V17Qm31CirclePoint {
  return { x: point.x, y: qmNeg(point.y) };
}

export function liftCirclePoint(point: CirclePoint): V17Qm31CirclePoint {
  return { x: liftM31(point.x), y: liftM31(point.y) };
}

/** Stwo CanonicCoset(logSize).step(), lifted into QM31. */
export function v17CanonicalTraceStep(logSize: number): CirclePoint {
  if (!Number.isInteger(logSize) || logSize < 1 || logSize > 30) {
    throw new Error("v17 OODS trace log");
  }
  return scalarMul(CIRCLE_GEN, 1n << BigInt(31 - logSize));
}

/** The offset -1 mask point used by the flat AIR at the OODS challenge. */
export function v17OodsPredecessor(
  point: V17Qm31CirclePoint,
  traceLogSize: number,
): V17Qm31CirclePoint {
  const step = liftCirclePoint(v17CanonicalTraceStep(traceLogSize));
  return v17Qm31CircleAdd(point, v17Qm31CircleNegate(step));
}

/**
 * S-two Protocol 4 single-point zerofier:
 *   v_Q(P) = 1 - (h.x + i*h.y), h = P - Q.
 * It has its sole affine-circle zero at Q.
 */
export function v17PointVanishing(
  vanishPoint: V17Qm31CirclePoint,
  point: V17Qm31CirclePoint,
): QM31El {
  const relative = v17Qm31CircleAdd(point, v17Qm31CircleNegate(vanishPoint));
  return qmSub(QM31_ONE, qmAdd(relative.x, qmMul(V17_QM31_I, relative.y)));
}

/**
 * The same point-vanishing value represented directly from the Cayley
 * parameter, without a field inversion:
 *
 *   v_Q(P) = numerator / denominator,  denominator = 1 + t^2.
 *
 * This representation is useful in BCH Script: verifier identities can be
 * cross-multiplied once, so neither the Cayley map nor v_Q needs an inverse.
 */
export function v17PointVanishingCayleyFraction(
  t: QM31El,
  point: V17Qm31CirclePoint,
): { readonly numerator: QM31El; readonly denominator: QM31El } {
  if (isM31Subfield(t) || isV17CayleyPole(t)) {
    throw new Error("v17 OODS invalid Cayley parameter");
  }
  const t2 = qmSquare(t);
  const denominator = qmAdd(QM31_ONE, t2);
  const qxNumerator = qmSub(QM31_ONE, t2);
  const qyNumerator = qmAdd(t, t);
  const relativeXNumerator = qmAdd(
    qmMul(point.x, qxNumerator),
    qmMul(point.y, qyNumerator),
  );
  const relativeYNumerator = qmAdd(
    qmNeg(qmMul(point.x, qyNumerator)),
    qmMul(point.y, qxNumerator),
  );
  return {
    numerator: qmSub(
      denominator,
      qmAdd(relativeXNumerator, qmMul(V17_QM31_I, relativeYNumerator)),
    ),
    denominator,
  };
}

/**
 * One pointwise degree-corrected term (f(P)-f(Q))/v_Q(P), with explicit zero
 * rejection. This identity does not by itself prove the quotient's degree;
 * Protocol 4 must still low-degree test both f and this quotient.
 */
export function v17EvaluationQuotient(
  pointValue: QM31El,
  claimedValueAtQ: QM31El,
  vanishPoint: V17Qm31CirclePoint,
  point: V17Qm31CirclePoint,
): QM31El {
  const denominator = v17PointVanishing(vanishPoint, point);
  if (isZero(denominator)) throw new Error("v17 OODS evaluation quotient denominator is zero");
  return qmMul(qmSub(pointValue, claimedValueAtQ), qmInv(denominator));
}

export function v17EvaluationQuotientIdentity(args: {
  readonly pointValue: QM31El;
  readonly claimedValueAtQ: QM31El;
  readonly quotientValue: QM31El;
  readonly vanishPoint: V17Qm31CirclePoint;
  readonly point: V17Qm31CirclePoint;
}): boolean {
  return qmEq(
    qmSub(args.pointValue, args.claimedValueAtQ),
    qmMul(v17PointVanishing(args.vanishPoint, args.point), args.quotientValue),
  );
}

export function encodeV17Qm31CirclePoint(point: V17Qm31CirclePoint): Uint8Array {
  return concatBytes(encodeQm31(point.x), encodeQm31(point.y));
}

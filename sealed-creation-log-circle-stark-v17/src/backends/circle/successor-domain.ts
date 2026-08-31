import { CIRCLE_GEN, scalarMul, type CirclePoint } from "./group.ts";
import type { M31El } from "./m31.ts";

const CIRCLE_ORDER = 1n << 31n;

export function bitReverseIndex(index: number, logSize: number): number {
  if (!Number.isInteger(logSize) || logSize < 0 || logSize > 30) throw new Error("bit reverse log");
  const size = 2 ** logSize;
  if (!Number.isInteger(index) || index < 0 || index >= size) throw new Error("bit reverse index");
  let input = index;
  let output = 0;
  for (let bit = 0; bit < logSize; bit += 1) {
    output = output * 2 + (input & 1);
    input = Math.floor(input / 2);
  }
  return output;
}

function pointAtExponent(exponent: bigint): CirclePoint {
  return scalarMul(CIRCLE_GEN, ((exponent % CIRCLE_ORDER) + CIRCLE_ORDER) % CIRCLE_ORDER);
}

/** Stwo CanonicCoset(logSize).circle_domain().at(naturalIndex). */
export function successorCirclePointAt(logSize: number, naturalIndex: number): CirclePoint {
  if (!Number.isInteger(logSize) || logSize < 1 || logSize > 30) throw new Error("circle domain log");
  const size = 2 ** logSize;
  if (!Number.isInteger(naturalIndex) || naturalIndex < 0 || naturalIndex >= size) throw new Error("circle index");
  const half = size / 2;
  const initial = 1n << BigInt(30 - logSize);
  const step = 1n << BigInt(32 - logSize);
  return naturalIndex < half
    ? pointAtExponent(initial + BigInt(naturalIndex) * step)
    : pointAtExponent(-(initial + BigInt(naturalIndex - half) * step));
}

export function successorCirclePointAtBitReversed(logSize: number, bitReversedIndex: number): CirclePoint {
  return successorCirclePointAt(logSize, bitReverseIndex(bitReversedIndex, logSize));
}

/** Stwo LineDomain(Coset::half_odds(logSize)).at(naturalIndex). */
export function successorLineXAt(logSize: number, naturalIndex: number): M31El {
  if (!Number.isInteger(logSize) || logSize < 0 || logSize > 29) throw new Error("line domain log");
  const size = 2 ** logSize;
  if (!Number.isInteger(naturalIndex) || naturalIndex < 0 || naturalIndex >= size) throw new Error("line index");
  const initial = 1n << BigInt(29 - logSize);
  const step = 1n << BigInt(31 - logSize);
  return pointAtExponent(initial + BigInt(naturalIndex) * step).x;
}

export function successorLineXAtBitReversed(logSize: number, bitReversedIndex: number): M31El {
  return successorLineXAt(logSize, bitReverseIndex(bitReversedIndex, logSize));
}

/** Exact Stwo offset_bit_reversed_circle_domain_index mapping. */
export function successorTraceOffsetIndex(
  bitReversedIndex: number,
  traceLogSize: number,
  evaluationLogSize: number,
  offset: number,
): number {
  if (!Number.isInteger(offset)) throw new Error("trace offset");
  let natural = bitReverseIndex(bitReversedIndex, evaluationLogSize);
  const halfSize = 2 ** (evaluationLogSize - 1);
  const stepSize = offset * 2 ** (evaluationLogSize - traceLogSize - 1);
  if (natural < halfSize) {
    natural = ((natural + stepSize) % halfSize + halfSize) % halfSize;
  } else {
    natural = ((natural - halfSize - stepSize) % halfSize + halfSize) % halfSize + halfSize;
  }
  return bitReverseIndex(natural, evaluationLogSize);
}

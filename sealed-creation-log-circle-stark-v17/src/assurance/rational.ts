export type Rational = {
  readonly numerator: bigint;
  readonly denominator: bigint;
};

function gcd(left: bigint, right: bigint): bigint {
  let a = left < 0n ? -left : left;
  let b = right < 0n ? -right : right;
  while (b !== 0n) [a, b] = [b, a % b];
  return a;
}

export function rational(numerator: bigint, denominator = 1n): Rational {
  if (denominator === 0n) throw new Error("rational zero denominator");
  const sign = denominator < 0n ? -1n : 1n;
  const divisor = gcd(numerator, denominator);
  return {
    numerator: sign * numerator / divisor,
    denominator: sign * denominator / divisor,
  };
}

export const ZERO = rational(0n);
export const ONE = rational(1n);

export function rAdd(left: Rational, right: Rational): Rational {
  return rational(
    left.numerator * right.denominator + right.numerator * left.denominator,
    left.denominator * right.denominator,
  );
}

export function rSub(left: Rational, right: Rational): Rational {
  return rational(
    left.numerator * right.denominator - right.numerator * left.denominator,
    left.denominator * right.denominator,
  );
}

export function rMul(left: Rational, right: Rational): Rational {
  return rational(left.numerator * right.numerator, left.denominator * right.denominator);
}

export function rDiv(left: Rational, right: Rational): Rational {
  if (right.numerator === 0n) throw new Error("rational division by zero");
  return rational(left.numerator * right.denominator, left.denominator * right.numerator);
}

export function rCompare(left: Rational, right: Rational): -1 | 0 | 1 {
  const difference = left.numerator * right.denominator - right.numerator * left.denominator;
  return difference < 0n ? -1 : difference > 0n ? 1 : 0;
}

export function rMax(values: readonly Rational[]): Rational {
  if (values.length === 0) throw new Error("rational maximum of empty set");
  return values.reduce((maximum, value) => rCompare(value, maximum) > 0 ? value : maximum);
}

export function rMin(values: readonly Rational[]): Rational {
  if (values.length === 0) throw new Error("rational minimum of empty set");
  return values.reduce((minimum, value) => rCompare(value, minimum) < 0 ? value : minimum);
}

export function rPow(base: Rational, exponent: number): Rational {
  if (!Number.isSafeInteger(exponent) || exponent < 0) throw new Error("rational exponent");
  let result = ONE;
  let factor = base;
  let remaining = exponent;
  while (remaining > 0) {
    if ((remaining & 1) === 1) result = rMul(result, factor);
    factor = rMul(factor, factor);
    remaining = Math.floor(remaining / 2);
  }
  return result;
}

export function rPow2(exponent: number): Rational {
  if (!Number.isSafeInteger(exponent)) throw new Error("rational power of two");
  return exponent >= 0
    ? rational(1n << BigInt(exponent))
    : rational(1n, 1n << BigInt(-exponent));
}

export function rCeil(value: Rational): bigint {
  if (value.numerator < 0n) return value.numerator / value.denominator;
  return (value.numerator + value.denominator - 1n) / value.denominator;
}

function integerSqrt(value: bigint): bigint {
  if (value < 0n) throw new Error("integer square root");
  if (value < 2n) return value;
  let estimate = 1n << BigInt(Math.ceil(value.toString(2).length / 2));
  for (;;) {
    const next = (estimate + value / estimate) >> 1n;
    if (next >= estimate) return estimate;
    estimate = next;
  }
}

/** Outward dyadic interval enclosing sqrt(value). */
export function rSqrtInterval(
  value: Rational,
  precisionBits = 96,
): { readonly lower: Rational; readonly upper: Rational } {
  if (rCompare(value, ZERO) < 0 || !Number.isSafeInteger(precisionBits) || precisionBits < 1) {
    throw new Error("rational square-root interval");
  }
  const scale = 1n << BigInt(precisionBits);
  const scaledNumerator = value.numerator * scale * scale;
  const quotient = scaledNumerator / value.denominator;
  let floor = integerSqrt(quotient);
  while ((floor + 1n) * (floor + 1n) * value.denominator <= scaledNumerator) floor += 1n;
  while (floor * floor * value.denominator > scaledNumerator) floor -= 1n;
  const exact = floor * floor * value.denominator === scaledNumerator;
  return {
    lower: rational(floor, scale),
    upper: rational(exact ? floor : floor + 1n, scale),
  };
}

export function rToNumber(value: Rational): number {
  return Number(value.numerator) / Number(value.denominator);
}

/** Conservative lower bound on -log2(value), for reports only. */
export function rSecurityBits(value: Rational): number {
  if (rCompare(value, ZERO) <= 0) return Number.POSITIVE_INFINITY;
  const log2BigInt = (integer: bigint): number => {
    const bits = integer.toString(2).length;
    const shift = Math.max(0, bits - 53);
    return shift + Math.log2(Number(integer >> BigInt(shift)));
  };
  return log2BigInt(value.denominator) - log2BigInt(value.numerator);
}

export function rString(value: Rational): string {
  return `${value.numerator}/${value.denominator}`;
}

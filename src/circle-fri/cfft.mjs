import {
  M31_MODULUS,
  add,
  inverse,
  mul,
  neg,
  sub,
} from '../../research-lanes/bch-shielded-pool-design/p2/reference/m31.mjs';

import {
  assertCirclePoint,
  piX,
} from './circle.mjs';

const HALF = (M31_MODULUS + 1n) / 2n;

const fail = (message) => {
  throw new TypeError(message);
};

const assertElement = (value, name) => {
  if (typeof value !== 'bigint' || value < 0n || value >= M31_MODULUS) {
    fail(`${name} must be a canonical M31 element`);
  }
  return value;
};

const isPowerOfTwo = (value) => (
  Number.isSafeInteger(value)
  && value > 0
  && (value & (value - 1)) === 0
);

const assertPowerOfTwoLength = (values, name) => {
  if (!Array.isArray(values) || !isPowerOfTwo(values.length)) {
    fail(`${name} length must be a positive power of two`);
  }
  return values.length;
};

const assertElements = (values, expectedLength, name) => {
  if (!Array.isArray(values) || values.length !== expectedLength) {
    fail(`${name} must contain exactly ${expectedLength} elements`);
  }
  return values.map((value, index) => assertElement(value, `${name}[${index}]`));
};

const buildXFibers = (domain) => {
  const fibersByX = new Map();
  for (let index = 0; index < domain.length; index += 1) {
    const p = assertCirclePoint(domain[index], `domain[${index}]`);
    const key = p.x.toString();
    const fiber = fibersByX.get(key) ?? [];
    fiber.push({ index, point: p });
    fibersByX.set(key, fiber);
  }

  const fibers = [];
  for (const [xText, fiber] of fibersByX) {
    if (fiber.length !== 2) fail(`x=${xText} must have exactly two J preimages`);
    const [positive, negative] = fiber;
    if (positive.point.x !== negative.point.x || positive.point.y !== neg(negative.point.y)) {
      fail(`x=${xText} preimages are not J twins`);
    }
    if (positive.point.y === 0n) fail(`x=${xText} has a zero J-fold coordinate`);
    fibers.push(Object.freeze({
      leftIndex: positive.index,
      rightIndex: negative.index,
      x: positive.point.x,
      y: positive.point.y,
    }));
  }
  if (fibers.length * 2 !== domain.length) fail('circle domain is not J-symmetric');
  return fibers;
};

const buildPiFibers = (xs) => {
  const fibersByImage = new Map();
  for (let index = 0; index < xs.length; index += 1) {
    const x = assertElement(xs[index], `xDomain[${index}]`);
    const image = piX(x);
    const key = image.toString();
    const fiber = fibersByImage.get(key) ?? [];
    fiber.push({ index, x });
    fibersByImage.set(key, fiber);
  }

  const fibers = [];
  for (const [imageText, fiber] of fibersByImage) {
    if (fiber.length !== 2) fail(`pi image ${imageText} must have exactly two preimages`);
    const [positive, negative] = fiber;
    if (negative.x !== neg(positive.x)) fail(`pi image ${imageText} preimages are not x/-x`);
    if (positive.x === 0n) fail(`pi image ${imageText} has a zero fold coordinate`);
    fibers.push(Object.freeze({
      leftIndex: positive.index,
      rightIndex: negative.index,
      x: positive.x,
      image: BigInt(imageText),
    }));
  }
  if (fibers.length * 2 !== xs.length) fail('x domain is not pi-symmetric');
  return fibers;
};

const interpolateXLine = (xs, values) => {
  if (xs.length === 1) return [values[0]];
  const fibers = buildPiFibers(xs);
  const nextDomain = new Array(fibers.length);
  const evenValues = new Array(fibers.length);
  const oddValues = new Array(fibers.length);

  for (let index = 0; index < fibers.length; index += 1) {
    const fiber = fibers[index];
    const left = values[fiber.leftIndex];
    const right = values[fiber.rightIndex];
    nextDomain[index] = fiber.image;
    evenValues[index] = mul(add(left, right), HALF);
    oddValues[index] = mul(sub(left, right), inverse(mul(2n, fiber.x)));
  }

  return interpolateXLine(nextDomain, evenValues)
    .concat(interpolateXLine(nextDomain, oddValues));
};

/**
 * Interpolate evaluations on a J-symmetric circle coset into the recursive
 * Circle-FFT basis {1,y} x {1,x} x {1,pi(x)} x ... .
 */
export const circleIFFT = (domain, values) => {
  const size = assertPowerOfTwoLength(domain, 'domain');
  const evaluations = assertElements(values, size, 'values');
  if (size === 1) {
    assertCirclePoint(domain[0], 'domain[0]');
    return [evaluations[0]];
  }

  const fibers = buildXFibers(domain);
  const xDomain = new Array(fibers.length);
  const evenValues = new Array(fibers.length);
  const oddValues = new Array(fibers.length);

  for (let index = 0; index < fibers.length; index += 1) {
    const fiber = fibers[index];
    const left = evaluations[fiber.leftIndex];
    const right = evaluations[fiber.rightIndex];
    xDomain[index] = fiber.x;
    evenValues[index] = mul(add(left, right), HALF);
    oddValues[index] = mul(sub(left, right), inverse(mul(2n, fiber.y)));
  }

  return interpolateXLine(xDomain, evenValues)
    .concat(interpolateXLine(xDomain, oddValues));
};

const buildXPlan = (xs) => {
  if (xs.length === 1) return Object.freeze({ size: 1 });
  const fibers = buildPiFibers(xs);
  return Object.freeze({
    size: xs.length,
    fibers,
    child: buildXPlan(fibers.map(({ image }) => image)),
  });
};

const evaluateXLine = (plan, coefficients) => {
  if (plan.size === 1) return [coefficients[0]];
  const half = plan.size / 2;
  const evenValues = evaluateXLine(plan.child, coefficients.slice(0, half));
  const oddValues = evaluateXLine(plan.child, coefficients.slice(half));
  const result = new Array(plan.size);

  for (let index = 0; index < plan.fibers.length; index += 1) {
    const fiber = plan.fibers[index];
    const weightedOdd = mul(fiber.x, oddValues[index]);
    result[fiber.leftIndex] = add(evenValues[index], weightedOdd);
    result[fiber.rightIndex] = sub(evenValues[index], weightedOdd);
  }
  return result;
};

/** Evaluate one recursive Circle-FFT coefficient vector on a circle coset. */
export const circleFFT = (domain, coefficients) => {
  const size = assertPowerOfTwoLength(domain, 'domain');
  const canonicalCoefficients = assertElements(coefficients, size, 'coefficients');
  if (size === 1) {
    assertCirclePoint(domain[0], 'domain[0]');
    return [canonicalCoefficients[0]];
  }

  const fibers = buildXFibers(domain);
  const half = size / 2;
  const xPlan = buildXPlan(fibers.map(({ x }) => x));
  const evenValues = evaluateXLine(xPlan, canonicalCoefficients.slice(0, half));
  const oddValues = evaluateXLine(xPlan, canonicalCoefficients.slice(half));
  const result = new Array(size);

  for (let index = 0; index < fibers.length; index += 1) {
    const fiber = fibers[index];
    const weightedOdd = mul(fiber.y, oddValues[index]);
    result[fiber.leftIndex] = add(evenValues[index], weightedOdd);
    result[fiber.rightIndex] = sub(evenValues[index], weightedOdd);
  }
  return result;
};

export const evaluateXPolynomial = (coefficients, x) => {
  if (coefficients.length === 1) return coefficients[0];
  const half = coefficients.length / 2;
  return add(
    evaluateXPolynomial(coefficients.slice(0, half), piX(x)),
    mul(x, evaluateXPolynomial(coefficients.slice(half), piX(x))),
  );
};

/** Evaluate a Circle-FFT basis polynomial at one arbitrary circle point. */
export const evaluateCirclePolynomial = (coefficients, circlePoint) => {
  const size = assertPowerOfTwoLength(coefficients, 'coefficients');
  const canonicalCoefficients = assertElements(coefficients, size, 'coefficients');
  const p = assertCirclePoint(circlePoint);
  if (size === 1) return canonicalCoefficients[0];
  const half = size / 2;
  return add(
    evaluateXPolynomial(canonicalCoefficients.slice(0, half), p.x),
    mul(p.y, evaluateXPolynomial(canonicalCoefficients.slice(half), p.x)),
  );
};

/**
 * Extend evaluations from a smaller Circle-FFT basis to a larger circle coset.
 * Basis coordinates are strided because each added pi layer is inserted above
 * the source basis, e.g. size-4 [1,x,y,yx] maps to size-8 slots [0,2,4,6].
 */
export const extendCircleEvaluations = ({ sourceDomain, targetDomain, values }) => {
  const sourceSize = assertPowerOfTwoLength(sourceDomain, 'sourceDomain');
  const targetSize = assertPowerOfTwoLength(targetDomain, 'targetDomain');
  if (targetSize < sourceSize || targetSize % sourceSize !== 0) {
    fail('targetDomain size must be a power-of-two multiple of sourceDomain size');
  }
  const stride = targetSize / sourceSize;
  if (!isPowerOfTwo(stride)) fail('Circle-FFT extension stride must be a power of two');
  const coefficients = circleIFFT(sourceDomain, values);
  const extendedCoefficients = new Array(targetSize).fill(0n);
  for (let index = 0; index < sourceSize; index += 1) {
    extendedCoefficients[index * stride] = coefficients[index];
  }
  return Object.freeze({
    coefficients,
    extendedCoefficients,
    evaluations: circleFFT(targetDomain, extendedCoefficients),
    stride,
  });
};

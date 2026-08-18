/**
 * CM31 = M31[i] / (i^2 + 1). p = 2^31-1 ≡ 3 (mod 4), so i^2+1 is irreducible.
 * Used only for Circle DEEP Re/Im; it does not select an extension tower.
 */

import {
  M31_MODULUS,
  add as addM31,
  inverse as inverseM31,
  mul as mulM31,
  neg as negM31,
  sub as subM31,
} from '../../research-lanes/bch-shielded-pool-design/p2/reference/m31.mjs';

const fail = (message) => {
  throw new TypeError(message);
};

const assertM31 = (value, name) => {
  if (typeof value !== 'bigint' || value < 0n || value >= M31_MODULUS) {
    fail(`${name} must be a canonical M31 element`);
  }
  return value;
};

export const cm31 = (re, im) => Object.freeze({
  re: assertM31(re, 're'),
  im: assertM31(im, 'im'),
});

export const cm31FromM31 = (value) => cm31(assertM31(value, 'value'), 0n);

export const cm31Zero = cm31(0n, 0n);
export const cm31One = cm31(1n, 0n);
export const cm31I = cm31(0n, 1n);

export const cm31Eq = (left, right) => left.re === right.re && left.im === right.im;

export const cm31Add = (left, right) => cm31(addM31(left.re, right.re), addM31(left.im, right.im));

export const cm31Sub = (left, right) => cm31(subM31(left.re, right.re), subM31(left.im, right.im));

export const cm31Neg = (value) => cm31(negM31(value.re), negM31(value.im));

export const cm31Conj = (value) => cm31(value.re, negM31(value.im));

export const cm31Mul = (left, right) => cm31(
  subM31(mulM31(left.re, right.re), mulM31(left.im, right.im)),
  addM31(mulM31(left.re, right.im), mulM31(left.im, right.re)),
);

export const cm31Norm = (value) => addM31(mulM31(value.re, value.re), mulM31(value.im, value.im));

export const cm31Inv = (value) => {
  const norm = cm31Norm(value);
  if (norm === 0n) fail('CM31 inverse of zero');
  const invNorm = inverseM31(norm);
  const conj = cm31Conj(value);
  return cm31(mulM31(conj.re, invNorm), mulM31(conj.im, invNorm));
};

export const cm31Div = (left, right) => cm31Mul(left, cm31Inv(right));

/** pi(x) = 2x^2 - 1 over CM31. */
export const cm31PiX = (x) => cm31Sub(cm31Mul(cm31(2n, 0n), cm31Mul(x, x)), cm31One);

export const assertCm31CirclePoint = (value, name = 'point') => {
  if (value === null || typeof value !== 'object') fail(`${name} must be a CM31 circle point`);
  const x = cm31(value.x.re, value.x.im);
  const y = cm31(value.y.re, value.y.im);
  if (!cm31Eq(cm31Add(cm31Mul(x, x), cm31Mul(y, y)), cm31One)) {
    fail(`${name} does not satisfy x^2 + y^2 = 1 over CM31`);
  }
  return Object.freeze({ x, y });
};

export const embedRealCirclePoint = ({ x, y }) => Object.freeze({
  x: cm31FromM31(x),
  y: cm31FromM31(y),
});

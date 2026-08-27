import { add, inv, mul, sub, type M31El } from "./m31.ts";
import { type CirclePoint } from "./group.ts";

/** Newton divided-difference interpolation on (x, y) pairs. */
export function newtonCoeffs(xs: M31El[], ys: M31El[]): M31El[] {
  const n = xs.length;
  const div = ys.slice();
  for (let i = 1; i < n; i += 1) {
    for (let j = n - 1; j >= i; j -= 1) {
      const dx = sub(xs[j]!, xs[j - i]!);
      if (dx === 0n) throw new Error("repeat x in interpolation");
      div[j] = mul(sub(div[j]!, div[j - 1]!), inv(dx));
    }
  }
  return div;
}

export function evalNewton(coeffs: M31El[], xs: M31El[], at: M31El): M31El {
  let acc = 0n;
  let prod = 1n;
  for (let i = 0; i < coeffs.length; i += 1) {
    acc = add(acc, mul(coeffs[i]!, prod));
    if (i + 1 < coeffs.length) prod = mul(prod, sub(at, xs[i]!));
  }
  return acc;
}

/**
 * Circle function f(P) = E(x) + y·O(x). Pair each point with its conjugate
 * (x, −y) — the group inverse — which share an x-coordinate.
 */
export function interpolateCircle(domain: CirclePoint[], values: M31El[]): {
  xs: M31El[];
  even: M31El[];
  odd: M31El[];
} {
  if (domain.length !== values.length) throw new Error("circle interpolate width");
  const xs: M31El[] = [];
  const ev: M31El[] = [];
  const od: M31El[] = [];
  const seen = new Set<string>();
  for (let i = 0; i < domain.length; i += 1) {
    const p = domain[i]!;
    const key = p.x.toString();
    if (seen.has(key)) continue;
    seen.add(key);
    let j = i;
    const ny = p.y === 0n ? 0n : (2147483647n - p.y);
    for (let k = 0; k < domain.length; k += 1) {
      if (domain[k]!.x === p.x && domain[k]!.y === ny) {
        j = k;
        break;
      }
    }
    xs.push(p.x);
    ev.push(mul(add(values[i]!, values[j]!), inv(2n)));
    const twoY = add(p.y, p.y);
    od.push(twoY === 0n ? 0n : mul(sub(values[i]!, values[j]!), inv(twoY)));
  }
  return { xs, even: newtonCoeffs(xs, ev), odd: newtonCoeffs(xs, od) };
}

export function evalCirclePoly(
  interp: { xs: M31El[]; even: M31El[]; odd: M31El[] },
  p: CirclePoint,
): M31El {
  const e = evalNewton(interp.even, interp.xs, p.x);
  const o = evalNewton(interp.odd, interp.xs, p.x);
  return add(e, mul(p.y, o));
}

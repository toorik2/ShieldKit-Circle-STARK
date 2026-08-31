/** M31 = 2^31 - 1. Independent of the sealed P2 .mjs so this profile can move. */
export const M31 = 2147483647n;

export type M31El = bigint;

export type M31RuntimeOperations = {
  readonly add: (a: unknown, b: unknown) => unknown;
  readonly sub: (a: unknown, b: unknown) => unknown;
  readonly mul: (a: unknown, b: unknown) => unknown;
  readonly neg?: (a: unknown) => unknown;
  readonly inv?: (a: unknown) => unknown;
};

let runtimeOperations: M31RuntimeOperations | undefined;

/**
 * Synchronously trace the exact field program without maintaining a second
 * handwritten AIR. The override cannot nest and is always restored.
 */
export function withM31RuntimeOperations<T>(operations: M31RuntimeOperations, run: () => T): T {
  if (runtimeOperations) throw new Error("nested M31 runtime override");
  runtimeOperations = operations;
  try {
    return run();
  } finally {
    runtimeOperations = undefined;
  }
}

export function el(value: bigint, name = "m31"): M31El {
  if (value < 0n || value >= M31) throw new Error(`${name} not in [0, p)`);
  return value;
}

export function add(a: M31El, b: M31El): M31El {
  if (runtimeOperations) return runtimeOperations.add(a, b) as M31El;
  return (el(a, "a") + el(b, "b")) % M31;
}

export function sub(a: M31El, b: M31El): M31El {
  if (runtimeOperations) return runtimeOperations.sub(a, b) as M31El;
  return (el(a, "a") - el(b, "b") + M31) % M31;
}

export function neg(a: M31El): M31El {
  if (runtimeOperations) {
    if (runtimeOperations.neg) return runtimeOperations.neg(a) as M31El;
    return runtimeOperations.sub(0n, a) as M31El;
  }
  const n = el(a);
  return n === 0n ? 0n : M31 - n;
}

export function mul(a: M31El, b: M31El): M31El {
  if (runtimeOperations) return runtimeOperations.mul(a, b) as M31El;
  return (el(a, "a") * el(b, "b")) % M31;
}

export function square(a: M31El): M31El {
  if (runtimeOperations) return runtimeOperations.mul(a, a) as M31El;
  return mul(a, a);
}

export function inv(a: M31El): M31El {
  if (runtimeOperations) {
    if (!runtimeOperations.inv) throw new Error("symbolic M31 inverse is unavailable");
    return runtimeOperations.inv(a) as M31El;
  }
  const input = el(a);
  if (input === 0n) throw new Error("zero has no inverse");
  let oldR = input;
  let r = M31;
  let oldT = 1n;
  let t = 0n;
  while (r !== 0n) {
    const q = oldR / r;
    [oldR, r] = [r, oldR - q * r];
    [oldT, t] = [t, oldT - q * t];
  }
  if (oldR !== 1n) throw new Error("non-unit");
  return ((oldT % M31) + M31) % M31;
}

export function encodeLe(value: M31El): Uint8Array {
  let n = el(value);
  const out = new Uint8Array(4);
  for (let i = 0; i < 4; i += 1) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
}

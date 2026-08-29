import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { add, inv, mul, sub, type M31El } from "../src/backends/circle/m31.ts";
import { projectPi } from "../src/backends/circle/group.ts";
import { evalCirclePoly, interpolateCircle } from
  "../src/backends/circle/interpolate.ts";
import {
  circleHalfCosetDomain,
  circleHalfCosetPoint,
  circlePointKey,
  circleSubgroupDomain,
} from "../src/backends/circle/circle-domain.ts";
import {
  createPrivateTraceSet,
  m31MatrixRank,
  randomizerEvaluationMatrix,
  sealPrivateTrace,
  traceEvaluationRank,
} from "../src/backends/circle/sealed-oracle.ts";

function counterSource(start: bigint): () => bigint {
  let value = start;
  return () => {
    const out = value;
    value = add(value, 1n);
    return out;
  };
}

function solveSquare(matrix: readonly (readonly M31El[])[], values: readonly M31El[]): M31El[] {
  const rows = matrix.map((row, index) => [...row, values[index]!]);
  for (let column = 0; column < rows.length; column += 1) {
    const pivot = rows.findIndex((row, index) => index >= column && row[column] !== 0n);
    if (pivot < column) throw new Error("singular observer matrix");
    [rows[column], rows[pivot]] = [rows[pivot]!, rows[column]!];
    const scale = inv(rows[column]![column]!);
    for (let item = column; item <= rows.length; item += 1) {
      rows[column]![item] = mul(rows[column]![item]!, scale);
    }
    for (let row = 0; row < rows.length; row += 1) {
      if (row === column) continue;
      const factor = rows[row]![column]!;
      for (let item = column; item <= rows.length; item += 1) {
        rows[row]![item] = sub(rows[row]![item]!, mul(factor, rows[column]![item]!));
      }
    }
  }
  return rows.map((row) => row.at(-1)!);
}

describe("successor sealed-oracle foundation", () => {
  it("half-coset LDE is disjoint, antipode-paired, and fold-stable", () => {
    const trace = circleSubgroupDomain(64);
    const lde = circleHalfCosetDomain(1024);
    const traceKeys = new Set(trace.map(circlePointKey));
    assert.equal(lde.some((p) => traceKeys.has(circlePointKey(p))), false);
    for (let i = 0; i < lde.length / 2; i += 1) {
      const p = lde[i]!;
      const partner = lde[i + lde.length / 2]!;
      assert.equal(add(p.x, partner.x), 0n);
      assert.equal(add(p.y, partner.y), 0n);
    }
    const folded = lde.slice(0, lde.length / 2).map(projectPi);
    assert.deepEqual(folded, circleHalfCosetDomain(512));
  });

  it("seals private columns with fresh secret Z_H randomizers", () => {
    const traceDomain = circleSubgroupDomain(64);
    const evaluationDomain = circleHalfCosetDomain(1024);
    const columns = [
      Array.from({ length: 64 }, (_, i) => BigInt(i & 1)),
      Array.from({ length: 64 }, (_, i) => BigInt((i * 17 + 3) % 101)),
    ];
    const privateTrace = createPrivateTraceSet(traceDomain, columns);
    const a = sealPrivateTrace(privateTrace, evaluationDomain, 80, counterSource(1n));
    const b = sealPrivateTrace(privateTrace, evaluationDomain, 80, counterSource(101n));
    assert.equal(a.columns.length, 2);
    assert.equal(a.columns[0]!.length, 1024);
    assert.notDeepEqual(a.columns[0], b.columns[0]);
    assert.equal("randomizers" in a, false, "secret coefficients must not cross the seal API");
  });

  it("80 mask dimensions cover a worst-case 72-point two-row opening view", () => {
    const traceDomain = circleSubgroupDomain(64);
    const lde = circleHalfCosetDomain(1024);
    const starts = Array.from({ length: 36 }, (_, i) => (i * 27) % 1024);
    const indices = new Set<number>();
    for (const start of starts) {
      indices.add(start);
      indices.add((start + 16) % 1024);
    }
    assert.equal(indices.size, 72);
    const observations = [...indices].map((i) => lde[i]!);
    const matrix = randomizerEvaluationMatrix(traceDomain, observations, 80);
    assert.equal(m31MatrixRank(matrix), observations.length);
  });

  it("512 mask dimensions cover 216 direct locations at the successor geometry", () => {
    const trace = circleHalfCosetDomain(8192);
    const observations = Array.from({ length: 216 }, (_, i) => circleHalfCosetPoint(262144, i * 997));
    const matrix = randomizerEvaluationMatrix(trace, observations, 512);
    assert.equal(m31MatrixRank(matrix), observations.length);
  });

  it("masking ablation recovers the trace, while a full-rank seal erases that view", () => {
    const trace = circleSubgroupDomain(8);
    const witness = Array.from({ length: trace.length }, (_, row) => BigInt(row * 17 + 3));
    const observations: typeof trace[number][] = [];
    for (const point of circleHalfCosetDomain(16)) {
      if (traceEvaluationRank(trace, [...observations, point]) > observations.length) {
        observations.push(point);
      }
      if (observations.length === trace.length) break;
    }
    assert.equal(observations.length, trace.length);
    const witnessPolynomial = interpolateCircle(trace, witness);
    const unmaskedView = observations.map((point) => evalCirclePoly(witnessPolynomial, point));
    const evaluationMatrix = observations.map((point) =>
      Array.from({ length: trace.length }, (_, basis) => {
        const basisTrace = Array.from({ length: trace.length }, (_, row) =>
          row === basis ? 1n : 0n);
        return evalCirclePoly(interpolateCircle(trace, basisTrace), point);
      }));
    assert.deepEqual(solveSquare(evaluationMatrix, unmaskedView), witness);
    assert.equal(traceEvaluationRank(trace, observations), trace.length);

    // Full row rank means the secret mask map is surjective on the complete
    // observer vector: every unmasked witness shift is exactly covered by a
    // mask shift, which is the linear-algebra reason the distributions agree.
    const maskMap = randomizerEvaluationMatrix(trace, observations, trace.length);
    assert.equal(m31MatrixRank(maskMap), observations.length);
  });
});

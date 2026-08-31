import assert from "node:assert/strict";
import test from "node:test";

import {
  ONE,
  rational,
  rCompare,
  rPow2,
  rSecurityBits,
  rSqrtInterval,
} from "../src/assurance/rational.ts";
import {
  V17_ATTACKER_QUERY_LIMIT_EXCLUSIVE,
  bcsPerQueryError,
  certifyV17WorkFactor,
  maximumAllowedAdjustedRound,
  minimalGrindingBits,
  qm31ChallengeMaximumProbability,
  v17FriJohnsonBounds,
  withMinimalGrinding,
  type V17SoundnessRound,
} from "../src/assurance/v17-soundness.ts";

test("rational square-root intervals are outward and exact for dyadic squares", () => {
  const exact = rSqrtInterval(rational(1n, 16n));
  assert.deepEqual(exact, { lower: rational(1n, 4n), upper: rational(1n, 4n) });
  const interval = rSqrtInterval(rational(3n, 17n));
  assert.ok(rCompare(interval.lower, interval.upper) < 0);
  assert.ok(rCompare(rational(
    interval.lower.numerator ** 2n,
    interval.lower.denominator ** 2n,
  ), rational(3n, 17n)) <= 0);
  assert.ok(rCompare(rational(
    interval.upper.numerator ** 2n,
    interval.upper.denominator ** 2n,
  ), rational(3n, 17n)) >= 0);
});

test("QM31 modulo-reduction bias is exact and conservative", () => {
  const biased = qm31ChallengeMaximumProbability();
  assert.ok(rCompare(biased, rPow2(-124)) > 0);
  assert.ok(rCompare(biased, rPow2(-123)) < 0);
  assert.ok(rSecurityBits(biased) > 123 && rSecurityBits(biased) < 124);
});

test("BCS work-factor certificate checks both convex endpoints and fails closed", () => {
  const allowed = maximumAllowedAdjustedRound(2);
  const raw = rPow2(-90);
  const grindBits = minimalGrindingBits(raw, allowed);
  const rounds: V17SoundnessRound[] = [
    { id: "air", dependsOn: [], rawError: raw, grindBits, status: "proved", theorem: "local lemma" },
    { id: "fri", dependsOn: ["air"], rawError: raw, grindBits, status: "cited", theorem: "T19" },
  ];
  const certificate = certifyV17WorkFactor(rounds);
  assert.equal(certificate.qualified, true);
  assert.equal(certificate.endpoints.length, 2);
  assert.equal(certificate.endpoints[1]!.attackerQueries, V17_ATTACKER_QUERY_LIMIT_EXCLUSIVE - 1n);
  assert.ok(certificate.endpoints.every(({ passes }) => passes));
  const conjectural = certifyV17WorkFactor([
    rounds[0]!,
    { ...rounds[1]!, status: "conjectural" },
  ]);
  assert.equal(conjectural.qualified, false);
  assert.deepEqual(conjectural.reasons, ["fri:conjectural"]);
  assert.ok(rCompare(bcsPerQueryError(1n, 2, allowed), rPow2(-100)) <= 0);
});

test("minimal grinding is synthesized per round, never as a union worksheet", () => {
  const rounds = withMinimalGrinding([
    { id: "one", dependsOn: [], rawError: rPow2(-80), status: "proved", theorem: "L1" },
    { id: "two", dependsOn: ["one"], rawError: rPow2(-95), status: "cited", theorem: "T2" },
  ]);
  assert.ok(rounds[0]!.grindBits > rounds[1]!.grindBits);
  assert.equal(certifyV17WorkFactor(rounds).qualified, true);
});

test("Theorem 19 Johnson calculator stays inside the proven radius", () => {
  const bounds = v17FriJohnsonBounds({
    logBlowup: 4,
    evaluationLog: 24,
    batchWidth: 27,
    foldDomainLogs: [23, 21, 19, 17, 15, 13, 11, 9, 7],
    queries: 29,
    theta: rational(11n, 16n),
  });
  assert.equal(bounds.regime, "johnson");
  assert.equal(bounds.folds.length, 9);
  assert.ok(rCompare(bounds.batch, ONE) < 0);
  assert.ok(rCompare(bounds.query, rational(5n ** 29n, 16n ** 29n)) === 0);
  assert.throws(() => v17FriJohnsonBounds({
    logBlowup: 4,
    evaluationLog: 24,
    batchWidth: 27,
    foldDomainLogs: [23],
    queries: 29,
    theta: rational(3n, 4n),
  }), /outside proven Johnson regime/);
});

test("round DAG rejects forward dependencies", () => {
  assert.throws(() => certifyV17WorkFactor([
    { id: "a", dependsOn: ["b"], rawError: rPow2(-120), grindBits: 0, status: "proved", theorem: "L" },
    { id: "b", dependsOn: [], rawError: rPow2(-120), grindBits: 0, status: "proved", theorem: "L" },
  ]), /DAG order/);
});

import assert from "node:assert/strict";
import test from "node:test";

import { rational, rCompare, rPow2 } from "../src/assurance/rational.ts";
import { defaultV17FriParameterCandidates } from "../src/assurance/v17-parameter-synthesis.ts";
import {
  V17_CORRESPONDENCE_GATE_IDS,
  V17_THEOREM_M31,
  V17_THEOREM_OOD_POINT_SET_SIZE,
  buildV17TheoremMap,
  uniformV17OodPointMaximumProbability,
  v17Theorem15Bounds,
  v17Theorem15JohnsonListSize,
  type V17CorrespondenceGate,
  type V17FlatAirTheoremInput,
} from "../src/assurance/v17-theorem-map.ts";

const fri = defaultV17FriParameterCandidates()[0]!;

function air(): V17FlatAirTheoremInput {
  return {
    inputMessages: 8n,
    outputMessages: 1n,
    airDegree: 3n,
    theta: fri.theta,
    logBlowup: fri.logBlowup,
    tables: [{
      id: "local-word",
      rows: 1n << 18n,
      constraints: 25n,
      uses: 9n,
      yields: 1n,
      maximumMessageDimension: 24n,
      maximumMultiplicity: 1n << 21n,
    }],
    oodPointMaximumProbability: uniformV17OodPointMaximumProbability(),
  };
}

function gates(status: V17CorrespondenceGate["status"]): readonly V17CorrespondenceGate[] {
  return V17_CORRESPONDENCE_GATE_IDS.map((id) => ({ id, status, evidence: `kat:${id}` }));
}

test("Theorem 15 uses exact Circle-set cardinalities and checks its side conditions", () => {
  assert.equal(V17_THEOREM_OOD_POINT_SET_SIZE,
    V17_THEOREM_M31 ** 4n - V17_THEOREM_M31 - 2n);
  const bounds = v17Theorem15Bounds(air());
  assert.equal(bounds.technicalCondition54, true);
  assert.equal(bounds.multiplicitiesBelowCharacteristic, true);
  assert.ok(rCompare(bounds.logup, rPow2(-90)) < 0);
  assert.ok(rCompare(bounds.composition, bounds.logup) < 0);
  assert.ok(rCompare(bounds.outOfDomain, bounds.logup) < 0);
});

test("Theorem 15 equation 54 uses the linear (1+2/N) factor", () => {
  const singleRow = air();
  const bounds = v17Theorem15Bounds({
    ...singleRow,
    theta: rational(1n, 2n),
    logBlowup: 4,
    tables: singleRow.tables.map((table) => ({ ...table, rows: 1n })),
  });
  // 1/2 > (1/16)*3, while 1/2 is not > (1/16)*3^2. This vector
  // therefore fails if equation (54)'s parenthesized factor is squared.
  assert.equal(bounds.technicalCondition54, true);
});

test("Johnson list formula rejects the unproved radius", () => {
  assert.ok(rCompare(v17Theorem15JohnsonListSize(fri.theta, fri.logBlowup), rational(1n)) > 0);
  assert.throws(() => v17Theorem15JohnsonListSize(rational(3n, 4n), 4),
    /outside Johnson radius/);
});

test("the theorem DAG assigns a separate minimum grind to every round", () => {
  const map = buildV17TheoremMap({ air: air(), fri, gates: gates("proved") });
  assert.equal(map.rounds.length, 14);
  assert.equal(map.certificate.qualified, true);
  assert.ok(map.rounds.every(({ grindBits }) => Number.isSafeInteger(grindBits) && grindBits >= 0));
  assert.deepEqual(map.rounds.slice(0, 4).map(({ id }) => id),
    ["air:logup", "air:composition", "air:ood", "fri:batch"]);
});

test("unresolved correspondence and theorem side conditions fail closed", () => {
  const unresolved = gates("proved").map((gate) => gate.id === "grouped-folds"
    ? { ...gate, status: "unresolved" as const }
    : gate);
  const map = buildV17TheoremMap({ air: air(), fri, gates: unresolved });
  assert.equal(map.certificate.qualified, false);
  assert.ok(map.certificate.reasons.includes("fri:fold:0:unresolved"));

  const invalidMultiplicity = air();
  const bad = buildV17TheoremMap({
    air: {
      ...invalidMultiplicity,
      tables: invalidMultiplicity.tables.map((table) => ({
        ...table,
        maximumMultiplicity: V17_THEOREM_M31,
      })),
    },
    fri,
    gates: gates("proved"),
  });
  assert.equal(bad.certificate.qualified, false);
  assert.ok(bad.certificate.reasons.includes("multiplicity-field-bound"));
});

test("gate coverage and OOD sampler probability are mandatory", () => {
  assert.throws(() => buildV17TheoremMap({ air: air(), fri, gates: gates("proved").slice(1) }),
    /gate coverage/);
  assert.throws(() => v17Theorem15Bounds({
    ...air(),
    oodPointMaximumProbability: rational(0n),
  }), /geometry/);
});

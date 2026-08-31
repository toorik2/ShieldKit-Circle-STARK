import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { V17_PRODUCTION_ROLE_LAYOUT } from "../src/chain/v17-role-layout.ts";
import type { V17Profile } from "../src/construction/v17-graph.ts";
import {
  aggregateV17P2shMeasurements,
  v17CarrierCapacityProofBytes,
  v17ResidualProofBytes,
  V17_P2SH_PROFILE_MEASUREMENT_SCHEMA,
  type V17P2shProfileMeasurement,
} from "../scripts/v17-p2sh-measurements.ts";

function profileMeasurement(profile: V17Profile): V17P2shProfileMeasurement {
  const roles = V17_PRODUCTION_ROLE_LAYOUT.map((role, index) => {
    const operationCost = 800 * (2_000 + index + profile * 100);
    const densityControlLength = 1_000 + profile;
    const proofCarrierBytes = 256 + profile;
    return {
      logicalInputIndex: index,
      roleId: role.id,
      familyId: role.familyId,
      kind: role.kind,
      operationCost,
      densityControlLength,
      proofCarrierBytes,
      nonProofDensityBytes: densityControlLength - proofCarrierBytes,
      requiredProofBytes: v17ResidualProofBytes({
        operationCost,
        densityControlLength,
        proofCarrierBytes,
      }),
      capacityProofBytes: v17CarrierCapacityProofBytes(500, role.id),
      redeemBytes: 500,
      unlockingBytes: 760,
      maximumMemorySlots: 20,
      maximumControlDepth: 3,
      maximumStackItemBytes: 256,
      hashDigestIterations: 4,
      evaluatedInstructions: 100,
    };
  });
  return {
    schema: V17_P2SH_PROFILE_MEASUREMENT_SCHEMA,
    status: "measured-unbounded-opcost-diagnostic",
    operationCostEngine: "libauth-3.1.0-next.8-bch2026-diagnostic",
    protocolIdHex: "ab".repeat(32),
    profile,
    proofBytes: 447_000 + profile,
    proofSha256Hex: (profile + 1).toString(16).padStart(2, "0").repeat(32),
    transactionBytes: 700_000 + profile,
    transactionSha256Hex: (profile + 4).toString(16).padStart(2, "0").repeat(32),
    roleCount: roles.length,
    roles,
  };
}

describe("v17 exact P2SH residual measurement aggregation", () => {
  it("requires and combines the canonical 210-role inventory in profile order", () => {
    const measurements = [profileMeasurement(2), profileMeasurement(0), profileMeasurement(1)];
    const aggregate = aggregateV17P2shMeasurements(measurements);
    assert.equal(aggregate.roleCount, V17_PRODUCTION_ROLE_LAYOUT.length);
    assert.deepEqual(aggregate.profiles.map(({ profile }) => profile), [0, 1, 2]);
    aggregate.roles.forEach((role, index) => {
      assert.equal(role.roleId, V17_PRODUCTION_ROLE_LAYOUT[index]!.id);
      assert.equal(role.requiredProofBytes, role.profileRequiredProofBytes[2]);
      assert.equal(role.maximumOperationCost, role.profileOperationCosts[2]);
      assert.equal(role.capacityProofBytes, role.profileCapacityProofBytes[0]);
    });
    assert.equal(aggregate.minimumProofBytesBeforeQuantizationGuards,
      aggregate.roles.reduce((sum, role) => sum + role.requiredProofBytes, 0));
  });

  it("rejects a missing profile and a role-order mutation", () => {
    assert.throws(() => aggregateV17P2shMeasurements([
      profileMeasurement(0), profileMeasurement(1),
    ]), /requires profiles/);
    const changed = structuredClone(profileMeasurement(2));
    (changed.roles[4] as { roleId: string }).roleId = "wrong";
    assert.throws(() => aggregateV17P2shMeasurements([
      profileMeasurement(0), profileMeasurement(1), changed,
    ]), /measurement role/);
  });
});

import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { compileV17AffineReaderConstruction } from
  "../src/chain/v17-affine-reader-vm.ts";
import { V17_PRODUCTION_ROLE_LAYOUT } from "../src/chain/v17-role-layout.ts";
import {
  allocateV17DensityClosure,
  appendV17DensityClosureTrace,
  createV17DensityClosure,
  createV17DensityClosureTrace,
  joinV17DensityClosure,
  replayV17DensityClosureTrace,
  validateV17DensityClosure,
  validateV17DensityRows,
  v17DensityClosureDominates,
  type V17DensityClosureTrace,
  type V17DensityFeasibilityRow,
} from "../src/construction/v17-density-closure.ts";

function rows(seed = 0): readonly V17DensityFeasibilityRow[] {
  return V17_PRODUCTION_ROLE_LAYOUT.map((role, index) => {
    const required = 256 + ((index + seed) % 5);
    const costs = [
      1_000 + seed + index,
      1_100 + seed + index,
      1_200 + seed + index,
    ] as const;
    const requiredProfiles = [required, required + 1, required + 2] as const;
    const capacities = [9_000 - (index % 3), 8_999 - (index % 3), 8_998 - (index % 3)] as const;
    return {
      roleId: role.id,
      maximumOperationCost: Math.max(...costs),
      profileOperationCosts: costs,
      requiredProofBytes: Math.max(...requiredProfiles),
      profileRequiredProofBytes: requiredProfiles,
      capacityProofBytes: Math.min(...capacities),
      profileCapacityProofBytes: capacities,
    };
  });
}

function replaceRow(
  source: readonly V17DensityFeasibilityRow[],
  index: number,
  replacement: V17DensityFeasibilityRow,
): readonly V17DensityFeasibilityRow[] {
  return source.map((row, at) => at === index ? replacement : row);
}

function append(
  trace: V17DensityClosureTrace,
  measuredRows: readonly V17DensityFeasibilityRow[],
  phase: "local-sizing" | "post-link-bchn" = "local-sizing",
): V17DensityClosureTrace {
  const head = replayV17DensityClosureTrace(trace);
  return appendV17DensityClosureTrace({
    trace,
    phase,
    currentAllocation: head.allocation,
    currentReader: compileV17AffineReaderConstruction(head.allocation).evidence,
    romPreviewIdHex: "11".repeat(32),
    measurementEvidenceSha256Hex: "22".repeat(32),
    measuredRows,
  });
}

describe("v17 monotone density closure", () => {
  it("joins profile coordinates monotonically and derives every aggregate", () => {
    const firstRows = rows();
    const retained = createV17DensityClosure(firstRows);
    const old = firstRows[7]!;
    const nextCosts = [old.profileOperationCosts[0] - 10,
      old.profileOperationCosts[1] + 500, old.profileOperationCosts[2] - 20] as const;
    const nextRequired = [old.profileRequiredProofBytes[0] + 9,
      old.profileRequiredProofBytes[1] - 1, old.profileRequiredProofBytes[2] + 4] as const;
    const nextCapacities = [old.profileCapacityProofBytes[0] + 2,
      old.profileCapacityProofBytes[1] - 7, old.profileCapacityProofBytes[2] + 3] as const;
    const nextRow = {
      roleId: old.roleId,
      profileOperationCosts: nextCosts,
      maximumOperationCost: Math.max(...nextCosts),
      profileRequiredProofBytes: nextRequired,
      requiredProofBytes: Math.max(...nextRequired),
      profileCapacityProofBytes: nextCapacities,
      capacityProofBytes: Math.min(...nextCapacities),
    };
    const measured = replaceRow(firstRows, 7, nextRow);
    const joined = joinV17DensityClosure(retained, measured);
    const row = joined.rows[7]!;
    assert.deepEqual(row.profileOperationCosts, [
      old.profileOperationCosts[0], nextCosts[1], old.profileOperationCosts[2],
    ]);
    assert.deepEqual(row.profileRequiredProofBytes, [
      nextRequired[0], old.profileRequiredProofBytes[1], nextRequired[2],
    ]);
    assert.deepEqual(row.profileCapacityProofBytes, [
      old.profileCapacityProofBytes[0], nextCapacities[1], old.profileCapacityProofBytes[2],
    ]);
    assert.equal(row.maximumOperationCost, Math.max(...row.profileOperationCosts));
    assert.equal(row.requiredProofBytes, Math.max(...row.profileRequiredProofBytes));
    assert.equal(row.capacityProofBytes, Math.min(...row.profileCapacityProofBytes));
    assert.equal(v17DensityClosureDominates(joined, firstRows), true);
    assert.equal(v17DensityClosureDominates(joined, measured), true);
    const allocation = allocateV17DensityClosure(joined);
    assert.equal(allocation.at(-1)!.basePrefixEnd, joined.minimumProofBytes);
    assert.equal(allocation.at(-1)!.elasticPrefixEnd, 4_095);
  });

  it("closes an oscillating map only on an explicit no-change pass", () => {
    const first = rows();
    const old = first[12]!;
    const raisedRequired = [old.profileRequiredProofBytes[0] + 17,
      old.profileRequiredProofBytes[1], old.profileRequiredProofBytes[2]] as const;
    const second = replaceRow(first, 12, {
      ...old,
      profileRequiredProofBytes: raisedRequired,
      requiredProofBytes: Math.max(...raisedRequired),
      profileCapacityProofBytes: [old.profileCapacityProofBytes[0],
        old.profileCapacityProofBytes[1] - 11, old.profileCapacityProofBytes[2]],
      capacityProofBytes: old.profileCapacityProofBytes[1] - 11,
    });
    let trace = createV17DensityClosureTrace();
    trace = append(trace, first);
    assert.equal(replayV17DensityClosureTrace(trace).terminalNoChange, false);
    trace = append(trace, second);
    assert.equal(replayV17DensityClosureTrace(trace).terminalNoChange, false);
    trace = append(trace, first, "post-link-bchn");
    const head = replayV17DensityClosureTrace(trace);
    assert.equal(head.terminalNoChange, true);
    assert.equal(head.terminalPhase, "post-link-bchn");
    assert.deepEqual(trace.entries.map(({ changedRoleIds }) => changedRoleIds.length),
      [V17_PRODUCTION_ROLE_LAYOUT.length, 1, 0]);
    assert.equal(head.closure!.rows[12]!.profileRequiredProofBytes[0], raisedRequired[0]);
    assert.equal(head.closure!.rows[12]!.profileCapacityProofBytes[1],
      second[12]!.profileCapacityProofBytes[1]);
  });

  it("rejects malformed rows, infeasible joins, caller state, and trace edits", () => {
    const valid = rows();
    const wrongOrder = [valid[1]!, valid[0]!, ...valid.slice(2)];
    assert.throws(() => validateV17DensityRows(wrongOrder), /row/);
    assert.throws(() => validateV17DensityRows(replaceRow(valid, 0, {
      ...valid[0]!,
      profileRequiredProofBytes: [255, 256, 256],
      requiredProofBytes: 256,
    })), /row/);
    assert.throws(() => validateV17DensityRows(replaceRow(valid, 0, {
      ...valid[0]!,
      profileCapacityProofBytes: [10_001, 9_000, 9_000],
    })), /row/);
    assert.throws(() => validateV17DensityRows(replaceRow(valid, 0, {
      ...valid[0]!,
      maximumOperationCost: valid[0]!.maximumOperationCost + 1,
    })), /row/);
    const impossible = replaceRow(valid, 0, {
      ...valid[0]!,
      profileRequiredProofBytes: [9_001, 9_001, 9_001],
      requiredProofBytes: 9_001,
      profileCapacityProofBytes: [9_000, 9_000, 9_000],
      capacityProofBytes: 9_000,
    });
    assert.throws(() => joinV17DensityClosure(null, impossible), /infeasible/);

    let trace = append(createV17DensityClosureTrace(), valid);
    trace = append(trace, valid, "post-link-bchn");
    assert.equal(replayV17DensityClosureTrace(trace).terminalNoChange, true);
    const edited = structuredClone(trace);
    (edited.entries[1] as { measurementEvidenceSha256Hex: string })
      .measurementEvidenceSha256Hex = "ff".repeat(32);
    assert.throws(() => replayV17DensityClosureTrace(edited), /trace entry/);
    assert.throws(() => replayV17DensityClosureTrace({
      ...trace,
      entries: trace.entries.slice(1),
    }), /trace entry/);
    const wrongState = replayV17DensityClosureTrace(createV17DensityClosureTrace()).allocation;
    assert.throws(() => appendV17DensityClosureTrace({
      trace,
      phase: "post-link-bchn",
      currentAllocation: wrongState,
      currentReader: compileV17AffineReaderConstruction(wrongState).evidence,
      romPreviewIdHex: "11".repeat(32),
      measurementEvidenceSha256Hex: "22".repeat(32),
      measuredRows: valid,
    }), /caller state/);
    const finalClosure = replayV17DensityClosureTrace(trace).closure!;
    assert.deepEqual(validateV17DensityClosure(finalClosure), finalClosure);
  });
});

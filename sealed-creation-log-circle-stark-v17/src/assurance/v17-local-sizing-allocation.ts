import { createHash } from "node:crypto";
import { createVirtualMachine } from "@bitauth/libauth";
import {
  V17_INPUT_FIXED_DENSITY_BYTES,
  assessV17UnqualifiedSizingDensity,
  type V17UnqualifiedSizingProfile,
} from "../construction/v17-linker.ts";
import {
  V17_CONSTRUCTION_GRAPH,
  V17_PROFILES,
  canonicalV17Json,
} from "../construction/v17-graph.ts";
import type { V17PostLinkCandidateSet } from
  "../construction/v17-product-link.ts";
import type { V17PublicSettlementFixture } from
  "../construction/v17-settlement-transaction.ts";
import type { V17AffineAllocation } from "../chain/v17-affine-allocation.ts";
import {
  appendV17DensityClosureTrace,
  replayV17DensityClosureTrace,
  type V17DensityClosureTrace,
  type V17DensityFeasibilityRow,
} from "../construction/v17-density-closure.ts";
import { encodeV17CanonicalPush } from "../chain/v17-code-rom.ts";
import {
  V17_LIBAUTH_OP_DEFINE_DIAGNOSTIC_ENGINE,
  createV17LibauthBchnOpDefineDiagnosticInstructionSet,
} from "./v17-libauth-opdefine-diagnostic.ts";
import { materializeV17PostLinkCandidateEnvelopes } from
  "./v17-post-link-bchn-measurement.ts";

export const V17_LOCAL_SIZING_ALLOCATION_SCHEMA =
  "ShieldKit/V17LocalSizingAllocation/v2" as const;

export type V17LocalSizingAllocation = {
  readonly schema: typeof V17_LOCAL_SIZING_ALLOCATION_SCHEMA;
  readonly status: "fixed-point" | "requires-resizing";
  readonly qualification: "local-sizing-only-not-resource-evidence";
  readonly engine: typeof V17_LIBAUTH_OP_DEFINE_DIAGNOSTIC_ENGINE;
  readonly currentAllocation: V17AffineAllocation;
  readonly measuredAllocation: V17AffineAllocation;
  readonly measurementSha256Hex: string;
  readonly measuredRows: readonly V17DensityFeasibilityRow[];
  readonly trace: V17DensityClosureTrace;
  readonly profiles: readonly {
    readonly profile: 0 | 1 | 2;
    readonly maximumOperationCost: number;
    readonly workers: number;
  }[];
};

export type V17LocalSizingProfiles = readonly [
  V17UnqualifiedSizingProfile,
  V17UnqualifiedSizingProfile,
  V17UnqualifiedSizingProfile,
];

function allocationGeometry(allocation: V17AffineAllocation): unknown {
  return {
    minimumProofBytes: allocation.minimumProofBytes,
    maximumProofBytes: allocation.maximumProofBytes,
    elasticScaleUnits: allocation.elasticScaleUnits,
    assignments: allocation.assignments,
  };
}

function digest(value: unknown): string {
  return createHash("sha256").update(canonicalV17Json(value)).digest("hex");
}

/**
 * Find an executable affine allocation before invoking the independent BCHN
 * oracle. This pass runs the exact linked transactions and the source-backed
 * BCHN OP_DEFINE delta, but it is intentionally non-evidentiary: only a later
 * byte-exact BCHN fixed point can qualify resource acceptance.
 */
export function measureV17LocalSizingProfiles(args: {
  readonly candidates: V17PostLinkCandidateSet;
  readonly fixtures: readonly V17PublicSettlementFixture[];
}): V17LocalSizingProfiles {
  const envelopes = materializeV17PostLinkCandidateEnvelopes(args);
  const profiles = envelopes.map((envelope): V17UnqualifiedSizingProfile => {
    const instructionSet = createV17LibauthBchnOpDefineDiagnosticInstructionSet(false);
    const every = instructionSet.every!;
    const vm = createVirtualMachine({
      ...instructionSet,
      every: (state) => {
        state.metrics.maximumOperationCost = 1_000_000_000;
        return every(state);
      },
    });
    const workers = envelope.candidate.roles.map((role, inputIndex) => {
      if (role.index !== inputIndex || role.carrier.index !== inputIndex) {
        throw new Error(`v17 local sizing role index ${envelope.profile}:${inputIndex}`);
      }
      const state = vm.evaluate({
        inputIndex,
        sourceOutputs: envelope.materialized.sourceOutputs,
        transaction: envelope.materialized.transaction,
      } as never);
      if (vm.stateSuccess(state) !== true) {
        throw new Error(
          `v17 local sizing execution ${envelope.profile}:${inputIndex}: ${String(state.error)}`,
        );
      }
      const maximumOperationCost = Number(state.metrics.operationCost);
      if (!Number.isSafeInteger(maximumOperationCost) || maximumOperationCost < 1) {
        throw new Error(`v17 local sizing opcost ${envelope.profile}:${inputIndex}`);
      }
      const input = envelope.materialized.transaction.inputs[inputIndex]!;
      const sourceOutput = envelope.materialized.sourceOutputs[inputIndex]!;
      const redeemPushBytes = encodeV17CanonicalPush(role.redeem).length;
      const unlockingPrefixBytecode = role.unlockingBytecode.slice(
        0,
        role.unlockingBytecode.length - redeemPushBytes,
      );
      return {
        profile: envelope.profile,
        logicalInputIndex: inputIndex,
        roleId: role.name,
        redeemBytecode: role.redeem,
        unlockingPrefixBytecode,
        proofCarrierBytes: role.carrier.chunk.length,
        valueSatoshis: sourceOutput.valueSatoshis,
        sequenceNumber: input.sequenceNumber,
        maximumOperationCost,
        densityControlLength: V17_INPUT_FIXED_DENSITY_BYTES + role.unlockingBytecode.length,
      };
    });
    return {
      qualification: "local-sizing-only-not-resource-evidence",
      profile: envelope.profile,
      workers,
    };
  }) as unknown as V17LocalSizingProfiles;
  if (profiles.some((profile, index) => profile.profile !== V17_PROFILES[index])) {
    throw new Error("v17 local sizing profile order");
  }
  return profiles;
}

export function deriveV17LocalSizingAllocation(args: {
  readonly candidates: V17PostLinkCandidateSet;
  readonly fixtures: readonly V17PublicSettlementFixture[];
  readonly trace: V17DensityClosureTrace;
}): V17LocalSizingAllocation {
  const profiles = measureV17LocalSizingProfiles(args);
  const currentAllocation = args.candidates.profiles[0]!.allocation;
  if (args.candidates.profiles.some((profile) =>
    canonicalV17Json(allocationGeometry(profile.allocation)) !==
      canonicalV17Json(allocationGeometry(currentAllocation)))) {
    throw new Error("v17 local sizing mixed allocation");
  }
  const feasibility = assessV17UnqualifiedSizingDensity(V17_CONSTRUCTION_GRAPH, profiles);
  if (feasibility.status !== "feasible") {
    throw new Error(`v17 local sizing infeasible ${feasibility.infeasibleRoleIds.join(",")}`);
  }
  const summary = profiles.map((profile) => ({
    profile: profile.profile,
    maximumOperationCost: Math.max(...profile.workers.map((worker) =>
      worker.maximumOperationCost)),
    workers: profile.workers.length,
  }));
  const measurementSha256Hex = digest({
      schema: V17_LOCAL_SIZING_ALLOCATION_SCHEMA,
      qualification: "local-sizing-only-not-resource-evidence",
      engine: V17_LIBAUTH_OP_DEFINE_DIAGNOSTIC_ENGINE,
      currentGeometry: allocationGeometry(currentAllocation),
      measuredRows: feasibility.rows,
      profiles: profiles.map((profile) => ({
        profile: profile.profile,
        workers: profile.workers.map((worker) => ({
          logicalInputIndex: worker.logicalInputIndex,
          roleId: worker.roleId,
          proofCarrierBytes: worker.proofCarrierBytes,
          redeemBytes: worker.redeemBytecode.length,
          densityControlLength: worker.densityControlLength,
          maximumOperationCost: worker.maximumOperationCost,
        })),
      })),
    });
  const reader = args.candidates.preview.affineReader;
  if (reader === null) throw new Error("v17 local sizing missing affine reader");
  const trace = appendV17DensityClosureTrace({
    trace: args.trace,
    phase: "local-sizing",
    currentAllocation,
    currentReader: reader.evidence,
    romPreviewIdHex: args.candidates.preview.certificate.previewIdHex,
    measurementEvidenceSha256Hex: measurementSha256Hex,
    measuredRows: feasibility.rows,
  });
  const head = replayV17DensityClosureTrace(trace);
  const entry = trace.entries.at(-1)!;
  return {
    schema: V17_LOCAL_SIZING_ALLOCATION_SCHEMA,
    status: entry.noChange ? "fixed-point" : "requires-resizing",
    qualification: "local-sizing-only-not-resource-evidence",
    engine: V17_LIBAUTH_OP_DEFINE_DIAGNOSTIC_ENGINE,
    currentAllocation,
    measuredAllocation: head.allocation,
    measurementSha256Hex,
    measuredRows: feasibility.rows,
    trace,
    profiles: summary,
  };
}

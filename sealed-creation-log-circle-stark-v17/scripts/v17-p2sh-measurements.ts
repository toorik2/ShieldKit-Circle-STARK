import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { V17_PRODUCTION_ROLE_LAYOUT } from "../src/chain/v17-role-layout.ts";
import {
  V17_CONSTRUCTION_GRAPH,
  V17_PROFILES,
  canonicalV17Json,
  type V17Profile,
} from "../src/construction/v17-graph.ts";
import { V17_OPCOST_PER_DENSITY_BYTE } from "../src/construction/v17-linker.ts";
import { LOCAL_WORD_BATCH_LEADER_ROLE_ID } from
  "../src/chain/local-word-proof-carriers.ts";
import { V17_BATCH_LEADER_CELL_BYTES } from
  "../src/backends/circle/v17-batch-leader-cell.ts";

export const V17_P2SH_PROFILE_MEASUREMENT_SCHEMA =
  "ShieldKit/V17P2shProfileMeasurement/v1" as const;
export const V17_P2SH_AGGREGATE_MEASUREMENT_SCHEMA =
  "ShieldKit/V17P2shAggregateMeasurement/v1" as const;

export type V17P2shRoleMeasurement = {
  readonly logicalInputIndex: number;
  readonly roleId: string;
  readonly familyId: string;
  readonly kind: typeof V17_PRODUCTION_ROLE_LAYOUT[number]["kind"];
  readonly operationCost: number;
  readonly densityControlLength: number;
  readonly proofCarrierBytes: number;
  readonly nonProofDensityBytes: number;
  readonly requiredProofBytes: number;
  readonly capacityProofBytes: number;
  readonly redeemBytes: number;
  readonly unlockingBytes: number;
  readonly maximumMemorySlots: number;
  readonly maximumControlDepth: number;
  readonly maximumStackItemBytes: number;
  readonly hashDigestIterations: number;
  readonly evaluatedInstructions: number;
};

export type V17P2shProfileMeasurement = {
  readonly schema: typeof V17_P2SH_PROFILE_MEASUREMENT_SCHEMA;
  readonly status: "measured-unbounded-opcost-diagnostic";
  readonly operationCostEngine: "libauth-3.1.0-next.8-bch2026-diagnostic";
  readonly protocolIdHex: string;
  readonly profile: V17Profile;
  readonly proofBytes: number;
  readonly proofSha256Hex: string;
  readonly transactionBytes: number;
  readonly transactionSha256Hex: string;
  readonly roleCount: number;
  readonly roles: readonly V17P2shRoleMeasurement[];
};

export type V17P2shAggregateMeasurement = {
  readonly schema: typeof V17_P2SH_AGGREGATE_MEASUREMENT_SCHEMA;
  readonly status: "measured-unbounded-opcost-diagnostic";
  readonly operationCostEngine: V17P2shProfileMeasurement["operationCostEngine"];
  readonly protocolIdHex: string;
  readonly roleCount: number;
  readonly profiles: readonly {
    readonly profile: V17Profile;
    readonly proofBytes: number;
    readonly proofSha256Hex: string;
    readonly transactionBytes: number;
    readonly transactionSha256Hex: string;
    readonly measurementSha256Hex: string;
  }[];
  readonly roles: readonly {
    readonly logicalInputIndex: number;
    readonly roleId: string;
    readonly familyId: string;
    readonly kind: V17P2shRoleMeasurement["kind"];
    readonly profileOperationCosts: readonly [number, number, number];
    readonly profileRequiredProofBytes: readonly [number, number, number];
    readonly profileCapacityProofBytes: readonly [number, number, number];
    readonly maximumOperationCost: number;
    readonly requiredProofBytes: number;
    readonly capacityProofBytes: number;
  }[];
  readonly minimumProofBytesBeforeQuantizationGuards: number;
};

function assertHex32(label: string, value: string): void {
  if (!/^[0-9a-f]{64}$/.test(value)) throw new Error(`v17 measurement ${label}`);
}

function sha256Hex(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

export function v17ResidualProofBytes(args: {
  readonly operationCost: number;
  readonly densityControlLength: number;
  readonly proofCarrierBytes: number;
}): number {
  if (!Number.isSafeInteger(args.operationCost) || args.operationCost < 1 ||
    !Number.isSafeInteger(args.densityControlLength) || args.densityControlLength < 1 ||
    !Number.isSafeInteger(args.proofCarrierBytes) || args.proofCarrierBytes < 1 ||
    args.proofCarrierBytes > args.densityControlLength) {
    throw new Error("v17 residual measurement shape");
  }
  return Math.max(
    V17_CONSTRUCTION_GRAPH.allocation.minimumProofBytesPerRole,
    Math.ceil(args.operationCost / V17_OPCOST_PER_DENSITY_BYTE) -
      (args.densityControlLength - args.proofCarrierBytes),
  );
}

export function v17CarrierCapacityProofBytes(redeemBytes: number, roleId?: string): number {
  if (!Number.isSafeInteger(redeemBytes) || redeemBytes < 1 || redeemBytes > 10_000) {
    throw new Error("v17 carrier capacity redeem width");
  }
  const pushOverhead = redeemBytes <= 75 ? 1 : redeemBytes <= 0xff ? 2 : 3;
  const cellBytes = roleId === LOCAL_WORD_BATCH_LEADER_ROLE_ID
    ? 2 + V17_BATCH_LEADER_CELL_BYTES
    : 0;
  return 10_000 - 3 - cellBytes - pushOverhead - redeemBytes;
}

export function validateV17P2shProfileMeasurement(
  measurement: V17P2shProfileMeasurement,
): V17P2shProfileMeasurement {
  if (measurement.schema !== V17_P2SH_PROFILE_MEASUREMENT_SCHEMA ||
    measurement.status !== "measured-unbounded-opcost-diagnostic" ||
    measurement.operationCostEngine !== "libauth-3.1.0-next.8-bch2026-diagnostic" ||
    !V17_PROFILES.includes(measurement.profile) ||
    !Number.isSafeInteger(measurement.proofBytes) || measurement.proofBytes < 1 ||
    !Number.isSafeInteger(measurement.transactionBytes) || measurement.transactionBytes < 1 ||
    measurement.roleCount !== V17_PRODUCTION_ROLE_LAYOUT.length ||
    measurement.roles.length !== V17_PRODUCTION_ROLE_LAYOUT.length) {
    throw new Error("v17 profile measurement envelope");
  }
  assertHex32("protocol id", measurement.protocolIdHex);
  assertHex32("proof digest", measurement.proofSha256Hex);
  assertHex32("transaction digest", measurement.transactionSha256Hex);
  measurement.roles.forEach((row, index) => {
    const role = V17_PRODUCTION_ROLE_LAYOUT[index]!;
    if (row.logicalInputIndex !== index || row.roleId !== role.id ||
      row.familyId !== role.familyId || row.kind !== role.kind ||
      !Number.isSafeInteger(row.nonProofDensityBytes) || row.nonProofDensityBytes < 1 ||
      row.nonProofDensityBytes !== row.densityControlLength - row.proofCarrierBytes ||
      row.requiredProofBytes !== v17ResidualProofBytes(row) ||
      !Number.isSafeInteger(row.redeemBytes) || row.redeemBytes < 1 ||
      row.capacityProofBytes !== v17CarrierCapacityProofBytes(row.redeemBytes, row.roleId) ||
      row.requiredProofBytes > row.capacityProofBytes ||
      !Number.isSafeInteger(row.unlockingBytes) || row.unlockingBytes < 1 ||
      !Number.isSafeInteger(row.maximumMemorySlots) || row.maximumMemorySlots < 1 ||
      !Number.isSafeInteger(row.maximumControlDepth) || row.maximumControlDepth < 0 ||
      !Number.isSafeInteger(row.maximumStackItemBytes) || row.maximumStackItemBytes < 1 ||
      !Number.isSafeInteger(row.hashDigestIterations) || row.hashDigestIterations < 0 ||
      !Number.isSafeInteger(row.evaluatedInstructions) || row.evaluatedInstructions < 1) {
      throw new Error(`v17 profile measurement role ${measurement.profile}:${role.id}`);
    }
  });
  return measurement;
}

export function aggregateV17P2shMeasurements(
  measurements: readonly V17P2shProfileMeasurement[],
): V17P2shAggregateMeasurement {
  if (measurements.length !== V17_PROFILES.length) {
    throw new Error("v17 aggregate requires profiles 0, 1, and 2");
  }
  const checked = [...measurements]
    .map(validateV17P2shProfileMeasurement)
    .sort((left, right) => left.profile - right.profile);
  if (checked.some((measurement, index) => measurement.profile !== V17_PROFILES[index]) ||
    new Set(checked.map(({ protocolIdHex }) => protocolIdHex)).size !== 1) {
    throw new Error("v17 aggregate profile or protocol mismatch");
  }
  const roles = V17_PRODUCTION_ROLE_LAYOUT.map((role, index) => {
    const rows = checked.map((measurement) => measurement.roles[index]!);
    const profileOperationCosts = rows.map(({ operationCost }) => operationCost) as
      unknown as readonly [number, number, number];
    const profileRequiredProofBytes = rows.map(({ requiredProofBytes }) => requiredProofBytes) as
      unknown as readonly [number, number, number];
    const profileCapacityProofBytes = rows.map(({ capacityProofBytes }) => capacityProofBytes) as
      unknown as readonly [number, number, number];
    return {
      logicalInputIndex: index,
      roleId: role.id,
      familyId: role.familyId,
      kind: role.kind,
      profileOperationCosts,
      profileRequiredProofBytes,
      profileCapacityProofBytes,
      maximumOperationCost: Math.max(...profileOperationCosts),
      requiredProofBytes: Math.max(...profileRequiredProofBytes),
      capacityProofBytes: Math.min(...profileCapacityProofBytes),
    };
  });
  return {
    schema: V17_P2SH_AGGREGATE_MEASUREMENT_SCHEMA,
    status: "measured-unbounded-opcost-diagnostic",
    operationCostEngine: "libauth-3.1.0-next.8-bch2026-diagnostic",
    protocolIdHex: checked[0]!.protocolIdHex,
    roleCount: roles.length,
    profiles: checked.map((measurement) => ({
      profile: measurement.profile,
      proofBytes: measurement.proofBytes,
      proofSha256Hex: measurement.proofSha256Hex,
      transactionBytes: measurement.transactionBytes,
      transactionSha256Hex: measurement.transactionSha256Hex,
      measurementSha256Hex: sha256Hex(canonicalV17Json(measurement)),
    })),
    roles,
    minimumProofBytesBeforeQuantizationGuards: roles.reduce(
      (sum, role) => sum + role.requiredProofBytes,
      0,
    ),
  };
}

export function readV17P2shProfileMeasurement(path: string): V17P2shProfileMeasurement {
  return validateV17P2shProfileMeasurement(
    JSON.parse(readFileSync(path, "utf8")) as V17P2shProfileMeasurement,
  );
}

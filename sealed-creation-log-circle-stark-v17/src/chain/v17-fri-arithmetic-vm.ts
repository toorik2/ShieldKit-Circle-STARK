/** BCH-2026 lowering certificate for the v17 FRI arithmetic kernel. */
import {
  OpcodesBch,
  binToHex,
  cashAssemblyToBin,
  decodeAuthenticationInstructions,
} from "@bitauth/libauth";
import { M31, inv as mInv, type M31El } from "../backends/circle/m31.ts";
import { V17_FRI_CURRENT_DENOMINATOR_COUNT } from
  "../backends/circle/v17-fri-arithmetic.ts";
import { M31_INV, M31_MUL } from "./m31-asm.ts";
import { QM31_ADD_ASM, QM31_MUL_ASM, QM31_MUL_M31_ASM } from "./qm31-asm.ts";
import { V17_CONSTRUCTION_GRAPH, V17_PROFILES } from "../construction/v17-graph.ts";

export type V17FriInversionMode = "legacy" | "batch";

export type V17FriVmLoweringFootprint = {
  readonly bytecodeBytes: number;
  readonly instructionCount: number;
  readonly nativeMultiplyOpcodes: number;
};

export type V17FriArithmeticVmCertificate = {
  readonly layerArities: readonly (2 | 4)[];
  readonly denominators: number;
  readonly proofSuppliedInverseBytes: 0;
  readonly legacy: {
    readonly m31Inversions: number;
    readonly batchProductMultiplications: 0;
  };
  readonly batched: {
    readonly m31Inversions: 1;
    readonly batchProductMultiplications: number;
  };
  readonly commonFoldCore: {
    readonly pairFolds: number;
    readonly independentChallenges: number;
    readonly qm31Multiplications: number;
    readonly qm31ScalarMultiplications: number;
    readonly qm31Additions: number;
    readonly qm31Subtractions: number;
  };
  readonly lowering: {
    readonly m31Inverse: V17FriVmLoweringFootprint;
    readonly m31Multiply: V17FriVmLoweringFootprint;
    readonly qm31Multiply: V17FriVmLoweringFootprint;
    readonly qm31ScalarMultiply: V17FriVmLoweringFootprint;
    readonly qm31Add: V17FriVmLoweringFootprint;
  };
  /** Coverage target; the integration meter supplies measurement evidence. */
  readonly productionRoleTarget: {
    readonly bch2026Roles: number;
    readonly profiles: number;
    readonly queriesPerProfile: number;
    readonly differentialLegacyOracle: true;
  };
};

export const V17_FRI_CURRENT_LAYER_ARITIES = [4, 4, 4, 4, 4, 4, 4, 4, 2] as const;

function compile(assembly: string, label: string): Uint8Array {
  const result = cashAssemblyToBin(assembly);
  if (typeof result === "string") throw new Error(`${label}: ${result}`);
  return result;
}

function footprint(assembly: string, label: string): V17FriVmLoweringFootprint {
  const bytecode = compile(assembly, label);
  const instructions = decodeAuthenticationInstructions(bytecode);
  return {
    bytecodeBytes: bytecode.length,
    instructionCount: instructions.length,
    nativeMultiplyOpcodes: instructions.filter((instruction) =>
      !("data" in instruction) && instruction.opcode === OpcodesBch.OP_MUL).length,
  };
}

function assertCount(count: number): void {
  if (!Number.isSafeInteger(count) || count < 1) {
    throw new Error("v17 inverse emitter requires at least one denominator");
  }
}

/**
 * Stack contract: d0 ... d(n-1) -> inv(d0) ... inv(d(n-1)).
 *
 * Each input is checked before the forward pass. The emitted prefix/suffix
 * program uses one inverse and exactly 3(n-1) M31 multiplications. The caller
 * may provide an OP_INVOKE expression for the inverse, allowing one shared VM
 * definition instead of repeating M31_INV bytecode.
 */
export function v17M31BatchInverseAssembly(
  count: number,
  inverseAssembly = M31_INV,
): string {
  assertCount(count);
  const explicitZeroChecks = Array.from({ length: count }, (_, index) =>
    `<${count - 1 - index}> OP_PICK OP_0 OP_NUMEQUAL OP_NOT OP_VERIFY`).join("\n");
  const prefixes = [
    `<${count - 1}> OP_PICK`,
    ...Array.from({ length: count - 1 }, () => `OP_DUP <${count}> OP_PICK\n${M31_MUL}`),
  ].join("\n");
  const suffixes = Array.from({ length: count - 1 }, (_, reverseIndex) => {
    return `OP_DUP OP_2 OP_PICK ${M31_MUL} OP_TOALTSTACK
OP_DUP <${count + 1}> OP_PICK ${M31_MUL} OP_NIP
OP_SWAP OP_DROP`;
  }).join("\n");
  return `${explicitZeroChecks}
${prefixes}
${inverseAssembly}
${suffixes}
OP_TOALTSTACK
${Array.from({ length: count }, () => "OP_DROP").join("\n")}
${Array.from({ length: count }, () => "OP_FROMALTSTACK").join("\n")}`;
}

/**
 * Stack contract: canonical 4n-byte LE blob -> inverse blob in the same order.
 * The blob contains verifier-derived domain twiddles, not proof-supplied
 * inverses. Decoding, zero rejection, inversion, and re-encoding are all part
 * of this emitted program.
 */
export function v17M31BatchInverseBlobAssembly(
  count: number,
  inverseAssembly = M31_INV,
): string {
  assertCount(count);
  const decode = `${Array.from({ length: count - 1 }, () =>
    "<4> OP_SPLIT OP_SWAP OP_BIN2NUM OP_SWAP").join("\n")}
OP_BIN2NUM`;
  const encode = `<4> OP_NUM2BIN
${Array.from({ length: count - 1 }, () =>
    "OP_SWAP <4> OP_NUM2BIN OP_SWAP OP_CAT").join("\n")}`;
  return `${decode}
${v17M31BatchInverseAssembly(count, inverseAssembly)}
${encode}`;
}

/** Same stack contract, deliberately retaining one inverse per denominator. */
export function v17M31LegacyInverseAssembly(
  count: number,
  inverseAssembly = M31_INV,
): string {
  assertCount(count);
  return `${Array.from({ length: count }, () => `${inverseAssembly}\nOP_TOALTSTACK`).join("\n")}
${Array.from({ length: count }, () => "OP_FROMALTSTACK").join("\n")}`;
}

function define(assembly: string, identifier: number, label: string): string {
  const bytecode = compile(assembly, label);
  return `<0x${binToHex(bytecode)}> <${identifier}> OP_DEFINE`;
}

function pushM31(value: M31El): string {
  if (value <= 0n || value >= M31) throw new Error("v17 inverse meter denominator");
  return `<${value}>`;
}

/**
 * Deterministic arithmetic-only lock used to meter both lowerings under the
 * same BCH VM. Expected inverses are constants in this test lock, never bytes
 * accepted from a proof or unlocking script.
 */
export function compileV17FriInversionMeterLock(
  denominators: readonly M31El[],
  mode: V17FriInversionMode,
): Uint8Array {
  if (denominators.length < V17_FRI_CURRENT_DENOMINATOR_COUNT) {
    throw new Error(`v17 inverse meter requires at least ${V17_FRI_CURRENT_DENOMINATOR_COUNT} denominators`);
  }
  const inverseFunction = 0;
  const body = mode === "batch"
    ? v17M31BatchInverseAssembly(denominators.length, `<${inverseFunction}> OP_INVOKE`)
    : v17M31LegacyInverseAssembly(denominators.length, `<${inverseFunction}> OP_INVOKE`);
  const expected = denominators.map((denominator) => mInv(denominator));
  const checks = [...expected].reverse().map((value, reverseIndex) =>
    `<${value}> ${reverseIndex === expected.length - 1 ? "OP_NUMEQUAL" : "OP_NUMEQUALVERIFY"}`)
    .join("\n");
  return compile(`${define(M31_INV, inverseFunction, "v17 shared M31 inverse")}
${denominators.map(pushM31).join("\n")}
${body}
${checks}`, `v17 ${mode} inversion meter`);
}

/**
 * Exact algebraic certificate for the emitted kernel. It intentionally does
 * keeps primitive counts distinct from the content-dependent role measurements
 * reproduced by v17-fri-gate-integration.test.ts.
 */
export function createV17FriArithmeticVmCertificate(
  layerArities: readonly (2 | 4)[] = V17_FRI_CURRENT_LAYER_ARITIES,
): V17FriArithmeticVmCertificate {
  if (layerArities.length < 1 || layerArities.some((arity) => arity !== 2 && arity !== 4)) {
    throw new Error("v17 FRI layer arities");
  }
  const denominators = layerArities.reduce((total, arity) => total + arity - 1, 0);
  if (denominators < V17_FRI_CURRENT_DENOMINATOR_COUNT) {
    throw new Error(`v17 FRI certificate requires at least ${V17_FRI_CURRENT_DENOMINATOR_COUNT} denominators`);
  }
  const independentChallenges = layerArities.reduce(
    (total, arity) => total + (arity === 4 ? 2 : 1),
    0,
  );
  return {
    layerArities: [...layerArities],
    denominators,
    proofSuppliedInverseBytes: 0,
    legacy: {
      m31Inversions: denominators,
      batchProductMultiplications: 0,
    },
    batched: {
      m31Inversions: 1,
      batchProductMultiplications: 3 * (denominators - 1),
    },
    commonFoldCore: {
      pairFolds: denominators,
      independentChallenges,
      qm31Multiplications: denominators,
      qm31ScalarMultiplications: denominators,
      qm31Additions: 2 * denominators,
      qm31Subtractions: denominators,
    },
    lowering: {
      m31Inverse: footprint(M31_INV, "v17 M31 inverse footprint"),
      m31Multiply: footprint(M31_MUL, "v17 M31 multiply footprint"),
      qm31Multiply: footprint(QM31_MUL_ASM, "v17 QM31 multiply footprint"),
      qm31ScalarMultiply: footprint(QM31_MUL_M31_ASM, "v17 QM31 scalar footprint"),
      qm31Add: footprint(QM31_ADD_ASM, "v17 QM31 add footprint"),
    },
    productionRoleTarget: {
      bch2026Roles: V17_CONSTRUCTION_GRAPH.foundation.queries * V17_PROFILES.length,
      profiles: V17_PROFILES.length,
      queriesPerProfile: V17_CONSTRUCTION_GRAPH.foundation.queries,
      differentialLegacyOracle: true,
    },
  };
}

import { createHash } from "node:crypto";
import { cashAssemblyToBin } from "@bitauth/libauth";
import { LOCAL_WORD_PROOF_MAX_BYTES } from
  "../backends/circle/local-word-sealed-proof.ts";
import {
  V17_AFFINE_READER_PLAN_GEOMETRY,
  buildV17AffineReaderPlan,
  encodeV17AffineReaderPlan,
  type V17AffineReaderPlan,
  type V17AffineReaderPlanGeometry,
  v17AffineReaderPlanDigestHex,
} from "../construction/v17-affine-reader-plan.ts";
import {
  V17_AFFINE_SEQUENCE_BASE,
  V17_AFFINE_SEQUENCE_RADIX,
  V17_AFFINE_VALUE_BASE,
  type V17AffineAllocation,
} from "./v17-affine-allocation.ts";
import {
  LOCAL_WORD_CARRIER_ELASTIC_SCALE,
  LOCAL_WORD_CARRIER_INPUTS,
} from "./local-word-proof-carriers.ts";

/** May-2025+ BCH maximum pushed-element width. */
export const V17_AFFINE_READER_MAXIMUM_READ_BYTES = 10_000 as const;

export type V17AffineReaderVm = {
  readonly planDigestHex: string;
  readonly intervalTableBytes: Uint8Array;
  /** Stack contract: `proofLength proofOffset width -> proofLength bytes`. */
  readonly assembly: string;
  readonly bytecode: Uint8Array;
};

export type V17AffineReaderConstructionEvidence = {
  readonly schema: "ShieldKit/V17AffineReaderConstruction/v1";
  readonly certification: V17AffineReaderPlan["certification"];
  readonly allocationSha256Hex: string;
  readonly planSha256Hex: string;
  readonly readerBytecodeSha256Hex: string;
  readonly canonicalPlanBytes: number;
  readonly readerBytecodeBytes: number;
  readonly lengthCells: number;
  readonly normalizedOffsetCells: number;
  readonly maximumIntervalCarriers: number;
};

export type V17AffineReaderConstruction = {
  readonly allocation: V17AffineAllocation;
  readonly plan: V17AffineReaderPlan;
  readonly vm: V17AffineReaderVm;
  readonly evidence: V17AffineReaderConstructionEvidence;
};

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

/**
 * Validate the structural certificate and materialize only its search table.
 *
 * The allocation digest and resulting bytecode are construction-identity data;
 * this module deliberately does not pretend to re-prove the exhaustive plan.
 */
export function v17AffineReaderIntervalTable(
  plan: V17AffineReaderPlan,
): Uint8Array {
  // The canonical encoder performs the complete structural validation shared
  // by the plan digest and this executable specialization.
  encodeV17AffineReaderPlan(plan);
  if (plan.maximumProofBytes !== LOCAL_WORD_PROOF_MAX_BYTES ||
    plan.elasticScaleUnits !== LOCAL_WORD_CARRIER_ELASTIC_SCALE ||
    plan.elasticScaleUnits >= V17_AFFINE_SEQUENCE_RADIX ||
    plan.carrierCount !== LOCAL_WORD_CARRIER_INPUTS) {
    throw new Error("v17 affine reader VM construction envelope");
  }
  const table = new Uint8Array(plan.intervals.length * 2);
  plan.intervals.forEach((interval, index) => {
    table[index * 2] = interval.lowCarrier;
    table[index * 2 + 1] = interval.highCarrier;
  });
  return table;
}

/** Stack: inputIndex -> the first canonical PUSHDATA2 proof chunk. */
function carrierChunkAssembly(): string {
  return `OP_INPUTBYTECODE
<1> OP_SPLIT OP_SWAP <0x4d> OP_EQUALVERIFY
<2> OP_SPLIT OP_SWAP OP_BIN2NUM
OP_DUP <256> OP_GREATERTHANOREQUAL OP_VERIFY
OP_SPLIT OP_DROP`;
}

/** Stack: proofLength boundaryIndex -> authenticated affine boundary. */
function affineBoundaryAssembly(plan: V17AffineReaderPlan): string {
  return `OP_DUP OP_0 OP_NUMEQUAL
OP_IF
  OP_2DROP OP_0
OP_ELSE
  OP_DUP <${plan.carrierCount}> OP_NUMEQUAL
  OP_IF
    OP_DROP
  OP_ELSE
    OP_INPUTSEQUENCENUMBER
    <${V17_AFFINE_SEQUENCE_BASE}> OP_SUB
    OP_DUP <${V17_AFFINE_SEQUENCE_RADIX}> OP_MOD
    OP_SWAP <${V17_AFFINE_SEQUENCE_RADIX}> OP_DIV
    <2> OP_PICK <1> OP_UTXOVALUE <${V17_AFFINE_VALUE_BASE}> OP_SUB OP_SUB
    OP_ROT OP_MUL <${plan.elasticScaleUnits}> OP_DIV OP_ADD
    OP_NIP
  OP_ENDIF
OP_ENDIF`;
}

/**
 * Compile the certified affine address specialization.
 *
 * The caller supplies the proof length produced by
 * `localWordProofLengthAssembly`; input one authenticates the allocation
 * origin R. Repeating the caller's sequence/range checks in every invocation
 * would create a second proof-length mechanism. The table only narrows the search.
 * Acceptance still depends on the exact transaction-authenticated boundaries
 * surrounding the selected carrier.
 */
export function v17AffineReaderAssembly(plan: V17AffineReaderPlan): string {
  const table = v17AffineReaderIntervalTable(plan);
  const boundary = affineBoundaryAssembly(plan);
  const proofLengthCount = plan.maximumProofBytes - plan.minimumProofBytes + 1;
  return `OP_TXINPUTCOUNT <${plan.carrierCount}> OP_GREATERTHANOREQUAL OP_VERIFY
<1> OP_UTXOVALUE <${V17_AFFINE_VALUE_BASE}> OP_SUB <${plan.minimumProofBytes}> OP_NUMEQUALVERIFY
<1> OP_PICK OP_0 OP_GREATERTHANOREQUAL OP_VERIFY
OP_DUP OP_0 OP_GREATERTHAN OP_VERIFY
OP_DUP <${V17_AFFINE_READER_MAXIMUM_READ_BYTES}> OP_LESSTHANOREQUAL OP_VERIFY
<1> OP_PICK <3> OP_PICK OP_LESSTHAN OP_VERIFY
<1> OP_PICK <1> OP_PICK OP_ADD <3> OP_PICK OP_LESSTHANOREQUAL OP_VERIFY

<2> OP_PICK <${plan.minimumProofBytes}> OP_SUB
<${plan.lengthCells}> OP_MUL <${proofLengthCount}> OP_DIV
OP_DUP <${plan.lengthCells}> OP_LESSTHAN OP_VERIFY
<2> OP_PICK <${plan.normalizedOffsetCells}> OP_MUL
<4> OP_PICK OP_DIV
OP_DUP <${plan.normalizedOffsetCells}> OP_LESSTHAN OP_VERIFY
OP_SWAP <${plan.normalizedOffsetCells}> OP_MUL OP_ADD <2> OP_MUL
<0x${hex(table)}> OP_SWAP OP_SPLIT OP_NIP <2> OP_SPLIT OP_DROP
<1> OP_SPLIT
<0x00> OP_CAT OP_BIN2NUM
OP_SWAP <0x00> OP_CAT OP_BIN2NUM OP_SWAP

<2> OP_ROLL OP_TOALTSTACK
OP_2DUP OP_NUMEQUAL OP_NOT
OP_IF
  OP_BEGIN
    OP_2DUP OP_ADD <2> OP_DIV
    OP_DUP OP_1ADD
    <5> OP_PICK OP_SWAP
    ${boundary}
    <4> OP_PICK OP_SWAP OP_LESSTHAN
    OP_IF
      OP_SWAP OP_DROP
    OP_ELSE
      OP_1ADD OP_ROT OP_DROP OP_SWAP
    OP_ENDIF
    OP_2DUP OP_NUMEQUAL
  OP_UNTIL
OP_ENDIF
OP_DROP

<2> OP_PICK OP_OVER
${boundary}
OP_DUP <3> OP_PICK OP_LESSTHANOREQUAL OP_VERIFY
<3> OP_PICK <2> OP_PICK OP_1ADD
${boundary}
<3> OP_PICK OP_SWAP OP_LESSTHAN OP_VERIFY

OP_OVER ${carrierChunkAssembly()}
<3> OP_PICK <2> OP_PICK OP_SUB OP_SPLIT OP_NIP
OP_TOALTSTACK OP_DROP OP_TOALTSTACK OP_DROP
OP_FROMALTSTACK OP_FROMALTSTACK OP_FROMALTSTACK
OP_OVER OP_SIZE OP_NIP
OP_2DUP OP_LESSTHANOREQUAL
OP_IF
  OP_DROP OP_SPLIT OP_DROP OP_SWAP OP_DROP
OP_ELSE
  OP_SUB
  OP_BEGIN
    <2> OP_PICK OP_1ADD OP_DUP ${carrierChunkAssembly()}
    OP_DUP OP_SIZE OP_NIP
    <3> OP_PICK OP_SWAP OP_LESSTHANOREQUAL
    OP_IF
      <2> OP_PICK OP_SPLIT OP_DROP
      <3> OP_ROLL OP_SWAP OP_CAT
      OP_TOALTSTACK OP_2DROP OP_DROP OP_FROMALTSTACK OP_1
    OP_ELSE
      OP_DUP OP_SIZE OP_NIP
      <3> OP_PICK OP_SWAP OP_SUB OP_TOALTSTACK
      <3> OP_ROLL OP_SWAP OP_CAT
      OP_TOALTSTACK OP_TOALTSTACK OP_2DROP
      OP_FROMALTSTACK OP_FROMALTSTACK OP_FROMALTSTACK OP_0
    OP_ENDIF
  OP_UNTIL
OP_ENDIF`;
}

export function compileV17AffineReaderVm(
  plan: V17AffineReaderPlan,
): V17AffineReaderVm {
  const intervalTableBytes = v17AffineReaderIntervalTable(plan);
  const assembly = v17AffineReaderAssembly(plan);
  const bytecode = cashAssemblyToBin(assembly);
  if (typeof bytecode === "string") {
    throw new Error(`v17 affine reader VM: ${bytecode}`);
  }
  if (bytecode.length > 10_000) {
    throw new Error(`v17 affine reader VM locking limit ${bytecode.length}`);
  }
  return Object.freeze({
    planDigestHex: v17AffineReaderPlanDigestHex(plan),
    intervalTableBytes,
    assembly,
    bytecode,
  });
}

/**
 * Deterministically compile the reader owned by one allocation iteration.
 * This object is construction evidence, never a proof-protocol parameter or a
 * proof-controlled execution hint.
 */
export function compileV17AffineReaderConstruction(
  allocation: V17AffineAllocation,
  geometry: V17AffineReaderPlanGeometry = V17_AFFINE_READER_PLAN_GEOMETRY,
): V17AffineReaderConstruction {
  const plan = buildV17AffineReaderPlan(allocation, geometry);
  const canonicalPlan = encodeV17AffineReaderPlan(plan);
  const vm = compileV17AffineReaderVm(plan);
  const evidence = Object.freeze({
    schema: "ShieldKit/V17AffineReaderConstruction/v1" as const,
    certification: plan.certification,
    allocationSha256Hex: plan.allocationSha256Hex,
    planSha256Hex: vm.planDigestHex,
    readerBytecodeSha256Hex: createHash("sha256").update(vm.bytecode).digest("hex"),
    canonicalPlanBytes: canonicalPlan.length,
    readerBytecodeBytes: vm.bytecode.length,
    lengthCells: plan.lengthCells,
    normalizedOffsetCells: plan.normalizedOffsetCells,
    maximumIntervalCarriers: plan.maximumIntervalCarriers,
  });
  return Object.freeze({ allocation, plan, vm, evidence });
}

/** Fail closed if a retained construction object does not replay byte-for-byte. */
export function validateV17AffineReaderConstruction(
  candidate: V17AffineReaderConstruction,
): V17AffineReaderConstruction {
  const replay = compileV17AffineReaderConstruction(candidate.allocation, {
    lengthCells: candidate.evidence.lengthCells,
    normalizedOffsetCells: candidate.evidence.normalizedOffsetCells,
  });
  const sameBytes = (left: Uint8Array, right: Uint8Array): boolean =>
    left.length === right.length && left.every((byte, index) => byte === right[index]);
  if (JSON.stringify(candidate.evidence) !== JSON.stringify(replay.evidence) ||
    v17AffineReaderPlanDigestHex(candidate.plan) !== replay.evidence.planSha256Hex ||
    candidate.vm.planDigestHex !== replay.evidence.planSha256Hex ||
    !sameBytes(candidate.vm.bytecode, replay.vm.bytecode) ||
    candidate.vm.assembly !== replay.vm.assembly) {
    throw new Error("v17 affine reader construction replay");
  }
  return candidate;
}

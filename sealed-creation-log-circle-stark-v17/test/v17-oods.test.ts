import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  binToHex,
  cashAssemblyToBin,
  createInstructionSetBch2026,
  createVirtualMachine,
} from "@bitauth/libauth";
import { add as mAdd, M31 } from "../src/backends/circle/m31.ts";
import {
  V17_OODS_FAILURE_CERTIFICATE,
  V17_OODS_REJECTION_LIMIT,
  V17_OODS_SHA_SPACE,
  V17_OODS_VALID_T_COUNT,
  V17_QM31_CARDINALITY,
  deriveV17OodsChallenge,
  encodeV17Qm31CirclePoint,
  inspectV17OodsCandidate,
  isM31Subfield,
  isV17CayleyPole,
  liftCirclePoint,
  v17CanonicalTraceStep,
  v17CayleyPoint,
  v17EvaluationQuotient,
  v17EvaluationQuotientIdentity,
  v17InverseCayley,
  v17OodsDigestToQm31,
  v17OodsPredecessor,
  v17PointVanishing,
  v17Qm31CircleAdd,
  v17Qm31CircleNegate,
  v17Qm31CircleOnCurve,
  v17Qm31CirclePointIsBase,
  type V17OodsChallenge,
  type V17Qm31CirclePoint,
} from "../src/backends/circle/v17-oods.ts";
import {
  QM31_ONE,
  QM31_ZERO,
  encodeQm31,
  qm31,
  qmAdd,
  qmEq,
  qmMul,
  type QM31El,
} from "../src/backends/circle/qm31.ts";
import { successorCirclePointAtBitReversed } from
  "../src/backends/circle/successor-domain.ts";
import {
  compileV17OodsKatLock,
  v17OodsCandidateAcceptanceAssembly,
  v17OodsDigestToTAssembly,
  v17OodsSelectDigestAssembly,
} from "../src/chain/v17-oods-vm.ts";
import { bytesToHex, writeU256BE } from "../src/pool/bytes.ts";

const TRANSCRIPT_DIGEST = Uint8Array.from({ length: 32 }, (_, index) => index);
const KAT = {
  attempt: 0,
  digest: "e47e5ba4365c4da2e7a7a3472f9f198b2c1cda29f81e3e5afefda4bb3949a5f0",
  t: [1036777332n, 1457740227n, 2034799267n, 1258383182n] as const,
  x: [1262204531n, 827150057n, 1232883686n, 1627658694n] as const,
  y: [2091978002n, 1647165221n, 682014862n, 91971145n] as const,
  predecessorX: [1361221331n, 410747752n, 112548121n, 1531126006n] as const,
  predecessorY: [77943164n, 1124581332n, 1789467369n, 488479241n] as const,
};

function compileRaw(assembly: string): Uint8Array {
  const bytecode = cashAssemblyToBin(assembly);
  if (typeof bytecode === "string") throw new Error(bytecode);
  return bytecode;
}

function push(bytes: Uint8Array): string {
  return `<0x${binToHex(bytes)}>`;
}

function unboundedVm() {
  const instructionSet = createInstructionSetBch2026(false);
  const every = instructionSet.every!;
  return createVirtualMachine({
    ...instructionSet,
    every: (state) => {
      state.metrics.maximumOperationCost = 1_000_000_000;
      return every(state);
    },
  });
}

function evaluate(lockingBytecode: Uint8Array) {
  const vm = unboundedVm();
  const transaction = {
    version: 2,
    locktime: 0,
    inputs: [{
      outpointTransactionHash: new Uint8Array(32).fill(1),
      outpointIndex: 0,
      sequenceNumber: 0xffff_fffen,
      unlockingBytecode: new Uint8Array(),
    }],
    outputs: [{ lockingBytecode: Uint8Array.of(0x51), valueSatoshis: 1_000n }],
  };
  const state = vm.evaluate({
    inputIndex: 0,
    sourceOutputs: [{ lockingBytecode, valueSatoshis: 1_000n }],
    transaction,
  } as never);
  return { vm, state };
}

function assertVmSuccess(lockingBytecode: Uint8Array): void {
  const result = evaluate(lockingBytecode);
  assert.equal(result.vm.stateSuccess(result.state), true, String(result.state.error));
}

function candidateLock(digest: Uint8Array, accepted: boolean): Uint8Array {
  return compileRaw(`${push(digest)}
${v17OodsCandidateAcceptanceAssembly()}
${accepted ? "" : "OP_NOT"}`);
}

function linearValue(
  point: V17Qm31CirclePoint,
  coefficients: readonly [QM31El, QM31El, QM31El],
): QM31El {
  return qmAdd(coefficients[0], qmAdd(qmMul(coefficients[1], point.x), qmMul(coefficients[2], point.y)));
}

describe("v17 theorem-aligned OODS primitives", () => {
  it("derives the fixed SHA-256/QM31/Cayley known-answer vector", () => {
    const challenge = deriveV17OodsChallenge(TRANSCRIPT_DIGEST);
    assert.equal(challenge.attempt, KAT.attempt);
    assert.equal(bytesToHex(challenge.digest), KAT.digest);
    assert.deepEqual(challenge.t, KAT.t);
    assert.deepEqual(challenge.point.x, KAT.x);
    assert.deepEqual(challenge.point.y, KAT.y);
    assert.equal(v17Qm31CircleOnCurve(challenge.point), true);
    assert.equal(v17Qm31CirclePointIsBase(challenge.point), false);
    assert.equal(isM31Subfield(challenge.t), false);
    assert.equal(isV17CayleyPole(challenge.t), false);
    assert.equal(qmEq(v17InverseCayley(challenge.point), challenge.t), true);
    assert.equal(encodeV17Qm31CirclePoint(challenge.point).length, 32);

    const inspected = inspectV17OodsCandidate(TRANSCRIPT_DIGEST, 0);
    assert.equal(inspected.rejection, undefined);
    assert.deepEqual(inspected.t, challenge.t);
  });

  it("uses exact rejection sampling and names the bounded failure event", () => {
    const certificate = V17_OODS_FAILURE_CERTIFICATE;
    assert.equal(certificate.validTCount, V17_OODS_VALID_T_COUNT);
    assert.equal(certificate.validTCount, V17_QM31_CARDINALITY - M31 - 2n);
    assert.equal(
      certificate.acceptedDigestCountPerValidT * V17_QM31_CARDINALITY + certificate.rangeTailCount,
      V17_OODS_SHA_SPACE,
    );
    assert.equal(
      certificate.rejectedDigestCountPerAttempt,
      certificate.rangeTailCount + certificate.acceptedDigestCountPerValidT * (M31 + 2n),
    );
    // The two-attempt fail-closed event is strictly below 2^-185 in the ROM.
    assert.ok(
      certificate.exhaustionProbabilityNumerator * (1n << 185n) <
      certificate.exhaustionProbabilityDenominator,
    );

    assert.throws(() => v17OodsDigestToQm31(writeU256BE(V17_OODS_REJECTION_LIMIT)), /range rejection/);
    assert.deepEqual(v17OodsDigestToQm31(writeU256BE(M31 ** 3n)), [0n, 0n, 0n, 1n]);
    assertVmSuccess(candidateLock(writeU256BE(0n), false));
    assertVmSuccess(candidateLock(writeU256BE(M31), false)); // +i Cayley pole
    assertVmSuccess(candidateLock(writeU256BE((M31 - 1n) * M31), false)); // -i
    assertVmSuccess(candidateLock(writeU256BE(M31 ** 3n), true));
    assertVmSuccess(candidateLock(writeU256BE(V17_OODS_REJECTION_LIMIT), false));
  });

  it("matches the TypeScript mapping in the BCH VM and fails closed on exhaustion", () => {
    const challenge = deriveV17OodsChallenge(TRANSCRIPT_DIGEST);
    const lock = compileV17OodsKatLock(TRANSCRIPT_DIGEST, challenge);
    const honest = evaluate(lock);
    assert.equal(honest.vm.stateSuccess(honest.state), true, String(honest.state.error));

    const wrong: V17OodsChallenge = {
      ...challenge,
      point: {
        ...challenge.point,
        x: qm31(mAdd(challenge.point.x[0], 1n), ...challenge.point.x.slice(1) as [bigint, bigint, bigint]),
      },
    };
    const rejected = evaluate(compileV17OodsKatLock(TRANSCRIPT_DIGEST, wrong));
    assert.notEqual(rejected.vm.stateSuccess(rejected.state), true);

    const changedTranscript = TRANSCRIPT_DIGEST.slice();
    changedTranscript[11] ^= 1;
    const transcriptRejected = evaluate(compileV17OodsKatLock(changedTranscript, challenge));
    assert.notEqual(transcriptRejected.vm.stateSuccess(transcriptRejected.state), true);

    const acceptedDigest = writeU256BE(M31 ** 3n + 7n);
    const expectedT = v17OodsDigestToQm31(acceptedDigest);
    const checks = [...expectedT].reverse().map((limb, index) =>
      `<${limb}> ${index === 3 ? "OP_NUMEQUAL" : "OP_NUMEQUALVERIFY"}`).join("\n");
    assertVmSuccess(compileRaw(`${push(acceptedDigest)}
${v17OodsDigestToTAssembly()}
${checks}`));

    const rejectFunction = compileRaw("OP_DROP OP_0");
    const exhausted = compileRaw(`<0x${binToHex(rejectFunction)}> <0> OP_DEFINE
${push(TRANSCRIPT_DIGEST)}
${v17OodsSelectDigestAssembly(0)}
OP_1`);
    const exhaustedResult = evaluate(exhausted);
    assert.notEqual(exhaustedResult.vm.stateSuccess(exhaustedResult.state), true);
  });

  it("shifts the OODS point by the exact canonical predecessor step", () => {
    const challenge = deriveV17OodsChallenge(TRANSCRIPT_DIGEST);
    const predecessor = v17OodsPredecessor(challenge.point, 18);
    assert.deepEqual(predecessor.x, KAT.predecessorX);
    assert.deepEqual(predecessor.y, KAT.predecessorY);
    assert.equal(v17Qm31CircleOnCurve(predecessor), true);

    const step = liftCirclePoint(v17CanonicalTraceStep(18));
    assert.deepEqual(v17Qm31CircleAdd(predecessor, step), challenge.point);
    assert.deepEqual(
      v17Qm31CircleAdd(challenge.point, v17Qm31CircleNegate(step)),
      predecessor,
    );
  });

  it("satisfies the Protocol-4 point-vanishing and degree-corrected quotient identities", () => {
    const challenge = deriveV17OodsChallenge(TRANSCRIPT_DIGEST);
    assert.equal(qmEq(v17PointVanishing(challenge.point, challenge.point), QM31_ZERO), true);

    const basePoint = liftCirclePoint(successorCirclePointAtBitReversed(24, 0x51f15));
    const vanishing = v17PointVanishing(challenge.point, basePoint);
    assert.equal(qmEq(vanishing, QM31_ZERO), false);
    const coefficients = [
      qm31(3n, 5n, 7n, 11n),
      qm31(13n, 17n, 19n, 23n),
      qm31(29n, 31n, 37n, 41n),
    ] as const;
    const atQ = linearValue(challenge.point, coefficients);
    const atBase = linearValue(basePoint, coefficients);
    const quotient = v17EvaluationQuotient(atBase, atQ, challenge.point, basePoint);
    assert.equal(v17EvaluationQuotientIdentity({
      pointValue: atBase,
      claimedValueAtQ: atQ,
      quotientValue: quotient,
      vanishPoint: challenge.point,
      point: basePoint,
    }), true);
    assert.equal(v17EvaluationQuotientIdentity({
      pointValue: atBase,
      claimedValueAtQ: atQ,
      quotientValue: qmAdd(quotient, QM31_ONE),
      vanishPoint: challenge.point,
      point: basePoint,
    }), false);
    assert.throws(
      () => v17EvaluationQuotient(atQ, atQ, challenge.point, challenge.point),
      /denominator is zero/,
    );
  });
});

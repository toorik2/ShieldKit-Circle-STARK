import {
  OpcodesBch,
  createInstructionSetBch2026,
} from "@bitauth/libauth";

export const V17_LIBAUTH_OP_DEFINE_DIAGNOSTIC_ENGINE =
  "libauth-3.1.0-next.8-plus-bchn-v29-op-define-delta-diagnostic" as const;

/**
 * Diagnostic-only repair for one confirmed libauth 3.1.0-next.8 divergence.
 *
 * BCHN v29.0.0 charges `TallyPushOp(functionBody.size())` after a successful
 * OP_DEFINE (`src/script/interpreter.cpp`); libauth next.8 registers the body
 * without adding those stack-pushed bytes. The source-backed one-byte VMB KAT
 * `67am0u` is therefore 802 in libauth and 803 in BCHN.
 *
 * This wrapper mirrors only that known delta. It is useful for conservative
 * local sizing, but it is not independent BCHN evidence and cannot qualify a
 * v17 verifier bank.
 */
export function createV17LibauthBchnOpDefineDiagnosticInstructionSet(
  standard = false,
) {
  const instructionSet = createInstructionSetBch2026(standard);
  const libauthOpDefine = instructionSet.operations[OpcodesBch.OP_DEFINE];
  if (libauthOpDefine === undefined) {
    throw new Error("v17 diagnostic missing libauth OP_DEFINE");
  }

  const bchnDeltaOpDefine: typeof libauthOpDefine = (state) => {
    const functionCountBefore = state.functionCount;
    const functionBodyBytes = state.stack.at(-2)?.length;
    const nextState = libauthOpDefine(state);
    const definedFunctions = nextState.functionCount - functionCountBefore;

    // Skipped branches and rejected definitions receive no BCHN body charge.
    if (definedFunctions === 0) return nextState;
    if (definedFunctions !== 1 || functionBodyBytes === undefined) {
      throw new Error("v17 diagnostic OP_DEFINE transition");
    }

    // BCHN's TallyPushOp(body.size()) increments the pushed-byte component;
    // libauth's ordinary `every` hook then recomputes the composite opcost.
    nextState.metrics.stackPushedBytes += functionBodyBytes;
    return nextState;
  };

  return {
    ...instructionSet,
    operations: {
      ...instructionSet.operations,
      [OpcodesBch.OP_DEFINE]: bchnDeltaOpDefine,
    },
  };
}

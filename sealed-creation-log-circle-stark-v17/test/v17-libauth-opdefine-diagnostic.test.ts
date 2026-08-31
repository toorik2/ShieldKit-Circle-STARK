import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  cashAssemblyToBin,
  createVirtualMachine,
  createVirtualMachineBch2026,
} from "@bitauth/libauth";
import {
  createV17LibauthBchnOpDefineDiagnosticInstructionSet,
} from "../src/assurance/v17-libauth-opdefine-diagnostic.ts";

function compile(assembly: string): Uint8Array {
  const bytecode = cashAssemblyToBin(assembly);
  if (typeof bytecode === "string") throw new Error(bytecode);
  return bytecode;
}

function program(lockingBytecode: Uint8Array) {
  return {
    inputIndex: 0,
    sourceOutputs: [{ lockingBytecode, valueSatoshis: 1_000n }],
    transaction: {
      version: 2,
      locktime: 0,
      inputs: [{
        outpointTransactionHash: new Uint8Array(32).fill(1),
        outpointIndex: 0,
        sequenceNumber: 0xffff_fffe,
        unlockingBytecode: new Uint8Array(),
      }],
      outputs: [{ lockingBytecode: Uint8Array.of(0x51), valueSatoshis: 1_000n }],
    },
  };
}

describe("v17 libauth OP_DEFINE opcost diagnostic", () => {
  it("reproduces the source-backed one-byte 802 -> 803 BCHN delta", () => {
    const kat = program(compile(
      "<OP_0> <0> OP_DEFINE <0> OP_INVOKE <0> OP_EQUAL",
    ));
    const libauthVm = createVirtualMachineBch2026(false);
    const diagnosticVm = createVirtualMachine(
      createV17LibauthBchnOpDefineDiagnosticInstructionSet(false),
    );
    const libauth = libauthVm.evaluate(kat);
    const diagnostic = diagnosticVm.evaluate(kat);

    assert.equal(libauthVm.stateSuccess(libauth), true, String(libauth.error));
    assert.equal(diagnosticVm.stateSuccess(diagnostic), true, String(diagnostic.error));
    assert.equal(libauth.metrics.operationCost, 802);
    assert.equal(diagnostic.metrics.operationCost, 803);
    assert.equal(
      diagnostic.metrics.stackPushedBytes - libauth.metrics.stackPushedBytes,
      1,
    );
  });

  it("does not charge an OP_DEFINE skipped by control flow", () => {
    const skipped = program(compile(
      "<0> OP_IF <OP_0 OP_1> <0> OP_DEFINE OP_ENDIF OP_1",
    ));
    const libauthVm = createVirtualMachineBch2026(false);
    const diagnosticVm = createVirtualMachine(
      createV17LibauthBchnOpDefineDiagnosticInstructionSet(false),
    );
    const libauth = libauthVm.evaluate(skipped);
    const diagnostic = diagnosticVm.evaluate(skipped);

    assert.equal(libauthVm.stateSuccess(libauth), true, String(libauth.error));
    assert.equal(diagnosticVm.stateSuccess(diagnostic), true, String(diagnostic.error));
    assert.equal(diagnostic.metrics.operationCost, libauth.metrics.operationCost);
    assert.equal(
      diagnostic.metrics.stackPushedBytes,
      libauth.metrics.stackPushedBytes,
    );
  });
});

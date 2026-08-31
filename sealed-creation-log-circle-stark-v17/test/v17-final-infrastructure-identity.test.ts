import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  assertV17FinalInfrastructureIdentity,
  replayV17FinalInfrastructureIdentity,
} from "../src/assurance/v17-final-infrastructure-identity.ts";
import type { V17FinalInfrastructureSet } from
  "../src/construction/v17-product-link.ts";
import { fakeV17FinalInfrastructureSet } from
  "./helpers/v17-final-infrastructure-fixture.ts";

describe("v17 final infrastructure identity replay", () => {
  it("binds every profile inventory while remaining explicitly non-qualifying", () => {
    const fixture = fakeV17FinalInfrastructureSet();
    const identity = replayV17FinalInfrastructureIdentity(fixture);
    assert.equal(identity.status, "identity-replayed-not-qualified");
    assert.deepEqual(identity.profiles.map(({ infrastructureInputs }) =>
      infrastructureInputs), fixture.profiles.map(({ infrastructure }) => infrastructure.length));
    assert.doesNotThrow(() => assertV17FinalInfrastructureIdentity(identity));
  });

  it("rejects worker, bank, certificate, and construction drift", () => {
    const worker = structuredClone(fakeV17FinalInfrastructureSet()) as
      V17FinalInfrastructureSet;
    worker.profiles[1]!.infrastructure[4]!.lockingBytecode[0] ^= 1;
    assert.throws(() => replayV17FinalInfrastructureIdentity(worker),
      /infrastructure role|bank digest/);

    const certificate = structuredClone(fakeV17FinalInfrastructureSet()) as
      V17FinalInfrastructureSet;
    (certificate.construction.certificate as { certificateIdHex: string })
      .certificateIdHex = "ff".repeat(32);
    assert.throws(() => replayV17FinalInfrastructureIdentity(certificate),
      /certificate digest/);

    const bank = structuredClone(fakeV17FinalInfrastructureSet()) as
      V17FinalInfrastructureSet;
    bank.authorizedBankDigests[2]![0] ^= 1;
    assert.throws(() => replayV17FinalInfrastructureIdentity(bank),
      /role 0:settlement|bank digest|construction digest/);
  });
});

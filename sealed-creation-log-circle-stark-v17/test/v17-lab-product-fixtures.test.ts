import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { V17_PROOF_PROTOCOL_ID } from
  "../src/backends/circle/v17-proof-layout.ts";
import { V17_PROFILES, v17ProtocolIdHex } from
  "../src/construction/v17-graph.ts";
import {
  V17_LAB_MINER_FEE_SATOSHIS,
  buildV17LabProductFixture,
} from "../src/construction/v17-lab-product-fixtures.ts";

describe("v17 deterministic offline product fixtures", () => {
  it("covers deposit, full withdrawal, and change without private transaction inputs", () => {
    const fixtures = V17_PROFILES.map(buildV17LabProductFixture);
    assert.deepEqual(fixtures.map(({ profile }) => profile), V17_PROFILES);
    assert.ok(fixtures.every(({ publicWords }) => publicWords.length === 8));
    assert.ok(fixtures.every(({ settlementFixture }) =>
      settlementFixture.minerFeeSatoshis === V17_LAB_MINER_FEE_SATOSHIS));
    assert.equal(Buffer.from(V17_PROOF_PROTOCOL_ID).toString("hex"), v17ProtocolIdHex());
    assert.equal("funding" in fixtures[0]!.settlementFixture, true);
    assert.equal("funding" in fixtures[1]!.settlementFixture, false);
    assert.equal("edgeDataLockingBytecode" in fixtures[2]!.settlementFixture, true);
  });

  it("is byte-deterministic for every prover and settlement input", () => {
    for (const profile of V17_PROFILES) {
      const left = buildV17LabProductFixture(profile);
      const right = buildV17LabProductFixture(profile);
      assert.deepEqual(left.bundle, right.bundle);
      assert.deepEqual(left.constructionDescriptor, right.constructionDescriptor);
      assert.deepEqual(left.transcriptInitial, right.transcriptInitial);
      assert.deepEqual(left.settlementFixture, right.settlementFixture);
    }
  });
});

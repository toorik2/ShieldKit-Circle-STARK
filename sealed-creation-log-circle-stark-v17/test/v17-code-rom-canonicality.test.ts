import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { binToHex } from "@bitauth/libauth";
import {
  createV17RomPage,
  type V17RomEntryInput,
} from "../src/chain/v17-code-rom.ts";
import {
  assertV17VerifierPlanConformsToSchema,
  buildV17VerifierPlanSchema,
} from "../src/construction/v17-artifacts.ts";
import { buildV17VerifierPlan } from "../src/construction/v17-graph.ts";

function page(entries: readonly V17RomEntryInput[]) {
  return createV17RomPage({
    pageIndex: 0,
    inputIndex: 2,
    outputIndex: 2,
    entries,
  });
}

describe("v17 canonical ROM function identifiers", () => {
  it("orders minimal positive unsigned-BE identifiers across the one-byte boundary", () => {
    const entries = [
      { functionId: Uint8Array.of(1, 0), body: Uint8Array.of(0x53) },
      { functionId: Uint8Array.of(0xff), body: Uint8Array.of(0x52) },
      { functionId: Uint8Array.of(1), body: Uint8Array.of(0x51) },
    ];
    const forward = page(entries);
    const reverse = page([...entries].reverse());

    assert.deepEqual(forward.entries.map(({ functionIdHex }) => functionIdHex),
      ["01", "ff", "0100"]);
    assert.deepEqual(forward.entries.map(({ body }) => binToHex(body)),
      ["51", "52", "53"], "body identity remains attached to its canonical identifier");
    assert.deepEqual(reverse.entries, forward.entries);
    assert.deepEqual(reverse.payload, forward.payload,
      "caller order cannot perturb the canonical directory or payload");
  });

  it("rejects zero, leading-zero, and numeric-alias identifiers", () => {
    assert.throws(() => page([
      { functionId: Uint8Array.of(0), body: Uint8Array.of(0x51) },
    ]), /minimal positive unsigned big-endian/);
    assert.throws(() => page([
      { functionId: Uint8Array.of(0, 1), body: Uint8Array.of(0x51) },
    ]), /minimal positive unsigned big-endian/);
    assert.throws(() => page([
      { functionId: Uint8Array.of(1), body: Uint8Array.of(0x51) },
      { functionId: Uint8Array.of(0, 1), body: Uint8Array.of(0x52) },
    ]), /minimal positive unsigned big-endian/,
    "01 and 0001 may not represent two directory identities for the same unsigned ordinal");
  });

  it("publishes the same minimal-positive invariant in the verifier-plan schema", () => {
    const schema = buildV17VerifierPlanSchema() as {
      properties: {
        rom: {
          properties: {
            pages: {
              items: {
                properties: {
                  functionIds: { uniqueItems: boolean; items: { pattern: string } };
                };
              };
            };
          };
        };
      };
    };
    const pattern = new RegExp(
      schema.properties.rom.properties.pages.items.properties.functionIds.items.pattern,
    );
    assert.equal(
      schema.properties.rom.properties.pages.items.properties.functionIds.uniqueItems,
      true,
    );
    for (const accepted of ["01", "ff", "0100"]) assert.match(accepted, pattern);
    for (const rejected of ["00", "0001"]) assert.doesNotMatch(rejected, pattern);
  });

  it("rejects duplicate and non-numerically-ordered function IDs at the artifact gate", () => {
    const schema = buildV17VerifierPlanSchema();
    const descriptor = (index: number, functionIds: readonly string[]) => ({
      index,
      inputIndex: 210 + index,
      outputIndex: 210 + index,
      sha256Hex: (index + 1).toString(16).padStart(2, "0").repeat(32),
      bytes: 9,
      functionIds,
    });
    const planWithPages = (pages: readonly ReturnType<typeof descriptor>[]) => {
      const plan = structuredClone(buildV17VerifierPlan());
      return { ...plan, rom: { ...plan.rom, pages } };
    };

    assert.throws(() => assertV17VerifierPlanConformsToSchema({
      plan: planWithPages([descriptor(0, ["01", "01"])]),
      schema,
    }), /duplicate items/);
    assert.throws(() => assertV17VerifierPlanConformsToSchema({
      plan: planWithPages([descriptor(0, ["02", "01"])]),
      schema,
    }), /noncanonical ROM function id order/);
    assert.throws(() => assertV17VerifierPlanConformsToSchema({
      plan: planWithPages([descriptor(0, ["01"]), descriptor(1, ["01"])]),
      schema,
    }), /duplicate ROM function id 01/);
  });
});

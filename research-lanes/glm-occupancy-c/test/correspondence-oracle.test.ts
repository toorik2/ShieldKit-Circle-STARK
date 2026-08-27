import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";
import { FRI_QUERIES, FRI_VERSION, VK_ID } from "../src/backends/circle/params.ts";
import { runCorrespondenceOracle } from "../scripts/correspondence-oracle.ts";
import { compactLayerKernelAsm } from "../src/chain/fri-kernel.ts";

describe("correspondence oracle + argument freeze", () => {
  it("ARGUMENT.md freezes this vk and names the query conjecture", () => {
    const spec = readFileSync(new URL("../ARGUMENT.md", import.meta.url), "utf8");
    assert.ok(spec.includes(VK_ID), "spec names vk");
    assert.ok(spec.includes("ePrint 2021/582"), "spec names ethSTARK conjecture");
    assert.ok(spec.includes("JS-only"), "spec lists JS-only holes");
    assert.ok(spec.includes("checkBatchSpends"), "H1 batch-exit extra notes");
    assert.equal(FRI_VERSION, 9);
    assert.equal(FRI_QUERIES, 36);
  });

  it("Merkle PICK is bounded (k ≥ 0 and k < DEPTH) before OP_PICK", () => {
    const asm = compactLayerKernelAsm(0);
    assert.ok(asm.includes("OP_GREATERTHANOREQUAL"), "k ≥ 0");
    assert.ok(asm.includes("OP_LESSTHAN"), "k < DEPTH");
    const pickAt = asm.lastIndexOf("OP_PICK");
    const geAt = asm.lastIndexOf("OP_GREATERTHANOREQUAL");
    const ltAt = asm.lastIndexOf("OP_LESSTHAN");
    assert.ok(geAt < pickAt && ltAt < pickAt, "bounds sit before PICK");
  });

  it("honest JS and VM agree; mutated proof cannot be JS-fail VM-accept", () => {
    const out = runCorrespondenceOracle();
    assert.equal(out.vk, VK_ID);
    assert.equal(out.p0.length, 0, JSON.stringify(out.p0));
    const [honest, mutated, omit] = out.rows;
    assert.equal(honest!.js, true, "verifyFri honest");
    assert.equal(honest!.vm, true, honest!.error ?? "VM honest");
    assert.equal(mutated!.js, false, "verifyFri mutated");
    assert.equal(mutated!.vm, false, "VM mutated");
    assert.equal(omit!.js, true, "omit openings does not change the proof");
    assert.equal(omit!.vm, false, "chain rejects skip-N");
  });
});

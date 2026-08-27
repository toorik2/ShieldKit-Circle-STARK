import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { compilePoolCovenant, poolLockP2s, poolLockP2sh32 } from "../src/chain/covenant-p2s.ts";
import { addCommits, commitAmount, conserves } from "../src/amounts/pedersen.ts";
import { describePlugins } from "../src/plugins/registry.ts";

describe("covenant locks", () => {
  it("compiles P2S program and a P2SH32 wrapper", () => {
    const p2s = poolLockP2s();
    const p2sh = poolLockP2sh32();
    assert.ok(compilePoolCovenant().length > 20);
    assert.ok(p2s.length > 20);
    assert.equal(p2sh[0], 0xaa);
    assert.notDeepEqual(p2s, p2sh);
    assert.ok(compilePoolCovenant().includes(0x75), "OP_DROP after OP_SIZE");
  });
});

describe("Pedersen amount conservation (BCR 1570 profile)", () => {
  it("adds homomorphically", () => {
    const a = { v: 10n, r: 3n };
    const b = { v: 7n, r: 9n };
    assert.equal(addCommits(commitAmount(a.v, a.r), commitAmount(b.v, b.r)), commitAmount(17n, 12n));
    assert.ok(conserves([a, b], [{ v: 17n, r: 12n }]));
    assert.equal(conserves([a], [b]), false);
  });
});

describe("plugin split", () => {
  it("keeps Quantumroot and ML-KEM off the covenant hook", () => {
    const d = describePlugins() as {
      covenant: string;
      side: Array<{ family: string }>;
      zkp: Array<{ family: string }>;
    };
    assert.match(d.covenant, /P2S/);
    const families = d.side.map((s) => s.family);
    assert.ok(families.includes("quantumroot-lmots"));
    assert.ok(families.includes("ml-kem-768"));
    assert.ok(families.includes("sha256-tagged-amount"));
    assert.ok(families.includes("pedersen-secp-profile"));
    assert.ok(!d.zkp.some((z) => z.family === "ml-kem-768"));
    assert.ok(!d.zkp.some((z) => z.family === "quantumroot-lmots"));
    const zkp = d.zkp.map((z) => z.family);
    assert.ok(zkp.includes("circle-fri-m31"));
    assert.ok(zkp.includes("hash-lab-v0"));
    assert.ok(zkp.length >= 2);
    assert.ok(!zkp.some((f) => /groth16|pairing|bn254/i.test(f)));
    const reserved = (d as { zkpReserved?: Array<{ family: string; role?: string; pcs?: string }> }).zkpReserved ?? [];
    assert.ok(reserved.some((z) => z.family === "groth16"));
    assert.ok(reserved.some((z) => z.family === "whir" && z.role === "pcs"));
    assert.ok(reserved.some((z) => z.family === "air-whir" && z.pcs === "whir"));
    assert.ok(reserved.some((z) => z.family === "spartan-whir" && z.pcs === "whir"));
  });
});

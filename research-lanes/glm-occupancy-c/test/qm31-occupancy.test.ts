import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import {
  BLOWUP,
  FRI_N,
  FRI_QUERIES,
  FRI_VERSION,
  GRIND_BITS,
  RULES_SHA256,
  TRACE_LEN,
  VK_ID,
} from "../src/backends/circle/params.ts";
import { soundnessWorksheet } from "../src/backends/circle/soundness.ts";
import {
  encodeFriProof,
  isQm31,
  proveFri,
  verifyFri,
  wDeposit,
} from "../src/backends/circle/fri.ts";
import { encodeLe } from "../src/backends/circle/m31.ts";
import { encodeQm31 } from "../src/backends/circle/qm31.ts";
import { applyDeposit } from "../src/pool/transition.ts";
import { IncrementalMerkle, NullifierSet, type Note } from "../src/pool/notes.ts";
import { emptyState } from "../src/pool/state.ts";
import { encodeAirPacked, AIR_OFF_QTABLE } from "../src/chain/air-cqz.ts";
import { evaluateFoldKernelOnly } from "../src/chain/vm-verifier.ts";

const rnd32 = () => crypto.getRandomValues(new Uint8Array(32));

function depositProof() {
  const note: Note = { amountSats: 12_345n, rho: rnd32(), ownerSecret: rnd32() };
  const d = applyDeposit(
    { state: emptyState(rnd32()), notes: new IncrementalMerkle(), nullifiers: new NullifierSet() },
    note,
  );
  const proof = proveFri(d.statement, wDeposit(note, d.index, d.path));
  return { ...d, note, proof };
}

describe("QM31 occupancy + vk", () => {
  it("vk contains qm31 and current RULES.md sha256; n=32/q=8 refused", () => {
    const here = dirname(fileURLToPath(import.meta.url));
    const rules = readFileSync(join(here, "../RULES.md"));
    const sha = createHash("sha256").update(rules).digest("hex");
    assert.equal(sha, RULES_SHA256);
    assert.equal(VK_ID.includes("qm31"), true);
    assert.equal(VK_ID.includes(RULES_SHA256), true);
    assert.notEqual(FRI_N, 32);
    assert.notEqual(FRI_QUERIES, 8);
    assert.equal(FRI_QUERIES, 36);
    assert.equal(GRIND_BITS, 20);
    assert.equal(TRACE_LEN, 64);
    assert.equal(BLOWUP, 16);
    assert.equal(FRI_VERSION, 10);
    const w = soundnessWorksheet();
    assert.equal(w.field, "QM31");
    assert.equal(w.fieldBits, 124);
    assert.equal(w.queryConjectureBits, 128);
    assert.equal(w.minBits >= 100, true);
    assert.equal(w.note.includes("speculative") || w.note.includes("not Stwo-128"), true);
    assert.equal(w.vkId, VK_ID);
  });

  it("qTable and layer-0 are 4-byte M31; λ-folded layers and final are QM31", () => {
    const { statement, proof } = depositProof();
    const fri = verifyFri(statement, proof);
    assert.equal(fri.ok, true, fri.reason ?? "verifyFri");
    const q0 = proof.queries[0]!;
    assert.equal(typeof q0.layers[0]!.value, "bigint");
    assert.equal(encodeLe(q0.layers[0]!.value as bigint).length, 4);
    assert.equal(isQm31(q0.layers[1]!.value), true);
    assert.equal(encodeQm31(q0.layers[1]!.value as [bigint, bigint, bigint, bigint]).length, 16);
    assert.equal(isQm31(proof.final[0]!), true);
    assert.equal(encodeQm31(proof.final[0]!).length, 16);
    const packed = encodeAirPacked(statement, proof);
    const qFelt = packed.subarray(AIR_OFF_QTABLE, AIR_OFF_QTABLE + 4);
    assert.equal(qFelt.length, 4);
  });

  it("mutated post-fold pair is JS-reject and VM-reject", () => {
    const { statement, proof } = depositProof();
    const q = proof.queries[0]!;
    const v = q.layers[1]!.value as [bigint, bigint, bigint, bigint];
    q.layers[1] = { ...q.layers[1]!, value: [v[0] ^ 1n, v[1], v[2], v[3]] };
    const fri = verifyFri(statement, proof);
    assert.equal(fri.ok, false);
    const vm = evaluateFoldKernelOnly({
      statement,
      proof: encodeFriProof(proof),
      nFold: 1,
    });
    assert.equal(vm.accepted, false, vm.error ?? "mutated pair VM");
  });

  it("mutated layer-1 root (λ transcript) is JS-reject and VM-reject", () => {
    const { statement, proof } = depositProof();
    const root = new Uint8Array(proof.layerRoots[1]!);
    root[0] ^= 1;
    proof.layerRoots[1] = root;
    const fri = verifyFri(statement, proof);
    assert.equal(fri.ok, false);
    const vm = evaluateFoldKernelOnly({
      statement,
      proof: encodeFriProof(proof),
      nFold: 1,
    });
    assert.equal(vm.accepted, false, vm.error ?? "mutated λ VM");
  });
});

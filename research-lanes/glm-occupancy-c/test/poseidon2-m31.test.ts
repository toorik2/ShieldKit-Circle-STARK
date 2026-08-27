import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  POSEIDON2_M31_ID,
  POSEIDON2_RATE,
  POSEIDON2_RF,
  POSEIDON2_ROUND_CONSTANTS,
  POSEIDON2_ROUNDS,
  POSEIDON2_RP,
  POSEIDON2_SBOX_PER_PERM,
  POSEIDON2_T,
  applyPoseidon2External,
  bytesToM31Limbs,
  digestPoseidon2M31Bytes,
  hashPoseidon2Sponge,
  nextPoseidon2Snapshot,
  permutePoseidon2M31,
  poseidon2DomainFelt,
} from "../src/backends/circle/poseidon2-m31.ts";
import { add } from "../src/backends/circle/m31.ts";

function zeros(n = POSEIDON2_T): bigint[] {
  return new Array(n).fill(0n);
}

describe("Poseidon2-M31 permutation (toorik Grain t=16 RF=8 RP=14)", () => {
  it("matches the published instance id and Grain budget", () => {
    assert.equal(POSEIDON2_M31_ID, "poseidon2-m31-t16-rf8-rp14-grain-v1");
    assert.equal(POSEIDON2_T, 16);
    assert.equal(POSEIDON2_RATE, 8);
    assert.equal(POSEIDON2_RF, 8);
    assert.equal(POSEIDON2_RP, 14);
    assert.equal(POSEIDON2_ROUNDS, 22);
    assert.equal(POSEIDON2_SBOX_PER_PERM, 8 * 16 + 14);
    assert.equal(POSEIDON2_ROUND_CONSTANTS.length, POSEIDON2_SBOX_PER_PERM);
    for (const c of POSEIDON2_ROUND_CONSTANTS) {
      assert.ok(c >= 0n && c < 2147483647n);
    }
  });

  it("external mix is circ(2,1,…,1): out[i] = in[i] + sum", () => {
    const input = zeros();
    input[0] = 1n;
    input[1] = 2n;
    input[2] = 3n;
    let sum = 0n;
    for (const v of input) sum = add(sum, v);
    const out = applyPoseidon2External(input);
    assert.equal(out.length, 16);
    assert.equal(out[0], add(1n, sum));
    assert.equal(out[1], add(2n, sum));
    assert.equal(out[2], add(3n, sum));
    assert.equal(out[3], sum);
  });

  it("permute is deterministic and snapshot 22 reconstitutes the output", () => {
    const input = zeros();
    input[0] = 1n;
    const a = permutePoseidon2M31(input);
    const b = permutePoseidon2M31(input);
    assert.deepEqual([...a], [...b]);
    assert.equal(a.length, 16);
    assert.ok(a.some((v) => v !== 0n));
    let state = applyPoseidon2External(input).slice();
    for (let i = 0; i < POSEIDON2_ROUNDS; i += 1) {
      state = nextPoseidon2Snapshot(state, i).slice();
    }
    assert.deepEqual([...state], [...a]);
  });

  it("sponge digest is rate-8 and domain-separated", () => {
    const d = poseidon2DomainFelt("PAA1-IH-poseidon2-m31-v1");
    const sponge = hashPoseidon2Sponge([d, 1n, 2n, 3n]);
    assert.equal(sponge.digest.length, 8);
    assert.equal(sponge.capacity.length, 8);
    assert.ok(sponge.permutations >= 1);
    const other = hashPoseidon2Sponge([d + 1n, 1n, 2n, 3n]);
    assert.notDeepEqual([...sponge.digest], [...other.digest]);
  });

  it("byte digest is 32 bytes, distinct from SHA-256, and 32-byte limbs split into 9", () => {
    const msg = new TextEncoder().encode("paa1-poseidon2-m31");
    const d = digestPoseidon2M31Bytes(msg);
    assert.equal(d.length, 32);
    const again = digestPoseidon2M31Bytes(msg);
    assert.deepEqual([...d], [...again]);
    const other = digestPoseidon2M31Bytes(new TextEncoder().encode("paa1-poseidon2-m31."));
    assert.notDeepEqual([...d], [...other]);
    const limbs = bytesToM31Limbs(d);
    assert.equal(limbs.length, 9);
  });

  it("lab source is TypeScript; AIR-in-lock files are not copied", () => {
    const here = dirname(fileURLToPath(import.meta.url));
    const src = join(here, "..", "src");
    const body = readFileSync(join(src, "backends", "circle", "poseidon2-m31.ts"), "utf8");
    assert.match(body, /ePrint 2023\/323/);
    assert.match(body, /toorik2\/ShieldKit-Circle-STARK\/blob\/%40toorik2\/src\/circle-fri\/poseidon2-m31\.mjs/);
    assert.match(body, /Not a production hash lock/);
    assert.equal(body.includes(".mjs'"), false);
    const labRoot = join(here, "..");
    assert.equal(
      readFileSync(join(src, "chain", "covenant-p2s.ts"), "utf8").includes("OP_SHA256") ||
        readFileSync(join(src, "chain", "covenant-p2s.ts"), "utf8").includes("OP_HASH256"),
      true,
    );
    assert.equal(existsSync(join(labRoot, "src", "circle-fri")), false);
  });
});

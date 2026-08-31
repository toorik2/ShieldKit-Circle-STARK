import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { bytesToHex, writeU32LE } from "../src/pool/bytes.ts";
import { SuccessorTranscript } from "../src/backends/circle/successor-transcript.ts";
import {
  localWordQuerySamples,
  validateLocalWordQuerySamplerGeometry,
} from "../src/backends/circle/local-word-transcript.ts";
import { LOCAL_WORD_PRODUCTION_PARAMETERS } from
  "../src/backends/circle/local-word-successor-params.ts";

describe("successor SHA-256 transcript", () => {
  it("has one fixed-cost challenge, PoW-only grind, and query schedule", () => {
    const transcript = new SuccessorTranscript(new TextEncoder().encode("transcript-kat"));
    transcript.absorb("statement", Uint8Array.of(1, 2, 3, 4));
    const alpha0 = transcript.challengeQm31("fri-alpha:0");
    transcript.absorb("fri-root:1", new Uint8Array(32).fill(0xa5));
    const alpha1 = transcript.challengeQm31("fri-alpha:1");
    const nonce = transcript.grind(8);
    const queries = transcript.queryIndices(512, 12);

    assert.deepEqual(alpha0, [641955534n, 1156760623n, 378207287n, 2059957541n]);
    assert.deepEqual(alpha1, [286744312n, 1230511567n, 1287274865n, 1635578672n]);
    assert.equal(nonce, 18);
    assert.deepEqual(queries, [86, 267, 415, 124, 170, 180, 10, 65, 100, 311, 491, 404]);
    assert.equal(bytesToHex(transcript.digest), "f47eae2692e04be72e91eb15d33f966dd849323106cd03ff083b2e5c732d3f34");
    assert.equal(new Set(queries.map((index) => index >> 1)).size, queries.length);
  });

  it("fails closed on a changed PoW nonce", () => {
    const transcript = new SuccessorTranscript(Uint8Array.of(9));
    const honest = transcript.grind(4);
    const verifier = new SuccessorTranscript(Uint8Array.of(9));
    assert.equal(verifier.acceptGrind(4, honest), true);
    const changed = new SuccessorTranscript(Uint8Array.of(9));
    assert.equal(changed.acceptGrind(4, honest ^ 1), false);
  });

  it("selects deep orbits canonically without replacement", () => {
    const transcript = new SuccessorTranscript(Uint8Array.of(0x31));
    assert.equal(transcript.grind(0), 0);
    const selected = transcript.queryOrbits(512, 12, 3);
    const queries = selected.map(({ orbit, seed }) => orbit * 8 + seed);
    assert.equal(new Set(queries.map((index) => index >> 3)).size, queries.length);
    assert.ok(selected.some(({ counter }, index) => counter > index), "duplicate orbits are skipped");
  });

  it("certifies and realizes the production total representative scan", () => {
    assert.deepEqual(validateLocalWordQuerySamplerGeometry(), {
      rowCount: 16_777_216,
      orbitSize: 131_072,
      orbitCount: 128,
      orbitPrefixLog: 7,
      predecessorStep: 32,
      maxForbiddenCandidates: 4,
      maxScanAttempts: 5,
    });
    const transcript = new SuccessorTranscript(writeU32LE(12_701));
    const samples = localWordQuerySamples(transcript, LOCAL_WORD_PRODUCTION_PARAMETERS);
    assert.equal(samples.length, 29);
    assert.equal(new Set(samples.flatMap(({ query, predecessor }) => [query, predecessor])).size, 58);
    assert.deepEqual(
      { counter: samples[22]!.counter, scan: samples[22]!.scan },
      { counter: 27, scan: 1 },
    );
    assert.deepEqual(samples.map(({ query }) => query), [
      3_148_955, 2_456_095, 15_207_392, 2_310_022, 13_809_885, 15_734_966,
      6_074_301, 1_327_113, 12_552_758, 9_533_181, 16_047_716, 3_993_142,
      5_467_988, 914_973, 6_482_757, 13_450_019, 6_930_327, 4_343_796,
      13_652_611, 13_999_361, 7_848_179, 10_915_404, 4_605_941, 11_831_684,
      15_899_725, 5_328_662, 11_410_360, 8_281_749, 16_575_578,
    ]);
    assert.throws(() => validateLocalWordQuerySamplerGeometry({
      relationLog: 4,
      evalLog: 8,
      quotientDegreeRows: 16,
      fri: {
        logBlowup: 4,
        finalLogDegree: 2,
        foldLog: 2,
        queryOrbitLog: 2,
        queries: 2,
        grindBits: 0,
      },
    }), /total query sampler geometry/);
  });
});

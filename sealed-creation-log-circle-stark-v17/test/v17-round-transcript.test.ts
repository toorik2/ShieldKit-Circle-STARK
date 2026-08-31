import assert from "node:assert/strict";
import test from "node:test";
import { SuccessorTranscript } from
  "../src/backends/circle/successor-transcript.ts";
import {
  V17_THEOREM_ROUND_IDS,
  V17TheoremRoundCursor,
  acceptV17TheoremRound,
  grindV17TheoremRound,
  validateV17ProductionRoundGrinding,
  v17RoundNonceVector,
  type V17RoundGrinding,
} from "../src/backends/circle/v17-round-transcript.ts";

const schedule: readonly V17RoundGrinding[] = V17_THEOREM_ROUND_IDS.map((id, index) => ({
  id,
  bits: index % 4,
}));

test("all fourteen theorem rounds replay in one exact transcript", () => {
  const prover = new SuccessorTranscript(new TextEncoder().encode("v17-round-test"));
  const proof = schedule.map((round) => {
    prover.absorb(`message:${round.id}`, new TextEncoder().encode(round.id));
    return grindV17TheoremRound(prover, round);
  });
  const verifier = new SuccessorTranscript(new TextEncoder().encode("v17-round-test"));
  proof.forEach((round) => {
    verifier.absorb(`message:${round.id}`, new TextEncoder().encode(round.id));
    assert.equal(acceptV17TheoremRound(verifier, round), true);
  });
  assert.deepEqual(verifier.digest, prover.digest);
  assert.equal(v17RoundNonceVector(proof).length, 14);
});

test("nonce relocation and round reordering fail", () => {
  const prover = new SuccessorTranscript(new TextEncoder().encode("v17-round-mutation"));
  prover.absorb("message:air:logup", Uint8Array.of(1));
  const first = grindV17TheoremRound(prover, { id: "air:logup", bits: 6 });

  const wrongId = new SuccessorTranscript(new TextEncoder().encode("v17-round-mutation"));
  wrongId.absorb("message:air:logup", Uint8Array.of(1));
  assert.equal(acceptV17TheoremRound(wrongId, { ...first, id: "air:composition" }), false);

  const wrongMessage = new SuccessorTranscript(new TextEncoder().encode("v17-round-mutation"));
  wrongMessage.absorb("message:air:logup", Uint8Array.of(2));
  assert.equal(acceptV17TheoremRound(wrongMessage, first), false);
});

test("the schedule rejects missing, duplicate, and out-of-range rounds", () => {
  assert.throws(() => v17RoundNonceVector([]));
  assert.throws(() => v17RoundNonceVector(schedule.map((round, index) => ({
    ...round,
    nonce: index === 0 ? -1 : 0,
  }))));
  assert.throws(() => v17RoundNonceVector(schedule.map((round, index) => ({
    ...round,
    id: index === 1 ? "air:logup" : round.id,
    nonce: 0,
  })) as never));
});

test("the production cursor owns order and exact graph grinding bits", () => {
  assert.throws(() => validateV17ProductionRoundGrinding(schedule));
  const prover = new V17TheoremRoundCursor(
    new SuccessorTranscript(new TextEncoder().encode("v17-production-cursor")),
  );
  assert.equal(prover.nextRound?.id, "air:logup");
  assert.throws(() => prover.grind("air:composition"), /round order/);
  const first = prover.grind("air:logup");
  assert.equal(first.bits, 9);
  assert.equal(prover.completedRounds, 1);
  assert.throws(() => prover.finish(), /incomplete/);

  const verifier = new V17TheoremRoundCursor(
    new SuccessorTranscript(new TextEncoder().encode("v17-production-cursor")),
  );
  assert.equal(verifier.accept("air:logup", first.nonce), true);
  assert.deepEqual(verifier.transcript.digest, prover.transcript.digest);
  assert.throws(() => verifier.accept("air:logup", first.nonce), /round order/);
});

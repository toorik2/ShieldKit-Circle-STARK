/** Explicit round-by-round Fiat-Shamir/PoW schedule for the v17 theorem DAG. */
import { SuccessorTranscript } from "./successor-transcript.ts";
import {
  V17_PRODUCTION_ROUND_GRINDING,
  type V17ProductionRoundId,
} from "../../construction/v17-graph.ts";

/** Derived view: the construction graph is the only production owner. */
export const V17_THEOREM_ROUND_IDS = V17_PRODUCTION_ROUND_GRINDING.map(
  ({ id }) => id,
) as readonly V17ProductionRoundId[];

export type V17TheoremRoundId = V17ProductionRoundId;

export type V17RoundGrinding = {
  readonly id: V17TheoremRoundId;
  readonly bits: number;
};

export type V17RoundGrindingNonce = V17RoundGrinding & {
  readonly nonce: number;
};

const ROUND_DOMAIN_LABEL = "v17-theorem-round";

function roundBytes(id: V17TheoremRoundId): Uint8Array {
  const ordinal = V17_THEOREM_ROUND_IDS.indexOf(id);
  if (ordinal < 0 || ordinal > 0xff) throw new Error("v17 theorem round id");
  const name = new TextEncoder().encode(id);
  return Uint8Array.of(17, ordinal, name.length, ...name);
}

export function validateV17RoundGrinding(
  schedule: readonly V17RoundGrinding[],
): readonly V17RoundGrinding[] {
  if (schedule.length !== V17_THEOREM_ROUND_IDS.length || schedule.some((round, index) =>
    round.id !== V17_THEOREM_ROUND_IDS[index] || !Number.isSafeInteger(round.bits) ||
    round.bits < 0 || round.bits > 32)) {
    throw new Error("v17 theorem grinding schedule");
  }
  return schedule;
}

export function validateV17ProductionRoundGrinding(
  schedule: readonly V17RoundGrinding[],
): readonly V17RoundGrinding[] {
  validateV17RoundGrinding(schedule);
  if (schedule.some((round, index) =>
    round.bits !== V17_PRODUCTION_ROUND_GRINDING[index]!.bits)) {
    throw new Error("v17 production grinding bits");
  }
  return schedule;
}

/** Prover side: bind the named round before searching its independent nonce. */
export function grindV17TheoremRound(
  transcript: SuccessorTranscript,
  round: V17RoundGrinding,
): V17RoundGrindingNonce {
  transcript.absorb(ROUND_DOMAIN_LABEL, roundBytes(round.id));
  const nonce = transcript.grind(round.bits);
  return { ...round, nonce };
}

/** Verifier side: exact named-round replay; no nonce may move between rounds. */
export function acceptV17TheoremRound(
  transcript: SuccessorTranscript,
  round: V17RoundGrindingNonce,
): boolean {
  if (!Number.isSafeInteger(round.bits) || round.bits < 0 || round.bits > 32 ||
    !Number.isSafeInteger(round.nonce) || round.nonce < 0 || round.nonce > 0xffff_ffff ||
    !V17_THEOREM_ROUND_IDS.includes(round.id)) return false;
  transcript.absorb(ROUND_DOMAIN_LABEL, roundBytes(round.id));
  return transcript.acceptGrind(round.bits, round.nonce);
}

export function v17RoundNonceVector(
  rounds: readonly V17RoundGrindingNonce[],
): readonly number[] {
  validateV17RoundGrinding(rounds);
  if (rounds.some((round) => !Number.isSafeInteger(round.nonce) ||
    round.nonce < 0 || round.nonce > 0xffff_ffff)) {
    throw new Error("v17 theorem nonce vector");
  }
  return rounds.map(({ nonce }) => nonce);
}

/**
 * Ordered production cursor. Message absorption stays explicit at each
 * protocol boundary, while this class makes skipping, repeating, or moving a
 * valid nonce to another round impossible by construction.
 */
export class V17TheoremRoundCursor {
  private next = 0;

  constructor(readonly transcript: SuccessorTranscript) {}

  get completedRounds(): number {
    return this.next;
  }

  get nextRound(): V17RoundGrinding | undefined {
    return V17_PRODUCTION_ROUND_GRINDING[this.next];
  }

  grind(id: V17TheoremRoundId): V17RoundGrindingNonce {
    const expected = this.expect(id);
    const result = grindV17TheoremRound(this.transcript, expected);
    this.next += 1;
    return result;
  }

  accept(id: V17TheoremRoundId, nonce: number): boolean {
    const expected = this.expect(id);
    if (!acceptV17TheoremRound(this.transcript, { ...expected, nonce })) return false;
    this.next += 1;
    return true;
  }

  finish(): void {
    if (this.next !== V17_PRODUCTION_ROUND_GRINDING.length) {
      throw new Error(`v17 theorem rounds incomplete: ${this.next}/${V17_PRODUCTION_ROUND_GRINDING.length}`);
    }
  }

  private expect(id: V17TheoremRoundId): V17RoundGrinding {
    const expected = V17_PRODUCTION_ROUND_GRINDING[this.next];
    if (!expected || expected.id !== id) {
      throw new Error(`v17 theorem round order: expected ${expected?.id ?? "end"}, got ${id}`);
    }
    return expected;
  }
}

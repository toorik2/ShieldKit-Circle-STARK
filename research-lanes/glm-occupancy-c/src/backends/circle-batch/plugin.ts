/**
 * The FRI10 batch family, registered ALONGSIDE circle-fri-m31 rather than
 * replacing it. FRI_VERSION stays 9; nothing here bumps it.
 *
 * Same Circle FRI, same AIR, same soundness parameters - those modules are
 * imported from ../circle, not copied, so 36 queries / blowup 16 / grind 20 /
 * 128 conjectural bits are the same objects, not values kept in sync.
 *
 * The difference is that the published proof carries every spent note's auth
 * instead of one, so a public verifier can run the membership, nullifier and
 * sum checks that FRI9 could only do with the witness in hand. Masked with
 * per-auth pads (auth-pad.ts) - one pad per plaintext, which is what keeps this
 * as sound as FRI9 rather than a two-time pad.
 */
import {
  decodeFriBatchProof,
  encodeFriBatchProof,
  proveFriBatch,
  verifyFriBatch,
  type FriWitness,
} from "./fri-batch.ts";
import { DEFAULT_INTERNAL_HASH_ID, type InternalHashId } from "../circle/internal-hash.ts";
import type { PluginVerifyResult, ZkpPlugin } from "../../pool/plugin.ts";
import type { PoolStatement } from "../../pool/statement.ts";
import { soundnessWorksheet } from "../circle/soundness.ts";
import { VK_ID } from "../circle/params.ts";

const sheet = soundnessWorksheet();

/** Distinct from FRI9's so cross-family verification cannot silently succeed. */
export const BATCH_VK_ID = `${VK_ID}-batch`;

export const circleFriBatchPlugin: ZkpPlugin = {
  family: "circle-fri-m31-batch",
  vkId: BATCH_VK_ID,
  sound: sheet.sound,
  async prove(statement: PoolStatement, witness: unknown) {
    const w = (witness ?? {}) as FriWitness & { hash?: InternalHashId };
    return encodeFriBatchProof(proveFriBatch(statement, w, { hash: w.hash ?? DEFAULT_INTERNAL_HASH_ID }));
  },
  verify(statement: PoolStatement, proof: Uint8Array, opts?: { hash?: InternalHashId }): PluginVerifyResult {
    try {
      return verifyFriBatch(statement, decodeFriBatchProof(proof), {}, { hash: opts?.hash });
    } catch (e) {
      return { ok: false, reason: e instanceof Error ? e.message : String(e) };
    }
  },
};

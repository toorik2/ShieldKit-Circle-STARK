import { encodeFriProof, proveFri, verifyFri, decodeFriProof, type FriWitness } from "./fri.ts";
import { DEFAULT_INTERNAL_HASH_ID, type InternalHashId } from "./internal-hash.ts";
import type { PluginVerifyResult, ZkpPlugin } from "../../pool/plugin.ts";
import type { PoolStatement } from "../../pool/statement.ts";
import { soundnessWorksheet } from "./soundness.ts";
import { VK_ID } from "./params.ts";

/** Kept so old imports compile. The shipped plugin is `sound` per the worksheet. */
export const CIRCLE_FRI_NOT_SOUND_YET = "CIRCLE_FRI_SOUND_WORKSHEET";

const sheet = soundnessWorksheet();

/**
 * Circle FRI of the pool AIR. B=M31, F_fri=QM31. Hash-based = PQ family.
 * Conjectural bits: see soundnessWorksheet(). Addresses stay Schnorr.
 */
export const circleFriPlugin: ZkpPlugin = {
  family: "circle-fri-m31-qm31",
  vkId: VK_ID,
  sound: sheet.sound,
  async prove(statement: PoolStatement, witness: unknown) {
    const w = (witness ?? {}) as FriWitness & { hash?: InternalHashId };
    return encodeFriProof(proveFri(statement, w, { hash: w.hash ?? DEFAULT_INTERNAL_HASH_ID }));
  },
  verify(statement: PoolStatement, proof: Uint8Array, opts?: { hash?: InternalHashId }): PluginVerifyResult {
    try {
      return verifyFri(statement, decodeFriProof(proof), {}, { hash: opts?.hash });
    } catch (e) {
      return { ok: false, reason: e instanceof Error ? e.message : String(e) };
    }
  },
};

import { IncrementalMerkle } from "../pool/notes.ts";
import type { PluginVerifyResult, ZkpPlugin } from "../pool/plugin.ts";
import { encodeStatement, type PoolStatement } from "../pool/statement.ts";
import { sha256 } from "../pool/bytes.ts";

export type HashLabWitness = {
  /** Off-chain membership path. Not hidden — this backend is not private. */
  path?: Uint8Array[];
  index?: number;
  leaf?: Uint8Array;
};

/**
 * Lab backend: re-hashes the public statement. Anyone who sees the tx sees
 * `publicAmount`. Membership is checked in the CLI, not in this proof.
 * The covenant still requires the lab key so a stranger cannot rewrite roots.
 */
export const hashLabPlugin: ZkpPlugin = {
  family: "hash-lab-v0",
  vkId: "hash-lab-v0",
  sound: false,
  async prove(statement: PoolStatement, witness: unknown) {
    const w = (witness ?? {}) as HashLabWitness;
    if (w.leaf && w.path && w.index !== undefined) {
      if (!IncrementalMerkle.verify(w.leaf, w.index, w.path, statement.oldState.noteRoot) &&
          statement.action === "WITHDRAW") {
        throw new Error("hash-lab: leaf not in old noteRoot");
      }
    }
    return sha256(encodeStatement(statement));
  },
  verify(statement: PoolStatement, proof: Uint8Array): PluginVerifyResult {
    const expect = sha256(encodeStatement(statement));
    if (proof.length !== expect.length || proof.some((b, i) => b !== expect[i])) {
      return { ok: false, reason: "hash-lab digest mismatch" };
    }
    return { ok: true };
  },
};

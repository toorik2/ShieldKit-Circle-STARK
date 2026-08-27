import type { PoolStatement } from "./statement.ts";

export type ProofBytes = Uint8Array;

export type PluginVerifyResult =
  | { ok: true }
  | { ok: false; reason: string };

/**
 * ZKP-agnostic hook. The covenant (later) calls this. Circle FRI is plugin #1.
 * A backend that is not sound must refuse, not pretend.
 */
export type PluginVerifyOpts = { hash?: string };

export interface ZkpPlugin {
  readonly family: string;
  readonly vkId: string;
  readonly sound: boolean;
  prove(statement: PoolStatement, witness: unknown): Promise<ProofBytes>;
  verify(statement: PoolStatement, proof: ProofBytes, opts?: PluginVerifyOpts): PluginVerifyResult;
}

export function requirePlugin(plugin: ZkpPlugin, want: string): void {
  if (plugin.family !== want) {
    throw new Error(`plugin ${plugin.family} is not ${want}`);
  }
}

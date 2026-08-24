import { circleFriPlugin } from "../backends/circle/plugin.ts";
import type { ZkpPlugin } from "../pool/plugin.ts";

export const zkpPlugins: ZkpPlugin[] = [circleFriPlugin];
export const DEFAULT_ZKP_FAMILY = circleFriPlugin.family;

export function defaultZkpPlugin(): ZkpPlugin {
  return circleFriPlugin;
}

export function zkpPluginByFamily(family: string): ZkpPlugin {
  const p = zkpPlugins.find((x) => x.family === family);
  if (!p) throw new Error(`unknown zkp family ${family}`);
  return p;
}

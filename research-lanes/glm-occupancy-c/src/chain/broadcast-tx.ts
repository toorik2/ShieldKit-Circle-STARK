/**
 * Size-gated Chipnet broadcast.
 * ≤ 100000 bytes: Electrum (public relay).
 * > 100000 bytes: JSON-RPC sendrawtransaction only. Not Electrum. Not P2P inv.
 */
import { binToHex } from "@bitauth/libauth";
import { sendRawTransactionRpc, type BchnRpcConfig } from "./bchn-rpc.ts";
import { RELAY_STANDARD_TX_BYTES } from "./envelope.ts";

export type BroadcastPath = "electrum" | "json-rpc";

export function chooseBroadcastPath(txBytes: number): BroadcastPath {
  return txBytes > RELAY_STANDARD_TX_BYTES ? "json-rpc" : "electrum";
}

export async function broadcastSized(args: {
  raw: Uint8Array;
  electrum?: (rawHex: string) => Promise<string>;
  rpc?: BchnRpcConfig;
}): Promise<{ txid: string; path: BroadcastPath }> {
  const path = chooseBroadcastPath(args.raw.length);
  const hex = binToHex(args.raw);
  if (path === "electrum") {
    if (!args.electrum) throw new Error("electrum required for standard-size broadcast");
    const txid = await args.electrum(hex);
    return { txid, path };
  }
  if (!args.rpc) throw new Error("BCHN JSON-RPC required for consensus-size broadcast");
  const txid = await sendRawTransactionRpc(hex, args.rpc);
  return { txid, path };
}

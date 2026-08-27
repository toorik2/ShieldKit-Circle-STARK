/**
 * BCHN JSON-RPC sendrawtransaction (HTTP body).
 * Used for consensus-size Chipnet spends. Never logs user/password.
 * bitcoin-cli argv cannot carry a ~600 KB hex.
 */
export type RpcAuth = { user: string; password: string };

export type RpcPost = (url: string, body: unknown, auth?: RpcAuth) => Promise<unknown>;

export type BchnRpcConfig = {
  url: string;
  user?: string;
  password?: string;
  post?: RpcPost;
};

export type JsonRpcRequest = {
  jsonrpc: "1.0";
  id: string;
  method: string;
  params: unknown[];
};

export function sendRawTransactionBody(rawHex: string): JsonRpcRequest {
  return {
    jsonrpc: "1.0",
    id: "land",
    method: "sendrawtransaction",
    params: [rawHex],
  };
}

export async function defaultRpcPost(url: string, body: unknown, auth?: RpcAuth): Promise<unknown> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (auth?.user) {
    headers.Authorization = `Basic ${Buffer.from(`${auth.user}:${auth.password}`).toString("base64")}`;
  }
  const res = await fetch(url, { method: "POST", headers, body: JSON.stringify(body) });
  const text = await res.text();
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw new Error(`bchn-rpc non-json ${res.status}`);
  }
}

export function rpcConfigFromEnv(env: NodeJS.ProcessEnv = process.env): BchnRpcConfig {
  const url = env.BCHN_RPC_URL?.trim();
  if (!url) throw new Error("BCHN_RPC_URL required for consensus-size sendrawtransaction");
  return {
    url,
    user: env.BCHN_RPC_USER,
    password: env.BCHN_RPC_PASSWORD,
  };
}

export async function sendRawTransactionRpc(rawHex: string, cfg: BchnRpcConfig): Promise<string> {
  if (!rawHex || rawHex.length < 2) throw new Error("empty hex");
  const body = sendRawTransactionBody(rawHex);
  const post = cfg.post ?? defaultRpcPost;
  const auth =
    cfg.user !== undefined ? { user: cfg.user, password: cfg.password ?? "" } : undefined;
  const raw = await post(cfg.url, body, auth);
  const parsed = raw as { result?: unknown; error?: { message?: string } | string | null };
  if (parsed.error) {
    const msg = typeof parsed.error === "string" ? parsed.error : parsed.error.message ?? "rpc";
    throw new Error(`sendrawtransaction: ${msg}`);
  }
  if (typeof parsed.result !== "string" || parsed.result.length < 16) {
    throw new Error("sendrawtransaction: missing txid");
  }
  return parsed.result;
}

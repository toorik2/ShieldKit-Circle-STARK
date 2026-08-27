const CHIPNET_PUBLIC = [
  "wss://chipnet.imaginary.cash:50004",
  "wss://chipnet.bch.ninja:50004",
];

/** Prefer CHIPNET_ELECTRUM, then a local BCHN/Start9 Electrum if present, then public. */
function chipnetServers(): string[] {
  const extra = process.env.CHIPNET_ELECTRUM?.trim();
  const local = [
    "ws://192.168.0.55:50004",
    "wss://192.168.0.55:50004",
    "ws://127.0.0.1:50004",
  ];
  return [...(extra ? [extra] : []), ...local, ...CHIPNET_PUBLIC];
}

type Pending = {
  resolve: (value: unknown) => void;
  reject: (err: Error) => void;
};

export class ElectrumClient {
  private ws: WebSocket | undefined;
  private nextId = 1;
  private readonly pending = new Map<number, Pending>();

  async connect(url: string, timeoutMs = 15_000): Promise<void> {
    if (typeof WebSocket === "undefined") {
      throw new Error("WebSocket not available; need Node 22+");
    }
    await new Promise<void>((resolve, reject) => {
      const ws = new WebSocket(url);
      this.ws = ws;
      const timer = setTimeout(() => reject(new Error(`electrum timeout ${url}`)), timeoutMs);
      ws.addEventListener("open", () => {
        clearTimeout(timer);
        resolve();
      });
      ws.addEventListener("error", () => {
        clearTimeout(timer);
        reject(new Error(`electrum error ${url}`));
      });
      ws.addEventListener("message", (ev) => {
        const msg = JSON.parse(String(ev.data)) as {
          id?: number;
          result?: unknown;
          error?: { message?: string };
        };
        if (msg.id === undefined) return;
        const p = this.pending.get(msg.id);
        if (!p) return;
        this.pending.delete(msg.id);
        if (msg.error) p.reject(new Error(msg.error.message ?? "electrum"));
        else p.resolve(msg.result);
      });
    });
  }

  async request(method: string, params: unknown[] = [], timeoutMs = 20_000): Promise<unknown> {
    if (!this.ws) throw new Error("not connected");
    const id = this.nextId++;
    const body = JSON.stringify({ id, method, params });
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.ws!.send(body);
      setTimeout(() => {
        if (this.pending.delete(id)) reject(new Error(`electrum ${method} timed out`));
      }, timeoutMs);
    });
  }

  close(): void {
    this.ws?.close();
    this.ws = undefined;
  }
}

export async function connectChipnet(): Promise<ElectrumClient> {
  let last: Error | undefined;
  const servers = chipnetServers();
  for (const url of servers) {
    const c = new ElectrumClient();
    const local = url.includes("192.168.0.55") || url.includes("127.0.0.1");
    try {
      await c.connect(url, local ? 800 : 15_000);
      return c;
    } catch (e) {
      last = e instanceof Error ? e : new Error(String(e));
      c.close();
    }
  }
  throw last ?? new Error("no chipnet electrum");
}

export type ElectrumUtxo = {
  tx_hash: string;
  tx_pos: number;
  value: number;
  height: number;
  token_data?: {
    category: string;
    amount?: string;
    nft?: { capability: string; commitment: string };
  };
};

export async function listUnspent(
  client: ElectrumClient,
  address: string,
): Promise<ElectrumUtxo[]> {
  const r = await client.request("blockchain.address.listunspent", [address]);
  return r as ElectrumUtxo[];
}

export async function broadcast(client: ElectrumClient, rawHex: string): Promise<string> {
  // rawHex.length is twice the tx byte size, so the old `> 200_000` cutoff meant
  // "over 100 KB". Envelope C tape hops are 82-89 KB (165-179 K hex): under that
  // cutoff, so they got 30 s, which public chipnet Electrum does not reliably meet
  // for an 80 KB push. Scale on bytes instead.
  const bytes = rawHex.length / 2;
  // 90 s was not enough for an 83 KB tape hop: the run reported a timeout while
  // the same tx broadcast fine on a direct 150 s attempt. Give big pushes room.
  const timeoutMs = bytes > 100_000 ? 240_000 : bytes > 20_000 ? 240_000 : 30_000;
  return (await client.request("blockchain.transaction.broadcast", [rawHex], timeoutMs)) as string;
}

export async function getTx(client: ElectrumClient, txid: string): Promise<string> {
  return (await client.request("blockchain.transaction.get", [txid])) as string;
}

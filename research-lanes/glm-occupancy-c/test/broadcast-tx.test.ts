import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { sendRawTransactionBody } from "../src/chain/bchn-rpc.ts";
import { broadcastSized, chooseBroadcastPath } from "../src/chain/broadcast-tx.ts";
import { RELAY_STANDARD_TX_BYTES } from "../src/chain/envelope.ts";

describe("size-gated Chipnet broadcast", () => {
  it("sends a >100000-byte payload with JSON-RPC sendrawtransaction, not Electrum or P2P", async () => {
    const raw = new Uint8Array(RELAY_STANDARD_TX_BYTES + 1).fill(0xab);
    let electrumCalls = 0;
    let p2pCalls = 0;
    const posts: Array<{ url: string; method: string; hexLen: number }> = [];
    const r = await broadcastSized({
      raw,
      electrum: async () => {
        electrumCalls += 1;
        return "electrum-should-not-run";
      },
      rpc: {
        url: "http://bchn.test:48332",
        user: "u",
        password: "p",
        post: async (url, body) => {
          const req = body as { method?: string; params?: string[] };
          posts.push({ url, method: String(req.method), hexLen: req.params?.[0]?.length ?? 0 });
          return { result: "11".repeat(32), error: null };
        },
      },
    });
    void p2pCalls;
    assert.equal(chooseBroadcastPath(raw.length), "json-rpc");
    assert.equal(r.path, "json-rpc");
    assert.equal(electrumCalls, 0);
    assert.equal(posts.length, 1);
    assert.equal(posts[0]!.url, "http://bchn.test:48332");
    assert.equal(posts[0]!.method, "sendrawtransaction");
    assert.equal(sendRawTransactionBody("aa").method, "sendrawtransaction");
    assert.equal(posts[0]!.hexLen, raw.length * 2);
    assert.equal(r.txid, "11".repeat(32));
  });

  it("sends a standard-size payload with Electrum, not JSON-RPC", async () => {
    const raw = new Uint8Array(100).fill(0x01);
    let rpcCalls = 0;
    const r = await broadcastSized({
      raw,
      electrum: async (hex) => {
        assert.equal(hex.length, 200);
        return "22".repeat(32);
      },
      rpc: {
        url: "http://bchn.test:48332",
        post: async () => {
          rpcCalls += 1;
          return { result: "rpc-should-not-run", error: null };
        },
      },
    });
    assert.equal(chooseBroadcastPath(raw.length), "electrum");
    assert.equal(r.path, "electrum");
    assert.equal(rpcCalls, 0);
    assert.equal(r.txid, "22".repeat(32));
  });
});

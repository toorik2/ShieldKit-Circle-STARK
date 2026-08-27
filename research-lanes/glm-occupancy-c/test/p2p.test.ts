import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { CHIPNET_NET_MAGIC, encodeP2pMessage, encodeVersionPayload } from "../src/chain/p2p.ts";

describe("chipnet p2p framing", () => {
  it("encodes a 24-byte header plus payload with Chipnet magic", () => {
    const payload = Uint8Array.of(1, 2, 3, 4);
    const msg = encodeP2pMessage("verack", payload);
    assert.equal(msg.length, 24 + 4);
    assert.deepEqual(msg.subarray(0, 4), CHIPNET_NET_MAGIC);
    assert.equal(new TextDecoder().decode(msg.subarray(4, 16)).replace(/\0+$/, ""), "verack");
    assert.equal(msg[16], 4);
    assert.equal(msg[17], 0);
  });

  it("version payload is at least 85 bytes", () => {
    const v = encodeVersionPayload("192.168.0.55", 48333);
    assert.ok(v.length >= 85, `version ${v.length}`);
  });
});

import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { getPublicKey, nip44 } from "nostr-tools";
import { announceEvent, giftWrapJson, newRoundKey, POOL_ANNOUNCE_KIND } from "../src/nostr/bus.ts";
import { torStatus } from "../src/nostr/tor.ts";

describe("nostr bus", () => {
  it("announce is replaceable kind 12240", () => {
    const { secret } = newRoundKey();
    const ev = announceEvent(secret, {
      network: "chipnet",
      profile: "any-amount-v0",
      pluginFamily: "hash-lab-v0",
      instanceHint: "demo",
      expiresAt: 1,
    });
    assert.equal(ev.kind, POOL_ANNOUNCE_KIND);
    assert.ok(ev.id.length === 64);
  });

  it("NIP-44/59 wrap decrypts for the recipient", () => {
    const sender = newRoundKey();
    const recipient = newRoundKey();
    const wrap = giftWrapJson(sender.secret, recipient.pub, "hello-pool");
    assert.equal(wrap.kind, 1059);
    const sealJson = nip44.v2.decrypt(
      wrap.content,
      nip44.v2.utils.getConversationKey(recipient.secret, wrap.pubkey),
    );
    const seal = JSON.parse(sealJson) as { content: string; pubkey: string };
    const rumorJson = nip44.v2.decrypt(
      seal.content,
      nip44.v2.utils.getConversationKey(recipient.secret, seal.pubkey),
    );
    const rumor = JSON.parse(rumorJson) as { content: string; pubkey: string };
    assert.equal(rumor.content, "hello-pool");
    assert.equal(rumor.pubkey, getPublicKey(sender.secret));
  });

  it("tor required fails closed without SOCKS", () => {
    const prev = process.env.TOR_SOCKS;
    const all = process.env.ALL_PROXY;
    delete process.env.TOR_SOCKS;
    delete process.env.ALL_PROXY;
    assert.match(torStatus("required"), /fail closed/);
    if (prev) process.env.TOR_SOCKS = prev;
    if (all) process.env.ALL_PROXY = all;
  });
});

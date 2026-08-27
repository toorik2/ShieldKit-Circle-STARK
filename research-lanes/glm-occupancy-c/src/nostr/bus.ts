import {
  finalizeEvent,
  generateSecretKey,
  getPublicKey,
  type Event,
  type EventTemplate,
} from "nostr-tools";
import { nip44 } from "nostr-tools";

/** Same job as OPTN fusion: replaceable announce + gift-wrapped private payload. */
export const POOL_ANNOUNCE_KIND = 12240;
export const POOL_PROTOCOL = 1;

export type PoolAnnounce = {
  network: "chipnet";
  profile: "any-amount-v0";
  pluginFamily: string;
  instanceHint: string;
  expiresAt: number;
};

export function announceEvent(secret: Uint8Array, announce: PoolAnnounce): Event {
  const template: EventTemplate = {
    kind: POOL_ANNOUNCE_KIND,
    created_at: Math.floor(Date.now() / 1000),
    tags: [
      ["d", "any-amount"],
      ["network", announce.network],
      ["profile", announce.profile],
      ["plugin", announce.pluginFamily],
    ],
    content: JSON.stringify(announce),
  };
  return finalizeEvent(template, secret);
}

/**
 * NIP-44 encrypt a rumor, NIP-59 seal (kind 13) + wrap (kind 1059).
 * IP still leaks to the relay unless the WebSocket is over Tor.
 */
export function giftWrapJson(
  senderSecret: Uint8Array,
  recipientPubHex: string,
  rumorContent: string,
): Event {
  const conversation = nip44.v2.utils.getConversationKey(senderSecret, recipientPubHex);
  const sealedContent = nip44.v2.encrypt(
    JSON.stringify({
      pubkey: getPublicKey(senderSecret),
      created_at: Math.floor(Date.now() / 1000),
      kind: 14,
      tags: [["p", recipientPubHex]],
      content: rumorContent,
    }),
    conversation,
  );
  const seal = finalizeEvent(
    {
      kind: 13,
      created_at: Math.floor(Date.now() / 1000) - Math.floor(Math.random() * 86_400),
      tags: [],
      content: sealedContent,
    },
    senderSecret,
  );
  const wrapKey = generateSecretKey();
  const wrapConv = nip44.v2.utils.getConversationKey(wrapKey, recipientPubHex);
  return finalizeEvent(
    {
      kind: 1059,
      created_at: Math.floor(Date.now() / 1000) - Math.floor(Math.random() * 86_400),
      tags: [["p", recipientPubHex]],
      content: nip44.v2.encrypt(JSON.stringify(seal), wrapConv),
    },
    wrapKey,
  );
}

export function newRoundKey(): { secret: Uint8Array; pub: string } {
  const secret = generateSecretKey();
  return { secret, pub: getPublicKey(secret) };
}

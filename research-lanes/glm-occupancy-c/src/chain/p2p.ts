/**
 * Minimal Chipnet P2P submit. Public Electrum enforces 100 KB standard.
 * A local BCHN (Start9 :48333) can take a larger tx if it will mine nonstandard.
 */
import { createConnection, type Socket } from "node:net";
import { sha256 } from "../pool/bytes.ts";

/** BCHN CChipNetParams.netMagic */
export const CHIPNET_NET_MAGIC = Uint8Array.of(0xe2, 0xb7, 0xda, 0xaf);
export const CHIPNET_P2P_DEFAULT = { host: "192.168.0.55", port: 48333 };

function sha256d(data: Uint8Array): Uint8Array {
  return sha256(sha256(data));
}

function u32le(n: number): Uint8Array {
  return Uint8Array.of(n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >> 24) & 0xff);
}

function u64le(n: bigint): Uint8Array {
  const out = new Uint8Array(8);
  let x = n;
  for (let i = 0; i < 8; i += 1) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}

function compactSize(n: number): Uint8Array {
  if (n < 253) return Uint8Array.of(n);
  if (n <= 0xffff) return Uint8Array.of(253, n & 0xff, (n >> 8) & 0xff);
  return Uint8Array.of(254, ...u32le(n));
}

export function encodeP2pMessage(command: string, payload: Uint8Array, magic = CHIPNET_NET_MAGIC): Uint8Array {
  const cmd = new Uint8Array(12);
  const enc = new TextEncoder().encode(command);
  if (enc.length > 12) throw new Error(`p2p command ${command}`);
  cmd.set(enc);
  const checksum = sha256d(payload).subarray(0, 4);
  const out = new Uint8Array(24 + payload.length);
  out.set(magic, 0);
  out.set(cmd, 4);
  out.set(u32le(payload.length), 16);
  out.set(checksum, 20);
  out.set(payload, 24);
  return out;
}

function ipv4Mapped(ip: string): Uint8Array {
  const parts = ip.split(".").map((p) => Number(p));
  if (parts.length !== 4 || parts.some((p) => !Number.isInteger(p) || p < 0 || p > 255)) {
    return Uint8Array.of(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1);
  }
  return Uint8Array.of(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, parts[0]!, parts[1]!, parts[2]!, parts[3]!);
}

function netAddr(ip: string, port: number): Uint8Array {
  const out = new Uint8Array(26);
  out.set(u64le(0n), 0);
  out.set(ipv4Mapped(ip), 8);
  out.set(Uint8Array.of((port >> 8) & 0xff, port & 0xff), 24);
  return out;
}

export function encodeVersionPayload(peerHost: string, peerPort: number): Uint8Array {
  const ua = new TextEncoder().encode("/any-amount-lab:0.1.0/");
  const parts = [
    u32le(70016),
    u64le(0n),
    u64le(BigInt(Math.floor(Date.now() / 1000))),
    netAddr(peerHost, peerPort),
    netAddr("127.0.0.1", 0),
    u64le(0x414e59414d543031n),
    compactSize(ua.length),
    ua,
    u32le(0),
    Uint8Array.of(1),
  ];
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

export type P2pBroadcastResult = {
  ok: boolean;
  host: string;
  port: number;
  reject?: string;
  note?: string;
};

function pullMessages(
  buf: Uint8Array,
  magic: Uint8Array,
): { msgs: Array<{ command: string; payload: Uint8Array }>; rest: Uint8Array } {
  const msgs: Array<{ command: string; payload: Uint8Array }> = [];
  let cur = buf;
  while (cur.length >= 24) {
    if (cur[0] !== magic[0] || cur[1] !== magic[1] || cur[2] !== magic[2] || cur[3] !== magic[3]) {
      cur = cur.subarray(1);
      continue;
    }
    const len = cur[16]! | (cur[17]! << 8) | (cur[18]! << 16) | (cur[19]! << 24);
    if (len < 0 || len > 32_000_000 || cur.length < 24 + len) break;
    msgs.push({
      command: new TextDecoder().decode(cur.subarray(4, 16)).replace(/\0+$/, ""),
      payload: cur.subarray(24, 24 + len),
    });
    cur = cur.subarray(24 + len);
  }
  return { msgs, rest: cur };
}

export async function broadcastP2p(
  raw: Uint8Array,
  host = CHIPNET_P2P_DEFAULT.host,
  port = CHIPNET_P2P_DEFAULT.port,
  timeoutMs = 20_000,
): Promise<P2pBroadcastResult> {
  return await new Promise((resolve) => {
    let sock: Socket | undefined;
    let acc = new Uint8Array();
    let handed = false;
    let sent = false;
    const done = (r: P2pBroadcastResult) => {
      clearTimeout(timer);
      try {
        sock?.destroy();
      } catch {
        /* ignore */
      }
      resolve(r);
    };
    const timer = setTimeout(() => {
      done(
        sent
          ? { ok: true, host, port, note: "sent; no reject before timeout (peer may have accepted)" }
          : { ok: false, host, port, reject: "p2p timeout before handshake" },
      );
    }, timeoutMs);

    sock = createConnection({ host, port }, () => {
      sock!.write(Buffer.from(encodeP2pMessage("version", encodeVersionPayload(host, port))));
    });
    sock.setTimeout(timeoutMs);
    sock.on("timeout", () => done({ ok: false, host, port, reject: "p2p socket timeout" }));
    sock.on("error", (e) => done({ ok: false, host, port, reject: e.message }));
    sock.on("data", (chunk: Buffer) => {
      const next = new Uint8Array(acc.length + chunk.length);
      next.set(acc);
      next.set(chunk, acc.length);
      acc = next;
      const pulled = pullMessages(acc, CHIPNET_NET_MAGIC);
      acc = pulled.rest;
      for (const m of pulled.msgs) {
        if (!m.command) continue;
        if (m.command === "version" && !handed) {
          sock!.write(Buffer.from(encodeP2pMessage("verack", new Uint8Array())));
          handed = true;
        }
        if ((m.command === "verack" || handed) && !sent) {
          sock!.write(Buffer.from(encodeP2pMessage("tx", raw)));
          sent = true;
        }
        if (m.command === "reject") {
          const msg = new TextDecoder().decode(m.payload).replace(/[^\x20-\x7e]+/g, " ").trim();
          done({ ok: false, host, port, reject: msg.slice(0, 200) });
          return;
        }
      }
    });
  });
}

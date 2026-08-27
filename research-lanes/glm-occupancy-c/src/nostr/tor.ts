/**
 * Tor is unlinkability for the Nostr/Electrum sockets, not a mix-net.
 * Privacy ops fail closed if a SOCKS proxy is required and missing.
 */
export type TorMode = "off" | "required" | "optional";

export function resolveSocks(mode: TorMode, explicit?: string): string | undefined {
  const url = explicit ?? process.env.ALL_PROXY ?? process.env.TOR_SOCKS;
  if (mode === "off") return undefined;
  if (mode === "required" && !url) {
    throw new Error("Tor required (set TOR_SOCKS=socks5h://127.0.0.1:9050) — fail closed");
  }
  return url;
}

export function torStatus(mode: TorMode): string {
  try {
    const socks = resolveSocks(mode);
    if (!socks) return `tor=${mode} unused`;
    return `tor=${mode} socks=${socks}`;
  } catch (e) {
    return e instanceof Error ? e.message : String(e);
  }
}

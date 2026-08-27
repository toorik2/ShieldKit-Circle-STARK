#!/usr/bin/env python3
"""Run on Start9 inside bitcoind netns. Never prints RPC secrets."""
import base64
import json
import os
import pathlib
import urllib.error
import urllib.request

HEX_PATH = os.environ.get("LAND_HEX", "/tmp/successor-consensus.hex")
STORE_CANDIDATES = [
    "/media/startos/data/package-data/volumes/bitcoincashd/data/main/store.json",
    "/data/store.json",
    "/root/.bitcoin/store.json",
]


def main() -> None:
    raw_hex = pathlib.Path(HEX_PATH).read_text().strip()
    if len(raw_hex) < 200:
        raise SystemExit("hex too small")
    store = next((p for p in STORE_CANDIDATES if os.path.exists(p)), None)
    if store is None:
        raise SystemExit("store.json not found")
    cfg = json.loads(pathlib.Path(store).read_text())
    user = cfg.get("rpcUser") or cfg.get("rpcuser")
    password = cfg.get("rpcPassword") or cfg.get("rpcpassword")
    if not user:
        raise SystemExit("rpc user missing")
    body = json.dumps(
        {"jsonrpc": "1.0", "id": "land", "method": "sendrawtransaction", "params": [raw_hex]}
    ).encode()
    auth = base64.b64encode(f"{user}:{password}".encode()).decode()
    req = urllib.request.Request(
        "http://127.0.0.1:48332",
        data=body,
        headers={"Content-Type": "application/json", "Authorization": f"Basic {auth}"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            out = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        out = json.loads(e.read().decode())
    if out.get("error"):
        err = out["error"]
        msg = err if isinstance(err, str) else err.get("message", str(err))
        raise SystemExit(f"rpc: {msg}")
    print(out.get("result"))


if __name__ == "__main__":
    main()

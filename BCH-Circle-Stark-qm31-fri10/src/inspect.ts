import { existsSync, readFileSync } from "node:fs";
import { decodeTransaction, hexToBin, hash256 } from "@bitauth/libauth";
import { COMMITTED_LAYERS } from "./backends/circle/params.ts";
import { soundnessWorksheet } from "./backends/circle/soundness.ts";
import { compileFoldKernel } from "./chain/fold-kernel.ts";
import { compileFriQueryKernel, FRI_LEFTOVER_BYTES, FRI_PAIR_BYTES_L0, FRI_PAIR_BYTES_QM } from "./chain/fri-kernel.ts";
import { connectChipnet, getTx } from "./chain/electrum.ts";

const CHIPNET = "60d186ded18897a50d0a4205ed446ab02339a53eb6d8f4a7043b4e405796edc4";

function lastPush(u: Uint8Array): Uint8Array {
  let i = 0;
  let last = new Uint8Array();
  while (i < u.length) {
    const op = u[i]!;
    if (op > 0 && op <= 75) {
      last = u.subarray(i + 1, i + 1 + op);
      i += 1 + op;
    } else if (op === 0x4c) {
      const n = u[i + 1]!;
      last = u.subarray(i + 2, i + 2 + n);
      i += 2 + n;
    } else if (op === 0x4d) {
      const n = u[i + 1]! | (u[i + 2]! << 8);
      last = u.subarray(i + 3, i + 3 + n);
      i += 3 + n;
    } else i += 1;
  }
  return last;
}

function dummy22Prefix(u: Uint8Array): number {
  if (u.length < 2) return 0;
  const op = u[0]!;
  let n = 0;
  let off = 1;
  if (op > 0 && op <= 75) n = op;
  else if (op === 0x4c && u.length >= 2) {
    n = u[1]!;
    off = 2;
  } else if (op === 0x4d && u.length >= 3) {
    n = u[1]! | (u[2]! << 8);
    off = 3;
  } else return 0;
  if (n < 1 || off + n > u.length) return 0;
  return u.subarray(off, off + n).every((b) => b === 0x22) ? n : 0;
}

function countOp(bin: Uint8Array, op: number): number {
  return bin.reduce((n, b) => n + (b === op ? 1 : 0), 0);
}

export async function loadSuccessorHex(arg?: string): Promise<{ hex: string; txid: string }> {
  if (arg && /^[0-9a-f]{64}$/i.test(arg)) {
    const client = await connectChipnet();
    try {
      return { hex: await getTx(client, arg), txid: arg };
    } finally {
      client.close();
    }
  }
  const path = arg ?? "artifact/chipnet-successor.hex";
  if (existsSync(path)) return { hex: readFileSync(path, "utf8").trim(), txid: CHIPNET };
  const local = ".local/successor-consensus.hex";
  if (existsSync(local)) return { hex: readFileSync(local, "utf8").trim(), txid: CHIPNET };
  const client = await connectChipnet();
  try {
    return { hex: await getTx(client, CHIPNET), txid: CHIPNET };
  } finally {
    client.close();
  }
}

export function inspectHex(hex: string, txid = CHIPNET) {
  const raw = hexToBin(hex.startsWith("0x") ? hex.slice(2) : hex);
  if (typeof raw === "string") throw new Error(raw);
  const tx = decodeTransaction(raw);
  if (typeof tx === "string") throw new Error(tx);
  const unlocking = tx.inputs.map((i) => i.unlockingBytecode);
  const redeems = unlocking.map(lastPush);
  const padSum = unlocking.reduce((n, u) => n + dummy22Prefix(u), 0);
  const merkle = Array.from({ length: COMMITTED_LAYERS }, (_, layer) => {
    const want = compileFriQueryKernel(layer);
    const hit = redeems.findIndex((r) => Buffer.from(hash256(r)).equals(Buffer.from(hash256(want))));
    return { layer, redeemMatch: hit, sha256: hit >= 0 ? countOp(redeems[hit]!, 0xa8) : 0 };
  });
  const foldHits = Array.from({ length: 6 }, (_, f) => {
    const want = compileFoldKernel(6, f * 6);
    const i = redeems.findIndex((r) => Buffer.from(hash256(r)).equals(Buffer.from(hash256(want))));
    return { queryIndex: f * 6, redeemMatch: i };
  });
  const w = soundnessWorksheet();
  return {
    txid,
    txBytes: raw.length,
    nIn: tx.inputs.length,
    nOut: tx.outputs.length,
    maxUnlocking: Math.max(...unlocking.map((u) => u.length)),
    maxRedeem: Math.max(...redeems.map((r) => r.length)),
    padSum,
    leftoverBytes: FRI_LEFTOVER_BYTES,
    pairBytes: { l0: FRI_PAIR_BYTES_L0, later: FRI_PAIR_BYTES_QM },
    merkle,
    foldHits,
    worksheet: { vkId: w.vkId, field: w.field, fieldBits: w.fieldBits, minBits: w.minBits },
    standardBox: raw.length <= 100_000 && Math.max(...unlocking.map((u) => u.length)) <= 10_000,
  };
}

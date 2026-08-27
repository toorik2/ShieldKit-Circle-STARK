/**
 * Adversarial inspect of mined Chipnet successor: size, input count,
 * leftover-bind / SHA-256 in P2SH32 redeems, occupancy fingerprints.
 */
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { decodeTransaction, hexToBin, binToHex, hash256, hashTransaction } from "@bitauth/libauth";
import { compileFriQueryKernel, FRI_LEFTOVER_BYTES, FRI_PAIR_BYTES_L0, FRI_PAIR_BYTES_QM } from "../src/chain/fri-kernel.ts";
import { compileFoldKernel } from "../src/chain/fold-kernel.ts";
import { COMMITTED_LAYERS } from "../src/backends/circle/params.ts";
import { soundnessWorksheet } from "../src/backends/circle/soundness.ts";
import { connectChipnet, getTx } from "../src/chain/electrum.ts";

const TXID = process.argv[2] ?? "60d186ded18897a50d0a4205ed446ab02339a53eb6d8f4a7043b4e405796edc4";
const OUT = process.argv[3] ?? "chipnet-inspect.json";

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
    } else {
      i += 1;
    }
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
  const body = u.subarray(off, off + n);
  return body.every((b) => b === 0x22) ? n : 0;
}

function countOp(bin: Uint8Array, op: number): number {
  return bin.reduce((n, b) => n + (b === op ? 1 : 0), 0);
}

function hasPush(bin: Uint8Array, data: Uint8Array): boolean {
  const needle = Buffer.from(data);
  return Buffer.from(bin).includes(needle);
}

async function loadHex(): Promise<string> {
  if (TXID.endsWith(".hex") && existsSync(TXID)) return readFileSync(TXID, "utf8").trim();
  const client = await connectChipnet();
  try {
    return await getTx(client, TXID);
  } finally {
    client.close();
  }
}

const hex = await loadHex();
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
  const r = hit >= 0 ? redeems[hit]! : undefined;
  return {
    layer,
    stride: layer === 0 ? FRI_PAIR_BYTES_L0 : FRI_PAIR_BYTES_QM,
    redeemMatch: hit,
    sha256: r ? countOp(r, 0xa8) : 0,
    equalverify: r ? countOp(r, 0x88) : 0,
    hasStridePush: r ? hasPush(r, Uint8Array.of(layer === 0 ? FRI_PAIR_BYTES_L0 : FRI_PAIR_BYTES_QM)) : false,
  };
});

const foldHits = Array.from({ length: 6 }, (_, f) => {
  const want = compileFoldKernel(6, f * 6);
  const i = redeems.findIndex((r) => Buffer.from(hash256(r)).equals(Buffer.from(hash256(want))));
  return { queryIndex: f * 6, redeemMatch: i, sha256: i >= 0 ? countOp(redeems[i]!, 0xa8) : 0 };
});
const foldAny = redeems.find((r) => r.length > 4000 && countOp(r, 0xa8) > 5);

const w = soundnessWorksheet();
const report = {
  txid: hashTransaction(raw),
  requested: TXID,
  txBytes: raw.length,
  version: tx.version,
  nIn: tx.inputs.length,
  nOut: tx.outputs.length,
  maxUnlocking: Math.max(...unlocking.map((u) => u.length)),
  maxRedeem: Math.max(...redeems.map((r) => r.length)),
  padSum,
  leftoverBytes: FRI_LEFTOVER_BYTES,
  merkle,
  foldKernel0Match: foldHits,
  foldSha256: foldAny ? countOp(foldAny, 0xa8) : 0,
  poseidonLiteral: redeems.some((r) => Buffer.from(r).includes(Buffer.from("poseidon")) || Buffer.from(r).includes(Buffer.from("Poseidon"))),
  worksheet: {
    vkId: w.vkId,
    field: w.field,
    fieldBits: w.fieldBits,
    queryConjectureBits: w.queryConjectureBits,
    minBits: w.minBits,
    note: w.note,
  },
  standardBox: raw.length <= 100_000 && Math.max(...unlocking.map((u) => u.length)) <= 10_000 && Math.max(...redeems.map((r) => r.length)) <= 10_000,
  oneTxNotCHops: tx.inputs.length >= 12 && tx.outputs.length <= 8,
};

console.log(JSON.stringify(report, null, 2));
writeFileSync(OUT, `${JSON.stringify(report, null, 2)}\n`);

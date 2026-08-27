import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { decodeTransaction, hexToBin } from "@bitauth/libauth";

const root = join("survey/artifacts");
const completeness = {
  friVersion: 9,
  uniqueOrbits: 36,
  grind: 20,
  sha256: "sha256",
  worksheetBits: 128,
  dummyPad: false,
};

for (const mark of [400000, 300000, 200000, 150000]) {
  const dir = join(root, `${mark}b`);
  const hex = readFileSync(join(dir, "tx.hex"), "utf8").trim();
  const tx = decodeTransaction(hexToBin(hex));
  if (typeof tx === "string") throw new Error(`${mark}: ${tx}`);
  const inputs = tx.inputs.map((i, n) => ({ i: n, unlocking: i.unlockingBytecode.length }));
  const inputsPath = join(dir, "inputs.json");
  if (!existsSync(inputsPath)) {
    const meta = JSON.parse(readFileSync(join(dir, "meta.json"), "utf8"));
    writeFileSync(inputsPath, `${JSON.stringify({ txBytes: meta.txBytes, inputs }, null, 2)}\n`);
    console.log("wrote", inputsPath, "n=", inputs.length);
  } else {
    console.log("exists", inputsPath);
  }
  const metaPath = join(dir, "meta.json");
  const meta = JSON.parse(readFileSync(metaPath, "utf8"));
  let changed = false;
  if (!meta.completeness) {
    meta.completeness = completeness;
    changed = true;
  }
  if (meta.unlockingSum === undefined) {
    meta.unlockingSum = inputs.reduce((n: number, x: { unlocking: number }) => n + x.unlocking, 0);
    changed = true;
  }
  if (changed) {
    writeFileSync(metaPath, `${JSON.stringify(meta, null, 2)}\n`);
    console.log("patched", metaPath);
  }
}

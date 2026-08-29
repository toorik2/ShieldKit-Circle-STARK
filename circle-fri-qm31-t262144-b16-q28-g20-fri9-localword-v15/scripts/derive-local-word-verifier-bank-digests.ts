import assert from "node:assert/strict";
import { mkdirSync, renameSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  LOCAL_WORD_V15_CONSTRUCTION_ID,
  LOCAL_WORD_V15_CONSTRUCTION_ID_HEX,
} from "../src/backends/circle/local-word-construction-v15.ts";
import {
  LOCAL_WORD_PROOF_LENGTH_OFFSET,
  LOCAL_WORD_PROOF_VERSION,
} from "../src/backends/circle/local-word-sealed-proof.ts";
import { LOCAL_WORD_V15_VERIFIER_KEYS } from
  "../src/backends/circle/local-word-verifier-keys-v15.ts";
import {
  compileLocalWordVerifierBank,
  localWordVerifierBankDigest,
} from "../src/chain/local-word-role-manifest.ts";
import { LOCAL_WORD_V15_VERIFIER_BANK_DIGESTS_HEX } from
  "../src/chain/local-word-verifier-bank-digests-v15.ts";
import { writeU32BE } from "../src/pool/bytes.ts";

/**
 * Rebuild the three persistent verifier banks from the frozen construction.
 * Their digests cannot be construction-manifest inputs: every bank script
 * embeds that manifest's ID, so doing so would create a hash cycle.
 */
const rows = LOCAL_WORD_V15_VERIFIER_KEYS.map((key) => {
  const proofBytes = new Uint8Array(key.maximumProofBytes);
  proofBytes.set(new TextEncoder().encode("SKLW"), 0);
  proofBytes[4] = LOCAL_WORD_PROOF_VERSION;
  proofBytes[5] = key.profile;
  proofBytes.set(writeU32BE(proofBytes.length), LOCAL_WORD_PROOF_LENGTH_OFFSET);
  const bank = compileLocalWordVerifierBank({
    profile: key.profile,
    proofBytes,
    constructionId: LOCAL_WORD_V15_CONSTRUCTION_ID,
    constructionDigest: key.constructionDigest,
    expectedPreprocessedRoot: key.preprocessedRoot,
  });
  return {
    profile: key.profile,
    roles: bank.length,
    maximumProofBytes: key.maximumProofBytes,
    digestHex: Buffer.from(localWordVerifierBankDigest(bank)).toString("hex"),
  };
});

assert.deepEqual(rows.map(({ profile }) => profile), [0, 1, 2]);
assert.equal(new Set(rows.map(({ digestHex }) => digestHex)).size, 3);
if (!process.argv.includes("--derive")) {
  assert.deepEqual(rows.map(({ digestHex }) => digestHex),
    LOCAL_WORD_V15_VERIFIER_BANK_DIGESTS_HEX);
}
const report = {
  version: 1,
  constructionIdHex: LOCAL_WORD_V15_CONSTRUCTION_ID_HEX,
  rows,
};
mkdirSync(resolve(".local"), { recursive: true });
const path = resolve(".local/local-word-verifier-bank-digests-v15.json");
const temporary = `${path}.tmp`;
writeFileSync(temporary, `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600 });
renameSync(temporary, path);
console.log("local-word-verifier-bank-digests", JSON.stringify({ path, ...report }));

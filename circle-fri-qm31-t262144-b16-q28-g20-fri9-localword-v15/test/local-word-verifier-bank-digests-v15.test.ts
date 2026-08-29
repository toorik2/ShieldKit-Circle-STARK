import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { LOCAL_WORD_V15_CONSTRUCTION_ID_HEX } from
  "../src/backends/circle/local-word-construction-v15.ts";
import {
  LOCAL_WORD_V15_VERIFIER_BANK_CONSTRUCTION_ID_HEX,
  LOCAL_WORD_V15_VERIFIER_BANK_DIGESTS,
  LOCAL_WORD_V15_VERIFIER_BANK_DIGESTS_HEX,
} from "../src/chain/local-word-verifier-bank-digests-v15.ts";

describe("local-word v15 persistent verifier-bank digests", () => {
  it("pins three distinct profile banks to the frozen construction", () => {
    assert.equal(LOCAL_WORD_V15_VERIFIER_BANK_CONSTRUCTION_ID_HEX,
      LOCAL_WORD_V15_CONSTRUCTION_ID_HEX);
    assert.equal(LOCAL_WORD_V15_VERIFIER_BANK_DIGESTS.length, 3);
    assert.equal(new Set(LOCAL_WORD_V15_VERIFIER_BANK_DIGESTS_HEX).size, 3);
    for (const [index, digest] of LOCAL_WORD_V15_VERIFIER_BANK_DIGESTS.entries()) {
      assert.equal(digest.length, 32);
      assert.equal(Buffer.from(digest).toString("hex"),
        LOCAL_WORD_V15_VERIFIER_BANK_DIGESTS_HEX[index]);
    }
  });
});

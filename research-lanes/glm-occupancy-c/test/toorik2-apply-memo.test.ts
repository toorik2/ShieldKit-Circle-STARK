import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const labRoot = join(here, "..");
const repoRoot = join(labRoot, "..", "..");
const memoPath = join(repoRoot, "Reference", "literature", "notes", "toorik2-apply-list.md");
const statusPath = join(labRoot, "STATUS.md");

function taggedRows(md: string, tag: "apply-now" | "later" | "do-not-copy"): string[] {
  const heading =
    tag === "apply-now" ? "### apply-now" : tag === "later" ? "### later" : "### do-not-copy";
  const start = md.indexOf(heading);
  assert.ok(start >= 0, `memo must contain ${heading}`);
  const rest = md.slice(start + heading.length);
  const next = rest.search(/\n### /);
  const section = next < 0 ? rest : rest.slice(0, next);
  const rows = section
    .split("\n")
    .filter((line) => line.startsWith("|") && !line.includes("---") && !/^\| Idea \|/.test(line));
  return rows;
}

describe("toorik2 apply-list memo vs shipped STATUS envelopes", () => {
  it("memo has Inventory, Papers, Ranked apply-list with public citations", () => {
    const md = readFileSync(memoPath, "utf8");
    assert.match(md, /^## Inventory/m);
    assert.match(md, /^## Papers/m);
    assert.match(md, /^## Ranked apply-list/m);
    assert.match(md, /https:\/\/eprint\.iacr\.org\/2024\/278/);
    assert.match(md, /https:\/\/eprint\.iacr\.org\/2024\/1037/);
    assert.match(md, /https:\/\/vitalik\.eth\.limo\/general\/2024\/07\/23\/circlestarks\.html/);
    assert.match(md, /1b6e6facf6572b83cf0035b99f532a0558414c38/);
    assert.match(md, /https:\/\/github\.com\/toorik2\/ShieldKit-Circle-STARK\/tree\/%40toorik2/);
    const now = taggedRows(md, "apply-now");
    const later = taggedRows(md, "later");
    const never = taggedRows(md, "do-not-copy");
    assert.ok(now.length >= 3, `apply-now rows: ${now.length}`);
    assert.ok(later.length >= 3, `later rows: ${later.length}`);
    assert.ok(never.length >= 5, `do-not-copy rows: ${never.length}`);
    for (const row of [...now, ...later, ...never]) {
      assert.match(row, /src\/circle-fri\/|[0-9a-f]{7}|language-policy|Non-goals|excluded/i, `row must name evidence: ${row}`);
    }
    assert.match(md, /This memo does not implement the list/);
    assert.equal(existsSync(join(labRoot, "src", "circle-fri")), false, "must not copy src/circle-fri into the lab");
    assert.match(md, /74e477951348b4e81e4a27cf0aac802d601e5f99/);
    assert.equal(md.includes("74e477951348b4e81e4a27cf0ac802d601e5f99"), false, "truncated 39-hex 74e4779 URL");
    assert.match(md, /44f1239ef942852e2cc111e7cbe105b2e4a20be2958f980e94082d309e10d02d/);
    assert.match(md, /CRLF checkout, \*\*not\*\* sealed-lane drift/);
    assert.equal(md.includes("f4341a31"), true, "CRLF working-tree hash is named as CRLF, not as a pin");
    const commitShas = [...md.matchAll(/github\.com\/toorik2\/ShieldKit-Circle-STARK\/commit\/([0-9a-f]+)/g)].map(
      (m) => m[1]!,
    );
    for (const sha of commitShas) {
      assert.ok(sha.length === 7 || sha.length === 40, `commit SHA length ${sha.length}: ${sha}`);
    }
  });

  it("STATUS envelopes still forbid Poseidon2-in-lock and Lean HVZK claims", () => {
    const status = readFileSync(statusPath, "utf8");
    assert.match(status, /On-chain Circle STARK verifier\?/);
    assert.match(status, /Statistical ZK openings\?/);
    assert.match(status, /Confidential TX \+ aggregated pool\?/);
    assert.match(status, /not a Lean HVZK theorem/i);
    assert.match(status, /10 KB/);
    assert.match(status, /100 KB/);
    assert.match(status, /1 MB/);
    assert.match(status, /OP_SHA256/);
    assert.match(status, /Poseidon2-M31 is a prover-side InternalHash table entry/);
    assert.match(status, /lock opcode/);
    const md = readFileSync(memoPath, "utf8");
    assert.match(md, /Poseidon2 \/ absorb-in-Q \*\*in the lock\*\*/);
    assert.match(md, /do-not-copy/);
    assert.match(md, /no new JS/);
  });
});

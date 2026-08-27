/** Land N-note envelope-B batch on Chipnet Electrum. Usage: npx tsx scripts/chipnet-land-batch.ts [notes] [scratch] */
import { landBatch } from "../src/chain/land-batch.ts";

const notes = Number(process.argv[2] ?? "5");
const scratch = process.argv[3] ?? ".local/chipnet-batch";
const dry = process.argv.includes("--dry");
const out = await landBatch({
  envelope: "consensus",
  notes,
  scratch,
  dryRun: dry,
});
console.log(JSON.stringify(out, null, 2));
if (!out.ok) process.exitCode = 1;

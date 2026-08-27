/**
 * Land envelope A (100 KB), B (1 MB), and/or C (chained) on Chipnet.
 * Writes a report. Never prints WIF or keys.
 */
import { landChipnetEnvelopes, type LandWhich } from "../src/chain/land-envelopes.ts";
import { CHAINED_HOPS_DEFAULT } from "../src/chain/envelope.ts";

const scratch = process.argv[2];
const only = (process.argv[3] ?? "all") as LandWhich | "both";
if (!scratch) throw new Error("usage: land-chipnet <scratchDir> [all|standard|consensus|chained]");

const which: LandWhich = only === "both" ? "all" : only;
const report = await landChipnetEnvelopes({
  which,
  hops: CHAINED_HOPS_DEFAULT,
  scratch,
});
console.log(JSON.stringify(report, null, 2));

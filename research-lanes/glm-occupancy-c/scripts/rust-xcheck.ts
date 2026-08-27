import { applyDeposit } from "../src/pool/transition.ts";
import { IncrementalMerkle, NullifierSet, type Note } from "../src/pool/notes.ts";
import { emptyState } from "../src/pool/state.ts";
import { rustProve } from "../src/backends/circle/rust-worker.ts";
import { verifyFri } from "../src/backends/circle/fri.ts";

const note: Note = {
  amountSats: 12_345n,
  rho: crypto.getRandomValues(new Uint8Array(32)),
  ownerSecret: crypto.getRandomValues(new Uint8Array(32)),
};
const d = applyDeposit(
  { state: emptyState(crypto.getRandomValues(new Uint8Array(32))), notes: new IncrementalMerkle(), nullifiers: new NullifierSet() },
  note,
);
const proof = rustProve(d.statement);
const v = verifyFri(d.statement, proof);
if (!v.ok) {
  console.error("TS verify rejected rust proof:", v);
  process.exit(1);
}
console.log(JSON.stringify({ ok: true, family: "circle-fri-m31", rustProofQueries: proof.queries.length }));

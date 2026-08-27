import {
  cashAssemblyToBin,
  createTestAuthenticationProgramBch,
  createVirtualMachineBch2026,
} from "@bitauth/libauth";
import { applyDeposit, applyWithdraw } from "../src/pool/transition.ts";
import { IncrementalMerkle, NullifierSet, type Note } from "../src/pool/notes.ts";
import { emptyState } from "../src/pool/state.ts";
import { LAB_PAYOUT_DIGEST } from "../src/chain/payout.ts";
import { encodeFriProof, proveFri, wWithdraw } from "../src/backends/circle/fri.ts";
import {
  AIR_OFF_IDX,
  BE16_UNSIGNED,
  encodeAirPacked,
  bindUniqueFsTableAsm,
  fsQuerySeedAsm,
  uniqueQueryAttemptAsm,
} from "../src/chain/air-cqz.ts";
import { FRI_N } from "../src/backends/circle/params.ts";
import { evaluateBch2026 } from "../src/chain/vm-verifier.ts";
import { pushData } from "../src/chain/covenant-p2s.ts";
import { densityPadUnlocking } from "../src/chain/envelope.ts";

const note: Note = {
  amountSats: 10_000n,
  rho: crypto.getRandomValues(new Uint8Array(32)),
  ownerSecret: crypto.getRandomValues(new Uint8Array(32)),
};
const d = applyDeposit(
  { state: emptyState(crypto.getRandomValues(new Uint8Array(32))), notes: new IncrementalMerkle(), nullifiers: new NullifierSet() },
  note,
);
const w = applyWithdraw(d.machine, note, d.index, LAB_PAYOUT_DIGEST, 3_000n);
const packed = encodeAirPacked(
  w.statement,
  encodeFriProof(proveFri(w.statement, wWithdraw(note, d.index, w.path, w.created))),
);
console.log(
  "packedIdx",
  Array.from({ length: 4 }, (_, s) => (packed[AIR_OFF_IDX + s * 2]! << 8) | packed[AIR_OFF_IDX + s * 2 + 1]!),
);
const slot0 = cashAssemblyToBin(`
OP_DROP
${fsQuerySeedAsm()}
<0x71> OP_CAT
<0x00> OP_CAT
OP_SHA256
<2> OP_SPLIT OP_DROP
${BE16_UNSIGNED}
<${FRI_N}> OP_MOD
OP_SWAP
<${AIR_OFF_IDX}> OP_SPLIT OP_NIP
<2> OP_SPLIT OP_DROP
${BE16_UNSIGNED}
OP_NUMEQUALVERIFY
OP_1
`);
if (typeof slot0 === "string") throw new Error(slot0);
function evalPadded(lock: Uint8Array, inner: Uint8Array) {
  const dummy = new Uint8Array(8000).fill(0x11);
  const suffix = pushData(dummy);
  const unlocking = new Uint8Array(inner.length + suffix.length);
  unlocking.set(inner, 0);
  unlocking.set(suffix, inner.length);
  const drop = cashAssemblyToBin("OP_DROP");
  if (typeof drop === "string") throw new Error(drop);
  const locking = new Uint8Array(drop.length + lock.length);
  locking.set(drop, 0);
  locking.set(lock, drop.length);
  return evaluateBch2026(locking, unlocking);
}
const bindLock = cashAssemblyToBin(`${bindUniqueFsTableAsm()}\nOP_DROP\nOP_1`);
if (typeof bindLock === "string") throw new Error(bindLock);
const evb = evalPadded(bindLock, pushData(packed));
console.log("bindUniqueFsTable", evb.accepted, evb.error);

const collect = `
OP_DROP
${fsQuerySeedAsm()}
OP_0
OP_0
OP_BEGIN
  ${uniqueQueryAttemptAsm()}
  OP_SIZE
  <72>
  OP_GREATERTHANOREQUAL
OP_UNTIL
OP_NIP
OP_NIP
OP_1
`;
const collectLock = cashAssemblyToBin(collect);
if (typeof collectLock === "string") throw new Error(collectLock);
const vm = createVirtualMachineBch2026(false);
const program = createTestAuthenticationProgramBch({
  lockingBytecode: collectLock,
  unlockingBytecode: densityPadUnlocking(pushData(packed), 8000),
  valueSatoshis: 1000n,
});
const state = vm.evaluate(program);
console.log("collect", vm.stateSuccess(state), (state as { error?: string }).error);
const stack = (state as { stack?: Uint8Array[] }).stack ?? [];
console.log("stackn", stack.length);
for (const item of stack) {
  const hex = Buffer.from(item).toString("hex");
  console.log("item", item.length, hex.slice(0, 160));
}

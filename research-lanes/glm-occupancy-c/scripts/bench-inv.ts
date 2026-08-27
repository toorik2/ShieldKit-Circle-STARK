import { cashAssemblyToBin, createVirtualMachineBch2026 } from "@bitauth/libauth";
import { M31_INV } from "../src/chain/m31-asm.ts";
import { applyDeposit } from "../src/pool/transition.ts";
import { IncrementalMerkle, NullifierSet, type Note } from "../src/pool/notes.ts";
import { emptyState } from "../src/pool/state.ts";
import { encodeFriProof, proveFri, wDeposit } from "../src/backends/circle/fri.ts";
import { encodeAirPacked } from "../src/chain/air-cqz.ts";
import { compileFoldLockP2sh32, foldKernelUnlocking, foldQueryShardInput } from "../src/chain/fold-kernel.ts";
import { compileFriQueryLockP2sh32 } from "../src/chain/fri-kernel.ts";
import { friShardUnlockings } from "../src/chain/fri-openings.ts";
import { pushData } from "../src/chain/covenant-p2s.ts";

function num(v: unknown): number {
  if (typeof v === "number") return v;
  if (typeof v === "bigint") return Number(v);
  return 0;
}

function run(lock: Uint8Array, unlock: Uint8Array) {
  const vm = createVirtualMachineBch2026(true);
  const program = {
    inputIndex: 0,
    sourceOutputs: [{ lockingBytecode: lock, valueSatoshis: 1000n }],
    transaction: {
      version: 2,
      locktime: 0,
      inputs: [{
        outpointTransactionHash: new Uint8Array(32).fill(0x11),
        outpointIndex: 0,
        sequenceNumber: 0xffffffff,
        unlockingBytecode: unlock,
      }],
      outputs: [{ lockingBytecode: lock, valueSatoshis: 1000n }],
    },
  };
  const state = vm.evaluate(program as never);
  const ok = vm.stateSuccess(state);
  const m = (state as { metrics?: Record<string, number | bigint> }).metrics ?? {};
  return {
    accepted: ok === true,
    error: ok === true ? null : String(ok).slice(0, 120),
    op: num(m.operationCost),
    opMax: num(m.maximumOperationCost),
    unlocking: unlock.length,
  };
}

function invLock(n: number): Uint8Array {
  const body = cashAssemblyToBin(M31_INV);
  if (typeof body === "string") throw new Error(body);
  const hex = Buffer.from(body).toString("hex");
  const loop = Array.from({ length: n }, () => "OP_DUP\n<0> OP_INVOKE\nOP_DROP").join("\n");
  const asm = `<0x${hex}>\n<0> OP_DEFINE\n${loop}\nOP_DROP\nOP_1`;
  const bin = cashAssemblyToBin(asm);
  if (typeof bin === "string") throw new Error(bin);
  return bin;
}

const unlock7 = Uint8Array.of(0x57); // OP_7
const inv1 = run(invLock(1), unlock7);
const inv7 = run(invLock(7), unlock7);
const inv28 = run(invLock(28), unlock7);

const note: Note = {
  amountSats: 8_000n,
  rho: crypto.getRandomValues(new Uint8Array(32)),
  ownerSecret: crypto.getRandomValues(new Uint8Array(32)),
};
const d = applyDeposit(
  { state: emptyState(crypto.getRandomValues(new Uint8Array(32))), notes: new IncrementalMerkle(), nullifiers: new NullifierSet() },
  note,
);
const proof = encodeFriProof(proveFri(d.statement, wDeposit(note, d.index, d.path)));
const packed = encodeAirPacked(d.statement, proof);

function foldMeter(nFold: number) {
  const lastShard = Math.max(...Array.from({ length: nFold }, (_, q) => foldQueryShardInput(q)));
  const allShards = friShardUnlockings(proof, { allPairGroups: true });
  const shards = allShards.slice(0, lastShard);
  const foldLock = compileFoldLockP2sh32(nFold, 0);
  const foldUnlock = foldKernelUnlocking(nFold, 0, nFold > 1 ? packed : undefined);
  const friLock = compileFriQueryLockP2sh32();
  const carrierLock = Uint8Array.of(0x75, 0x51);
  const vm = createVirtualMachineBch2026(true);
  const sourceOutputs = [
    { lockingBytecode: carrierLock, valueSatoshis: 1000n },
    ...shards.map(() => ({ lockingBytecode: friLock, valueSatoshis: 1000n })),
    { lockingBytecode: foldLock, valueSatoshis: 1000n },
  ];
  const transaction = {
    version: 2,
    locktime: 0,
    inputs: [
      {
        outpointTransactionHash: new Uint8Array(32).fill(0x22),
        outpointIndex: 0,
        sequenceNumber: 0xffffffff,
        unlockingBytecode: pushData(packed),
      },
      ...shards.map((unlocking, i) => ({
        outpointTransactionHash: new Uint8Array(32).fill(0x44 + i),
        outpointIndex: 0,
        sequenceNumber: 0xffffffff,
        unlockingBytecode: unlocking,
      })),
      {
        outpointTransactionHash: new Uint8Array(32).fill(0x87),
        outpointIndex: 0,
        sequenceNumber: 0xffffffff,
        unlockingBytecode: foldUnlock,
      },
    ],
    outputs: [{ lockingBytecode: carrierLock, valueSatoshis: 1000n }],
  };
  const state = vm.evaluate({
    inputIndex: sourceOutputs.length - 1,
    sourceOutputs,
    transaction,
  } as never);
  const ok = vm.stateSuccess(state);
  const m = (state as { metrics?: Record<string, number | bigint> }).metrics ?? {};
  return {
    nFold,
    accepted: ok === true,
    error: ok === true ? null : String(ok).slice(0, 160),
    op: num(m.operationCost),
    opMax: num(m.maximumOperationCost),
    unlocking: foldUnlock.length,
    opPct: num(m.maximumOperationCost) ? +(100 * num(m.operationCost) / num(m.maximumOperationCost)).toFixed(1) : 0,
  };
}

console.log(JSON.stringify({
  inv1, inv7, inv28,
  perInv: (inv28.op - inv1.op) / 27,
  fold: [1, 2, 4].map(foldMeter),
}, null, 2));

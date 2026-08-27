import { createVirtualMachineBch2026 } from "@bitauth/libauth";
import { applyDeposit, applyWithdraw } from "../src/pool/transition.ts";
import { IncrementalMerkle, NullifierSet, type Note } from "../src/pool/notes.ts";
import { emptyState } from "../src/pool/state.ts";
import { encodeFriProof, proveFri, wWithdraw } from "../src/backends/circle/fri.ts";
import { LAB_PAYOUT_DIGEST } from "../src/chain/payout.ts";
import { evaluateFoldKernelOnly } from "../src/chain/vm-verifier.ts";
import { cashAssemblyToBin } from "@bitauth/libauth";
import { foldDefinesAsm, foldQueriesAsm } from "../src/chain/fold-asm.ts";
import { foldKernelUnlocking, compileFoldKernel, compileFoldLockP2sh32, foldKernelAsm } from "../src/chain/fold-kernel.ts";
import { encodeAirPacked } from "../src/chain/air-cqz.ts";
import { packedWithPairs, queryPairShard } from "../src/chain/fri-openings.ts";
import { pushData } from "../src/chain/covenant-p2s.ts";

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
const proof = encodeFriProof(proveFri(w.statement, wWithdraw(note, d.index, w.path, w.created)));
const packed = encodeAirPacked(w.statement, proof);
{
  const asm = foldKernelAsm(6);
  const bin = (s: string) => {
    const b = cashAssemblyToBin(s);
    if (typeof b === "string") throw new Error(b);
    return b.length;
  };
  console.log(JSON.stringify({
    asmBytes: compileFoldKernel(6, 0).length,
    defines: bin(foldDefinesAsm()),
    queries6: bin(foldQueriesAsm(6, 0)),
    queries1: bin(foldQueriesAsm(1, 0)),
    sha256: (asm.match(/OP_SHA256/g) ?? []).length,
    lambdaTag: (asm.match(/6c616d626461/g) ?? []).length,
    invoke3: (asm.match(/<3> OP_INVOKE/g) ?? []).length,
  }));
}

for (const n of [4, 5, 6]) {
  const ev = evaluateFoldKernelOnly({ statement: w.statement, proof, nFold: n, queryIndex: 0 });
  console.log(JSON.stringify({
    n,
    accepted: ev.accepted,
    unlocking: ev.unlockingBytes,
    redeem: compileFoldKernel(n, 0).length,
    packedUnlock: foldKernelUnlocking(n, 0, packed).length,
    error: ev.error?.slice(0, 280) ?? null,
  }));
}

{
  const nFold = 6;
  const vm = createVirtualMachineBch2026(true);
  const carrier = packedWithPairs(packed, proof);
  const foldLock = compileFoldLockP2sh32(nFold, 0);
  const foldUnlock = foldKernelUnlocking(nFold, 0, packed, queryPairShard(proof, 0, nFold));
  const carrierLock = Uint8Array.of(0x75, 0x51);
  const sourceOutputs = [
    { lockingBytecode: carrierLock, valueSatoshis: 1000n },
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
        unlockingBytecode: pushData(carrier),
      },
      {
        outpointTransactionHash: new Uint8Array(32).fill(0x87),
        outpointIndex: 0,
        sequenceNumber: 0xffffffff,
        unlockingBytecode: foldUnlock,
      },
    ],
    outputs: [{ lockingBytecode: carrierLock, valueSatoshis: 1000n }],
  };
  const state = vm.evaluate({ inputIndex: 1, sourceOutputs, transaction } as never) as {
    metrics?: Record<string, number | bigint>;
  };
  const m = state.metrics ?? {};
  const num = (x: number | bigint | undefined) => (x === undefined ? 0 : Number(x));
  console.log(JSON.stringify({
    meters: Object.fromEntries(Object.entries(m).map(([k, v]) => [k, typeof v === "bigint" ? Number(v) : v])),
    slack: num(m.maximumOperationCost) - num(m.operationCost),
    ok: String(vm.stateSuccess(state)).slice(0, 220),
  }));
}

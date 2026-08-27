import { createVirtualMachineBch2026 } from "@bitauth/libauth";
import { applyDeposit } from "../src/pool/transition.ts";
import { IncrementalMerkle, NullifierSet, type Note } from "../src/pool/notes.ts";
import { emptyState } from "../src/pool/state.ts";
import { encodeFriProof, proveFri, wDeposit } from "../src/backends/circle/fri.ts";
import { collectFriOpenings, openingPairsBlob } from "../src/chain/fri-openings.ts";
import { buildLayerProofs, encodeLayerUnlocking } from "../src/chain/merkle-multiproof.ts";
import { compileFriQueryKernel, compileFriQueryLockP2sh32 } from "../src/chain/fri-kernel.ts";
import { encodeAirPacked } from "../src/chain/air-cqz.ts";
import { pushData } from "../src/chain/covenant-p2s.ts";

const note: Note = {
  amountSats: 8_000n,
  rho: crypto.getRandomValues(new Uint8Array(32)),
  ownerSecret: crypto.getRandomValues(new Uint8Array(32)),
};
const d = applyDeposit(
  { state: emptyState(crypto.getRandomValues(new Uint8Array(32))), notes: new IncrementalMerkle(), nullifiers: new NullifierSet() },
  note,
);
const proved = proveFri(d.statement, wDeposit(note, d.index, d.path));
const proof = encodeFriProof(proved);
const packed = encodeAirPacked(d.statement, proof);
const openings = collectFriOpenings(proved);
const pairs = openingPairsBlob(openings);
const layer = buildLayerProofs(openings)[0]!;
const one = process.argv.includes("--one");
const used = one ? { ...layer, openings: layer.openings.slice(0, 1) } : layer;
const unlocking = encodeLayerUnlocking(used, compileFriQueryKernel(0));
const carrier = packed;

const vm = createVirtualMachineBch2026(true);
const carrierLock = Uint8Array.of(0x75, 0x51);
const lock = compileFriQueryLockP2sh32(0);
const result = vm.verify({
  sourceOutputs: [
    { lockingBytecode: carrierLock, valueSatoshis: 1000n },
    { lockingBytecode: lock, valueSatoshis: 1000n },
  ],
  transaction: {
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
        outpointTransactionHash: new Uint8Array(32).fill(0x44),
        outpointIndex: 0,
        sequenceNumber: 0xffffffff,
        unlockingBytecode: unlocking,
      },
    ],
    outputs: [{ lockingBytecode: carrierLock, valueSatoshis: 1000n }],
  },
});
console.log(result === true ? "ok" : String(result).slice(0, 300));
console.log({ unlocking: unlocking.length, openings: used.openings.length, redeem: compileFriQueryKernel(0).length });

import { createVirtualMachineBch2026 } from "@bitauth/libauth";
import { applyDeposit } from "../src/pool/transition.ts";
import { IncrementalMerkle, NullifierSet, type Note } from "../src/pool/notes.ts";
import { emptyState } from "../src/pool/state.ts";
import { encodeFriProof, proveFri, wDeposit } from "../src/backends/circle/fri.ts";
import { packedWithPairs, friShardUnlockings } from "../src/chain/fri-openings.ts";
import { encodeAirPacked } from "../src/chain/air-cqz.ts";
import { compileFriQueryLockP2sh32 } from "../src/chain/fri-kernel.ts";
import { pushData } from "../src/chain/covenant-p2s.ts";

const note: Note = {
  amountSats: 8000n,
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
const carrier = packedWithPairs(packed, proof);
const shards = friShardUnlockings(proof);
console.log({ shards: shards.length, sizes: shards.map((s) => s.length), carrier: carrier.length });
const vm = createVirtualMachineBch2026(true);
for (let i = 0; i < shards.length; i += 1) {
  const r = vm.verify({
    sourceOutputs: [
      { lockingBytecode: Uint8Array.of(0x75, 0x51), valueSatoshis: 1000n },
      { lockingBytecode: compileFriQueryLockP2sh32(i), valueSatoshis: 1000n },
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
          unlockingBytecode: shards[i]!,
        },
      ],
      outputs: [{ lockingBytecode: Uint8Array.of(0x75, 0x51), valueSatoshis: 1000n }],
    },
  });
  console.log("layer", i, r === true ? "ok" : String(r).slice(0, 240));
}

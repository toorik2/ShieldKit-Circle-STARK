/** Compare linear-scan bind-T vs 512-byte orbit-flag bind-T. Does not ship the flag kernel. */
import { createVirtualMachineBch2026, encodeLockingBytecodeP2sh32, hash256 } from "@bitauth/libauth";
import { applyDeposit, applyWithdraw } from "../src/pool/transition.ts";
import { IncrementalMerkle, NullifierSet, type Note } from "../src/pool/notes.ts";
import { emptyState } from "../src/pool/state.ts";
import { encodeFriProof, proveFri, wWithdraw } from "../src/backends/circle/fri.ts";
import { LAB_PAYOUT_DIGEST } from "../src/chain/payout.ts";
import {
  AIR_PACKED_SIZE,
  bindUniqueFsTableAsm,
  bindUniqueFsTableFlagAsm,
  compileCqzBind,
  compileCqzKernel,
  CQZ_BIND_TAIL,
  encodeAirPacked,
} from "../src/chain/air-cqz.ts";
import { packedWithPairs } from "../src/chain/fri-openings.ts";

function num(x: number | bigint | undefined): number {
  if (x === undefined) return 0;
  return typeof x === "bigint" ? Number(x) : x;
}

function pushRedeem(data: Uint8Array): Uint8Array {
  if (data.length <= 75) return Uint8Array.of(data.length, ...data);
  if (data.length <= 255) return Uint8Array.of(0x4c, data.length, ...data);
  return Uint8Array.of(0x4d, data.length & 0xff, (data.length >> 8) & 0xff, ...data);
}

function cqzUnlock(redeem: Uint8Array, packed: Uint8Array): Uint8Array {
  const head = packed.subarray(0, AIR_PACKED_SIZE);
  const tail = packed.subarray(AIR_PACKED_SIZE, AIR_PACKED_SIZE + CQZ_BIND_TAIL);
  const body = new Uint8Array(head.length + tail.length);
  body.set(head, 0);
  body.set(tail, head.length);
  const push = Uint8Array.of(0x4d, body.length & 0xff, (body.length >> 8) & 0xff, ...body);
  const r = pushRedeem(redeem);
  const out = new Uint8Array(push.length + r.length);
  out.set(push, 0);
  out.set(r, push.length);
  return out;
}

function evalCqz(redeem: Uint8Array, carrier: Uint8Array) {
  const vm = createVirtualMachineBch2026(true);
  const lock = encodeLockingBytecodeP2sh32(hash256(redeem));
  const carrierLock = Uint8Array.of(0x75, 0x51);
  const unlocking = cqzUnlock(redeem, carrier);
  const sourceOutputs = [
    { lockingBytecode: carrierLock, valueSatoshis: 1000n },
    { lockingBytecode: lock, valueSatoshis: 1000n },
  ];
  const transaction = {
    version: 2,
    locktime: 0,
    inputs: [
      {
        outpointTransactionHash: new Uint8Array(32).fill(0x22),
        outpointIndex: 0,
        sequenceNumber: 0xffffffff,
        unlockingBytecode: Uint8Array.of(0x4d, carrier.length & 0xff, (carrier.length >> 8) & 0xff, ...carrier),
      },
      {
        outpointTransactionHash: new Uint8Array(32).fill(0xa0),
        outpointIndex: 0,
        sequenceNumber: 0xffffffff,
        unlockingBytecode: unlocking,
      },
    ],
    outputs: [{ lockingBytecode: carrierLock, valueSatoshis: 1000n }],
  };
  const st = vm.evaluate({ inputIndex: 1, sourceOutputs, transaction } as never);
  const ok = vm.stateSuccess(st);
  const m = (st as { metrics?: Record<string, number | bigint> }).metrics ?? {};
  const op = num(m.operationCost);
  const opMax = num(m.maximumOperationCost);
  return {
    accepted: ok === true,
    error: ok === true ? null : String(ok).slice(0, 220),
    redeem: redeem.length,
    unlocking: unlocking.length,
    op,
    opMax,
    slack: opMax - op,
    opPct: opMax ? +(100 * op / opMax).toFixed(3) : 0,
    hash: num(m.hashDigestIterations),
  };
}

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
const proved = proveFri(w.statement, wWithdraw(note, d.index, w.path, w.created));
const proof = encodeFriProof(proved);
const packed = encodeAirPacked(w.statement, proof);
const carrier = packedWithPairs(packed, proof);
const linear = compileCqzKernel();
const flags = compileCqzBind(bindUniqueFsTableFlagAsm());
console.log(JSON.stringify({
  linear: evalCqz(linear, carrier),
  flags: evalCqz(flags, carrier),
  sameBind: bindUniqueFsTableAsm() === bindUniqueFsTableFlagAsm(),
}, null, 2));

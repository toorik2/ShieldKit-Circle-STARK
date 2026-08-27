import { compileCqzKernel, cqzKernelUnlocking, slotsKernelUnlocking, SLOTS_PER_KERNEL } from "../src/chain/air-cqz.ts";
import { foldKernelUnlocking, compileFoldKernel } from "../src/chain/fold-kernel.ts";
import { grindKernelUnlocking } from "../src/chain/grind-kernel.ts";
import { algebraicCKernelUnlocking } from "../src/chain/algebraic-c-kernel.ts";

const t = Date.now();
const cqz = compileCqzKernel();
console.log(JSON.stringify({
  cqzRedeem: cqz.length,
  cqzUnlock: cqzKernelUnlocking().length,
  fold0: foldKernelUnlocking(1, 0).length,
  fold35: foldKernelUnlocking(1, 35).length,
  fold0Redeem: compileFoldKernel(1, 0).length,
  slot0: slotsKernelUnlocking(0, SLOTS_PER_KERNEL).length,
  slot35: slotsKernelUnlocking(33, SLOTS_PER_KERNEL).length,
  grind: grindKernelUnlocking().length,
  algebraicC: algebraicCKernelUnlocking().length,
  ms: Date.now() - t,
}));

# Next (this ruleset)

A wall is a number, then the next construction.

Starting artifact: the `e0b0de3` lock state — fused N = leftover L0 C(z) + 36 leftover-z `C_SHA` evals (144 B, grind-bound `hashBitRoot`). Honest accepts; mixed occupancy leftover + occupancy packed VM-rejects fused input 12. **100 kB still off.** That is evidence. It is not B under RULES.md.

## First construction that can change the score

Close gates 1–6 on the fused-N lock, then pack **this** lock under 100 kB:

1. Lock N is leftover C(z) at leftover z — a stranger reading the redeem sees occupancy+SHA leftover FRI and fused `(q−R)·Z==C(z)`.
2. Mixed rejects on that equation (input 12, JS-fail **and** VM-reject).
3. Occupancy-only leftover + occupancy packed cannot skip SHA (independent 144 B `C_SHA` in N).
4. Missing TRACE fail-closed (N ≠ leftover vs a real statement).
5. Joint recook of packed interpolant AND leftover-z openings cannot skip SHA.
6. Silent: every unlocking — no rho/owner/amount8; leftover pair-bind L0–L6 still runs; unlocking/redeem ≤ 10_000.

The suite that asserts 1–6 must pass before sub-100 kB packing resumes. Then: honest 18-input `createVirtualMachineBch2026(true)`, Electrum, padSum 0. Re-land only when lock/C actually changed vs the evidence ledger.

Measure: tx bytes, per-input density, leftover width, packed AIR. Mixed proveFromTLde (victim leaf + attacker nf + garbage amountCommit) must JS-fail and VM-reject **on the SHA relation**.

Do not start by packing more Merkle, shrinking A, or dropping queries/grind/TRACE to fit. Do not golf 73 B or `5_256_000`. Do not dummy pad / `KERNEL_UNLOCK_PAD` / leftover-fill / identity SWAP-NOP.

## Not a win

First new byte-count wall. Green tests on a weaker statement. Relabeling `e0b0de3`, `5de68272…`, `60d186de…`, the 91 KB freeze, or the 1 MB fork as this B. `standard=false`. 36 extra SHA-AIR inputs. “The lane cannot.”

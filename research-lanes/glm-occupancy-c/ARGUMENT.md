# Argument = vk (this family — none yet)

```
vk = (none)
rulesSha256 = 4962183ee111b488b0cf9d872c5a057817f5f081d4ec4cacba486b29442fa061
```

Occupancy sibling vk `circle-fri-m31-qm31-t64-b16-q36-g20-fri10-de1f4dcf0b16d9f8cec265719673a108e2ac4703059fd9d1998d09fcd121de22` is **evidence**, not this vk. Pack: [`survey/artifacts/qm31-fri10/`](survey/artifacts/qm31-fri10/).

This family: SHA residuals in occupancy composition C, same 36 queries, standard Electrum box. HASH_BIT leftover merkle/prefix (`5de68272…` / 99144 B) is not the relation. 36 extra SHA-AIR inputs (**94788 B**) are not this geometry.

§6 in flight (not the named end). The copied start is the `e0b0de3` fused-N lock: `(q−R)·Z == N` with N = leftover L0 C(z) + 36 leftover-z `C_SHA` evals (144 B, grind-bound `hashBitRoot`). Do not say shielded.

Occupancy: **B = M31** (circle, Merkle, qTable, layer-0 pairs, inverses, AIR cells). **F_fri = QM31** (7 λ, post-fold layers 1–6, final). **H = SHA-256**. qTable / layer-0 are 4-byte.

## Soundness worksheet

| knob | value | status |
|---|---|---|
| Field | QM31 \(\log_2 p^4 \approx 124\) | written |
| Query conjecture | \(36 \times 3 + 20 = 128\) at rate \(2/B\) | **speculative**, named; not Stwo-128 |
| SZ | TRACE 64 over QM31 | not tens of bits |
| Hash-RO | SHA-256 | |
| min | \(\min(128, 124, \ldots) \approx 124 \ge 100\) | floor |

n=32/q=8 is refused. d5 is not the fold alphabet.

## Parent freeze (evidence, different family)

`survey/artifacts/argument-freeze/`, vk `circle-fri-m31-t64-b16-q36-g20-fri9`, Chipnet `58b7df7f…` 91598 B. M31 challenges. Not this product.

## Checks the miner must run (this family)

Numbered lock checks of the 18-input fused fold+R skeleton plus QM31 λ mix and QM31 post-fold pairs. Merkle leftover-binds layers 0–6. Occupancy composition C includes SHA residuals of leaf↔nf↔amount. Same 36 queries. `verifyFri` is a lab oracle. Mixed publics (victim leaf + attacker nf + garbage amountCommit) with a recooked occupancy proof: JS-fail and VM-reject **on the SHA relation** (fused input 12 at the fork), not on sticker-matching.

Stwo KATs: CM31 `(1+2i)(4+5i)=(p−6)+13i`; QM31 `(1,2,3,4)*(4,5,6,7)=(p−71,93,p−16,50)`; inverses.

Leftover is layer-major `[L6]…[L1][L0]` (7200 B) on the start. No dummy pad / leftover-fill / packTo / KERNEL_UNLOCK_PAD. TRACE 64, q 36, grind 20, blowup 16.

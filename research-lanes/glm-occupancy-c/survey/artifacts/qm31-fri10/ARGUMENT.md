# Argument = vk (QM31 SecureField family)

```
vk = circle-fri-m31-qm31-t64-b16-q36-g20-fri10-de1f4dcf0b16d9f8cec265719673a108e2ac4703059fd9d1998d09fcd121de22
rulesSha256 = de1f4dcf0b16d9f8cec265719673a108e2ac4703059fd9d1998d09fcd121de22
```

Pack: [`survey/artifacts/qm31-fri10/`](survey/artifacts/qm31-fri10/). Chipnet Electrum successor `60d186ded18897a50d0a4205ed446ab02339a53eb6d8f4a7043b4e405796edc4` (99043 B). Not parent freeze `58b7df7f…`. Not the named end: RULES §6 / §7 are not this object.

Occupancy: **B = M31** (circle, Merkle, qTable, layer-0 pairs, inverses, AIR cells). **F_fri = QM31** (7 λ, post-fold layers 1–6, final). **H = SHA-256**. qTable / layer-0 are 4-byte. This vk does **not** claim RULES §6 shielded unlocking or §7 walk-in batch.

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

## Checks the miner must run

Numbered lock checks of the 18-input fused fold+R skeleton plus QM31 λ mix and QM31 post-fold pairs. Merkle leftover-binds layers 0–6; fold `EQUALVERIFY`s its pair shard against that leftover. `verifyFri` is a lab oracle. Mutated λ or post-fold pair: JS-fail and VM-reject (P0).

Stwo KATs: CM31 `(1+2i)(4+5i)=(p−6)+13i`; QM31 `(1,2,3,4)*(4,5,6,7)=(p−71,93,p−16,50)`; inverses.

Leftover is layer-major `[L6]…[L1][L0]` (7200 B). Merkle leftover-binds layers 0–6; fold `EQUALVERIFY`s its query-major pairShard against that leftover. Compact-path PICK bounded. No dummy pad / leftover-fill / packTo / KERNEL_UNLOCK_PAD. TRACE 64, q 36, grind 20, blowup 16.

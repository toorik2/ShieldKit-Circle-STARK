# circle-fri-m31-qm31-t64-b16-q36-g20-fri10-de1f4dcf0b16d9f8cec265719673a108e2ac4703059fd9d1998d09fcd121de22

Lab compile **99175 B**. Chipnet Electrum land **99043 B** `60d186ded18897a50d0a4205ed446ab02339a53eb6d8f4a7043b4e405796edc4`.

FRI10, q=36, grind 20, TRACE 64, blowup 16, hash sha256.
Occupancy: B = M31 (qTable / layer-0 4-byte), F_fri = QM31 (~124 bits), H = SHA-256.
Query worksheet 128 (speculative, rate 2/B). Field 124. min ≈ 124.

Encoding: leftover **bound** (7200 B, layers 0–6); fold EQUALVERIFYs pairShard against Merkle leftover; compact-path PICK bounded. padSum 0. Not leftover-fill. Not the parent freeze (leftover-pairs empty, FRI9, M31).

This directory is self-contained: `tx.hex` (lab rebuild), `chipnet-successor.hex` (mined object), `proof.bin`, `ARGUMENT.md` (the vk), `RULES.md` (vk includes its SHA-256), `vk.txt`, `meta.json`, `inputs.json`, `meters.json`.

Chipnet: https://chipnet.imaginary.cash/tx/60d186ded18897a50d0a4205ed446ab02339a53eb6d8f4a7043b4e405796edc4

standard=true: true (ok)
verifyFri: {"ok":true}
leftoverBound: true
pickBounded: true
foldVkPinsRulesSha: true

**Not the named end.** RULES §6 (rho/owner/amount not in unlocking) and §7 (walk-in N-note batch) are not this object. Only the human declares that end.

Recompile/verify from the lane (needs the rest of the tree to *rebuild*; the pack itself is the saved instance):

```bash
cd research-lanes/ideal-bch-shielded-pool-stark
npx tsx --test test/qm31-artifact.test.ts test/qm31-occupancy.test.ts
npx tsx scripts/save-qm31-artifact.ts
```

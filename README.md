# Circle FRI on Bitcoin Cash

A Circle-domain FRI verifier in May-2026 CashVM. One family, one standard transaction: ≤ 100 000 B, unlocking and redeem ≤ 10 000 B, `createVirtualMachineBch2026(true)`, Electrum. The miner runs the numbered checks; `verifyFri` is a lab oracle.

```
vk = circle-fri-m31-qm31-t64-b16-q36-g20-fri10-de1f4dcf0b16d9f8cec265719673a108e2ac4703059fd9d1998d09fcd121de22
```

`RULES.md` is hashed into that string. Change a rule, it is a different family.

**Occupancy.** Circle, Merkle, qTable, and layer-0 stay **M31** (4-byte). Fiat–Shamir λ, post-fold layers 1–6, and the final polynomial are **QM31** (~124 bits). Hash is **SHA-256** (`OP_SHA256`). TRACE 64, blowup 16, 36 unique first-fold orbits, grind 20, FRI version 10. The FRI’d polynomial is the algebraicC residual interpolant: honest \(C = 0\), slot check \((qTable - R)\cdot Z = C(z)\).

**On chain.** 18-input fused fold+R skeleton. Merkle leftover-binds layers 0–6; each fold `EQUALVERIFY`s its pair shard against that leftover. No dummy pad.

Chipnet Electrum [`60d186de…`](https://chipnet.imaginary.cash/tx/60d186ded18897a50d0a4205ed446ab02339a53eb6d8f4a7043b4e405796edc4) · 99 043 B · 18 in / 2 out · padSum 0.

Field floor is QM31 (~124). Query worksheet \(36\times 3 + 20 = 128\) at rate \(2/B\) is ethSTARK-style speculative, not Stwo-128. Shielded unlocking and walk-in batch are not this object. Chipnet only.

Tree: [`BCH-Circle-Stark-qm31-fri10/`](BCH-Circle-Stark-qm31-fri10/).

Made by [ABL](https://github.com/CyberAshven) ([`@ABLalgorithm`](https://github.com/toorik2/ShieldKit-Circle-STARK/tree/@ABLalgorithm)) and [toorik](https://github.com/toorik2).

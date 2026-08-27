# Tracks (they do not share a bottleneck)

**Order:** SHA residuals in occupancy C first.

## Track 0 — SHA in occupancy C (now)

**Question:** can leaf↔nf↔amount live in occupancy composition C at the same 36 queries, inside one standard Electrum tx, without 36 extra SHA-AIR inputs?

Known start (not closed): the `e0b0de3` fused-N lock — N = leftover L0 C(z) + 144 B leftover-z `C_SHA`; mixed VM-rejects fused input 12; gates 1–6 not yet all asserted; 100 kB off. Older evidence: HASH_BIT host `5de68272…`; extra-input meter 94788 B.

Scoreboard: `test/note-auth-air.test.ts`, `test/onchain-privacy.test.ts`, `test/shielded-unlocking-b.test.ts`, `START.md`.

## Track 1 — walked leaf not in unlocking (later, not a §6 fail)

**Question:** once SHA-in-C holds, can membership stay inside the STARK so spend unlocking does not publish the leaf? A one-note test tx walking its leaf is fine.

Not a lever: extra-input SHA AIR.

## How they run

| | Track 0 | Track 1 |
|---|---|---|
| Edit | occupancy C, SHA AIR residuals, leftover spend/replace | membership hiding |
| Do not edit for the other track | membership hiding | occupancy C |
| Shared | FRI10 pins, packed AIR, PAA1, RULES §1–8 |
| Merge | only at a candidate that already has a 100 kB SHA-in-C story **or** an honest wall |

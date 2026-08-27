# Argument-freeze B (standard-size verifier)

Lab compile **92357 B**. Chipnet Electrum land **91598 B** `58b7df7f59c3b85a5c8357b0b4c10ab12c74dac984f7a8e95832ab6965c3b03a`.

vk `circle-fri-m31-t64-b16-q36-g20-fri9`. FRI9, q=36, grind 20, hash sha256, worksheet 128 (query conjecture; M31 field gap in ARGUMENT.md).

Encoding: leftover pair groups size 0; compact-path PICK bounded (`k ≥ 0` and `k < DEPTH`). This pack is that walker. Not `56be9ac0…` (skip-N). Not `86d5413f…` (unbounded PICK).

This directory is self-contained: `tx.hex`, `proof.bin`, `ARGUMENT.md` (the vk), `meta.json`, `inputs.json`, `meters.json` (VM `operationCost` / `hashDigestIterations`, `standard=true`).

Chipnet: https://chipnet.imaginary.cash/tx/58b7df7f59c3b85a5c8357b0b4c10ab12c74dac984f7a8e95832ab6965c3b03a

standard=true: true (ok)
verifyFri: {"ok":true}
leftoverPairsEmpty: true
pickBounded: true

Recompile/verify from the lane (needs the rest of the tree to *rebuild*; the pack itself is the saved instance):

```bash
cd research-lanes/envelope-b-standard
npx tsx --test --test-name-pattern 'full-completeness B successor|correspondence oracle' test/hole-free-b.test.ts test/correspondence-oracle.test.ts
npx tsx scripts/save-freeze-artifact.ts
```

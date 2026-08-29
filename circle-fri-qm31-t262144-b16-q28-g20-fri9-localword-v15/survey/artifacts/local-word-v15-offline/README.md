# Local-word v15 offline qualification artifact

This is the exact offline-qualified candidate for construction
`8d583c84312f7c79519b65bf374dc2ffb6597544a504d88a587c578f9bed2133`.
It is not a mined transaction and not the human-declared named end.

## Exact artifact

| Item | Exact result |
|---|---:|
| proof | 327,674 bytes |
| proof SHA-256 | `a786071c0839e5dbcaf235d477c2441268abbc2f5538bb793971110874668d90` |
| quotient degree bound | 786,433 |
| transaction | 967,476 bytes |
| transaction SHA-256 | `8b7200b5a76ecc0e9ae038a5698d2d33ec884ea54548ccb347dd0d62390aef53` |
| remaining consensus bytes | 32,524 |
| inputs accepted | 168 / 168 |
| maximum verifier / redeem / unlocking | 9,383 / 9,435 / 9,699 bytes |
| maximum operation cost | 7,321,148 at input 114 |
| tightest operation-cost slack | 19,905 at input 130 |

The ignored raw files are `.local/local-word-product-v15.proof`,
`.local/local-word-product-v15.tx`, and
`.local/local-word-product-v15-report.json`. [`meta.json`](meta.json) pins their
hashes and identity. [`meters.json`](meters.json) records every input's exact VM
meters, the complete transaction-derived observer ledger, and all exact
artifact mutations.

## PROMPT gate disposition

| Gate | Evidence |
|---|---|
| complete relation | C1–C33 in `COMPLETENESS.md`; fresh reference verification; all 168 production VM inputs accepted |
| ZK membrane | independently sealed original/interaction columns, unsplit quotient, coefficient-one FRI isolator, and one transcript |
| privacy | exact 168-input carrier union parsed; 28/56 direct locations against 262,144 mask dimensions; protected-trace recovery false; QROM remains unresolved |
| simplification | one canonical codec and schedule; byte-only carriers; product import graph has 50 files and no FRI11 witness path |
| adversarial | changed root, opening, mask, fold, statement, and carrier placement rejected by the reference layer and a production VM role |
| security and bounds | conservative classical-ROM union above 101.37 bits; proof below 340,490-byte bound; transaction and every script below consensus bounds |
| version integrity | proof version 15; constitution hash and 14-component manifest bind the exact family ID above; three distinct profile-bank digests pinned |
| final evidence | fresh proof, exact transaction, all-role meters, observer ledger, mutations, and skipped broad checks recorded here |

## Reproduce

From this lane:

```bash
npx tsx scripts/audit-local-word-product-imports.ts
npx tsx scripts/prove-local-word-product.ts --dry-run --preflight
npx tsx scripts/prove-local-word-product.ts --fresh-proof --vm --audit
npx tsx scripts/save-local-word-v15-offline-artifact.ts
```

The final proving command is intentionally long and should only be repeated
after an identity-bound change. The complete historical `npm test` and
`cargo test` suites were skipped as non-essential. The focused v15 relation,
codec, algebra, Merkle, settlement, privacy, and compatibility run passed
81/81 tests; release Cargo checking also passed. The full source-lane TypeScript
check reports 10 inherited errors in seven excluded historical files; none
point to the exported v15 system. The minimal self-contained export typechecks
cleanly.

Chipnet mining is the only remaining product gate. It requires a separate
explicit authorization and must never target mainnet.

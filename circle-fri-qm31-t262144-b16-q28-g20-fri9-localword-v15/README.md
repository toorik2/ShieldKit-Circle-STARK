# Research lane: nonstandard ideal Circle STARK

This lane contains the offline-qualified local-word v15 successor. Its frozen
construction ID is:

```text
8d583c84312f7c79519b65bf374dc2ffb6597544a504d88a587c578f9bed2133
```

The governing documents are the minimal [`RULES.md`](RULES.md) constitution,
numbered [`COMPLETENESS.md`](COMPLETENESS.md) relation, frozen
[`ZK-MEMBRANE.md`](ZK-MEMBRANE.md), and versioned
[`SUCCESSOR-CONSTRUCTION.md`](SUCCESSOR-CONSTRUCTION.md). The exact offline
artifact is [`survey/artifacts/local-word-v15-offline/`](survey/artifacts/local-word-v15-offline/).

## What the system is

V15 proves one deposit, one full withdrawal, or one withdrawal with at most one
private change note. It protects note ownership and identity, private amounts,
membership paths, and change allocation. Net deposits, payouts, miner fees,
nullifiers, and TVL are public. It has no transfer, merge, split, batching,
administration, escape path, or non-miner fee.

```text
private relation traces -> secret ZK seal -> one transcript
                        -> canonical proof bytes -> 168 byte-only carriers
```

The proof is a Circle FRI STARK using SHA-256, M31 trace representation, and
QM31 security arithmetic. One static local-word machine contains SHA-256,
membership, nullifier, amount, conservation, and change logic. The transaction
builder accepts canonical proof bytes and public settlement data—not notes,
paths, or traces.

## Exact offline candidate

| Item | Result |
|---|---:|
| fresh proof | 327,674 bytes |
| proof SHA-256 | `a786071c0839e5dbcaf235d477c2441268abbc2f5538bb793971110874668d90` |
| transaction | 967,476 bytes |
| transaction SHA-256 | `8b7200b5a76ecc0e9ae038a5698d2d33ec884ea54548ccb347dd0d62390aef53` |
| inputs accepted by BCH-2026 VM | 168 / 168 |
| maximum verifier / redeem / unlocking | 9,383 / 9,435 / 9,699 bytes |
| remaining transaction bytes | 32,524 |

The conservative classical-ROM soundness union is above 101.37 bits; the
104-bit FRI row remains an explicit conjecture. Algebraic openings are perfect
HVZK conditioned on nonzero denominators, the bad-denominator distance is below
`2^-102.61`, serialized privacy is computational in the classical programmable
ROM, and QROM zero knowledge remains unresolved. The quantum stance is only
“no known polynomial-time quantum break under the stated assumptions.”

## Fast verification

From this directory:

```bash
npm ci
npx tsx scripts/audit-local-word-product-imports.ts
npx tsx scripts/prove-local-word-product.ts --dry-run --preflight
```

Only repeat the long final run after an identity-bound change:

```bash
npx tsx scripts/prove-local-word-product.ts --fresh-proof --vm --audit
npx tsx scripts/save-local-word-v15-offline-artifact.ts
```

Historical FRI11 and batch-exit code is deliberately omitted from this export;
the v15 product import graph also rejects it. The complete broad historical suite
is not the fast qualification command; targeted v15 tests and the exact end-to-end
artifact are authoritative.

Chipnet mining remains a separately authorized action. Never target mainnet,
and only the human user declares the named end complete.

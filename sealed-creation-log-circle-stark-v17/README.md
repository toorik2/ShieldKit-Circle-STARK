# Sealed Creation Log Circle STARK V17

V17 is a self-contained BCH-native private-pool research candidate. It proves
one deposit, full withdrawal, or withdrawal with one private change note using
a sealed Circle FRI STARK, then verifies and settles that transition inside one
May-2026 BCH consensus transaction.

The exact fresh qualification reached the deliberately narrow label
`offline-theorem-qualified-candidate`. Its generated protocol and construction
identities are:

```text
protocol      9195e2b02944a9355c50a76e5ddc33e2e03ba48375e95932bb0713933e7ebc96
construction  c434ed36bf04d8265ec6d0e447f69cd7a437baf91bcc6eab6eb0ff5f9cbe62e1
```

This is an identity-bound offline result, not a claim that the named research
end is human-declared complete.

## The shape

```text
private relation -> independent full-dimensional seals -> one whole quotient
                 -> one degree-corrected Protocol-4 batch
                 -> grouped binary Circle FRI -> one canonical proof
                 -> 210 proof-carrier roles:
                    role 0 state/value-changing settlement
                    roles 1..209 byte-only value-neutral verifier workers
                 -> one authenticated value-neutral ROM page at role 210
```

V17 removes several accidental feedback loops:

- one typed graph owns the transcript, proof layout, Merkle geometry, roles,
  allocation law, and ROM law;
- carrier sizing closes by a coordinatewise monotone envelope and an explicit
  no-change replay, rather than equality of oscillating raw measurements;
- ROM selection starts from an exact byte-length census that is explicitly not
  VM evidence, then earns promotion only after all-profile BCHN measurement;
- ROM function IDs come from the earliest static semantic occurrence, so an
  unrelated body-class split cannot renumber them; and
- one affine proof reader and one authenticated ROM page replace repeated
  literal machinery without creating a proof-controlled interpreter.

## Fresh all-profile evidence

| Profile | Proof bytes | Transaction bytes | Inputs / outputs | Byte headroom |
|---|---:|---:|---:|---:|
| deposit | 448,482 | 942,780 | 212 / 212 | 57,220 |
| full withdrawal | 448,094 | 949,604 | 211 / 213 | 50,396 |
| withdrawal with change | 448,502 | 951,099 | 211 / 214 | 48,901 |

All three proofs were freshly generated without cache, independently replayed,
reassembled exactly from their 210 carrier slices, and observed over the full
serialized transaction. BCHN 29.0.0 accepted every input script in all three
envelopes: 634 inputs total. The final assay measured maximum composite opcost
7,733,035, maximum hash-digest iterations 552, and maximum unlocking bytecode
9,672 bytes.

The runtime theorem certificate passes
`epsilon(T)/T <= 2^-100` for every integer `1 <= T < 2^128`. The exact observer
finds the protected original-column opening system non-unique, with rank 48
against 262,144 trace and 262,144 independent mask coefficients.

The compact, sanitized evidence index is
[evidence/v17-offline-qualification-receipt.json](evidence/v17-offline-qualification-receipt.json).
Raw proof and transaction bytes remain ignored under `.local/` and are not
committed.

## Claim boundary

The qualified statement is conditional on the exact cited theorem model,
construction correspondences, and SHA-256/classical programmable-ROM
transcript and soundness assumptions. The rank witness establishes opening
non-uniqueness; it is not a complete honest-verifier simulation and does not
claim statistical, computational, or QROM zero knowledge. The quantum
statement is only: no known polynomial-time quantum break under the stated
assumptions.

The BCHN result is every-input consensus `VerifyScript` plus local canonical
serialization, value/token, topology, and infrastructure checks. It explicitly
excludes transaction-level `CheckTransaction`/`CheckTxInputs`, live UTXO and
relative-locktime context, standardness, mempool acceptance, mining, and
broadcast. V17 is not a standard sub-100,000-byte transaction.

## Read in this order

1. [RULES.md](RULES.md) — constitutional boundary.
2. [CONSTRUCTION.md](CONSTRUCTION.md) — fixed design and packaging.
3. [COMPLETENESS.md](COMPLETENESS.md) — C1-C33 miner obligations.
4. [ZK-MEMBRANE.md](ZK-MEMBRANE.md) — the sole private-to-public doorway.
5. [THEOREM.md](THEOREM.md) — static theorem and runtime promotion.
6. [ARGUMENT.md](ARGUMENT.md) — exact evidence and judgment.
7. [technical.md](technical.md) — consolidated technical tables.
8. [NEXT.md](NEXT.md) — assurance work before a smaller successor.

## Commands

```bash
npm ci --ignore-scripts
npm run typecheck
npm run generate:v17:check
npm run audit:imports
npm run test:v17
npm run qualify:dry
bash scripts/build-bchn-v29-assay.sh
npm run qualify
npm run verify:receipt
```

The fresh all-profile qualifier is a long final gate, not an iteration test.
The receipt verifier is read-only and fail-closed against the final local
artifacts. None of these commands performs RPC, funding, spending, broadcast,
or mining.

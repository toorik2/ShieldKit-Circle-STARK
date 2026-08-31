# V17 complete observer ledger

The V17 observer receives the whole serialized transaction, not one convenient
input. It strictly decodes all 210 proof-carrier slices, reassembles exactly one
canonical proof, replays the SHA-256 transcript, derives the q44 query schedule
and QM31 OOD point, and verifies the sorted indices and ranks of all five matrix
and nine FRI opening families. Missing, duplicated, moved, malformed,
rank-deficient, or trailing bytes abort the audit.

The all-profile result is identity-bound in
[evidence/v17-offline-qualification-receipt.json](evidence/v17-offline-qualification-receipt.json).

## Public transaction view

| Object | Exposure | Treatment |
|---|---:|---|
| action, PAA2 transition, reserve, payout, miner fee, TVL | transaction | public by constitution |
| creation handle and depth-32 append path | profile 0/2 only | public wallet-rebuild data |
| nullifier and depth-256 sparse update path | profile 1/2 only | public anti-replay state |
| selected verifier bank and infrastructure topology | 210 proof roles + 1 ROM page | integrity, not privacy |
| canonical proof | one contiguous partition | byte-for-byte exact union |

The profile shapes are:

| Profile | Public creation handles | Edge path nodes | Nullifier path nodes |
|---|---:|---:|---:|
| deposit | 1 | 32 | 0 |
| full withdrawal | 0 | 0 | 256 |
| withdrawal with change | 1 | 32 | 256 |

Fresh decoded envelope measurements:

| Profile | Proof bytes | Transaction bytes | Authentication nodes | FRI authentication nodes |
|---|---:|---:|---:|---:|
| deposit | 448,482 | 942,780 | 7,968 | 3,284 |
| full withdrawal | 448,094 | 949,604 | 7,948 | 3,266 |
| withdrawal with change | 448,502 | 951,099 | 7,963 | 3,284 |

## Canonical algebraic view

The proof prefix is 4,474 bytes. Its dynamic mixed-Merkle tail has one strict
14-entry directory. For every profile, the observer confirms:

| Object | Exact exposure |
|---|---:|
| current query points | 44 |
| global current/predecessor points | 88 |
| original openings | 1,496 M31 values |
| interaction openings | 2,464 M31 values |
| global interaction openings | 1,056 M31 values |
| original OOD points | 1 QM31 point per column |
| whole quotient | 44 QM31 values |
| independent FRI mask | 44 QM31 values |
| FRI-layer values | 1,496 QM31 values |
| final polynomial | 8 QM31 coefficients |
| relation/auxiliary roots | 5 |
| FRI roots | 9 |
| named-round nonces | 14 |
| independent FRI challenges | 17 |

The whole quotient has no decomposition and no extra witness form at queries.
Later FRI data is isolated by an independent degree-below-`2^20` QM31 mask
whose batch coefficient is exactly one.

## Protected witness and recovery experiment

The transaction does not intentionally reveal owner secret, `rho`, note
commitment/preimage, note amount, spent creation index or previous head,
private depth-32 membership path, change amount/identity/allocation, or any
private SHA/ALU trace intermediate.

Each of the 34 protected original columns is a polynomial with 262,144 trace
coefficients and 262,144 independent mask coefficients. The serialized view
contains 44 M31 evaluations plus one QM31 OOD evaluation. The OOD value gives
four M31-linear equations, so the exact opening-system rank is 48.

The observer works in Stwo's implemented bit-reversed Circle FFT coefficient
basis. It changes the trace by the constant-one polynomial and solves

```text
1 + Z_H(P) * delta_r(P) = 0
```

at all 44 base points and all four OOD coordinates. For each protected original
column it verifies:

| Quantity | Result |
|---|---:|
| equations / certified rank | 48 / 48 |
| trace dimensions | 262,144 |
| independent mask dimensions | 262,144 |
| conditioned mask nullity | 262,096 |
| joint trace/mask nullity | 524,240 |
| nonzero compensating mask coefficients | 48 |
| all exposed-opening residuals | zero |
| protected trace changes | yes |
| uniquely recovered | no |

Interaction columns have the same 262,144-dimensional independent masks. The
interaction, global-interaction, and FRI-isolator figures of 48, 92, and 44 are
opening-count/dimension budgets, not separately executed rank certificates.
The independent FRI isolator has 1,048,576 dimensions.

This is a positive executable witness that the algebraic opening view is not
unique. It is stronger than a secret-byte substring search, but narrower than a
zero-knowledge theorem: it does not construct a second AIR-valid semantic
witness and does not provide a complete algebraic-IOP honest-verifier
simulation or prove statistical, computational, or QROM zero knowledge for the
complete serialized proof.

## Full-envelope gates

For all three fresh proofs, the observer reports exact carrier ownership and
union, generated frame order, exact partition, strict transcript-derived
schedules, and protected-trace recovery false. Swapping carrier positions is
rejected. The fresh reference audit also rejects a matrix-root byte mutation,
an opening-body byte mutation, proof truncation, and a false public transcript
for every profile.

The schedule, compensating-witness, observed-value, proof, and transaction
digests are generated evidence and are recorded in the compact receipt. The
table above is a human projection of that receipt, not a second authority.

## Claim boundary

| Layer | Claim |
|---|---|
| full-dimensional seal | exact affine-fibre algebra |
| opening recovery | non-unique with an executable compensating witness |
| algebraic opening view | non-unique under the exact rank witness; complete algebraic-IOP honest-verifier simulation is not claimed |
| exact V17 bad-denominator distance | unresolved |
| Merkle commitments | binding/integrity under SHA-256; hiding additionally relies on sealed-value entropy, not collision resistance alone |
| Fiat-Shamir transcript and soundness | classical programmable ROM; not a computational-ZK claim |
| complete proof zero knowledge | no complete honest-verifier, statistical, computational, or QROM ZK claim |
| quantum stance | no known polynomial-time quantum break under stated assumptions |

No negative-recovery result is presented as a complete proof of privacy. The
final privacy evidence boundary is the conjunction of the membrane design,
strict complete-transaction observer, exact protected-original rank witness,
classical transcript/soundness model, sealed-value entropy assumption, and the
explicit exclusions above.

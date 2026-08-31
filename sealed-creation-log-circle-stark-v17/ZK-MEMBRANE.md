# V17 zero-knowledge membrane

This document fixes the only doorway from the private relation to consensus:

```text
private word trace -> independent full-dimensional seals -> one whole quotient
                   -> one independently masked Protocol-4 batch
                   -> grouped Circle FRI -> canonical proof bytes
                   -> canonical proof-byte payloads on BCH inputs
```

Transaction assembly receives one canonical proof and public settlement data.
It never receives a note, path, trace, polynomial, opening, or privacy mask.

## 1. Observer and protected witness

The observer receives the complete serialized transaction: the union of every
proof-carrier input, authenticated code-ROM input, proof byte, state/output
field, public edge-append path, public sparse-nullifier path, and everything
efficiently derived from them.

The protected witness is the note preimage and amount, owner secret, `rho`,
spent edge and index, previous creation head, private history path, change note
and amount, and every corresponding word-machine intermediate. The public
creation handle, PAA2 fields, nullifier, payout, miner fee, reserve, TVL, proof,
and verifier topology are not secrets.

## 2. Full-dimensional seal

The relation domain `H` has `2^18` rows. For each protected M31 trace column
`w`, the prover samples an independent uniform `r` from `L'_18` and commits only
to

```text
s = w + Z_H * r.
```

Restriction from `L'_19` to `H` is surjective, and `Z_H * L'_18` is its full
`2^18`-dimensional kernel. Thus `s|_H = w`, while `s` is uniform over the entire
affine fibre of functions with that restriction. Original and interaction
columns use independent randomness. No transcript-derived value is privacy
randomness.

V17 exposes a protected original column at 44 transcript-derived M31-domain
query points and once at the transcript-derived QM31 OOD point `Q`. The OOD
value contributes four M31-linear equations, so the exact observed rank is 48,
not 44. The executable observer builds the evaluation matrix in the implemented
Stwo Circle basis and row-reduces it against 262,144 trace coefficients and
262,144 independent mask coefficients.

As a concrete non-recovery witness, it changes the trace by the constant-one
polynomial and solves for `delta_r` such that

```text
1 + Z_H(P) * delta_r(P) = 0
```

at all 44 base points and all four base-field coordinates of `Q`. It verifies
zero residual, conditioned mask nullity 262,096, and joint trace/mask nullity
524,240 for every protected original column. This proves non-uniqueness of the
observed algebraic opening system; it does not produce a second AIR-valid
semantic witness and is not, by itself, a zero-knowledge theorem.

## 3. Whole quotient and OOD closure

There is one unsplit quotient:

```text
C = sum_j alpha_constraint^j * R_j(s, predecessor(s), public)
q = C / Z_H.
```

The singleton miner-run OOD role evaluates all 25 quadratic AIR residuals at
`Q`, reconstructs the composition, and checks

```text
q(Q) * Z_H(Q) = C(Q).
```

The proof carries no serialized composition partials and has no second
note-aware algebra path.

## 4. Degree-corrected Protocol-4 batch

At `Q`, the proof claims exactly 98 function values. At each of the 44 queried
base points `P`, the batch contains:

- one independent FRI-mask value;
- the 98 function values; and
- the 98 degree-corrected values `(f_i(P)-f_i(Q))/v_Q(P)`.

The canonical batch width is therefore `1 + 98 + 98 = 197`. If
`A_beta(P) = sum_i beta^i f_i(P)`, layer zero is linked by

```text
H_beta(P) = mask(P)
          + beta * A_beta(P)
          + beta^99 * (A_beta(P)-A_beta(Q)) / v_Q(P).
```

The independent degree-below-`2^20` QM31 mask has coefficient exactly one. It
cannot disappear for an unlucky batching challenge. Forty-four graph-owned
batch-link roles authenticate these values and bind them to FRI layer zero.

## 5. Grouped FRI and authentication

The degree descent has 17 independent binary folds. The first eight committed
groups each execute two adjacent binary folds with two independent Fiat-Shamir
challenges; the ninth executes one. Each uncommitted middle oracle is the
deterministic output of the first fold, never a prover-selected object.

Matrix commitments are binary. FRI layers zero through seven use one quartet
leaf level followed by binary levels; the final FRI layer is binary. Arity,
labels, indices, cut depths, frontiers, ranks, and merge order come only from the
typed graph. One strict codec and one transcript-derived q44 schedule own every
opening.

The graph has 210 proof-carrier roles, which partition one canonical proof
once. Role zero is the pool/settlement input: its reserve value and mutable-NFT
state make the public transition and are intentionally not value-neutral. Roles
1 through 209 are tokenless verifier workers rolled forward exactly and
value-neutrally. Authenticated code-ROM role/input 210 carries only verifier
bytecode and is also an exact tokenless, value-neutral rollover. No carrier
receives private witness material outside the canonical proof bytes.

## 6. Claim boundary

| Layer | V17 claim boundary |
|---|---|
| full-dimensional affine-fibre seal | exact algebraic statement |
| rank-48 recovery experiment | executable non-uniqueness evidence for the observed original-column system |
| bad-denominator and reduction events | must be charged explicitly by the classical soundness theorem |
| SHA-256 Merkle commitments | computational binding in the classical random-oracle model; hiding additionally relies on the entropy of independently sealed committed values |
| Fiat-Shamir compilation | classical programmable-ROM transcript and soundness model; no complete zero-knowledge claim |
| QROM zero knowledge | no claim |
| quantum stance | no known polynomial-time quantum break under stated assumptions |

The complete serialized product is not called statistically hiding or
zero-knowledge merely because the linear recovery experiment fails. Promotion
requires the exact final transaction observer to decode all 210 carrier slices,
replay the transcript and every opening schedule, reproduce the rank-48 result,
and report protected-trace recovery false. It also requires the exact runtime
theorem certificate for the same generated identity.

## 7. Fail-closed rules

Reject any construction containing:

- raw trace rows or unsealed LDE values in proof or carrier bytes;
- mask reuse across columns or proofs;
- a second note-aware opening path or query schedule;
- quotient splitting without a simulator for the exact split;
- a FRI mask coefficient that can be zero;
- transaction code that accepts private witness material;
- proof-length-specific verifier locks or uncommitted carrier coordinates; or
- substring-based or negative-recovery tests presented as proof of privacy.

Protocol identities, construction identities, proof sizes, transaction sizes,
and observer measurements are generated evidence. This specification contains
no hand-authored final artifact claim.

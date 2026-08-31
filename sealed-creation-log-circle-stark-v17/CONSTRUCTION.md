# Sealed Creation Log Circle STARK V17 construction

V17 changes the proof and BCH verifier construction while deliberately freezing
the public relation and privacy membrane. The clean version boundary is:

| Layer | Version |
|---|---:|
| canonical proof and product graph | 17 |
| sealed-creation-log relation descriptor | 16 |

The relation program and its descriptor are byte-identical to frozen V16. The
V17 protocol identity binds that frozen relation digest together with the new
proof graph, transcript, theorem map, Merkle geometry, role layout, allocation
law, and ROM law.

## 1. State and relation

The mutable continuation NFT carries one 128-byte PAA2 commitment:

| Bytes | Meaning |
|---:|---|
| `0..4` | ASCII `PAA2` |
| `4` | version 2 |
| `5..8` | zero |
| `8..16` | transition sequence, u64 big-endian |
| `16..24` | creation count, u64 big-endian, constrained below `2^32` |
| `24..32` | zero |
| `32..64` | current creation head |
| `64..96` | depth-32 edge-history root |
| `96..128` | depth-256 sparse-nullifier root |

The pool category comes from the continuation NFT and the reserve from BCH
value. A wallet needs only `{ amount, rho, ownerSecret, creationIndex,
previousHead }`; commitment, edge, nullifier, and current membership path are
reconstructed from that record and canonical public history.

The relation permits exactly:

| Profile | Private relation | Public transition |
|---|---|---|
| 0 — deposit | create one positive note | reserve and creation history advance |
| 1 — full withdrawal | spend one historical note | payout and nullifier set advance |
| 2 — withdrawal with change | spend one note and create one same-owner note with fresh `rho` | payout, nullifier set, and creation history advance |

There is no transfer, merge, split, batch, administrator, escape path, protocol
fee, or second state thread.

All private relation fields enter one 412-byte word-aligned statement. CashVM
reconstructs the same public statement and authenticates only its eight-word
SHA-256 digest across the algebra boundary. The deposit, full-withdrawal, and
change programs use 17, 85, and 95 SHA-256 compressions; the worst program uses
218,165 active word rows inside the fixed `2^18` relation domain.

## 2. One sealed argument

```text
private 32-bit SHA word trace
        -> independent s = w + Z_H r seals
        -> one 25-residual composition
        -> one whole quotient
        -> one 98-claim OOD check
        -> one width-197 degree-corrected batch
        -> 17 binary folds in nine committed groups
        -> one strict canonical proof
```

The trace field is M31. Security-critical challenges, interaction arguments,
composition, quotient, batching, and FRI use QM31. Every protected original and
interaction column has an independent full-dimensional `2^18`-coefficient
mask. One independent degree-below-`2^20` QM31 polynomial enters the FRI batch
with coefficient exactly one.

At the sampled QM31 point `Q`, one singleton role receives exactly:

```text
43 preprocessed + 34 original + 17 interaction
+ 3 predecessor interaction + 1 quotient = 98 claims.
```

For every one of the 44 collision-free query orbits, one batch-link role checks
the mask, all 98 functions, and all 98 degree-corrected functions. Thus the
Protocol-4 width is `1 + 98 + 98 = 197`.

The degree descent is 17 independent binary folds grouped as
`[2,2,2,2,2,2,2,2,1]`. Each two-fold group derives two independent
Fiat-Shamir challenges. Its uncommitted middle oracle is only the deterministic
output of the first fold.

## 3. One transcript and one proof language

One causally ordered SHA-256 transcript owns interaction challenges, the
constraint mix, OOD sample, batch challenge, all 17 fold challenges, 14 named
round nonces, final coefficients, and q44 query schedule. Serialized challenge
snapshots are checked caches, not reabsorbed messages. The terminal opening
directory and bodies precede no later challenge.

The fixed proof prefix is 4,474 bytes. The dynamic tail contains one strict
directory for five matrix opening families and nine FRI opening families. The
maximum canonical proof envelope is 457,514 bytes. The proof codec rejects a
wrong version/profile/protocol, malformed field, duplicate or reordered frame,
bad total length, wrong rank manifest, missing body, or trailing byte.

The 44 query roles share one generic candidate body invoked with fixed ordinals
`0..43`; proof bytes never select an interpreter instruction or query count.

## 4. One Merkle language

All five matrix commitments are binary trees over a `2^24` evaluation domain.
FRI layers 0 through 7 have a quartet leaf level followed by binary levels;
layer 8 is binary. Descriptors fix domain labels, row widths, arity, indices,
cut depths, ranks, frontiers, and merge order before the proof exists.

The graph assigns 31 matrix-Merkle roles and 43 FRI-Merkle roles. These include
52 parent roles. One generated planner owns every cut; the TypeScript prover,
reference verifier, and CashVM roles consume the same canonical opening bodies.

## 5. One graph and 210 proof roles

| Role family | Count | Purpose |
|---|---:|---|
| settlement | 1 | state, value, token, bank, and infrastructure covenant |
| singleton OOD AIR | 1 | all 25 residuals and whole-quotient identity |
| batch-link query | 44 | width-197 link to FRI layer zero |
| FRI-fold query | 44 | all 17 folds and final polynomial |
| public boundary | 2 | eight inverses and claimed-sum closure |
| proof header | 1 | version, profile, protocol, relation, key |
| edge append | 1 | public depth-32 creation-history append |
| sparse nullifier | 4 | absence/used path halves |
| transcript | 6 | one ordered Fiat-Shamir transcript |
| query schedule | 1 | collision-free q44 derivation |
| opening schedule | 31 | matrix/global/FRI directories and ranks |
| matrix Merkle | 31 | binary matrix authentication |
| FRI Merkle | 43 | quartet-first/binary FRI authentication |
| **Total** | **210** | one contiguous partition of one proof |

Every role is a proof carrier, including settlement input zero. A deposit adds
one transparent funding input; withdrawals do not. Authenticated ROM is
separate infrastructure and never carries proof or witness bytes.

## 6. Monotone allocation closure

Carrier size affects density credit; density credit affects which verifier
scripts fit; and those scripts affect carrier capacity. Raw measurement
equality can therefore oscillate even when every candidate is feasible. V17
turns this feedback loop into one monotone construction:

1. start from the canonical 256-byte-per-role bootstrap allocation;
2. assay every role under all three profiles;
3. join each role coordinatewise using maximum opcost, maximum required proof
   bytes, and minimum capacity;
4. derive the next allocation with the single graph-fixed Hamilton rule;
5. derive the affine reader from that allocation; and
6. stop only on an explicit replay where closure, allocation, reader plan, and
   reader bytecode all remain unchanged.

Every step is domain-separated and SHA-256 chained. The exact final BCHN rows
remain separate from the conservative closure rows: certification requires the
closure to dominate them and the final assay to append another no-change entry.
Historical maxima can never decrease, so remeasurement cannot silently make a
previously tight role look easier.

The affine reader represents every proof-slice boundary as a monotone function
of total proof length. The linked construction certifies all integer lengths by
checking normalized offset endpoints, rather than enumerating selected proof
sizes.

## 7. Authenticated code ROM

ROM is a linker optimization, not a new trust layer or a proof-controlled VM.
The linker recursively censuses every literal `OP_DEFINE` body and classifies
only construction-independent, top-level exact-byte duplicates as eligible.

The pre-link baseline is deliberately **length-only**:

- it prices exact serialized bytecode and page/input/output overhead;
- it is labelled non-executable and non-measurement;
- each body must pay for its own authenticated page in every profile before
  packing can help; and
- no baseline opcost can enter construction certification.

After linking, the exact scripts and full profile envelopes are independently
assayed by BCHN. A page survives only if the linked result has strict positive
byte saving in every profile and all resource limits pass.

Function IDs are minimal positive unsigned big-endian encodings of the
earliest static semantic occurrence `(profile, logical input, nested path)`.
Ordinals are assigned before body equality and eligibility. Splitting, merging,
or declining an unrelated body class therefore cannot renumber a retained
function. Zero, leading-zero aliases, duplicate occurrence anchors, and
noncanonical page order reject.

The fresh linked construction selected one page containing 13 exact bodies and
saved 283,893 relevant serialized bytes in every profile versus its exact
length-only baseline.
It is placed immediately after the 210 proof-carrier inputs and is recreated
with the same lock, value, sequence, payload, position, and token state.

## 8. Identity and settlement

The protocol ID binds the exact bytes of `RULES.md`, `ZK-MEMBRANE.md`, and
`COMPLETENESS.md`, plus the typed proof graph. The construction ID adds the
three exact linked verifier-bank digests. A separate final-infrastructure
identity replays every proof slice, lock, unlock, value, sequence, role, ROM
page, and proof hash for all three profiles.

The settlement covenant selects exactly one profile bank, checks all 210 proof
roles, authenticates and value-neutrally recreates the ROM page, enforces PAA2
and token authority, verifies public edge/nullifier updates, and settles public
value conservation. Transaction assembly receives only canonical proof bytes
and public settlement data; it has no API for notes, paths, traces,
polynomials, openings, or masks.

Exact identity and all-profile measurements are generated evidence, not fixed
construction prose. See
[evidence/v17-offline-qualification-receipt.json](evidence/v17-offline-qualification-receipt.json).

## 9. Qualification scope

The final evidence runs every serialized input under unmodified BCHN 29.0.0
consensus `VerifyScript`, while local checks own canonical transaction
serialization, value/token invariants, V17 topology, and byte-exact
infrastructure identity.

It does not run BCHN transaction-level `CheckTransaction` or `CheckTxInputs`,
live UTXO maturity or relative-locktime context, standardness, mempool
acceptance, mining, or broadcast. It makes no complete honest-verifier,
statistical, computational, or QROM zero-knowledge claim and no sub-100,000-byte
standard-relay claim.

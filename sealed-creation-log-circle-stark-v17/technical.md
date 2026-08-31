# V17 technical reference

This file separates four kinds of statement:

- **constitutional** — fixed by `RULES.md`;
- **fixed graph** — protocol-identity-bound V17 design;
- **measured receipt** — exact values for one fresh linked identity; and
- **nonclaim** — explicitly outside the qualified result.

The compact measured evidence is
[evidence/v17-offline-qualification-receipt.json](evidence/v17-offline-qualification-receipt.json).
Raw proof and transaction bytes are intentionally not committed.

## Version and identity layers

| Item | Value | Class |
|---|---|---|
| family | Sealed Creation Log Circle STARK | constitutional relation |
| proof format | SKLW version 17 | fixed graph |
| product graph | version 17 | fixed graph |
| relation descriptor | PLWC version 16, byte-identical to frozen V16 | fixed relation |
| private bundle | SKLB version 2 | fixed relation |
| normative byte files | `RULES.md`, `ZK-MEMBRANE.md`, `COMPLETENESS.md` | protocol identity |
| protocol identity | normative bytes + typed V17 graph | generated |
| construction identity | protocol ID + three linked bank digests | generated |
| final infrastructure identity | exact locks, unlocks, values, sequences, roles, ROM, and proof hashes | measured receipt |
| qualification label | `offline-theorem-qualified-candidate` | exact receipt only |
| protocol ID | `9195e2b02944a9355c50a76e5ddc33e2e03ba48375e95932bb0713933e7ebc96` | generated |
| construction ID | `c434ed36bf04d8265ec6d0e447f69cd7a437baf91bcc6eab6eb0ff5f9cbe62e1` | generated |
| linker certificate ID | `cdb0ad11453a9c84c203a77c50a2858c97fb0b8d53728f5b2cf50a377d181d78` | measured receipt |
| final infrastructure identity | `e8165cbca0d7d8fc83382169133fc1c9d07f94f8514936f92cd8669440173ba8` | measured receipt |

The static generated qualification file intentionally remains a pending
template. Qualification is not embedded into protocol source; it lives in a
separate fresh receipt so an old artifact cannot qualify a changed identity.

## Implementation pins

| Item | Value | Class |
|---|---|---|
| Rust toolchain | nightly-2026-01-15 | fixed source |
| Stwo dependency | commit `826591c6c371376810ca8213b5812d5daf6d5092`, crate 2.2.0 | fixed source |
| CashVM library | `@bitauth/libauth` 3.1.0-next.8 | fixed source |
| final opcost engine | BCHN 29.0.0 | measured receipt |
| BCHN source tag commit | `89a591f7c5b1fd110c0819377ad8f2647d656800` | measured receipt |
| assay executable SHA-256 | `ce382830e2201f170cd30d605eb181a683007abf11e7f2a617542056fe686f97` | measured receipt |
| BCH constants source commit | `864c53ee34924cca6c6b6d96607ff2cedcdccf02` | evidence provenance |
| native hash | SHA-256 | constitutional |

The exact receipt pins the lane-owned assay source and executable. Its build is
not claimed hermetic or bit-reproducible across hosts; a clean independent
rebuild is follow-up supply-chain assurance, not a failure of the result for
the exact pinned executable.

## Relation profiles

| Item | Deposit | Full withdrawal | Withdrawal with change |
|---|---:|---:|---:|
| profile | 0 | 1 | 2 |
| creates private note | 1 | 0 | 1 |
| consumes private note | 0 | 1 | 1 |
| SHA-256 compressions | 17 | 85 | 95 |
| public boundary words | 8 | 8 | 8 |
| creation history advances | yes | no | yes |
| sparse nullifier root advances | no | yes | yes |
| public payout | no | yes | yes |

There is no transfer, merge, split, batching, administrator, escape path,
relayer fee, protocol fee, or trusted verification route.

## Private and public data

| Protected by the proof boundary | Public by constitution |
|---|---|
| owner secret and `rho` | action/profile |
| note amount and commitment/preimage | reserve delta, payout, miner fee, TVL |
| spent creation index and previous head | PAA2 sequence/count/head/history/nullifier roots |
| private depth-32 membership path | created edge handle and public append path |
| change amount, identity, and allocation | withdrawal nullifier and sparse update path |
| private SHA/ALU rows and intermediates | proof bytes and verifier topology |

## State and hash relation

| Item | Value | Class |
|---|---:|---|
| PAA2 commitment | 128 bytes | fixed relation |
| PAA2 fields | sequence, creation count/head, history root, nullifier root | fixed relation |
| edge history | depth-32 SHA-256 sequential tree | fixed relation |
| nullifier set | depth-256 sparse SHA-256 tree | fixed relation |
| creation link message | 168 bytes | fixed relation |
| creation edge message | 168 bytes | fixed relation |
| nullifier message | 192 bytes | fixed relation |
| relation statement preimage | canonical 412 bytes | fixed relation |
| Fiat-Shamir public statement | canonical 410 bytes | fixed relation |
| public relation seam | SHA-256 digest, eight words | fixed relation |
| maximum active word rows | 218,165 | fixed relation program |
| relation inputs, worst profile | 405 | fixed relation program |
| full-capacity behavior | no deposit/change after `2^32` creations; full exits remain | constitutional |

A wallet needs amount, `rho`, owner secret, creation index, and previous head.
Current paths are reconstructible from canonical public BCH history.

## Algebra and proof geometry

| Item | Value | Class |
|---|---:|---|
| trace field | M31, `p = 2^31 - 1` | constitutional |
| challenge/composition/FRI field | QM31 | constitutional |
| relation rows | `2^18` | fixed graph |
| sealed trace bucket | `2^19` | fixed graph |
| quotient commitment bucket | `2^20` | fixed graph |
| evaluation domain | `2^24` | fixed graph |
| AIR residuals | 25 quadratic residuals | fixed graph |
| preprocessed/original/interaction/predecessor/quotient claims at Q | 43 / 34 / 17 / 3 / 1 | fixed graph |
| OOD claims | 98 QM31 values | fixed graph |
| quotient | one unsplit polynomial | fixed graph |
| maximum quotient degree in theorem convention | 393,216 | proved degree certificate |
| Rust `quotientDegreeBound` support count | 786,433 (`2d+1` Circle support convention) | measured proof contract |
| trace seal | `w + Z_H r`, `2^18` independent dimensions per column | fixed graph |
| FRI isolator | independent degree-below-`2^20` QM31 polynomial | fixed graph |
| isolator coefficient | exactly one | fixed graph |
| Protocol-4 width | `1 + 98 + 98 = 197` | fixed graph |
| query schedule | 44 collision-free orbits | fixed graph |
| FRI folds | 17 independent binary folds | fixed graph |
| fold groups | `[2,2,2,2,2,2,2,2,1]` | fixed graph |
| committed FRI roots | 9 | fixed graph |
| final polynomial | 8 QM31 coefficients | fixed graph |
| maximum canonical proof envelope | 457,514 bytes | fixed graph |

Named-round grinding bits in transcript order are:

```text
[9,0,3,26,20,18,16,14,12,10,8,6,4,26]
```

for `air:logup`, `air:composition`, `air:ood`, `fri:batch`, FRI fold groups
0 through 8, and `fri:query`.

## Proof framing and observer counts

| Item | Count | Class |
|---|---:|---|
| fixed proof prefix | 4,474 bytes | fixed graph |
| opening directory entries | 14 | fixed graph |
| current query points | 44 | decoded proof |
| global current/predecessor points | 88 | decoded proof |
| original M31 openings | 1,496 | decoded proof |
| interaction M31 openings | 2,464 | decoded proof |
| global interaction M31 openings | 1,056 | decoded proof |
| quotient QM31 openings | 44 | decoded proof |
| FRI-mask QM31 openings | 44 | decoded proof |
| FRI-layer QM31 values | 1,496 | decoded proof |
| final QM31 coefficients | 8 | decoded proof |
| relation/auxiliary roots | 5 | decoded proof |
| FRI roots | 9 | decoded proof |
| named-round nonces | 14 | decoded proof |
| independent fold challenges | 17 | transcript replay |

## Verifier role graph

| Family | Roles |
|---|---:|
| settlement | 1 |
| OOD AIR | 1 |
| batch-link query | 44 |
| FRI-fold query | 44 |
| public boundary | 2 |
| proof header | 1 |
| edge append | 1 |
| sparse nullifier | 4 |
| transcript | 6 |
| query schedule | 1 |
| opening schedule | 31 |
| matrix Merkle | 31 |
| FRI Merkle | 43 |
| **proof-carrier roles** | **210** |
| Merkle parent roles within those families | 52 |

The 210 carriers partition one proof contiguously and exactly once. Role zero
is the pool/settlement carrier. The other 209 proof-worker carriers and every
authenticated ROM page are auxiliary, value-neutral infrastructure.

## Allocation and affine reader

| Item | Value | Class |
|---|---|---|
| strategy | base plus elastic prefix | fixed graph |
| bootstrap minimum | 256 proof bytes per role | fixed graph |
| elastic scale | 4,095 units | fixed graph |
| join | max opcost, max required bytes, min capacity per role | fixed graph |
| slack allocator | capacity-proportional Hamilton, graph role order | fixed graph |
| trace | domain-separated SHA-256 chain | fixed graph |
| terminal condition | explicit closure/allocation/reader no-change replay | fixed graph |
| final admissibility | closure dominates exact post-link and final BCHN rows | fixed graph |
| measured minimum proof endpoint | 437,256 bytes | measured receipt |
| maximum proof endpoint | 457,514 bytes | fixed graph |
| closure digest | `cd0aaae1474305019f3e5cf093a7476c6f05f5495cd7668852c3b2153dfda46a` | measured receipt |
| final trace root | `478e662a123c1b31391005680a89f373b1464b9a47b71d49638dc637555238ec` | measured receipt |
| trace stages | 7 local-sizing + 1 post-link BCHN + 1 final BCHN | measured receipt |
| terminal changes | 0 roles; closure/allocation/reader all unchanged | measured receipt |

Local libauth sizing is labelled
`local-sizing-only-not-resource-evidence`. It may find a seed but cannot certify
the construction. The construction certificate and final runtime theorem use
exact BCHN-derived rows.

The linked affine reader uses five proof-length cells and 21 normalized offset
cells. Its canonical plan is 279 bytes, reader bytecode is 638 bytes, and the
widest interval crosses 44 carriers. Endpoint monotonicity certifies every
integer proof length in the graph envelope.

## Authenticated ROM

| Item | Rule | Class |
|---|---|---|
| eligible body | construction-independent, top-level, exact-byte duplicate | fixed graph |
| baseline | exact serialized lengths only; non-executable/non-measurement | fixed graph |
| promotion | strict positive saving in every profile | fixed graph |
| final evidence | exact post-link all-profile BCHN assay | fixed graph |
| body identity | SHA-256 of exact bytes | fixed graph |
| function ID | minimal positive unsigned-BE earliest static occurrence ordinal | fixed graph |
| packing | minimum pages, then semantic anchor | fixed graph |
| body access | canonical sibling-input bytecode slice | fixed graph |
| page recreation | same index, lock, value, sequence, payload, token state | constitutional |

The linker rejects zero and leading-zero ID aliases, duplicate semantic
anchors, dynamic definitions, body mismatch, noncanonical packing, a
non-positive saving in any profile, or a failed post-link resource assay.

The fresh linked result has one ROM page at input/output 210. It contains 13
functions in a 7,194-byte payload; its redeem script is 115 bytes and its
unlocking bytecode 7,314 bytes. The exact census found 7,398 static definition
occurrences and 104 exact body classes. Linked relevant bytes are 283,893 lower
than the exact baseline in every profile.

## Runtime theorem

| Item | Result | Class |
|---|---|---|
| assurance rows | 16 | fixed theorem map |
| randomized rounds | 14 | fixed theorem map |
| artifact-independent rows | 1 cited + 10 proved | static theorem |
| product rows | 5 unresolved statically; promoted only by exact runtime evidence | fail-closed law |
| classical work-factor gate | `epsilon(T)/T <= 2^-100` for every integer `1 <= T < 2^128` | exact runtime receipt |
| Fiat-Shamir transcript and soundness | classical programmable ROM | conditional claim |
| complete proof zero knowledge | no honest-verifier, statistical, computational, or QROM ZK theorem | nonclaim |
| quantum statement | no known polynomial-time quantum break under stated assumptions | constitutional |

## Privacy recovery result

| Item | Value | Class |
|---|---:|---|
| protected original columns | 34 | fixed graph |
| trace coefficients per column | 262,144 | fixed graph |
| independent mask coefficients per column | 262,144 | fixed graph |
| base-domain observations | 44 | exact observer |
| OOD coordinates | 4 M31 equations | exact observer |
| certified opening rank | 48 | exact observer |
| conditioned mask nullity | 262,096 | exact observer |
| joint trace/mask nullity | 524,240 | exact observer |
| compensating trace delta | constant-one Circle polynomial | exact observer |
| exposed-opening residuals | zero | exact observer |
| unique protected-trace recovery | false | exact observer |

This is algebraic-opening non-uniqueness evidence, not an AIR-valid alternative
witness, complete honest-verifier simulation, or statistical, computational,
or QROM zero-knowledge theorem. Merkle integrity relies on SHA-256; any hiding
additionally relies on sealed-value entropy, not collision resistance alone.

## BCH product boundary

The product target is one consensus transaction no larger than 1,000,000 bytes
with each locking or unlocking script and each pushed element no larger than
10,000 bytes. The future 100,000-byte standard relay target is not a V17 claim.

Final evidence uses BCHN 29.0.0 in consensus `VerifyScript` mode for every
serialized input. Local checks separately own canonical serialization,
value/token conservation, V17 topology, and exact infrastructure identity.

Explicit exclusions are:

- BCHN transaction-level `CheckTransaction` and `CheckTxInputs`;
- live UTXO existence, maturity, and relative-locktime context; and
- standardness, mempool/block acceptance, mining, and broadcast.

No RPC, funding, spending, chain mutation, or mainnet action occurred.

## Fresh all-profile receipt

| Profile | Proof bytes | Proof ceiling headroom | Transaction bytes | Transaction headroom | Inputs / outputs |
|---|---:|---:|---:|---:|---:|
| 0 — deposit | 448,482 | 9,032 | 942,780 | 57,220 | 212 / 212 |
| 1 — full withdrawal | 448,094 | 9,420 | 949,604 | 50,396 | 211 / 213 |
| 2 — withdrawal with change | 448,502 | 9,012 | 951,099 | 48,901 | 211 / 214 |

| Profile | Maximum composite opcost / input limit | Maximum hash iterations | Maximum unlocking bytes | Inputs checked |
|---|---:|---:|---:|---:|
| 0 | 7,730,877 / 7,770,400 | 552 | 9,672 | 212 |
| 1 | 7,733,035 / 7,769,600 | 548 | 9,671 | 211 |
| 2 | 7,732,906 / 7,769,600 | 552 | 9,671 | 211 |

Aggregate BCHN evidence covers 634 accepted input scripts, zero signature
checks, maximum composite opcost 7,733,035, and maximum hash-digest iterations
552. Each profile has 211 identity-bound lane inputs: the state/value-changing
settlement carrier, 209 value-neutral verifier workers, and one value-neutral
ROM page. Profile 0 adds one transparent funding input.

Proof and transaction hashes:

| Profile | Proof SHA-256 | Transaction SHA-256 |
|---|---|---|
| 0 | `526d1e50248f48b313e56ddb84d3b09363e5ab6c1773138a6fa02f2074b3319e` | `6d19548f624f74b8fbe8aa8ef4906a2f51ff776c27a7a3c7958822892ad3a457` |
| 1 | `bb3c4638a40e3daa1685596a67359e3943da431d6a4ecde7e5843f0dba98a4cb` | `e4679449f2d4d99c7e3e776ccbbc42b1f2cffd5011b89f2f93eb20605d7ba7ca` |
| 2 | `f36ba840b6d1a54a03aaa0e39ce0915c8ea814f8793c834865e45bc9bb9db3af` | `991399be753b50baff24947ee194d8715fdfb87c694e95b743aa30ddd6de99d3` |

Linked bank digests:

| Profile | Bank digest |
|---|---|
| 0 | `f88c217c3227206efb35de7e1fa638a8613cb71532fb20eff9c0006a81937023` |
| 1 | `43f978b77f2bffd8f884fbb117303d14fbd20a99a92c7557b95f4370a2f35b66` |
| 2 | `c6f5b57e0061eb31e0d7d0ea00871f61b98c1befe68274db61219fa054aea3f4` |

Top-level evidence digests:

| Evidence | SHA-256 |
|---|---|
| final BCHN product | `0c6f021f320de3d11cfc18e09791d72ee1efcfc98bf1c5760b5321158ad23c63` |
| runtime theorem | `92ee21cabdf9cc1cfd5dc5c32df3df422b19c78a2c3ef0bb051a119d0979a482` |
| proof set | `db249abc908aa55d383748d48e4b294da6893c3187c37c33e735e3a6bb8b8d84` |
| privacy ledger | `e241cbdae94f7de72741948ecb5faa9b101e6c2f2f14610f6be8af288f24b755` |
| adversarial ledger | `49571a44aa58fb7035a263af282e726069b5cc89901807dbe24f7a495d32d28d` |

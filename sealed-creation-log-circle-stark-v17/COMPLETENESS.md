# V17 completeness map

Every C1-C33 obligation below must reach miner execution. A host-only assertion
is test scaffolding, not part of the system. The typed construction graph owns
the exact role order, obligation owner, and dependency edges.

## A. Public settlement and state

| ID | CashVM obligation |
|---|---|
| C1 | derive nonzero reserve delta and select deposit, full withdrawal, or withdrawal-with-change |
| C2 | require exactly one mutable, zero-FT continuation NFT at input/output zero; same UI-order category, covenant lock, and value-derived reserve; reject minting authority and category escape |
| C3 | require PAA2 version/canonical reserved bytes and sequence `+1` |
| C4 | deposit/change: creation count `+1`; full withdrawal: count/head/history unchanged |
| C5 | deposit/change: decode one canonical public edge record and verify the depth-32 empty-to-edge append from old root to new root at the old count |
| C6 | deposit/change: bind the record edge to the proof statement; full withdrawal: require zero created edge and no edge record |
| C7 | deposit: transparent funding pays reserve increase plus miner fee; created note amount equals reserve increase |
| C8 | withdrawal: positive token-free payout; reserve decrease equals payout plus miner fee; bind payout lock digest |
| C9 | withdrawal: decode one canonical nonzero nullifier/path record and verify unused-to-used depth-256 sparse-root transition; deposit leaves nullifier root fixed |
| C10 | bind proof-carrier role zero and its canonical proof slice to the exact pool-state and settlement transition; bind roles 1-209 and authenticated code-ROM role 210 to their exact position, lock, value, tokenless state, sequence policy, canonical payload or proof slice, and identical input/output rollover |
| C11 | authorize exactly the selected profile bank and constrain every transaction input/output relevant to token authority or value flow |

## B. Private relation compiled to the sealed AIR

| ID | Relation obligation |
|---|---|
| C12 | all private computation is expressed by the pinned 32-bit local SHA word machine and fixed 4-bit lookup table |
| C13 | lookup LogUp authenticates every ALU access; word-copy permutation binds sources, rotations, digest handoffs, equality classes, and public rows |
| C14 | ordinary SHA-256 padding, schedule, 64 rounds, chaining, and digest output |
| C15 | note commitment: `amountCommit=H(tag16||amount_i64le||rho)` then `C=H(amountCommit||rho||owner)` |
| C16 | deposit: amount equals public reserve increase; derive `h_next` and public `E` from old count/head and `C`; no private append path |
| C17 | spend: derive its historical `h_next` and `E` from private index/previous head and the same `C` |
| C18 | tie the same private index bits to both the edge preimage and all 32 history-path directions; bind the resulting root to current PAA2 |
| C19 | nullifier: derive from domain/context/category, derived historical `E`, owner, and `rho`; bind public `nf` |
| C20 | full withdrawal: spent amount equals public reserve decrease |
| C21 | change: spent amount equals public reserve decrease plus positive change without overflow; reuse owner; require fresh `rho`; derive exactly one new head and `E` at current count |
| C22 | hash one canonical 412-byte relation statement inside the AIR; CashVM independently reconstructs it and authenticates its eight digest words through one public-boundary LogUp |

## C. V17 proof correspondence

| ID | Verifier obligation |
|---|---|
| C23 | proof version 17, profile, protocol ID, relation-construction digest, relation descriptor, fixed `2^18` row domain, verifier key, and preprocessed root match the selected profile |
| C24 | every protected original and interaction column is committed only after an independent full-dimensional `w + Z_H r` seal; no transcript-derived value is used as privacy randomness |
| C25 | one causally ordered SHA-256 transcript binds protocol and public statement, matrix roots, public inverses/sum, constraint and OOD data, batch and FRI roots, 17 independent fold challenges, every named-round nonce, final coefficients, and queries; derived snapshots are checked but never reabsorbed |
| C26 | one collision-free transcript-derived q44 schedule owns every current, predecessor, quotient, mask, and FRI opening; one generic candidate body reads the canonical 176-byte query frame once and executes fixed ordinals `0..43` |
| C27 | one graph-fixed mixed-Merkle codec authenticates all openings: binary matrix trees, quartet-first FRI layers 0-7, binary FRI layer 8, descriptor-separated hashes, exact rank manifests, exact cut frontiers, and no proof-selected geometry |
| C28 | one singleton OOD AIR role evaluates and mixes all 25 quadratic residuals at the sampled QM31 point; there are no serialized composition partials or per-query AIR sidecars |
| C29 | one unsplit degree-bounded quotient satisfies `q(Q) * Z_H(Q) = composition(Q)` and fits the fixed `L'_20` cap |
| C30 | exactly 44 batch-link roles authenticate the 98 function values and their 98 OOD degree corrections, add one independent FRI mask with coefficient exactly one, and bind the resulting width-197 Protocol-4 vector to FRI layer zero |
| C31 | exactly 44 FRI query roles verify 17 independent binary folds grouped as eight two-fold rounds plus one final fold, nine committed roots, deterministic uncommitted middle values, eight final QM31 coefficients, and the fixed named-round grinding schedule |
| C32 | strict proof-version framing, total length, transcript snapshots, query/rank manifests, opening directory/bodies, graph-derived role order, monotone affine-allocation closure trace, and authenticated ROM with minimal positive occurrence-anchor IDs have one canonical encoding with no missing, duplicated, reordered, aliased, or trailing bytes |
| C33 | all 210 graph-owned proof-carrier roles execute their assigned semantics; the reference verifier and CashVM consume the same single proof, protocol, and public statement; settlement additionally binds the exact final construction identity and selected linked bank |

## D. Fixed V17 construction target

| Item | V17 value | Claim class |
|---|---:|---|
| proof/product graph / frozen relation-construction descriptor | `17 / 16` | fixed graph / inherited relation |
| relation / sealed / quotient / evaluation rows | `2^18 / 2^19 / 2^20 / 2^24` | fixed graph |
| field stack | M31 / QM31 | constitutional |
| OOD function claims / Protocol-4 width | `98 / 197` | fixed graph |
| queries | 44 collision-free orbits | fixed graph |
| FRI | 17 binary folds in groups `[2,2,2,2,2,2,2,2,1]`; final degree 8 | fixed graph |
| named-round grind bits | `[9,0,3,26,20,18,16,14,12,10,8,6,4,26]` | fixed graph |
| graph-owned proof-carrier roles | 210 | fixed graph |
| Merkle parent roles | 52 | fixed graph |
| allocation closure | coordinatewise max opcost/required bytes, min capacity; canonical bootstrap and explicit no-change replay | fixed graph; final rows must come from exact BCHN assay |
| ROM identity / packing | minimal positive unsigned-BE ID from earliest static occurrence; minimum pages then semantic anchor | fixed graph |
| maximum canonical-proof envelope | 457,514 bytes | generated construction ceiling, not a measured proof |
| state / edge-history / nullifier depths | 128 bytes / 32 / 256 | fixed relation |
| classical work-factor gate | `epsilon(T)/T <= 2^-100` for every integer `1 <= T < 2^128` | must pass exact runtime theorem |
| transaction | at most 1,000,000 bytes; every script/push at most 10,000 bytes | constitutional; must be freshly measured |

The grind vector is ordered as:

```text
air:logup, air:composition, air:ood, fri:batch,
fri:fold:0, ..., fri:fold:8, fri:query.
```

This map contains no final protocol ID, construction ID, bank digest, proof
size, transaction size, or VM meter. Those values are exact generated evidence
for one fully linked identity and must be regenerated after every identity-bound
edit. V17 is not qualified while any theorem or product correspondence is
unresolved, conjectural, skipped, or cache-only.

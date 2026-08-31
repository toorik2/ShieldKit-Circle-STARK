# V17 implementation goal

Work only in `research-lanes/sealed-creation-log-circle-stark-v17`. Read
`AGENTS.md`, `RULES.md`, `V17-PLAN.md`, `THEOREM.md`, `COMPLETENESS.md`,
`ZK-MEMBRANE.md`, and `OBSERVER-LEDGER.md` before changing the construction.
Frozen V16 and imported FRI11 are evidence, not editable product surfaces. Only
the human user declares the named end complete.

## Goal

Deliver the smallest intelligible BCH-native Circle-STARK verifier that proves
the complete sealed-creation-log relation and settles it in one May-2026 BCH
consensus transaction. This is V17, not a compatibility wrapper around V16.

Keep the foundation fixed: transparent Circle FRI, SHA-256, M31 private
computation, QM31 security-critical challenges, at least 100 classical bits,
and only the statement “no known polynomial-time quantum break under the stated
assumptions.” QROM zero knowledge is a nonclaim.

Keep the constitutional product boundary: one transaction of at most 1,000,000
bytes; every locking or unlocking script and every pushed element at most
10,000 bytes; every required check miner-run under the May-2026 VM. The
100,000-byte standard relay target belongs to a later construction.

The proof must protect note ownership, identity and preimages, private amounts,
membership paths, change allocation, and every private relation trace. Net
deposits, payouts, miner fees, reserve change, TVL, public state, nullifiers,
and creation handles remain public by design.

## Design law

There is one doorway from private computation to settlement:

```text
private relation -> full-dimensional seal -> one whole quotient
                 -> one degree-corrected Protocol-4 batch
                 -> grouped Circle FRI -> one canonical proof
                 -> one pool settlement carrier
                    + byte-only, value-neutral BCH verifier carriers
```

One typed construction graph owns the protocol parameters, transcript,
commitment geometry, C1-C33 ownership, role order, allocation policy, and
canonical proof layout. The current fixed graph has:

- proof/product-graph version 17 over the frozen relation-construction
  descriptor version 16;
- 44 transcript-derived collision-free query orbits;
- 98 OOD function claims and one width-197 Protocol-4 batch;
- 17 independent binary FRI folds grouped into nine committed rounds;
- 210 graph-owned proof-carrier roles, including 52 Merkle parent roles; and
- a 457,514-byte maximum canonical-proof envelope.

The query schedule has one generic candidate body invoked for fixed ordinals
`0..43`. It reads the canonical 176-byte query frame once. This removes 44
unrolled copies; it does not remove or weaken any of the 44 semantic queries.

Every new abstraction must delete or unify machinery. Transaction builders
accept canonical proof bytes and public settlement data, never private notes,
paths, traces, polynomials, or openings. Proof size comes from the argument,
never ballast, padding, duplicated openings, or density tricks.

## Qualification gates

The target label is only `offline-theorem-qualified-candidate`, and only for an
exact generated identity. Qualification fails closed if any required theorem or
product row is `conjectural`, `unresolved`, `skipped`, or `cache-only`.

The goal is not complete until the exact final identity passes all of these:

1. **Complete relation:** C1-C33 are miner-run. No security-critical host-only
   assertion substitutes for a role.
2. **One transcript:** every root, OOD value, challenge snapshot, named-round
   nonce, final coefficient, query, rank, and opening directory has one causal
   position and one strict encoding.
3. **One proof system:** all 25 AIR residuals and the whole-quotient identity are
   checked at the sampled OOD point; 44 batch-link roles connect the canonical
   width-197 vector to FRI layer zero; 44 FRI roles check all grouped folds and
   the final polynomial.
4. **One Merkle language:** graph-fixed binary matrix trees, quartet-first FRI
   trees, exact cut frontiers, and every one of the 52 parent roles agree across
   TypeScript, Rust, and CashVM.
5. **ZK membrane:** every private column is independently sealed before
   commitment, the independent FRI mask has coefficient one, and the complete
   observer performs the rank-48 recovery experiment over the final carrier
   union.
6. **Exact theorem:** for every integer `1 <= T < 2^128`, the checked classical
   ROM bound satisfies `epsilon(T) / T <= 2^-100`, with every construction-to-
   theorem correspondence proved for the serialized product.
7. **Adversarial rejection:** altered statements, masks, OOD values, roots,
   openings, cut frontiers, folds, first/middle/last queries, digests, carrier
   placement, token authority, and value settlement reject at the applicable
   reference and miner-run boundaries.
8. **Exact BCH envelope:** fixed-point proof allocation, authenticated ROM,
   every script/input meter, and all three complete serialized transactions fit
   the constitutional limits. BCHN input assays and the separate transaction-
   level invariant checks must both pass; neither is described as a mined or
   mempool-accepted transaction.
9. **Version integrity:** the generated protocol identity binds the normative
   constitution, privacy membrane, completeness semantics, parameters,
   transcript, commitment cuts, roles, and proof encoding. The final
   construction identity additionally binds all three exact linked banks.
10. **Fresh evidence:** generate all three profile proofs without cache, replay
    them independently, run the exact observers and BCHN assays, verify source
    purity and the frozen V16 fingerprint, and record exact proof, transaction,
    identity, and meter digests.

Protocol IDs, construction IDs, bank digests, proof sizes, transaction sizes,
and VM measurements are generated evidence. Never hand-author them into a
claim, and never reuse a value from an earlier graph after an identity-bound
edit.

## Persistence and safety

Use the smallest useful falsifier while iterating. At every wall, record the
exact failing invariant, simplify the mechanism, and continue without weakening
the relation, privacy boundary, soundness floor, or product constraints. The
fresh all-profile qualification is an essential final gate, not a routine test.

Do not broadcast, fund, spend, expose secrets, or mutate chain state. Mainnet is
out of scope. If external authority is the only remaining blocker, finish and
preserve every offline gate first.

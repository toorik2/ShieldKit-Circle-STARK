# Goal prompt (paste into `/goal`)

Work only in `research-lanes/nonstandard-ideal-circle-stark`. Read
`AGENTS.md`, `RULES.md`, `GOAL.md`, `COMPLETENESS.md`, `PRIVACY-AUDIT.md`, and
`ZK-MEMBRANE.md` before changing the construction. Preserve FRI11 as defective
historical evidence; build a new, explicitly versioned successor. Only the
human declares the named end complete.

## Goal

Deliver the smallest intelligible Circle-STARK shielded-pool verifier that
satisfies the complete relation and privacy boundary—not a containment patch,
partial demo, or renamed weaker envelope.

Keep the foundation fixed: Circle FRI, SHA-256, QM31, at least 100-bit
soundness, and no known polynomial-time quantum break under the assumptions
actually stated. Keep the product boundary in `RULES.md`: one envelope-B
consensus transaction, at most 1 MB, each unlocking and redeem script at most
10,000 bytes, with every required relation check executed by the May-2026 VM.

The final proof must protect note ownership, identity and preimages, private
amounts, membership paths, and change allocation. Declared net deposits,
withdrawals, payouts, miner fees, and TVL remain public. Changing the amount tag
does not repair proof leakage and is not this task.

## Design law

There is one doorway from private computation to the transaction:

```text
private relation traces -> secret ZK seal -> one transcript
                        -> canonical proof bytes -> byte-only carriers
```

Zero knowledge is a compiler boundary, not another verifier bolted beside the
old ones. SHA, booleanity, membership, nullifier, and settlement stay clean
relation modules, but every witness-derived oracle crosses the same sealed
boundary before commitment or opening.

Every new abstraction must delete an old witness-to-transaction path. Remove or
absorb raw `openShaBit` openings, `occupancyBoolShardsFromNote`, carrier-side
witness interpolation, note-aware packaging, and any public randomizer described
as privacy. Transaction builders must accept canonical proof bytes and public
settlement data—not private notes or traces. Carriers only partition and
reassemble bytes. Do not retain the old machinery and wrap it in `sealTrace()`.

Beauty is fewer mechanisms, explicit ownership, and local reasoning in the
parts nobody screenshots. The VM is the paper. Proof size must come from the
argument, never ballast, padding, duplicated openings, or packaging tricks.

## Gates

The goal is not complete until all of these hold for the exact final artifact:

1. **Complete relation:** SHA message construction, schedule, rounds, output
   bindings, membership, nullifier, amounts, conservation, change, and every
   `COMPLETENESS.md` item are miner-run. No security-critical JS-only assertion.
2. **ZK membrane:** every private trace and auxiliary oracle is secretly
   randomized before commitment; quotient pieces and FRI are included; no mask
   is derived from public transcript data.
3. **Privacy argument:** the complete observation ledger is filled in and a
   Circle/QM31 simulator argument covers direct, adjacent, DEEP, composition,
   FRI, final-polynomial, authentication, and carrier-union views. State
   statistical, computational, ROM/QROM, and unresolved claims separately.
4. **Architectural simplification:** one logical transcript and query schedule;
   one canonical encoding; byte-only carriers; fewer independent privacy and
   opening mechanisms than FRI11.
5. **Adversarial evidence:** false statements and altered masks, openings,
   folds, roots, and carrier placement reject in both the reference verifier and
   the VM. The transaction-level interpolation extractor no longer recovers
   protected data; this test supports, but does not replace, the privacy proof.
6. **Security and product bounds:** the exact soundness worksheet remains at or
   above the floor; the exact serialized B transaction and every script satisfy
   the fixed bounds and VM-accept honestly.
7. **Version integrity:** a new proof version and construction identifier bind
   the exact rules, membrane specification, parameters, completeness list, and
   canonical encoding. Reconcile the existing rules-hash mismatch explicitly.
8. **Final evidence:** record exact proof bytes, transaction bytes, VM meters,
   privacy accounting, and all skipped broader checks. When separately
   authorized, land the exact candidate on Chipnet and verify the mined artifact
   end to end. Never target mainnet.

## Persistence

Work gate by gate with the smallest useful falsifier. At every wall:

1. record the exact number, failing invariant, and minimal reproducer;
2. decide which mechanism can be deleted, unified, or moved behind the membrane;
3. build and measure the next construction; and
4. continue without weakening the relation, privacy boundary, soundness floor,
   or product constraints.

Do not stop at shared-query containment, a failed extractor, a green local
suite, a type-check wall, a byte/op-cost miss, or “the lane cannot.” A wall is a
measurement, then the next construction. Avoid long non-essential tests while
iterating; perform exact end-to-end verification at the final gate.

Do not broadcast, fund, spend, expose secrets, or mutate chain state without
explicit authorization. If external authority is the only remaining blocker,
finish every offline gate, preserve a reproducible candidate, and request only
the missing authority.

End goal or bust: a complete, sealed, simpler verifier whose inner structure is
worthy of the security claim. Only the human says done.

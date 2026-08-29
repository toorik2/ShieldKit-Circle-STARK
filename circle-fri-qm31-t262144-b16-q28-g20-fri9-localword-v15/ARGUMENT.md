# Argument and construction identity

## v15 successor

```text
family = circle-stark-qm31-sha256-localword-v15
proofVersion = 15
relationConstructionVersion = 15
constructionId = 8d583c84312f7c79519b65bf374dc2ffb6597544a504d88a587c578f9bed2133
rulesSha256 = 49542e5f5fc9a13a16a3e205fe1408b1cfca49311c1f4e2613527d530fed9db5
```

The construction identifier is the SHA-256 of one canonical manifest. It binds:

- `RULES.md`;
- `ZK-MEMBRANE.md`;
- `COMPLETENESS.md`;
- the versioned successor construction document;
- v15 parameters and transcript;
- canonical proof and relation codecs;
- the named soundness worksheet;
- byte-only carrier encoding; and
- the canonical carrier allocation;
- the three deterministic profile verifier keys; and
- the ordered verifier-role manifest.

`test/local-word-construction-v15.test.ts` hashes every component from disk and
fails on any unversioned change. The manifest is intentionally not
self-referential.

The verifier key for an exact profile additionally contains the
statement-independent construction descriptor digest, preprocessed root, and
authorized verifier-bank digest. The proof header binds the descriptor digest;
the transcript binds the family construction ID; the pool covenant binds the
profile's ordered verifier bank.

## One argument

The private relation is compiled into one static word machine:

```text
note preimages + private paths + amount relation
                    |
                    v
     SHA-256/ALU table + copy/public LogUps
                    |
                    v
       sealed original and interaction traces
                    |
                    v
          one unsplit QM31 quotient
                    |
                    v
      one independently masked QM31 Circle FRI
                    |
                    v
       one canonical proof / 168 addressed byte slices
```

The lock does not trust a JavaScript SHA assertion. Twenty-five quadratic AIR
residuals enforce table lookup, whole-word copy, mask shape, public boundary,
and accumulator closure. SHA-256 schedule and rounds, note commitments,
membership, append, nullifier ownership, amount conservation, and change rules
are rows and copy classes in that machine. The public sparse-nullifier insertion
and value settlement are direct SHA-256/transaction checks in the same
consensus transaction.

All roots, challenges, openings, quotient checks, FRI folds, final
coefficients, grind, and query orbits belong to one transcript. Every matrix
and FRI path uses one canonical radix-4 schedule. Carriers neither interpret
nor manufacture proof values.

The complete numbered relation is [`COMPLETENESS.md`](COMPLETENESS.md).

## Soundness worksheet

All algebraic challenges are QM31. The base M31 representation does not reduce
challenge security to 31 bits.

| Event | Exact v15 count or bound | Bits |
|---|---:|---:|
| QM31 cardinality | about `2^124` | about 124 |
| false word permutation | degree 728,097 | 104.52 |
| word-product zero denominator | at most 786,432 terms | 104.41 |
| false lookup identity | at most 1,945,961 terms | 103.10 |
| lookup zero denominator | charged again at 1,945,961 terms | 103.10 |
| public-boundary identity | 34 terms | 118.91 |
| public-boundary zero denominator | 34 terms | 118.91 |
| AIR Horner cancellation | degree at most 24 | 119.41 |
| oracle-batch cancellation | degree at most 26 | 119.29 |
| FRI/query/grind | `28 * (4 - 1) + 20` | 104, conjectural |
| SHA-256 collision | classical ROM | 128 |
| conservative union | sum of the above event probabilities | **above 101.37** |

The union clears the constitutional 100-bit classical floor. The FRI row is an
explicit query conjecture, not a Stwo theorem and not a Lean proof. The hash
row is classical; no 100-bit post-quantum collision claim is made. The quantum
stance is only **no known polynomial-time quantum break under the stated
assumptions**.

## Zero knowledge

Every private M31 column is `w + Z_H r` with 262,144 fresh base-field mask
coefficients. Direct openings expose at most 28 points per original/current
column and 56 per predecessor column. Circle codes are MDS, so these
off-domain evaluation maps are surjective.

The quotient is unsplit and is determined at each query by the simulated sealed
AIR frame. One fresh uniform degree-`2^20` QM31 polynomial enters the FRI batch
with coefficient one. It isolates every later fold and final coefficient from
the trace masks.

The algebraic opening view is perfect honest-verifier zero knowledge
conditioned on nonzero denominators; the conservative bad-denominator distance
is below `2^-102.61`. Merkle commitments and Fiat–Shamir make the serialized
argument computational in the classical programmable random-oracle model.
QROM zero knowledge is unresolved. Full definitions and the observation ledger
are [`ZK-MEMBRANE.md`](ZK-MEMBRANE.md) and
[`OBSERVER-LEDGER.md`](OBSERVER-LEDGER.md).

For the PROMPT ledger: “adjacent” is exactly the 28 authenticated predecessor
openings of the global interaction matrix. V15 has no separate DEEP sample or
DEEP oracle, so that observer component is empty rather than silently omitted.
Composition and quotient values are determined by the simulated sealed frames;
the coefficient-one FRI isolator covers every fold and final coefficient; and
SHA-256 authentication plus the byte-for-byte carrier union are included in the
computational serialized view.

## Product bounds

The fixed v15 geometry has:

- relation `2^18`, sealed bucket `2^19`, quotient bucket `2^20`, LDE
  `2^24`;
- 28 collision-free orbits, grind 20, nine FRI layers, eight final QM31
  coefficients;
- 168 verifier roles;
- a 340,490-byte exact upper bound for every profile-2 canonical proof; and
- a measured maximum-proof transaction of 980,292 bytes, with maximum redeem
  9,435 bytes and maximum unlocking 9,710 bytes.

The fresh profile-2 qualification artifact is 327,674 proof bytes and produces
a 967,476-byte transaction, leaving 32,524 bytes. Its maximum verifier, redeem,
and unlocking sizes are 9,383, 9,435, and 9,699 bytes. All 168 inputs accept;
the maximum measured operation cost is 7,321,148 at
`merkle:preprocessed:0`, and the tightest operation-cost slack is 19,905 at
`merkle:interactionGlobal:2`.

## Adversarial evidence

Targeted tests and the exact fresh artifact cover:

- false public statements;
- altered original and interaction openings;
- altered quotient/FRI-mask rows;
- altered composition partials;
- altered FRI folds, roots, final data, transcript stages, and queries;
- changed public-boundary inverses;
- sparse-nullifier replay and path mutations;
- changed carrier position, role, slice length, and proof bytes;
- strict canonical decoding and reference-verifier cross-checks; and
- observer extraction plus masking ablation.

The artifact audit ran root, opening, FRI-mask, fold, false-statement, and
carrier-placement mutations against the same fresh proof and complete
transaction used for the product measurement. Each rejected at the reference
boundary and at a production VM role. Exact outcomes are recorded in
[`survey/artifacts/local-word-v15-offline/meters.json`](survey/artifacts/local-word-v15-offline/meters.json).

## Reconciled FRI11 metadata

Historical FRI11 named:

```text
circle-fri-m31-qm31-t64-b16-q36-g20-fri11-
5d7bac107945d433cf00d8a3affd875f07587f33e03d5551c432ca8f86453f54
```

That suffix did not match the then-live imported `RULES.md` hash
`bc64c18b...` and does not match the minimal v1 constitution hash
`49542e5f...`. FRI11 is preserved under its historical, mismatched metadata
because silently renaming it would manufacture provenance. It also remains
privacy- and completeness-defective. V15 resolves the mismatch only for the
new family: its construction manifest binds the exact live rules hash above.

## Final status

V15 is an offline-qualified sealed successor candidate. The fresh proof,
exact 168-input VM-accepted transaction, observer ledger, mutation matrix, and
requirement-by-requirement audit are recorded in
[`survey/artifacts/local-word-v15-offline/`](survey/artifacts/local-word-v15-offline/).
It is not yet the named end: Chipnet mining and mined-artifact verification
remain a separate, explicitly authorized action, and only the human declares
completion.

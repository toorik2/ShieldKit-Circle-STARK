# V17 theorem and correspondence ledger

**Status: the static ledger is deliberately fail-closed; only an exact runtime
certificate may promote its five product rows. The committed qualification
receipt indexes the promoted result for one exact identity.**

This document separates the mathematical reduction from the serialized BCH
product. A row is qualifying only when its status is `cited` or `proved`.
`conjectural`, `unresolved`, `skipped`, and `cache-only` are hard stops. The
machine-readable static mirror is `V17ProductionAssurance/v1` in
`src/assurance/v17-production-theorem.ts`.

That static export intentionally leaves every artifact-dependent product row
`unresolved`; source code alone cannot truthfully prove what a future proof,
linked bank, ROM page, or transaction executes. The only path to
`qualified: true` accepts exact runtime evidence, replaces precisely those five
rows, re-evaluates all 16 assurance rows and 14 randomized rounds, and binds the
result to the protocol, construction, linker, final infrastructure, fresh proof
set, BCHN assays, privacy ledger, and adversarial ledger. This is fail-closed
staging, not a contradiction and not generic qualification of other artifacts.

The cited source is *S-two: Simple STARKs from Circle FRI* (ePrint 2026/532).
The local lemmas below establish construction-specific correspondences; they do
not amend the cited theorems.

## 1. Fixed notation

- `q = 2^31 - 1`, `F_q = M31`, and `F = QM31`.
- `H` is the canonical relation coset with `N = 2^18` points.
- The evaluation domain has `2^24` points, hence rate `rho = 2^-4` and minimum
  distance `delta = 1-rho`.
- The proximity parameter is `theta = 181/256`; `alpha = 1-theta = 75/256`.
- `L'_n` is the S-two circle FFT space of dimension `2^n` and degree bound
  `2^(n-1)` under the convention used by the implementation.
- `Z_H` is the relation-coset zerofier, of degree `N/2`.
- All challenge probabilities use the exact maximum mass of four independent
  256-bit SHA-256 reductions modulo M31, never an idealized `1/|F|` when the
  distinction matters.

The security claim here is classical ROM knowledge soundness, conditional on
the named correspondences and SHA-256 assumptions. The quantum statement is
only “no known polynomial-time quantum break.” This document makes no QROM
zero-knowledge reduction.

## 2. Exact cited formulas

For S-two Theorem 15, equation (53), with `alpha = 1-theta`, the combinatorial
Johnson list bound is

```text
l(theta) = (alpha - (1-delta)) / (alpha^2 - (1-delta)).
```

Theorem 15 equation (54) is, for every nonzero table of height `N_t`,

```text
1-theta > (1-delta) * (1 + 2/N_t).
```

The factor `(1 + 2/N_t)` is **linear, not squared**. V17 checks this exact
inequality. For the augmented table below, `N_t=N`; its multiplicities are zero
and therefore below the characteristic.

Theorem 15's three printed round errors are

```text
eps_1 <= l(theta) * r *
         (k_in + k_out + sum_t (r_t+s_t)N_t) / |F|,

eps_2 <= l(theta) *
         (2 + max_t(k_t+r_t+s_t)) / |F|,

eps_3 <= l(theta) *
         (1 + deg(A)N) / |C(F) \ C(F_q)|.
```

Here source-symbol `r` is the maximum message-vector dimension, not the seal
randomizer used later. V17 replaces a uniform field factor by the exact
SHA-256-to-QM31 maximum mass where required.

S-two Theorem 19 charges the cross-domain batch by the leading factor `M-1`,
each binary fold by leading factor `3`, and the query phase by
`(1-theta)^s`. The implementation uses the printed Guruswami-Sudan list bound
and domain-specific rate correction, with outward-rounded exact rationals.

Protocol 4 includes, for every claimed function `f_i`, both

```text
f_i                    and                    (f_i-v_i)/v_Q.
```

Theorem 21 inherits Theorem 19's round errors when equation (80) holds:

```text
1-theta > (1-delta) * (1 + 2/N_i).
```

Again, this factor is linear.

Finally, S-two Theorem 22, equation (89), gives for an `R`-round IOP and a
`T`-query random-oracle attacker

```text
eps(T) <= (T+R) * max_i(eps_i) + 3*(T^2+1)/2^256.
```

Dividing by `T` gives the per-query work-factor expression used by V17:

```text
(1+R/T)e + 3*(T+1/T)/2^256.
```

Convexity makes the checked endpoints `T=1` and `T=2^128-1` sufficient for
the configured integer range.

## 3. The custom first reduction

The existing relation does not enter Protocol 1 as an ordinary generic LogUp
instance. It first performs three construction-specific randomized reductions.
They are charged once by `V17InteractionReduction/v1`; after they succeed, the
remaining AIR has no outstanding use or yield messages.

### Lemma L1 — local lookup running sum

For each active row there are eight 6-tuples `a_i`, and the fixed universal
4-bit table has exactly 1,841 legal tagged tuples `t_j` with trace-provided
multiplicities `m_j`. Let `D(x)` be
the independently challenged affine tuple compression. Residuals 0–7 enforce
the eight access recurrences and residual 8 enforces the cyclic table
recurrence. Its terminal equality is exactly

```text
sum_i 1/D(a_i) - sum_j m_j/D(t_j) = 0.
```

After clearing denominators, unequal multisets give a nonzero challenge
polynomial; zero denominators are charged separately. Thus, outside those
Schwartz-Zippel events, the running sum proves equality of the access and
fixed-table multisets. The exact factor inventory is

```text
K = 8N + 1,841 = 2,098,993.
```

This is the checked correspondence for `local-word-air.ts` residuals 0–8.

### Lemma L2 — compiled word-copy grand product

Each row has three word ports: `a`, `b`, and `out`. Residuals 9–11 recompute
each port's eight-limb random compression. For a compiled identity label `id`
and permutation label `sigma`, define

```text
W(label,c) = gamma_copy + eta_id*label + c.
```

Residuals 12–14 multiply the three ratios in the fixed compiled permutation
order, and residual 15 requires the terminal product to be one. Consequently,
if no denominator or compression collision occurs,

```text
product W(id,c) = product W(sigma,c),
```

so sources, rotations, digest handoffs, and equality-class word copies agree.
There are exactly

```text
S = 3N = 786,432
```

compiled slots. The limb-compression, product-identity, and denominator events
are separately included in the first-reduction degree charge.

### Lemma L3 — public boundary reduction

The public statement owns eight digest words. After the boundary challenges
are derived, the verifier computes their eight affine factors, checks each
serialized inverse, and recomputes their claimed sum. Those inverses and that
sum are absorbed before the interaction roots and constraint challenge.

At the eight fixed statement rows, residual 23 checks the witness word's
inverse against the same `(id, eight limbs)` fingerprint. Residual 24 is the
cyclic access-sum recurrence, subtracting the public claimed sum at its fixed
impulse row. Its terminal zero therefore equates the witness boundary multiset
with the verifier-owned eight public words, outside the separately charged
fingerprint and denominator events. Public expected words never enter a
proof-controlled preprocessing root.

### Lemma L4 — augmented `r=s=0` flat AIR

Condition on successful L1–L3 reductions and their committed interaction
oracles. The residual relation is one table of height `N` with exactly 25
quadratic residuals:

```text
43 preprocessed base functions
+ 34 original base functions
+ 17 interaction functions
+ 3 cyclic-predecessor interaction functions.
```

There are no remaining Protocol-1 input/output messages and this augmented
table has `r_t=s_t=0`, maximum message dimension one, and maximum multiplicity
zero. Protocol-1 composition and OOD rounds apply to this residual relation.
The custom first-round error is not counted again as generic LogUp.

`V17InteractionReduction/v1` records the direct event total `6,557,314` and
uses the deliberately larger S-two-shaped envelope

```text
9 * (8 + 16N) = 37,748,808
```

times the Johnson list bound and exact challenge maximum mass.

## 4. Seal and whole quotient

### Lemma L5 — full-dimensional affine-fibre seal

The trace interpolant `w` lies in `L'_18`, which has dimension `N`. Sample
`r` uniformly from an independent copy of `L'_18` and commit

```text
s = w + Z_H*r.
```

Restriction `L'_19 -> F^H` is surjective because `L'_18` already interpolates
arbitrary values on `H`. Its kernel therefore has dimension `2N-N=N`.
Multiplication by nonzero `Z_H` injects `L'_18` into that kernel, also with
dimension `N`; hence

```text
ker(restrict_H) = Z_H * L'_18.
```

It follows that `s|_H=w` and that uniform `r` makes `s` uniform over the entire
affine fibre of functions restricting to `w`. This is an exact algebraic seal,
not a sparse masking heuristic.

### Lemma L6 — one whole quotient

Let `R_0,...,R_24` be the residuals evaluated on the sealed functions and let

```text
C = sum_j alpha_constraint^j R_j.
```

Every residual is at most quadratic. Since a valid trace makes every `R_j`
zero on `H`, `Z_H` divides `C` in the circle coordinate ring. V17 commits one
whole quotient

```text
q = C/Z_H
```

and serializes no composition partials. The exact degree certificate is

```text
maximum sealed degree       N       = 262,144
maximum composition degree  2N      = 524,288
maximum quotient degree      3N/2    = 393,216
L'_20 strict degree cap      2N      = 524,288.
```

Thus the quotient fits strictly below the committed `L'_20` cap.

## 5. OOD AIR and Protocol-4 batch

### Lemma L7 — singleton OOD identity and width 197

At the sampled `Q in C(F)\C(F_q)`, the proof claims the following 98 values in
one canonical order:

```text
43 preprocessed + 34 original + 17 interaction + 3 predecessor + 1 quotient.
```

The singleton `ood-air` role recomputes all 25 residuals, their alpha-mix
`C(Q)`, and checks

```text
q(Q) * Z_H(Q) = C(Q).
```

No partial sidecar is permitted.

For `f_0,...,f_97`, define `A_beta(P)=sum_i beta^i f_i(P)`. With an independent
committed mask and Protocol 4's single-point zerofier `v_Q`, the canonical
degree-corrected function is

```text
H_beta(P) = mask(P)
          + beta*A_beta(P)
          + beta^99*(A_beta(P)-A_beta(Q))/v_Q(P).
```

This is precisely the random combination of

```text
[mask, f_0,...,f_97, (f_0-f_0(Q))/v_Q,...,(f_97-f_97(Q))/v_Q].
```

Therefore `M=1+98+98=197`, and Theorem 19's batching factor is exactly
`M-1=196`. Mask and `f_0` deliberately use different beta powers; sharing
coefficient one would create an identically cancelling direction. Exactly 44
`batch-link-query` workers must authenticate queried function values and link
this expression to FRI layer zero.

## 6. Seventeen binary folds in nine groups

### Lemma L8 — deterministic virtual intermediates

The degree descent consists of 17 binary S-two folds. The first eight on-chain
groups each execute two adjacent binary folds with independent challenges
`alpha[g,0]` and `alpha[g,1]`; the final group executes one. The middle oracle
inside a two-fold group is the deterministic result of the first fold. It is
neither prover-selected nor separately committed.

For each two-fold group, sequential substitution gives exactly the grouped
four-way evaluation checked by the verifier. A false grouped identity implies
a false first or second binary identity, so its round error is bounded by the
sum of the two adjacent Theorem-19 binary-fold errors. The final group retains
the seventeenth error unchanged. This yields challenge counts

```text
[2,2,2,2,2,2,2,2,1]
```

and nine committed FRI roots, without deriving the second challenge by
squaring the first.

## 7. Fixed-arity Merkle forest and BCS

### Lemma L9 — abstract partial decommitment

Fix a descriptor before any challenge: domain label, row width, row count,
tree key, and the complete leaf-to-root arity vector. Leaves and internal nodes
use disjoint tags; binary and quartet nodes use different tags and fixed child
counts; the descriptor-derived key namespaces every node.

Suppose two accepted partial openings under one fixed root disagree on a leaf.
Following both computations upward, choose the first equal parent whose child
encodings differ. Either the differing leaf encodings hash equally or two
distinct, injectively encoded internal nodes hash equally. In both cases one
obtains a SHA-256 collision. Thus all accumulated answers under that root define
one consistent partial oracle, except with SHA-256 binding failure.

A fixed forest is the disjoint union of this argument over its descriptor-keyed
roots. Consequently the ordinary BCS partial-decommitment step applies to the
abstract v17 forest; no proof-selected arity, key, label, index, or merge rule is
admitted.

This lemma alone does **not** qualify the production codec. The static ledger
therefore keeps its product row unresolved until one runtime certificate
supplies exact byte grammar and cross-language evidence that:

1. roots are absorbed before their dependent challenges;
2. transcript-derived indices and overlap ranks are recomputed, never chosen;
3. leaf, sibling, and frontier lengths are exact, with no trailing bytes;
4. every binary/quartet boundary and cut is graph-derived;
5. all 44 query workers and every cut worker consume the same openings; and
6. TypeScript, Rust, and CashVM agree byte for byte.

S-two Remark 23's informal mixed-domain observation is not treated as this
product proof. For the receipt identity, the runtime path promotes
`product-mixed-merkle-codec` only after strict TypeScript decoding and every
final graph-owned mixed-Merkle CashVM role accept the same byte-exact fresh
artifacts. The static source export remains unresolved so that this conclusion
cannot leak to a different proof set.

## 8. Transcript causality and section semantics

Every proof section is consumed exactly once with one explicit mode:

| Mode | Meaning |
|---|---|
| `transcript-absorb` | prover message absorbed before the phase challenge |
| `derived-snapshot` | checked cache of an already-derived challenge/digest/schedule; never reabsorbed |
| `named-round-pow` | nonce used only by that named round's PoW check |
| `terminal-strict-codec` | post-query strict-codec field; no later challenge |

In particular:

- interaction challenges are derived before public inverses and claimed sum;
- those public fields and both interaction roots are absorbed before the
  constraint challenge;
- challenge and digest frames are checked snapshots, not transcript messages;
- each nonce is bound only through its named round and cannot migrate;
- `totalLength`, the final opening directory, and opening bodies occur after
  query derivation, are strict-codec checked, and precede no challenge; and
- query/index/rank frames are checked derivation caches after the last
  challenge.

This removes both causal cycles: proof-selected boundary values cannot precede
their challenges, and a query-dependent serialized length cannot affect the
query that determines it.

## 9. Role and obligation preservation

The meanings and dependency edges of C1–C33 are unchanged. Only verifier-role
ownership is refined:

- one `ood-air` role owns C12–C22, C28, and C29;
- 44 `batch-link-query` roles own C24 and C30;
- C31 remains with the 44 FRI query workers; and
- all other obligation owners remain as before.

The former 44 direct-query AIR roles do not exist. AIR algebra and the whole
quotient are checked once at OOD; per-query work is only the Protocol-4 batch
link. This is the architectural reduction, not an omitted check.

## 10. Qualification ledger

The first eleven rows are artifact-independent. Their status is the same in the
static and runtime ledgers:

| Row | Status | Boundary |
|---|---|---|
| S-two formulas | cited | Theorems 15, 19, 21, 22; equations 53, 54, 80, 89 |
| lookup running sum | proved | L1, algebraic model |
| word-copy grand product | proved | L2, algebraic model |
| public boundary | proved | L3, algebraic model |
| augmented `r=s=0` AIR | proved | L4, post-first-reduction model |
| full-dimensional seal | proved | L5, circle-space model |
| whole quotient | proved | L6, circle coordinate ring |
| OOD sampler | proved | exact finite sampler certificate |
| width-197 Protocol-4 batch | proved | L7, algebraic model |
| grouped virtual FRI | proved | L8, adjacent-error union |
| fixed-arity Merkle forest | proved | L9, abstract hash model |

The remaining five rows are necessarily two-stage:

| Product row | Static export | Exact receipt runtime |
|---|---|---|
| first-reduction transcript | unresolved | proved by fresh Rust proof, strict TypeScript replay, and transcript-bound CashVM inputs |
| singleton OOD AIR role | unresolved | proved by the graph-owned role in every exact profile envelope |
| 44 batch-link roles | unresolved | proved by all graph-owned workers under the final infrastructure identity |
| grouped-FRI transcript | unresolved | proved by replay of 17 independent challenges in nine graph-owned rounds |
| mixed-Merkle codec | unresolved | proved by strict codec replay and every final graph-owned Merkle role |

The static `V17_PRODUCTION_THEOREM` therefore remains intentionally
`qualified: false`. The exact runtime certificate may be
`offline-theorem-qualified-candidate` only when all five evidence records are
present, all 16 rows are then cited/proved, all 14 randomized rounds are bound
to the same proof product, and both checked work-factor endpoints pass. Its
claim is:

```text
epsilon(T) / T <= 2^-100 for every integer 1 <= T < 2^128.
```

The identity and evidence digests for that promotion are recorded in
[evidence/v17-offline-qualification-receipt.json](evidence/v17-offline-qualification-receipt.json).
For protocol `9195e2b02944a9355c50a76e5ddc33e2e03ba48375e95932bb0713933e7ebc96`
and construction
`c434ed36bf04d8265ec6d0e447f69cd7a437baf91bcc6eab6eb0ff5f9cbe62e1`,
the runtime theorem evidence digest is
`92ee21cabdf9cc1cfd5dc5c32df3df422b19c78a2c3ef0bb051a119d0979a482`.
They qualify only that receipt identity. Cached measurements, skipped suites,
numerical worksheets, host-only verification, or a different proof set cannot
promote the static rows.

The theorem result remains a classical programmable-ROM transcript and
knowledge-soundness statement under the named SHA-256 and correspondence
assumptions. It makes no complete honest-verifier, statistical, computational,
or QROM zero-knowledge claim; the quantum statement remains only that no
polynomial-time quantum break is known under the stated assumptions.

# ZK membrane — v15 sealed-oracle contract

**Normative status:** frozen membrane for proof format 15. Implementation and
qualification evidence live in [`STATUS.md`](STATUS.md), which is deliberately
outside the construction identity. FRI11 remains defective historical
evidence.

This document fixes one doorway from private computation to consensus:

```text
private relation traces -> secret seal -> one transcript
                        -> canonical proof bytes -> byte-only carriers
```

It does not alter the relation, privacy boundary, or product constraints in
[`RULES.md`](RULES.md).

## 1. Privacy experiment

Let `P` contain the public statement and intentionally public transaction data.
Let `W` contain note ownership, note identity and preimages, private amounts,
private note-tree paths, and change allocation. The observer receives every
byte of the final transaction and anything efficiently derivable from it:
roots, openings, paths, indices, folds, final coefficients, scripts, outputs,
and the union of all carrier inputs.

The goal is to simulate this view from `P` alone. Net deposits, reserve deltas,
withdrawal payouts, BCH miner fees, the public nullifier and its public sparse
insertion path, and pool TVL are intentionally public. Protocol, developer,
operator, treasury, and relayer fees are forbidden by the relation.

## 2. Ownership rule

The implementation has four conceptual types:

```text
PrivateTraceSet --seal--> SealedOracleSet --prove--> CanonicalProof
CanonicalProof --encode--> ProofBytes      --slice--> CarrierChunk[]
```

- Relation code may construct private traces and public preprocessing.
- Only the seal may turn a private trace into a committed oracle.
- The quotient and FRI code consume sealed oracles, never raw witness traces.
- The encoder consumes one canonical proof object.
- Transaction code consumes canonical proof bytes and public settlement data.
- A carrier only owns one contiguous byte slice. Public values and disabled
  sequences locate that slice; they contain no proof or witness value. A
  carrier cannot accept a note, choose a query, interpolate a value, or
  manufacture proof data.

The removed FRI11 paths—`FriAuth`, witness OTP, `openShaBit`,
`occupancyBoolShardsFromNote`, note-aware carrier interpolation, and the
duplicate trace tree—are not compatibility APIs for v15.

## 3. Exact v15 seal

The relation domain `H` is the canonical Circle coset with `2^18` rows. The
evaluation domain `D` is the canonical `2^24`-point Circle coset. The quotient
builder rejects if the trace zerofier vanishes anywhere on `D`, enforcing
`H ∩ D = ∅` for the implemented domains.

For every private M31 trace column `w`, the prover commits to

\[
\widehat w = w + Z_H r,
\]

where `r` is a uniform Circle polynomial with `2^18` independently sampled M31
coefficients. Every column and every proof uses fresh `getrandom` entropy.
Original and interaction traces are sealed independently. Public preprocessing
is deterministic and is not counted as private entropy.

Circle codes are generalized Reed–Solomon codes and are MDS. Therefore, for
any set of at most `2^18` distinct off-domain points, evaluation of `r` onto
those points is surjective. Since `Z_H` is nonzero there, the corresponding
opened values of `w + Z_H r` are uniform and independent of `w`. This is the
Circle-domain form of the ordinary witness-randomization lemma.

The exact direct view is:

| Oracle | Private width | Public locations per column | Secret dimensions per column |
|---|---:|---:|---:|
| original | 34 M31 | 28 current points | 262,144 M31 |
| interaction | 56 M31 | 28 current points | 262,144 M31 |
| interaction-global | 12 M31 | 28 current + 28 predecessor points | 262,144 M31 |
| quotient | 1 QM31 | 28 current points | none needed; determined by the sealed AIR openings |
| FRI isolator | 1 QM31 | 28 current points, then the FRI view | 1,048,576 QM31 |

The 28 query orbits and all predecessor locations are collision-free by the
transcript sampler and are checked by the VM.

## 4. Quotient and FRI

The construction has one unsplit quotient. At an opened point it is exactly

\[
q(x) = C(\widehat w(x),\widehat w(g^{-1}x),P)/Z_H(x).
\]

It contributes no witness linear form beyond the already opened sealed trace
values. There is no quotient decomposition, quotient pad, or separately
randomized component whose simulator could disagree with its recombination.

Before the batching challenge, the prover commits to one fresh uniform QM31
polynomial `R` of degree below `2^20`. The FRI layer-zero polynomial is

\[
B = \operatorname{Horner}_\beta(\text{sealed originals},
    \text{sealed interactions},q) + R.
\]

The coefficient of `R` is exactly one. It cannot vanish for an unlucky
`beta`, and it is independent of all trace seals and the quotient. Conditional
on the directly opened values of `R`, adding this uniform polynomial makes the
remaining batch polynomial, folds, and final polynomial independent of the
earlier witness-dependent oracles. This is the decoupling step that prevents
FRI folding from consuming the trace-mask entropy.

## 5. Simulator and claim boundary

For the ideal algebraic IOP, conditioned on nonzero LogUp denominators, an
honest-verifier simulator:

1. samples the direct sealed-oracle openings uniformly using the Circle MDS
   evaluation map;
2. computes public-boundary values and the unsplit quotient from those sampled
   openings;
3. samples the FRI-isolator values and a compatible uniform batch polynomial;
   and
4. runs the ordinary FRI transcript on that polynomial.

This gives **perfect honest-verifier zero knowledge for the algebraic opening
view**. Counting every possible implemented lookup, permutation, and public
boundary denominator gives a conservative abort probability below
`2^-102.61`; without conditioning, the statement is statistical to that
distance.

The serialized non-interactive artifact has a different claim boundary:

| Layer | v15 claim |
|---|---|
| Algebraic opening view | perfect HVZK conditional on nonzero denominators |
| Honest execution including bad-challenge abort | statistical distance below `2^-102.61` |
| SHA-256 Merkle commitments | computational hiding/binding in the classical random-oracle model |
| Fiat–Shamir compilation | computational zero knowledge in the classical programmable ROM |
| QROM compilation | unresolved; no QROM zero-knowledge theorem is claimed |
| Quantum stance | no known polynomial-time quantum break under the stated hash/field assumptions |

The Circle MDS step is supported by *Circle STARKs*, ePrint 2024/278. Witness
randomization, the independent FRI mask, and the warning about quotient
decomposition follow Haböck and Kindi, *A note on adding zero-knowledge to
STARKs*, ePrint 2024/1037. The multiplicative-domain formulas in that note are
not copied as Circle theorems; only the MDS evaluation argument and isolator
argument are adapted here.

## 6. Complete observer ledger

The authoritative machine-readable ledger is produced by
`analyzeLocalWordObserverTransaction` from the serialized transaction—not from
prover objects. It extracts and reassembles all 168 carrier slices, decodes the
one proof, and records:

- five relation/auxiliary roots and every matrix authentication node;
- every original, interaction, predecessor, quotient, and FRI-mask opening;
- every FRI layer value, authentication node, and final coefficient;
- all transcript challenges, digests, query ranks, and opening directories;
- the proof-length sequence plus every public carrier prefix and jump index;
- the public sparse-nullifier path and settlement outputs; and
- the byte-for-byte carrier union.

The old interpolation adversary is run against this view. With masking removed,
the ablation recovers the protected trace; with the v15 seal, the observer has
28 openings against 262,144 fresh dimensions per original column and reports no
protected-trace recovery. This test is evidence for the implemented data flow;
the simulator argument above is the reason for privacy.

## 7. Fail-closed rules

The construction rejects:

- raw trace rows or unsealed LDE values in any proof or carrier;
- public-transcript-derived values described as privacy randomness;
- reuse of mask coefficients across columns or proofs;
- a transaction builder that accepts notes, paths, traces, or polynomials;
- a second query schedule, trace opening helper, or proof encoding;
- a proof-length-specific verifier lock or uncommitted carrier coordinate;
- quotient decomposition without a simulator for the exact split;
- a FRI batch in which the independent mask coefficient can be zero;
- byte-substring privacy tests used as a substitute for representation-level
  analysis; and
- changing the amount commitment and calling that a proof-privacy repair.

## 8. Promotion gate

Proof version 15 is eligible to become the candidate construction only when:

1. the construction identifier binds `RULES.md`, this file,
   `COMPLETENESS.md`, parameters, transcript, and canonical codecs;
2. fresh randomness, masking ablation, false-statement, altered-opening,
   altered-mask, root, fold, and carrier-placement tests reject as specified;
3. the reference verifier and every VM role accept the same fresh proof;
4. the exact 168-input transaction remains within all fixed bounds; and
5. exact proof bytes, transaction bytes, VM meters, observer ledger, and
   skipped broader checks are recorded.

Chipnet landing is separate and requires explicit authorization. Until the
offline gates are complete, the honest label is **v15 sealed successor
candidate**, not the named product.

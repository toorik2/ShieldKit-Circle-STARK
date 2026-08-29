# Completeness list — v15 successor

**This file is part of the construction identity.** Removing or weakening a row
creates a new family. The exact relation remains [`RULES.md`](RULES.md):
one envelope-B consensus transaction, one deposit note or one consumed note
with at most one private change note, and no transfer, merge, split, batching,
administration, escape path, or protocol fee.

FRI11 is retained below as defective historical evidence. It is not v15.

## A. Public settlement checked by the VM

| ID | Required transition | Exact v15 rule |
|---|---|---|
| C1 | one action | reserve delta is nonzero and selects exactly deposit, full withdrawal, or withdrawal-with-change |
| C2 | covenant continuity | pool lock, CashToken category/capability/amount, and pool instance roll forward exactly; the selected profile bank is recreated exactly |
| C3 | sequence and counters | sequence increments once; only the selected deposit or withdrawal counter increments |
| C4 | carrier neutrality | every selected verifier-bank input and output has identical lock, value, and token; the other two standing banks remain unspent |
| C5 | deposit value | transparent funding supplies public deposit plus BCH miner fee; the created private note amount equals the reserve increase |
| C6 | withdrawal value | reserve decrease equals public payout plus BCH miner fee; no other fee output is permitted |
| C7 | public payout | payout is positive, token-free, and its locking-bytecode digest is bound into the proof statement |
| C8 | nullifier state | the public nullifier opens an unused leaf and updates the same 256-level sparse SHA-256 path to the used leaf |
| C9 | verifier bank | the pool authorizes three deterministic profile-bank digests; the proof profile selects the matching 167 locks, values, sequences, and exact order |

The settlement lock derives the public statement and miner fee from the
transaction itself. JavaScript's `deriveLocalWordPublicSettlement` is a
reference mirror, not the consensus authority.

## B. Private relation compiled into the sealed AIR

| ID | Required relation | Exact v15 rule |
|---|---|---|
| C10 | one machine | every private computation is a row of the pinned eight-operation word machine: input, mask, constant, rotate, xor, and, add, or nonzero |
| C11 | universal ALU | eight four-bit limbs per word make table accesses; the lookup LogUp proves every access belongs to the fixed 1,841-row table |
| C12 | copy integrity | one word-compressed permutation binds every source use, rotation, digest handoff, public boundary, and equality class |
| C13 | SHA-256 | message padding, schedule, all 64 rounds, chaining, and digest output are ordinary rows of C10–C12 |
| C14 | note identity | `amountCommit = SHA256(tag16 || amount_i64le || rho32)` and `leaf = SHA256(amountCommit || rho || owner)` |
| C15 | deposit append | the created leaf and private 16-level path open the old empty leaf and bind the new public note root |
| C16 | spend membership | the spent leaf and private 16-level path bind the old public note root |
| C17 | nullifier ownership | `nf = SHA256(poolInstanceId || owner || rho)` binds the public nullifier |
| C18 | full withdrawal amount | spent note amount equals the public reserve decrease, which settlement C6 fixes to payout plus miner fee |
| C19 | change conservation | spent amount equals public reserve decrease plus private change amount, without signed overflow |
| C20 | change policy | change is positive, reuses the spent owner, has a different rho, and is appended on a private path to the new public note root |
| C21 | statement boundary | every statement-owned word is bound through the public-boundary LogUp and verifier-checked public inverses |

Amount, rho, owner, spent leaf, created leaf, both private note paths, path
directions, and change allocation are inputs to this relation but are not public
statement fields.

## C. Proof correspondence checked by the VM

| ID | Required proof check | Exact v15 rule |
|---|---|---|
| C22 | construction | proof version 15, profile, construction digest, pinned program descriptor, and preprocessed root match the verifier bank |
| C23 | secret seal | all original and interaction columns are committed only after independent `w + Z_H r` sealing |
| C24 | one transcript | construction, public statement, roots, challenges, public inverses, FRI roots, final coefficients, grind, and queries form one domain-separated transcript |
| C25 | one schedule | 28 collision-free first-fold orbits own all current, predecessor, quotient, mask, and FRI openings |
| C26 | authentication | every opened matrix and FRI row reaches its committed root through the canonical radix-4 multiproof and fixed frontier schedule |
| C27 | AIR composition | all 25 quadratic residuals are evaluated and mixed at every query; the three serialized partials recombine to the same composition |
| C28 | quotient | one unsplit degree-bounded quotient satisfies `composition = quotient * Z_H` at every query |
| C29 | FRI isolation | a fresh degree-`2^20` QM31 mask enters the batch with coefficient exactly one |
| C30 | oracle batch | 9 packed original, 17 packed interaction, and one quotient value are Horner-batched with C29 and equal FRI layer zero |
| C31 | Circle FRI | nine committed layers perform eight radix-4 folds and one binary fold, end in eight checked QM31 coefficients, and use grind 20 |
| C32 | canonical bytes | strict proof framing has no alternate encoding, trailing bytes, repeated roots, or prover-chosen geometry |
| C33 | byte-only carriers | 168 inputs partition the canonical proof once, contiguously and in order; input zero binds header length, and every stable role lock derives its own slice from the committed length and canonical allocation |

The reference verifier independently performs C22–C32. Consensus performs
C1–C9 and C21–C33 across the 168 inputs. C10–C20 reach consensus through the
AIR, quotient, batch, and FRI checks rather than through a trusted host
assertion.

## D. Fixed v15 parameters and bounds

| Item | v15 value | Claim boundary |
|---|---:|---|
| base/trace field | M31 | arithmetic representation |
| challenge, composition, quotient, FRI field | QM31, about 124 bits | field cardinality |
| relation rows | `2^18` | fixed |
| sealed degree bucket | `2^19` | fixed |
| quotient degree bucket | `2^20` | measured proof must not exceed |
| evaluation rows | `2^24` | fixed |
| effective FRI blowup | 16 | fixed |
| unique query orbits | 28 | fixed |
| grind | 20 | fixed |
| query worksheet | `28 * (4 - 1) + 20 = 104` bits | named conjecture |
| conservative named-event union | above 101.37 bits | classical-ROM worksheet; FRI term remains conjectural |
| hash | SHA-256 | classical collision term 128; no QROM claim |
| canonical proof upper bound, profile 2 | 340,490 bytes | exact combinatorial bound |
| verifier roles / inputs | 168 | exact manifest |
| worst-case script-bearing transaction bound | 980,292 bytes | measured with maximum canonical proof |
| remaining transaction bytes at that bound | 19,708 bytes | measured |
| maximum redeem / unlocking at that bound | 9,435 / 9,710 bytes | measured |

The security floor is classical and at least 100 bits under the explicitly
named FRI query conjecture and classical random-oracle model. The separate
quantum statement is only: **no known polynomial-time quantum break under the
stated assumptions**.

## E. Privacy gate

C23 and C29 are necessary but not sufficient. The exact observer view and
simulator are specified in [`ZK-MEMBRANE.md`](ZK-MEMBRANE.md) and
[`OBSERVER-LEDGER.md`](OBSERVER-LEDGER.md). The final transaction must expose
no second note-derived path around those mechanisms.

## F. Historical FRI11 failure

FRI11 used 36 occupancy queries, separate SHA-bit openings, booleanity carriers,
public note-auth paths, and multiple witness-to-transaction paths. Its 32 plus
36 SHA opening union had rank 64 and recovered amount and rho. SHA round gates
also remained host-only. It therefore failed both completeness and privacy.
Those facts remain frozen in [`PRIVACY-AUDIT.md`](PRIVACY-AUDIT.md); v15 does
not rename or repair FRI11 in place.

## G. Qualification evidence

An offline artifact qualifies only if its evidence records:

1. generate a fresh worst-profile v15 proof under the frozen construction ID;
2. make the reference verifier and all 168 production VM inputs accept that
   same proof and transaction;
3. record exact proof hash/bytes, transaction bytes, every script maximum and
   VM maximum, quotient degree, observer ledger, and mutation results; and
4. record any broader suites deliberately skipped.

Chipnet mining is a separate final action and requires explicit authorization.

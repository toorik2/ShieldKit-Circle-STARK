# Versioned construction — local-word v15

**Normative status:** frozen construction for proof/relation version 15.
Implementation and qualification evidence live in [`STATUS.md`](STATUS.md),
which is deliberately outside the construction identity.

This document records construction choices. The constitution is
[`RULES.md`](RULES.md); the complete relation is
[`COMPLETENESS.md`](COMPLETENESS.md); the privacy theorem boundary is
[`ZK-MEMBRANE.md`](ZK-MEMBRANE.md).

## 1. Fixed foundation

| Choice | v15 |
|---|---|
| proof family | Circle FRI STARK |
| native hash | SHA-256 |
| base trace representation | M31 |
| challenge/composition/FRI field | QM31 |
| relation | one deposit note, or one spent note with at most one private change note |
| settlement | one May-2026 BCH consensus transaction |
| privacy stance | perfect algebraic HVZK conditional on denominators; computational classical-ROM NIZK; QROM unresolved |
| quantum stance | no known polynomial-time quantum break under stated assumptions |

No transfer, merge, split, batching, administration, escape path, or protocol
fee is compiled into v15.

## 2. Relation machine

One static word circuit expresses every private relation operation:

```text
input | private-mask | constant | rotate-right | xor | and | add | nonzero
```

A word has eight four-bit limbs. Each limb makes one access to the fixed
1,841-row ALU table. One lookup LogUp proves table membership. One
word-compressed permutation proves all copy classes, rotations, digest
handoffs, and statement bindings. There is no memory machine, SHA side proof,
message bus, or path bus.

The worst withdrawal-with-change profile compiles to:

| Item | Exact value |
|---|---:|
| SHA compressions | 106 |
| active rows | 243,015 |
| relation rows | 262,144 |
| private input words | 316 |
| public input words | 34 |
| original columns | 34 M31 |
| public preprocessed columns | 67 M31 |
| interaction columns | 17 QM31 |
| current interaction commitment | 56 M31 |
| predecessor interaction commitment | 12 M31 |
| AIR residuals | 25 quadratic QM31 identities |

The relation directly reuses computed digest wires as later message wires. It
contains amount commitment, note leaf, private membership, old-empty/new-leaf
append, nullifier ownership, public boundary, full-withdraw equality, partial
withdraw conservation, positive change, same-owner change, and fresh change
rho. Public sparse-nullifier insertion is checked directly by the settlement
roles because its public 8,192-byte path is not private witness material.

## 3. Domains and sealing

| Parameter | v15 |
|---|---:|
| relation log | 18 |
| sealed degree log | 19 |
| quotient degree log | 20 |
| LDE log | 24 |
| effective FRI blowup log | 4 |
| queries | 28 |
| grind | 20 |
| FRI folds | eight 2-bit folds, then one 1-bit fold |
| final degree log | 3 |

Every original and interaction M31 column is independently committed as
`w + Z_H r`, with one fresh M31 coefficient of `r` per relation row. The
preprocessed matrix is public and deterministic. The production quotient
builder verifies that `Z_H` is nonzero over the full LDE domain.

Interaction challenges are sampled only after the original root. Interaction
traces are then built and independently sealed. Public-boundary inverses are
computed from the statement and checked by dedicated VM roles.

## 4. Quotient and FRI

V15 keeps the quotient whole. The prover computes the one QM31 composition over
the sealed committed rows and divides by `Z_H`. It rejects a degree above
`2^20`. No quotient component, decomposition, pad, or randomizer is
serialized.

The prover separately samples one uniform degree-`2^20` QM31 polynomial
`R`. The canonical `quotientAndFriMask` row is exactly:

```text
quotient[16 bytes] || R[16 bytes]
```

The FRI layer-zero value is the Horner batch of nine packed original values,
seventeen packed interaction values, and the quotient, followed by `+ R`.
The mask coefficient is exactly one.

## 5. Transcript

There is one domain-separated transcript in this order:

1. public statement plus construction ID;
2. construction descriptor, preprocessed root, and sealed original root;
3. lookup, copy, and public-boundary challenges;
4. verifier-checked public-boundary inverses;
5. sealed interaction roots and AIR mixing challenge;
6. quotient-and-FRI-mask root and batching challenge;
7. nine FRI roots and fold challenges;
8. eight final coefficients;
9. grind-20 nonce; and
10. 28 collision-free query orbits.

The VM re-derives each stage. It also checks the exact current,
current/predecessor, and FRI opening schedules. No proof field may introduce
another query.

## 6. Canonical proof

Proof magic is `SKLW`, version is 15, and the profile is one byte. The
verifier key supplies fixed widths and geometry. The proof serializes each root
once, every opening row once, canonical siblings, fixed frontier handoffs, one
checked transcript manifest, and one compact ownership directory.

Five matrix openings are authenticated:

1. preprocessed;
2. sealed original;
3. sealed current interaction;
4. sealed current/predecessor interaction;
5. quotient plus FRI mask.

Nine FRI openings follow. Indices and intermediate Merkle work are derived from
the checked schedule; there is no merge program or duplicated opening body.

For every collision-free transcript schedule, the profile-2 canonical proof is
at most **340,490 bytes**. The bound follows from the exact radix-4 sibling and
frontier recurrence, not from a sample proof or padding.

## 7. Consensus lowering

The proof is split once into 168 contiguous carrier chunks. A single semantic
allocation gives every verifier role a measured weight. There are no density
classes, duplicated proof regions, or filler bytes.

```text
canonical proof bytes
  -> weighted contiguous partition
  -> input 0: settlement plus fixed control-plane prefix
  -> inputs 1..167: one semantic verifier role each
```

Input zero's BIP68-disabled sequence commits the exact proof length. The pool
redeem binds that value to the canonical big-endian header length; the header
role independently checks magic, version, length, profile, construction, and
preprocessed root. Every verifier redeem derives its own expected slice length
from that committed proof length, so verifier locks are stable across all
canonical proof lengths.

Inputs and outputs 1–167 form one public addressing ledger:

- each value carries one cumulative weight prefix;
- each BIP68-disabled input sequence carries one direct 256-weight jump index;
- a reader makes one direct jump and then a short prefix refinement; and
- the settlement bank digest commits every lock, value, sequence, and order.

The selected bank's outputs reproduce its locks, values, and token state
exactly. These satoshis are infrastructure capital, not settlement value, and
the bank can neither subsidize nor receive a pool payment.

There are three standing profile-specific banks: deposit, full withdrawal, and
withdrawal with change. A transaction spends and recreates exactly the one
matching its proof profile; the other two remain untouched. The pool lock
authorizes all three digests. The transaction still contains 168 inputs—not
three copies of the verifier bank.

Merkle verification uses wider fixed stages rather than a second compression
layer:

- ordinary matrices: four levels per stage;
- interaction: five levels per stage;
- global: one first level, then two levels per stage;
- FRI: one first level, then three levels per stage.

The two-level global cut replaces the two stages that exceeded one input's
absolute op-cost-density envelope with four smaller mathematical stages. It
adds two roles and 3,624 worst-case proof bytes; it adds no padding or second
authentication mechanism.

## 8. Security accounting

The exact named-event worksheet is [`ARGUMENT.md`](ARGUMENT.md). Its
conservative classical-ROM union is above 101.37 bits; the 104-bit FRI term is
explicitly conjectural. Algebraic privacy is perfect conditional on nonzero
denominators, with conservative abort distance below `2^-102.61`.

SHA-256 provides the Merkle, Fiat–Shamir, note, nullifier, and sparse-tree
hashes. The design does not silently substitute a proof-friendly hash.

## 9. Measured bounds

Using the maximum canonical profile-2 proof rather than a favorable sample:

| Item | Measurement |
|---|---:|
| proof upper bound | 340,490 bytes |
| roles / transaction inputs | 168 |
| verifier bytes | 606,863 |
| redeem bytes | 615,663 |
| unlocking bytes | 957,161 |
| maximum verifier | 9,383 bytes |
| maximum redeem | 9,435 bytes |
| maximum unlocking | 9,710 bytes |
| full script-bearing transaction | 980,292 bytes |
| remaining transaction bytes | 19,708 bytes |

All measured fixed-cut Merkle roles are below the input-local operation-cost
ceiling. The exact fresh proof may be smaller than the combinatorial bound, but
the final claim uses its actual serialized transaction.

## 10. Mechanisms deleted

V15 has no product path through:

- raw `openShaBit` trace openings;
- `occupancyBoolShardsFromNote`;
- `FriAuth` note/path serialization;
- witness OTP inside the consensus proof;
- public-commit-derived privacy masks;
- duplicate trace roots;
- note-aware carrier builders;
- quotient decomposition or padding;
- independent query schedules; or
- dummy bytes used for size or operation-cost density.

Historical files may reproduce FRI11, but v15 imports none of their witness
paths.

## 11. Qualification gate

The construction identity includes this exact document, the three deterministic
verifier keys, and the canonical carrier allocation. An artifact qualifies only
after all of the following are recorded for that exact identity:

1. generate one fresh profile-2 proof;
2. reference-verify it;
3. build the exact 168-input settlement transaction;
4. run every VM role and the complete observer/mutation audits; and
5. record exact meters and skipped broad tests.

Chipnet mining is separately authorized work. Only the human declares the
named end complete.

# Sealed Creation Log — minimal constitution

This is the unchanged constitutional boundary inherited by V17. It fixes only
the foundation, relation, privacy boundary, settlement invariants, soundness
floor, and product boundary. Proof version 17, q44, OOD batching, FRI grouping,
Merkle cuts, role allocation, and BCH packaging belong to the versioned
construction. A change here creates a new protocol identity; it is never a
silent optimization.

## 1. Foundation

1. The proof family is a transparent Circle FRI STARK.
2. SHA-256 is the sole native cryptographic hash.
3. Private computation uses M31; security-critical challenges, composition,
   quotient, batching, and FRI use QM31.
4. The classical security floor is at least 100 bits under every assumption
   actually counted.
5. The quantum claim is only: **no known polynomial-time quantum break under
   the stated assumptions**.

## 2. Relation

One transition is exactly one of:

1. deposit, creating one positive private note;
2. full withdrawal, consuming one note and creating none; or
3. withdrawal with change, consuming one note and creating one positive change
   note owned by the same secret with fresh `rho`.

There is no transfer, merge, split, batching, administrator, migration,
emergency escape, alternate settlement path, or second state thread.

Let `C` be the private SHA-256 note commitment. Every creation at public
sequential index `i` extends one private-preimage creation chain:

```text
h_next = H(link-domain || relation-context || pool-category ||
           u64be(i) || h_previous || C)
E      = H(edge-domain || relation-context || pool-category ||
           u64be(i) || h_previous || h_next)
nf     = H(nullifier-domain || relation-context || pool-category ||
           E || owner-secret || rho)
```

`E` is appended at index `i` to the public depth-32 SHA-256 edge-history tree.
A spend privately proves that its derived `E` belongs to the current public
history root. A creation proves the new linked head and `E`; CashVM verifies
the public history append. Binding `nf` to `E` makes equal note preimages at
different creation edges independently spendable.

At `2^32` creations, no deposit or change creation is allowed. Full exits stay
allowed. Public services may accelerate witness delivery, but the note record
plus canonical BCH history must always be sufficient to reconstruct a spend.

## 3. Privacy boundary

The final transaction protects:

- owner secret, `rho`, note commitment/preimage, and note amount;
- which historical public edge is being spent;
- the spent edge index, previous head, and depth-32 membership path;
- change amount, note identity, allocation, and its link to the spent note; and
- every private relation trace and intermediate SHA-256 word.

The following are public by design:

- action/profile and PAA2 state transition;
- pool CashToken category, sequence, creation count/head, and history root;
- one pseudorandom creation handle `E` for each deposit or change creation;
- net deposit, payout, reserve change, miner fee, and TVL;
- withdrawal nullifier and its public sparse-tree update; and
- proof bytes and verifier-carrier topology.

`E` may identify one creation event, but it must not reveal `C`, amount, owner,
`rho`, which later nullifier spends it, or whether it was deposit or change
beyond what the public action already reveals. Privacy is judged over the union
of every serialized transaction byte and every efficient derivation from it,
not by substring searches.

## 4. Settlement invariants

Each transition may pay one explicit public BCH miner fee and no other fee.
Protocol, developer, operator, treasury, and relayer fees are forbidden.

1. Deposit: transparent inputs fund the reserve increase and miner fee; the
   created note equals the reserve increase.
2. Withdrawal: spent note equals public payout plus private change plus miner
   fee; reserve decreases by payout plus miner fee.
3. The one mutable continuation NFT keeps the same category and mutable
   capability, zero fungible amount, covenant lock, and canonical position.
   Minting authority is forbidden.
4. Proof-carrier role zero is the pool/settlement input. It keeps the covenant
   lock, category, mutable capability, zero fungible amount, and canonical
   position, while its BCH reserve value and PAA2 commitment advance exactly as
   the settlement requires; it is not value-neutral. Proof-verifier roles 1
   through 209 and authenticated code-ROM role 210 are tokenless, exact
   input/output rollovers with the same lock, value, token state, and position.
   Only these auxiliary roles 1 through 210 are value-neutral verifier
   infrastructure; they may neither subsidize nor receive settlement value.
5. PAA2 sequence advances once. Creation count/head/history advance exactly on
   deposit or change and remain fixed on full withdrawal. Nullifier root
   advances exactly on withdrawal.

## 5. Soundness floor

The construction must separately account for field and algebraic bad events,
lookup and copy reductions, OOD sampling, quotient degree, degree-corrected
batching, FRI proximity/query/grinding, Fiat-Shamir/BCS loss, and SHA-256
binding. The minimum and conservative union must both remain at least 100
classical bits.

Every conjecture and model assumption is named. A query-times-rate worksheet is
a parameter target, not a theorem. Classical ROM and QROM claims are separate.
No QROM zero-knowledge claim is made without a reduction.

## 6. Product boundary

The research product is one May-2026 BCH consensus transaction:

- at most 1,000,000 serialized bytes;
- every locking or unlocking script and every pushed element at most 10,000
  bytes;
- every input accepts under the unmodified May-2026 BCH VM; and
- relation, transcript, authentication, quotient, FRI, canonical encoding,
  carrier placement, state, token authority, and settlement are miner-run.

The 100,000-byte standard relay ceiling is a future optimization target, not a
V17 claim. Multiple transactions, trusted host verification, dummy padding,
duplicated proof bytes, or density ballast may not satisfy this boundary.

The lane is an offline research preview. No mainnet, RPC, funding, spending,
broadcast, mining, or chain mutation is authorized by this constitution.

## 7. Claim discipline

- **Proven:** follows from an identified theorem or checked correspondence.
- **Measured:** exact bytes, VM meters, or reproducible experiment for one
  identified artifact.
- **Speculative:** a named hypothesis or unproved model step.
- **Unresolved:** no claim.

A qualifying protocol identity must bind this constitution, the relation and
privacy membrane, parameters, transcript, codecs, completeness semantics, and
CashVM role graph. The final construction identity must additionally bind the
exact linked verifier banks. Identities, proof/transaction sizes, and VM meters
are generated evidence; they are never hand-authored into this constitution.

Only the human user declares a named end complete.

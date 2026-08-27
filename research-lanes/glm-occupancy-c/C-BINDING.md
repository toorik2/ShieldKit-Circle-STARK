# Envelope C: what the tape chain does and does not bind

> **CLOSED 2026-08-21.** The counted tip covenant described under "What would
> close it" is implemented and landed: pay hop
> `06a6078a1d85ed68233e44a3a22a07d1b6a89774e1b0b7ff69799ac727b603c0` plus 18 tape
> hops. Every hop is pinned to `hash256(proof)` by consensus. The analysis below
> is kept because it is why the covenant exists, and because the two design traps
> it did **not** anticipate are worth remembering:
>
> - a self-propagating lock cannot terminate — the pay hop's output 1 is the
>   payout — and recognising the pay hop by its pool lock is circular, because the
>   pool covenant must assert the tip lock;
> - one identical lock for every hop would let the pay hop spend the funder's
>   initial tip and skip the whole tape, silently breaking skip-tape rejection.
>
> A counter fixes both: `L(d,i)` requires output 1 to be `L(d,i+1)`, `L(d,N)` is
> terminal, and the pool covenant pins `L(d,N)`.

**Question.** B checks 36 unique-orbit queries in one transaction. C checks the same
36 across 19 transactions. Is C's chain equivalent, or is B strictly stronger?

**Answer.** B is stronger, and the gap is not nominal. C's per-hop verification is
real and enforced; what is *not* enforced is that the hops attest the **same
statement**. This is a script-level fact, not a conjecture.

## What C does enforce

Each tape hop is an ordinary transaction that must be valid to be mined. Its inputs
include the fold and R-slot kernel P2SH32 locks, and those locks run the real checks:
`foldPair` on the remaining FRI layers, and `(qTable − R)·Z == C(z)` at a
Fiat–Shamir index the lock **recomputes itself** (`fsIndexSlotAsm`, seeded from the
packed AIR) rather than accepting from the prover. A hop whose 2 queries do not
verify cannot be mined.

The pay hop spends the tape tip, so the 18 hops must exist on chain before the pay
transaction is valid. Skipping a hop leaves the tip unspent and the pay hop
references a missing input.

So: **18 hops of genuine verification work happened, and the pay hop cannot land
without them.**

## What C does not enforce

Nothing ties hop *i*'s statement to the pay hop's statement. Three reasons, each
checkable in the source:

| | |
| --- | --- |
| `chained.ts` `tapeCommit()` | `TAPE1 ‖ digest ‖ index ‖ hopCount ‖ chunkHash` is written into an `OP_RETURN` and **never read by any script**. Grep it: it appears where it is built and nowhere else. It is an annotation for observers. |
| `chained.ts` `compileTapeHop()` | Hop *i+1* spends hop *i*'s output 0, which is `p2pkhLockingOf(wallet)` — a plain P2PKH. The chain is held together by a **signature**, not a covenant. Any holder of the key can build any tape. |
| `covenant-spend.ts` tape carrier | On a tape hop, input 0 is the AIR carrier, whose lock is `OP_DROP OP_1`. The packed AIR is **dropped, not checked**. Each hop supplies its own. |

And BCH script cannot inspect an ancestor transaction's outputs, so the pay hop has
no way to read what the tape hops committed to.

The consequence: a prover holding the wallet key could compile each hop against a
*different* packed AIR — 18 statements, 2 satisfied queries each — and every hop
would be individually valid, the tip would exist, and the pay hop would land. The
chain proves "eighteen valid hops occurred", not "eighteen hops attested one
statement".

In B, all 36 slot kernels read one packed AIR inside one script evaluation. One
statement, 36 checks, atomically. That is the difference, and it is real.

## What this does not affect

**Completeness is unaffected.** Note Merkle, nullifier, and amount/auth run in the
note-auth kernel on C's pay hop exactly as on B — one transaction, one statement,
nothing deferred to `verifyFri`. The gap here is about the *tape*, not the note.

## What shipped since this was written (2026-08-21)

Tape hops now spend a **sibling NFT of the pool category** at input 0, minted by
C's genesis (which is the category genesis, so no minting token is needed). This
was forced by cqz — `bindPackedStmtToPaa1Asm` reads `<0> OP_UTXOTOKENCOMMITMENT`
and a tokenless carrier made that an empty item — but it also moves the binding
question, so record what it does and does not achieve.

**It binds the noteRoot.** cqz compares commitment bytes `[64..96]`, and
`state.ts` puts the **noteRoot** there. Every tape hop must therefore present the
same old noteRoot (the sibling it spends) and the same new noteRoot (its own
output 0). The category is derived from the genesis outpoint and cannot be forged.
So all 18 hops are pinned to one note-tree transition, where before they were
pinned to nothing.

**It does not bind the rest.** `poolInstanceId` (bytes 32..64), `nullifierRoot`
(96..128), and the remainder of the packed AIR are still unchecked across hops. A
prover can still vary those hop to hop.

So the gap below is narrowed, not closed. 18 tape hops carrying this design landed
on Chipnet on 2026-08-21.

## What would close it

The pay hop can introspect **its own** inputs even though it cannot read ancestors.
That is enough, if the tape tip's *locking bytecode* is made a function of the
statement and each hop is forced to propagate it.

**1. A digest-parameterised, self-propagating tip covenant.** Replace the tape
tip's bare P2PKH (output 1) with a P2SH32 whose redeem embeds `digest` and requires
its own successor to carry the identical lock:

```
<digest> OP_DROP                       // the parameter, committed in the lock hash
OP_INPUTINDEX OP_UTXOBYTECODE          // this input's locking bytecode
<1> OP_OUTPUTBYTECODE                  // output 1 of the spending tx
OP_EQUALVERIFY                         // ... must be the same lock
OP_1
```

Because `digest` is inside the redeem, it is inside the P2SH32 hash, so the lock
*is* a commitment to the statement. Because the covenant forces output 1 to repeat
it, hop g cannot change it, and the parameter propagates from the tape funder all
the way to the tip.

**2. The pay hop asserts it.** In the pool covenant, check the tape input:

```
<tapeInputIndex> OP_UTXOBYTECODE
<0x…expected P2SH32 for digest…> OP_EQUALVERIFY
```

where the expected lock is derived from the statement the pay hop is verifying.
Now "the tip I am spending descends from hops committed to *my* digest" is a
consensus fact, not a convention.

**Notes for whoever builds it**

- The tip must **stay tokenless**. A token-carrying tip broke P2PKH signing with
  NULLFAIL; output 0 already holds the sibling NFT, and these are different jobs.
- The covenant makes the tip anyone-can-spend (no signature in the redeem above).
  For a lab that is fine — it is dust and the covenant is the point — but a
  production version should also require the wallet's signature, or a griefer can
  spend a tip and strand the chain.
- Verify with the full-transaction harness in `test/chained-vm.test.ts` before
  landing. Every C defect so far was invisible to isolated script evaluation.
- This is a covenant change only. It does not touch `FRI_VERSION`, the kernels, or
  the proof format.

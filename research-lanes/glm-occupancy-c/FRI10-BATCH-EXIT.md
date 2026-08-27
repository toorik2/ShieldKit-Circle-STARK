# Batch-exit note walks — build FRI10 **beside** FRI9, do not bump

> **If you are an AI or a new contributor picking this up: read this section first.**
>
> - **Do not change `FRI_VERSION`.** It is 9. Leave it at 9.
> - **Do not edit `src/backends/circle/fri.ts` in place.** FRI9 is landed, sound,
>   and has on-chain artifacts depending on it.
> - Add a **new zkp plugin family** alongside `circle-fri-m31`. That is the
>   supported extension point, stated in `src/plugins/registry.ts`: *"A later
>   plugin is one registry row + prove/verify; notes/nullifiers stay."*
> - Related: [`C-BINDING.md`](C-BINDING.md) (what the tape does and does not bind),
>   [`MILESTONE.md`](MILESTONE.md), [`STATUS.md`](STATUS.md).

**Status: off-chain half BUILT and passing (commit `7289d13`); on-chain half open.**
`circle-fri-m31-batch` is registered beside `circle-fri-m31` and runs today via
`--plugin circle-fri-m31-batch`. `FRI_VERSION` is still 9 and was never bumped.
Six soundness invariants pass (`test/fri10-invariants.test.ts`), full suite 183/0,
and FRI9's compile sizes are byte-identical (A 87611, B 498398).

## Documentation convention

The same copy-don't-mutate rule applies to **documents**, not just code. When the
batch work needs to change something a FRI9 doc asserts, **do not edit the FRI9
doc** — copy it to a new file with `-FRI10` appended and change the copy:

| FRI9 (leave as-is) | FRI10 (create when needed) |
| --- | --- |
| `MILESTONE.md` | `MILESTONE-FRI10.md` |
| `STATUS.md` | `STATUS-FRI10.md` |
| `C-BINDING.md` | `C-BINDING-FRI10.md` |
| `COMPARISON.md` | `COMPARISON-FRI10.md` |

The FRI9 documents describe a configuration with on-chain artifacts behind it.
They stay true no matter what happens to the batch work. If FRI10 is abandoned,
delete the `-FRI10` files and nothing else moves.

## The gap

Envelope B and C's pay hop walk **one** spent note plus **one** change note on
chain, in the note-auth kernel. A batch-exit round with N waiters walks the first
and leaves the other N−1 in `verifyFri`. `vm-verifier.ts:566`:

> B adds a note-auth kernel; batch-exit extra notes still stay in `verifyFri`.

This is the last item on the note/nullifier/amount-auth list that is not on-chain.
Everything else was closed on FRI9.

## Why it looks like a version bump, and why it must not be one

The kernel side is easy — N note-auth kernels instead of 1, the same pattern the
36 fold kernels already use. The blocker is upstream: **the encoded proof carries
exactly one auth.** `fri.ts:89` is `auth: FriAuth`, singular, and
`noteAuthUnlockingFromProof` (`note-auth-kernel.ts:243`) builds its walk from it:

```ts
const auth = decodeFriProof(args.proof).auth;
spentIndex: deposit ? auth.createdIndex : auth.index,
```

A kernel can only walk a note whose index and path are in the proof, so carrying N
changes what a proof *is*.

The tempting move is `FRI_VERSION` 9 → 10. **Don't.** `VK_ID` (`params.ts:26`)
embeds the version and `fri.ts:435` rejects a mismatched `proof.version`, so a bump
invalidates every FRI9 artifact — including the Chipnet lands of 2026-08-21
(A `614b7077…`, B `81bb2cef…`, and C's 18 tape hops). If the new work has a bug you
have lost the known-good configuration at the same moment.

## The safe shape: a second family

`zkpPlugins` is a list (`registry.ts:50`), each entry carries its own `family` and
`vkId`, and `zkpPluginByFamily()` dispatches. `hash-lab-v0` already demonstrates a
second family coexisting. So:

| | |
| --- | --- |
| **Leave alone** | `FRI_VERSION = 9`, `VK_ID`, `fri.ts`, `circleFriPlugin`, the note-auth kernel's checks, every existing lock |
| **Add** | `src/backends/circle-batch/` (or similar) with its own `fri.ts` supporting `auths[]`, its own `VK_ID`, its own plugin object |
| **Register** | one row in `zkpPlugins`, e.g. `family: "circle-fri-m31-batch"` |
| **Select** | `--plugin circle-fri-m31-batch`; default stays `DEFAULT_ZKP_FAMILY` = FRI9 |

Cross-family verify already rejects, so a batch proof cannot be mistaken for a FRI9
proof or vice versa. FRI9 keeps working the entire time, and the fallback is
"don't pass `--plugin`".

Duplication is the price and it is the right price. Share by extracting helpers
only where it cannot change FRI9 behaviour; when in doubt, copy.

## Work items

**Items 1, 2, 3 and 5 are DONE** (commit `7289d13`). Item 4 turned out not to be
what this document originally said it was; its on-chain half is now built as
**option A’** (see below), with only the landing wiring and the switchover left.

| # | Where | What | Status |
| --- | --- | --- | --- |
| 1 | new backend | `FriProof.auths: FriAuth[]`, length-prefixed in the encoding | **done** |
| 2 | new backend | per-auth OTP pads (`auth-pad.ts`) | **done** |
| 3 | new backend | verify checks every auth, count pinned to `withdrawalCount` | **done** |
| 4 | `covenant-spend.ts`, `tape-tip.ts`, `covenant-p2s.ts`, `chained.ts`, `land-envelopes.ts` | N note-auth kernels on chain, via **option A’** (one per tape hop + root binding), wired through `landC(..., batchNotes)` | **built, wired & VM-verified; not broadcast** |
| 5 | `registry.ts` | `circle-fri-m31-batch` beside `circle-fri-m31` | **done** |

What 1-3 turned out to mean, which was less than expected: FRI9 **already**
validates N notes correctly (`checkBatchSpends` — no duplicate index, positive
amounts, membership, non-zero nullifier, `sum == public net`), but only when the
**witness** carries them (`air.ts:141`). Without a witness it falls through to the
single-note check and rejects an honest batch with `"withdraw exceeds note"`
(`air.ts:144`), because `auths[0]` covers only its own amount. So FRI10 publishes
the auths and feeds them to FRI9's own audited path. `buildTrace`, the AIR and the
FRI layers are untouched and shared.

## Item 4: one nullifier insertion per transaction

The note-auth kernel asserts

```
SHA256(oldNfRoot || nf) == newNfRoot
```

reading `<0> OP_UTXOTOKENCOMMITMENT` for the old root and
`<0> OP_OUTPUTTOKENCOMMITMENT` for the new one (`note-auth-kernel.ts:106-122`).
Both come from **one** transaction, so a transaction has exactly one
`(oldNfRoot, newNfRoot)` pair.

N independent note-auth kernels in that transaction would each require
`SHA256(oldNfRoot || nf_i) == newNfRoot`. Distinct notes give distinct `nf`, so
that is **N distinct required values for a single output commitment —
unsatisfiable for N > 1.** Adding kernels to one transaction cannot work no matter
how many bytes are free.

### Verified five independent ways (2026-08-22)

This was double-checked before acting on it, because the whole item hinges on it
and an earlier claim in this work ("FRI10's exposure is closed") turned out to be
false when tested. Each check below is independent of the others.

1. **The assembly itself.** The withdraw branch after `OP_ELSE`
   (`note-auth-kernel.ts:126-175`) is literally
   `<0> OP_UTXOTOKENCOMMITMENT / EXTRACT_NF_ROOT / OP_SWAP / OP_CAT / OP_SHA256 /
   <0> OP_OUTPUTTOKENCOMMITMENT / EXTRACT_NF_ROOT / OP_EQUALVERIFY`. The indices are
   absolute `0`, so every kernel in a transaction reads the **same** input 0 and the
   **same** output 0 regardless of which input slot it occupies.
2. **There is only one kernel variant.** `compileNoteAuthLockP2sh32()` takes **no
   parameter**, unlike `compileSlotsLockP2sh32(slot = 0)` (`air-cqz.ts:1325`) and
   `compileFoldLockP2sh32(nFold = 1, queryIndex = 0)` (`fold-kernel.ts:162`). Kernel
   *i* cannot be made to differ from kernel *j*.
3. **Arithmetic.** For two real notes, the required new roots are distinct
   (`af276d46…` vs `d60501d3…`). One 128-byte commitment holds one value.
4. **No multi-note support exists anywhere.** Every call site of
   `compileNoteAuthLockP2sh32` / `noteAuthKernelUnlocking` emits at most one per
   transaction, and no covenant path counts note-auth inputs above one.
5. **Empirically, in the real BCH 2026 VM.** Building the transactions and running
   `vm.verify`:

   | scenario | result |
   | --- | --- |
   | state advanced by 1 note, kernel for that note | **accepted** |
   | same state, kernel for a *different* note | rejected, `OP_VERIFY` at its input |
   | both kernels in one transaction | rejected at the second kernel's input |
   | genuine 2-note batch exit, either kernel alone | **rejected** |
   | genuine 2-note batch exit, both kernels | **rejected** |

   The last two rows are the important ones. A real batch moves the root by two
   steps, `SHA256(SHA256(old ‖ nf₀) ‖ nf₁)`, which equals neither single-step value,
   so on a genuine batch **neither** kernel is satisfiable — not just "not both".

**Provenance.** The kernel came from commit `5f47e04` *"On-chain note Merkle,
nullifier, and amount/auth on B"*, written before this line of work. There is no
batch or N-note intent anywhere in the file. The one-note shape is original design,
not something a later change broke.

The claim stands: **N distinct required values for a single output commitment,
unsatisfiable for N > 1.**

Two ways out were considered:

**A. One kernel per transaction, N transactions.** Envelope C only. Each tape hop
carries one note-auth kernel and advances the nfRoot by one step, with the genesis
siblings minted as a **chain of intermediate nfRoots** rather than all holding OLD.
Needs the batch known at genesis. No kernel change.

**B. Fold a list inside one kernel.** Change the note-auth kernel to walk N
nullifiers and assert the folded root in a single transaction. Works on B as well
as C, but it is a kernel change, and the kernels are the part the project has been
most careful about.

**A was chosen.** B is neither small nor superior, measured:

| | bytes |
| --- | --- |
| compiled note-auth kernel (redeem) | **467** |
| per-note payload (2 x 512 B merkle paths + fields) | **684** |
| one note-auth input, total | **1154** |

Script has no loops, so B must unroll the kernel N times, and under P2SH32 the
redeem is pushed *inside* the unlocking. So B costs `N*467` on top of `N*684` -
the same total bytes as N separate inputs, but crammed into **one** input's 10 KB
budget instead of N budgets. **B caps at 8 notes** (N=8 -> 9211 B; N=9 -> 10362 B,
over the cap); A has no ceiling. B also changes the kernel's P2SH32 address, since
the lock is `hash256(kernel)`, making N part of the pool's on-chain identity.

If B is ever wanted (it would take envelope B's single consensus transaction from
1 note to 8), it must be a **new, differently-named kernel beside the audited one**,
never an edit to it. Deciding to switch envelopes over to it is an audit call.

## Option A' - the soundness gap in plain A, and what closes it

Plain A does not work. Each hop's kernel verifies in the real VM on its own, but
the kernels are **unobserved**:

- nothing on a tape hop *requires* a note-auth kernel to be present - the pool
  covenant's `requireFriInputsAsm` guards input 0 of the *pool* transaction, and
  tape hops spend a sibling under its own lock instead;
- the hop output NFTs are dead ends - *"Nothing spends this output again"*
  (covenant-spend.ts);
- the tip chain carries only the digest and the count - `L(d,i)` asserts output
  **1** and says nothing about output 0 (tape-tip.ts); and
- nothing else constrains the root: `checkBatchSpends` (air.ts:148) checks
  membership, duplicate indices, amounts, non-zero nullifiers and
  `sum == public net`, but **never** that `newState.nullifierRoot` is the correct
  fold. AIR cells 21/22 hold the two roots and appear in **no constraint** - they
  are committed, not constrained.

So a prover could skip every hop kernel and the pool would not notice. Since the
nullifier accumulator is the double-spend defence, that must not be possible. The
enforcement lives entirely in the on-chain kernel, exactly as covenant-p2s.ts:28
says: `nullifierRoot (equal or SHA-256(old||nf))`.

**This is a gap in the unbuilt N>1 feature, not in anything landed.** With one note
a single kernel enforces exactly one step, which is correct. FRI9 as shipped is fine.

A' closes it by making the running root reach the pool. Three additions, all
**opt-in**, none touching the audited kernel:

| # | where | what |
| --- | --- | --- |
| 1 | `covenant-spend.ts` | `siblingNfts.commitments?` - mint sibling *i* carrying R_i instead of the shared OLD PAA1 |
| 2 | `tape-tip.ts` | `tapeTipRedeemChainWithRoots` / `tapeTipLockChainWithRoots` - tip *i* asserts its hop's own output-0 nfRoot == R_{i+1} |
| 3 | `covenant-p2s.ts` | `finalNfRoot?` - the pool covenant asserts its output-0 nfRoot == R_N |

Consensus then verifies the whole chain: R_N is reachable from R_0 by N honest
nullifier insertions, each for a note that walks to the committed noteRoot. Piece 2
is what makes the per-hop kernels observable - a hop cannot write a root its kernel
did not produce, and a hop carrying **no** kernel cannot forge one either.

Why this is legal at all: cqz's `bindPackedStmtToPaa1Asm` binds only **noteRoot**
(PAA1 bytes 64..96) and **seq** (bytes 8..16). **nullifierRoot (bytes 96..128) is
unbound by cqz**, so a hop may legally carry its own intermediate. And a full-note
batch exit leaves `noteRoot` unchanged (`transition.ts`: `noteRoot: oldState.noteRoot`),
so the constant-noteRoot binding holds at every hop. Chaining hops by *spending*
would break the seq bind instead - hop i+1's input would carry NEW.seq where cqz
demands OLD.seq - which is why the chain lives in the **values** (pre-minted
siblings), not the UTXO topology.

Verified in `test/batch-root-binding.test.ts` (12 tests), including the decisive
one: *"the tip pins the root even when the hop carries NO note-auth kernel."*
FRI9 stays byte-identical - measured A 87611 / B 498398 / C pay 89354 /
C total 1662420, unchanged.

### Wired end to end (2026-08-22)

A' is no longer three loose primitives. The path a real batch takes now exists:

| where | what |
| --- | --- |
| `mix-successor.ts` | `runBatchSuccessor` - N-note batch + FRI9 proof + R_0..R_N |
| `covenant-spend.ts` | `noteSpent?` so a hop supplies its own walk; note-auth allowed on a tape hop |
| `note-auth-kernel.ts` | `prefixExtraKernelCount` returns 2 for a tape hop that carries a kernel |
| `chained.ts` | `compileTapeKernelGroups({ noteAuthHops })` + `compileChainedWithdraw({ batch })` |
| `land-envelopes.ts` | `landC(hops, scratch, batchNotes)` - genesis mints the intermediate siblings and pins R_N |

Two things worth knowing about the shape:

**The proof is a plain FRI9 proof over a batch statement.** That is what lets A'
land with no `FRI_VERSION` bump: FRI9 already validates N notes through
`checkBatchSpends` when the witness carries them. Its single published `auth`
covers only the first note, which is exactly why every hop supplies its own
`noteSpent` walk rather than reading the proof.

**The pay hop carries NO note-auth kernel under a batch** (`forceNoteAuth: !batch`).
Its single step `SHA256(R_0 || nf) == R_N` is precisely what is unsatisfiable for
N > 1. The hops do the walking; the covenant's `finalNfRoot` pin validates where
they landed. Genesis commits that pin, so it must be known before genesis.

Verified in `test/batch-chained-vm.test.ts`: a 3-note batch built through
`compileChainedWithdraw` where **every one of the 18 tape hops verifies on the 2026
VM**, three of them carrying their own note-auth kernel, and a forged intermediate
root is rejected. FRI9 single-note chaining is asserted unchanged in the same file.

**Still open:** nothing has been broadcast. `landC(..., batchNotes)` builds and
signs but no N-note batch has touched Chipnet, so every claim here is about
compiled and VM-verified transactions, not confirmed ones. The FRI10 switchover -
bumping the version and moving all envelopes onto the batch family - remains an
audit call.

## Option B, done as a NEW kernel (2026-08-22)

Not an edit to the audited kernel — a second kernel beside it, per the standing
rule that audited on-chain code is never modified in place. `note-auth-step-kernel.ts`.

The earlier costing of option B assumed unrolling N notes inside one kernel, which
Script's lack of loops forces and which caps at 8. **That was the wrong shape.**
The right one is the position-indexing the codebase already uses for
`compileFoldLockP2sh32(nFold, queryIndex)` and `compileSlotsLockP2sh32(slot)`: one
kernel per note, each with its two roots **baked into the redeem**.

```
SHA256(R_IN || nf) == R_OUT        (both constants, not read from the tx)
```

Because the roots are constants rather than `<0> OP_UTXOTOKENCOMMITMENT` and
`<0> OP_OUTPUTTOKENCOMMITMENT`, step j and step k are different programs at
different P2SH32 addresses with nothing to collide over. N of them coexist in one
transaction. That is precisely what the audited kernel cannot do.

### Measured, and better than the unrolled estimate

| | redeem | unlocking | lock |
| --- | --- | --- | --- |
| step kernel (new) | **182 B** | **792 B** | 35 B |
| audited kernel | 467 B | 1154 B | 35 B |

It is *smaller* because batch exit is full-note only, so there is no change branch
and no deposit branch — the absence of those cases, not a weakening of the rules.

And each step is its **own input**, so the 2026 per-input 10 KB cap never binds
(792 B << 10 000). The unrolled design would have paid `N x 467` for the redeem
inside a single input and capped at 8. Room in one transaction, by bytes:

| envelope | free | notes in ONE tx |
| --- | --- | --- |
| A standard (87611 of 100000) | 12389 B | **14** |
| B consensus (498398 of 1000000) | 501602 B | **602** |
| C pay hop (89354 of 100000) | 10646 B | **12** |

### What makes it sound rather than merely possible

The covenant **pins each step lock by index** (`stepLocks` in
`compilePoolCovenant`). Without that the step kernels would be unobserved and a
prover could simply omit them — the same trap plain option A fell into. With it,
neither the count nor the order can be altered.

A batched transaction also **drops the audited kernel**: its single
`SHA256(oldRoot || nf) == newRoot` step is exactly what N insertions cannot
satisfy. `requireFriInputsAsm` therefore uses a 3-kernel prefix when steps are
present, and `covenant-spend.ts` matches it — a mismatch there would shift every
fold and slot index by one.

Anchoring is deliberately outside the kernel, so every step is the same shape:
genesis mints R_0 and pins R_N through `finalNfRoot`. A step proves only "this
note's nullifier carries R_IN to R_OUT", which is all it should prove.

### Envelope A also batches - the old "A has no room" is retired

A was always described as the envelope that cannot walk a note: *"A cannot hold
this plus 36 queries in 100 KB"*, *"A has no room for that kernel"*. That was true
of the **audited** kernel. The step kernel is 182 B of redeem and 792 B of
unlocking, and a standard A leaves ~12.4 KB spare, so the constraint was the
kernel's shape, not the byte budget.

`test/envelope-batch.test.ts` verifies a 3-note batch on envelope A in **standard**
VM mode, inside 100 KB, with the covenant pinning its steps exactly as B's.

### Envelope B now batches (verified)

`test/envelope-b-batch.test.ts` builds a real consensus transaction through
`compileCovenantSuccessor({ stepSpends })` and runs the 2026 VM over it:

| | |
| --- | --- |
| 3-note batch verifies | yes |
| 8-note batch verifies | yes (503 671 B, non-standard by design, under 1 MB) |
| dropping a step | rejected by the covenant |
| swapping two steps | rejected - each is pinned at its own index |
| audited kernel present | no - a batched B drops it |
| FRI9's unbatched covenant | byte-identical |

Two things that had to be right, and were not at first:

**Verify B in CONSENSUS mode, not standard.** B is ~500 KB and non-standard by
design, so `createVirtualMachineBch2026(true)` rejects it on size alone - which
would also make every negative test above pass for the wrong reason. The test
helper now throws if a size rejection ever masks a covenant check.

**`BIND_PAA1` ties payout count to the withdrawal delta**: it requires
`withdrawalCount delta == outputCount - 2`. A single-note withdraw gets away with
two outputs, but a batch of N needs N payout outputs *plus* a change output, so
`runBatchSuccessor` returns its payouts and the caller must supply a funder input.

### Status

Built, VM-verified, **not adopted**. `FRI_VERSION` stays 9, nothing points at it by
default, and FRI9 is byte-identical (A 87611 / B 498398 / C pay 89354 /
C total 1662420). Switching envelopes onto it is an audit call.

## Size budget (measured)

A note-auth input is **1725 B** when it carries a change note (1684 unlocking + ~41
overhead); the lock is 35 B. Batch exit is **full-note only**, so it mints no change
and its unlocking is **1154 B** measured - 467 B redeem + 684 B payload + push
overhead. Both figures are right, for their own case.

| envelope | headroom in one tx | extra notes in one tx |
| --- | --- | --- |
| **B** (498398 B of 1 MB) | 501602 B | **290** |
| **C pay hop** (89338 B of 100000) | 10662 B | **6** |

**Those byte figures are not the real constraint.** Item 4 above shows a
transaction can only make **one** nullifier insertion, so B — one transaction — can
walk **one** note on chain regardless of its 501602 free bytes. The 290 figure is
what the bytes would allow, not what the nfRoot chaining allows. An earlier
draft claimed note-auth "cannot move to a tape hop because it reads
`<0> OP_UTXOTOKENCOMMITMENT` and only the pay hop spends the pool NFT". That is
**no longer true**: tape hops now carry a sibling NFT of the pool category at input
0, so `OP_UTXOTOKENCOMMITMENT`, `OP_OUTPUTTOKENCOMMITMENT` and `OP_INPUTBYTECODE`
are all available there. Nothing in the kernel needs the pool specifically.

So batch-exit on C scales by **hop count**: 320 hops against 32 MB
(`CHAINED_HOPS_MAX`, `CHAINED_TX_BYTES`), one nullifier insertion per hop. Under
option A, **C is not merely the more scalable envelope for on-chain batch-exit — it
is the only one that works at all**, because B has a single transaction and
therefore a single nfRoot step.

Two real constraints, neither about size:

1. **The batch must be known at genesis.** Note-auth asserts one insertion per
   kernel (`SHA256(oldNfRoot ‖ nf) == newNfRoot`), so N waiters need N distinct
   transitions and the siblings must be minted as a chain of intermediate nfRoots.
   Genesis mints them, so the round is fixed there. cqz is unaffected — it compares
   the noteRoot slice (64..96), and a withdraw with no change note leaves noteRoot
   equal (`note-auth-kernel.ts:47`).
2. **It changes the binding claim.** `C-BINDING.md` argues the siblings pin every
   hop to one statement; a chained-nfRoot design has hops attesting a *sequence*.
   That may be equally sound. It is not verified. Do not assert it.

## Test gaps to close at the same time

- No test walks more than one note. Add a batch case with N ≥ 2 that fails if any
  waiter's note is unchecked on chain.
- Add a VM case rejecting a **fake** extra note (the one-note version exists).
- Add a regression asserting the FRI9 family's compile sizes are unchanged.

## Do not change

- The note-auth kernel's checks. `amountCommit = SHA256(tag ‖ amount8 ‖ rho)`,
  `leaf = SHA256(amountCommit ‖ rho ‖ owner)`, `nf = SHA256(instance ‖ owner ‖ rho)`
  all stay. This is a count change, not a scheme change.
- The claim discipline. Until this ships and is tested, batch-exit extra notes are
  off-chain and `MILESTONE.md` keeps saying so.

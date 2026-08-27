# Completeness list (parent freeze table — copied)

**This lane’s completeness is [`RULES.md`](RULES.md).** No vk until every RULES line holds ([`ARGUMENT.md`](ARGUMENT.md)). The table below is the **parent freeze** list (`circle-fri-m31-t64-b16-q36-g20-fri9`). It is evidence. If it disagrees with RULES.md, RULES.md wins.

**Parent freeze ARGUMENT:** [`survey/artifacts/argument-freeze/ARGUMENT.md`](survey/artifacts/argument-freeze/ARGUMENT.md).

Signed 2026-08-22. Changing an item later is allowed. Changing it **silently** is not: edit this page in the same commit as the construction.

This is **B’s claim** (one consensus tx, ≤ 1 MB). A candidate that drops a row is a **different family** and a different vk, not “smaller B.”

**A** is the later attempt to hold this **same list** in one **standard** 100 KB tx. That work starts only after B and C have no remaining soundness/privacy hole we can still close.

**C** must hold the same STARK/privacy criteria, split across hops, with fund-safe reject/reclaim (`C-BINDING.md`). Per hop ≤ 100 KB.

## Must hold on B (one consensus transaction, ≤ 1 MB)

| # | Piece | Today on B | Allowed substitute |
|---|---|---|---|
| 1 | `FRI_VERSION` **9** | 9 | New family + new vk. No silent bump. |
| 2 | **36 unique first-fold orbits** | `FRI_QUERIES = 36`, rejection-sampled | Fewer orbits only with a new worksheet that still **≥ 100** conjectural bits, written here first |
| 3 | **On-chain foldPair**, one orbit per redeem until fusion is measured | 36 fold kernels | Fusion of fold+R for the **same** orbit, if density holds |
| 4 | **On-chain \(R\)** | 36 R-slots: `(q−R)·Z = C(z)`, honest C = 0 | Same check, cheaper ASM |
| 5 | **Grind 20** | grind kernel | Same bits, possibly in another kernel |
| 6 | **algebraicC** | residual interpolant point-check | Same binding |
| 7 | **bind-T** | Newton T interpolates `onChainCells`; cells match PAA1 | Same binding |
| 8 | **Note membership + nullifier + amount/auth on chain** | audited note-auth, **one** note | Step-kernel equivalent for N notes; **not** “leave it in `verifyFri`” (that is A) |
| 9 | **Same-tx binds** | all 36 orbits see one PAA1 | Not C’s tape |
| 10 | Worksheet **≥ 100** conjectural bits | 128 = \(36\times(\log_2 16-1)+20\) | 128 stays the **target**. Floor is 100. Do not keep the vk string if bits drop |
| 11 | **Standard meters** | not yet | `createVirtualMachineBch2026(true)`: 100 000 B, 10 000 B unlocking/redeem, hash 0.5 iter/byte and 192/iter. `standard=false` is diagnostic |
| 12 | **No dummy pad** | B currently pads high-index kernels to 6000 | Forbidden on a candidate that claims this list |

## Explicitly not on this list

- Batching **N notes** (step kernel). That is the other track. See [`TRACKS.md`](TRACKS.md).
- Hidden pool TVL. `STATE_BASE`+reserve stays public.
- Lean HVZK theorem. Shipped \(R\) is not that theorem.
- Electrum land is a **consequence** of 11, not a substitute for it.

## Controls (must still compile)

- **A**: 4 R-slots, 1 fold, no note-auth, standard 100 KB.
- **C**: 19 standard hops, completeness split across txs.

A candidate weaker than B and larger than C’s pay hop is neither.

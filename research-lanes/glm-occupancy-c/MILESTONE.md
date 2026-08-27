# Chipnet milestones

**Network:** BCH Chipnet only. Never mainnet.  
**Unlocking + redeem:** ≤ 10 KB (Velma).  
Old txids stay. They are not relabeled.

## Now (2026-08-21)

Any-amount pool. Circle FRI is **plugin #1**, not the pool identity.

| Knob | Live | Notes |
| --- | --- | --- |
| `--envelope a` / `b` / `c` | A 100 KB (1 fold + 4 R-slots); B one consensus tx, 36-query R; C the same work chunked across 19 standard txs (18 tape + 1 pay), every hop ≤ 100 KB | Dummy cargo is not the verifier. Unlocking 10 KB **per input** — chunk kernels. |
| `--hash sha256` / `blake2s` / `poseidon2-m31` | default **sha256** (CashVM `OP_SHA256`) | Poseidon2-M31 is toorik Grain (ePrint 2023/323), not a lock opcode. |
| `--plugin` | **circle-fri-m31** first; `hash-lab-v0` lab stub | Reserved sandwiches: `goldilocks-fri` (AIR+FRI), `air-whir` (AIR+WHIR), `spartan-whir` (Spartan+WHIR), `groth16` (pairing). `whir` is a PCS; `spartan` is an IOP. |

Envelope **B** is the hole-free statistical-soundness envelope (C's pay hop runs the same kernels, but 4 R-slots instead of 36 — see Envelope C below). One consensus tx, Circle FRI M31, TRACE=64, FRI_N=1024, **36 unique-orbit** queries, 20-bit grind, FRI_VERSION 9. CashVM kernels (chunked, 10 KB unlocking each):

| Kernel | On-chain check |
| --- | --- |
| Grind | SHA256(grindSeed \|\| nonce \|\| `"grind"`) has 20 leading zero bits; FS seed from packed AIR |
| FRI ×10 | Merkle auth of openings; L0 felt binds `qTable[slot]`; pair blob = merklized `left\|\|right` |
| Fold ×36 | Remaining FRI layers (`COMMITTED_LAYERS` = 7) + foldPair, one query per redeem |
| Bind-T | Newton T interpolates packed cells |
| algebraicC | Point checks (digest cell, seq+1, action 1\|2, UTXO conservation). **Is** the FRI interpolant: C = interpolant(algebraicC residuals), Q = C/Z (`FRI_VERSION` 9). Off-trace airNumerator (`FRI_VERSION` 8) is prior art, not this statement |
| Slot ×36 | FS index recomputed; `R_on(i)+Z(i)·R_off(i)`; `(qTable−R)·Z` equals `C(z)`, the algebraicC residual interpolant (`FRI_VERSION` 9); honest C is the zero polynomial. Independent of nTable — masked nTable cannot cancel R |
| Note-auth ×1 | SHA-256 note preimage → leaf; Merkle walk to NFT `noteRoot`; `nf = SHA256(instance\|\|owner\|\|rho)`; `SHA256(oldNfRoot\|\|nf)` (withdraw) or equal nfRoots (deposit). Change-note append when `createdSteps` is non-empty. On **B and C's pay hop** (C funds it with `forceNoteAuth`). A does not carry *this* kernel by default; the smaller step kernel (182 B) does fit A - see FRI10-BATCH-EXIT.md. |

**99 KB packing is not the verifier.** `packTo` defaults to **0**. Dummy `OP_DROP` leftover-fill cargo is not foldPair / C=QZ / R / note-auth. Density pad on high-index FS kernels (unlocking longer so `800×(41+unlocking)` covers the hash loop) is the VM meter, not cargo. Leftover 1 MB on B is unused headroom for more real kernels.

Envelope **C** is B's work **chunked to stay standard**: 19 txs, every hop ≤ 100 KB, so
the whole chain relays on public Electrum with no JSON-RPC. Tape hops are real
fold/R-slot slices (**18 hops × 2 queries** = 36 orbits), 82814–87572 B each; the pay
hop is standard (`SLOT_KERNEL_COUNT` = 4 R-slots), **89338 B**. Chain total 1659128 B.
Skip-tape still rejects the pay tx.

The pay hop carries **the same completeness kernels as B**: bind-T, grind,
algebraicC, and the **note-auth kernel** (note Merkle + nullifier + amount/auth
preimage). `landC` funds it with `forceNoteAuth`, and the opened note is threaded
to the pay hop, so `wantNote` fires at 4 slots. Note/nullifier completeness is
**not** back in `verifyFri` for C.

What still differs from B is *binding*, not completeness: B runs all 36 R-slots in
one tx, C runs 4 on the pay hop with the other 32 orbits across the 18 tape hops.
So C does not accumulate 36 **same-tx** binds. Skip-tape rejects the pay tx.

Envelope **A** is the 100 KB relay path: 1 fold + **4** R-slots + grind + algebraicC. Hole-free 36-query does not fit A; do not drop B’s 36 queries to make A look hole-free.

Compile size proof (not a land): A **87611 B** (unlock 2685), B **498398 B** (unlock 5405), 1 MB headroom **501602 B** unused (not cargo). C: 19 hops, max **89338 B**, total **1659128 B**, none over the 100000 relay gate. Leftover-fill is stripped from A/B/C; unlocking bytes are unchanged. Each unlocking ≤ 10 KB. Gating VM tests: honest 36-query B accepts; cooked viewing-commit / recooked Q/N / cooked pair blob reject; false AIR (`mutateTraceAndProve`) rejects on-chain; fake note preimage / cooked Merkle path / cooked nfRoot reject on the note-auth kernel.

### On Chipnet 2026-08-21 (`FRI_VERSION` 9, leftover-fill stripped)

**A — standard, Electrum, 87470 B** (unlock 2685). First land of these kernels on
`FRI_VERSION` 9.

| | |
| --- | --- |
| Successor | `614b7077a768ae7ed1d7aa34d5efe53dea337eff1a7bc5bed4284d1d68323024` |
| Kernels | `834f8ca14ded7e15d3380678ce902f7cf7c16be53a9c9ec6fc3f1c8ab17d03a2` |
| Genesis | `b08420db6850ea725d7d852c95804edc67d27db5c07411fdd8abf407650eb6b7` |
| Prep | `c50663208b83e9b3eeaa472fabd2e3ee487e6e26468976df4bd0e6308a5f2a5e` |

https://chipnet.imaginary.cash/tx/614b7077a768ae7ed1d7aa34d5efe53dea337eff1a7bc5bed4284d1d68323024

**B — consensus, 498398 B** (unlock 5405, 36 folds + 36 R-slots + note-auth).
Accepted by the Start9 BCHN via JSON-RPC `sendrawtransaction` through `nsenter`
into the bitcoind netns (`acceptnonstdtxn=1`). Accepted at zero-conf by the lab
node, which is the bar for a consensus-size land here — same as `b6818bd2…`.
Public Electrum does **not** carry the successor (>100000 B does not relay);
it appears publicly once the lab miner includes it. Prep/genesis/kernels are public.

| | |
| --- | --- |
| Successor | `81bb2cefe40233f096f7a69c2f3b98aa60bf6e3fb969d2b9bb5f3f82f3ecdf83` |
| Kernels | `008eb3f70c16b1a1b350f75ee92caef585c657c2c64c9992d14496a1819cacf1` |
| Genesis | `8a0349efca9560fe50ef8bef1573deb270ffddc4cb1e06f51f2201d3f99b5aac` |
| Prep | `0e9c3de9dabe6ada2b382a953c5f7210e4054601af98827c5c8e235b1358385d` |

Needed `CONSENSUS_SUCCESSOR_FEE_SATS` 400000 → 600000: relay floor is 1 sat/byte
and the FRI 9 successor is 498398 B, so 400000 drew `min relay fee not met (code 66)`.

**C — 19 chunked standard txs, all on public Electrum, with the binding covenant.**
18 tape hops + pay hop, total **1662420 B**, every hop under the 100000 relay
gate. Genesis `a8b3b679d8185911ede709ab24c18fa7d24d01fcd30c54b25055b33a6616359d`
(pool + change + 18 sibling NFTs).

| Hop | Role | Bytes | Txid |
| --- | --- | --- | --- |
| 0 | tape | 82996 | `c7e001a63e27fde6f085b53439fac3138c8e5baba999b368d25ec006b115b22d` |
| 1 | tape | 86006 | `6051141ca2fc73fcf3ec05f06545e19586262a575c8a9f944a75be559b8da114` |
| 2 | tape | 87754 | `89cbc6db3b2d1ee94944db9bbb6f94579a29e680c469ab6914debfc12488841f` |
| 3 | tape | 87754 | `ac74990535afdaf32dcabeaaa1a4e3015289f09111b56faf8938587a5a43cbf4` |
| 4 | tape | 87754 | `a042ac38ef3ec87ad5f8c0517efb089f5dd9089297f726597d25188620ec5e57` |
| 5 | tape | 87754 | `1eb3e61354b5ccb27944fe0a5242433ac7ffe99c21addfd6c0289b6353d571d3` |
| 6 | tape | 87754 | `5ef54bd9ee92c8f2afcb4824c7fa15b3b91cb8cc29d15a80feceb6e8914d3e12` |
| 7 | tape | 87754 | `09f8b80d2705fe2e49c4802bb09eee118bb19fcdae45b5723a782299766bfdc6` |
| 8 | tape | 87754 | `7510b501d95b1694dc1613fcc7fc7e1788c9f27a830cb09a33295713c68948f8` |
| 9 | tape | 87754 | `aa05dc7d3f29c1f6375fed0130fe6e3a923598f7a2770d4706d82297984a8c5b` |
| 10 | tape | 87754 | `edcf357644934a95603d2e5b20af98216430bdf5a5fa4c2e244cc1c258ba404d` |
| 11 | tape | 87754 | `5abc066b16ff3b315ad9a3a879e5d79a09327567e6f69d242a4fe579fcbac937` |
| 12 | tape | 87754 | `c5c3bcb3c26eeff3f579543a71c20993be03a7f08f72270af75256a98e29dee2` |
| 13 | tape | 87754 | `033ec00308bf12a55bfe2377fbd09d73aa6324a3ffdd8e10291abe381ca48c7c` |
| 14 | tape | 87754 | `50c9a328d37b50a1ff1e56ea5da0307280cf3fa967c6aa3bcc83f4a0ced23e7b` |
| 15 | tape | 87754 | `56efb46ac132db40ee8651c57b66b1ba8b8c8937d37edf56702b9b4670721638` |
| 16 | tape | 87754 | `9e2dd016adca9844c718ac135575082a5a85ab3b1a527a9bb9af69e0a974364b` |
| 17 | tape | 87754 | `1ef3edbacc5dc9ee8cdd39317e6717465f00c6ac75d480f1d2e17f0e2e4c41ef` |
| 18 | **pay** | 89354 | `06a6078a1d85ed68233e44a3a22a07d1b6a89774e1b0b7ff69799ac727b603c0` |

**The tape is bound by consensus, not by convention.** Each hop's tip is
`L(d, i)` — a P2SH32 whose redeem embeds `d = hash256(proof)` and requires output
1 to be exactly `L(d, i+1)`; `L(d, tapeN)` is terminal, and the pool covenant
asserts `OP_TXINPUTCOUNT OP_1SUB OP_UTXOBYTECODE == L(d, tapeN)`. So every hop is
pinned to one statement, and hops cannot be skipped because `L(d,0) != L(d,tapeN)`
— the pay hop cannot reach past the tape to the funder's tip. Before this the tape
was held together only by a signature and an OP_RETURN no script reads.

What the land also required, none of which had executed before: per-hop kernels
via `tapeKernels` with **absolute** fold/slot query indices; sibling NFTs of the
pool category so cqz's `<0> OP_UTXOTOKENCOMMITMENT` has a commitment to read; a
pool lock built with `forceNoteAuth` because the pay hop runs 4 slots yet carries
a note-auth kernel; dust-safe 3000-sat token outputs; and a tokenless tape tip.

Covered by `test/chained-vm.test.ts` (7/7) against the real VM with full
transaction context.

### On Chipnet, earlier sessions

These txs landed **before** grind/algebraicC kernels. `b6818bd2…` is the 479 KB 36-fold land, not the hole-free kernel. Do not relabel it. Next B/C land is a new txid.

**A — standard, Electrum, 82365 B**

| | |
| --- | --- |
| Successor | `05f17bf1374f8bab5718bc7e929abe991cc709d1f2c0e881ab0f05bacb28b55c` |
| Genesis | `dd3894fc1a5daf8620bbe36867b1674ef43bdb2d772a881f54b6546f45ddbfb5` |
| Kernels | `7b1e321be30309cab3a36c9e7eb6c2334d065c1cc88136cc298992b87f2738e9` |
| Prep | `c1c0f26d24be919211bd09a5ca94c43af0c48e62fb549cebcc7634d54b1ac09b` |

https://chipnet.imaginary.cash/tx/05f17bf1374f8bab5718bc7e929abe991cc709d1f2c0e881ab0f05bacb28b55c

**B — consensus, JSON-RPC mempool, 479356 B, 84 vin**

| | |
| --- | --- |
| Successor | `b6818bd260a9fff6803195fcd14d276116eedc25a36686b2eaba5655d788b002` |
| Path | local BCHN `sendrawtransaction` (`acceptnonstdtxn=1`). Public Electrum will not show it. |

**C — chained tape + last-hop pay (pre-pack land)**

| Hop | Role | Bytes | Payouts | Txid |
| --- | --- | --- | --- | --- |
| 0 | tape | 267 | 0 | `6d242fee88f61ee22af83902dccdb204d6d37a39a741376d416a5ab48a51d967` |
| 1 | tape | 267 | 0 | `ec4cd5b3a10a23ebc4b82786a1d06dc71bfffce5fdb5a81f2be2080d03df9601` |
| 2 | pay | 82506 | 1 | `6f9fd1d07594674cf3ec3d5c83312ee5e77a0df6597ddd97ae3f423486970b57` |

Genesis `5f9701e4f52c3e0c74bc07c405b5c0cb75080f774b465ef7b5917d656c5060d3`.  
https://chipnet.imaginary.cash/tx/6f9fd1d07594674cf3ec3d5c83312ee5e77a0df6597ddd97ae3f423486970b57

CLI: `pool land --envelope a|b|c|all`. C is not a 5-tx Core package.

## What compile + 2026 VM tests prove (not a new Chipnet land)

- Hole-free 36-query B: grind, Merkle + pair-blob bind, remaining fold layers, foldPair, `(q−R)·Z = C(z)` (honest C = 0), algebraicC point checks, on-chain R, note Merkle + nullifier chain + amount/auth preimage.
- False AIR rejected on the 36-query lock, not only by `verifyFri`. Fake note / cooked path / cooked nfRoot rejected on CashVM.
- A ≤ 100 KB (no note-auth kernel); B ≤ 1 MB; leftover unused, not cargo.
- C is 19 standard txs: 18 tape query slices + a standard pay hop (89338 B), none over 100 KB.

## What the Chipnet txs below prove (older kernels)

- CashTokens genesis from vout-0, P2SH32 five-point `PAA1`.
- Velma 10 KB unlocking + redeem.
- Packed AIR unlocking (no spent rho/owner).
- Standard fold spend on public Electrum.
- Consensus 36-fold spend via JSON-RPC + Chipnet miner (`b6818bd2…` is that land, **not** the hole-free kernel).
- Envelope C: tape hops do not pay; last hop pays; missing tape hop rejects the pay tx.

> Batch-exit: the **off-chain half is built**. `circle-fri-m31-batch` is registered
> beside `circle-fri-m31` (`FRI_VERSION` stays 9), publishes every spent note's
> auth, and passes six soundness invariants. The on-chain half is **built and
> tested, not landed**: N note-auth kernels cannot share one transaction, so
> **option A'** puts one per envelope-C tape hop and binds the running nullifier
> root end to end - pre-minted sibling roots, a root-pinned tip chain, and a
> `finalNfRoot` pin on the pool covenant. It is wired end to end through
> `landC(hops, scratch, batchNotes)`, and a 3-note batch has been verified on the
> 2026 VM with **all 18 tape hops passing** and a forged intermediate root
> rejected (`test/batch-chained-vm.test.ts`). FRI9 stays byte-identical at
> A 87611 / B 498398 / C pay 89354 / C total 1662420. **Nothing has been
> broadcast**: no N-note batch has touched Chipnet, so batch-exit extra notes
> remain off-chain in practice and the claim below stands.
> See [`FRI10-BATCH-EXIT.md`](FRI10-BATCH-EXIT.md).
>
> Envelope **B** batches too, via a SECOND kernel built beside the audited one
> (`note-auth-step-kernel.ts`, never an edit to it). It bakes (R_in, R_out) into
> the redeem rather than reading them at index 0, so N coexist in one transaction
> - which the audited kernel cannot do. 3- and 8-note batches verified on the 2026
> VM in consensus mode, with the covenant pinning each step by index so none can
> be dropped or reordered. Room by bytes: A 14 notes, B 602, C pay hop 12. Not
> adopted, not broadcast: `FRI_VERSION` stays 9 and FRI9 is byte-identical.

## Landed: N-note batch exit on chain (2026-08-22)

**12 notes walked on chain in ONE standard transaction**, each by its own step
kernel. 12 is the ceiling for envelope A: 99063 B against the 100000 B standard
limit, and N=13 measures 100014 B - fourteen bytes over. ~951 B per extra note.

| | txid | bytes |
| --- | --- | --- |
| genesis | `ee9f46c0dea8b7a81a628b48c44ee0de7ca99bea718f4e87f4f5a1f05bb6516d` | 392 |
| kernels | `638c55f2eadab2876c7882968bf3284e5d6fd5ebbd9c49efe46cd0b258b428e6` | 1505 |
| successor | `ce421f056a05680b44345ec92ecae3e26fb501d949a6f554a4e73200c128b981` | 99063 |

32 inputs (1 pool + 10 FRI + cqz/grind/algebraicC + 1 fold + 4 slots + **12 steps**
+ 1 funder) and 14 outputs (pool + 12 payouts + change - BIND_PAA1 requires
`withdrawalCount delta == outputCount - 2`, so the funder input is not optional).
No audited note-auth kernel: a batch drops it.

An earlier 3-note run landed the same way: genesis
`938336c4af01412c2d9e87af708934635b1d2bc7e21d5d520677977f4c727cfa`, kernels
`fff91c85fff28b6061d5dd5d409ad94838e1e29e5892f0194724c686d490bdb4`, successor
`0c669205e84ba0bf109e182e85779ef61ec7dd31c7b7e713884c0e373f3e284f` (90504 B).

**Envelope B is not landed.** It compiles, pre-flights clean and verifies on the VM
at 499665 B, but that is non-standard and electrum will not relay it - it needs a
direct node RPC (`BCHN_RPC_URL`). A transport limit, not a validity one.

## What is still not claimed

- A **confirmed block** for B's successor (accepted at zero-conf in the lab BCHN; depth follows from the lab miner).
- That C's 36 orbits are **same-tx** binds. C matches B on the completeness kernels — note-auth included — but 32 of the 36 orbits sit on tape hops; only 4 R-slots run on the pay tx.
- Envelope A note/nullifier membership by default (still `verifyFri`). Not a size limit: the step kernel fits A and a 3-note batch verifies there in 100 KB (`test/envelope-batch.test.ts`); it is simply not adopted.
- Batch-exit extra notes (one-auth FRI + this kernel still walk the first spent note).
- Dummy 99 KB cargo as a verifier (it never was).
- A Lean theorem that FRI openings hide the statement.
- Hidden pool-UTXO value (`STATE_BASE` + reserve is public TVL).
- Zcash / Monero / Voidify parity.
- Groth16 / WHIR / Spartan as a live verifier (reserved slots only).

## History (do not relabel)

| When | What | Tx / commit |
| --- | --- | --- |
| 2026-08-19 | Post-plugin standard **79525 B** + consensus **283992 B** | `23fd1b7dae7c10ac692113cf3e3bc3776cd42d4e6780d916032342fc73faaf59` / `9362df54203c560a34e105ec3a11442a2a50c750e82938191811f1bda3edc833` |
| 2026-08-19 | Hash-knob + Q/N pack, standard **79436 B** | `f14bff7baae1befc2f8becba04b968788b4e8bec65bc336b514a8d5977075671` |
| 2026-08-19 | Intermediate standard **99742 B** (T still interpolated cells+c) | `c40f49480997ecb00354766d4d31e4ec3d5811b61b8d66620ad3c321b12b87ad` |
| 2026-08-17 | Opening-mask standard **98979 B** + consensus **383031 B** | `617b102276fb79122bdd7ca36f902ad65e753845fddb168c0bb1aeb97bbb2ccc` / `b3ea8a75db4badfa1690bd9d8e98ce08565b360ddf8098e5ffade053adf643a3` |
| 2026-08-16 | Consensus **36-fold** **382203 B** @ 319402 | `b1415fafdc65e76d106956064667f94bc988a38da69e63c06acef1e8a1b9cb29` |
| 2026-08-16 | Standard 1-fold + 6 C=QZ **98831 B** | `2acb1196589b32fb1179f57dafc402dcb747f2698f364633d90dec180ab446e0` |
| 2026-08-16 | 10-fold consensus **301279 B** @ 319278 | `18c74b49731c1914425ba10804233bb208c524e5af943c8bafc55751b007f3e6` |
| 2026-08-16 | 36-slot **no-fold** **270251 B** | `356630bd10c6bf9b3d4bbd6d1835ed3baed430641f168c2ad1e1f534a3080898` |

`18c74b49…` stays the 10-fold land. `356630bd…` stays no-fold.

Earlier 6-slot spends without the current fold lock: `b6069db772455de4b247bbd50e1dea14244900e7517739157a1a9d53deeb9a7f`, `a408709c8fca1eca942548437ea9cdee054aa909215705a2c83842e54b7679d1`.

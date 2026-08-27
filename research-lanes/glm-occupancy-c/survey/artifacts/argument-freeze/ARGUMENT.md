# Argument freeze = vk

**vk:** `circle-fri-m31-t64-b16-q36-g20-fri9`  
**Lock this document names:** envelope B successor, `slotKernels = 6`, `createVirtualMachineBch2026(true)`.  
**Chipnet object this freeze applies to:** Electrum successor `58b7df7f59c3b85a5c8357b0b4c10ab12c74dac984f7a8e95832ab6965c3b03a` (91598 B, leftover-pairs empty + PICK-bounded). Not `56be9ac0…` (skip-N walker). Not `86d5413f…` (leftover-pairs, unbounded PICK).

Changing a numbered check, the conjecture, or a JS-only row **without** changing this file and the vk string is a silent family swap. Forbidden.

This is not a Lean theorem. It is the statement the lock is allowed to claim.

---

## 0. Named conjecture (FRI query bits)

**Conjecture (ethSTARK toy / 2021/582 §5.9–5.10, rate-adjusted).**  
If SHA-256 is a random oracle and the Circle-FRI proximity test on Reed–Solomon-like codes of rate \(\rho = 2/B\) obeys the ethSTARK toy-problem conjecture, then each unique first-fold query contributes \(\log_2(1/\rho) = \log_2 B - 1\) bits, and \(\zeta\) grind bits add to that:

\[
\lambda_{\text{query}} = q \cdot (\log_2 B - 1) + \zeta = 36 \cdot 3 + 20 = 128.
\]

Rate is **2/B** because composition is cubic (Merkle mix), \(\deg(C) \sim 3T\), \(Q = C/Z_H\). That is why we do **not** use \(q \cdot \log_2 B\) (rate 1/B).

**What this is not.**

- Not a reduction a referee must accept. Same class of conjecture Stwo/ethSTARK use for *query* bits.
- **Not “like Stwo 128” as a field statement.** Stwo FRI runs on an extension of M31 (QM31). This lock FRIs **M31** (\(p = 2^{31}-1\)). ethSTARK (19) also has \(\lambda \ge \min\{\zeta + R\cdot s,\ \log_2|K|\}-1\). We do **not** take \(\min\) with \(|\mathbb{F}_{p}|\approx 2^{31}\). Algebraic identity error (Schwartz–Zippel on TRACE 64) is \(\sim \deg/p\), tens of bits, not 128.
- 2026/858 (FRI above Johnson, Lean) is **not** instantiated here. We do not claim that bound.

**Decision (this freeze):** do **not** bump \(q\) or grind to “buy 128.” Extra queries do not remove the field-size gap. Accept **query-conjecture 128 at rate 2/B, grind 20, SHA-256 RO**, and keep the field/SZ gap **written**. Coins-class later = extension-field FRI or a reviewer who signs this split. Bumping \(q\) and refitting 100 KB is a **new vk**.

---

## 1. Public statement

- **Field / domain:** M31, circle \(x^2+y^2=1\), TRACE \(T=64\), blowup \(B=16\), \(N=1024\), 7 committed layers, final width 8.
- **Hash:** SHA-256 (`OP_SHA256` on chain). Poseidon2-M31 is a prover-side table id, not a lock opcode.
- **Public cells (PAA1 / `onChainCells`):** action, digest, note/nf roots, seq — **not** note limbs, **not** rho/owner. Pool TVL (`STATE_BASE`+reserve) is public.
- **Witness:** FRI openings + (for B) one note preimage on the note-auth input.

---

## 2. Numbered checks the lock must run

Same proof `proveFri` produced. JS `verifyFri` is a **lab oracle**, not a miner.

| # | Check | Kernel (B successor inputs) | Fail-closed encoding |
|---|---|---|---|
| C1 | SHA256(grindSeed \|\| nonce \|\| `"grind"`) has 20 leading zero bits; nonce bound to packed | grind | bit tests in `grind-kernel.ts` |
| C2 | 36 unique first-fold orbits; on-chain sampler matches packed FS table | bind-T (`bindUniqueFsTableAsm`) | unique-orbit loop + 36 `NUMEQUALVERIFY` |
| C3 | Each of 36 query **pairs** at each of 7 layers opens to `layerRoots[r]` | Merkle L0–L6 (`compactLayerKernelAsm`) | LIFO last-56 pair group = `left\|\|right`; leftover pairs **size 0**; path length = \(9-r\) compact strides; root `EQUALVERIFY` |
| C4 | L0 opened felt is `qTable[slot]` (left or right) | Merkle L0 | `compactQBindAsm` |
| C5 | foldPair along each orbit; witness `inv` with `inv · denom ≡ 1` (M31) | 6 fold kernels × 6 queries | `FOLD_PAIR_ASM` `NUMEQUALVERIFY` |
| C6 | \((q-R)\cdot Z = C(z)\); honest \(C=0\) | 6 R-slot kernels × 6 slots | `r-kernel` / `slotRCqz` |
| C7 | Newton \(T\) interpolates `onChainCells`; cells = this tx’s PAA1 | bind-T | `bindTToCells` + `bindPackedStmtToPaa1` |
| C8 | algebraicC residual at the public point | algebraicC kernel | kernel redeem |
| C9 | One spent note: Merkle membership + nullifier + amount-auth | note-auth | payload + redeem, **no** dummy `OP_DROP` |
| C10 | Same-tx binds: all orbits see **one** packed\|\|pairs on input 0 | every kernel `INPUTBYTECODE 0` | first-push body |

**Merkle PICK (C3).** Compact path index is a stack PICK. Index `0xFFFF` must not succeed. Walker: `k = DEPTH-2-idx`; require `k ≥ 0` and `k < DEPTH` before `OP_PICK`. Leftover pair groups empty (skip-N class).

**Compact Merkle is the same tree as JS `MerkleTree.verifyPaired`** iff table index, bit, and leftover-pairs hold. Skip-N (spender `N` with leftover pairs dropped) was a counterexample; it is closed.

---

## 3. JS-only rows (holes, not features)

These run in `verifyFri` / `plugin.verify` / `checkBatchSpends`. A miner does **not** run them. If the product sentence includes the row, the covenant is unfinished.

| Hole | What JS does | What the lock does | Product rule |
|---|---|---|---|
| H1 | `checkBatchSpends` for `--batch-exit` notes 2…N | Walks **one** note (C9) | Completeness §8: not “leave it in `verifyFri`”. Step kernels are the substitute. Until then N-note batch-exit is **not** B. |
| H2 | Envelope **A**: membership/nullifier in `verifyFri` | A has no note-auth | A is a **different** statement. Do not sell as B. |
| H3 | `plugin.verify` of the encoded blob: FRI + membership **without** preimage | B note-auth is the preimage bind for **one** note | Extra auths in the blob are not in the lock. |
| H4 | `verifyFri` traces Merkle at every query layer on the **proof object** | Lock checks openings the unlocking actually **pushes** (C3 leftover-pairs) | Lab must run **both**. JS-only 36 openings was the skip-N hole. |

**Not JS-only (different defect):** C9 unlocking publishes amount/rho/owner. Anonymity set 1. Privacy, not “JS checked it.”

**Lab bar:** `createVirtualMachineBch2026(true)` **and** `verifyFri` of the **same** proof. Split “JS reject / VM accept” on a mutated proof is P0.

---

## 4. Correspondence oracle

Shipped: `test/correspondence-oracle.test.ts` / `scripts/correspondence-oracle.ts`.

- Honest B: `verifyFri` ok **and** every successor input `standard=true` accept.
- Mutated proof (`mutateTraceAndProve`): `verifyFri` fail **and** VM fail.
- Mutated unlocking, honest proof (omit openings, junk inv, 0xFFFF PICK, dup×36, grind nonce): VM fail. `verifyFri` may still pass — chain stricter is allowed.

---

## 5. Read vs Circle / ethSTARK (same-team)

**Not an independent implementer.** This section is the literature check the freeze promised. A second person still has to read spec + kernels.

| Source | What we take | What we do not take |
|---|---|---|
| Circle STARKs, ePrint 2024/278 (Haböck–Levit–Papini) | Circle \(x^2+y^2=1\) over M31; p+1 smooth; fold on circle | Their production/Stwo parameter sheets; extension-field FRI |
| ethSTARK, ePrint 2021/582 §5.9 toy conjecture, §5.10.1 | Query bits \(\sim q \log_2(1/\rho)\) + grind under SHA-256 RO | \(\min\) with \(\log_2\|K\|\); Rescue AIR; \(\rho=1/4\) default sheet |
| ethSTARK §3.5 informal | blowup \(2^k\) ⇒ \(\lambda/k\) queries at rate \(1/B\) | We use \(k-1\) at rate \(2/B\) |
| Stwo book | “each query gives \(\beta=\log_2 B\) bits” under the toy conjecture | Stwo QM31; we are M31-only |
| ePrint 2026/858 | Exists; proven FRI above Johnson | **Not** our bound; we do not claim it |

**Accept:** query-conjecture 128 at rate 2/B + grind 20 + SHA-256, **with** the M31/SZ gap explicit.  
**Reject:** bumping \(q\) this freeze to manufacture a 128 that Stwo would recognize as field+query bits.

---

## 6. What this freeze does not claim

- Lean HVZK; Orchard-style hiding; Poseidon-in-AIR (TRACE 64 cannot hold ~5112 S-boxes).
- Batch-exit N notes (H1).
- Mainnet; “no remaining PICK/stack bugs” beyond the shipped falsifiers.
- The pre-patch Chipnet tx `56be9ac0…`.

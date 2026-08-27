# Field-extension choice for BCH Circle FRI

Research note, 2026-08-23. No vk, no lock change, no density run. This file is the choice, not the construction.

RULES §2: `min(FRI-query, field, SZ, hash-RO) ≥ 100`. Query worksheet of the 91 KB freeze is 128 at rate \(2/B\). Hash-RO is SHA-256. Field and Schwartz–Zippel are **M31 (~31)**. This note asks which **extension** is the right next family for *this* chain, not which field is fastest on a CPU prover.

---

## 1. What “the field” is in the protocol

ethSTARK (ePrint 2021/582, (19)) writes conjectural security as

\[
\lambda \ge \min\{\zeta + R\cdot s,\ \log_2|K|\}-1
\]

with \(K\) the field from which **random challenges** are drawn. Query bits and field bits are different knobs. Bumping \(q\) does not buy \(\log_2|K|\). The freeze already refused that cheat.

Circle STARKs / Stwo split the job further (Stwo book, “Mersenne primes”; Chainsafe Circle tutorial):

| Role | Stwo name | Where it lives |
|---|---|---|
| Circle, FFT domain, Merkle **query values** | **BaseField = M31** | \(x^2+y^2=1\), \(p+1=2^{31}\) |
| Fiat–Shamir λ, DEEP, fold mixing | **SecureField = QM31** | degree-4 extension, \(\lvert K\rvert=p^4\approx 2^{124}\) |

“We should be doing FRI over a bigger field” is almost right and slightly too coarse. The **circle stays on M31**. The **challenges and post-fold values** move to the extension. Query openings that Merkle-walk are still base-field elements. That is the construction Stwo and Plonky3 actually ship, not “replace every felt with a 4-tuple from layer 0.”

Schwartz–Zippel of an identity of degree \(d\) at a QM31 point is \(\sim d/p^4\). TRACE 64, cubic composition: tens of bits over M31, **far above 100** over QM31.

---

## 2. Degree: the floor is 100, so 4 is the smallest that works

\(\log_2 p \approx 31\). Tower degree \(e\):

| \(e\) | \(\log_2 p^e\) | Floor 100 |
|---|---|---|
| 1 M31 | ~31 | fail |
| 2 CM31 = M31\[i\]/(i²+1) | ~62 | fail |
| 3 | ~93 | fail |
| **4 QM31** | **~124** | **pass** |
| 5 | ~155 | pass, extra limb, extra bytes |

There is no degree-3 Circle/Stwo tower in production. Degree 4 is the **minimal** extension that satisfies RULES §2 without changing the prime. Anything smaller is a silent “claim 100 on 93.”

ethSTARK’s own 128-bit table used a ~61-bit prime and **degree 3** (\(\lvert K\rvert\approx 2^{183}\)) plus more queries. We already have \(q=36\), grind 20. We do not need their query sheet; we need their **min with \(\log_2|K|\)**.

---

## 3. Why the 91 KB skeleton wants M31’s circle, not another prime

Circle STARKs (ePrint 2024/278): efficient FRI when **\(p+1\)** is divisible by a large power of two. Mersenne \(p=2^{31}-1\) gives \(p+1=2^{31}\). That is why this lock has `foldPair`, \(\pi(x,y)=(2x^2-1, 2xy)\), and conjugation \((x,-y)\).

Other popular small primes buy a **different** FFT:

| Prime | Why people use it | FFT group | Cost of switching here |
|---|---|---|---|
| **M31** \(2^{31}-1\) | Cheapest 31-bit reduction; Circle | Circle, \(p+1\) 2-adic | **What we have** |
| BabyBear \(2^{31}-2^{27}+1\) | Max 2-adicity of \(p-1\) (27) | Standard multiplicative | Throw away circle kernels; new family |
| KoalaBear \(2^{31}-2^{24}+1\) | Small S-box \(x^3\) for Poseidon | Standard | Same; plus Poseidon-in-AIR is not our lock hash |
| Goldilocks \(2^{64}-2^{32}+1\) | 64-bit word, 2-adicity 32 | Standard | New skeleton; still only ~64 bits, so **still need an extension** (deg 2 → ~128) |
| BN254 / BLS12 | Pairings | n/a | No pairing opcode. Groth16. RULES: Circle FRI |

KoalaBear/BabyBear “win” on **prover CPU** and algebraic hashes (Plonky3 notes). That is ABL’s **internal-hash plug** and a **different verifier FFT**, not a better SecureField for this lock. RULES §4: SHA-256 default, no silent Poseidon-in-the-lock.

Goldilocks as *base* field would rebuild FFT and still need a quadratic extension to clear 100 bits. It is not a shortcut around a 4-limb tower; it is a different 2-limb tower on a different circle.

---

## 4. What is actually “best for BCH” (not for a Rust prover, not for BTC script)

May 2026 CashVM (CHIP VM limits + BigInt):

- `OP_MUL` / `OP_MOD` cost \(100 + 2\cdot\lvert c\rvert + \lvert a\rvert\cdot\lvert b\rvert\) (bytes of VM numbers).
- Budget \(800\times(41+\text{unlocking})\). Redeem ≤ 10 000. Tx ≤ 100 000.
- Native `OP_SHA256`. No pairings.

**M31 limb is 4 bytes.** One `M31_MUL` is a handful of ops (`OP_MUL <p> OP_MOD`). Goldilocks limb is 8 bytes: \(\lvert a\rvert\cdot\lvert b\rvert=64\) vs 16, so **one native mul is ~4× dearer** before you even extend.

**Bitcoin Script (BitVM, no BigInt)** is the opposite world. BitVM’s M31 mul is **1415 weight** (bit-sliced). Their QM31 mul is **13321**; BabyBear4 is **13576**. Those numbers measure *bitwise emulation*. Copying them onto BCH would be a category error. On BCH the extension cost is **how many 4-byte muls + stack traffic**, not 13k Bitcoin weight units.

Implication: the BCH-native comparison is

1. Keep 4-byte M31 limbs we already reduce with \(p=2^{31}-1\).
2. Pay a **tower** of those muls (Karatsuba: CM31 ~3 M31 muls; QM31 ~3 CM31 muls ≈ 9 M31 muls, Stwo/Papini double-Karatsuba).
3. Pay **blob size** where values become QM31 (16 bytes vs 4) — mostly fold/R after the first mix, not the Merkle L0 query values (still M31).

That is why QM31 is the default candidate: **same limbs, same circle, smallest \(e\) that clears 100, published irreducible, Stwo vectors to cross-check.**

Irreducible (Stwo):

\[
\text{CM31}=\mathbb{F}_p[i]/(i^2+1),\qquad
\text{QM31}=\text{CM31}[u]/(u^2-2-i).
\]

Do not invent a custom degree-4 polynomial unless a later density measurement shows a real CashVM win. BitVM already found QM31 slightly cheaper than BabyBear4 *even in bitwise script*, because of that tower.

---

## 5. ABL’s three plugs (useful, and they cut the design space)

| Plug | This choice |
|---|---|
| **Pool** (notes, nullifiers, PAA1) | Unchanged. Field extension is not a new note format. |
| **Verifier / ZKP family** | New family: Circle FRI with **QM31 SecureField**. New vk. |
| **Internal hash** | Stay SHA-256 in the lock. Poseidon2-M31 remains a prover-side table id. |

Swapping Poseidon “to get bits” does not extend \(K\). Swapping Groth16 “because 128” abandons Circle and CashVM-native SHA-256. The field plug is the one RULES §2 is pointing at.

---

## 6. What this choice does **not** decide

- Whether QM31 `foldPair` **fits** the freeze box. L6 is 99.29% dense, folds ~90%, R ~88%, ~8 KB tx headroom. That is a **measurement**, after the family is named — a wall with a number, then fold+R fusion if needed. Not a reason to pick Goldilocks today.
- Whether later FRI layers’ 16-byte values blow packed AIR. Query Merkle stays 4-byte M31 if we follow Stwo. Fold/R kernels today assume M31 felts.
- Independent-reviewer acceptance of the ethSTARK *query* conjecture. That stays speculative and named. Field bits from \(\lvert K\rvert=p^4\) are the part that is **not** that conjecture.
- Privacy / TRACE 64 SHA-256 of notes. Different RULES line (§6).

---

## 7. Decision (research, not a vk)

**Candidate SecureField: Stwo QM31.** Base/circle stays M31. Hash stays SHA-256. Pool stays. New vk when the lock actually draws λ from QM31 and correspondence holds.

Reject as *this* next family: stay-M31, CM31-only, BabyBear/KoalaBear (wrong FFT), Goldilocks-as-base (wrong skeleton, still needs an extension), pairings.

How we will *know* it is best for BCH: not CPU benches, not BitVM weight. Isolated then in-skeleton `foldPair` / R-slot **op-cost and bytes** on `createVirtualMachineBch2026(true)` against the 91 KB meters.

No construction in this note.

---

## 8. What ShieldKit-LABS already measured (do not rediscover)

Repo: `Projects/ShieldKit/ShieldKit-LABS`. Lane `research-lanes/bch-native-zk-proof` + contract `research-lanes/bch-shielded-pool-design/research/field-frontier-contract.md`. Occupancy, not this vk.

### Roles (the useful cut)

They refused “an M31 degree-5 proof” as a design name. Separate:

| Role | Symbol | LABS occupancy (v6+) |
|---|---|---|
| Trace / circle coordinates | `B` | M31 |
| Fold **alphabet** (values in the fold kernel) | `E` | **CM31** |
| FRI **challenge** field | `F_fri` | **QM31**, and is **not** `E` |
| Byte hash | `H_outer` | SHA-256 |

That is stricter than “FRI over a bigger field.” Circle stays M31. Cheap Script fold can stay 2-limb. Soundness λ is sampled from QM31.

### One-pair fold, 2026 VM (generator bytecode)

`bch-native-zk-proof/build/fold-score.json` (2026-08-20). One J-fold pair, P2SH32, `standard=true`. Not the 91 KB production `FOLD_PAIR` (that redeem is ~3 kB and already ~90% dense).

| field | limbs | P2SH32 unlocking | op-cost | bare kernel |
|---|---:|---:|---:|---|
| M31 | 1 | 278 | 21995 | ok |
| CM31 | 2 | 543 | 41749 | ok |
| QM31 | 4 | 1365 | 101034 | ok |
| M31-d5 | 5 | 2053 | 151229 | **density fail** (bare) |

Relative: CM31 is the cheapest *extension fold alphabet*. QM31 is ~2.4× CM31 op-cost. **d5 is not a bare-kernel occupant.** Ranking text: fold alphabet ≠ F_fri.

### Why they wanted d5, and why we may not

LABS soundness floor in that contract is **128 raw bits of field cardinality** before a candidate is even a finalist. Least Mersenne \(d\) with \(\log_2 p^d > 128\):

| base | least \(d\) for >128 raw bits |
|---|---|
| M31 | **5** (20-byte payload) |
| M61 | 3 |
| M89 | 2 (`X^2+1` certified) |

They listed **M31-d4 (~124 bits) as a control, not a finalist**, unless a separate repetition/event-DAG closes the gap to 128. That is their 128-bit *systemic* target, not our RULES §2 **floor 100 / target 128**.

Our min is `min(query, field, SZ, hash-RO)`. Query worksheet is already 128. Field QM31 is ~124. **min ≈ 124 ≥ 100.** The *target* 128 for the min is still slightly short on the field knob (124 vs 128). LABS’ answer to that shortfall was d5 — and d5 **failed density** on a *bare* fold. That is a measured wall, not a preference.

Also in that repo: **M29 killed** (\(2^{29}-1=233\times1103\times2089\)). Goldilocks **killed as Circle occupant** (traditional multiplicative-FRI / Poseidon2-hash-chain 29k specimen; 22-input ~120 kB layout is not this lock). `H_outer` SHA-256, not Poseidon2-in-script.

### What LABS does *not* give us

- Not a 91 KB successor with QM31 λ.
- Fold-score is generator bytecode, not our inlined 6-query fold kernel.
- They did not pin E; they scored it.
- Raw cardinality is not systemic soundness (their event-DAG warning). Do not add “124 + 128 = 252.”

Useful here: **split `E` vs `F_fri`**, **d5 is too fat to be the fold alphabet**, **QM31 is the soundness occupant they already named**, **Goldilocks is not the circle**.

---

## 9. Isolated 2026-VM muls (this lane, not a successor)

`scripts/measure-field-mul.ts` → `survey/field-mul-measure.json`. One `a*b mod p`, unlocking = expected ‖ a ‖ b. `createVirtualMachineBch2026(true)`.

**Wire of one max element** (VM number, then push opcode):

| | payload | unlocking to push it |
|---|---:|---:|
| M31 | 4 B | 5 B |
| M107 | 14 B | 15 B |
| M127 | 16 B | 17 B |
| 4× M31 limbs (QM31 as four pushes) | 16 B | **20 B** |
| 1× M107 | 14 B | **15 B** |

Yes: 14 vs 4×4 is **2 bytes of payload**. On the script wire it is **5 bytes** per element, because four limbs pay four push opcodes. Packed AIR blobs (concatenated 4-byte felts, one push) would be closer to the 2-byte gap (16 vs 14).

**One mul, bare locking** (modulus lives in the script):

| | unlocking | locking | op-cost | `a.len×b.len` term |
|---|---:|---:|---:|---:|
| M31 | 15 | 8 | **783** | 16 |
| M107 | 45 | 18 | **1413** | 196 |
| M127 | 51 | 20 | **1629** | 256 |

BigInt does **not** blow the tx. One 14-byte `OP_MUL` is ~1.8× a 4-byte mul, not 196/16 ≈ 12×, because the 100-per-opcode base dominates a *single* mul. The quadratic byte-product shows up when you do **many** muls (a fold kernel), or when the modulus push itself sits in every redeem (14 B vs 4 B in locking).

**Tower vs one wide mul** (same harness, sequential M31 squares vs one M107 mul):

| | bare op-cost |
|---|---:|
| 1× M31 square | 783 |
| 3× M31 squares (~CM31 muls) | 1743 |
| **9× M31 squares (~QM31 Karatsuba)** | **4623** |
| 16× M31 squares (schoolbook 4-limb) | 7977 |
| **1× M107 mul** | **1413** |

For *one field multiplication*, no-tower M107 is cheaper in op-cost than a 9-mul M31 tower. That is not yet `foldPair` (stack, inv, six queries). It is the BCH-VM root: **width is cheap once; a tower is many opcodes.**

P2SH32 wraps add HASH256 of the redeem (~2 digest iters) and put the modulus in the unlocking redeem. M31 p2sh unlocking 24 B / 1640 ops; M107 64 B / 2280 ops. Still tiny next to a 3 kB fold redeem.

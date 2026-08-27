# GLM-OCCUPANCY-C — RULESET

**Work only in `research-lanes/glm-occupancy-c`.** Do not edit `research-lanes/sha-in-occupancy-c`, `research-lanes/ideal-bch-shielded-pool-stark`, `research-lanes/nonstandard-ideal-circle-stark`, `research-lanes/envelope-b-standard`, `research-lanes/batch-exit-walkin`, or `workspaces/any-amount` for this track.

**vk changes if any line of this file changes.** Changing a numbered rule, a floor, or a fail-closed sentence without changing the vk string is a silent family swap. Forbidden.

Sibling HASH_BIT host (`5de68272…`, 99144 B, leftover merkle/prefix) is **evidence**, not this product. The 36-input SHA AIR extra of **94788 B** (occupancy+AIR ≈ 194 kB) is a wall on that geometry, not this one. Occupancy `60d186de…` / 99043 B is evidence. Parent 91 KB freeze (`survey/artifacts/argument-freeze/`, Chipnet `58b7df7f…`, 91598 B, vk `circle-fri-m31-t64-b16-q36-g20-fri9`) is evidence: M31 (fails §2) and preimage in unlocking (fails §6). The nonstandard 1 MB fork is a sibling box, not this product. Parent lane `sha-in-occupancy-c` at `e0b0de3` shipped fused N = leftover L0 C(z) + 144 B leftover-z `C_SHA` (mixed VM-reject fused input 12; 100 kB still off) — that lock state is this lane’s **starting artifact**, not the named end.

Chipnet only. Never mainnet.

---

1. ONE STANDARD TX
   tx ≤ 100_000 B. Each unlocking and each redeem ≤ 10_000 B.
   createVirtualMachineBch2026(true) accepts. Electrum relays it.
   Not JSON-RPC, not standard=false, not “C hops pretending to be one tx.”

2. SOUNDNESS ≥ 100 BITS, ALL OF THEM
   min(FRI-query, field, SZ, hash-RO) ≥ 100.
   Query worksheet alone is not 100. M31 (~31) is not 100.
   If the field is M31, you do not claim 100. Extension FRI (or a signed split) first.
   Floor 100, target 128. n=32/q=8 is a fail.

3. THE LOCK IS THE PAPER
   Numbered checks C1…Ck. Miner runs every one. verifyFri is a lab oracle.
   JS-fail / VM-accept on a mutated proof is P0.
   JS-only membership, nullifier, fold, bind-T, or extra batch notes = unfinished.

4. FAMILY
   Circle FRI, SHA-256 default (OP_SHA256). No silent Poseidon-in-the-lock.
   Unique first-fold orbits, grind, same-tx PAA1. Completeness list is the vk.
   Leaf↔nf↔amount is occupancy composition C, same 36 queries.
   Not 36 extra SHA-AIR inputs. Not leftover merkle/prefix as the relation.

5. ON-CHAIN MONEY RELATION
   Note Merkle membership, nullifier, amount-auth, foldPair, R, bind-T: in script.
   Encoding ≡ spec (leftover pair groups empty, PICK in range, N not spender-free).
   Dummy pad / leftover-fill / density ballast is not a check.

6. SHIELDED MEANS SHIELDED
   If the tin says shielded/confidential pool: rho/owner/amount preimage is NOT
   in the unlocking. Leaf↔nf↔amount lives in the on-chain STARK.
   Tagged SHA-256 commits ≠ Maxwell; say so. TVL public is allowed if stated.

7. NO SHENANIGANS
   No dummy pad, packTo, KERNEL_UNLOCK_PAD, fewer queries/grind/TRACE to fit,
   36 extra SHA-AIR inputs, consensus hash meters as the pass bar, or “the lane cannot.”
   A wall is a number, then the next construction.

8. PROVEN / MEASURED / SPEC
   Proven = lock + correspondence.
   Measured = bytes, op-cost, Chipnet Electrum txid.
   Speculative = FRI toy conjecture, named in the vk.
   Chipnet dust ≠ production. Independent read of spec+kernels before coins.

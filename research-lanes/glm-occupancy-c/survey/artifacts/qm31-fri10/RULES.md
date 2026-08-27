# IDEAL BCH SHIELDED-POOL STARK — RULESET

**Work only in `research-lanes/ideal-bch-shielded-pool-stark`.** Do not edit `research-lanes/envelope-b-standard`, `research-lanes/batch-exit-walkin`, or `workspaces/any-amount` for this track.

**vk changes if any line of this file changes.** Changing a numbered rule, a floor, or a fail-closed sentence without changing the vk string is a silent family swap. Forbidden.

Parent 91 KB freeze (`survey/artifacts/argument-freeze/`, Chipnet `58b7df7f…`, 91598 B, vk `circle-fri-m31-t64-b16-q36-g20-fri9`) is **evidence**, not this product. That freeze is M31 (fails §2) and walks notes with preimages in the unlocking (fails §6).

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

5. ON-CHAIN MONEY RELATION
   Note Merkle membership, nullifier, amount-auth, foldPair, R, bind-T: in script.
   Encoding ≡ spec (leftover pair groups empty, PICK in range, N not spender-free).
   Dummy pad / leftover-fill / density ballast is not a check.

6. SHIELDED MEANS SHIELDED
   If the tin says shielded/confidential pool: rho/owner/amount preimage is NOT
   in the unlocking. Leaf↔nf↔amount lives in the on-chain STARK.
   Tagged SHA-256 commits ≠ Maxwell; say so. TVL public is allowed if stated.
   Anonymity set 1 for a walked note is not shielded.

7. BATCH EXIT
   Opt-in, shared CSPRNG window. N notes in ONE standard tx ⇒ N on-chain walks
   (generic step program or equivalent). Nullifiers must not need to be painted
   into genesis before deposits exist. CLI flush compiles+VM-checks that tx.
   verifyFri extras are not a batch.

8. ENVELOPES ARE TYPES, NOT NICKNAMES
   A = weaker lock (not this product).
   B = this object, one standard tx, full completeness.
   C = fund-safe ≤100 KB hops, reject/reclaim; not a substitute for B.
   Do not relabel A or C as B.

9. NO SHENANIGANS
   No dummy pad, packTo, KERNEL_UNLOCK_PAD, fewer queries/grind/TRACE to fit,
   consensus hash meters as the pass bar, or “the lane cannot.”
   A wall is a number, then the next construction.

10. PROVEN / MEASURED / SPEC
    Proven = lock + correspondence.
    Measured = bytes, op-cost, Chipnet Electrum txid.
    Speculative = FRI toy conjecture, named in the vk.
    Chipnet dust ≠ production. Independent read of spec+kernels before coins.

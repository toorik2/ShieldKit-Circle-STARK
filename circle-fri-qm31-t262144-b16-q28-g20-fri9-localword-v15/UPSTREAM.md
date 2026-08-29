# Upstream provenance

This LABS lane is synchronized with:

- repository: `https://github.com/CyberAshven/ShieldKit-Circle-STARK.git`
- branch: `@ABLalgorithm`
- commit: `1bfb415aed96c0f2bc366667cc4880ee40a0fd7e`
- commit subject: `docs: amount-hiding handoff is self-contained`
- source tree: `research-lanes/nonstandard-ideal-circle-stark`
- source tree object: `8ee71712449627281f52d33e36c2b5613b683957`
- synchronized: `2026-08-27`

The initial LABS import came from the same branch at
`4c43e0f37d36f6e4005db9555ca5365afcd9c574` (tree
`7496a9c4b130a3e97eb7822e4c804c90cae1c7ac`). The reviewed synchronization to
`1bfb415` applied the six intervening commits and changed 16 upstream files.
Historical `PINNED_FROM` and `lane.json` metadata remain upstream research
history.

## Self-contained boundary

Build, test, research, and documentation dependencies must live in this lane or
be declared by its own `package.json`, `package-lock.json`, Cargo manifests, and
Cargo lockfile. Code must not import another ShieldKit checkout or sibling
research lane. Sibling paths in historical prose are evidence references only.

Future upstream synchronization is an explicit, reviewed operation. Do not
silently replace local work from a moving branch.

## Successor Circle FFT dependency

The LABS successor worker declares StarkWare's `stwo` crate directly in its
own Cargo manifest and lockfile, pinned to commit
`826591c6c371376810ca8213b5812d5daf6d5092` (crate version 2.2.0, Apache-2.0).
Only its Circle-domain/FFT prover API is used so far; its default hashes,
transcript, parameters, and proof encoding are not adopted as this lane's
construction. The worker pins Stwo's required `nightly-2026-01-15` toolchain.

## LABS-local preservation

The synchronization intentionally preserves `AGENTS.md`, `UPSTREAM.md`,
`PRIVACY-AUDIT.md`, and the LABS privacy-blocker section appended to
`STATUS.md`. These are LABS integration or audit material, not mismatches
silently presented as upstream source.

## Synchronization validation — 2026-08-27

- Every upstream-modified file matched the prior `4c43e0f` snapshot before it
  was replaced; the new `AMOUNT-HIDING.md` had no local collision.
- All 243 files in the current upstream subtree match `1bfb415`, except for the
  explicitly preserved LABS privacy-blocker addition in `STATUS.md`.
- No sibling checkout, ignored `.local/`, wallet material, or `node_modules/`
  content was imported.
- Targeted FRI11-parameter and fused-leftover tests passed. No broad or Chipnet
  suite was run.
- `npm run typecheck` still reaches the compiler and reports the inherited
  upstream errors in `covenant-spend.ts`, `vm-verifier.ts`,
  `hole-free-b.test.ts`, `qm31-lab-successor.test.ts`,
  `qm31-occupancy.test.ts`, and `statistical-zk.test.ts`.
- The files implementing the audited 32 proof openings and 36 booleanity
  carrier openings did not change in this synchronization, so the
  transcript-level privacy blocker remains applicable.

## Import validation — 2026-08-27

- Recursive comparison against the temporary upstream checkout differed only by
  this file and `AGENTS.md` before the LABS privacy audit was recorded.
- `npm ci --ignore-scripts` completed from the lane-local lockfile with no audit
  vulnerabilities.
- `npm run typecheck` reaches the local compiler but inherits upstream type
  errors in `covenant-spend.ts`, `vm-verifier.ts`, `hole-free-b.test.ts`,
  `qm31-lab-successor.test.ts`, `qm31-occupancy.test.ts`, `r-onchain.test.ts`,
  and `statistical-zk.test.ts`. These were not weakened or silently fixed during
  import.
- A two-file legacy test invocation was stopped after 30 seconds with no useful
  output. No broad suite was run.
- The focused amount-transcript result is recorded in `PRIVACY-AUDIT.md`.

# Nonstandard ideal Circle STARK working scope

## Boundary

- Treat this directory as the complete working surface for this research lane.
- Do not edit sibling ShieldKit checkouts or depend on their working trees.
- Read `RULES.md`, `GOAL.md`, `ARGUMENT.md`, `COMPLETENESS.md`, `NEXT.md`, and
  `UPSTREAM.md` before changing the construction or its claims.
- Preserve the imported upstream commit in `UPSTREAM.md`; synchronize only by an
  explicit, reviewed import.

## Research discipline

- Optimize for inner simplicity: state the relation and privacy experiment
  before optimizing its encoding.
- Preserve proven, measured, speculative, and unresolved claim boundaries.
- Do not call the construction shielded, statistically hiding, zero-knowledge,
  post-quantum secure, complete, or qualified without evidence for the exact
  serialized proof and final transaction envelope.
- Privacy review covers information recoverable from representations, not only
  contiguous secret-byte searches. Bit-packed traces, schedules, openings,
  carriers, paths, and auxiliary artifacts are part of the transcript.
- Only the human user declares the named end complete.

## Verification pace

- Prefer the smallest targeted check that can falsify or support the current
  claim. Avoid long non-essential suites while iterating.
- Before a final construction claim, verify the exact user-visible artifact or
  serialized transaction end to end and report broader checks skipped.
- Use the lane-local lockfiles and commands. Do not weaken checks to obtain a
  pass.

## Chain and secret safety

- Default to offline analysis. Do not broadcast, fund, spend, or mutate chain
  state without an explicit request. Never target mainnet.
- Never commit wallet material, credentials, WIFs, mnemonics, RPC
  authentication, `.local/`, `node_modules/`, or generated secrets.
- Use `bch-constants` for precise BCH constants, `cashscript-next` for pinned
  CashScript Next analysis, and `bchn-rpc` for every chipnet/RPC operation.

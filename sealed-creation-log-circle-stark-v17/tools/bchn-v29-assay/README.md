# BCHN v29 offline script-input assay

This helper runs one serialized transaction input through the unmodified BCHN
v29.0.0 script interpreter with full source-output context. It exists to make
v17's operation-cost and acceptance measurements independent of libauth's
May-2026 `OP_DEFINE` accounting defect.

## Fixed engine

- BCHN tag: `v29.0.0`
- Git tag commit: `89a591f7c5b1fd110c0819377ad8f2647d656800`
- GitHub source archive SHA-256:
  `0dbc86a416e376a4b3813004e7aa493d7a4473467f32a5f5909a7408a4a3b2e4`
- fallback CMake: `4.1.2`, Linux x86-64 archive SHA-256
  `773cc679c3a7395413bd096523f8e5d6c39f8718af4e12eb4e4195f72f35e4ab`
- fallback Boost headers: Arch Linux `boost-1.91.0-2`, archive SHA-256
  `58a6ba3b464ff63993829684251c3adf72f71374da1f3151b2033471de08322a`

The build downloads only these public, hash-pinned source/tool archives into
the ignored lane-local `.local/bchn-v29-assay/` cache. It builds the static
`bitcoinconsensus`/`script` dependency perimeter and this small executable; it
does not extract the large VMB/benchmark fixture corpora and does not build or
start `bitcoind`.

The host must provide a C++20 toolchain plus GMP, libevent, OpenSSL, and Boost
chrono/filesystem libraries. On Linux x86-64, the script supplies pinned CMake
and Boost headers when they are absent; set `V17_BCHN_BOOST_LIBRARY_DIR` only
when the two Boost libraries are outside `/usr/lib`.

```bash
scripts/build-bchn-v29-assay.sh
scripts/test-bchn-v29-assay.sh
```

The test is BCHN's VMB vector `67am0u`, input 1. It locks the activated BCHN
result: valid, base/composite operation cost `803`, operation-cost limit
`32800`. Libauth `3.1.0-next.8` reports `802` for the same input because it
omits the one-byte function-body push cost. A second KAT, `a9k5xz`, verifies
that a P2SH input can inspect a sibling input's token-prefixed source output,
proving that the adapter is using BCHN's full context rather than its limited
single-coin constructor. That second KAT runs in consensus mode, the relevant
mode for v17's nonstandard-by-size one-transaction research boundary.

## Input contract

```text
v17-bchn-v29-assay \
  --transaction-file TX_HEX_FILE \
  --source-outputs-file SERIALIZED_VECTOR_CTXOUT_HEX_FILE \
  --input-index N \
  --mode consensus|standard
```

For small probes, `--transaction TX_HEX` and `--source-outputs HEX` are
equivalent. Use the file forms for v17-sized artifacts: Linux command-line
argument limits are smaller than the combined hex encoding of a near-1 MB
transaction and all source outputs. ASCII whitespace in hex files is ignored.

`--source-outputs` uses the VMB/BCHN encoding: CompactSize input count followed
by one network-serialized `CTxOut` per transaction input. `CTxOut` serialization
includes CashToken prefixes and data. The vector length must equal the input
count, decoding must consume every byte, and `ScriptExecutionContext` receives
all outputs, so sibling-input and token introspection have full context.

The JSON result reports the engine/tag, exact flags, validity, script error,
base and composite operation costs, hash iterations, sigchecks, and limits.
`sigChecksInputLimit` is the nullable standard-policy input bound;
`sigChecksTransactionLimit` is BCHN's `3000` consensus ceiling, which this
per-input helper reports but cannot itself enforce. Metrics are marked reliable
only when `VerifyScript` accepts, matching BCHN's own API contract.

## Claim boundary

This is an offline, per-input `VerifyScript` oracle. It performs no RPC, node,
wallet, funding, broadcast, or chain mutation. It does not run BCHN's
transaction-level checks for token supply/genesis, transaction sanity, or
standardness. A passing result is BCHN script-input evidence only; every input
must pass separately, its sigchecks must be accumulated against the reported
transaction ceiling, and transaction-level invariants need their own gate.

Rule evidence: CashScript Next records `LIM-001`, `LIM-003`, `LIM-005`,
`LIM-006`, `LIM-007`, `LIM-011`, and `INT-002`. Exact current constants were
cross-checked against the `bch-constants` table derived from BCHN source commit
`864c53ee34924cca6c6d96607ff2cedcdccf02`; this executable intentionally pins
the released BCHN v29.0.0 engine rather than substituting those later source
files for runtime measurement.

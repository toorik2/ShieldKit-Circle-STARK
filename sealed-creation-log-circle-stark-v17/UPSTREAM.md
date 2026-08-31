# Upstream provenance

The historical source imported into LABS was:

- repository: `https://github.com/CyberAshven/ShieldKit-Circle-STARK.git`
- branch: `@ABLalgorithm`
- commit: `1bfb415aed96c0f2bc366667cc4880ee40a0fd7e`
- source tree: `research-lanes/nonstandard-ideal-circle-stark`
- source tree object: `8ee71712449627281f52d33e36c2b5613b683957`
- synchronized: 2026-08-27

That snapshot is provenance, not the current construction identity and not
current qualification evidence.

## Local lineage

V17 is a purification successor to the frozen local V16 construction:

```text
V16 construction  f29ef06d0e2868a4e6207f060b6246fd49a51fabd0bd14e7d41b48324a1e70e5
V16 fingerprint   8031205218e91763da4414eeae1c8411cb61478e65515a2ff20ff9168d512af6
V17 protocol      9195e2b02944a9355c50a76e5ddc33e2e03ba48375e95932bb0713933e7ebc96
V17 construction  c434ed36bf04d8265ec6d0e447f69cd7a437baf91bcc6eab6eb0ff5f9cbe62e1
```

V16 is evidence, not an editable compatibility surface. V17 retains the
constitutional relation and privacy membrane while replacing the verifier
construction, theorem map, q44 transcript, grouped binary FRI, mixed-Merkle
cuts, affine carrier reader, monotone allocation closure, and authenticated
ROM/linker identity.

## Self-contained boundary

No product source imports another ShieldKit checkout or sibling research lane.
The TypeScript and Rust dependencies are declared in this lane's package,
Cargo, and lock files. Ignored `.local/`, `node_modules/`, Rust targets, prover
scratch data, raw proofs, and raw transactions are caches or local evidence,
not source dependencies.

The lane-local worker pins StarkWare's Stwo crate to commit
`826591c6c371376810ca8213b5812d5daf6d5092`, crate version 2.2.0, under
`nightly-2026-01-15`. V17 uses its Circle-domain and FFT machinery but owns its
SHA-256 transcript, parameters, commitments, proof codec, and BCH verifier.

## Synchronization rule

Future upstream synchronization must be explicit and reviewed. Never replace
the local construction from a moving branch, silently restore deleted legacy
surfaces, or present upstream, FRI11, or V16 evidence as V17 evidence. Any
identity-bound change requires new protocol/construction identities as
applicable and fresh all-profile qualification.

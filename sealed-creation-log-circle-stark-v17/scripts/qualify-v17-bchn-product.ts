/**
 * The v1 standalone artifact-only entry point was intentionally retired.
 * Raw transaction paths cannot prove which measured linker product they came
 * from. The production driver calls qualifyV17BchnProduct in-process with the
 * live V17FinalInfrastructureSet, so the exact certificate, proof partition,
 * worker bank, ROM pages, and serialized transactions share one identity.
 */
if (process.argv.includes("--help") || process.argv.includes("-h")) {
  console.log(`v17 BCHN qualification is identity-bound and runs inside:

  npm run qualify

The former raw-path-only command is disabled because it could qualify an
arbitrary topology-compatible transaction without its linker certificate.`);
  process.exit(0);
}

throw new Error(
  "identity-bound v17 BCHN qualification must run through npm run qualify",
);

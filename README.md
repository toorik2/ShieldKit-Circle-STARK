# ShieldKit Circle STARK

Public collaboration mirror of the Circle-domain FRI shielded-pool research
lane from ShieldKit-LABS.

The lane is preserved at
[`research-lanes/bch-shielded-pool-design/`](research-lanes/bch-shielded-pool-design/)
so its content-addressed paths and sealed validation bindings remain stable.
It is a research workspace, not a qualified implementation or product release.

## Start here

```bash
npm ci
npm run lane:shielded-pool:research:test
```

Initial mirror provenance: ShieldKit-LABS commit
`c92e1f81176f6d196410e70564c50c2bdbd02cb9`.

ShieldKit-LABS retains its copy of this lane. Synchronization between the two
repositories should be explicit and reviewable rather than automatic.

The Telegram-derived source package under
`research-lanes/bch-shielded-pool-design/sources/telegram-2026-07-29/` is
intentionally excluded from this public mirror, including chat exports and
source images (the architecture JPEG is not published here).
The complete LABS lane validator remains bound to that private source package,
so it is not a clean-clone validation entrypoint for this public mirror.

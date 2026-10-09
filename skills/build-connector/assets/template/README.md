# my-connector

A bitcd connector: an executor over `@bitcd/core/reconcile` for one governed
system. Copy this directory next to the `bitcd-core` checkout, so `check.mjs`
finds the proof rig's keystore and deployment by default, then:

```bash
pnpm install
pnpm check                                   # proves the loop against the proof rig's org on the devnet
BITCD_EXECUTOR_ADDRESS=… BITCD_EXECUTOR_PK=… BITCD_DEPLOYMENT_FILE=… pnpm watch
```

`provider.mjs` is the file to replace: it governs one JSON file on disk until a
real system is wired in. `executor.mjs` is the loop and stays. `check.mjs`
proves the connector on a local devnet; its header lists the environment it
reads. `@bitcd/core` comes from npm; for an unreleased checkout, set the
dependency to `link:../bitcd-core/core`.

# bitcd indexer

The off-chain **materialized view**. The chain is a control plane, **not a query
plane**: "is everything Synced?", drift dashboards, and history are answered
from the **event stream**, never by per-request on-chain reads.

It folds `ValueChanged` (desired) + `StatusChanged` (observed) per `value_key`
and **derives** the authoritative `Synced`/`OutOfSync` — the contract never
computes it. Drift, revision lag, and an executor's `SYNCED` claim over a stale
digest all surface honestly from the derivation. It also folds
`ProposalApproved` + `ApprovalSigned` into the governance tally — which
approvals were machine votes and which were intent-bound human signatures
(fleet/notary quorums included) — and `HumanReviewRequested` into the
per-proposal escalation flag.

## Run

```bash
export NO_PROXY="localhost,127.0.0.1,0.0.0.0,devnet,ministack"
node src/index.mjs            # current view (table) + "is everything Synced?"
node src/index.mjs --json     # the projection as JSON
node src/index.mjs --watch    # re-poll + reprint every few seconds
```

Config via env: `BITCD_RPC`, `BITCD_DEPLOYMENT_FILE` (defaults match the e2e dev
stack). The folds come from `@bitcd/core/events` (`fetchAllEvents`,
`projectKeys`, `projectProposals`) — shared with every consumer (executors,
the console UI), so every reader agrees on the exact derivation.

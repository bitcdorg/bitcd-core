# Contributing to bitcd

Thanks for your interest. bitcd is a governed etcd on Starknet: the contract
**stores and gates, it never computes business logic**. Before writing code,
read [`AGENTS.md`](AGENTS.md) (the golden rules and the security invariants)
and the [`README`](README.md) for the layout of this repo and where use-case
code belongs.

## Ground rules (the short version)

The project's **golden rules** (dumb contract, no on-chain scripting, control
plane not data plane, append-only, block-time only, OpenZeppelin components)
are listed in [`AGENTS.md`](AGENTS.md) — **PRs that violate them will not
merge.** Any change touching governance, policy, or `commit` dispatch must
additionally preserve **all** the security invariants listed there.

## Build & test

```bash
# contract — the snforge suite must stay green
cd contracts && scarb build && snforge test
```

The full local stack (host and docker/compose paths, toolchain pins, gotchas)
is described in [`AGENTS.md`](AGENTS.md). The JS side is a **pnpm workspace**:
one `pnpm install` at the repo root. TTL expiry in tests uses
`devnet_increaseTime` / `start_cheat_block_timestamp`, never wall-clock sleep.

## Pull requests

- Keep the snforge suite green; add regression tests for behavior changes,
  named for the property they pin.
- **Governance-touching contract changes gate on a security audit**: a
  `cairo-auditor` deep run with no unresolved high/critical findings. Expect
  this to be required before merge.
- **Explain non-obvious choices where they apply** — in the comment or README
  next to the code, rationale first. The design record lives in the `docs`
  repo (the bitcd.org site).
- Substrate non-goals are tripwires: use-case schemas, product daemons, and UI
  do not belong here. Scope changes go through an issue first.
- Never commit secrets (`*.key`, `*.pem`, `.env*`, account JSONs are
  gitignored; keep it that way).

## Reporting security issues

Please do not open public issues for vulnerabilities — see
[`SECURITY.md`](SECURITY.md).

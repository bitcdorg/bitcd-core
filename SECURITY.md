# Security Policy

## Reporting a vulnerability

Please report suspected vulnerabilities **privately** via
[GitHub Security Advisories](../../security/advisories/new) ("Report a
vulnerability" on the repo's Security tab). Do not open a public issue for
anything you believe is exploitable.

Include what you can: the affected component (`contracts/` vs an off-chain
component), a reproduction or proof-of-concept, and the impact as you
understand it. You should receive an acknowledgement within a few days.

## Scope

The highest-value target is the Cairo contract (`contracts/`) — specifically
the governance/policy/commit authorization paths. The standing security
invariants any change must preserve are documented in
[`AGENTS.md`](AGENTS.md); the audit record lives in the `docs` repo (the
bitcd.org site).

The off-chain components (executors, indexer, the e2e rig) are reference
implementations that run against a local devnet; reports are still welcome,
but they are not deployed, custodial, or fund-bearing surfaces.

## Deployment scope

bitcd targets a local `starknet-devnet`. **There is no public mainnet/testnet
deployment**; the project's own acceptance gate requires a `cairo-auditor` deep
run with no unresolved high/critical findings before any governance-touching
deploy.

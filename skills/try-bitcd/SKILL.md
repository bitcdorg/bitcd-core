---
name: try-bitcd
description: Runs bitcd's devnet proof rig end to end in Docker, onboards a declared organization with no admin left, and checks leases, document integrity, reconciliation, executor agreement, human approvals and escalation. Guides newcomers who want to try bitcd locally with git and Docker.
---

# Try bitcd, in Docker

bitcd gates changes through approval policies in a Starknet contract.
Executors apply approved changes off chain and report through a separate
entry point that cannot rewrite the decision. This skill runs the substrate's
proof rig against a local chain and explains each check. It uses local devnet
accounts, including scripted human signatures; no public chain or personal
keys are involved.

## Prerequisites

- `git` and a running Docker engine with Compose v2.
- Ports `5051` (the devnet) and `4566` (the S3 store) free on the host. Run one
  bitcd compose stack at a time; a sibling bitcd repo's stack uses the same ports.
- Network access to GitHub, Docker Hub, Debian's package mirrors, and the
  Scarb and npm registries. Docker builds download the toolchain and dependencies;
  no host Node.js or Cairo toolchain is needed.

## Run it

Use an existing `bitcd-core` checkout if available; otherwise clone it below.
Run the compose commands from the repo root, in order, and stop if a command
exits non-zero. The ladder needs a fresh devnet; for a previous run, use the
reset instructions below first.

```bash
git clone https://github.com/bitcdorg/bitcd-core.git
cd bitcd-core
docker compose run --rm builder                # build the image and publish contract artifacts to a shared volume
docker compose up -d devnet ministack          # the local Starknet devnet (:5051) and S3 store (:4566)
docker compose run --rm e2e                    # the whole ladder: onboard, then every proof
```

The e2e service waits for the chain and store to pass their health checks and
for the builder to publish the compiled artifacts. It builds its own image
when needed. Allow long-running commands to finish: a measured run took about
35 seconds for the builder and 13 minutes for e2e, including its image build.
Transactions in that run generally took about 10 seconds each. These are
observations, not deadlines; keep collecting output if the command is still
running.

Success requires the final line `demo complete` and exit code `0`. Onboarding
prints `CLEAN: yaml == ownership == chain policy table == active signer roster == on-chain manifest`;
each subsequent stage prints a `PASS:` summary. Stages collect check results
and exit non-zero if any fail; an exception can stop a stage earlier. The
ladder stops at the first stage that exits non-zero. Report the outcome and,
on failure, the last `===== step =====` banner and the relevant error or
`FAIL` line.

## What you are watching

The `e2e` run goes through these stages in order. Each one is a script under
`e2e/scripts/`; the organization it runs against is declared in `e2e/bitcd.yaml`.

| Stage | What it proves |
| --- | --- |
| `onboard` | The `bitcd` CLI validates the declaration offline, deploys the contract, seeds signers and policies, renounces ownership, commits the org manifest as a governed value, then reads back and compares it with the declaration (`diff` reports `CLEAN`). |
| `contend` | Wallets contend for one lock: one wins, the others are refused, and another acquires it after the script advances devnet time past its TTL. No wall-clock wait is needed. |
| `store` | A lease holder writes a document to S3 and commits its fingerprint on chain. The reader reports `VERIFIED` for the original bytes and `MISMATCH` after tampering. |
| `reconcile` | An executor applies the approved value to an S3-backed demo provider, detects drift as `OUTOFSYNC`, and repairs it. A newly committed revision stays `OUTOFSYNC` until applied. Failed applies report `FAILED` without changing desired state, then recover to `SYNCED` when the provider works again. |
| `redundancy` | A report below quorum is not promoted. An agreeing quorum promotes `SYNCED`; conflicting reports without a quorum produce `DISAGREE`. An honest quorum then overrides the misreporting executor. |
| `human-approve` | Plain approvals from human-labelled accounts cannot satisfy the human floor. Scripted SNIP-12 signatures bound to the exact change do satisfy it; the same approval path authorizes a force-unlock. |
| `escalate` | Machine approvals commit a routine proposal. On another proposal, an eligible voter requests human review; the same machine quorum is blocked until a scripted human signature satisfies the raised floor. |

## Tear down, or run again

```bash
docker compose down -v        # removes the stack and its build, deployment and S3 volumes
```

To run again, tear down with the command above, then repeat the three compose
commands under “Run it.” The chain starts fresh, and the builder republishes
the compiled contract into a new volume. Docker retains the images for reuse.

## If something goes wrong

- **`port is already allocated`** — another stack holds `5051` or `4566`.
  Identify the container or process using the port. Stop only a stack known
  to belong to this run; otherwise report the conflict.
- **The builder fails fetching Scarb or Starknet Foundry** — the build stage
  downloads them from GitHub releases. Check Docker's network or proxy access
  to the failed URL before retrying the builder.
- **`devnet not reachable`** from the e2e container — the devnet stopped or is
  still starting. Inspect its service logs. If onboarding has not started,
  retry from `docker compose up -d devnet ministack`; otherwise reset first.
- **Onboarding fails or `diff` is not `CLEAN`** — inspect the reported mismatch
  or error. If this stack contains a previous run, reset it and repeat the
  ladder. If the error recurs on a fresh chain, report it and stop retrying.
- **`pull access denied` for `bitcd-contracts` or `bitcd-e2e`** — Compose may
  try pulling these local image names before building them. In the successful
  run, each message was followed by a successful build; check what follows it.
- **`WARN: Insufficient transaction data`** lines — starknet.js estimating a
  tip on a chain with few transactions. These warnings appear in the successful
  run; judge the outcome by the stage summaries and exit code.
- **Everything else** — inspect the failed command's output and the service
  logs. For a named e2e stage, read `e2e/scripts/<stage>.mjs`. Report the failure
  without changing the proof scripts or weakening their checks.

## Where next

- The model and where each safeguard lives: [Concept](https://bitcd.org/concept/).
- The same stages one at a time, from the checkout: [Quickstart](https://bitcd.org/docs/quickstart/).
- Govern a system of your own: the `build-connector` skill beside this one, and [Connectors](https://bitcd.org/connectors/).
- The repo you cloned: `README.md` for the layout, `AGENTS.md` for the working
  guide and the invariants every change must keep.

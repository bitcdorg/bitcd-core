// bitcd — the org-declaration CLI: compile a bitcd/v1 declaration into the
// deploy + ceremony, the governed org manifest, and per-connector executor
// configs; then keep the deployment in step with the file through governance.
//
//   bitcd validate <bitcd.yaml>                  offline: schema + invariants
//   bitcd plan <bitcd.yaml> [-o|--o out/]        compile; write the artifacts
//   bitcd apply-ceremony <bitcd.yaml>            deploy (or resume) + seed + renounce
//   bitcd publish-manifest <bitcd.yaml>          governed commit of orgmanifest/v1
//   bitcd diff <bitcd.yaml>                      yaml <-> chain policy table, signer
//                                                roster (incl. undeclared) <-> manifest
//   bitcd propose-changes <bitcd.yaml> [--no-commit]
//                                                day-2: signer adds/changes/deactivations,
//                                                strengthen-only SET_POLICY deltas, quartets on
//                                                RESERVED prefixes, then the manifest; with
//                                                --no-commit, one step at a time for people
//                                                to sign (`agentgate sign`), re-run to continue
//
// Chain/dev config via flags or env:
//   --rpc / BITCD_RPC                    (default http://localhost:5051)
//   --deployment / BITCD_DEPLOYMENT_FILE (default ./deployment.json)
//   --keys / BITCD_KEYS_FILE             dev keystore: {name: {address, pk}} —
//                                        the signers these verbs act as; real
//                                        humans sign via `agentgate sign`
//   --s3-endpoint                        else the env var the yaml names in
//                                        storage.endpoint_env, else
//                                        BITCD_S3_ENDPOINT, else http://localhost:4566
//
// A proposed document never replaces the one readers verify: it waits at
// <prefix>/proposals/<id>.blob until its commit, then is copied into place
// (./pending.mjs).
//
// `runBitcd` is the whole command; bin/bitcd.mjs is its entry point. A host
// that governs more than the declaration adds its own verbs:
//
//   runBitcd({ parseYaml, verbs: { "intent new": { flags, booleans, run } } })
//
// where `flags` are the verb's own options (the chain/store options are
// always accepted), `booleans` the ones that take no value, and `run(ctx)`
// receives the plumbing the built-in verbs use. validate/plan are offline;
// the chain verbs load the client lazily.
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { validateOrg } from "./org/schema.mjs";
import { checkInvariants } from "./org/invariants.mjs";
import { ORG_SCHEMA, compileOrg } from "./org/compile.mjs";
import { ORG_SCHEMA_FELT, canonicalOrgManifest, manifestSpecKey } from "./org/manifest.mjs";
import { loadOrgManifest } from "./org/loader.mjs";
import { pickApprovers } from "./org/approvers.mjs";
import { waitSucceeded } from "./tx.mjs";

/// Run one `bitcd` command. `parseYaml` is the yaml parser (the entry point
/// passes the `yaml` package's `parse`, so this module needs no dependency);
/// `verbs` adds host verbs beside the built-in ones.
export async function runBitcd({ argv = process.argv.slice(2), parseYaml, verbs = {} } = {}) {
  if (typeof parseYaml !== "function") throw new TypeError("runBitcd: parseYaml is required");

  const verb = argv[0];

  // Every verb accepts the chain/store options; anything else must be one of the
  // verb's own. An unknown option is refused before anything happens — a
  // misspelled or unsupported flag (say, --no-commit where there is none) must
  // never be silently ignored by a command that signs.
  const COMMON_FLAGS = ["rpc", "deployment", "keys", "s3-endpoint"];
  const VERB_FLAGS = {
    validate: [],
    plan: ["o"],
    "apply-ceremony": ["owner"],
    "publish-manifest": ["proposer", "no-commit"],
    diff: [],
    "propose-changes": ["proposer", "no-commit"],
    ...Object.fromEntries(Object.entries(verbs).map(([name, v]) => [name, v.flags ?? []])),
  };
  const BOOLEAN_FLAGS = new Set(["no-commit", ...Object.values(verbs).flatMap((v) => v.booleans ?? [])]);
  // A verb is one word, or two when the host registered it that way ("intent new").
  const verbKey = `${verb} ${argv[1]}` in verbs ? `${verb} ${argv[1]}` : verb;
  {
    const own = VERB_FLAGS[verbKey];
    if (own) {
      const allowed = new Set([...COMMON_FLAGS, ...own]);
      for (let i = 1; i < argv.length; i++) {
        const a = argv[i];
        if (!a.startsWith("-")) continue; // a positional argument
        const name = a === "-o" ? "o" : a.startsWith("--") ? a.slice(2) : a;
        if (!allowed.has(name)) {
          console.error(`unknown option ${a} for \`bitcd ${verbKey}\` (accepts: ${[...allowed].map((f) => (f === "o" ? "-o" : `--${f}`)).join(" ")}) — nothing was done`);
          process.exit(2);
        }
        if (!BOOLEAN_FLAGS.has(name)) {
          const value = argv[i + 1];
          if (value === undefined || value.startsWith("-")) {
            console.error(`option ${a} needs a value — nothing was done`);
            process.exit(2);
          }
          i++; // the option's value
        }
      }
    }
  }

  const flag = (name, dflt) => {
    const i = argv.indexOf(`--${name}`);
    return i >= 0 ? argv[i + 1] : dflt;
  };
  const has = (name) => argv.includes(`--${name}`);
  const multi = (name) => argv.flatMap((a, i) => (a === `--${name}` ? [argv[i + 1]] : []));

  const RPC = flag("rpc", process.env.BITCD_RPC ?? "http://localhost:5051");
  const DEPLOYMENT = flag("deployment", process.env.BITCD_DEPLOYMENT_FILE ?? "./deployment.json");
  const KEYS_FILE = flag("keys", process.env.BITCD_KEYS_FILE);
  // The store endpoint: the flag, else the variable the org file names in
  // storage.endpoint_env, else BITCD_S3_ENDPOINT. Verbs that read the org from
  // the chain have no file, so they pass null and skip the middle step.
  const s3Endpoint = (storage) => flag("s3-endpoint", undefined)
    ?? (storage?.endpoint_env ? process.env[storage.endpoint_env] : undefined)
    ?? process.env.BITCD_S3_ENDPOINT ?? "http://localhost:4566";

  const die = (msg, code = 1) => { console.error(msg); process.exit(code); };
  const say = (m) => console.log(m);

  // ---------------------------------------------------------------------------
  // offline: load + validate + lint
  // ---------------------------------------------------------------------------
  function loadModel(file) {
    if (!file || !existsSync(file)) die(`no such file: ${file}\nusage: bitcd ${verb} <bitcd.yaml>`);
    let doc;
    try {
      doc = parseYaml(readFileSync(file, "utf8"));
    } catch (e) {
      die(`yaml parse error: ${e.message}`);
    }
    const r = validateOrg(doc);
    if (!r.ok) die(`INVALID ${file}:\n  - ${r.errors.join("\n  - ")}`);
    const lint = checkInvariants(r.model);
    if (lint.length > 0) die(`INVALID ${file} (security lints):\n  - ${lint.join("\n  - ")}`);
    return r.model;
  }

  // ---------------------------------------------------------------------------
  // chain plumbing (lazy)
  // ---------------------------------------------------------------------------
  async function chain() {
    const client = await import("./client.mjs");
    const protocol = await import("./protocol.mjs");
    const { logger } = await import("starknet");
    client.applyNoProxy();
    // starknet.js prices a tip for every transaction by sampling the last few
    // blocks, and warns whenever it finds fewer tipped transactions than it
    // wants — on a devnet, or any quiet chain, that is every transaction, and
    // the zero tip it then falls back to is the right one there. Nothing an
    // operator can act on, so only its errors reach the terminal.
    logger.setLogLevel("ERROR");
    const p = client.provider(RPC);
    const encPrefix = (s) => (s === "GLOBAL" ? protocol.GLOBAL : protocol.str(s));
    // role is null on an open-ACQUIRE lease row — encoded as felt 0.
    const encPolicy = (pl) => ({
      threshold: pl.threshold, role: pl.role === null ? 0 : protocol.str(pl.role), min_humans: pl.min_humans,
      max_per_operator: pl.max_per_operator, allow_open: pl.allow_open, exists: true,
    });
    return { client, protocol, p, encPrefix, encPolicy };
  }

  function readKeys() {
    if (!KEYS_FILE) die("this verb needs a dev keystore: --keys <file> (JSON {name: {address, pk}})");
    return JSON.parse(readFileSync(KEYS_FILE, "utf8"));
  }

  function loadDeploymentFile() {
    if (!existsSync(DEPLOYMENT)) die(`no deployment record at ${DEPLOYMENT} (run apply-ceremony first)`);
    return JSON.parse(readFileSync(DEPLOYMENT, "utf8"));
  }

  // A deployment record names one contract on one chain, and nothing else ties
  // it to the chain behind --rpc. Check that a contract lives at the recorded
  // address there, and that it runs the recorded class, before acting on it:
  // a record left over from a restarted devnet, or pointed at the wrong
  // network, is refused instead of silently "resumed".
  async function assertDeployed(c, dep) {
    let classHash;
    try {
      classHash = await c.p.getClassHashAt(dep.address);
    } catch {
      die(`no contract at ${dep.address} on ${RPC} — the deployment record ${DEPLOYMENT} belongs to another chain (a restarted devnet?). Delete it to deploy afresh, or point --rpc / --deployment at the right network`);
    }
    if (dep.classHash && BigInt(classHash) !== BigInt(dep.classHash)) {
      die(`the contract at ${dep.address} runs class ${feltHex(classHash)}, not ${dep.classHash} as ${DEPLOYMENT} records — refusing to act on it`);
    }
    return feltHex(classHash);
  }

  async function openDeployment(c) {
    const dep = loadDeploymentFile();
    await assertDeployed(c, dep);
    return dep;
  }

  // An open (uncommitted) proposal for exactly this change, if one exists —
  // found from the proposal events and the params published beside each one,
  // and trusted only once the contract confirms those params are the ones the
  // proposal carries (its approval_digest). Lets a propose-only run be repeated
  // without proposing the same change twice, and a forged side channel can't
  // make it wait on the wrong proposal.
  async function openProposalFor({ c, dep, store, prefixStr, actionName, params }) {
    const { fetchAllEvents, projectProposals } = await import("./events.mjs");
    const { assertRoundTrip } = await import("./snip12.mjs");
    const { pendingParamsKey } = await import("./pending.mjs");
    const want = params.map((x) => BigInt(x));
    const view = c.client.bitcdContract(dep.address, c.p);
    const chainId = await c.p.getChainId();
    const prefixFelt = prefixStr === "GLOBAL" ? c.protocol.GLOBAL : c.protocol.str(prefixStr);
    const rows = projectProposals(await fetchAllEvents(c.p, dep.address));
    for (const pr of [...rows].reverse()) {
      if (pr.committed || pr.action !== actionName || pr.prefix !== prefixStr) continue;
      try {
        const { params: claimed } = JSON.parse(await store.getText(pendingParamsKey(prefixStr, pr.id)));
        if (!Array.isArray(claimed) || claimed.length !== want.length || !claimed.every((x, i) => BigInt(x) === want[i])) continue;
      } catch { continue; } // nothing (or nothing readable) published for it — not one of ours
      try {
        await assertRoundTrip(view, {
          verifyingContract: dep.address, chainId, proposalId: pr.id,
          action: c.protocol.ACTION[actionName], prefix: prefixFelt, params: want,
        }, pr.proposer);
      } catch {
        say(`  proposal #${pr.id}'s published params don't match what it carries on chain — ignoring it`);
        continue;
      }
      return pr;
    }
    return null;
  }

  async function proposeId(p, call) {
    const { hash, num } = await import("starknet");
    const { transaction_hash } = await call;
    await waitSucceeded(p, transaction_hash, "propose");
    const rcpt = await p.getTransactionReceipt(transaction_hash);
    const sel = "0x" + hash.starknetKeccak("ProposalCreated").toString(16);
    const evs = rcpt.events ?? rcpt.value?.events ?? [];
    return BigInt(evs.find((e) => num.toHex(e.keys?.[0]) === sel).keys[1]);
  }

  // The keystore's signers as the CHAIN knows them right now. Approvals are
  // judged against on-chain identity, so they are always picked from here —
  // never from the yaml, which may describe a roster that doesn't exist yet
  // (a signer being rotated in cannot approve its own installation).
  async function chainPool(c, view, keys) {
    const { decode } = await import("./events.mjs");
    const pool = [];
    const seen = new Set();   // one approver per ADDRESS: two keystore names for one key are one vote
    for (const [name, k] of Object.entries(keys)) {
      if (!k?.address || seen.has(BigInt(k.address))) continue;
      seen.add(BigInt(k.address));
      const s = await view.get_signer(k.address);
      if (!Boolean(s.active)) continue;
      pool.push({ name, address: k.address, human: Boolean(s.is_human), operator: decode(s.operator_id), role: decode(s.role) });
    }
    return pool;
  }

  const quorumText = (q) => `${q.threshold}-of-${q.role}, min_humans ${q.min_humans}, max_per_operator ${q.max_per_operator}`;

  // The policy the chain ENFORCES for (prefix, action) — what a commit is
  // judged against, whatever the yaml or the manifest declares.
  async function chainQuorum(c, view, prefixStr, actionName) {
    const { decode } = await import("./events.mjs");
    const pol = await view.get_policy(c.encPrefix(prefixStr), c.protocol.ACTION[actionName]);
    if (!Boolean(pol.exists)) die(`no (${prefixStr}, ${actionName}) policy on chain — nothing was proposed`);
    return { threshold: Number(pol.threshold), role: decode(pol.role), min_humans: Number(pol.min_humans), max_per_operator: Number(pol.max_per_operator) };
  }

  // Who proposes: --proposer if given (it must be active on chain), else the
  // first active keystore signer holding `role`, else any active one — propose
  // only needs an active signer. Never a signer the chain doesn't know yet.
  function pickProposer(pool, role) {
    const named = flag("proposer", null);
    if (named) return pool.find((s) => s.name === named) ?? die(`--proposer ${named} is not in the keystore or not an active signer on chain — nothing was proposed`);
    return pool.find((s) => s.role === role) ?? pool[0] ?? die("the keystore holds no signer active on chain — nothing was proposed");
  }

  // Refuse up front when the keystore cannot approve — before anything is proposed.
  async function assertDevQuorum(c, view, keys, quorum, what) {
    if (!pickApprovers(await chainPool(c, view, keys), quorum)) {
      die(`the keystore cannot satisfy ${quorumText(quorum)} for ${what} with the signers active on chain — nothing was proposed`);
    }
  }

  // Dev-mode quorum: humans sign SNIP-12 via approve_sigs, machines approve()
  // raw, then commit — every approver an active on-chain signer.
  async function devQuorum({ keys, c, dep, id, action, prefix, params, quorum }) {
    const view = c.client.bitcdContract(dep.address, c.p);
    const picked = pickApprovers(await chainPool(c, view, keys), quorum)
      ?? die(`keystore cannot satisfy ${quorumText(quorum)} with the signers active on chain`);
    const humans = picked.filter((s) => s.human);
    const machines = picked.filter((s) => !s.human);
    if (humans.length > 0) {
      await c.client.approveWithSigs({
        p: c.p, contractAddress: dep.address, proposalId: id, action, prefix, params,
        signers: humans.map((s) => ({ ...keys[s.name], name: s.name })),
        relayer: { ...keys[humans[0].name], name: humans[0].name },
      });
      say(`  approve_sigs: ${humans.map((s) => s.name).join(", ")} (SNIP-12 intent-bound)`);
    }
    for (const s of machines) {
      const conn = c.client.bitcdContract(dep.address, c.client.account(keys[s.name], c.p));
      const { transaction_hash } = await conn.approve(id);
      await waitSucceeded(c.p, transaction_hash, `approve by ${s.name}`);
      say(`  approve: ${s.name}`);
    }
    const committer = c.client.bitcdContract(dep.address, c.client.account(keys[picked[0].name], c.p));
    const { transaction_hash } = await committer.commit(id);
    await waitSucceeded(c.p, transaction_hash, `commit of proposal #${id}`);
    say(`  commit: proposal #${id} committed`);
  }

  const feltHex = (v) => "0x" + BigInt(v).toString(16);

  // Every account ACTIVE on chain as a signer. The contract cannot enumerate
  // signers, but every SET_ROLE (ceremony seed or governed) emits RoleChanged
  // with the account as a key — fold those, then read each account's current
  // record. This is how a signer deleted from the yaml is still seen.
  async function activeRoster(c, dep, view) {
    const { hash } = await import("starknet");
    const { deploymentBlock } = await import("./events.mjs");
    const sel = "0x" + hash.starknetKeccak("RoleChanged").toString(16);
    // From the contract's first block — recorded at deploy, else located — never
    // from genesis, which a public node refuses to scan.
    const from = dep.block ?? await deploymentBlock(c.p, dep.address);
    const accounts = new Set();
    let token;
    do {
      const page = await c.p.getEvents({
        address: dep.address, from_block: { block_number: from }, to_block: "latest",
        keys: [[sel]], chunk_size: 100, continuation_token: token,
      });
      for (const ev of page.events) accounts.add(BigInt(ev.keys[1]));
      token = page.continuation_token;
    } while (token);
    const out = [];
    for (const a of accounts) {
      const signer = await view.get_signer(feltHex(a));
      if (Boolean(signer.active)) out.push({ address: feltHex(a), signer });
    }
    return out;
  }
  const undeclared = (roster, model) => {
    const declared = new Set(model.signers.map((s) => BigInt(s.address)));
    return roster.filter((r) => !declared.has(BigInt(r.address)));
  };

  // After a commit, copy the committed blob into place (it hashes to the
  // committed digest by construction — promoteCommitted re-checks anyway) —
  // but only while that digest is still the value's CURRENT one: a publisher
  // that stalled after its commit must not overwrite a newer revision's copy.
  async function promoteAfterCommit({ c, view, keyFelt, store, specKey, digest, prefixStr, id }) {
    const now = await view.get_value(keyFelt);
    if (BigInt(now.digest) !== BigInt(digest)) {
      say(`  a newer revision has landed since proposal #${id} committed — leaving ${specKey} to it`);
      return;
    }
    const { promoteCommitted } = await import("./pending.mjs");
    const r = await promoteCommitted({ store, specKey, digest, prefixStr, proposalIds: [id], digestOf: c.protocol.digestOf });
    if (r === null) die(`committed #${id} but its pending blob does not hash to ${digest} — ${specKey} left untouched`);
    say(`  ${specKey} <- proposal #${id}'s blob (committed digest)`);
  }

  // ---------------------------------------------------------------------------
  // verbs
  // ---------------------------------------------------------------------------
  if (verb === "validate") {
    const model = loadModel(argv[1]);
    const compiled = compileOrg(model);
    const surfaces = [
      `${model.intent_types.length} intent type(s)`,
      ...(model.fleets.length > 0 ? [`${model.fleets.length} fleet(s)`] : []),
      ...(model.values.length > 0 ? [`${model.values.length} governed value(s)`] : []),
      ...(model.locks.length > 0 ? [`${model.locks.length} lock surface(s)`] : []),
    ];
    say(`OK ${argv[1]}: org=${model.org} v${model.version} — ${model.signers.length} signers, ${model.connectors.length} connector(s), ${surfaces.join(", ")}, ${compiled.ceremony.policies.length} policies to seed, renounce=${model.ceremony.renounce}`);
  } else if (verb === "plan") {
    const model = loadModel(argv[1]);
    const oi = argv.findIndex((a) => a === "-o" || a === "--o");
    const out = oi >= 0 ? argv[oi + 1] : null;
    const compiled = compileOrg(model);
    say(`ceremony for org=${model.org} (renounce=${model.ceremony.renounce}):`);
    for (const s of compiled.ceremony.signers) say(`  ${s.label}  (${s.signer.role}${s.signer.is_human ? ", human" : ""})`);
    for (const p of compiled.ceremony.policies) say(`  ${p.label}`);
    say(`org manifest: ${ORG_SCHEMA} at ${model.manifest.key} (constitution ${compiled.manifest.self.quorum.threshold}-of-${compiled.manifest.self.quorum.role}, min_humans ${compiled.manifest.self.quorum.min_humans})`);
    if (out) {
      mkdirSync(out, { recursive: true });
      writeFileSync(join(out, "ceremony.json"), JSON.stringify(compiled.ceremony, null, 2));
      writeFileSync(join(out, "manifest.json"), canonicalOrgManifest(compiled.manifest));
      for (const ec of compiled.executorConfigs) {
        writeFileSync(join(out, `${ec.connector}.config.json`), JSON.stringify(ec, null, 2));
        writeFileSync(join(out, `${ec.connector}.env.example`),
          [...Object.entries(ec.env).map(([k, v]) => `${k}=${v}`),
            ...ec.env_required.map((k) => `${k}=`), ""].join("\n"));
      }
      say(`wrote ${out}/: ceremony.json, manifest.json, ${compiled.executorConfigs.map((e) => e.connector + ".{config.json,env.example}").join(", ")}`);
    }
  } else if (verb === "apply-ceremony") {
    const model = loadModel(argv[1]);
    const compiled = compileOrg(model);
    const c = await chain();
    const keys = readKeys();
    const ownerName = flag("owner", "genesis");
    if (!keys[ownerName]) die(`keystore has no "${ownerName}" (the transient owner)`);
    const { deployBitcd, runCeremony } = await import("./ceremony.mjs");
    const owner = c.client.account(keys[ownerName], c.p);

    let dep;
    if (existsSync(DEPLOYMENT)) {
      dep = JSON.parse(readFileSync(DEPLOYMENT, "utf8"));
      await assertDeployed(c, dep);
      say(`resuming against ${dep.address} (${DEPLOYMENT})`);
    } else {
      dep = await deployBitcd({ owner, deploymentFile: DEPLOYMENT, rpc: RPC, log: say });
    }
    const view = c.client.bitcdContract(dep.address, c.p);
    const cur = await view.owner();
    if (BigInt(cur) === 0n) {
      die("ownership already renounced — the ceremony is one-shot; day-2 changes go through `bitcd propose-changes`");
    }

    // Idempotent resume: skip already-correct entries (a crashed ceremony
    // re-runs safely; a DIFFERING existing entry is an error, not an update).
    const signers = [];
    for (const s of compiled.ceremony.signers) {
      const on = await view.get_signer(s.address);
      if (Boolean(on.active)) {
        const same = Boolean(on.is_human) === s.signer.is_human
          && BigInt(on.operator_id) === BigInt(c.protocol.str(s.signer.operator_id))
          && BigInt(on.role) === BigInt(c.protocol.str(s.signer.role));
        if (same) { say(`  skip ${s.label} (already seeded)`); continue; }
        die(`${s.label}: on-chain signer differs from the declaration — refuse to overwrite mid-ceremony`);
      }
      signers.push({ ...s, signer: { ...s.signer, operator_id: c.protocol.str(s.signer.operator_id), role: c.protocol.str(s.signer.role) } });
    }
    const policies = [];
    for (const pl of compiled.ceremony.policies) {
      const prefix = c.encPrefix(pl.prefix);
      const action = c.protocol.ACTION[pl.action];
      const on = await view.get_policy(prefix, action);
      if (Boolean(on.exists)) {
        const want = c.encPolicy(pl.policy);
        const same = Number(on.threshold) === want.threshold
          && BigInt(on.role) === BigInt(want.role)
          && Number(on.min_humans) === want.min_humans
          && Number(on.max_per_operator) === want.max_per_operator
          && Boolean(on.allow_open) === want.allow_open;
        if (same) { say(`  skip ${pl.label} (already seeded)`); continue; }
        die(`${pl.label}: on-chain policy differs from the declaration — a ceremony never amends (use propose-changes)`);
      }
      policies.push({ label: pl.label, prefix, action, policy: c.encPolicy(pl.policy) });
    }
    const contract = c.client.bitcdContract(dep.address, owner);
    await runCeremony({ contract, provider: c.p, signers, policies, renounce: model.ceremony.renounce, log: say });
    const after = await contract.owner();
    say(`owner now: ${BigInt(after) === 0n ? "0x0 (renounced)" : feltHex(after)}`);
  } else if (verb === "publish-manifest") {
    const model = loadModel(argv[1]);
    const c = await chain();
    const keys = readKeys();
    const dep = await openDeployment(c);
    const compiled = compileOrg(model, { classHash: dep.classHash });
    const blob = canonicalOrgManifest(compiled.manifest);
    const digest = c.protocol.digestOf(blob);
    const keyFelt = c.protocol.str(model.manifest.key);
    const view = c.client.bitcdContract(dep.address, c.p);
    const cur = await view.get_value(keyFelt);
    const { s3Store } = await import("./store.mjs");
    const store = s3Store({ endpoint: s3Endpoint(model.storage), bucket: model.storage.bucket });
    await store.ensureBucket();
    const specKey = manifestSpecKey(model.manifest.key);
    if (Number(cur.version) > 0 && BigInt(cur.digest) === BigInt(digest) && !cur.tombstoned) {
      // Already committed — but a run that stopped between commit and copy
      // leaves the old blob in place, so make sure the committed one is there.
      let current = false;
      try { current = BigInt(c.protocol.digestOf(await store.getText(specKey))) === BigInt(digest); } catch { /* missing */ }
      if (!current) { await store.putText(specKey, blob); say(`  ${specKey} <- the committed manifest (was missing or stale)`); }
      say(`no-op: on-chain manifest already at this digest (v${Number(cur.version)})`); process.exit(0);
    }

    const params = [keyFelt, digest, ORG_SCHEMA_FELT, c.protocol.STORAGE_CLASS.S3, Number(cur.version)];
    const prefix = c.protocol.str(model.manifest.prefix);
    const noCommit = has("no-commit");
    const mq = await chainQuorum(c, view, model.manifest.prefix, "SET_VALUE");
    if (noCommit) {
      const open = await openProposalFor({ c, dep, store, prefixStr: model.manifest.prefix, actionName: "SET_VALUE", params });
      if (open) {
        say(`waiting: proposal #${open.id} already proposes this definition (${quorumText(mq)}) — humans sign via \`agentgate sign ${open.id}\`; once it commits, run publish-manifest again to put it in place`);
        process.exit(0);
      }
    }
    if (!noCommit) await assertDevQuorum(c, view, keys, mq, `${model.manifest.key}`);
    const proposerName = pickProposer(await chainPool(c, view, keys), mq.role).name;
    const proposer = c.client.bitcdContract(dep.address, c.client.account(keys[proposerName], c.p));
    const id = await proposeId(c.p, proposer.propose(c.protocol.ACTION.SET_VALUE, prefix, params));
    say(`proposal #${id}: SET_VALUE ${model.manifest.key} (${ORG_SCHEMA} v${model.version})`);
    // The new manifest waits beside its proposal; the one loaders verify stays
    // put until the commit lands.
    const { publishPending } = await import("./pending.mjs");
    await publishPending(store, model.manifest.prefix, id, blob, params);
    say(`  pending blob -> ${model.manifest.prefix}/proposals/${id}.blob (digest ${digest.slice(0, 12)}…)`);
    if (noCommit) {
      say(`pending: ${quorumText(mq)} — humans sign via \`agentgate sign ${id}\`. Once it commits, run publish-manifest again to put the manifest in place (loaders halt until then).`);
      process.exit(0);
    }
    await devQuorum({ keys, c, dep, id, action: c.protocol.ACTION.SET_VALUE, prefix, params, quorum: mq });
    await promoteAfterCommit({ c, view, keyFelt, store, specKey, digest, prefixStr: model.manifest.prefix, id });
    const after = await view.get_value(keyFelt);
    say(`org manifest committed: chain version ${Number(after.version)}, digest ${feltHex(after.digest).slice(0, 12)}…`);
  } else if (verb === "diff") {
    const model = loadModel(argv[1]);
    const c = await chain();
    const dep = loadDeploymentFile();
    const liveClass = await assertDeployed(c, dep);
    const compiled = compileOrg(model, { classHash: dep.classHash });
    const view = c.client.bitcdContract(dep.address, c.p);
    let clean = true;
    // 0) ownership against ceremony.renounce, and the class it runs
    say(`  contract ${dep.address} runs class ${liveClass.slice(0, 12)}…`);
    {
      const owner = BigInt(await view.owner());
      if (model.ceremony.renounce && owner !== 0n) {
        say(`  OWNER still set: ${feltHex(owner)} — the file says renounce: true (run apply-ceremony to renounce)`);
        clean = false;
      } else if (!model.ceremony.renounce && owner === 0n) {
        say("  OWNER renounced on chain, but the file says renounce: false");
        clean = false;
      }
    }
    // 1) yaml -> chain policy table
    for (const pl of compiled.ceremony.policies) {
      const on = await view.get_policy(c.encPrefix(pl.prefix), c.protocol.ACTION[pl.action]);
      const want = c.encPolicy(pl.policy);
      if (!Boolean(on.exists)) { say(`  MISSING on chain: ${pl.label}`); clean = false; continue; }
      const same = Number(on.threshold) === want.threshold && BigInt(on.role) === BigInt(want.role)
        && Number(on.min_humans) === want.min_humans && Number(on.max_per_operator) === want.max_per_operator
        && Boolean(on.allow_open) === want.allow_open;
      if (!same) {
        say(`  DIFFERS: ${pl.label} — chain has ${Number(on.threshold)}-of-role(${feltHex(on.role).slice(0, 10)}…)/h${Number(on.min_humans)}/mpo${Number(on.max_per_operator)}`);
        clean = false;
      }
    }
    // 2) declared signers -> chain roster
    for (const s of model.signers) {
      const on = await view.get_signer(s.address);
      const same = Boolean(on.active) && Boolean(on.is_human) === s.human
        && BigInt(on.operator_id) === BigInt(c.protocol.str(s.operator))
        && BigInt(on.role) === BigInt(c.protocol.str(s.role));
      if (!same) { say(`  SIGNER DIFFERS/MISSING: ${s.name} (${s.address.slice(0, 10)}…)`); clean = false; }
    }
    // 2b) the chain's active roster -> declared signers: an account removed from
    // the yaml is still a signer until it is deactivated on chain.
    const { decode } = await import("./events.mjs");
    for (const r of undeclared(await activeRoster(c, dep, view), model)) {
      say(`  UNDECLARED SIGNER active on chain: ${r.address} (role ${decode(r.signer.role)}) — propose-changes deactivates it`);
      clean = false;
    }
    // 3) local compile -> on-chain manifest (verify-on-read)
    const { s3Store } = await import("./store.mjs");
    const store = s3Store({ endpoint: s3Endpoint(model.storage), bucket: model.storage.bucket });
    const keyFelt = c.protocol.str(model.manifest.key);
    const r = await loadOrgManifest({
      getValue: async () => {
        const v = await view.get_value(keyFelt);
        return { digest: feltHex(v.digest), schema_ref: v.schema_ref, version: Number(v.version), tombstoned: Boolean(v.tombstoned) };
      },
      getBlob: () => store.getText(manifestSpecKey(model.manifest.key)),
      valueKeyStr: model.manifest.key,
    });
    if (!r.ok) { say(`  MANIFEST: ${r.class} — ${r.reason}`); clean = false; }
    else {
      const localDigest = c.protocol.digestOf(canonicalOrgManifest(compiled.manifest));
      if (BigInt(localDigest) !== BigInt(r.digest)) {
        say(`  MANIFEST DIFFERS: chain v${r.version} (org v${r.manifest.version}) digest ${r.digest.slice(0, 12)}… != local ${localDigest.slice(0, 12)}… — publish-manifest (or reconcile the yaml)`);
        clean = false;
      }
    }
    say(clean ? "CLEAN: yaml == ownership == chain policy table == active signer roster == on-chain manifest" : "DIFFS FOUND (see above)");
    process.exit(clean ? 0 : 2);
  } else if (verb === "propose-changes") {
    const model = loadModel(argv[1]);
    const c = await chain();
    const keys = readKeys();
    const dep = await openDeployment(c);
    const compiled = compileOrg(model, { classHash: dep.classHash });
    const view = c.client.bitcdContract(dep.address, c.p);
    // --no-commit: propose without approving, for organizations whose approvals
    // come from people. Changes depend on each other (a new signer may be needed
    // by a later quorum; a gate change governs the next change on its prefix),
    // so this proposes ONE step, publishes its params for `agentgate sign`, and
    // stops; running it again after the commit proposes the next.
    const noCommit = has("no-commit");

    // Reserved-prefix set: quartet creation is only reachable where a
    // (prefix, SET_POLICY) gate exists (the envelope is sealed at ceremony).
    const gates = new Map(); // prefix name -> the SET_POLICY meta-policy quorum on chain
    for (const pl of compiled.ceremony.policies.filter((x) => x.action === "SET_POLICY")) {
      const on = await view.get_policy(c.encPrefix(pl.prefix), c.protocol.ACTION.SET_POLICY);
      if (Boolean(on.exists)) gates.set(pl.prefix, on);
    }

    const gateToQuorum = (gate, label) => ({
      threshold: Number(gate.threshold),
      role: model.roles.find((r) => BigInt(c.protocol.str(r)) === BigInt(gate.role)) ?? die(`unknown on-chain role on ${label}`),
      min_humans: Number(gate.min_humans),
      max_per_operator: Number(gate.max_per_operator),
    });
    const runGoverned = async ({ action, prefixFelt, params, quorum, label }) => {
      const proposerName = pickProposer(await chainPool(c, view, keys), quorum.role).name;
      const proposer = c.client.bitcdContract(dep.address, c.client.account(keys[proposerName], c.p));
      const id = await proposeId(c.p, proposer.propose(action, prefixFelt, params));
      say(`proposal #${id}: ${label}`);
      await devQuorum({ keys, c, dep, id, action, prefix: prefixFelt, params, quorum });
    };

    // PLAN everything first, then send. Each change is its own governed
    // proposal, so a run cannot be atomic — but every check that can refuse a
    // change runs before the first transaction, so a refusable file changes
    // nothing on chain. Re-running after a transient failure picks up where it
    // stopped (every step diffs against the chain).
    const roleGate = await view.get_policy(c.protocol.GLOBAL, c.protocol.ACTION.SET_ROLE);
    const roleQuorum = () => {
      if (!Boolean(roleGate.exists)) die("no (GLOBAL, SET_ROLE) gate on chain — signer changes are unreachable on this deployment");
      return gateToQuorum(roleGate, "(GLOBAL, SET_ROLE)");
    };

    // 1) declared signers missing (or differing) on chain -> SET_ROLE
    const signerChanges = [];
    for (const s of model.signers) {
      const on = await view.get_signer(s.address);
      const same = Boolean(on.active) && Boolean(on.is_human) === s.human
        && BigInt(on.operator_id) === BigInt(c.protocol.str(s.operator))
        && BigInt(on.role) === BigInt(c.protocol.str(s.role));
      if (same) continue;
      signerChanges.push({
        params: [s.address, 1, s.human ? 1 : 0, c.protocol.str(s.operator), c.protocol.str(s.role)],
        label: `SET_ROLE ${s.name} (${s.role}${s.human ? ", human" : ""})`,
      });
    }
    // 2) signers active on chain but no longer declared -> deactivate. The
    // record keeps its fields; only `active` drops, so its approvals (including
    // on still-open proposals) stop counting.
    for (const r of undeclared(await activeRoster(c, dep, view), model)) {
      signerChanges.push({
        params: [r.address, 0, Boolean(r.signer.is_human) ? 1 : 0, r.signer.operator_id, r.signer.role],
        label: `SET_ROLE ${r.address} -> inactive (removed from the yaml)`,
      });
    }
    if (signerChanges.length > 0) roleQuorum();

    // 3) policy deltas: strengthen-only, and creation only behind a gate
    const changes = [];
    for (const pl of compiled.ceremony.policies) {
      const prefix = c.encPrefix(pl.prefix);
      const action = c.protocol.ACTION[pl.action];
      const on = await view.get_policy(prefix, action);
      const want = c.encPolicy(pl.policy);
      if (Boolean(on.exists)) {
        const same = Number(on.threshold) === want.threshold && BigInt(on.role) === BigInt(want.role)
          && Number(on.min_humans) === want.min_humans && Number(on.max_per_operator) === want.max_per_operator
          && Boolean(on.allow_open) === want.allow_open;
        if (same) continue;
        // Opening a policy to anyone is a weakening; closing one is allowed.
        if (want.allow_open && !Boolean(on.allow_open)) die(`${pl.label}: would open a quorum-gated policy to anyone — a weakening; nothing was sent`);
        // Strengthen-only pre-check, quoting the on-chain assert each delta
        // would die on (never submit a doomed weakening).
        if (want.threshold < Number(on.threshold)) die(`${pl.label}: would die on 'commit: weakens threshold' (chain has ${Number(on.threshold)}) — nothing was sent`);
        if (want.min_humans < Number(on.min_humans)) die(`${pl.label}: would die on 'commit: weakens min_humans' (chain has ${Number(on.min_humans)}) — nothing was sent`);
        if (BigInt(want.role) !== BigInt(on.role)) die(`${pl.label}: would die on 'commit: changes gov role' — re-targeting a gate's role needs a fresh ceremony; nothing was sent`);
        if (Number(on.max_per_operator) !== 0 && (want.max_per_operator === 0 || want.max_per_operator > Number(on.max_per_operator))) {
          die(`${pl.label}: would die on 'commit: weakens diversity' (chain has ${Number(on.max_per_operator)}) — nothing was sent`);
        }
        changes.push({ ...pl, kind: "strengthen" });
      } else {
        if (!gates.has(pl.prefix)) {
          die(`${pl.label}: prefix "${pl.prefix}" has no (prefix, SET_POLICY) gate on chain — the envelope was sealed at ceremony; a new unreserved prefix means a NEW DEPLOYMENT, or declare it under reserved_prefixes before the next org's ceremony. Nothing was sent`);
        }
        changes.push({ ...pl, kind: "create" });
      }
    }

    // SIMULATE the run before sending anything: walk the steps in order against
    // an in-memory copy of the keystore signers' on-chain records, and refuse
    // when any step's quorum could not be met at that point (a signer being
    // added only counts once its SET_ROLE has landed; one being removed stops
    // counting), when a policy change has no gate, and when the manifest could
    // not be republished at the end.
    {
      const { decode } = await import("./events.mjs");
      const sim = new Map();
      for (const [name, k] of Object.entries(keys)) {
        if (!k?.address) continue;
        const on = await view.get_signer(k.address);
        sim.set(BigInt(k.address), { name, address: k.address, active: Boolean(on.active), human: Boolean(on.is_human), operator: decode(on.operator_id), role: decode(on.role) });
      }
      const pool = () => [...sim.values()].filter((x) => x.active);
      const named = flag("proposer", null);
      const need = (quorum, label) => {
        if (named && !pool().some((x) => x.name === named)) die(`${label}: --proposer ${named} would not be an active signer at this point of the plan — nothing was sent`);
        if (pool().length === 0) die(`${label}: no keystore signer would be active to propose it at this point of the plan — nothing was sent`);
        if (!noCommit && !pickApprovers(pool(), quorum)) die(`${label}: the keystore could not satisfy ${quorumText(quorum)} at this point of the plan — nothing was sent`);
      };
      for (const ch of signerChanges) {
        need(roleQuorum(), ch.label);
        const x = sim.get(BigInt(ch.params[0]));
        if (x) Object.assign(x, { active: Number(ch.params[1]) === 1, human: Number(ch.params[2]) === 1, operator: decode(ch.params[3]), role: decode(ch.params[4]) });
      }
      const simGates = new Map(gates);
      let manifestQ = await chainQuorum(c, view, model.manifest.prefix, "SET_VALUE");
      for (const ch of changes) {
        const gate = simGates.get(ch.prefix)
          ?? die(`${ch.label}: prefix "${ch.prefix}" has no (prefix, SET_POLICY) gate on chain, so its policies can't be changed — nothing was sent`);
        need(gateToQuorum(gate, `${ch.prefix}'s SET_POLICY gate`), `${ch.kind} ${ch.label}`);
        if (ch.action === "SET_POLICY") simGates.set(ch.prefix, c.encPolicy(ch.policy));
        if (ch.prefix === model.manifest.prefix && ch.action === "SET_VALUE") manifestQ = gateToQuorum(c.encPolicy(ch.policy), "the manifest gate");
      }
      need(manifestQ, `republishing ${model.manifest.key}`);
    }

    if (noCommit) {
      const { s3Store } = await import("./store.mjs");
      const { pendingParamsKey } = await import("./pending.mjs");
      const store = s3Store({ endpoint: s3Endpoint(model.storage), bucket: model.storage.bucket });
      await store.ensureBucket();
      const steps = [
        ...signerChanges.map((ch) => ({ action: "SET_ROLE", prefixStr: "GLOBAL", params: ch.params, quorum: roleQuorum(), label: ch.label })),
        ...changes.map((ch) => {
          const want = c.encPolicy(ch.policy);
          return {
            action: "SET_POLICY", prefixStr: ch.prefix,
            params: [c.encPrefix(ch.prefix), c.protocol.ACTION[ch.action], want.threshold, want.role, want.min_humans, want.max_per_operator, want.allow_open ? 1 : 0, 1],
            quorum: gateToQuorum(gates.get(ch.prefix), `${ch.prefix}'s SET_POLICY gate`), label: `${ch.kind} ${ch.label}`,
          };
        }),
      ];
      say(`plan: ${signerChanges.length} signer change(s), ${changes.length} policy change(s) — proposing one step at a time (--no-commit)`);
      if (steps.length > 0) {
        const step = steps[0];
        const open = await openProposalFor({ c, dep, store, prefixStr: step.prefixStr, actionName: step.action, params: step.params });
        if (open) {
          say(`waiting: proposal #${open.id} (${step.label}) needs ${quorumText(step.quorum)} — sign via \`agentgate sign ${open.id}\`, then run propose-changes again`);
          process.exit(0);
        }
        const proposerName = pickProposer(await chainPool(c, view, keys), step.quorum.role).name;
        const proposer = c.client.bitcdContract(dep.address, c.client.account(keys[proposerName], c.p));
        const prefixFelt = step.prefixStr === "GLOBAL" ? c.protocol.GLOBAL : c.protocol.str(step.prefixStr);
        const id = await proposeId(c.p, proposer.propose(c.protocol.ACTION[step.action], prefixFelt, step.params));
        await store.putText(pendingParamsKey(step.prefixStr, id), JSON.stringify({ params: step.params.map(String) }));
        say(`proposal #${id}: ${step.label} — needs ${quorumText(step.quorum)}; sign via \`agentgate sign ${id}\`, then run propose-changes again (${steps.length - 1} more step(s) after this one, then the manifest)`);
        process.exit(0);
      }
      say("signers and policies match the file — proposing the manifest");
    }

    // SEND: signers first (a new signer may be needed by a later quorum), then
    // the policy deltas, then the manifest.
    if (!noCommit) say(`plan: ${signerChanges.length} signer change(s), ${changes.length} policy change(s)`);
    for (const ch of noCommit ? [] : signerChanges) {
      await runGoverned({ action: c.protocol.ACTION.SET_ROLE, prefixFelt: c.protocol.GLOBAL, params: ch.params, quorum: roleQuorum(), label: ch.label });
    }
    if (!noCommit && changes.length === 0) say("policy table: no changes");
    for (const ch of noCommit ? [] : changes) {
      const prefixFelt = c.encPrefix(ch.prefix);
      const want = c.encPolicy(ch.policy);
      // SET_POLICY params: [target_prefix, target_action, threshold, role,
      // min_humans, max_per_operator, allow_open, exists] (arity 8).
      const params = [prefixFelt, c.protocol.ACTION[ch.action], want.threshold, want.role, want.min_humans, want.max_per_operator, want.allow_open ? 1 : 0, 1];
      await runGoverned({
        action: c.protocol.ACTION.SET_POLICY, prefixFelt, params,
        quorum: gateToQuorum(gates.get(ch.prefix), `${ch.prefix}'s SET_POLICY gate`),
        label: `${ch.kind} ${ch.label}`,
      });
      // A prefix's own gate just changed: its later changes need the new one.
      if (ch.action === "SET_POLICY") gates.set(ch.prefix, c.encPolicy(ch.policy));
    }
    // Manifest v+1 rides the same run (no-op when unchanged).
    say("republishing the org manifest…");
    const { spawnSync } = await import("node:child_process");
    const r = spawnSync(process.execPath, [process.argv[1], "publish-manifest", argv[1],
      "--rpc", RPC, "--deployment", DEPLOYMENT, "--s3-endpoint", s3Endpoint(model.storage), ...(KEYS_FILE ? ["--keys", KEYS_FILE] : []),
      ...(flag("proposer", null) ? ["--proposer", flag("proposer", null)] : []),
      ...(noCommit ? ["--no-commit"] : [])], { stdio: "inherit" });
    process.exit(r.status ?? 0);
  } else if (verbs[verbKey]) {
    await verbs[verbKey].run({
      argv, flag, has, multi, say, die, s3Endpoint,
      chain, readKeys, openDeployment, chainPool, chainQuorum, pickProposer,
      assertDevQuorum, devQuorum, proposeId, promoteAfterCommit, quorumText, feltHex,
    });
  } else {
    die(`usage: bitcd <${Object.keys(VERB_FLAGS).join("|")}> …`);
  }
}

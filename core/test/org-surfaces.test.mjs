// The org declaration — the connector-less surfaces (fleets / locks / values) unit tests. Pure,
// no chain; the fixture mirrors the agentgate org shape (a fleet + a
// notary-style value, no connector).
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { parse as parseYaml } from "yaml";
import { validateOrg } from "../src/org/schema.mjs";
import { checkInvariants } from "../src/org/invariants.mjs";
import { compileOrg } from "../src/org/compile.mjs";
import { canonicalOrgManifest, validateOrgManifest } from "../src/org/manifest.mjs";

const EXAMPLE = resolve(new URL(".", import.meta.url).pathname, "../example/bitcd.yaml");

const addr = (n) => `0x0${n}23456789012345678901234567890123456789012345678901234567890123`;
const quorum = (o = {}) => ({ threshold: 2, role: "AGENT", min_humans: 0, max_per_operator: 1, ...o });

function fleetDoc() {
  return {
    schema: "bitcd/v1",
    org: "fleetorg",
    version: 1,
    naming: "literal",
    ceremony: { renounce: true },
    cast: {
      roles: ["AGENT", "APPROVER"],
      signers: {
        peerA: { address: addr(1), human: false, operator: "OP_A", role: "AGENT" },
        peerB: { address: addr(2), human: false, operator: "OP_B", role: "AGENT" },
        overseer: { address: addr(3), human: true, operator: "OP_H", role: "AGENT" },
        sre: { address: addr(4), human: true, operator: "OP_S", role: "APPROVER" },
        notary: { address: addr(5), human: false, operator: "OP_N", role: "APPROVER" },
      },
    },
    storage: { bucket: "bitcd-tfstate" },
    fleets: {
      remediation: {
        prefix: "fleet/remediation",
        schema: "remediation/v1",
        key: "fleet/remediation/cfg",
        quorum: quorum(),
        summon_human: true,
        meta: quorum(),
        lease: { prefix: "fleet/lease", recovery: quorum() },
      },
    },
    values: {
      notarygate: {
        prefix: "demo/notarygate",
        schema: "notarygate/v1",
        key: "demo/notarygate/cfg",
        quorum: { threshold: 2, role: "APPROVER", min_humans: 1, max_per_operator: 1 },
        mutable: false,
        immutable_ack: true,
      },
    },
    manifest: {
      key: "sys/manifest",
      quorum: { threshold: 2, role: "APPROVER", min_humans: 1, max_per_operator: 1 },
    },
  };
}

const validated = (mutate) => {
  const d = fleetDoc();
  mutate?.(d);
  return validateOrg(d);
};
const linted = (mutate) => {
  const r = validated(mutate);
  assert.ok(r.ok, `schema must pass before linting: ${r.errors.join("; ")}`);
  return checkInvariants(r.model);
};
const fleetModel = (mutate) => {
  const r = validated(mutate);
  assert.ok(r.ok, r.errors.join("; "));
  assert.deepEqual(checkInvariants(r.model), []);
  return r.model;
};

test("a fleet org (no connector, no intent types) validates and lints clean", () => {
  const r = validated();
  assert.deepEqual(r.errors, []);
  assert.deepEqual(checkInvariants(r.model), []);
  assert.equal(r.model.connectors.length, 0);
  assert.equal(r.model.fleets.length, 1);
  assert.equal(r.model.values.length, 1);
});

test("there is one schema id; anything else is refused", () => {
  const r = validated((d) => { d.schema = "bitcd/v2"; });
  assert.match(r.errors.join(";"), /schema must be "bitcd\/v1"/);
});

test("an org must declare at least one governed surface", () => {
  const r = validated((d) => { delete d.fleets; delete d.values; });
  assert.match(r.errors.join(";"), /at least one governed surface/);
});

test("compile seeds the fleet gates + the lease pair (open ACQUIRE, quorum FORCE_UNLOCK)", () => {
  const { ceremony } = compileOrg(fleetModel());
  const rows = ceremony.policies.map((p) => `${p.prefix}·${p.action}`);
  for (const want of [
    "GLOBAL·SET_ROLE", "GLOBAL·SET_POLICY",
    "sys·SET_VALUE", "sys·TOMBSTONE_VALUE", "sys·SET_POLICY",
    "fleet/remediation·SET_VALUE", "fleet/remediation·SET_POLICY",
    "fleet/lease·ACQUIRE", "fleet/lease·FORCE_UNLOCK",
    "demo/notarygate·SET_VALUE",
  ]) assert.ok(rows.includes(want), `missing ${want}`);
  // The ONLY open row is the lease ACQUIRE, and it is bare (threshold 0, no role).
  const open = ceremony.policies.filter((p) => p.policy.allow_open === true);
  assert.equal(open.length, 1);
  assert.deepEqual(open[0], {
    label: "policy fleet/lease·ACQUIRE=open", prefix: "fleet/lease", action: "ACQUIRE",
    policy: { threshold: 0, role: null, min_humans: 0, max_per_operator: 0, allow_open: true },
  });
  // The meta-gate is passed through VERBATIM — never floored to min_humans 1
  // (the dev/production difference is the org author's).
  const meta = ceremony.policies.find((p) => p.prefix === "fleet/remediation" && p.action === "SET_POLICY");
  assert.equal(meta.policy.min_humans, 0);
  // An immutable value with no revoke gate seeds ONLY its SET_VALUE.
  assert.deepEqual(rows.filter((r) => r.startsWith("demo/notarygate")), ["demo/notarygate·SET_VALUE"]);
});

test("values: revoke 'same' seeds TOMBSTONE at the value quorum; mutable seeds the floored meta", () => {
  const { ceremony } = compileOrg(fleetModel((d) => {
    d.values.notarygate.revoke = "same";
    d.values.notarygate.mutable = true;
    delete d.values.notarygate.immutable_ack;
  }));
  const rows = ceremony.policies.map((p) => `${p.prefix}·${p.action}`);
  assert.ok(rows.includes("demo/notarygate·TOMBSTONE_VALUE"));
  const meta = ceremony.policies.find((p) => p.prefix === "demo/notarygate" && p.action === "SET_POLICY");
  assert.ok(meta.policy.min_humans >= 1);
});

test("[policy-gate-not-weaker] a fleet meta-gate weaker than the value gate is refused; equal passes", () => {
  assert.match(linted((d) => { d.fleets.remediation.meta = quorum({ threshold: 1 }); }).join(";"), /\[policy-gate-not-weaker\].*weakens threshold/);
  assert.match(linted((d) => { d.fleets.remediation.meta = quorum({ role: "APPROVER" }); }).join(";"), /\[policy-gate-not-weaker\].*incomparable/);
  assert.ok(!linted((d) => { d.fleets.remediation.meta = quorum({ min_humans: 1 }); }).some((e) => e.startsWith("[policy-gate-not-weaker]")));
});

test("[lock-recovery] the lease recovery gate is held to the fleet's value gate", () => {
  const errs = linted((d) => { d.fleets.remediation.lease.recovery = quorum({ threshold: 1 }); });
  assert.match(errs.join(";"), /\[lock-recovery\].*weakens threshold/);
});

test("[lock-recovery] every open prefix carries an equivalent-strength recovery gate", () => {
  const errs = linted((d) => {
    d.locks = { dr: { prefix: "k8s/lease", recovery: quorum({ threshold: 3 }) } };
  });
  assert.match(errs.join(";"), /\[lock-recovery\].*equivalent-strength/);
  const ok = linted((d) => {
    d.locks = { dr: { prefix: "k8s/lease", recovery: quorum() } };
  });
  assert.deepEqual(ok, []);
});

test("locks.value: the ONE lock-scoped open SET_VALUE compiles, rides the manifest, and validates", () => {
  const d = fleetDoc();
  d.locks = { tf: { prefix: "tf/lock", recovery: quorum(), value: { schema: "tfstate/v4", key: "tf/lock/state/value" }, mutable: true } };
  const r = validateOrg(d);
  assert.ok(r.ok, r.errors.join("; "));
  assert.deepEqual(checkInvariants(r.model), []);
  const { ceremony, manifest } = compileOrg(r.model);
  const rows = ceremony.policies.filter((p) => p.prefix === "tf/lock").map((p) => `${p.action}:${p.policy.allow_open ? "open" : p.policy.threshold}`);
  assert.deepEqual(rows, ["ACQUIRE:open", "FORCE_UNLOCK:2", "SET_VALUE:open", "SET_POLICY:2"]);
  const meta = ceremony.policies.find((p) => p.prefix === "tf/lock" && p.action === "SET_POLICY").policy;
  assert.equal(meta.min_humans, 1);                       // floored to one human
  assert.deepEqual(manifest.locks[0].value, { schema: "tfstate/v4", key: "tf/lock/state/value" });
  assert.equal(manifest.locks[0].mutable, true);
  assert.deepEqual(validateOrgManifest(manifest).errors, []);
  // the open SET_VALUE row is legal ONLY on the declaring lock's prefix
  const evil = JSON.parse(canonicalOrgManifest(manifest));
  evil.policies.push({ prefix: "fleet/lease", action: "SET_VALUE", threshold: 0, role: null, min_humans: 0, max_per_operator: 0, allow_open: true });
  assert.match(validateOrgManifest(evil).errors.join(";"), /ONE lock that declares a value/);
  // a lock without value/mutable carries only name, prefix and recovery in the manifest
  const plain = fleetDoc();
  plain.locks = { dr: { prefix: "k8s/lease", recovery: quorum() } };
  const pm = compileOrg(validateOrg(plain).model).manifest;
  assert.deepEqual(Object.keys(pm.locks[0]).sort(), ["name", "prefix", "recovery"]);
});

test("[single-open-value] two locks declaring values are refused; a value key must sit under its lock prefix", () => {
  const errs = linted((d) => {
    d.locks = {
      tf: { prefix: "tf/lock", recovery: quorum(), value: { schema: "tfstate/v4", key: "tf/lock/state/value" } },
      other: { prefix: "app/lock", recovery: quorum(), value: { schema: "x/v1", key: "app/lock/v" } },
    };
  });
  assert.match(errs.join(";"), /\[single-open-value\].*exactly ONE open-SET_VALUE prefix/);
  const bad = validated((d) => {
    d.locks = { tf: { prefix: "tf/lock", recovery: quorum(), value: { schema: "tfstate/v4", key: "elsewhere/value" } } };
  });
  assert.match(bad.errors.join(";"), /must start with "tf\/lock\/"/);
});

test("[person-reachable] a min_humans=0 fleet needs summon_human AND an eligible human overseer", () => {
  assert.match(linted((d) => { d.fleets.remediation.summon_human = false; }).join(";"), /\[person-reachable\].*needs summon_human: true/);
  const errs = linted((d) => { d.cast.signers.overseer.role = "APPROVER"; });
  assert.match(errs.join(";"), /\[person-reachable\].*human signer holding role AGENT/);
});

test("[prefix-owner] a fleet's lease prefix is an owner like any other", () => {
  const errs = linted((d) => { d.locks = { clash: { prefix: "fleet/lease", recovery: quorum() } }; });
  assert.match(errs.join(";"), /\[prefix-owner\].*fleet\/lease/);
});

test("values: mutable must be explicit; immutable needs the ack", () => {
  assert.match(validated((d) => { delete d.values.notarygate.mutable; }).errors.join(";"), /mutable must be stated explicitly/);
  assert.match(validated((d) => { delete d.values.notarygate.immutable_ack; }).errors.join(";"), /immutable_ack/);
});

test("the compiled fleet manifest validates; the open row survives only as the bare lease ACQUIRE", () => {
  const { manifest } = compileOrg(fleetModel());
  assert.deepEqual(validateOrgManifest(manifest).errors, []);
  assert.equal(manifest.intent_types.length, 0);
  assert.equal(manifest.fleets.length, 1);
  assert.equal(manifest.fleets[0].lease.prefix, "fleet/lease");
  assert.equal(manifest.values.length, 1);
  // canonicalization round-trips
  assert.equal(canonicalOrgManifest(manifest), canonicalOrgManifest(JSON.parse(canonicalOrgManifest(manifest))));
  // a decorated open row is refused: allow_open anywhere but a bare ACQUIRE
  const evil = JSON.parse(canonicalOrgManifest(manifest));
  const sv = evil.policies.find((p) => p.prefix === "fleet/remediation" && p.action === "SET_VALUE");
  sv.allow_open = true;
  assert.match(validateOrgManifest(evil).errors.join(";"), /bare open-ACQUIRE/);
  // a manifest with no governed surface at all is refused
  const empty = JSON.parse(canonicalOrgManifest(manifest));
  delete empty.fleets;
  delete empty.values;
  assert.match(validateOrgManifest(empty).errors.join(";"), /no governed surface/);
});

test("an org without fleets/locks/values carries none of those keys; its source_digest is pinned", () => {
  const r = validateOrg(parseYaml(readFileSync(EXAMPLE, "utf8")));
  assert.ok(r.ok, r.errors.join("; "));
  const { manifest } = compileOrg(r.model);
  assert.ok(!("fleets" in manifest) && !("locks" in manifest) && !("values" in manifest));
  // The pinned source_digest of the example org. A mismatch means compile
  // output changed for EXISTING orgs — every already-published manifest
  // would re-publish. Update this constant only when the example org itself
  // (or the manifest format) changes deliberately.
  assert.equal(manifest.source_digest, "0x1bc9ad64e2630a1d800de3d28dc3ba0c952907ac72f7add1d849a35d7fa7c03");
});

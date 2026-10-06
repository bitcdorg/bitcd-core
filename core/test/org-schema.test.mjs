// The org declaration — bitcd/v1 schema + invariants unit tests (pure, no chain).
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { parse as parseYaml } from "yaml";
import { parseDuration, validateFieldSpec, validateOrg } from "../src/org/schema.mjs";
import { checkInvariants } from "../src/org/invariants.mjs";

const EXAMPLE = resolve(new URL(".", import.meta.url).pathname, "../example/bitcd.yaml");
const doc = () => parseYaml(readFileSync(EXAMPLE, "utf8"));

const validated = (mutate) => {
  const d = doc();
  mutate?.(d);
  return validateOrg(d);
};
const linted = (mutate) => {
  const r = validated(mutate);
  assert.ok(r.ok, `schema must pass before linting: ${r.errors.join("; ")}`);
  return checkInvariants(r.model);
};

test("the example declaration validates and lints clean", () => {
  const r = validated();
  assert.deepEqual(r.errors, []);
  assert.ok(r.ok);
  assert.deepEqual(checkInvariants(r.model), []);
});

test("parseDuration handles units and integers", () => {
  assert.equal(parseDuration("24h"), 86400);
  assert.equal(parseDuration("30m"), 1800);
  assert.equal(parseDuration("7d"), 604800);
  assert.equal(parseDuration("90s"), 90);
  assert.equal(parseDuration(300), 300);
  assert.equal(parseDuration("bogus"), null);
});

test("unknown fields are rejected at every level", () => {
  assert.ok(!validated((d) => { d.extra = 1; }).ok);
  assert.ok(!validated((d) => { d.cast.signers.agent1.note = "x"; }).ok);
  assert.ok(!validated((d) => { d.intent_types["k8s-access"].surprise = 1; }).ok);
});

test("ceremony.renounce and mutable must be explicit (the sealed envelope)", () => {
  assert.ok(!validated((d) => { delete d.ceremony; }).ok);
  const r = validated((d) => { d.intent_types["k8s-access"].mutable = undefined; });
  assert.ok(!r.ok);
  const r2 = validated((d) => { d.intent_types["k8s-access"].mutable = false; });
  assert.match(r2.errors.join(";"), /immutable_ack/);
  const r3 = validated((d) => {
    d.intent_types["k8s-access"].mutable = false;
    d.intent_types["k8s-access"].immutable_ack = true;
  });
  assert.ok(r3.ok);
});

test("naming: hashed is refused with the designed-for message", () => {
  const r = validated((d) => { d.naming = "hashed"; });
  assert.match(r.errors.join(";"), /designed-for but not yet expressible/);
});

test("the constitution floor: manifest quorum needs min_humans >= 1", () => {
  const r = validated((d) => { d.manifest.quorum.min_humans = 0; });
  assert.match(r.errors.join(";"), /never rewritten machine-only/);
});

test("allow_open is inexpressible in a quorum block", () => {
  const r = validated((d) => { d.intent_types["k8s-access"].quorum.allow_open = true; });
  assert.match(r.errors.join(";"), /allow_open is not expressible/);
});

test("credentials accept env-var NAMES only; secret values are linted", () => {
  const r = validated((d) => { d.connectors["dev-cluster"].credentials = { kubeconfig: "not-an-env-var" }; });
  assert.match(r.errors.join(";"), /ENV_VAR_NAME/);
  const r2 = validated((d) => { d.connectors["dev-cluster"].config.note = "AKIA0123456789ABCDEF"; });
  assert.match(r2.errors.join(";"), /secret material/);
});

test("[person-reachable] min_humans 0 without summon_human is a lint error", () => {
  const errs = linted((d) => {
    d.intent_types["k8s-access"].quorum.min_humans = 0;
    // keep the cast satisfiable: nothing else changes
  });
  assert.match(errs.join(";"), /\[person-reachable\]/);
  const ok = linted((d) => {
    d.intent_types["k8s-access"].quorum.min_humans = 0;
    d.intent_types["k8s-access"].summon_human = true;
  });
  assert.ok(!ok.some((e) => e.startsWith("[person-reachable]")));
});

test("summon_human is a boolean; an escalation key is refused with a pointer to it", () => {
  const set = (v) => validated((d) => {
    d.intent_types["k8s-access"].quorum.min_humans = 0;
    delete d.intent_types["k8s-access"].summon_human;
    v(d.intent_types["k8s-access"]);
  });
  const on = set((it) => { it.summon_human = true; });
  assert.ok(on.ok, on.errors.join("; "));
  assert.equal(on.model.intent_types[0].summon_human, true);
  assert.ok(!checkInvariants(on.model).some((e) => e.startsWith("[person-reachable]")));
  assert.equal(set(() => {}).model.intent_types[0].summon_human, false);
  assert.match(set((it) => { it.summon_human = "yes"; }).errors.join(";"), /summon_human must be true or false/);
  assert.match(set((it) => { it.escalation = "default"; }).errors.join(";"), /escalation is written summon_human/);
  assert.match(linted((d) => { d.intent_types["k8s-access"].quorum.min_humans = 0; }).join(";"), /needs summon_human: true/);
});

test("[executor-separation] executor roles stay disjoint from governance quorums", () => {
  const errs = linted((d) => { d.intent_types["k8s-access"].quorum.role = "EXEC_K8S"; });
  assert.match(errs.join(";"), /\[executor-separation\]/);
});

test("[executor-separation] a stray signer holding an executor role is refused", () => {
  const errs = linted((d) => {
    d.cast.signers.stray = {
      address: "0x0999999999999999999999999999999999999999999999999999999999999999",
      human: false, operator: "OP_STRAY", role: "EXEC_K8S",
    };
  });
  assert.match(errs.join(";"), /\[executor-separation\] signer stray/);
});

test("[threshold-reachable / humans-reachable / operator-diversity] quorum satisfiability against the declared cast", () => {
  assert.match(linted((d) => { d.intent_types["k8s-access"].quorum.threshold = 9; }).join(";"), /\[threshold-reachable\]/);
  assert.match(linted((d) => { d.intent_types["k8s-access"].quorum.min_humans = 3; }).join(";"), /\[humans-reachable\]/);
});

test("[operator-diversity] the operator cap is judged against how signers are actually spread", () => {
  // Three OPERATOR signers on OP_A, one on OP_B, cap 2: 2 + 1 = 3 usable, so a
  // threshold of 4 can never be met — even though 2 operators x cap 2 = 4.
  const errs = linted((d) => {
    d.cast.signers.agent4 = { address: "0x0000000000000000000000000000000000000000000000000000000000000abc", human: false, operator: "OP_A", role: "OPERATOR" };
    d.cast.signers.agent2.operator = "OP_A";
    d.cast.signers.agent2.human = true;
    d.cast.signers.agent3.operator = "OP_B";
    Object.assign(d.intent_types["k8s-access"].quorum, { threshold: 4, max_per_operator: 2, min_humans: 1 });
  });
  assert.match(errs.join(";"), /\[operator-diversity\] intent_types\.k8s-access.*leaves only 3 usable signer\(s\)/);
});

test("[operator-diversity] the cap can leave too few usable humans", () => {
  // Both humans share OP_A under cap 1: only one of them can ever count.
  const errs = linted((d) => {
    d.cast.signers.agent2.operator = "OP_A";
    d.cast.signers.agent3.operator = "OP_C";
    Object.assign(d.intent_types["k8s-access"].quorum, { threshold: 2, max_per_operator: 1, min_humans: 2 });
  });
  assert.match(errs.join(";"), /\[operator-diversity\] intent_types\.k8s-access.*only 1 usable human/);
});

test("[attest-reachable] attest.k above the executor roster is refused", () => {
  const errs = linted((d) => { d.intent_types["k8s-access"].attest = { k: 2 }; });
  assert.match(errs.join(";"), /\[attest-reachable\]/);
});

test("[revoke-not-weaker] a weaker revoke than the grant quorum is refused", () => {
  const errs = linted((d) => {
    d.intent_types["k8s-access"].revoke = { threshold: 1, role: "OPERATOR", min_humans: 0, max_per_operator: 1 };
  });
  assert.match(errs.join(";"), /\[revoke-not-weaker\]/);
});

test("[31-char] key template arithmetic is proven at compile", () => {
  const errs = linted((d) => { d.intent_types["k8s-access"].params.name.max_len = 30; });
  assert.match(errs.join(";"), /\[31-char\].*worst case/);
});

test("[prefix-owner] one prefix, one owner", () => {
  const errs = linted((d) => { d.reserved_prefixes[0].prefix = "k8s/rbac"; });
  assert.match(errs.join(";"), /\[prefix-owner\]/);
});

test("a duration or number default outside its own min..max is a schema error", () => {
  const errors = [];
  validateFieldSpec("d", { type: "duration", label: "D", max: "1h", default: "2h" }, "params.d", errors);
  validateFieldSpec("n", { type: "number", label: "N", min: 1, max: 5, default: 9 }, "params.n", errors);
  assert.equal(errors.filter((e) => /default must lie within min\.\.max/.test(e)).length, 2);
});

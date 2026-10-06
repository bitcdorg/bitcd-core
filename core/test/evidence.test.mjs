// Evidence-log chain integrity: the tamper demo as a regression test.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { chainLine, verifyChain, evidenceLog, GENESIS_PREV } from "../src/evidence.mjs";

const records = [
  { actor: "notary-prov", proposalId: 1, verdict: "APPROVE", reason: "digest allowlisted" },
  { actor: "notary-prov", proposalId: 2, verdict: "WITHHOLD", reason: "digest not allowlisted" },
  { actor: "peer-b", proposalId: 2, verdict: "APPROVE", reason: "blast radius ok" },
];

function buildChain() {
  const lines = [];
  for (const [i, r] of records.entries()) {
    lines.push(chainLine(lines.at(-1) ?? null, i, 1000 + i, r));
  }
  return lines;
}

test("a well-formed chain verifies", () => {
  const text = buildChain().join("\n") + "\n";
  assert.deepEqual(verifyChain(text), { ok: true, length: 3 });
});

test("genesis line carries the sentinel prev", () => {
  const [first] = buildChain();
  assert.equal(JSON.parse(first).prev, GENESIS_PREV);
});

test("mutating one line breaks the chain at the next line", () => {
  const lines = buildChain();
  // The attack the log exists to expose: quietly flip a WITHHOLD verdict.
  lines[1] = lines[1].replace("WITHHOLD", "APPROVE");
  const res = verifyChain(lines.join("\n"));
  assert.equal(res.ok, false);
  assert.equal(res.badLine, 2);
  assert.equal(res.reason, "prev-hash mismatch");
});

test("dropping a line breaks the chain", () => {
  const lines = buildChain();
  lines.splice(1, 1);
  const res = verifyChain(lines.join("\n"));
  assert.equal(res.ok, false);
  assert.equal(res.badLine, 1);
});

test("reordering lines breaks the chain", () => {
  const lines = buildChain();
  [lines[1], lines[2]] = [lines[2], lines[1]];
  assert.equal(verifyChain(lines.join("\n")).ok, false);
});

test("empty log verifies as length 0", () => {
  assert.deepEqual(verifyChain(""), { ok: true, length: 0 });
});

test("file-backed appender chains across reopen and detects on-disk tamper", () => {
  const path = join(mkdtempSync(join(tmpdir(), "bitcd-evidence-")), "peer-a.jsonl");
  let t = 0;
  const log1 = evidenceLog(path, { now: () => ++t });
  log1.append(records[0]);
  log1.append(records[1]);
  // Reopen (daemon restart) — the chain continues from disk, not stale memory.
  const log2 = evidenceLog(path, { now: () => ++t });
  log2.append(records[2]);
  assert.deepEqual(log2.verify(), { ok: true, length: 3 });

  const tampered = readFileSync(path, "utf8").replace("WITHHOLD", "APPROVE");
  writeFileSync(path, tampered);
  assert.equal(evidenceLog(path).verify().ok, false);
});

test("concurrent writers take turns: no duplicate sequence numbers", async () => {
  const { mkdtempSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const { spawn } = await import("node:child_process");
  const { fileURLToPath } = await import("node:url");
  const dir = mkdtempSync(join(tmpdir(), "evlock-"));
  const file = join(dir, "log.jsonl");
  const mod = fileURLToPath(new URL("../src/evidence.mjs", import.meta.url));
  const writer = (n) => new Promise((res, rej) => {
    const c = spawn(process.execPath, ["--input-type=module", "-e",
      `const { evidenceLog } = await import(${JSON.stringify(mod)}); const l = evidenceLog(${JSON.stringify(file)}); for (let i = 0; i < 40; i++) l.append({ w: ${n}, i });`]);
    c.on("exit", (code) => (code === 0 ? res() : rej(new Error(`writer ${n} exit ${code}`))));
  });
  await Promise.all([writer(1), writer(2), writer(3)]);
  const { evidenceLog } = await import("../src/evidence.mjs");
  const v = evidenceLog(file).verify();
  assert.equal(v.ok, true, JSON.stringify(v));
  assert.equal(v.length, 120);
});

test("a lock left by a process that no longer runs is taken over; a live owner's is not", async () => {
  const { mkdtempSync, writeFileSync: w, existsSync } = await import("node:fs");
  const { tmpdir, hostname } = await import("node:os");
  const { join } = await import("node:path");
  const { evidenceLog } = await import("../src/evidence.mjs");
  const dir = mkdtempSync(join(tmpdir(), "evstale-"));
  const file = join(dir, "log.jsonl");
  w(`${file}.lock`, `${hostname()} 2147483646`);           // a pid that isn't running
  evidenceLog(file).append({ a: 1 });
  assert.equal(existsSync(`${file}.lock`), false);
  w(`${file}.lock`, `${hostname()} ${process.pid}`);       // alive: this very process
  const slow = (() => { const t = Date.now(); try { evidenceLog(file).append({ b: 2 }); } catch (e) { return [Date.now() - t, e.message]; } return [0, "no error"]; })();
  assert.match(slow[1], /locked by another writer/);
});

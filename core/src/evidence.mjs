// @bitcd/core/evidence — the tamper-evident evidence log shared by every
// voter daemon (agent fleets, notaries).
//
// The contract records only *"approver X voted yes"* — never WHY. A dispute
// ("why did that agent approve?") is resolvable only if each agent's
// {verdict, reason, evidence} record is tamper-evident; otherwise trust has
// moved off-chain, not vanished.
// This module is that record: an append-only JSONL file where every line
// carries `prev` = digestOf(the previous line's exact bytes), so mutating,
// dropping, or reordering a line breaks the link from the line after it. The
// last line has no successor: cutting the tail, or rewriting the log from some
// line on, shows only against a digest of the last line kept elsewhere. The
// chain is per-file (one log per daemon identity); `verifyChain` checks it.
//
// Deliberately NOT on-chain: evidence is off-chain data (anchoring a periodic
// digest on-chain is a consumer's choice, not a substrate feature).
// Deliberately dumb: no schema enforcement beyond the chain fields — the
// payload is the daemon's {verdict, reason, evidence, proposalId, block, ...}.
import { readFileSync, appendFileSync, existsSync, mkdirSync, linkSync, unlinkSync, writeFileSync } from "node:fs";
import { hostname } from "node:os";
import { dirname } from "node:path";
import { digestOf } from "./protocol.mjs";

/// The genesis `prev` sentinel (same convention as the contract's "unbound" 0).
export const GENESIS_PREV = "0x0";

/// Render one chained line from the previous line's exact text. Pure — the
/// caller owns IO and time. The chain fields (`seq`, `prev`, `ts`) are written
/// first so a human eyeballing the file sees the chain; key order is part of
/// the hashed bytes, so lines are canonical by construction, not by re-sorting.
export function chainLine(prevLineText, seq, ts, record) {
  const prev = prevLineText == null ? GENESIS_PREV : digestOf(prevLineText);
  return JSON.stringify({ seq, prev, ts, ...record });
}

/// Verify a whole log's text. Returns { ok, length } or
/// { ok: false, length, badLine, reason } — `badLine` is the 0-based index of
/// the FIRST line that breaks the chain (tamper anywhere before it also lands
/// here, because the hashes cascade).
export function verifyChain(text) {
  const lines = String(text).split("\n").filter((l) => l.length > 0);
  let prevText = null;
  for (let i = 0; i < lines.length; i++) {
    let parsed;
    try {
      parsed = JSON.parse(lines[i]);
    } catch {
      return { ok: false, length: lines.length, badLine: i, reason: "unparseable" };
    }
    const wantPrev = prevText == null ? GENESIS_PREV : digestOf(prevText);
    if (parsed.prev !== wantPrev) {
      return { ok: false, length: lines.length, badLine: i, reason: "prev-hash mismatch" };
    }
    if (parsed.seq !== i) {
      return { ok: false, length: lines.length, badLine: i, reason: "seq mismatch" };
    }
    prevText = lines[i];
  }
  return { ok: true, length: lines.length };
}

/// Hold `<path>.lock` (created exclusively, holding this process's host and
/// pid) around `fn`, so two processes appending to one log can't read the
/// same tail and write the same sequence number. A lock is taken over only
/// when its owner is provably gone — same host, and that pid no longer runs —
/// never because it is old: a writer that is merely slow keeps its lock.
/// Waiting longer than `timeoutMs` throws rather than writing unguarded.
function withFileLock(path, fn, { timeoutMs = 5000 } = {}) {
  const lock = `${path}.lock`;
  const me = `${hostname()} ${process.pid}`;
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (createOwned(lock, me)) break;
    let owner = "";
    try { owner = readFileSync(lock, "utf8"); } catch (e) { if (e.code !== "ENOENT") throw e; continue; } // released meanwhile
    if (ownerIsGone(owner) && reclaim(lock, owner)) continue;
    if (Date.now() > deadline) throw new Error(`evidence log ${path} is locked by another writer (${lock}: ${owner || "unknown"})`);
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 20);
  }
  try { return fn(); } finally { try { if (readFileSync(lock, "utf8") === me) unlinkSync(lock); } catch { /* already gone */ } }
}

// Remove a dead owner's lock. Reclaimers take turns through a second lock
// (which names its holder too), and the owner is re-read while holding it: a
// lock can only disappear through its owner or a reclaimer, so a lock that
// still names the dead owner here is that owner's, never a replacement
// another writer just created.
function reclaim(lock, deadOwner) {
  const guard = `${lock}.reclaim`;
  const me = `${hostname()} ${process.pid}`;
  if (!createOwned(guard, me)) {
    let holder = "";
    try { holder = readFileSync(guard, "utf8"); } catch (e) { if (e.code !== "ENOENT") throw e; return false; } // released meanwhile
    // A guard whose holder died is never cleared automatically: doing that
    // safely needs an OS lock. It takes a crash in the middle of a reclaim,
    // so it gets a clear error instead.
    if (ownerIsGone(holder)) throw new Error(`evidence log lock recovery is stuck: ${guard} belongs to ${holder}, which no longer runs — remove that file once no process is writing to the log`);
    return false; // try again on the next turn
  }
  try {
    let current = null;
    try { current = readFileSync(lock, "utf8"); } catch { return true; } // already gone
    if (current === deadOwner) unlinkSync(lock);
    return true;
  } finally { try { if (readFileSync(guard, "utf8") === me) unlinkSync(guard); } catch { /* gone */ } }
}

// Create `path` holding `owner`, atomically: the owner is written to a
// private file first and hard-linked into place, so a lock never exists
// without its owner — a crash can't leave an empty, unrecoverable one.
// False when `path` already exists.
function createOwned(path, owner) {
  const tmp = `${path}.${process.pid}.${Math.random().toString(36).slice(2)}`;
  writeFileSync(tmp, owner);
  try {
    linkSync(tmp, path);
    return true;
  } catch (e) {
    if (e.code === "EEXIST") return false;
    throw e;
  } finally {
    try { unlinkSync(tmp); } catch { /* gone */ }
  }
}

function ownerIsGone(owner) {
  const [host, pidText] = owner.trim().split(" ");
  const pid = Number(pidText);
  if (host !== hostname() || !Number.isInteger(pid) || pid <= 0) return false; // can't tell: wait
  try { process.kill(pid, 0); return false; } catch (e) { return e.code === "ESRCH"; }
}

/// File-backed appender. `now` is injectable for deterministic tests; reads the
/// tail on every append (logs are small control-plane records, and re-reading
/// makes daemon restarts safe — the chain continues from whatever is actually
/// on disk, never from stale memory), under an exclusive lock file so
/// concurrent writers take turns.
export function evidenceLog(path, { now = () => Date.now() } = {}) {
  return {
    path,
    append(record) {
      mkdirSync(dirname(path), { recursive: true });
      return withFileLock(path, () => {
        const lines = existsSync(path)
          ? readFileSync(path, "utf8").split("\n").filter((l) => l.length > 0)
          : [];
        const line = chainLine(lines.at(-1) ?? null, lines.length, now(), record);
        appendFileSync(path, line + "\n");
        return line;
      });
    },
    verify() {
      return verifyChain(existsSync(path) ? readFileSync(path, "utf8") : "");
    },
  };
}

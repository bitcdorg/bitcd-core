// provider.mjs — the one file a real connector replaces.
//
// The executor calls four functions. This stand-in governs one JSON file on
// disk, so the loop can be proven on the devnet before a real system is wired
// in. A real provider keeps the same four functions and talks to the system's
// API instead of the filesystem.
//
//   getLiveBlob()          read the system, reduce it to the governed fields,
//                          render canonically; throw when nothing is there
//   applyToProvider(text)  refuse a document outside the delegated set, then write it
//   revoke()               remove what the connector manages (tombstone, expiry)
//   liveExists()           whether the managed object exists
import { access, mkdir, readFile, unlink, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { renderConfig } from "@bitcd/core/reconcile";

// The governed essence of what the system returns. Drop everything the system
// adds on its own (ids, timestamps, revisions), so the live hash moves only
// when a governed field moves. A real provider lists the fields it keeps.
export function project(live) {
  const { _written_at, ...governed } = live;
  return governed;
}

// Everything this connector may ever set. Derive it from the verified
// manifest at run time (the union of the intent types' pset maps), never from
// local configuration. Here it is a list of allowed top-level keys; null means
// the manifest delegates no fixed set.
export function assertWithin(spec, delegated) {
  if (!delegated) return;
  const outside = Object.keys(spec).filter((k) => !delegated.includes(k));
  if (outside.length) throw new Error(`outside the delegated set: ${outside.join(", ")}`);
}

export function makeProvider({ path, delegated = null, log = () => {} }) {
  const read = async () => JSON.parse(await readFile(path, "utf8")); // throws when absent
  return {
    getLiveBlob: async () => renderConfig(project(await read())),
    applyToProvider: async (text) => {
      const spec = JSON.parse(text);
      assertWithin(spec, delegated);
      await mkdir(dirname(path), { recursive: true });
      await writeFile(path, JSON.stringify({ ...spec, _written_at: new Date().toISOString() }, null, 2));
      log(`applied -> ${path}`);
    },
    revoke: async () => {
      try {
        await unlink(path);
        log(`revoked -> ${path} removed`);
      } catch (e) {
        if (e.code !== "ENOENT") throw e;
      }
    },
    liveExists: async () => {
      try { await access(path); return true; } catch { return false; }
    },
  };
}

// Three documents the system accepts, for check.mjs: two revisions and one
// more for the failed-apply check. A real provider returns documents of its
// own schema here.
export function sampleDocuments() {
  const doc = (serial, actions) => ({
    policySetName: "app-readers",
    serial,
    statements: [{ sid: "ReadAppBucket", effect: "Allow", actions, resources: ["arn:aws:s3:::app/*"] }],
  });
  return [
    doc(1, ["s3:GetObject", "s3:ListBucket"]),
    doc(2, ["s3:GetObject", "s3:ListBucket", "s3:DeleteObject"]),
    doc(3, ["s3:GetObject"]),
  ];
}

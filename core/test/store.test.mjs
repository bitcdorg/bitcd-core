import { test } from "node:test";
import assert from "node:assert/strict";
import { resolveStoreConfig, s3Store } from "../src/store.mjs";

test("defaults to the local dev store with the throwaway credentials", () => {
  const c = resolveStoreConfig({}, {});
  assert.equal(c.endpoint, "http://localhost:4566");
  assert.deepEqual(c.credentials, { accessKeyId: "bitcd", secretAccessKey: "bitcd" });
  assert.equal(c.forcePathStyle, true);
  assert.equal(c.bucket, "bitcd-tfstate");
});

test("an empty endpoint means AWS's own endpoint and the SDK credential chain", () => {
  const c = resolveStoreConfig({}, { BITCD_S3_ENDPOINT: "" });
  assert.equal(c.endpoint, undefined);
  assert.equal(c.credentials, undefined);
  assert.equal(c.forcePathStyle, false);
  assert.equal(resolveStoreConfig({ endpoint: null }, {}).endpoint, undefined);
});

test("a remote endpoint never gets the dev credentials", () => {
  const c = resolveStoreConfig({}, { BITCD_S3_ENDPOINT: "https://s3.eu-west-1.amazonaws.com" });
  assert.equal(c.credentials, undefined);
  assert.equal(c.forcePathStyle, true);
});

test("explicit AWS keys win, with the session token when present", () => {
  const c = resolveStoreConfig({}, { BITCD_S3_ENDPOINT: "", AWS_ACCESS_KEY_ID: "A", AWS_SECRET_ACCESS_KEY: "S", AWS_SESSION_TOKEN: "T" });
  assert.deepEqual(c.credentials, { accessKeyId: "A", secretAccessKey: "S", sessionToken: "T" });
  const d = resolveStoreConfig({}, { AWS_ACCESS_KEY_ID: "A", AWS_SECRET_ACCESS_KEY: "S" });
  assert.deepEqual(d.credentials, { accessKeyId: "A", secretAccessKey: "S" });
});

test("local, container and plain-http endpoints get the dev pair", () => {
  for (const e of ["http://ministack:4566", "http://127.0.0.1:4566", "http://host.docker.internal:4566",
    "http://host.k3d.internal:4566", "http://minio.internal:9000", "https://localhost:4566"]) {
    assert.ok(resolveStoreConfig({}, { BITCD_S3_ENDPOINT: e }).credentials, e);
  }
});

// ensureBucket against a stub client: create only on a 404.
function stubbed(headError) {
  const sent = [];
  const store = s3Store({ endpoint: "http://localhost:4566", bucket: "b" });
  store.client.send = async (cmd) => {
    sent.push(cmd.constructor.name);
    if (cmd.constructor.name === "HeadBucketCommand" && headError) throw headError;
    return {};
  };
  return { store, sent };
}

test("ensureBucket leaves an existing bucket alone", async () => {
  const { store, sent } = stubbed(null);
  await store.ensureBucket();
  assert.deepEqual(sent, ["HeadBucketCommand"]);
});

test("ensureBucket creates a missing bucket", async () => {
  const { store, sent } = stubbed(Object.assign(new Error("nf"), { name: "NotFound", $metadata: { httpStatusCode: 404 } }));
  await store.ensureBucket();
  assert.deepEqual(sent, ["HeadBucketCommand", "CreateBucketCommand"]);
});

test("ensureBucket doesn't try to create when HeadBucket is forbidden", async () => {
  const { store, sent } = stubbed(Object.assign(new Error("forbidden"), { name: "Forbidden", $metadata: { httpStatusCode: 403 } }));
  await store.ensureBucket();
  assert.deepEqual(sent, ["HeadBucketCommand"]);
});

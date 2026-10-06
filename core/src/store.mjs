// @bitcd/core/store — the verify-on-read blob store (the untrusted-storage boundary), S3 class.
//
// The chain stores only {digest, schema_ref, storage_class}; the bytes live
// here. Readers must verify: `digestOf(text)` of what they fetched has to equal the
// on-chain digest — a swapped/corrupted/missing blob is DETECTED, never trusted.
// The only @bitcd/core subpath that needs @aws-sdk/client-s3 (optional peer dep).
import {
  CreateBucketCommand, DeleteObjectCommand, GetObjectCommand, HeadBucketCommand, PutObjectCommand, S3Client,
} from "@aws-sdk/client-s3";

export { digestOf } from "./protocol.mjs";

/// Where the store connects and as whom, from explicit options and the
/// environment. Pure, so the resolution is testable without a client.
///
/// - endpoint: `BITCD_S3_ENDPOINT`, else the local dev store on :4566. An
///   empty string (or `null`) means AWS's own regional endpoint.
/// - credentials: `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` (+
///   `AWS_SESSION_TOKEN` for temporary credentials) when set. Otherwise the
///   throwaway dev pair for a LOCAL endpoint — a known local or container
///   hostname, or any plain-http URL (real S3 is https) — and nothing for
///   anything else: the AWS SDK's own chain then applies (profiles, SSO,
///   instance and task roles).
/// - path-style addressing for a custom endpoint, virtual-hosted for AWS.
export function resolveStoreConfig(opts = {}, env = process.env) {
  const raw = "endpoint" in opts ? opts.endpoint : (env.BITCD_S3_ENDPOINT ?? "http://localhost:4566");
  const endpoint = raw ? raw : undefined;
  const local = endpoint !== undefined && isLocalEndpoint(endpoint);
  const credentials = opts.credentials ?? (env.AWS_ACCESS_KEY_ID
    ? {
      accessKeyId: env.AWS_ACCESS_KEY_ID,
      secretAccessKey: env.AWS_SECRET_ACCESS_KEY,
      ...(env.AWS_SESSION_TOKEN ? { sessionToken: env.AWS_SESSION_TOKEN } : {}),
    }
    : (local ? { accessKeyId: "bitcd", secretAccessKey: "bitcd" } : undefined));
  return {
    endpoint,
    bucket: opts.bucket ?? env.BITCD_S3_BUCKET ?? "bitcd-tfstate",
    region: opts.region ?? env.BITCD_S3_REGION ?? "us-east-1",
    credentials,
    forcePathStyle: opts.forcePathStyle ?? endpoint !== undefined,
  };
}

const LOCAL_HOSTS = new Set([
  "localhost", "127.0.0.1", "0.0.0.0", "::1", "[::1]",
  "ministack", "localstack", "host.docker.internal", "host.k3d.internal", "host.containers.internal",
]);
function isLocalEndpoint(url) {
  try {
    const u = new URL(url);
    return u.protocol === "http:" || LOCAL_HOSTS.has(u.hostname);
  } catch { return false; }
}

/// S3-compatible store handle over `resolveStoreConfig(opts)`: the dev stack
/// by default, real S3 with `BITCD_S3_ENDPOINT` set to the regional URL or
/// left empty.
export function s3Store(opts = {}) {
  const { endpoint, bucket, region, credentials, forcePathStyle } = resolveStoreConfig(opts);
  const client = new S3Client({
    region, forcePathStyle,
    ...(endpoint ? { endpoint } : {}),
    ...(credentials ? { credentials } : {}),
  });

  /// Create the bucket only when it's missing. A HeadBucket that fails for
  /// any other reason (e.g. credentials scoped to objects) leaves the bucket
  /// alone — the next read or write reports a real problem.
  async function ensureBucket() {
    try {
      await client.send(new HeadBucketCommand({ Bucket: bucket }));
      return;
    } catch (e) {
      const status = e?.$metadata?.httpStatusCode;
      if (!(e?.name === "NotFound" || e?.name === "NoSuchBucket" || status === 404)) return;
    }
    try {
      await client.send(new CreateBucketCommand({ Bucket: bucket }));
    } catch (e) {
      const n = e?.name ?? "";
      if (n !== "BucketAlreadyOwnedByYou" && n !== "BucketAlreadyExists") throw e;
    }
  }

  const getText = async (Key) =>
    (await client.send(new GetObjectCommand({ Bucket: bucket, Key }))).Body.transformToString();
  const putText = (Key, Body) =>
    client.send(new PutObjectCommand({ Bucket: bucket, Key, Body }));
  const deleteObject = (Key) =>
    client.send(new DeleteObjectCommand({ Bucket: bucket, Key }));

  return { client, bucket, ensureBucket, getText, putText, deleteObject };
}

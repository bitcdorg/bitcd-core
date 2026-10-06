// @bitcd/core/fixtures — demo-only sample data. NOT part of the library API
// surface (no semver promise): kept in core only because both the e2e beats
// and the console scenarios render the same sample, and it must digest identically
// everywhere.

/// The demo IAM policy-set schema tag (the reconcile beat's single provider).
export const SCHEMA_REF = "iampolicyset/v1";

/// A small, valid desired IAM policy-set fixture (the "v1" config in the demo).
export function sampleConfig({ serial = 1, allowDelete = false } = {}) {
  const actions = ["s3:GetObject", "s3:ListBucket"];
  if (allowDelete) actions.push("s3:DeleteObject");
  return {
    policySetName: "bitcd-app-readers",
    serial,
    statements: [
      { sid: "ReadAppBucket", effect: "Allow", actions, resources: ["arn:aws:s3:::bitcd-app/*"] },
    ],
  };
}

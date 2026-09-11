# gpg-kms

Sign artifacts with OpenPGP while the private key stays in AWS KMS. Verify with stock GnuPG against a published public-key file.

Three jobs, usually three actors:

- **Admin** — create the key (and, for the approval service, the stack). Export the OpenPGP public key and publish it. That file is the root of trust: signing pipelines, release metadata, and install scripts consume it; they do not create the key.
- **Signing pipeline** — produce a detached signature. Needs the env file from deploy, not admin IAM.
- **Verifier** — install script or consumer. Needs the public key, the artifact, and the signature. No AWS.

Two backends, two different keys. Pick one:

- **Direct KMS** — the pipeline calls KMS.
- **Approval service** — the pipeline invokes a Lambda (`lambda:InvokeFunction` only). A human approves each signature over email.

The walkthroughs use one temp directory so you can paste commands in order. When the heading changes, that is a different actor with different credentials — in production those steps run on different machines.

Prerequisites: GnuPG 2.x, Java 25+, Apache Maven 3.x, AWS CLI v2. Log in with the AWS CLI (`aws sso login` if you use SSO). The JAR uses the SDK default credential chain. Verify-only needs GnuPG.

## Build

Once, for export and sign (not for verify). Wrappers in `dist/` call `kmspgp.jar` and expect it in the same directory.

```bash
./kmspgp/build.sh
```

## Direct KMS

### Admin: deploy and export

The key must exist before anyone can sign. Export writes the OpenPGP public key; ship that file to wherever verifiers will look (release assets, installer, docs). Identity (`--user-name` / `--user-email`) is chosen at export.

**Needs:** AWS credentials that can create a KMS signing key.  
**Deploy permissions:** `kms:CreateKey`, `kms:CreateAlias`, `kms:DescribeKey`, `kms:TagResource`.  
**Export permissions:** `kms:DescribeKey`, `kms:GetPublicKey`, `kms:Sign` (export self-certifies the OpenPGP packet). Not the same set as deploy.  
**Produces:** `$WORK/env` for the signing pipeline, `$WORK/signing.pub.asc` for verifiers.

```bash
WORK=$(mktemp -d)

./kmsdirect/deploy.sh
./kmsdirect/config.sh > "$WORK/env"
. "$WORK/env"

./dist/kms-export.sh --key "$KMSPGP_KMS_KEY" \
  --user-name "Release Signing" --user-email "security@example.com" \
  --out "$WORK/signing.pub.asc"
```

### Signing pipeline

**Needs:** `$WORK/env` (or the same exports in CI secrets), the artifact, `dist/kmspgp.jar`.  
**Permissions:** `kms:Sign`, `kms:DescribeKey`, `kms:GetPublicKey`. Not create-key.

```bash
. "$WORK/env"
echo "hello" > "$WORK/example-1.0.0.txt"

./dist/kms-sign.sh --key "$KMSPGP_KMS_KEY" \
  "$WORK/example-1.0.0.txt" "$WORK/example-1.0.0.txt.asc"
```

### Verifier

**Needs:** public key, detached signature, artifact.  
**Permissions:** none.

```bash
./verify.sh --pubkey "$WORK/signing.pub.asc" \
  "$WORK/example-1.0.0.txt.asc" "$WORK/example-1.0.0.txt"
```

### Admin: undeploy

```bash
./kmsdirect/undeploy.sh
```

## Approval service

Also needs Terraform ≥ 1.5, Node.js 22+, npm, `openssl`.

Name and email are bound at deploy (kept in gitignored `kmslambda/infra/terraform.tfvars` so later deploys reuse them). The public export endpoint always returns that User ID.

### Admin: deploy, approvers, export

The stack includes the KMS key, Lambda, and a public HTTP export endpoint. Publish `$WORK/signing.pub.asc` as the pinned root of trust; install scripts can also fetch the same key from the API later.

**Needs:** AWS credentials that can apply the Terraform stack (KMS, Lambda, API Gateway, DynamoDB, SNS, IAM, SSM, S3, CloudWatch). First deploy requires `--user-name` and `--user-email` (or `KMSPGP_USER_NAME` / `KMSPGP_USER_EMAIL`).  
**Export permissions:** none. HTTPS GET of `/openpgp-public-key` (needs `$KMSPGP_LAMBDA_API_BASE_URL` from env).  
**Produces:** `$WORK/env` for the signing pipeline (`KMSPGP_LAMBDA_FUNCTION_NAME`, `KMSPGP_LAMBDA_API_BASE_URL`, `AWS_REGION`), `$WORK/signing.pub.asc` for verifiers.

```bash
WORK=$(mktemp -d)

./kmslambda/deploy.sh \
  --user-name "Release Signing" --user-email "security@example.com"
./kmslambda/approvers.sh add you@example.com
# Confirm the AWS SNS email before the first sign.

./kmslambda/config.sh > "$WORK/env"
. "$WORK/env"

./dist/lambda-export.sh --api "$KMSPGP_LAMBDA_API_BASE_URL" \
  --out "$WORK/signing.pub.asc"
```

### Signing pipeline

**Needs:** `$WORK/env`, the artifact, `dist/kmspgp.jar`. A confirmed approver must click the email link while sign waits.  
**Permissions:** `lambda:InvokeFunction` only. Not the admin Terraform IAM, not `kms:Sign`.

```bash
. "$WORK/env"
echo "hello" > "$WORK/example-1.0.0.txt"

./dist/lambda-sign.sh \
  --function "$KMSPGP_LAMBDA_FUNCTION_NAME" \
  --api "$KMSPGP_LAMBDA_API_BASE_URL" \
  --version 1.0.0 \
  "$WORK/example-1.0.0.txt" "$WORK/example-1.0.0.txt.asc"
```

### Verifier

Same three files as direct KMS. No AWS.

```bash
./verify.sh --pubkey "$WORK/signing.pub.asc" \
  "$WORK/example-1.0.0.txt.asc" "$WORK/example-1.0.0.txt"
```

### Admin: undeploy

Keeps the Terraform state bucket and HMAC parameter. The KMS key is scheduled for deletion.

```bash
./kmslambda/undeploy.sh
```

Copyright © 2026 Christian Tschenett — Licensed under the Apache License 2.0.

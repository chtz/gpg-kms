# GitHub Actions integration

Use kmslambda as the signing backend for a GitHub Actions pipeline. The pipeline never sees the private key and is not granted `kms:Sign`. It assumes a short-lived IAM role through GitHub OIDC and may only call `lambda:InvokeFunction`. A human still approves each signature over email. Verifiers never talk to AWS: they use GnuPG plus a public key **pinned in git**.

This repository's `Release kmspgp.jar` workflow is the worked example. The same IAM pattern applies to any other artifact your pipeline produces.

## What you get

- A **manual** workflow (`workflow_dispatch`) that builds `kmspgp-<shortsha>.jar`, waits for kmslambda approval, and publishes two GitHub Release assets: the JAR and its detached OpenPGP signature (`.asc`).
- A **pinned** OpenPGP public key at [`keys/signing.pub.asc`](../keys/signing.pub.asc). That file is the root of trust. It is not attached to each Release; it changes only when the KMS signing key is rotated. The workflow checks that the pin contains **exactly one** primary key; it does not fetch a live key.
- Least-privilege AWS access: GitHub Environment `release` on `main`, plus an IAM trust policy that allows **only** [`.github/workflows/release-jar.yml`](../.github/workflows/release-jar.yml) to assume the role.

## Trust model

Three actors, three credential sets:

| Actor | Credentials | What they do |
|-------|-------------|--------------|
| **Admin** | Broad AWS (Terraform + IAM) and GitHub admin | Deploy kmslambda, invoke-export and commit the public key, create the OIDC role, set GitHub Environment values |
| **Signing pipeline** | GitHub OIDC → IAM role | `lambda:InvokeFunction` only. Cannot create keys, cannot call `kms:Sign` |
| **Verifier** | None | GnuPG + `keys/signing.pub.asc` + the JAR and `.asc` from the GitHub Release |

Do not put long-lived AWS access keys in GitHub secrets. The workflow uses `aws-actions/configure-aws-credentials` with `role-to-assume`. GitHub mints an OIDC token; AWS STS exchanges it for temporary credentials.

Human approval stays in kmslambda (SNS email). GitHub Environment protection here is for OIDC binding (which workflow, which branch), not a second product-approval gate. You can add GitHub required reviewers later without changing AWS.

## Prerequisites

- AWS CLI v2. Export `AWS_PROFILE` to the profile that owns this stack (the same profile you already use for `aws` in this repo). Scripts honor `AWS_PROFILE` the same way [`kmslambda/common.sh`](../kmslambda/common.sh) does. Log in yourself (`aws sso login --profile "$AWS_PROFILE"` if you use SSO).
- GitHub CLI (`gh`), authenticated to the repository (`gh auth login` if needed)
- For kmslambda deploy: Terraform ≥ 1.5, Node.js 22+, npm, `openssl`
- For a local dry-run of export/sign: Java 25+, Apache Maven 3.x, `./kmspgp/build.sh`

Region comes from that profile or `AWS_REGION`. Setup scripts resolve the account at runtime with `sts get-caller-identity`; they do not hard-code account IDs, and they print the **profile name**, not the account id.

## 1. Deploy kmslambda

The approval service owns the KMS key, Lambda, API, and SNS topic. First deploy binds the OpenPGP User ID (`--user-name` / `--user-email`). Confirm the SNS subscription **before** the first GitHub Actions run.

```bash
export AWS_PROFILE=your-profile   # the CLI profile for this account
# aws sso login --profile "$AWS_PROFILE"   # if the session expired

./kmslambda/deploy.sh \
  --user-name "Release Signing" --user-email "security@example.com"
./kmslambda/approvers.sh add you@example.com
# Confirm the AWS SNS email.

mkdir -p github-actions/.local
./kmslambda/config.sh > github-actions/.local/kmslambda.env
. github-actions/.local/kmslambda.env
```

`github-actions/.local/` is gitignored. `config.sh` prints `AWS_REGION`, `KMSPGP_LAMBDA_FUNCTION_NAME`, and informational `KMSPGP_LAMBDA_API_BASE_URL` (approve/poll HTTP). Do not commit those values.

Details: [README — Approval service](../README.md#approval-service).

## 2. Pin the OpenPGP public key

Admin step. Repeat only when the KMS key is rotated (new kmslambda key). Export is a Lambda invoke (`lambda:InvokeFunction`), not an HTTP GET.

```bash
./kmspgp/build.sh   # once, so dist/kmspgp.jar exists for the export wrapper
. github-actions/.local/kmslambda.env

mkdir -p keys
./dist/lambda-export.sh --function "$KMSPGP_LAMBDA_FUNCTION_NAME" \
  --out keys/signing.pub.asc
./verify.sh --check-pin keys/signing.pub.asc
git add keys/signing.pub.asc
```

The armored file contains the OpenPGP User ID (public by design). It does not contain AWS account identifiers.

The release workflow checks that this pin contains exactly one primary key. It does not fetch a live export. Armor bytes are not compared: each export re-signs the self-certification with ECDSA, so the `.asc` text changes even when the key is the same. After a KMS key rotation, commit the new pin before the next signed release. A stale pin is caught when GnuPG verifies the `.asc`.

## 3. Create the GitHub OIDC IAM role

Policy JSON lives in [`trust-policy.json`](trust-policy.json) and [`permissions-policy.json`](permissions-policy.json). Placeholders are filled at runtime; applied copies stay under `github-actions/.local/`.

The trust policy allows `sts:AssumeRoleWithWebIdentity` only when:

- `aud` is `sts.amazonaws.com`
- `sub` is GitHub's **immutable** subject (repos created after 15 Jul 2026): `repo:OWNER@OWNER_ID/REPO@REPO_ID:environment:release`
- `job_workflow_ref` is `OWNER/REPO/.github/workflows/release-jar.yml@refs/heads/main`

`setup-oidc-role.sh` reads `OWNER_ID` / `REPO_ID` from `gh api` (or `--owner-id` / `--repo-id`). Do not guess the name-only `sub` (`repo:OWNER/REPO:environment:…`); CloudTrail `userIdentity.userName` is the `sub` AWS actually saw. Older GitHub repos that never opted into immutable claims still emit the name-only format — change the template if you are integrating an old repository.

The permissions policy is a single statement: `lambda:InvokeFunction` on the kmslambda function ARN.

```bash
. github-actions/.local/kmslambda.env
./github-actions/setup-oidc-role.sh --repo OWNER/REPO \
  > github-actions/.local/role.env
. github-actions/.local/role.env
```

`setup-oidc-role.sh` uses `AWS_PROFILE` / `AWS_REGION`. Confirm the `profile:` line it prints before it creates IAM resources.

`--repo` defaults to `gh repo view` or `git remote origin`. `--role-name` defaults to `gha-gpg-kms-release`. `--function` defaults to `KMSPGP_LAMBDA_FUNCTION_NAME`.

The script is idempotent: it creates the account-level GitHub OIDC provider if missing, then creates or updates the role. The OIDC provider is shared by every GitHub Actions role in the account; do not delete it casually.

## 4. Configure the GitHub Environment

Creates Environment `release`, restricts deployments to branch `main`, and sets:

| Name | Kind | Source |
|------|------|--------|
| `AWS_ROLE_ARN` | environment **secret** | `setup-oidc-role.sh` |
| `AWS_REGION` | environment variable | `kmslambda/config.sh` |
| `KMSPGP_LAMBDA_FUNCTION_NAME` | environment variable | `kmslambda/config.sh` |

```bash
. github-actions/.local/kmslambda.env
. github-actions/.local/role.env
./github-actions/configure-github.sh --repo OWNER/REPO
```

The workflow YAML references only these names. Account IDs and role ARNs do not belong in git.

Push the workflow file, this guide, and `keys/signing.pub.asc` to `main` before the first run. The OIDC `job_workflow_ref` claim includes the ref; a run from another branch cannot assume the role.

## 5. Run a signed release

1. On GitHub: **Actions → Release kmspgp.jar → Run workflow** (branch `main`).
2. The job builds the JAR, checks that the pin has exactly one primary key, then assumes the IAM role.
3. `lambda-sign.sh --function …` waits up to 30 minutes. The sign step logs the artifact path, OpenPGP digest, and `hashedAt`. Approve the SNS email while it waits; compare those fields with the job log. The job timeout is 40 minutes.
4. GitHub Release `kmspgp-<shortsha>` is created with `kmspgp-<shortsha>.jar` and `kmspgp-<shortsha>.jar.asc`. AWS credentials are unset before `gh release create`.

Re-running the same commit fails if the tag already exists. That is intentional: a SHA maps to one Release. If sign succeeded and upload failed, delete the tag/release only when you intend to produce a new signature for the same bytes.

## 6. Verify a download

No AWS. Clone (or copy `keys/signing.pub.asc` and [`verify.sh`](../verify.sh)) and download the two Release assets.

```bash
gh release download kmspgp-SHORTSHA --pattern 'kmspgp-*'
./verify.sh --pubkey keys/signing.pub.asc \
  kmspgp-SHORTSHA.jar.asc kmspgp-SHORTSHA.jar
```

## Adapting this to another pipeline

Keep kmslambda as-is. Copy [`github-actions/`](.) and adjust:

1. Pin **your** OpenPGP public key in git (same export command, different path if you prefer).
2. Point `job_workflow_ref` in `trust-policy.json` at **your** workflow file and branch.
3. Use a GitHub Environment name and IAM role name that match that pipeline.
4. Grant the role `lambda:InvokeFunction` on the same function (or another kmslambda you deploy).
5. Put `AWS_ROLE_ARN` / region / function name in that Environment, not in the workflow file.
6. Call `./dist/lambda-sign.sh --function …` (or `java -jar kmspgp.jar lambda-sign --function …`) on the artifact you actually ship. The JAR in this repo is both the tool and the dogfood artifact; other pipelines only need it as the signer client.

Do not reuse this role for unrelated workflows. A second pipeline should get its own role and `job_workflow_ref` so a compromised workflow file cannot mint signing credentials.

## Tear down the CI role

```bash
export AWS_PROFILE=your-profile
./github-actions/teardown-oidc-role.sh
```

Deletes the IAM role and inline policy. Leaves the account-level GitHub OIDC provider. Undeploying kmslambda is separate: `./kmslambda/undeploy.sh`.

## Troubleshooting

| Symptom | Likely cause |
|---------|----------------|
| SNS email never arrives | Approver not added, or the subscription is still `PendingConfirmation` (`./kmslambda/approvers.sh list`) |
| `Not authorized to perform sts:AssumeRoleWithWebIdentity` | Trust policy `sub` does not match the token. After 15 Jul 2026 GitHub includes owner/repo IDs (`repo:OWNER@ID/REPO@ID:environment:release`). Re-run `setup-oidc-role.sh`. CloudTrail `userIdentity.userName` is the actual `sub`. Also check `job_workflow_ref` (workflow path and `@refs/heads/main`) |
| `lambda:InvokeFunction` denied | Permissions policy ARN does not match the function the workflow invokes; re-run `setup-oidc-role.sh` after sourcing `config.sh` |
| Job hits 40 minutes | Nobody approved; kmslambda poll timeout is 30 minutes |
| Email digest or artifact path does not match the Actions log | Approve only if they match. Recalculate with kmspgp from the artifact plus `hashedAt` (not `sha256sum`) |
| GnuPG verify fails after a key rotation | `keys/signing.pub.asc` was not updated; re-export and commit the pin |
| Pin check fails (`exactly one primary OpenPGP key`) | Extra keys in the pin; export a single primary key |
| Release create fails with tag exists | That commit already has a Release; use a new commit or delete the tag only if you mean to re-sign |
| `kmspgp.jar not found` | `./kmspgp/build.sh` did not run or Java/Maven is missing on the runner |

OIDC session duration is one hour, which covers the 30-minute approval wait.

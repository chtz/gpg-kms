# Artifact Signing Service (Serverless, AWS-only)

Minimal, KISS, pay-per-use artifact-signing service for release pipelines. Pipelines request signatures for precomputed SHA-256 digests; a human must approve via an SNS-delivered link. The actual signing key is an asymmetric AWS KMS key and never exposed to the pipeline.

- One Lambda (Node.js 22+, TypeScript, AWS SDK v3)
- KMS SIGN_VERIFY key (ECC_NIST_P256), MessageType=DIGEST
- DynamoDB for short-lived signing-request state (PAY_PER_REQUEST + TTL)
- SNS for human approvals (subscriptions manage recipients)
- API Gateway v2 HTTP API for approval/status/public-key/OpenPGP public key
- SSM Parameter Store SecureString for HMAC secret (script 01; not created by Terraform)
- S3 bucket for Terraform state (script 02; not managed by Terraform)
- Terraform provisions the rest (KMS, DynamoDB, SNS, API Gateway, Lambda, IAM)

No Step Functions, no containers, no DB beyond DynamoDB, no TUF.

## High-level flow

1) Pipeline builds artifact, computes SHA-256 digest (hex)  
2) Pipeline invokes the Lambda directly (SigV4/IAM) with `{ action: "create", digest, ... }`  
3) Lambda writes a WAITING request to DynamoDB and publishes an approval link via SNS  
4) Human opens the link (GET only renders HTML) and clicks Approve (POST)  
5) Lambda atomically claims the WAITING request, calls KMS Sign with MessageType=DIGEST, stores signature, transitions to SIGNED  
6) Pipeline polls the HTTP API for status and retrieves the signature  

Lifecycle: `WAITING → SIGNING → SIGNED | FAILED` and `WAITING → REJECTED`. Expiration via TTL.

## Security model

- Pipeline gets `lambda:InvokeFunction` only. It does NOT have `kms:Sign`. Only Lambda can use KMS Sign.
- Approval links are short-lived, HMAC-authenticated (secret from SSM SecureString), and GET has no side effects. POST performs approval.
- DynamoDB conditional update ensures one-time approval.
- Signing-relevant request data is immutable after creation.
- KMS is called with `MessageType=DIGEST` to avoid double hashing.
- Least-privilege IAM on all resources.

## HTTP surface (API Gateway v2)

- `GET /approve` — Render approval page (no side effects)
- `POST /approve` — Approve or reject (explicit action)
- `GET /requests/{id}` — Secure status/poll/signature retrieval (token)
- `GET /public-key` — Return KMS public key (PEM/SPKI) + metadata (`creationDate`, `description`, `arn`)
- `GET /openpgp-public-key` — Return a self-certified OpenPGP public key (`userName` and `userEmail` query params). Lambda calls `kms:Sign` for the UID certification only; this is not the artifact-approval path.

Separate signed tokens for approval and polling to avoid privilege escalation.

## Deploy and test

This directory is self-contained (no parent-repo files). After `git clone`, with `AWS_PROFILE` set to an SSO session:

Prereqs: Terraform ≥ 1.5, Node.js 22+, npm, AWS CLI v2, `openssl`, `curl`, `python3`. Region and account come from the profile. There is no `terraform.tfvars`.

```bash
cd kmslambda
./01_create_hmac_secret.sh              # SSM SecureString /artifact-signing/approval-hmac
./02_create_state_bucket.sh             # S3 state bucket + infra/backend.hcl
./03_npm_install.sh                     # npm ci from package-lock.json
./04_build.sh                           # dist/index.js (runs 03 if node_modules is missing)
./05_terraform_plan.sh                  # terraform init + plan → infra/tfplan
./06_terraform_apply.sh                 # terraform apply tfplan
./07_subscribe_approver.sh you@example.com
# Confirm the AWS SNS subscription email before creating a request.
./08_create_signing_request.sh          # SHA-256 testdata/artifact.txt, Lambda invoke
./09_poll_signing_request.sh            # waits until SIGNED / FAILED / REJECTED
# While 09 polls (or before), open the SNS approval link: GET is view-only, click Approve or Reject.
./10_verify_signature.sh                # ECDSA verify of testdata/artifact.txt vs /public-key
./11_terraform_destroy.sh               # destroy stack; keep state bucket + HMAC SSM
```

Terraform follows the CLI session (temporary keys are exported for the AWS SDK). The HTTP API stage is `prod`; approval and poll URLs include `/prod`.

Terraform outputs (printed by `06`):
- `api_base_url` — Base URL for approval page, polling, public key, and OpenPGP public key
- `lambda_function_name` — Function to invoke from pipeline
- `dynamodb_table_name`, `sns_topic_arn`, `kms_key_id` — Resource references

Override the HMAC parameter name with `APPROVAL_HMAC_PARAM_NAME` (script 01) and `TF_VAR_approval_hmac_param_name` (Terraform) if you do not use the default.

`11` removes Lambda, API Gateway, DynamoDB, SNS, IAM, and the KMS alias. The signing key is scheduled for deletion (7 days). Re-deploy with `04`–`06`; that creates a **new** KMS key and API URL, so run `07` again. Scripts `01` and `02` are idempotent.

Tracked vs generated: commit sources, `package-lock.json`, `infra/.terraform.lock.hcl`, and `testdata/artifact.txt`. Ignore `node_modules/`, `dist/`, `.terraform/`, `infra/backend.hcl`, `infra/tfplan`, and `last-signing-request.json`. Tamper tests must edit `testdata/artifact.txt` (not a different `testartifact.txt` in the working directory).

## Runtime configuration (env)

Lambda environment is populated by Terraform:
- `TABLE_NAME` — DynamoDB table
- `KMS_KEY_ID` — KMS key ID (ECC_NIST_P256)
- `SNS_TOPIC_ARN` — SNS approvals topic
- `API_BASE_URL` — `${api_endpoint}/${stage}`
- `APPROVAL_HMAC_PARAM_NAME` — SSM path (SecureString)
- `REQUEST_TTL_SECONDS` (default 3600), `APPROVAL_TTL_SECONDS` (default 1800)

## DynamoDB item shape

```json
{
  "requestId": "01J...ULID",
  "status": "WAITING" | "SIGNING" | "SIGNED" | "FAILED" | "REJECTED",
  "artifactDigest": "<sha256-hex, the digest KMS signs>",
  "fileSha256": "<optional sha256-hex of file bytes, display only>",
  "artifact": "...", "version": "...", "environment": "...",
  "metadata": { "..." : "..." },
  "createdAt": 1710000000,
  "expiresAt": 1710003600,
  "approvalExpiresAt": 1710001800,
  "approvedAt": 1710000123,
  "approverIp": "1.2.3.4",
  "signedAt": 1710000456,
  "algorithm": "ECDSA_SHA_256",
  "signature": "<base64-der>",
  "error": "..." // when FAILED
}
```

## Lambda direct Invoke (pipeline)

Action: `create`. This is NOT exposed via API Gateway; invoke the Lambda directly over SigV4/IAM.

Request:

```json
{
  "action": "create",
  "digest": "<sha256-hex, signed by KMS>",
  "fileSha256": "<optional 64-char hex of the artifact file>",
  "artifact": "myapp-linux-x64.tar.gz",
  "version": "2.3.1",
  "environment": "prod",
  "metadata": { "commit": "abc123", "buildUrl": "https://..." }
}
```

Response:

```json
{
  "ok": true,
  "requestId": "01J...",
  "status": "WAITING",
  "expiresAt": 1710003600,
  "approvalExpiresAt": 1710001800,
  "pollUrl": "https://....../requests/01J...?token=....",
  "pollToken": "eyJ2ZXIiOjEsImNhcCI6InBvbGwiLCJyaWQiOiIwMUoiLCJleHAiOjE3MTAwMDM2MDB9.abc..."
}
```

Errors:
```json
{ "ok": false, "error": "Invalid or missing digest: expected 64-char hex SHA-256", "code": "BAD_DIGEST" }
```

`fileSha256` is optional. `08_create_signing_request.sh` omits it; the approval page and SNS message then show a single `SHA-256` line (the digest KMS will sign), same as before. When `fileSha256` is set (kmspgp `lambda-sign` does this), SNS and the approval page show **File SHA-256** and **Signing digest** separately. `artifactDigest` in DynamoDB/poll is always the digest KMS signs.

Errors for a bad `fileSha256`:
```json
{ "ok": false, "error": "Invalid fileSha256: expected 64-char hex SHA-256", "code": "BAD_FILE_SHA256" }
```

## Polling for status/signature

`GET {api_base_url}/requests/{requestId}?token=<pollToken>` or `Authorization: Bearer <pollToken>`

Responses:

```json
{ "ok": true, "requestId": "...", "status": "WAITING", "artifactDigest": "...", "createdAt": 171..., "expiresAt": 171... }
```

```json
{ "ok": true, "requestId": "...", "status": "SIGNED", "artifactDigest": "...", "signature": "<base64-der>", "signingAlgorithm": "ECDSA_SHA_256", "publicKeyUrl": "https://.../public-key" }
```

```json
{ "ok": true, "requestId": "...", "status": "FAILED", "error": "..." }
```

```json
{ "ok": true, "requestId": "...", "status": "REJECTED", "rejectionReason": "Rejected" }
```

401/403 when token is missing/invalid/not for this request; 404 if request not found. Poll JSON includes `fileSha256` when the create request supplied it.

## Approval via SNS

- Subscribe approvers (email, SMS, etc.) to the SNS topic Terraform creates.
- The published message includes artifact metadata, digest (and file SHA-256 when `fileSha256` was sent), and the approval link.
- `GET /approve` renders an HTML page with details and Approve/Reject buttons.
- `GET` never approves; only `POST` changes state.
- Approval is one-time via DynamoDB conditional update; double-clicks are safe.

## Public key and verification

`GET {api_base_url}/public-key` returns:

```json
{
  "ok": true,
  "keyId": "1234abcd-...",
  "publicKeyPem": "-----BEGIN PUBLIC KEY-----\nMIIB...==\n-----END PUBLIC KEY-----\n",
  "keySpec": "ECC_NIST_P256",
  "signingAlgorithms": ["ECDSA_SHA_256"],
  "keyUsage": "SIGN_VERIFY",
  "creationDate": "2026-01-15T12:34:56.000Z",
  "description": "Artifact Signing Key (KMS) for artifact-signing-service",
  "arn": "arn:aws:kms:..."
}
```

`creationDate` / `description` / `arn` are additive. `10_verify_signature.sh` still only uses `publicKeyPem`.

Verification of signatures produced by `08`/`09` is KMS ECDSA over SHA-256 of the artifact bytes. The signature is ASN.1 DER ECDSA (r,s). **That path is not OpenPGP**; `gpg --verify` will not work on those DER signatures.

`./10_verify_signature.sh` fetches `/public-key` and uses Node `crypto.verify('sha256', fileBytes, pem, derSig)` on the current file (default: the path stored by `08`, usually `testdata/artifact.txt`). Changing that file after signing must fail. Pass another path to check a different file against the same signature.

### OpenPGP public key (`GET /openpgp-public-key`)

Query params `userName` and `userEmail` are required. Example:

`GET {api_base_url}/openpgp-public-key?userName=Test&userEmail=test%40example.com`

Returns JSON `{ ok, armored, fingerprint, keyCreationDate, userId }`. The `armored` value is a transferable OpenPGP public key (UID self-certification signed by KMS). OpenPGP key creation time is the KMS key creation date so fingerprints match kmspgp `lambda-sign`.

This endpoint is for kmspgp (`lambda-export`) and `gpg --import`. Numbered scripts `08`–`10` do not call it and do not require `gpg`. OpenPGP document signatures still go through `create` + human approval; kmspgp wraps the resulting DER as OpenPGP.

## Out-of-scope integrations (documented only)

### GitLab CI / pipeline
- Compute artifact SHA-256 (`sha256sum artifact.tar.gz | awk '{print $1}'`)
- Invoke Lambda via SigV4/IAM (`aws lambda invoke --function-name <name> --payload ...`)
- Extract `pollToken` or `pollUrl` from response
- Poll `GET /requests/{id}?token=...` until `SIGNED|FAILED|REJECTED`
- On `SIGNED`, verify signature using `/public-key`, then upload `{artifact, signature, versions.json}` to S3 (not implemented here)

### Updater design assumptions
- Maintains locally trusted signing keys (initial trust anchor)
- Verifies every artifact before install; rejects downgrades
- Supports version/update barriers to introduce new keys
- Example: A trusts K1; B (signed with K1) ships K1+K2; C (signed with K2) declares B as minimum; old installs must go A→B→latest

## Development

```bash
./03_npm_install.sh
./04_build.sh
npm run typecheck
```

### Project layout
```
src/index.ts                 # Lambda source
src/openpgp.ts               # OpenPGP public-key export (used by GET /openpgp-public-key)
testdata/artifact.txt        # Default file hashed by 08 / verified by 10
infra/*.tf                   # Terraform: KMS, DynamoDB, SNS, API GW, Lambda, IAM
infra/.terraform.lock.hcl    # Provider versions (tracked)
package-lock.json            # Tracked; required for npm ci after clone
common.sh                    # Shared AWS / Terraform helpers
01_create_hmac_secret.sh     # SSM HMAC secret
02_create_state_bucket.sh    # S3 Terraform state bucket
03_npm_install.sh            # npm ci
04_build.sh                  # Lambda bundle (runs 03 if node_modules is missing)
05_terraform_plan.sh
06_terraform_apply.sh
07_subscribe_approver.sh     # SNS email subscription
08_create_signing_request.sh # SHA-256 + Lambda invoke (create)
09_poll_signing_request.sh   # GET pollUrl until SIGNED / FAILED / REJECTED
10_verify_signature.sh       # Node ECDSA verify (not OpenPGP, not gpg)
11_terraform_destroy.sh      # terraform destroy (keeps state bucket + HMAC SSM)
```

## Notes

- Costs are effectively zero when unused; pay-per-request DynamoDB, Lambda, API GW, and SNS scale with traffic.
- Approval/poll tokens are HMAC-signed with an SSM SecureString secret and never logged.
- Only the Lambda can call `kms:Sign` for artifact signatures; the pipeline never gets that permission.
- OpenPGP / `gpg` verification is exercised by kmspgp (`lambda-sign` / `lambda-export`) and the repo-root `import-lambda-and-verify.sh`, not by scripts `08`–`10`.


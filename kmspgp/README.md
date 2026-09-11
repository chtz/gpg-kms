# kmspgp

Wraps an AWS KMS `ECC_NIST_P256` SIGN_VERIFY key as OpenPGP. Hash locally, sign the OpenPGP digest, emit a detached armored signature. The private key never leaves KMS. Verify with stock `gpg --verify`.

Two signing modes:

- **Direct KMS** (`export`, `-bsau`): the caller needs `kms:DescribeKey`, `kms:GetPublicKey`, `kms:Sign`.
- **Lambda-backed** (`lambda-export`, `lambda-sign`): the caller needs a deployed [kmslambda](../kmslambda) stack, `lambda:InvokeFunction`, and `AWS_PROFILE`. It does **not** need `kms:Sign`. Artifact signatures wait for human approval.

Credentials and region come from the AWS SDK default chain (`AWS_PROFILE`, `AWS_REGION`, …).

## Build

Java 25+, Maven 3.x.

```bash
cd kmspgp
mvn clean package
```

Produces `target/kmspgp.jar`.

## Sign with KMS directly, verify with gpg

`KEY` is a KMS key id, ARN, or alias. No kmslambda deployment is required.

```bash
# export public key (once)
java -jar target/kmspgp.jar export --user-name NAME --user-email EMAIL KEY > pubkey.asc
gpg --import pubkey.asc

# sign
java -jar target/kmspgp.jar -bsau KEY < artifact > artifact.asc

# verify (no AWS)
gpg --verify artifact.asc artifact
```

`-bsau` is gpg’s detach-sign + armor + local-user. Point existing `gpg -bsau` call sites at the jar.

Throwaway demo key: `./create_test_key.sh` then `export_test_key.sh` / `import_test_key.sh` / `sign_with_test_key.sh` / `verify_with_test_key.sh` / `delete_test_key.sh`. Those scripts use an isolated GnuPG homedir (`./gpg_temp`), not `~/.gnupg`. They write `kmspgp-pub.asc` and `testartifact.txt.asc`.

## Sign via kmslambda (approval)

Needs a deployed kmslambda stack (`./06_terraform_apply.sh` and an SNS subscription). The jar talks only to the Lambda and HTTP APIs (env vars below). It does not read Terraform files.

```bash
export KMSPGP_LAMBDA_FUNCTION_NAME=...   # terraform output lambda_function_name
export KMSPGP_LAMBDA_API_BASE_URL=...    # terraform output api_base_url

java -jar target/kmspgp.jar lambda-export --user-name NAME --user-email EMAIL > pubkey.asc

# stdin is the artifact; progress is on stderr; stdout is the signature
# approve the SNS link while this polls
java -jar target/kmspgp.jar lambda-sign --artifact NAME --version VER --environment ENV \
  < artifact > artifact.asc

gpg --import pubkey.asc
gpg --verify artifact.asc artifact
```

| Variable | Role |
| --- | --- |
| `KMSPGP_LAMBDA_FUNCTION_NAME` | Required for `lambda-sign` (name or ARN) |
| `KMSPGP_LAMBDA_API_BASE_URL` | Required for `lambda-export` and `lambda-sign` |
| `KMSPGP_LAMBDA_POLL_INTERVAL_SECONDS` | Default `2` |
| `KMSPGP_LAMBDA_POLL_TIMEOUT_SECONDS` | Default `1800` |
| `AWS_PROFILE` / `AWS_REGION` | SDK default chain (Lambda invoke) |

`lambda-sign` sends the OpenPGP digest as `digest` (what KMS signs) and the file SHA-256 as `fileSha256` (shown on the approval page). `lambda-export` calls `GET /openpgp-public-key`.

Test wrappers (look up function name and API URL from kmslambda Terraform; do not replace the direct-KMS scripts):

```bash
./sign_with_lambda.sh    # → testartifact.txt.lambda.asc (approve SNS while it waits)
./verify_with_lambda.sh  # → kmspgp-lambda-pub.asc, isolated ./gpg_temp_lambda
```

Then from the repo root (after `./sign-and-verify.sh` has created `./keyring`), import leftover files with stock gpg — no AWS:

```bash
./import-and-verify.sh          # direct-KMS leftovers: kmspgp-pub.asc / testartifact.txt.asc
./import-lambda-and-verify.sh   # lambda leftovers: kmspgp-lambda-pub.asc / testartifact.txt.lambda.asc
```

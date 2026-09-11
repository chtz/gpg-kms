# gpg-kms

Copyright © 2026 Christian Tschenett — Licensed under the Apache License 2.0.

This repository shows that an existing OpenPGP signing setup — local GnuPG keys on disk, public keys in a verification keyring, `gpg --verify` at the consumer — can be evolved so that **signing happens in AWS KMS**. The secret key never leaves KMS. Verification does not change: same `gpg`, same keyring, same detached signatures. The only extra step is importing the KMS public key into that keyring.

That is the whole point. Pipelines and developers keep verifying the way they already do. Signers need AWS credentials — either `kms:Sign` on a key, or `lambda:InvokeFunction` on a kmslambda stack (and typically SSO login) — not a private key file.

Scripts use isolated `--homedir` directories. They never read or write `~/.gnupg`.

## What it proves

| Claim | How the demo shows it |
| --- | --- |
| Local GPG signing and keyring verification already work | `./sign-and-verify.sh` |
| A KMS key can produce a GnuPG-verifiable detached signature | `kmspgp/` scripts: export, sign, verify |
| Approval-gated KMS signing still verifies with stock gpg | `kmspgp/` `sign_with_lambda.sh` / `verify_with_lambda.sh`, then `./import-lambda-and-verify.sh` |
| The private signing key never leaves KMS | `kmspgp` hashes locally and calls `kms:Sign`; it never materializes a secret key |
| Verification stays the same after KMS is introduced | `./import-and-verify.sh` uses the existing `./verify.sh` / `./import.sh` |
| A signature is rejected until its public key is in the keyring | First verify in `import-and-verify.sh` fails (`NO_PUBKEY`); after import it succeeds |

What this unlocks in a real system: signing in CI without putting a private key on the runner, and a security model where key use is an IAM decision, not a file on a laptop.

## Architecture

```
Signer (today)          Signer (after KMS)              Signer (KMS + approval)
─────────────────       ────────────────────────────    ────────────────────────────
local secret key   →    AWS KMS ECC_NIST_P256           kmslambda (human approves)
gpg --detach-sign  →    kmspgp -bsau <key-id>           kmspgp lambda-sign
artifact.sig            artifact.asc                    artifact.lambda.asc

Verifier (unchanged)
────────────────────────────
public-only keyring  (git / artifact store)
gpg --verify sig artifact
```

Two roles, two kinds of material:

- **Signers** hold either a local GnuPG secret key, permission to use a KMS key directly, or permission to invoke kmslambda (`lambda:InvokeFunction` only — not `kms:Sign`). They produce a detached ASCII-armored OpenPGP signature.
- **Verifiers** hold only public keys. They do not need AWS credentials. They need the signing public key in the keyring.

`kmspgp` is the bridge. Direct mode wraps a KMS `ECC_NIST_P256` public key in a self-certified OpenPGP public-key packet and calls `kms:Sign`. Lambda mode fetches a certified pubkey from kmslambda `GET /openpgp-public-key` and, for signatures, invokes Lambda `create`, waits for approval, and wraps the returned DER the same way. Verification does not change: `gpg --import` / `gpg --verify`.

The distributed verification keyring stays public-only. Import rejects private-key blocks.

## Prerequisites

| Tool | Why |
| --- | --- |
| GnuPG 2.x (`gpg`) | Local signing, import, verify |
| Bash | All demo scripts |
| Java 25+ | `kmspgp` (`maven.compiler.release` is 25) |
| Apache Maven 3.x | `mvn clean install` in `kmspgp/` |
| AWS CLI v2 | Create / describe / delete the demo KMS key; SSO login |

AWS:

1. An AWS account and an IAM identity that can create and use a KMS signing key (at least `kms:CreateKey`, `kms:CreateAlias`, `kms:DescribeKey`, `kms:GetPublicKey`, `kms:Sign`, `kms:DeleteAlias`, `kms:ScheduleKeyDeletion`).
2. AWS SSO configured (`aws configure sso`). A region must be set on the profile or via `AWS_REGION` / `AWS_DEFAULT_REGION`.
3. Before the KMS steps:

```bash
export AWS_PROFILE=your-profile
aws sso login
```

`kmspgp` itself uses the AWS SDK default credential and region chain (`AWS_PROFILE`, `AWS_REGION`, …). It does not take `--profile` / `--region` flags.

## Run the demo

Do the kmspgp work in `kmspgp/` first (direct KMS, and optionally lambda). Then come back to the repo root for the import scripts. Those root scripts do **not** call AWS: they import leftover `.asc` files into `./keyring` and verify with stock gpg.

`./sign-and-verify.sh` **resets** `keyring/`. Run it before the import scripts, not between them. Do not re-run an import script after it already succeeded unless you reset the ring — the first verify would succeed and the script treats that as an error.

### 1. Local GPG (no AWS)

From the repository root:

```bash
./sign-and-verify.sh
```

Creates three unprotected Ed25519 demo keypairs under `keys/`, a public-only keyring with signer 1 and 2 only, and three detached signatures of `artifact.txt`. Signatures 1 and 2 verify. Signature 3 fails because that public key was never imported.

This is the “before”: signing keys on disk, verification from a published keyring. It also creates `./keyring`, which the later import scripts require.

### 2. kmspgp direct KMS (in `kmspgp/`)

```bash
cd kmspgp
mvn clean install
export AWS_PROFILE=your-profile
aws sso login

./create_test_key.sh    # KMS key + alias/kmspgp-test-signing
./export_test_key.sh    # → kmspgp-pub.asc
./import_test_key.sh    # isolated keyring in ./gpg_temp (not ~/.gnupg)
./sign_with_test_key.sh # KMS signs testartifact.txt → testartifact.txt.asc
./verify_with_test_key.sh
./delete_test_key.sh    # drop alias, schedule key deletion (default 7 days)
```

`delete_test_key.sh` is last so leftover keys do not keep costing money. The export and signature files remain (`kmspgp-pub.asc`, `testartifact.txt.asc`); the root import scripts need those. Override the pending window with `KMS_PENDING_WINDOW_DAYS` (7–30). No Lambda required.

### 3. Optional: kmspgp via kmslambda (still in `kmspgp/`)

Requires a deployed [kmslambda](kmslambda) stack (`kmslambda/06_terraform_apply.sh` and an SNS subscriber). Does not replace stage 2; it writes **different** files so it cannot clobber the direct-KMS leftovers.

```bash
cd kmspgp
./sign_with_lambda.sh     # approve the SNS link while it polls → testartifact.txt.lambda.asc
./verify_with_lambda.sh   # → kmspgp-lambda-pub.asc + isolated ./gpg_temp_lambda
```

kmslambda numbered scripts `08`–`10` remain a gpg-free raw-ECDSA path and are not used here.

### 4. Same keyring, leftover kmspgp files (repo root, no AWS)

After stage 1 and the kmspgp flow(s), from the repository root:

```bash
./import-and-verify.sh
./import-lambda-and-verify.sh   # only if you ran stage 3
```

Both scripts: verify **must fail** (`NO_PUBKEY`) → `./import.sh` → verify **must succeed**. They reuse `./verify.sh` / `./import.sh` and the same `./keyring`. Different fingerprints, so the lambda verify still fails first even after the direct-KMS key is already in the ring.

| Script | Defaults |
| --- | --- |
| `./import-and-verify.sh` | `kmspgp/testartifact.txt.asc`, `kmspgp/testartifact.txt`, `kmspgp/kmspgp-pub.asc`, `./keyring` |
| `./import-lambda-and-verify.sh` | `kmspgp/testartifact.txt.lambda.asc`, `kmspgp/testartifact.txt`, `kmspgp/kmspgp-lambda-pub.asc`, `./keyring` |

No new verifier tooling. A KMS-made (or approval-gated) signature is a normal OpenPGP signature once its public key is in the ring.

## Day-to-day commands

These are the scripts a pipeline or developer would keep using.

**Sign with a local GnuPG home** (after stage 1, or any other isolated home with a secret key):

```bash
./sign.sh keys/signer1 /path/to/file
# writes /path/to/file.sig

./sign.sh keys/signer2 /path/to/file /path/to/file.signer2.sig
```

**Sign with KMS** (after `mvn clean install` in `kmspgp/`, with AWS credentials):

```bash
java -jar kmspgp/target/kmspgp.jar -bsau <key-id-or-alias> < artifact > artifact.asc
```

`-bsau` is the GnuPG combination “detach-sign, armor, local-user”. `kmspgp` accepts that shape so existing `gpg -bsau …` call sites can be pointed at the jar.

**Sign via kmslambda** (deployed stack; caller needs `lambda:InvokeFunction`, not `kms:Sign`):

```bash
export KMSPGP_LAMBDA_FUNCTION_NAME=...
export KMSPGP_LAMBDA_API_BASE_URL=...
java -jar kmspgp/target/kmspgp.jar lambda-sign --artifact NAME < artifact > artifact.asc
```

**Verify** (no AWS, no private keys):

```bash
./verify.sh /path/to/file.sig /path/to/file
# same as:
./verify.sh /path/to/file.sig /path/to/file ./keyring
```

Exit 0 on `GOODSIG`. Non-zero if the signature is bad or the key is missing (`NO_PUBKEY`).

**Import a public key** into the verification keyring (ASCII-armored `BEGIN PGP PUBLIC KEY BLOCK` only):

```bash
./import.sh /path/to/someone.pub.asc
./import.sh kmspgp/kmspgp-pub.asc ./keyring
```

Sets ownertrust to ultimate (`6`). Rejects private-key files.

List trusted public keys:

```bash
gpg --homedir keyring --list-keys --fingerprint
gpg --homedir keyring --list-secret-keys   # should be empty
```

## kmspgp

Small Java CLI in `kmspgp/`. Direct KMS (`export`, `-bsau`) or lambda-backed (`lambda-export`, `lambda-sign`). Only `ECC_NIST_P256` / `SIGN_VERIFY` keys.

### Goals

- Keep the verifier on stock GnuPG.
- Never export or hold the KMS private key.
- Stay small: hash locally, ask KMS (directly or via kmslambda) to sign the digest, wrap the result as OpenPGP.
- Be usable as a `gpg -bsau` stand-in for signing, plus `export` / `lambda-export` for keyring bootstrap.

### Usage

```bash
cd kmspgp
mvn clean install
java -jar target/kmspgp.jar export --user-name NAME --user-email EMAIL KEY
java -jar target/kmspgp.jar -bsau KEY < file > file.asc
java -jar target/kmspgp.jar lambda-export --user-name NAME --user-email EMAIL
java -jar target/kmspgp.jar lambda-sign [--artifact NAME] [--version VER] [--environment ENV] < file > file.asc
```

`KEY` is a KMS key id, ARN, or alias. User id on export is `NAME <EMAIL>` plus the KMS key description in parentheses when present.

The demo scripts in `kmspgp/` wrap this. Direct KMS: `export_test_key.sh`, `sign_with_test_key.sh` look up `alias/kmspgp-test-signing` (no Lambda). Lambda: `sign_with_lambda.sh`, `verify_with_lambda.sh` read kmslambda Terraform outputs.

### Design

| Piece | Behavior |
| --- | --- |
| `Main` | CLI: `export` / `-bsau` (direct KMS) or `lambda-export` / `lambda-sign`. Direct mode loads the key with `DescribeKey` + `GetPublicKey`. Rejects any spec other than `ECC_NIST_P256`. |
| `Pgp.export` | Builds an OpenPGP v4 ECDSA public key (secp256r1) from SPKI. Creation time is the KMS key creation date. Adds a user id and a generic certification (`0x10`). Key flags: certify + sign (`0x03`). |
| `Pgp.sign` | SHA-256 over stdin, then a binary document signature (`0x00`). Digest signing is pluggable (KMS or lambda-provided DER). |
| KMS sign | Direct: `MessageType.DIGEST`, `ECDSA_SHA_256` via `kms.sign`. Lambda: invoke `create`, poll until approved, use returned DER. |
| Armor | ASCII armor, version header `kmspgp`. |

Credentials: `DefaultCredentialsProvider` and `DefaultAwsRegionProviderChain` over the URL-connection HTTP client. SSO support is on the classpath (`sso`, `ssooidc`, `sts`).

IAM for production signing (no key admin): `kms:Sign`, `kms:DescribeKey`, `kms:GetPublicKey`. Export-only hosts need the last two. Lambda-backed signing: `lambda:InvokeFunction` only. Verifiers need none.

### Test-key scripts

| Script | Role |
| --- | --- |
| `create_test_key.sh` | Create `ECC_NIST_P256` `SIGN_VERIFY` key and `alias/kmspgp-test-signing`, or reuse it if already enabled |
| `export_test_key.sh` | `kmspgp export` → `kmspgp-pub.asc` (uid `Test <test@example.com>`) |
| `import_test_key.sh` | Import into `./gpg_temp` (cleared first; refuses `~/.gnupg`) |
| `sign_with_test_key.sh` | `kmspgp -bsau` on `testartifact.txt` → `testartifact.txt.asc` |
| `verify_with_test_key.sh` | `gpg --homedir gpg_temp --verify` |
| `delete_test_key.sh` | Delete alias, schedule key deletion |
| `test_key_common.sh` | Shared AWS / jar / isolation helpers |
| `sign_with_lambda.sh` | `kmspgp lambda-sign` via deployed kmslambda → `testartifact.txt.lambda.asc` |
| `verify_with_lambda.sh` | `lambda-export` → `kmspgp-lambda-pub.asc`; `gpg --homedir gpg_temp_lambda --verify` |

Override the isolated homedir with `GPG_TEMP_HOME` (direct KMS) or `GPG_TEMP_LAMBDA_HOME` (lambda). Override the jar with `KMSPGP_JAR`. Lambda wrappers look up URLs/ARNs from `../kmslambda` (`KMSLAMBDA_DIR` to override).

## Repository layout

| Path | Role | Git |
| --- | --- | --- |
| `sign.sh`, `verify.sh`, `import.sh` | Everyday GPG operations | Add |
| `sign-and-verify.sh` | Local GPG demo (resets key material) | Add |
| `import-and-verify.sh` | Import KMS pubkey into the existing keyring and re-verify | Add |
| `import-lambda-and-verify.sh` | Same, for leftover lambda OpenPGP files | Add |
| `gpg-common.sh` | Isolated GnuPG helpers | Add |
| `artifact.txt` | Fixture for the local GPG demo | Add |
| `keys/signerN/` | Demo GnuPG homes with **private** keys | Ignore |
| `keyring/` | Public-only verification keyring | Ignore (built by the demo) |
| `test-out/` | Signatures from `sign-and-verify.sh` | Ignore |
| `kmspgp/` | KMS signing CLI + its own demo scripts | Add (sources) |
| `kmspgp/gpg_temp/` | Isolated keyring for the kmspgp-only verify | Ignore |
| `kmspgp/gpg_temp_lambda/` | Isolated keyring for lambda verify | Ignore |
| `kmspgp/*.asc` | Exported pubkey and signatures | Ignore |
| `kmspgp/target/` | Maven build | Ignore |
| `kmslambda/` | Approval-gated signing service (Terraform + Lambda) | Add (sources) |

In production you would publish the verification keyring (or the trusted `.asc` files) to verifiers. This demo rebuilds `keyring/` locally and does not commit it.

## Script reference (root)

| Script | Role |
| --- | --- |
| `sign.sh <signer-home> <artifact> [output.sig]` | Detached armored signature with a local secret key |
| `verify.sh <signature> <artifact> [keyring-home]` | Verify against the public keyring |
| `import.sh <pubkey.asc> [keyring-home]` | Import a public key; set ownertrust |
| `sign-and-verify.sh [artifact]` | Reset keys/keyring, sign three ways, assert verify results |
| `import-and-verify.sh [sig] [artifact] [pubkey] [keyring]` | Fail-then-import-then-succeed against leftover direct-KMS files |
| `import-lambda-and-verify.sh [sig] [artifact] [pubkey] [keyring]` | Same against leftover kmspgp lambda files |
| `gpg-common.sh` | Shared helpers (sourced, not executed) |

`sign-and-verify.sh` identities: `Signer One <signer1@gpg-kms.local>` and signer 2 are in the keyring; `Signer Three` is not. Override directories with `KEYS_DIR`, `VERIFY_HOME`, `TEST_OUT`.

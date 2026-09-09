#!/usr/bin/env bash
# Shared helpers for isolated GnuPG homes. Sourced, not executed.

gpg_unattended() {
  local homedir="$1"
  shift
  gpg --homedir "$homedir" \
      --batch \
      --yes \
      --pinentry-mode loopback \
      --passphrase '' \
      "$@"
}

secret_key_fingerprint() {
  local homedir="$1"
  gpg --homedir "$homedir" --list-secret-keys --with-colons \
    | awk -F: '/^fpr:/{print $10; exit}'
}

public_key_fingerprint() {
  local homedir="$1"
  gpg --homedir "$homedir" --list-keys --with-colons \
    | awk -F: '/^fpr:/{print $10; exit}'
}

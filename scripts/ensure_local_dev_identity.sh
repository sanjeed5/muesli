#!/usr/bin/env bash
set -euo pipefail

# Ensures a generic local code-signing identity exists and prints its name.
# macOS TCC binds Accessibility / Input Monitoring / Microphone grants to that
# identity, so later rebuilds keep permissions instead of prompting again
# (ad-hoc cdhashes change every build).
#
# Override with LOCAL_DEV_SIGN_IDENTITY or MUESLI_LOCAL_DEV_IDENTITY.

# Prefer an already-granted personal identity when one exists. Rotating from
# "Sanjeed Local Dev" to a newly created "Muesli Local Dev" drops TCC.
DEFAULT_IDENTITY="Muesli Local Dev"
IDENTITY_NAME="${LOCAL_DEV_SIGN_IDENTITY:-${MUESLI_LOCAL_DEV_IDENTITY:-}}"
KEYCHAIN="${MUESLI_LOCAL_DEV_KEYCHAIN:-$HOME/Library/Keychains/login.keychain-db}"

if [[ -z "$IDENTITY_NAME" ]]; then
  if security find-identity -v -p codesigning | grep -Fq "Sanjeed Local Dev"; then
    IDENTITY_NAME="Sanjeed Local Dev"
  else
    IDENTITY_NAME="$DEFAULT_IDENTITY"
  fi
fi

if security find-identity -v -p codesigning | grep -Fq "$IDENTITY_NAME"; then
  printf '%s\n' "$IDENTITY_NAME"
  exit 0
fi

echo "Creating self-signed code-signing certificate '$IDENTITY_NAME'..." >&2

TMPDIR_CERT="$(mktemp -d)"
cleanup() { rm -rf "$TMPDIR_CERT"; }
trap cleanup EXIT

KEY="$TMPDIR_CERT/local-dev.key"
CRT="$TMPDIR_CERT/local-dev.crt"
P12="$TMPDIR_CERT/local-dev.p12"
PASS="local-dev-codesign"

openssl req -x509 -newkey rsa:2048 -keyout "$KEY" -out "$CRT" \
  -days 3650 -nodes -subj "/CN=$IDENTITY_NAME" \
  -addext "keyUsage=critical,digitalSignature" \
  -addext "extendedKeyUsage=codeSigning"

if ! openssl pkcs12 -export -out "$P12" -inkey "$KEY" -in "$CRT" \
  -passout "pass:$PASS" -legacy 2>/dev/null; then
  openssl pkcs12 -export -out "$P12" -inkey "$KEY" -in "$CRT" \
    -passout "pass:$PASS"
fi

security import "$P12" -k "$KEYCHAIN" -P "$PASS" \
  -T /usr/bin/codesign -T /usr/bin/security >/dev/null

if ! security find-identity -v -p codesigning | grep -Fq "$IDENTITY_NAME"; then
  echo "ERROR: failed to install '$IDENTITY_NAME' as a codesigning identity." >&2
  exit 1
fi

echo "Installed '$IDENTITY_NAME' for stable local TCC grants." >&2
printf '%s\n' "$IDENTITY_NAME"

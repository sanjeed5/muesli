#!/usr/bin/env bash
set -euo pipefail

# Ensures one personal local code-signing identity exists and prints its name.
# Reuse the same certificate across MuesliDev, VoiceInk, and other local apps so
# you are not managing a signer per project. macOS TCC still grants per bundle
# ID; the shared identity is what keeps those grants across rebuilds.
#
# Override with LOCAL_DEV_SIGN_IDENTITY or MUESLI_LOCAL_DEV_IDENTITY.

IDENTITY_NAME="${LOCAL_DEV_SIGN_IDENTITY:-${MUESLI_LOCAL_DEV_IDENTITY:-Sanjeed Local Dev}}"
KEYCHAIN="${MUESLI_LOCAL_DEV_KEYCHAIN:-$HOME/Library/Keychains/login.keychain-db}"

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

if ! security add-trusted-cert -d -r trustRoot -k "$KEYCHAIN" "$CRT" >/dev/null 2>&1; then
  echo "Warning: could not mark '$IDENTITY_NAME' as a trusted root. codesign still works; Gatekeeper may warn." >&2
fi

if ! security find-identity -v -p codesigning | grep -Fq "$IDENTITY_NAME"; then
  echo "ERROR: failed to install '$IDENTITY_NAME' as a codesigning identity." >&2
  exit 1
fi

echo "Installed '$IDENTITY_NAME' for stable local TCC grants." >&2
printf '%s\n' "$IDENTITY_NAME"

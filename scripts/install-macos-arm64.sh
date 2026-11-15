#!/bin/sh
# Install the verified, CI-built macOS ARM64 plugin binary.
# This script never reads or exports 1Password credentials.
set -eu

REPO="hohsiang-lab/agent-browser-plugin-1password-rs"
ARTIFACT="agent-browser-plugin-1password-aarch64-apple-darwin"
BINARY="agent-browser-plugin-1password"

if [ "$#" -ne 2 ]; then
  echo "Usage: sh scripts/install-macos-arm64.sh <workflow-run-id> <40-character-commit-sha>" >&2
  exit 2
fi
RUN_ID="$1"
EXPECTED_SHA="$2"
case "$RUN_ID" in
  ""|*[!0-9]*) echo "Invalid workflow run ID" >&2; exit 2 ;;
esac
case "$EXPECTED_SHA" in
  *[!0123456789abcdef]*|"") echo "Invalid lowercase commit SHA" >&2; exit 2 ;;
esac
if [ "${#EXPECTED_SHA}" -ne 40 ]; then
  echo "Expected a full 40-character commit SHA" >&2
  exit 2
fi

if [ "$(uname -s)" != "Darwin" ] || [ "$(uname -m)" != "arm64" ]; then
  echo "This installer requires macOS Apple Silicon" >&2
  exit 2
fi
if ! command -v gh >/dev/null 2>&1; then
  echo "GitHub CLI (gh) required; install with: brew install gh" >&2
  exit 2
fi
if ! gh auth status >/dev/null 2>&1; then
  echo "GitHub CLI is not authenticated; use gh auth login" >&2
  exit 2
fi

RUN_SHA="$(gh run view "$RUN_ID" --repo "$REPO" --json headSha --jq '.headSha')"
RESULT="$(gh run view "$RUN_ID" --repo "$REPO" --json conclusion --jq '.conclusion')"
if [ "$RUN_SHA" != "$EXPECTED_SHA" ] || [ "$RESULT" != "success" ]; then
  echo "Refusing to install: run SHA mismatch or workflow not successful" >&2
  exit 1
fi

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/ab-1password-ci.XXXXXXXX")"
trap 'rm -rf "$WORKDIR"' EXIT HUP INT TERM
gh run download "$RUN_ID" --repo "$REPO" --name "$ARTIFACT" --dir "$WORKDIR"
SOURCE="$WORKDIR/$BINARY"
if [ ! -s "$SOURCE" ] || ! file -b "$SOURCE" | grep -Eq 'Mach-O.*arm64'; then
  echo "Refusing to install: artifact is missing or is not an Apple Silicon executable" >&2
  exit 1
fi

DESTDIR="$HOME/.local/bin"
mkdir -p "$DESTDIR"
install -m 700 "$SOURCE" "$DESTDIR/$BINARY"

# Only the manifest is queried here: no op invocation, Vault read, or token.
MANIFEST="$(printf '%s\n' '{"protocol":"agent-browser.plugin.v1","type":"plugin.manifest","capability":"plugin.manifest","request":{}}' | "$DESTDIR/$BINARY")"
if ! printf '%s\n' "$MANIFEST" | grep -Fq '"credential.read"'; then
  echo "Plugin manifest verification failed" >&2
  exit 1
fi
printf 'Installed: %s\n' "$DESTDIR/$BINARY"
printf 'Verified source commit: %s\n' "$EXPECTED_SHA"
printf 'Plugin manifest: PASS\n'

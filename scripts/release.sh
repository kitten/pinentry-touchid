#!/usr/bin/env bash
# Developer ID-sign the flake's `unsigned` .app and publish it. Local signing,
# no CI/secrets.   nix run .#release -- X.Y.Z   (DRYRUN=1 to skip publishing)
#
# No hardened runtime: the cgo binary links nix-store dylibs that library
# validation would reject. The profile is embedded, so it must stay a bundle.
# No notarization: nix fetches into /nix/store unquarantined.
set -euo pipefail

VERSION="${1:?usage: nix run .#release -- X.Y.Z}"
REPO="kitten/pinentry-touchid"
# Resolve the repo from the CWD (this script may run from the nix store).
ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
ENT="$ROOT/assets/entitlements.plist"
APP="$ROOT/dist/pinentry-touchid.app"

# Log out on exit only if THIS run logged gh in — leave a pre-existing session.
LOGGED_IN_THIS_RUN=0
cleanup() {
  if [ "$LOGGED_IN_THIS_RUN" = 1 ]; then
    echo "Logging out the gh session this run created…" >&2
    gh auth logout --hostname github.com >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

ID_LINE=$(security find-identity -v -p codesigning | grep "Developer ID Application" | head -1) \
  || { echo "No 'Developer ID Application' identity in keychain." >&2; exit 1; }
ID_HASH=$(awk '{print $2}' <<<"$ID_LINE")
TEAM=$(grep -oE '\([A-Z0-9]{10}\)' <<<"$ID_LINE" | tr -d '()')
grep -q "${TEAM}\." "$ENT" \
  || { echo "entitlements.plist groups must be prefixed with signing team $TEAM" >&2; exit 1; }

# Publishing needs an authenticated gh (skipped for DRYRUN); log in if needed.
if [ -z "${DRYRUN:-}" ] && ! gh auth status >/dev/null 2>&1; then
  echo "GitHub CLI not authenticated — launching 'gh auth login'…" >&2
  gh auth login --skip-ssh-key -p ssh --hostname github.com
  gh auth status >/dev/null 2>&1 \
    || { echo "Still not authenticated; aborting." >&2; exit 1; }
  LOGGED_IN_THIS_RUN=1
fi

echo "preflight ok: signing as team $TEAM${DRYRUN:+ (DRYRUN)}"

# Build the unsigned .app reproducibly via the flake.
nix build "$ROOT#unsigned" -o "$ROOT/dist/result"

rm -rf "$APP"; mkdir -p "$ROOT/dist"
cp -R "$ROOT/dist/result/Applications/pinentry-touchid.app" "$APP"
chmod -R u+w "$APP"

# Developer ID sign (NOT hardened runtime — see header).
codesign --force --timestamp --entitlements "$ENT" -s "$ID_HASH" "$APP"
codesign -vv --strict "$APP"

( cd "$ROOT/dist" && zip -qry pinentry-touchid-macos.zip pinentry-touchid.app )

if [ -n "${DRYRUN:-}" ]; then
  echo "DRYRUN: signed bundle at $APP (not published)"
  exit 0
fi

gh release create "v$VERSION" "$ROOT/dist/pinentry-touchid-macos.zip" \
  --repo "$REPO" --title "v$VERSION" --generate-notes

echo "── sha256 (SRI) for flake.nix ──"
nix store prefetch-file --json \
  "https://github.com/$REPO/releases/download/v$VERSION/pinentry-touchid-macos.zip" \
  | jq -r .hash

#!/usr/bin/env bash
# Builds the macOS installer of Hirzla (ADR 0065; docs/livraison.md § 3): a `.pkg` that
# installs Hirzla.app into /Applications and the client manifest into
# /Library/Application Support/Hirzla/, both owned by root, where a macOS delivery build of
# the core reads it (crates/hirzla-core/src/codesign.rs, MACOS_MANIFEST_PATH).
#
# Usage:
#   .github/scripts/macos-pkg.sh APP MANIFEST VERSION [OUTPUT]
#
#   APP       Hirzla.app, already in its final signed state (ad hoc `codesign -s - -o runtime`
#             or Developer ID): nothing in it is changed here.
#   MANIFEST  hirzla-clients.manifest for this macOS platform, signed by the publisher key
#             (`hirzla-signer manifeste-clients`), made from the executables of APP as they
#             are in the signed bundle (APP/Contents/MacOS/*).
#   VERSION   X.Y.Z, the version of the release.
#   OUTPUT    the .pkg to write; default ./Hirzla_<VERSION>_<arch>.pkg (arch: aarch64, x64
#             or universal, read from hirzla-desktop).
#
# Environment (all optional):
#   HIRZLA_PKG_IDENTIFIER     base package identifier, default app.hirzla.desktop
#                             (components <id>.app and <id>.manifest).
#   HIRZLA_PKG_SIGN_IDENTITY  "Developer ID Installer: …" to sign the product with
#                             `productbuild --sign` (paid Apple account, ADR 0063 § 5).
#                             Absent: the .pkg is not signed and Gatekeeper warns once.
#   HIRZLA_PKG_KEYCHAIN       keychain holding that identity.
#
# Runs on macOS only (pkgbuild, productbuild, pkgutil, lsbom, codesign, lipo, shasum: tools
# of the system and of the Xcode command line tools). Reaches no network, holds no secret:
# APP and MANIFEST are public, signed data. Before building, it checks that APP's signature
# is intact, that MANIFEST is a client manifest and that it names the SHA-384 of every
# executable of APP (a consistency check only: the core and its clients verify the manifest
# signature themselves, and refuse to start on any mismatch). After building, it checks the
# owner and the mode of the manifest in the package.
set -euo pipefail

die() {
  echo "macos-pkg.sh: $*" >&2
  exit 1
}

[ "$#" -ge 3 ] && [ "$#" -le 4 ] || die "usage: macos-pkg.sh APP MANIFEST VERSION [OUTPUT]"
[ "$(uname -s)" = "Darwin" ] || die "macOS only."
for tool in pkgbuild productbuild pkgutil lsbom codesign lipo shasum xxd plutil ditto; do
  command -v "$tool" >/dev/null 2>&1 || die "missing tool: $tool"
done

app="${1%/}"
manifest="$2"
version="$3"
identifier="${HIRZLA_PKG_IDENTIFIER:-app.hirzla.desktop}"
manifest_name="hirzla-clients.manifest"
manifest_dir="/Library/Application Support/Hirzla"

[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "VERSION must be X.Y.Z."
[[ "$identifier" =~ ^[A-Za-z0-9.-]+$ ]] || die "invalid HIRZLA_PKG_IDENTIFIER."
[ -d "$app" ] && [[ "$app" == *.app ]] || die "APP must be an .app bundle."
macos="$app/Contents/MacOS"
[ -f "$macos/hirzla-desktop" ] && [ -f "$macos/hirzla-core" ] \
  || die "APP must hold Contents/MacOS/hirzla-desktop and hirzla-core."
[ -f "$manifest" ] && [ ! -L "$manifest" ] || die "MANIFEST must be a regular file."

# The bundle as signed: any change since the signature, the manifest's hashes would miss.
codesign --verify --strict --deep "$app" || die "APP's signature does not verify."

# A client manifest: "HIRZLA" ‖ 'C' ‖ format 01, of a macOS platform.
[ "$(head -c 8 "$manifest" | xxd -p)" = "4849525a4c414301" ] \
  || die "MANIFEST is not a client manifest."
size=$(wc -c <"$manifest" | tr -d ' ')
[ "$size" -le 80000 ] || die "MANIFEST is too large."
LC_ALL=C grep -aq "macos-" "$manifest" || die "MANIFEST is not for macOS."

# Every executable of the bundle is named by the manifest with its SHA-384 (the raw 48
# bytes of the hash appear in the manifest's CBOR), and nothing else lies in Contents/MacOS.
manifest_hex=$(xxd -p "$manifest" | tr -d '\n')
for exe in "$macos"/*; do
  name=$(basename "$exe")
  case "$name" in
    hirzla | hirzla-core | hirzla-desktop | hirzla-native-host) ;;
    *) die "unexpected file in Contents/MacOS: $name" ;;
  esac
  [ -f "$exe" ] && [ ! -L "$exe" ] || die "$name is not a regular file."
  hash=$(shasum -a 384 "$exe" | cut -d ' ' -f 1)
  case "$manifest_hex" in
    *"$hash"*) ;;
    *) die "MANIFEST does not hold the hash of $name as signed in APP." ;;
  esac
done

case "$(lipo -archs "$macos/hirzla-desktop")" in
  arm64) arch=aarch64 ;;
  x86_64) arch=x64 ;;
  *) arch=universal ;;
esac
output="${4:-$PWD/Hirzla_${version}_${arch}.pkg}"
[ ! -e "$output" ] || die "OUTPUT already exists: $output"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/app-root" "$work/manifest-root" "$work/pkgs"

# Component 1: the bundle, copied with its signatures and attributes, into /Applications,
# never relocated to another copy of Hirzla.app found on the disk, always written (no
# version check) so that it stays in step with the manifest.
ditto "$app" "$work/app-root/$(basename "$app")"
pkgbuild --analyze --root "$work/app-root" "$work/app.plist" >/dev/null
i=0
while plutil -extract "$i" xml1 -o /dev/null "$work/app.plist" 2>/dev/null; do
  plutil -replace "$i.BundleIsRelocatable" -bool NO "$work/app.plist"
  plutil -replace "$i.BundleIsVersionChecked" -bool NO "$work/app.plist"
  plutil -replace "$i.BundleOverwriteAction" -string upgrade "$work/app.plist"
  i=$((i + 1))
done
[ "$i" -ge 1 ] || die "pkgbuild found no bundle in APP."
pkgbuild --root "$work/app-root" --component-plist "$work/app.plist" \
  --identifier "$identifier.app" --version "$version" --ownership recommended \
  --install-location /Applications "$work/pkgs/hirzla-app.pkg"

# Component 2: the manifest, root:wheel 0644, in a directory root:wheel 0755.
cp "$manifest" "$work/manifest-root/$manifest_name"
chmod 0644 "$work/manifest-root/$manifest_name"
chmod 0755 "$work/manifest-root"
pkgbuild --root "$work/manifest-root" \
  --identifier "$identifier.manifest" --version "$version" --ownership recommended \
  --install-location "$manifest_dir" "$work/pkgs/hirzla-manifest.pkg"

# The product: both components, installed on the system volume only (never in a user's
# home, where the core would refuse the manifest).
productbuild --synthesize \
  --package "$work/pkgs/hirzla-app.pkg" --package "$work/pkgs/hirzla-manifest.pkg" \
  "$work/synth.xml"
awk '
  /<\/installer-gui-script>/ {
    print "    <title>Hirzla</title>"
    print "    <domains enable_anywhere=\"false\" enable_currentUserHome=\"false\" enable_localSystem=\"true\"/>"
  }
  { print }
' "$work/synth.xml" >"$work/distribution.xml"

sign=()
if [ -n "${HIRZLA_PKG_SIGN_IDENTITY:-}" ]; then
  sign=(--sign "$HIRZLA_PKG_SIGN_IDENTITY")
  if [ -n "${HIRZLA_PKG_KEYCHAIN:-}" ]; then
    sign+=(--keychain "$HIRZLA_PKG_KEYCHAIN")
  fi
fi
productbuild --distribution "$work/distribution.xml" --package-path "$work/pkgs" \
  ${sign[@]+"${sign[@]}"} "$output"

# What the package will install: the manifest and its directory owned by root (uid 0;
# group wheel or admin, never writable by it) and writable by root only.
pkgutil --expand "$output" "$work/expanded"
bom=$(lsbom -p fmug "$work/expanded/hirzla-manifest.pkg/Bom")
echo "$bom" | grep -Eq "^\./hirzla-clients\.manifest[[:space:]]+10*644[[:space:]]+0[[:space:]]+[0-9]+\$" \
  || die "the manifest in the package is not owned by root with mode 0644."
echo "$bom" | grep -Eq "^\.[[:space:]]+40*755[[:space:]]+0[[:space:]]+[0-9]+\$" \
  || die "the manifest directory in the package is not owned by root with mode 0755."

if [ "${#sign[@]}" -gt 0 ]; then
  pkgutil --check-signature "$output"
else
  echo "macos-pkg.sh: package not signed (no HIRZLA_PKG_SIGN_IDENTITY)." >&2
fi
shasum -a 256 "$output"

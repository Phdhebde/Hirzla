#!/bin/sh
# Signs the client manifests of a release by hand, on an offline signing station: fallback
# of ADR 0073. The Livraison workflow now signs the manifests itself in its "manifests" job,
# with the same commands, and does not consume manifests signed by this script: building
# installers from them is then manual (docs/livraison.md § 2). Kept for that case, e.g. when
# the CI secret has been revoked, and as the reference of the commands.
#
# Expects, next to this script, a folder assembled from the artifacts executables-<platform>
# of a Livraison run (executables-windows-x86_64-signes when SignPath signed them):
#   VERSION                 the version to sign (X.Y.Z)
#   ESSAI                   present only in a dry run of the flow (tag vX.Y.Z-essai.N)
#   SHA256SUMS              SHA-256 of the transferred files (the <platform>.sha256 files of
#                           the artifacts, concatenated), to check the transfer
#   linux-x86_64/ windows-x86_64/   the executables of each platform
#   macos-aarch64/Hirzla.app.zip    the signed macOS application, whole (ADR 0065): its
#                           manifest names the executables of Hirzla.app/Contents/MacOS as
#                           they are in the signed bundle
#
# Usage, from the artifact folder, network unplugged:
#   sh signer-manifestes.sh /media/usb/editeur.cle /media/usb/editeur.pub
# The hirzla-signer executable is taken from HIRZLA_SIGNER, or from the PATH.
#
# Writes hirzla-clients-<platform>.manifest for each platform folder present, then verifies
# each one against the public key and the executables. Never overwrites a file. The private
# key is only read by hirzla-signer; nothing else is written next to it. The macOS bundle is
# unzipped into macos-aarch64/app (ditto, unzip or Python, whichever is present).
set -eu

if [ "$#" -ne 2 ]; then
  echo "Usage : sh signer-manifestes.sh CLE_PRIVEE CLE_PUBLIQUE" >&2
  exit 2
fi
key="$1"
pub="$2"
signer="${HIRZLA_SIGNER:-hirzla-signer}"

cd "$(dirname "$0")"
version="$(cat VERSION)"
case "$version" in
  *[!0-9.]* | "") echo "VERSION illisible." >&2; exit 1 ;;
esac

# Dry run of the release flow (tag vX.Y.Z-essai.N): the executables carry the test keys.
if [ -e ESSAI ]; then
  cat ESSAI
  echo "Clé utilisée : $key. Ce doit être la clé d'éditeur JETABLE de l'essai."
  echo
fi

# unzip_app ZIP DEST: extracts the zipped bundle into DEST, which must not exist.
unzip_app() {
  if [ -e "$2" ]; then
    echo "$2 existe déjà : supprimez-le ou travaillez dans une copie propre." >&2
    exit 1
  fi
  mkdir "$2"
  if command -v ditto > /dev/null 2>&1; then
    ditto -x -k "$1" "$2"
  elif command -v unzip > /dev/null 2>&1; then
    unzip -q "$1" -d "$2"
  elif command -v python3 > /dev/null 2>&1; then
    python3 -I -m zipfile -e "$1" "$2"
  else
    echo "Ni ditto, ni unzip, ni python3 : impossible d'ouvrir $1." >&2
    exit 1
  fi
}

echo "1. Contrôle du transfert (SHA256SUMS)"
sha256sum -c SHA256SUMS

signed=0
for platform in linux-x86_64 windows-x86_64 macos-aarch64; do
  [ -d "$platform" ] || continue
  ext=""
  case "$platform" in windows-*) ext=".exe" ;; esac
  exe="$platform"
  if [ -f "$platform/Hirzla.app.zip" ]; then
    # macOS (ADR 0065): the executables as signed inside the bundle, and nothing else.
    unzip_app "$platform/Hirzla.app.zip" "$platform/app"
    exe="$platform/app/Hirzla.app/Contents/MacOS"
    for f in "$exe"/* "$exe"/.[!.]*; do
      [ -e "$f" ] || continue
      case "$(basename "$f")" in
        hirzla | hirzla-core | hirzla-desktop | hirzla-native-host) ;;
        *) echo "Fichier inattendu dans Contents/MacOS : $(basename "$f")" >&2; exit 1 ;;
      esac
    done
  fi
  out="hirzla-clients-$platform.manifest"
  if [ -e "$out" ]; then
    echo "$out existe déjà : supprimez-le ou travaillez dans une copie propre." >&2
    exit 1
  fi
  echo "2. Manifeste des clients $version pour $platform"
  "$signer" manifeste-clients --cle "$key" --version "$version" --plateforme "$platform" \
    --sortie "$out" \
    "$exe/hirzla$ext" "$exe/hirzla-core$ext" \
    "$exe/hirzla-desktop$ext" "$exe/hirzla-native-host$ext"
  echo "3. Vérification de $out"
  "$signer" verifier --publique "$pub" --version "$version" --plateforme "$platform" \
    --executables "$exe" "$out"
  signed=$((signed + 1))
done

if [ "$signed" -eq 0 ]; then
  echo "Aucun dossier de plateforme trouvé." >&2
  exit 1
fi
echo
echo "$signed manifeste(s) signé(s) : hirzla-clients-*.manifest. Construisez les installeurs"
echo "à partir de ces exécutables inchangés (docs/livraison.md, § 2)."

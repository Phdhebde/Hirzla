#!/bin/sh
# Signs the client manifests of a release on the publisher's offline signing station
# (ADR 0064, docs/guide-signature.md step 7). Copied by the first stage of the Livraison
# workflow into the "hirzla-X.Y.Z-a-signer" artifact, next to:
#   VERSION                 the version to sign (X.Y.Z)
#   SHA256SUMS              SHA-256 of the executables, to check the transfer
#   linux-x86_64/ windows-x86_64/ macos-aarch64/   the executables of each platform
#
# Usage, from the artifact folder, network unplugged:
#   sh signer-manifestes.sh /media/usb/editeur.cle /media/usb/editeur.pub
# The hirzla-signer executable is taken from HIRZLA_SIGNER, or from the PATH.
#
# Writes hirzla-clients-<platform>.manifest for each platform folder present, then verifies
# each one against the public key and the executables. Never overwrites a file. The private
# key is only read by hirzla-signer; nothing else is written next to it.
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

echo "1. Contrôle du transfert (SHA256SUMS)"
sha256sum -c SHA256SUMS

signed=0
for platform in linux-x86_64 windows-x86_64 macos-aarch64; do
  [ -d "$platform" ] || continue
  ext=""
  case "$platform" in windows-*) ext=".exe" ;; esac
  out="hirzla-clients-$platform.manifest"
  if [ -e "$out" ]; then
    echo "$out existe déjà : supprimez-le ou travaillez dans une copie propre." >&2
    exit 1
  fi
  echo "2. Manifeste des clients $version pour $platform"
  "$signer" manifeste-clients --cle "$key" --version "$version" --plateforme "$platform" \
    --sortie "$out" \
    "$platform/hirzla$ext" "$platform/hirzla-core$ext" \
    "$platform/hirzla-desktop$ext" "$platform/hirzla-native-host$ext"
  echo "3. Vérification de $out"
  "$signer" verifier --publique "$pub" --version "$version" --plateforme "$platform" \
    --executables "$platform" "$out"
  signed=$((signed + 1))
done

if [ "$signed" -eq 0 ]; then
  echo "Aucun dossier de plateforme trouvé." >&2
  exit 1
fi
echo
echo "$signed manifeste(s) signé(s). Joignez les fichiers hirzla-clients-*.manifest au"
echo "brouillon de la version sur GitHub, puis lancez la seconde étape du flux Livraison."

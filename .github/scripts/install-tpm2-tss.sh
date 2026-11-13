#!/usr/bin/env bash
# Builds and installs tpm2-tss from its release tarball, pinned by SHA-256 (ADR 0014).
# Distributions may ship older versions (Ubuntu 24.04: 4.0.1); tss-esapi-sys 0.6 is generated
# from 4.1.3, and 4.1.6 fixes GHSA-89w7-5q38-fgm3 in ESYS parameter decryption.
#
# Tarball signed by key DF46 9492 95D2 AA0F 3479 BF4A 965B 305B 2BFA B54E (Moritz Buhl,
# tpm2-tss maintainer, key published on his GitHub account), checked on 2026-11-13 before
# pinning the digest below.
#
# Usage: sudo -E .github/scripts/install-tpm2-tss.sh   (needs build-essential, pkg-config,
# libssl-dev). Installs under /usr/local; FAPI and the policy library are not built.
set -euo pipefail

VERSION=4.1.6
SHA256=014b147c8f9659f18c195c3ca7ad164323e8f72a51a337b1a42dbf4e95b1896b
MINIMUM=4.1.3

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cd "$work"
curl -fsSLO "https://github.com/tpm2-software/tpm2-tss/releases/download/${VERSION}/tpm2-tss-${VERSION}.tar.gz"
echo "${SHA256}  tpm2-tss-${VERSION}.tar.gz" | sha256sum --check --strict
tar xzf "tpm2-tss-${VERSION}.tar.gz"
cd "tpm2-tss-${VERSION}"
./configure --prefix=/usr/local --disable-fapi --disable-policy --disable-doxygen-doc \
  --with-crypto=ossl >/dev/null
make -j"$(nproc)" >/dev/null
make install >/dev/null
ldconfig

export PKG_CONFIG_PATH="/usr/local/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
for lib in tss2-esys tss2-sys tss2-mu tss2-tctildr; do
  pkg-config --atleast-version="$MINIMUM" "$lib" \
    || { echo "$lib: $(pkg-config --modversion "$lib") < $MINIMUM" >&2; exit 1; }
done
echo "tpm2-tss $(pkg-config --modversion tss2-esys) installed under /usr/local"

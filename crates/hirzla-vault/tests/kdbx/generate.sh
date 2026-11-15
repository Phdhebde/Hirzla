#!/bin/sh
# Régénère les bases de référence KDBX de l'import (ADR 0025). Mot de passe : « hirzla-test ».
#
# Deux implémentations indépendantes de celle de Hirzla :
# - pykeepass 4.2.0 (generate.py) écrit les bases « pykeepass-* » et deux bases vides ;
# - KeePassXC 2.7.6 importe source.xml (il écrit alors du KDBX 3.1 avec AES-KDF, gardé comme
#   base refusée), puis fusionne ce contenu dans les bases vides, qu'il réécrit en KDBX 4 en
#   gardant leur chiffrement et leur dérivation.
#
# Prérequis : python3 avec pykeepass==4.2.0, keepassxc-cli 2.7.6.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
python=${PYTHON:-python3}
"$python" -I "$here/generate.py" "$here"
rm -f "$here/keepassxc-kdbx3-aeskdf.kdbx"
printf 'hirzla-test\nhirzla-test\n' |
    keepassxc-cli import -q -p -t 100 "$here/source.xml" "$here/keepassxc-kdbx3-aeskdf.kdbx"
for target in keepassxc-aes-argon2d keepassxc-chacha20-argon2id; do
    printf 'hirzla-test\nhirzla-test\n' |
        keepassxc-cli merge -q -s "$here/$target.kdbx" "$here/keepassxc-kdbx3-aeskdf.kdbx"
done

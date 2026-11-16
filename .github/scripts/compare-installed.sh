#!/usr/bin/env bash
# Checks that an extracted installer holds, in one directory, the executables built by the
# first stage of the Livraison workflow byte for byte, and the client manifest signed for
# them (ADR 0064): a packaging tool that strips, patches or signs an executable would make
# the core refuse to start, so such an installer is never published.
#
# Usage: compare-installed.sh LABEL EXPECTED_DIR INSTALLED_DIR EXE_SUFFIX [LEVEL]
#   EXPECTED_DIR   the stage-1 executables and hirzla-clients.manifest
#   INSTALLED_DIR  the directory of the extracted installer that holds hirzla-core
#   EXE_SUFFIX     ".exe" on Windows, "" elsewhere
#   LEVEL          annotation level of a mismatch: error (default) or warning; the exit
#                  status is non-zero either way
set -euo pipefail

label="$1"
expected="$2"
installed="$3"
ext="$4"
level="${5:-error}"

status=0
for name in "hirzla$ext" "hirzla-core$ext" "hirzla-desktop$ext" "hirzla-native-host$ext" \
  hirzla-clients.manifest; do
  if [ ! -f "$installed/$name" ]; then
    echo "::$level::$label: $name is missing from the installed directory"
    status=1
  elif ! cmp -s "$expected/$name" "$installed/$name"; then
    echo "::$level::$label: $name differs from the signed stage-1 file"
    status=1
  else
    echo "$label: $name identical"
  fi
done
exit "$status"

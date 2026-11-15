#!/usr/bin/env bash
# Reproducible build check (ADR 0056): builds the shipped Linux executables twice, from two
# copies of the same commit in two different directories, with two different target
# directories, and compares them byte for byte. Any difference fails.
#
# What makes the build reproducible (also applied by docs/livraison.md):
# - SOURCE_DATE_EPOCH, the commit time, for any tool that stamps a date;
# - --remap-path-prefix for the source tree, the target directory, Cargo's home and rustup's
#   home, so that no absolute path of the build machine reaches the binaries (panic
#   locations, debug sections);
# - -ffile-prefix-map, the same for the C code of AWS-LC and SQLite built by cc and CMake;
# - Cargo.lock (--locked), the toolchain of rust-toolchain.toml, release profile with one
#   codegen unit and LTO (Cargo.toml).
#
# Usage: .github/scripts/reproducible-build.sh [WORK_DIR]
# Needs the crates of Cargo.lock already fetched (`cargo fetch --locked`): nothing is
# downloaded during the builds (--offline). Prints the SHA-256 of each executable.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
work="${1:-$(mktemp -d)}"
mkdir -p "$work"
cargo_home="${CARGO_HOME:-$HOME/.cargo}"
rustup_home="${RUSTUP_HOME:-$HOME/.rustup}"
packages=(-p hirzla-core -p hirzla-cli -p hirzla-server)
bins=(hirzla-core hirzla hirzlad)

SOURCE_DATE_EPOCH="$(git -C "$root" log -1 --format=%ct)"
export SOURCE_DATE_EPOCH
commit="$(git -C "$root" rev-parse HEAD)"

for n in 1 2; do
  src="$work/build-$n/src"
  target="$work/build-$n/target"
  rm -rf "$work/build-$n"
  mkdir -p "$src" "$target"
  # The committed tree only: no local file, no build product.
  git -C "$root" archive --format=tar "$commit" | tar -x -C "$src"
  maps="--remap-path-prefix=$src=/hirzla --remap-path-prefix=$target=/target"
  maps="$maps --remap-path-prefix=$cargo_home=/cargo --remap-path-prefix=$rustup_home=/rustup"
  cmaps="-ffile-prefix-map=$src=/hirzla -ffile-prefix-map=$target=/target"
  cmaps="$cmaps -ffile-prefix-map=$cargo_home=/cargo"
  (
    cd "$src"
    RUSTFLAGS="$maps" CFLAGS="$cmaps" CXXFLAGS="$cmaps" CARGO_TARGET_DIR="$target" \
      CARGO_INCREMENTAL=0 \
      cargo build --release --locked --offline "${packages[@]}"
  )
done

status=0
for b in "${bins[@]}"; do
  one="$work/build-1/target/release/$b"
  two="$work/build-2/target/release/$b"
  h1="$(sha256sum "$one" | cut -d' ' -f1)"
  h2="$(sha256sum "$two" | cut -d' ' -f1)"
  if [ "$h1" = "$h2" ]; then
    echo "identique  $h1  $b"
  else
    echo "DIFFÉRENT  $h1 / $h2  $b"
    status=1
  fi
done
exit $status

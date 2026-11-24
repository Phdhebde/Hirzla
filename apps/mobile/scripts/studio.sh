#!/bin/sh
# Opens the Android project of Hirzla (ADR 0080) in Android Studio with the environment the
# Rust builds need: a Studio started from the Dock sees neither cargo nor the NDK.
# Paths: the SDK and NDK of Homebrew's android-commandlinetools; override them if needed.
set -eu
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
: "${ANDROID_HOME:=/opt/homebrew/share/android-commandlinetools}"
: "${NDK_HOME:=$ANDROID_HOME/ndk/27.1.12297006}"
export ANDROID_HOME NDK_HOME ANDROID_NDK_HOME="$NDK_HOME"
export PATH="$HOME/.cargo/bin:$ANDROID_HOME/cmake/3.22.1/bin:$ANDROID_HOME/platform-tools:/opt/homebrew/bin:$PATH"
PROJECT="$ROOT/apps/mobile/src-tauri/gen/android"
# local.properties (not versioned): where Gradle finds the SDK and the NDK.
printf 'sdk.dir=%s\nndk.dir=%s\n' "$ANDROID_HOME" "$NDK_HOME" > "$PROJECT/local.properties"
exec "/Applications/Android Studio.app/Contents/MacOS/studio" "$PROJECT"

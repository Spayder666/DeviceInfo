#!/usr/bin/env bash
set -euo pipefail
NDK="${ANDROID_HOME:-$HOME/android-sdk}/ndk/27.2.12479018"
CLANG="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android33-clang"
OUT="$(cd "$(dirname "$0")/../.." && pwd)/app/src/main/assets/frida/arm64-v8a/libamhooks.so"
mkdir -p "$(dirname "$OUT")"
"$CLANG" -shared -fPIC -O2 -Wl,-soname,libamhooks.so \
  -o "$OUT" "$(dirname "$0")/amhooks.c" -llog -ldl
echo "wrote $OUT"

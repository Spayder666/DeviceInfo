#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NDK="${ANDROID_NDK_HOME:-${ANDROID_HOME:-$HOME/android-sdk}/ndk/27.2.12479018}"
PREBUILT="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin"
OUT="$ROOT/app/src/main/assets/zygisk"
mkdir -p "$OUT"

build_one() {
  local triple="$1"
  local soname="$2"
  local cxx="$PREBUILT/${triple}33-clang++"
  echo "Building $soname"
  "$cxx" -shared -fPIC -std=c++20 -O2 -fvisibility=hidden \
    -fno-exceptions -fno-rtti \
    -I "$ROOT/zygisk" \
    "$ROOT/zygisk/zygisk.cpp" \
    -llog -ldl \
    -static-libstdc++ \
    -Wl,-z,max-page-size=16384 \
    -o "$OUT/$soname"
  "$PREBUILT/llvm-strip" "$OUT/$soname" || true
  "$PREBUILT/llvm-nm" -D "$OUT/$soname" | grep -E 'zygisk_module_entry|zygisk_companion_entry'
}

build_one aarch64-linux-android arm64-v8a.so
build_one armv7a-linux-androideabi armeabi-v7a.so
ls -l "$OUT"

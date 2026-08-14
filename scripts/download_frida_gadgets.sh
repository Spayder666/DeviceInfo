#!/usr/bin/env bash
set -euo pipefail
VERSION="16.5.9"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ASSETS="$ROOT/app/src/main/assets/frida"

mkdir -p "$ASSETS/arm64-v8a" "$ASSETS/armeabi-v7a" "$ASSETS/x86_64"

download_one() {
  local abi="$1"
  local folder="$2"
  local dest="$ASSETS/$folder/libfrida-gadget.so"
  if [[ -f "$dest" && -s "$dest" ]]; then
    echo "skip $folder (exists)"
    return 0
  fi
  echo "download $abi -> $folder"
  curl -sL "https://github.com/frida/frida/releases/download/${VERSION}/frida-gadget-${VERSION}-android-${abi}.so.xz" \
    | xz -dc > "$dest"
}

download_one arm64 arm64-v8a
download_one arm armeabi-v7a
download_one x86_64 x86_64

echo "Frida gadgets ready"

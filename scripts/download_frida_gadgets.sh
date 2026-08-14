#!/usr/bin/env bash
set -euo pipefail
VERSION="16.5.9"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ASSETS="$ROOT/app/src/main/assets/frida"

mkdir -p "$ASSETS/arm64-v8a"

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

# arm64 покрывает большинство устройств Android 13+; остальные ABI — через downloadGadget()
download_one arm64 arm64-v8a

download_inject() {
  local dest="$ASSETS/arm64-v8a/frida-inject"
  if [[ -f "$dest" && -s "$dest" ]]; then
    echo "skip frida-inject (exists)"
    return 0
  fi
  echo "download frida-inject arm64"
  curl -sL "https://github.com/frida/frida/releases/download/${VERSION}/frida-inject-${VERSION}-android-arm64.xz" \
    | xz -dc > "$dest"
  chmod +x "$dest"
}

download_inject

echo "Frida gadget + inject (arm64) ready"

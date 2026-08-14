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

echo "Frida gadget (arm64) ready"

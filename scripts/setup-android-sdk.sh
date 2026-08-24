#!/usr/bin/env bash
# Idempotent local Android SDK bootstrap for Access Monitor.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ANDROID_SDK_ROOT="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-$HOME/android-sdk}}"
export ANDROID_SDK_ROOT
export ANDROID_HOME="$ANDROID_SDK_ROOT"

need_cmd() {
  command -v "$1" >/dev/null 2>&1
}

install_apt_if_missing() {
  local pkgs=()
  for pkg in "$@"; do
    local bin="$pkg"
    case "$pkg" in
      xz-utils) bin="xz" ;;
    esac
    if ! need_cmd "$bin"; then
      pkgs+=("$pkg")
    fi
  done
  if ((${#pkgs[@]})); then
    sudo apt-get update -qq
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "${pkgs[@]}"
  fi
}

install_apt_if_missing curl unzip xz-utils

mkdir -p "$ANDROID_SDK_ROOT"

if [[ ! -x "$ANDROID_SDK_ROOT/cmdline-tools/latest/bin/sdkmanager" ]]; then
  echo "Installing Android command-line tools into $ANDROID_SDK_ROOT"
  tmp="$(mktemp -d)"
  curl -fsSL -o "$tmp/cmdtools.zip" \
    "https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip"
  unzip -q "$tmp/cmdtools.zip" -d "$tmp"
  rm -rf "$ANDROID_SDK_ROOT/cmdline-tools/latest"
  mkdir -p "$ANDROID_SDK_ROOT/cmdline-tools"
  mv "$tmp/cmdline-tools" "$ANDROID_SDK_ROOT/cmdline-tools/latest"
  rm -rf "$tmp"
fi

SDKMANAGER="$ANDROID_SDK_ROOT/cmdline-tools/latest/bin/sdkmanager"

yes | "$SDKMANAGER" --sdk_root="$ANDROID_SDK_ROOT" --licenses >/dev/null || true

"$SDKMANAGER" --sdk_root="$ANDROID_SDK_ROOT" \
  "platform-tools" \
  "platforms;android-35" \
  "build-tools;35.0.0"

printf 'sdk.dir=%s\n' "$ANDROID_SDK_ROOT" > "$ROOT/local.properties"
echo "Android SDK ready at $ANDROID_SDK_ROOT"
echo "Wrote $ROOT/local.properties"

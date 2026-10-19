#!/usr/bin/env bash
# Sourced by the P0 lab scripts. No grants, sudo, or firewall changes.
set -euo pipefail
umask 077
P0_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ORC_SOURCE="${ORC_SOURCE:-$(cd "$P0_DIR/../.." && pwd)}"
export PATH="$HOME/.cargo/bin:$PATH"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ORC_SOURCE/target/p0}"
# A small Aliyun instance should not run release LTO or parallel rustc jobs.
export CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null || die "Missing prerequisite: $1"; }
platform() {
  [[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || die 'Requires Linux x86_64'
  [[ $(id -u) != 0 ]] || die 'Run as an ordinary test user, not root'
  [[ -r /etc/os-release ]] || die 'Missing /etc/os-release'
  . /etc/os-release
  [[ $ID == ubuntu && $VERSION_ID == 24.04 ]] || die 'P0 target is Ubuntu 24.04'
  for cmd in python3 openssl cc git curl systemctl; do need "$cmd"; done
}
user_manager() {
  export XDG_RUNTIME_DIR="/run/user/$(id -u)"
  export DBUS_SESSION_BUS_ADDRESS="unix:path=$XDG_RUNTIME_DIR/bus"
  systemctl --user show-environment >/dev/null || die 'A real systemd user manager is required'
}
set_root() {
  ORC_ROOT="${ORC_ROOT:-$HOME/.local/share/orc-p0-$1}"
  [[ $ORC_ROOT =~ ^/[a-zA-Z0-9_./-]+$ ]] || die 'Use an absolute root without spaces or shell metacharacters'
  [[ $ORC_ROOT != / && ! -L $ORC_ROOT ]] || die 'Invalid/symlink root'
  [[ $(realpath -m -- "$ORC_ROOT") == "$ORC_ROOT" ]] || die 'Root must be canonical, without symlink parents or dot segments'
  export ORC_ROOT
}
fresh_root() {
  [[ ! -e $ORC_ROOT ]] || die "Already exists: $ORC_ROOT; preserve identity/state and use service.sh or a new root"
  mkdir -p -m 700 "$ORC_ROOT"
}
build() {
  need cargo
  cd "$ORC_SOURCE"
  cargo build --locked "$@"
}
install_bin() {
  mkdir -p -m 700 "$ORC_ROOT/bin"
  for binary in "$@"; do install -m 700 "$CARGO_TARGET_DIR/debug/$binary" "$ORC_ROOT/bin/"; done
}

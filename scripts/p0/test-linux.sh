#!/usr/bin/env bash
# Saves actual exit codes/output; missing systemd is a failure, never a silent skip.
source "$(dirname "$0")/common.sh"
[[ $# == 1 && $1 =~ ^(mcp|endpoint)$ ]] || die 'Usage: test-linux.sh mcp|endpoint'
role="$1"
platform
user_manager
set_root "$role"
mkdir -p -m 700 "$ORC_ROOT/evidence"
run_dir="$(mktemp -d "$ORC_ROOT/evidence/$(date -u +%Y%m%dT%H%M%SZ)-XXXXXX")"
exec > >(tee "$run_dir/tests.log") 2>&1
trap 'rc=$?; printf "%s\n" "$rc" > "$run_dir/exit-code"; exit "$rc"' EXIT
cd "$ORC_SOURCE"
date -u +%FT%TZ
uname -srmo
id
git rev-parse HEAD
git status --short
sha256sum Cargo.lock
rustc --version
cargo --version
if [[ $role == mcp ]]; then
  cargo test --locked -p orc-mcp -p orc-auth -p orc-transport -p orc-protocol -p orc-store
else
  ORC_TEST_SECRET=should-not-be-inherited cargo test --workspace --locked
  build -p orc-runner
  export ORC_TEST_RUNNER_PATH="$CARGO_TARGET_DIR/debug/orc-runner"
  cargo test --locked -p orc-backend-host-linux --test systemd_linux -- --ignored --test-threads=1
fi
printf 'PASS: %s Linux tests. Does not establish cloud OAuth, two-device, gVisor or release acceptance.\n' "$role"

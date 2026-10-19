#!/usr/bin/env bash
# Run on each Ubuntu machine as its test user. Installs only a user Rust toolchain.
source "$(dirname "$0")/common.sh"
platform
user_manager
cd "$ORC_SOURCE"
channel="$(python3 -c 'import tomllib; print(tomllib.load(open("rust-toolchain.toml", "rb"))["toolchain"]["channel"])')"
if ! command -v rustup >/dev/null; then
  bootstrap_dir="$(mktemp -d)"
  trap 'rm -rf -- "$bootstrap_dir"' EXIT
  curl --connect-timeout 15 --max-time 180 --proto '=https' --tlsv1.2 -fsS \
    https://sh.rustup.rs -o "$bootstrap_dir/rustup-init.sh"
  timeout 600 sh "$bootstrap_dir/rustup-init.sh" -y --no-modify-path --profile minimal --default-toolchain "$channel"
fi
timeout 900 rustup toolchain install "$channel" --profile minimal --component rustfmt --component clippy
rustc --version
cargo --version
printf 'READY: ordinary user, pinned toolchain, systemd user manager. No services started.\n'

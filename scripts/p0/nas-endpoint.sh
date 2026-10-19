#!/usr/bin/env bash
# NEW endpoint root + local client key/CSR. Does not enable execution.
source "$(dirname "$0")/common.sh"
platform
user_manager
set_root endpoint
[[ ! -e $ORC_ROOT ]] || die "Refusing to replace existing root: $ORC_ROOT"
build -p orc-cli -p orc-endpoint -p orc-runner -p orc-watchdog
fresh_root
install_bin orc orc-endpoint orc-runner orc-watchdog
"$ORC_ROOT/bin/orc" setup --role endpoint --root "$ORC_ROOT" > "$ORC_ROOT/setup.json"
openssl req -new -newkey ed25519 -nodes \
  -keyout "$ORC_ROOT/endpoint/tls/client-key.pem" -out "$ORC_ROOT/endpoint/tls/client.csr" \
  -subj '/CN=ORC P0 NAS endpoint'
mkdir -m 700 "$ORC_ROOT/work"
printf 'Created %s. Transfer ONLY endpoint/tls/client.csr to the MCP owner for signing.\n' "$ORC_ROOT"

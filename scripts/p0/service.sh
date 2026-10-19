#!/usr/bin/env bash
# Dedicated P0 user units. Does not overwrite the ordinary orc-*.service units.
source "$(dirname "$0")/common.sh"
[[ $# == 2 && $1 =~ ^(mcp|endpoint)$ && $2 =~ ^(start|status|stop)$ ]] || die 'Usage: service.sh mcp|endpoint start|status|stop'
role="$1"; action="$2"
platform
user_manager
set_root "$role"
components=(mcp)
[[ $role != endpoint ]] || components=(watchdog endpoint)
units=()
for component in "${components[@]}"; do units+=("orc-p0-$component.service"); done
if [[ $action == start ]]; then
  python3 - "$ORC_ROOT" "$role" <<'PY'
import json, pathlib, sys
r = pathlib.Path(sys.argv[1]); role = sys.argv[2]
c = json.loads((r / role / 'config.json').read_text())
if role == 'endpoint' and c['mcp_id'] == 'UNCONFIGURED': raise SystemExit('Configure and enroll endpoint first')
tls = c['device_tls'] if role == 'mcp' else c['tls']
for file in tls.values():
    if not pathlib.Path(file).is_file(): raise SystemExit('Missing TLS file: ' + file)
PY
  unit_dir="$HOME/.config/systemd/user"
  mkdir -p "$unit_dir"
  for component in "${components[@]}"; do
    source_unit="$ORC_ROOT/systemd/orc-$component.service"
    dest="$unit_dir/orc-p0-$component.service"
    [[ ! -e $dest ]] || cmp -s "$source_unit" "$dest" || die "Unit belongs to another root: $dest"
    install -m 600 "$source_unit" "$dest"
  done
  systemctl --user daemon-reload
  systemctl --user enable --now "${units[@]}"
  sleep 2
  systemctl --user is-active "${units[@]}"
elif [[ $action == stop ]]; then
  # Owner must first inspect endpoint tasks and confirm they are terminal/stopped.
  [[ $role != endpoint ]] || die 'Inspect/stop tasks first; then stop endpoint and watchdog explicitly (see guide)'
  systemctl --user stop "${units[@]}"
else
  systemctl --user status --no-pager "${units[@]}"
fi

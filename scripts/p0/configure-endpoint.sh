#!/usr/bin/env bash
# On NAS after independently verifying peer.json against Aliyun's identity output.
source "$(dirname "$0")/common.sh"
platform
set_root endpoint
[[ $# == 1 ]] || die 'Usage: configure-endpoint.sh /absolute/verified-public-bundle'
bundle="$1"
[[ -d $bundle ]] || die 'Bundle directory missing'
[[ ! -e $ORC_ROOT/endpoint/state/state.sqlite3 ]] || die 'Endpoint state exists; use owner trust migration workflow'
python3 - "$ORC_ROOT" "$bundle" <<'PY'
import json, pathlib, sys, subprocess, os, hashlib, shutil
r, b = map(pathlib.Path, sys.argv[1:]); p = r / 'endpoint/config.json'
c = json.loads(p.read_text())
if c['mcp_id'] != 'UNCONFIGURED': raise SystemExit('Already configured; do not overwrite existing trust')
peer = json.loads((b / 'peer.json').read_text())
required = {'mcp_id', 'mcp_public_key', 'mcp_certificate_digest', 'mcp_address', 'mcp_server_name'}
if set(peer) != required or not all(isinstance(v, str) and v and 'UNCONFIGURED' not in v for v in peer.values()):
    raise SystemExit('Invalid peer fields')
subprocess.run(['openssl', 'verify', '-purpose', 'sslclient', '-CAfile', str(b/'ca.pem'), str(b/'client.pem')], check=True)
cert_pub = subprocess.check_output(['openssl', 'x509', '-in', str(b/'client.pem'), '-pubkey', '-noout'])
key_pub = subprocess.check_output(['openssl', 'pkey', '-in', str(r/'endpoint/tls/client-key.pem'), '-pubout'])
if cert_pub != key_pub: raise SystemExit('Client certificate does not match local private key')
for name in ('ca.pem', 'client.pem'):
    dest = r / 'endpoint/tls' / name
    shutil.copyfile(b / name, dest); dest.chmod(0o600)
c.update(peer)
c.update(execution_uid=os.getuid(), host_context_id='p0-nas', host_profile_id='p0-host-v1',
         host_environment_digest='sha256:' + hashlib.sha256((r/'bin/orc-runner').read_bytes()).hexdigest(),
         gvisor=None, continue_on_disconnect=False)
p.write_text(json.dumps(c, indent=2)+'\n'); p.chmod(0o600)
PY
"$ORC_ROOT/bin/orc" endpoint enrollment-request --identity "$ORC_ROOT/endpoint/identity.json" \
  --certificate "$ORC_ROOT/endpoint/tls/client.pem" > "$ORC_ROOT/enrollment-request.json"
printf 'Ready for owner enrollment. No grant or service created. Request: %s/enrollment-request.json\n' "$ORC_ROOT"

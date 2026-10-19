#!/usr/bin/env bash
# Creates a NEW development MCP root. Public HTTPS is a separate admin step.
source "$(dirname "$0")/common.sh"
platform
user_manager
set_root mcp
ORC_PUBLIC_URL="${ORC_PUBLIC_URL:-http://127.0.0.1:18787/mcp}"
ORC_DEVICE_BIND="${ORC_DEVICE_BIND:-127.0.0.1:18788}"
ORC_DEVICE_NAME="${ORC_DEVICE_NAME:-localhost}"
ORC_DEVICE_ADDRESS="${ORC_DEVICE_ADDRESS:-127.0.0.1:18788}"
[[ $ORC_DEVICE_NAME =~ ^[A-Za-z0-9.-]+$ ]] || die 'Invalid TLS DNS name'
[[ ! -e $ORC_ROOT ]] || die "Refusing to replace existing root: $ORC_ROOT"
build -p orc-cli -p orc-mcp
fresh_root
install_bin orc orc-mcp
"$ORC_ROOT/bin/orc" setup --role mcp --root "$ORC_ROOT" --public-url "$ORC_PUBLIC_URL" > "$ORC_ROOT/setup.json"
python3 - "$ORC_ROOT" "$ORC_DEVICE_BIND" <<'PY'
import json, pathlib, sys
p = pathlib.Path(sys.argv[1]) / 'mcp/config.json'
c = json.loads(p.read_text())
c.update(http_bind='127.0.0.1:18787', device_bind=sys.argv[2])
p.write_text(json.dumps(c, indent=2) + '\n')
PY
tls="$ORC_ROOT/mcp/tls"
openssl req -x509 -newkey ed25519 -nodes -keyout "$tls/ca-key.pem" -out "$tls/ca.pem" \
  -subj '/CN=ORC P0 device CA' -days 30 \
  -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign'
openssl req -new -newkey ed25519 -nodes -keyout "$tls/server-key.pem" -out "$tls/server.csr" \
  -subj "/CN=$ORC_DEVICE_NAME"
cat > "$tls/server.ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:$ORC_DEVICE_NAME,IP:127.0.0.1
EOF
openssl x509 -req -in "$tls/server.csr" -CA "$tls/ca.pem" -CAkey "$tls/ca-key.pem" \
  -CAcreateserial -out "$tls/server.pem" -days 7 -extfile "$tls/server.ext"
"$ORC_ROOT/bin/orc" identity show --kind mcp --file "$ORC_ROOT/mcp/identity.json" \
  --certificate "$tls/server.pem" > "$ORC_ROOT/mcp-public.json"
python3 - "$ORC_ROOT" "$ORC_DEVICE_NAME" "$ORC_DEVICE_ADDRESS" <<'PY'
import json, pathlib, sys
r = pathlib.Path(sys.argv[1]); identity = json.loads((r / 'mcp-public.json').read_text())
peer = dict(mcp_id=identity['id'], mcp_public_key=identity['public_key'],
            mcp_certificate_digest=identity['certificate_digest'],
            mcp_server_name=sys.argv[2], mcp_address=sys.argv[3])
(r / 'peer.json').write_text(json.dumps(peer, indent=2) + '\n')
PY
printf 'Created %s. Next: ORC_ROOT=%s bash scripts/p0/service.sh mcp start\n' "$ORC_ROOT" "$ORC_ROOT"

#!/usr/bin/env bash
# On Aliyun: sign a NAS CSR, produce a public peer bundle; no private keys leave MCP.
source "$(dirname "$0")/common.sh"
platform
set_root mcp
[[ $# == 2 ]] || die 'Usage: sign-client.sh /absolute/client.csr /absolute/new-bundle-directory'
csr="$1"; bundle="$2"
[[ -f $csr && $bundle == /* && ! -e $bundle ]] || die 'CSR missing or bundle directory already exists'
openssl req -in "$csr" -verify -noout
mkdir -m 700 "$bundle"
cat > "$bundle/client.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
EOF
openssl x509 -req -in "$csr" -CA "$ORC_ROOT/mcp/tls/ca.pem" \
  -CAkey "$ORC_ROOT/mcp/tls/ca-key.pem" -set_serial "0x$(openssl rand -hex 16)" \
  -out "$bundle/client.pem" -days 7 -extfile "$bundle/client.ext"
install -m 600 "$ORC_ROOT/mcp/tls/ca.pem" "$ORC_ROOT/peer.json" "$bundle/"
printf 'Return client.pem, ca.pem and peer.json to NAS. Verify MCP identity independently before activation.\n'

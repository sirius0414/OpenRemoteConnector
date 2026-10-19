#!/usr/bin/env bash
# ADMINISTRATOR STEP. Remote Desktop Commander currently blocks sudo on this host.
# Invoke from the owner's administrative SSH terminal after reviewing this file.
set -euo pipefail
[[ $(id -u) == 0 ]] || { echo 'Run this script from an administrator terminal as root' >&2; exit 1; }
: "${ORC_PUBLIC_HOST:?Set the certificate DNS name or certified IP}"
: "${ORC_HTTPS_CERT:?Set existing public fullchain PEM path}"
: "${ORC_HTTPS_KEY:?Set existing private key PEM path}"
ORC_HTTPS_PORT="${ORC_HTTPS_PORT:-12443}"
[[ $ORC_PUBLIC_HOST =~ ^[A-Za-z0-9.-]+$ && $ORC_HTTPS_PORT =~ ^[0-9]+$ ]] || exit 1
(( ORC_HTTPS_PORT >= 1024 && ORC_HTTPS_PORT <= 65535 )) || exit 1
for p in "$ORC_HTTPS_CERT" "$ORC_HTTPS_KEY"; do
  [[ $p =~ ^/[A-Za-z0-9_./-]+$ && -f $p ]] || { echo 'Invalid TLS file path' >&2; exit 1; }
done
available=/etc/nginx/sites-available/orc-p0
enabled=/etc/nginx/sites-enabled/orc-p0
[[ ! -e $available && ! -e $enabled && ! -L $enabled ]] || { echo 'orc-p0 site already exists; inspect it manually' >&2; exit 1; }
[[ -z $(ss -H -ltn "sport = :$ORC_HTTPS_PORT") ]] || { echo 'HTTPS port already occupied' >&2; exit 1; }
nginx -t
cat > "$available" <<EOF
server {
    listen $ORC_HTTPS_PORT ssl;
    server_name $ORC_PUBLIC_HOST;
    ssl_certificate $ORC_HTTPS_CERT;
    ssl_certificate_key $ORC_HTTPS_KEY;
    ssl_protocols TLSv1.2 TLSv1.3;
    client_max_body_size 256k;
    # OAuth authorize URLs contain code challenges/state. Do not write query logs.
    access_log off;
    location / {
        proxy_pass http://127.0.0.1:18787;
        proxy_http_version 1.1;
        # Preserve :12443; the MCP validates Host against its exact public_url.
        proxy_set_header Host \$http_host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header Connection "";
        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 3600s;
    }
}
EOF
ln -s "$available" "$enabled"
if ! nginx -t; then
  rm -- "$enabled" "$available"
  echo 'New site removed after failed config validation; original service retained' >&2
  exit 1
fi
systemctl reload nginx
printf 'HTTPS proxy installed. Configure MCP public_url=https://%s:%s/mcp before testing.\n' "$ORC_PUBLIC_HOST" "$ORC_HTTPS_PORT"
printf 'Security group/firewall changes are separate. Device mTLS is NOT HTTP-proxied by this site.\n'

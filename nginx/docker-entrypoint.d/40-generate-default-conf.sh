#!/bin/sh
set -eu

tls_enabled="${NGINX_TLS_ENABLED:-true}"
hsts_enabled="${NGINX_HSTS_ENABLED:-true}"
http_port="${NGINX_HTTP_PORT:-80}"
https_port="${NGINX_HTTPS_PORT:-7003}"
public_https_port="${NGINX_PUBLIC_HTTPS_PORT:-$https_port}"
cert_path="/etc/nginx/ssl/cert.pem"
key_path="/etc/nginx/ssl/key.pem"
fallback_cert_path="/tmp/nginx-selfsigned-cert.pem"
fallback_key_path="/tmp/nginx-selfsigned-key.pem"

write_common_headers() {
  cat <<'EOF'
  add_header X-Frame-Options "SAMEORIGIN" always;
  add_header X-Content-Type-Options "nosniff" always;
  add_header X-XSS-Protection "1; mode=block" always;
  add_header Referrer-Policy "strict-origin-when-cross-origin" always;
  add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';" always;
EOF
}

# Use a variable for the backend address so nginx re-resolves via the Docker DNS
# resolver (127.0.0.11) declared in nginx.conf instead of caching the IP at startup.
# This prevents stale-IP 502 errors after app container recreation.
write_proxy_locations() {
  local proto="$1"
  cat <<EOF
  location /health {
    limit_req zone=api_limit burst=50 nodelay;
    set \$app_backend http://app:8080;
    proxy_pass \$app_backend;
    proxy_set_header Host \$host;
    proxy_set_header X-Forwarded-Proto ${proto};
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
  }

  location ~ ^/(crowdsec|misp|indicators) {
    limit_req zone=feed_limit burst=20 nodelay;
    set \$app_backend http://app:8080;
    proxy_pass \$app_backend;
    proxy_set_header Host \$host;
    proxy_set_header X-Forwarded-Proto ${proto};
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
  }

  location / {
    limit_req zone=api_limit burst=50 nodelay;
    set \$app_backend http://app:8080;
    proxy_pass \$app_backend;
    proxy_set_header Host \$host;
    proxy_set_header X-Forwarded-Proto ${proto};
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
  }
EOF
}

if [ "$tls_enabled" = "true" ]; then
  if [ ! -s "$cert_path" ] || [ ! -s "$key_path" ]; then
    cert_path="$fallback_cert_path"
    key_path="$fallback_key_path"
    if [ ! -s "$cert_path" ] || [ ! -s "$key_path" ]; then
      openssl req -x509 -nodes -newkey rsa:2048 \
        -keyout "$key_path" \
        -out "$cert_path" \
        -days 7 \
        -subj "${NGINX_SELF_SIGNED_SUBJECT:-/CN=localhost}" >/dev/null 2>&1
    fi
  fi
  cat > /etc/nginx/conf.d/default.conf <<EOF
server {
  listen ${http_port};
  server_name _;
  location / {
    return 301 https://\$host:${public_https_port}\$request_uri;
  }
}

server {
  listen ${https_port} ssl http2;
  server_name _;

  ssl_certificate     ${cert_path};
  ssl_certificate_key ${key_path};
  ssl_protocols TLSv1.2 TLSv1.3;
  ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305';
  ssl_prefer_server_ciphers off;
  ssl_session_cache shared:SSL:10m;
  ssl_session_timeout 10m;
  ssl_session_tickets off;
EOF
  if [ "$hsts_enabled" = "true" ]; then
    printf '  add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;\n' >> /etc/nginx/conf.d/default.conf
  fi
  write_common_headers >> /etc/nginx/conf.d/default.conf
  cat >> /etc/nginx/conf.d/default.conf <<EOF

  client_max_body_size 5m;

$(write_proxy_locations https)
}
EOF
else
  cat > /etc/nginx/conf.d/default.conf <<EOF
server {
  listen ${http_port};
  server_name _;
EOF
  write_common_headers >> /etc/nginx/conf.d/default.conf
  cat >> /etc/nginx/conf.d/default.conf <<EOF

  client_max_body_size 5m;

$(write_proxy_locations http)
}
EOF
fi

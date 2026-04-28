#!/bin/sh
set -eu

tls_enabled="${NGINX_TLS_ENABLED:-true}"
hsts_enabled="${NGINX_HSTS_ENABLED:-true}"
http_port="${NGINX_HTTP_PORT:-80}"
https_port="${NGINX_HTTPS_PORT:-7003}"
public_https_port="${NGINX_PUBLIC_HTTPS_PORT:-$https_port}"

write_common_headers() {
  cat <<'EOF'
  add_header X-Frame-Options "SAMEORIGIN" always;
  add_header X-Content-Type-Options "nosniff" always;
  add_header X-XSS-Protection "1; mode=block" always;
  add_header Referrer-Policy "strict-origin-when-cross-origin" always;
  add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';" always;
EOF
}

if [ "$tls_enabled" = "true" ]; then
  cat > /etc/nginx/conf.d/default.conf <<EOF
upstream app_upstream {
  server app:8080;
  keepalive 32;
}

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

  ssl_certificate     /etc/nginx/ssl/cert.pem;
  ssl_certificate_key /etc/nginx/ssl/key.pem;
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
  cat >> /etc/nginx/conf.d/default.conf <<'EOF'

  client_max_body_size 5m;

  location /health {
    limit_req zone=api_limit burst=50 nodelay;
    proxy_pass http://app_upstream;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
  }

  location ~ ^/(crowdsec|misp|indicators) {
    limit_req zone=feed_limit burst=20 nodelay;
    proxy_pass http://app_upstream;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
  }

  location / {
    limit_req zone=api_limit burst=50 nodelay;
    proxy_pass http://app_upstream;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
  }
}
EOF
else
  cat > /etc/nginx/conf.d/default.conf <<EOF
upstream app_upstream {
  server app:8080;
  keepalive 32;
}

server {
  listen ${http_port};
  server_name _;
EOF
  write_common_headers >> /etc/nginx/conf.d/default.conf
  cat >> /etc/nginx/conf.d/default.conf <<'EOF'

  client_max_body_size 5m;

  location /health {
    limit_req zone=api_limit burst=50 nodelay;
    proxy_pass http://app_upstream;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto http;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
  }

  location ~ ^/(crowdsec|misp|indicators) {
    limit_req zone=feed_limit burst=20 nodelay;
    proxy_pass http://app_upstream;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto http;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
  }

  location / {
    limit_req zone=api_limit burst=50 nodelay;
    proxy_pass http://app_upstream;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto http;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
  }
}
EOF
fi

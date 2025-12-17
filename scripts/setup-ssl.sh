#!/usr/bin/env sh
set -eu

# Development helper: generate a self-signed cert into ./ssl/
# In production, use a real certificate (ACME/PKI).

mkdir -p ssl

if command -v openssl >/dev/null 2>&1; then
  openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
    -keyout ssl/key.pem -out ssl/cert.pem \
    -subj "/CN=localhost"
  echo "Generated ssl/cert.pem and ssl/key.pem"
else
  echo "openssl not found; cannot generate certificate."
  exit 1
fi

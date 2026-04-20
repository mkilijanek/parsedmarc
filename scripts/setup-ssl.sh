#!/usr/bin/env bash
set -euo pipefail

# setup-ssl.sh
# Modes:
#   1) import       - use existing cert/key files (.crt/.pem + .prv/.key)
#   2) self-signed  - generate self-signed cert for SSL_DOMAIN
#   3) acme         - obtain/renew Let's Encrypt cert using certbot (docker) via HTTP-01 (webroot)
#
# Outputs (project-local):
#   ./ssl/cert.pem
#   ./ssl/key.pem
#   ./ssl/chain.pem   (optional; created if available)
#
# Required env:
#   SSL_DOMAIN=example.com
# Optional env:
#   SSL_MODE=import|self-signed|acme   (default: self-signed)
#   SSL_CERT_IN=path/to/cert.crt|cert.pem        (import)
#   SSL_CHAIN_IN=path/to/chain.crt|fullchain.pem (import, optional)
#   SSL_KEY_IN=path/to/key.prv|key.pem           (import)
#   SSL_EMAIL=admin@example.com                  (acme; recommended)
#   ACME_STAGING=true|false                      (acme; default false)
#   ACME_WEBROOT=./certbot/www                   (acme; default ./certbot/www)
#   ACME_CONF_DIR=./certbot/conf                 (acme; default ./certbot/conf)
#
# Notes:
# - ACME HTTP-01 requires port 80 reachable for SSL_DOMAIN.
# - For ACME, nginx should serve /.well-known/acme-challenge/ from ACME_WEBROOT.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SSL_DIR="${ROOT_DIR}/ssl"
CERTBOT_WEBROOT_DEFAULT="${ROOT_DIR}/certbot/www"
CERTBOT_CONF_DEFAULT="${ROOT_DIR}/certbot/conf"

mkdir -p "${SSL_DIR}"

SSL_DOMAIN="${SSL_DOMAIN:-}"
SSL_MODE="${SSL_MODE:-self-signed}"

if [[ -z "${SSL_DOMAIN}" ]]; then
  echo "ERROR: SSL_DOMAIN is required (set in .env)."
  exit 2
fi

log() { echo "[setup-ssl] $*"; }

require_cmd() {
  local cmd="$1"
  command -v "${cmd}" >/dev/null 2>&1 || { echo "ERROR: missing command: ${cmd}"; exit 3; }
}

copy_out() {
  local cert_in="$1"
  local key_in="$2"
  local chain_in="${3:-}"

  [[ -f "${cert_in}" ]] || { echo "ERROR: cert file not found: ${cert_in}"; exit 4; }
  [[ -f "${key_in}"  ]] || { echo "ERROR: key file not found: ${key_in}"; exit 4; }

  cp -f "${cert_in}" "${SSL_DIR}/cert.pem"
  cp -f "${key_in}"  "${SSL_DIR}/key.pem"

  if [[ -n "${chain_in}" ]]; then
    [[ -f "${chain_in}" ]] || { echo "ERROR: chain file not found: ${chain_in}"; exit 4; }
    cp -f "${chain_in}" "${SSL_DIR}/chain.pem"
  else
    # If no chain provided, remove any stale chain.pem to avoid confusion
    rm -f "${SSL_DIR}/chain.pem" || true
  fi

  chmod 600 "${SSL_DIR}/key.pem"
  chmod 644 "${SSL_DIR}/cert.pem" || true
  [[ -f "${SSL_DIR}/chain.pem" ]] && chmod 644 "${SSL_DIR}/chain.pem" || true

  log "Wrote:"
  log "  ${SSL_DIR}/cert.pem"
  log "  ${SSL_DIR}/key.pem"
  if [[ -f "${SSL_DIR}/chain.pem" ]]; then
    log "  ${SSL_DIR}/chain.pem"
  fi
}

mode_import() {
  local cert_in="${SSL_CERT_IN:-}"
  local key_in="${SSL_KEY_IN:-}"
  local chain_in="${SSL_CHAIN_IN:-}"

  if [[ -z "${cert_in}" || -z "${key_in}" ]]; then
    cat <<EOF
ERROR: import mode requires:
  SSL_CERT_IN=/path/to/cert.crt|cert.pem
  SSL_KEY_IN=/path/to/key.prv|key.pem
Optional:
  SSL_CHAIN_IN=/path/to/chain.crt|fullchain.pem
EOF
    exit 5
  fi

  log "Importing existing certificate for ${SSL_DOMAIN}"
  copy_out "${cert_in}" "${key_in}" "${chain_in}"
}

mode_self_signed() {
  require_cmd openssl

  local days="${SSL_SELF_SIGNED_DAYS:-825}" # <= 825 days common max for many clients
  log "Generating self-signed certificate for ${SSL_DOMAIN} (${days} days)"

  local tmp_dir
  tmp_dir="$(mktemp -d)"
  trap "rm -rf '${tmp_dir}'" EXIT

  # Create an OpenSSL config with SAN
  local conf="${tmp_dir}/openssl.cnf"
  cat >"${conf}" <<EOF
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = ${SSL_DOMAIN}

[v3_req]
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
EOF

  if [[ "${SSL_DOMAIN}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    echo "IP.1 = ${SSL_DOMAIN}" >>"${conf}"
  else
    echo "DNS.1 = ${SSL_DOMAIN}" >>"${conf}"
  fi

  openssl req -x509 -nodes -newkey rsa:2048 \
    -keyout "${tmp_dir}/key.pem" \
    -out "${tmp_dir}/cert.pem" \
    -days "${days}" \
    -config "${conf}" \
    -extensions v3_req >/dev/null 2>&1

  copy_out "${tmp_dir}/cert.pem" "${tmp_dir}/key.pem"
}

mode_acme() {
  require_cmd docker

  local email="${SSL_EMAIL:-}"
  local staging="${ACME_STAGING:-false}"
  local webroot="${ACME_WEBROOT:-${CERTBOT_WEBROOT_DEFAULT}}"
  local conf_dir="${ACME_CONF_DIR:-${CERTBOT_CONF_DEFAULT}}"

  mkdir -p "${webroot}" "${conf_dir}"

  if [[ -z "${email}" ]]; then
    log "WARN: SSL_EMAIL not set; Let's Encrypt registration email is recommended."
    email="admin@${SSL_DOMAIN}"
  fi

  local server_flag=""
  if [[ "${staging}" == "true" ]]; then
    server_flag="--staging"
    log "Using ACME staging endpoint (ACME_STAGING=true)"
  fi

  log "Requesting/renewing Let's Encrypt certificate for ${SSL_DOMAIN}"
  log "Webroot: ${webroot}"
  log "Conf:    ${conf_dir}"
  log "NOTE: Ensure nginx (HTTP) serves /.well-known/acme-challenge/ from this webroot and port 80 is reachable."

  # Use certbot in a disposable container; stores certs in ${conf_dir}/live/${SSL_DOMAIN}/
  docker run --rm \
    -v "${conf_dir}:/etc/letsencrypt" \
    -v "${webroot}:/var/www/certbot" \
    certbot/certbot:latest certonly \
      --webroot -w /var/www/certbot \
      -d "${SSL_DOMAIN}" \
      --agree-tos --no-eff-email \
      --email "${email}" \
      ${server_flag}

  local live_dir="${conf_dir}/live/${SSL_DOMAIN}"
  local fullchain="${live_dir}/fullchain.pem"
  local privkey="${live_dir}/privkey.pem"
  local chain="${live_dir}/chain.pem"

  [[ -f "${fullchain}" ]] || { echo "ERROR: expected ${fullchain} not found"; exit 6; }
  [[ -f "${privkey}"  ]] || { echo "ERROR: expected ${privkey} not found"; exit 6; }

  log "Copying issued certs to ${SSL_DIR}"
  copy_out "${fullchain}" "${privkey}" "${chain}"
}

case "${SSL_MODE}" in
  import)      mode_import ;;
  self-signed) mode_self_signed ;;
  acme)        mode_acme ;;
  *)
    echo "ERROR: unknown SSL_MODE: ${SSL_MODE} (use import|self-signed|acme)"
    exit 1
    ;;
esac

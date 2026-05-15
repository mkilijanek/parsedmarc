#!/usr/bin/env bash
# IOC Service — interactive deployment installer.
#
# Guides the operator through configuring Docker Compose, optional nginx,
# and TLS for a new or existing installation. Reads the current .env file
# (if present) and only updates deployment-related keys.
#
# Usage:
#   bash setup.sh [--non-interactive] [--env-file PATH]
#
# --non-interactive  Accept all current / default values without prompting.
# --env-file PATH    Path to the .env file (default: .env in the same dir).

set -euo pipefail

# ── Bash version guard ────────────────────────────────────────────────────────
# Associative arrays (declare -A) require bash 4.0+.
# macOS ships bash 3.2; users need to install bash via Homebrew.
if (( BASH_VERSINFO[0] < 4 )); then
  echo "ERROR: bash 4.0 or higher is required (found ${BASH_VERSION})." >&2
  echo "       On macOS: brew install bash" >&2
  exit 1
fi

# ── Locate script dir ─────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${SCRIPT_DIR}/.env"
NON_INTERACTIVE=false
NGINX_DIR=""   # overridable via --nginx-dir for testing / custom layouts

while [[ $# -gt 0 ]]; do
  case "$1" in
    --non-interactive) NON_INTERACTIVE=true; shift ;;
    --env-file=*)      ENV_FILE="${1#*=}"; shift ;;
    --env-file)        ENV_FILE="$2"; shift 2 ;;
    --nginx-dir=*)     NGINX_DIR="${1#*=}"; shift ;;
    --nginx-dir)       NGINX_DIR="$2"; shift 2 ;;
    *) shift ;;
  esac
done

# ── Colour helpers ────────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
  BOLD='\033[1m'; CYAN='\033[0;36m'; GREEN='\033[0;32m'
  YELLOW='\033[1;33m'; RED='\033[0;31m'; RESET='\033[0m'
else
  BOLD=''; CYAN=''; GREEN=''; YELLOW=''; RED=''; RESET=''
fi

info()    { printf "${CYAN}==> %s${RESET}\n" "$*"; }
success() { printf "${GREEN}✓ %s${RESET}\n" "$*"; }
warn()    { printf "${YELLOW}WARNING: %s${RESET}\n" "$*"; }
die()     { printf "${RED}ERROR: %s${RESET}\n" "$*" >&2; exit 1; }

# ── Pre-flight checks ─────────────────────────────────────────────────────────
command -v docker >/dev/null 2>&1 \
  || warn "docker not found — install Docker before running 'docker compose up'."

# ── Load existing .env ────────────────────────────────────────────────────────
declare -A ENV_MAP
if [[ -f "${ENV_FILE}" ]]; then
  info "Loading existing values from ${ENV_FILE}"
  while IFS= read -r line || [[ -n "${line}" ]]; do
    # Skip blank lines and comment lines (including leading-space comments)
    [[ -z "${line}" || "${line}" =~ ^[[:space:]]*# ]] && continue
    # Strip optional 'export ' prefix
    line="${line#export }"
    key="${line%%=*}"
    val="${line#*=}"
    # Strip surrounding single or double quotes from the value
    if [[ "${val}" =~ ^\"(.*)\"$ ]]; then
      val="${BASH_REMATCH[1]}"
    elif [[ "${val}" =~ ^\'(.*)\'$ ]]; then
      val="${BASH_REMATCH[1]}"
    fi
    [[ -n "${key}" ]] && ENV_MAP["${key}"]="${val}"
  done < "${ENV_FILE}"
fi

# env_get KEY [default] — prefers .env file, then shell env, then default
env_get() {
  local key="$1" default="${2:-}"
  if [[ -v "ENV_MAP[${key}]" ]]; then
    echo "${ENV_MAP[${key}]}"
  elif [[ -v "${key}" ]]; then
    echo "${!key}"
  else
    echo "${default}"
  fi
}

# ── Prompt helper ─────────────────────────────────────────────────────────────
# ask VAR_NAME "Question" "default"
ask() {
  local var_name="$1" question="$2" default="$3"
  if [[ "${NON_INTERACTIVE}" == "true" ]]; then
    printf -v "${var_name}" '%s' "${default}"
    return
  fi
  local prompt
  if [[ -n "${default}" ]]; then
    prompt="${BOLD}${question}${RESET} [${default}]: "
  else
    prompt="${BOLD}${question}${RESET}: "
  fi
  local answer
  read -rp "$(printf '%b' "${prompt}")" answer
  printf -v "${var_name}" '%s' "${answer:-${default}}"
}

# ask_yn VAR_NAME "Question" "y|n"
ask_yn() {
  local var_name="$1" question="$2" default="${3:-n}"
  local display_choices; [[ "${default}" == "y" ]] && display_choices="Y/n" || display_choices="y/N"
  local answer
  if [[ "${NON_INTERACTIVE}" == "true" ]]; then
    answer="${default}"
  else
    read -rp "$(printf '%b' "${BOLD}${question}${RESET} [${display_choices}]: ")" answer
    answer="${answer:-${default}}"
  fi
  [[ "${answer,,}" =~ ^y(es)?$ ]] && printf -v "${var_name}" 'y' || printf -v "${var_name}" 'n'
}

# ── Validators ────────────────────────────────────────────────────────────────
is_valid_port() {
  local p="$1"
  [[ "${p}" =~ ^[0-9]+$ ]] && (( p >= 1 && p <= 65535 ))
}

require_port() {
  local var_name="$1" question="$2" default="$3"
  while true; do
    ask "${var_name}" "${question}" "${default}"
    local val; val="${!var_name}"
    if is_valid_port "${val}"; then
      break
    fi
    # In non-interactive mode a bad default is a configuration error — abort
    # rather than spin forever.
    if [[ "${NON_INTERACTIVE}" == "true" ]]; then
      die "Default value '${val}' for '${var_name}' is not a valid port (1-65535). Fix your .env file or supply a valid --env-file."
    fi
    warn "'${val}' is not a valid port (1-65535). Please try again."
  done
}

require_file() {
  local var_name="$1" question="$2" default="$3"
  while true; do
    ask "${var_name}" "${question}" "${default}"
    local val; val="${!var_name}"
    if [[ -f "${val}" ]]; then
      break
    fi
    warn "File '${val}' not found. Please enter a valid path."
    if [[ "${NON_INTERACTIVE}" == "true" ]]; then
      die "Required file '${val}' (${var_name}) does not exist. Cannot continue in non-interactive mode."
    fi
  done
}

# ── .env writer ───────────────────────────────────────────────────────────────
# set_env_key rewrites one key in .env, preserving all other lines and their
# ordering. Uses a temp-file + mv for atomicity; safe for any value including
# those containing |, \, &, or newlines.
_ENV_BACKED_UP=false
set_env_key() {
  local key="$1" val="$2"

  # Take a one-time backup of the original .env before the first write.
  if [[ "${_ENV_BACKED_UP}" == "false" && -f "${ENV_FILE}" ]]; then
    cp "${ENV_FILE}" "${ENV_FILE}.bak" \
      || warn "Could not create backup of ${ENV_FILE} — continuing anyway."
    _ENV_BACKED_UP=true
    info "Backup saved to ${ENV_FILE}.bak"
  fi

  if [[ -f "${ENV_FILE}" ]] && grep -qF "${key}=" "${ENV_FILE}"; then
    local tmpfile
    tmpfile="$(mktemp "${ENV_FILE}.tmp.XXXXXX")" \
      || die "Cannot create a temporary file for .env update."
    # Rewrite preserving every line except the one being replaced.
    while IFS= read -r line || [[ -n "${line}" ]]; do
      if [[ "${line}" == "${key}="* ]]; then
        printf '%s=%s\n' "${key}" "${val}"
      else
        printf '%s\n' "${line}"
      fi
    done < "${ENV_FILE}" > "${tmpfile}"
    mv "${tmpfile}" "${ENV_FILE}"
  else
    printf '%s=%s\n' "${key}" "${val}" >> "${ENV_FILE}"
  fi

  ENV_MAP["${key}"]="${val}"
}

# ── Banner ────────────────────────────────────────────────────────────────────
cat <<'BANNER'

  ╔═══════════════════════════════════════════════════════╗
  ║        IOC Service — Deployment Setup Installer        ║
  ╚═══════════════════════════════════════════════════════╝

BANNER

# ── Step 1: Exposure mode ─────────────────────────────────────────────────────
info "Step 1 — Exposure mode"
echo "  direct  : app is accessed directly (no nginx)"
echo "  nginx   : app sits behind nginx (TLS termination, rate limiting)"
echo ""
ask_yn USE_NGINX "Use nginx as reverse proxy?" "$(env_get USE_NGINX_SETUP n)"

# ── Step 2: App port ──────────────────────────────────────────────────────────
info "Step 2 — App port"
if [[ "${USE_NGINX}" == "y" ]]; then
  DEFAULT_APP_PORT="$(env_get APP_HOST_PORT 8080)"
  require_port APP_HOST_PORT \
    "Internal app port (Docker host-side, nginx will proxy to this)" \
    "${DEFAULT_APP_PORT}"
  ask_yn APP_LOCALHOST_ONLY "Bind app port to 127.0.0.1 only (recommended when behind nginx)?" "y"
else
  DEFAULT_APP_PORT="$(env_get APP_HOST_PORT 7005)"
  require_port APP_HOST_PORT "App listen port (public)" "${DEFAULT_APP_PORT}"
  APP_LOCALHOST_ONLY="n"
fi

# ── Step 3: Nginx-specific questions ──────────────────────────────────────────
if [[ "${USE_NGINX}" == "y" ]]; then
  info "Step 3 — nginx configuration"

  DEFAULT_HTTP_PORT="$(env_get HTTP_PORT 80)"
  require_port HTTP_PORT "nginx HTTP port (redirect to HTTPS)" "${DEFAULT_HTTP_PORT}"

  DEFAULT_HTTPS_PORT="$(env_get HTTPS_PORT 7003)"
  require_port HTTPS_PORT "nginx HTTPS port" "${DEFAULT_HTTPS_PORT}"

  # Port conflict: nginx ports must not equal the internal app port
  if [[ "${HTTP_PORT}" == "${APP_HOST_PORT}" || "${HTTPS_PORT}" == "${APP_HOST_PORT}" ]]; then
    die "Port conflict: APP_HOST_PORT (${APP_HOST_PORT}) must differ from the nginx ports (${HTTP_PORT}, ${HTTPS_PORT}). Both would bind the same Docker host port."
  fi

  ask SERVER_NAME "Server name / domain (used in nginx server_name)" \
    "$(env_get SERVER_NAME "_")"

  ask_yn NGINX_LOCALHOST_ONLY \
    "Bind nginx ports to 127.0.0.1 only (e.g., behind a cloud load balancer)?" \
    "$(env_get NGINX_LOCALHOST_ONLY n)"

  # TLS
  info "Step 3b — TLS"
  ask_yn TLS_ENABLED "Enable TLS (nginx SSL termination)?" \
    "$(env_get TLS_ENABLED y)"

  TLS_CERT_PATH=""
  TLS_KEY_PATH=""
  TLS_CHAIN_PATH=""

  if [[ "${TLS_ENABLED}" == "y" ]]; then
    require_file TLS_CERT_PATH \
      "Path to TLS certificate (PEM)" \
      "$(env_get TLS_CERT_PATH "${SCRIPT_DIR}/ssl/cert.pem")"

    require_file TLS_KEY_PATH \
      "Path to TLS private key (PEM)" \
      "$(env_get TLS_KEY_PATH "${SCRIPT_DIR}/ssl/key.pem")"

    ask TLS_CHAIN_PATH \
      "Path to CA chain file (leave blank if none)" \
      "$(env_get TLS_CHAIN_PATH "")"
    # Chain file is optional — validate only when provided
    if [[ -n "${TLS_CHAIN_PATH}" && ! -f "${TLS_CHAIN_PATH}" ]]; then
      warn "Chain file '${TLS_CHAIN_PATH}' not found — continuing without it."
      TLS_CHAIN_PATH=""
    fi
  fi
else
  info "Step 3 — skipped (direct mode, no nginx)"
  HTTP_PORT=""; HTTPS_PORT=""; SERVER_NAME="_"
  NGINX_LOCALHOST_ONLY="n"; TLS_ENABLED="n"
  TLS_CERT_PATH=""; TLS_KEY_PATH=""; TLS_CHAIN_PATH=""
fi

# ── Step 4: Generate nginx config ─────────────────────────────────────────────
if [[ "${USE_NGINX}" == "y" ]]; then
  info "Step 4 — Generating nginx config"
  NGINX_CONF_DIR="${NGINX_DIR:-${SCRIPT_DIR}/nginx/conf.d}"
  mkdir -p "${NGINX_CONF_DIR}" \
    || die "Cannot create directory '${NGINX_CONF_DIR}' — check permissions."
  NGINX_CONF="${NGINX_CONF_DIR}/default.conf"

  # Back up existing nginx config if present
  if [[ -f "${NGINX_CONF}" ]]; then
    cp "${NGINX_CONF}" "${NGINX_CONF}.bak" \
      || warn "Could not back up existing ${NGINX_CONF}."
  fi

  if [[ "${TLS_ENABLED}" == "y" ]]; then
    CHAIN_DIRECTIVE=""
    if [[ -n "${TLS_CHAIN_PATH}" ]]; then
      CHAIN_DIRECTIVE="  ssl_trusted_certificate ${TLS_CHAIN_PATH};"
    fi

    # Omit port suffix in redirect URL when using the standard HTTPS port (443)
    if [[ "${HTTPS_PORT}" == "443" ]]; then
      HTTPS_REDIRECT_URL="https://\$host\$request_uri"
    else
      HTTPS_REDIRECT_URL="https://\$host:${HTTPS_PORT}\$request_uri"
    fi

    # Build the listen directive, optionally restricted to localhost
    HTTP_LISTEN="${HTTP_PORT}"
    HTTPS_LISTEN="${HTTPS_PORT} ssl http2"
    if [[ "${NGINX_LOCALHOST_ONLY}" == "y" ]]; then
      HTTP_LISTEN="127.0.0.1:${HTTP_PORT}"
      HTTPS_LISTEN="127.0.0.1:${HTTPS_PORT} ssl http2"
    fi

    cat > "${NGINX_CONF}" <<NGINXCONF
upstream app_upstream {
  server app:${APP_HOST_PORT};
  keepalive 32;
}

server {
  listen ${HTTP_LISTEN};
  server_name ${SERVER_NAME};

  location /.well-known/acme-challenge/ {
    root /var/www/certbot;
    try_files \$uri =404;
  }

  location / {
    return 301 ${HTTPS_REDIRECT_URL};
  }
}

server {
  listen ${HTTPS_LISTEN};
  server_name ${SERVER_NAME};

  ssl_certificate     ${TLS_CERT_PATH};
  ssl_certificate_key ${TLS_KEY_PATH};
${CHAIN_DIRECTIVE}
  ssl_protocols TLSv1.2 TLSv1.3;
  ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305';
  ssl_prefer_server_ciphers off;
  ssl_session_cache shared:SSL:10m;
  ssl_session_timeout 10m;
  ssl_session_tickets off;

  add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
  add_header X-Frame-Options "SAMEORIGIN" always;
  add_header X-Content-Type-Options "nosniff" always;
  add_header X-XSS-Protection "1; mode=block" always;
  add_header Referrer-Policy "strict-origin-when-cross-origin" always;
  add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';" always;

  client_max_body_size 5m;

  location /health {
    proxy_pass http://app_upstream;
    proxy_set_header Host \$host;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
  }

  location ~ ^/(crowdsec|misp|indicators) {
    proxy_pass http://app_upstream;
    proxy_set_header Host \$host;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
  }

  location / {
    proxy_pass http://app_upstream;
    proxy_set_header Host \$host;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_read_timeout 300;
    proxy_buffering off;
  }
}
NGINXCONF
  else
    # HTTP-only nginx (plain proxy, no TLS)
    HTTP_LISTEN="${HTTP_PORT}"
    [[ "${NGINX_LOCALHOST_ONLY}" == "y" ]] && HTTP_LISTEN="127.0.0.1:${HTTP_PORT}"

    cat > "${NGINX_CONF}" <<NGINXCONF
upstream app_upstream {
  server app:${APP_HOST_PORT};
  keepalive 32;
}

server {
  listen ${HTTP_LISTEN};
  server_name ${SERVER_NAME};

  client_max_body_size 5m;

  location / {
    proxy_pass http://app_upstream;
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_read_timeout 300;
    proxy_buffering off;
  }
}
NGINXCONF
  fi
  success "nginx config written to ${NGINX_CONF}"
fi

# ── Step 5: Update .env ───────────────────────────────────────────────────────
info "Step 5 — Updating ${ENV_FILE}"

# Deployment keys updated by this installer.
APP_PORT_BIND="${APP_HOST_PORT}"
[[ "${APP_LOCALHOST_ONLY}" == "y" ]] && APP_PORT_BIND="127.0.0.1:${APP_HOST_PORT}"

set_env_key "APP_HOST_PORT" "${APP_HOST_PORT}"
set_env_key "APP_PORT_BIND" "${APP_PORT_BIND}"
set_env_key "USE_NGINX_SETUP" "${USE_NGINX}"

if [[ "${USE_NGINX}" == "y" ]]; then
  set_env_key "HTTP_PORT" "${HTTP_PORT}"
  set_env_key "HTTPS_PORT" "${HTTPS_PORT}"
  set_env_key "SERVER_NAME" "${SERVER_NAME}"
  set_env_key "NGINX_LOCALHOST_ONLY" "${NGINX_LOCALHOST_ONLY}"
  set_env_key "TLS_ENABLED" "${TLS_ENABLED}"
  [[ -n "${TLS_CERT_PATH}" ]]  && set_env_key "TLS_CERT_PATH"  "${TLS_CERT_PATH}"
  [[ -n "${TLS_KEY_PATH}" ]]   && set_env_key "TLS_KEY_PATH"   "${TLS_KEY_PATH}"
  [[ -n "${TLS_CHAIN_PATH}" ]] && set_env_key "TLS_CHAIN_PATH" "${TLS_CHAIN_PATH}"
fi

success ".env updated"

# ── Step 6: Summary and next steps ────────────────────────────────────────────
echo ""
printf "${BOLD}═══════════════ Setup complete ═══════════════${RESET}\n"
echo ""
echo "  Mode       : $([ "${USE_NGINX}" == 'y' ] && echo 'nginx reverse proxy' || echo 'direct')"
echo "  App port   : ${APP_HOST_PORT}$([ "${APP_LOCALHOST_ONLY}" == 'y' ] && echo ' (localhost only)')"
if [[ "${USE_NGINX}" == "y" ]]; then
  echo "  HTTP port  : ${HTTP_PORT}$([ "${NGINX_LOCALHOST_ONLY}" == 'y' ] && echo ' (localhost only)')"
  echo "  HTTPS port : ${HTTPS_PORT}$([ "${NGINX_LOCALHOST_ONLY}" == 'y' ] && echo ' (localhost only)')"
  echo "  Server     : ${SERVER_NAME}"
  echo "  TLS        : $([ "${TLS_ENABLED}" == 'y' ] && echo 'enabled' || echo 'disabled')"
fi
echo ""
echo "Next steps:"
if [[ "${USE_NGINX}" == "y" ]]; then
  echo "  1. Review nginx/conf.d/default.conf"
  echo "  2. docker compose --profile edge up -d"
else
  echo "  1. docker compose up -d"
fi
echo "  2. docker compose run --rm migrate"
_scheme="http"; [[ "${TLS_ENABLED}" == "y" ]] && _scheme="https"
if [[ "${USE_NGINX}" == "y" ]]; then
  _display_host="${SERVER_NAME}"
  _port="${HTTPS_PORT:-${HTTP_PORT}}"
  # Standard ports don't need to appear in the URL
  if [[ "${_scheme}" == "https" && "${_port}" == "443" ]] \
     || [[ "${_scheme}" == "http"  && "${_port}" == "80"  ]]; then
    echo "  3. Open ${_scheme}://${_display_host}/health"
  else
    echo "  3. Open ${_scheme}://${_display_host}:${_port}/health"
  fi
else
  echo "  3. Open ${_scheme}://localhost:${APP_HOST_PORT}/health"
fi
echo ""

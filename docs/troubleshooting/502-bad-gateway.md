# Troubleshooting: 502 Bad Gateway

This guide covers the most common causes of 502 errors in the
`Client → F5 → Nginx (HTTPS:7004) → app (HTTP:8004)` stack and provides
step-by-step diagnosis and fixes.

---

## Quick triage

```bash
# 1. Is the app process listening?
ss -lntp | grep :8004

# 2. Can Nginx reach the app directly?
curl -sv http://127.0.0.1:8004/healthz

# 3. Is the container running?
docker compose ps app
docker compose logs --tail=50 app

# 4. Nginx error log
tail -f /var/log/nginx/error.log | grep -E "connect\(\) failed|upstream timed out|no live upstreams"
```

Expected output for a healthy app:

```
# ss output
LISTEN  0  128  0.0.0.0:8004  ...

# curl /healthz
HTTP/1.1 200 OK
{"status":"ok"}
```

---

## Cause 1: App process not running / not listening

**Symptoms:** `ss -lntp | grep :8004` returns nothing. Nginx log:
```
connect() failed (111: Connection refused) while connecting to upstream
```

**Fix:**
```bash
docker compose up -d app
docker compose logs --tail=100 app     # look for startup errors
```

Common startup failures:
- `SECRET_KEY` not set or too short → set `SECRET_KEY` env var (≥ 32 chars)
- DB connection refused at startup → ensure `postgres` container is healthy first
- Port conflict → check `APP_PORT` env var matches Nginx upstream config

---

## Cause 2: Wrong port in Nginx upstream

**Symptoms:** App is listening but Nginx still returns 502. Nginx log:
```
connect() failed (111: Connection refused) while connecting to upstream, server: 127.0.0.1:8080
```

Note the port mismatch — app listens on `8004` but Nginx sends to `8080`.

**Fix:** Check Nginx config:
```nginx
upstream app {
    server 127.0.0.1:8004;   # must match APP_PORT
}
```

After changing:
```bash
nginx -t && nginx -s reload
```

---

## Cause 3: SELinux blocking Nginx → app proxy connections (RHEL / CentOS)

**Symptoms:** App reachable via `curl http://127.0.0.1:8004/healthz` from the host,
but Nginx returns 502. `ausearch` shows AVC denials.

**Diagnose:**
```bash
# Check for recent SELinux denials
ausearch -m AVC -ts recent | grep nginx

# Check allowed http_port_t ports
semanage port -l | grep http_port_t
```

**Fix (option A) — add port to http_port_t:**
```bash
semanage port -a -t http_port_t -p tcp 8004
```

**Fix (option B) — allow httpd network connect globally:**
```bash
setsebool -P httpd_can_network_connect 1
```

Prefer option A (narrower scope). Apply option B only when A is insufficient (e.g., dynamic port ranges).

After applying, reload Nginx:
```bash
nginx -s reload
```

---

## Cause 4: F5 monitor configuration

F5 health monitors that check `/health` or `/readyz` with slow external dependency checks
can trigger false-positive outages. Use `/healthz` for all F5 liveness monitors.

**F5 HTTP monitor settings:**

| Field | Value |
|---|---|
| Send String | `GET /healthz HTTP/1.0\r\nHost: <app-hostname>\r\nConnection: Close\r\n\r\n` |
| Receive String | `{"status":"ok"}` |
| Interval | `5` s |
| Timeout | `16` s |
| Expected Response Code | `200` |

**Why `/healthz` not `/health`:**
- `/healthz` — no external calls, always < 50 ms, returns 200 as long as the process is alive
- `/health` — checks DB + Redis, reads MISP dep cache; slower and can return non-200 on infra issues
- `/readyz` — returns 503 when DB/Redis unreachable; correct for readiness, not liveness

**F5 SNI / Host header:**
If Nginx requires the `Host` header to match a `server_name`, include it in the Send String.
For IP-based virtual servers, `Host: localhost` is usually sufficient.

---

## Cause 5: Nginx upstream keepalive / connection pool exhaustion

**Symptoms:** 502 occurs under load, not at startup. Nginx log:
```
upstream timed out (110: Connection timed out) while reading response header from upstream
```

**Fix:**
```nginx
upstream app {
    server 127.0.0.1:8004;
    keepalive 32;
}

server {
    location / {
        proxy_pass http://app;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_read_timeout 120s;
        proxy_connect_timeout 10s;
    }
}
```

Also tune Gunicorn workers: `WORKERS=$(( 2 * CPU_CORES + 1 ))`.

---

## Cause 6: App crashed / OOM killed

**Symptoms:** App was running, 502 appeared suddenly. `docker compose ps` shows `app` exited.

```bash
docker compose logs --tail=200 app | grep -E "OOM|Killed|Error|Exception"
dmesg | grep -i "oom\|killed" | tail -20
```

**Fix:** Increase container memory limit or reduce `WORKERS`/`DB_POOL_SIZE`.

---

## See also

- [DEPLOYMENT.md](../../DEPLOYMENT.md) — production deployment guide
- [docs/runbook.md](../runbook.md) — operational runbook
- [docs/api.md](../api.md) — `/healthz`, `/readyz`, `/deps` endpoint reference
- GitHub issue #68

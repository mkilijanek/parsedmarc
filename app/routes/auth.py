from __future__ import annotations

import hmac
import secrets
from urllib.parse import quote

from flask import Response, redirect, request, session, url_for


ROLE_PERMISSIONS = {
    "admin": {
        "admin:read",
        "feed:configure",
        "feed:sync",
        "indicator:read",
        "indicator:export",
        "logs:view",
        "audit:view",
        "system:dangerous",
    },
    "operator": {
        "admin:read",
        "feed:sync",
        "indicator:read",
        "indicator:export",
        "logs:view",
        "audit:view",
    },
    "viewer": {
        "admin:read",
        "indicator:read",
        "logs:view",
    },
}


def auth_surface_request_is_secure() -> bool:
    forwarded_proto = (request.headers.get("X-Forwarded-Proto") or "").split(",")[0].strip().lower()
    return bool(request.is_secure or forwarded_proto == "https")


def canonical_https_url(cfg, target_path: str | None = None) -> str:
    request_host = (request.host or "").strip()
    request_host_name = request_host.split(":", 1)[0] if request_host else "localhost"
    host = (getattr(cfg, "CANONICAL_HTTPS_HOST", "") or "").strip() or request_host_name
    https_port = int(getattr(cfg, "HTTPS_PORT", 7003) or 7003)
    path = target_path or request.full_path.rstrip("?") or request.path or "/"
    if not path.startswith("/"):
        path = f"/{path}"
    default_https_port = 443
    netloc = host if https_port == default_https_port else f"{host}:{https_port}"
    return f"https://{netloc}{path}"


def should_redirect_auth_surface_to_https(cfg) -> bool:
    if auth_surface_request_is_secure():
        return False
    path = request.path or ""
    if not (path.startswith("/auth/") or path.startswith("/admin")):
        return False
    request_host = (request.host or "").strip()
    if ":" not in request_host:
        return False
    _, request_port = request_host.rsplit(":", 1)
    try:
        incoming_port = int(request_port)
    except ValueError:
        return False
    app_port = int(getattr(cfg, "APP_HOST_PORT", 7005) or 7005)
    https_port = int(getattr(cfg, "HTTPS_PORT", 7003) or 7003)
    return incoming_port == app_port and incoming_port != https_port


def register_auth_routes(app, *, limiter, cfg) -> None:
    def _ensure_admin_csrf_token() -> str:
        token = str(session.get("admin_csrf_token") or "").strip()
        if not token:
            token = secrets.token_urlsafe(32)
            session["admin_csrf_token"] = token
        return token

    def _admin_auth_configured() -> bool:
        return bool((cfg.ADMIN_API_TOKEN or "").strip())

    def _admin_authenticated() -> bool:
        return bool(session.get("admin_authenticated"))

    def _admin_role() -> str:
        role = str(session.get("admin_role") or "").strip().lower()
        return role if role in ROLE_PERMISSIONS else "viewer"

    def _has_permission(permission: str) -> bool:
        return permission in ROLE_PERMISSIONS.get(_admin_role(), set())

    def _permission_for_admin_request() -> str:
        path = request.path
        if path.startswith("/admin/danger"):
            return "system:dangerous"
        if path.startswith("/admin/audit"):
            return "audit:view"
        if path.startswith("/admin/sync") or "/sync-jobs/" in path:
            return "feed:sync"
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            return "feed:configure"
        return "admin:read"

    @app.before_request
    def _redirect_auth_surface_to_https():
        if not should_redirect_auth_surface_to_https(cfg):
            return None
        target = canonical_https_url(cfg)
        status_code = 307 if request.method not in {"GET", "HEAD", "OPTIONS"} else 302
        return redirect(target, code=status_code)

    @app.before_request
    def _require_admin_session():
        if not request.path.startswith("/admin"):
            return None
        if _admin_authenticated():
            permission = _permission_for_admin_request()
            if not _has_permission(permission):
                return Response("Forbidden: insufficient role permissions.", status=403)
            if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
                expected = _ensure_admin_csrf_token()
                provided = (
                    (request.form.get("csrf_token") or "").strip()
                    or (request.headers.get("X-CSRF-Token") or "").strip()
                )
                if not provided or not hmac.compare_digest(provided, expected):
                    return Response("CSRF validation failed.", status=400)
            return None
        next_url = request.full_path if request.query_string else request.path
        return redirect(url_for("auth_login", next=next_url.rstrip("?")))

    @app.after_request
    def _inject_admin_csrf(response: Response) -> Response:
        if request.method != "GET" or not request.path.startswith("/admin"):
            return response
        if response.status_code >= 400:
            return response
        content_type = (response.headers.get("Content-Type") or "").lower()
        if "text/html" not in content_type:
            return response
        body = response.get_data(as_text=True)
        if not body:
            return response
        token = _ensure_admin_csrf_token()
        script = (
            "<script>"
            f"window.__adminCsrfToken={token!r};"
            "document.querySelectorAll(\"form\").forEach(function(form){"
            "var method=(form.getAttribute('method')||'get').toLowerCase();"
            "if(method!=='post'){return;}"
            "if(form.querySelector('input[name=\"csrf_token\"]')){return;}"
            "var input=document.createElement('input');"
            "input.type='hidden';"
            "input.name='csrf_token';"
            "input.value=window.__adminCsrfToken;"
            "form.appendChild(input);"
            "});"
            "</script>"
        )
        if "</body>" in body:
            body = body.replace("</body>", script + "</body>")
        else:
            body = body + script
        response.set_data(body)
        return response

    @app.get("/auth/login")
    @limiter.limit(cfg.ADMIN_LOGIN_RATE_LIMIT)
    def auth_login():
        next_url = (request.args.get("next") or "/admin").strip() or "/admin"
        msg = (request.args.get("msg") or "").strip()
        configured = _admin_auth_configured()
        canonical_url = canonical_https_url(cfg, f"/auth/login?next={quote(next_url, safe='/?:=&')}")
        https_hint = ""
        if should_redirect_auth_surface_to_https(cfg):
            https_hint = (
                "<p><strong>Use the HTTPS admin entrypoint.</strong> "
                f"<a href=\"{canonical_url}\">{canonical_url}</a></p>"
            )
        disabled_note = (
            "<p><strong>Admin authentication is not configured.</strong> "
            "Set <code>ADMIN_API_TOKEN</code> before using the admin panel.</p>"
            if not configured
            else ""
        )
        message_html = f"<p style='color:#b00020'>{msg}</p>" if msg else ""
        escaped_next = quote(next_url, safe="/:?=&")
        return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Admin Login</title>
  <style>
    body {{ font-family: sans-serif; margin: 2rem; max-width: 32rem; }}
    form {{ display: grid; gap: .75rem; }}
    input {{ padding: .6rem; }}
    button {{ padding: .7rem 1rem; }}
    code {{ background: #f3f3f3; padding: .1rem .25rem; }}
  </style>
</head>
<body>
  <h1>Admin Login</h1>
  <p>Authenticate with the configured admin token to access <code>/admin</code>.</p>
  {disabled_note}
  {https_hint}
  {message_html}
  <form method="post" action="/auth/login">
    <input type="hidden" name="next" value="{escaped_next}">
    <label for="admin_token">Admin token</label>
    <input id="admin_token" type="password" name="admin_token" autocomplete="current-password" required>
    <button type="submit">Login</button>
  </form>
</body>
</html>"""

    @app.post("/auth/login")
    @limiter.limit(cfg.ADMIN_LOGIN_RATE_LIMIT)
    def auth_login_post():
        next_url = (request.form.get("next") or "/admin").strip() or "/admin"
        expected = (cfg.ADMIN_API_TOKEN or "").strip()
        provided = (request.form.get("admin_token") or "").strip()
        if not expected:
            return redirect(url_for("auth_login", next=next_url, msg="Admin authentication is not configured."))
        if not hmac.compare_digest(provided, expected):
            session.clear()
            return redirect(url_for("auth_login", next=next_url, msg="Invalid admin token."))
        session.clear()
        session.permanent = True
        session["admin_authenticated"] = True
        session["admin_user_id"] = "admin"
        configured_role = str(getattr(cfg, "ADMIN_ROLE", "admin") or "admin").strip().lower()
        session["admin_role"] = configured_role if configured_role in ROLE_PERMISSIONS else "admin"
        session["admin_csrf_token"] = secrets.token_urlsafe(32)
        return redirect(next_url if next_url.startswith("/") else "/admin")

    @app.post("/auth/logout")
    def auth_logout():
        session.clear()
        return redirect(url_for("auth_login", msg="Logged out."))

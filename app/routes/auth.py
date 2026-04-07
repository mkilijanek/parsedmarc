from __future__ import annotations

import hmac
import secrets
from urllib.parse import quote

from flask import Response, redirect, request, session, url_for


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

    @app.before_request
    def _require_admin_session():
        if not request.path.startswith("/admin"):
            return None
        if _admin_authenticated():
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
    @limiter.limit("5 per 15 minute")
    def auth_login():
        next_url = (request.args.get("next") or "/admin").strip() or "/admin"
        msg = (request.args.get("msg") or "").strip()
        configured = _admin_auth_configured()
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
    @limiter.limit("5 per 15 minute")
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
        session["admin_role"] = "admin"
        session["admin_csrf_token"] = secrets.token_urlsafe(32)
        return redirect(next_url if next_url.startswith("/") else "/admin")

    @app.post("/auth/logout")
    def auth_logout():
        session.clear()
        return redirect(url_for("auth_login", msg="Logged out."))

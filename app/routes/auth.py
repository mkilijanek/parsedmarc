from __future__ import annotations

import hmac
from urllib.parse import quote

from flask import redirect, request, session, url_for


def register_auth_routes(app, *, limiter, cfg) -> None:
    def _admin_auth_configured() -> bool:
        return bool((cfg.ADMIN_API_TOKEN or "").strip())

    def _admin_authenticated() -> bool:
        return bool(session.get("admin_authenticated"))

    @app.before_request
    def _require_admin_session():
        if not request.path.startswith("/admin"):
            return None
        if _admin_authenticated():
            return None
        next_url = request.full_path if request.query_string else request.path
        return redirect(url_for("auth_login", next=next_url.rstrip("?")))

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
        return redirect(next_url if next_url.startswith("/") else "/admin")

    @app.post("/auth/logout")
    def auth_logout():
        session.clear()
        return redirect(url_for("auth_login", msg="Logged out."))

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict

from flask import jsonify, render_template, request
from sqlalchemy import select


def register_logs_routes(
    app,
    *,
    limiter,
    cfg,
    logger: logging.Logger,
    deps: Dict[str, Any],
) -> None:
    _db = deps["_db"]
    AppLog = deps["AppLog"]

    @app.get("/api/logs")
    @limiter.limit("60 per minute")
    def api_logs():
        db = _db(read_only=True)
        try:
            stmt = select(AppLog).order_by(AppLog.created_at.desc())
            feed = (request.args.get("feed") or "").strip()
            job_id = (request.args.get("job_id") or request.args.get("run_id") or "").strip()
            level = (request.args.get("level") or "").strip().upper()
            component = (request.args.get("component") or "").strip()
            since = (request.args.get("since") or "").strip()
            until = (request.args.get("until") or "").strip()
            if feed:
                stmt = stmt.where(AppLog.feed_source_id == feed)
            if job_id:
                stmt = stmt.where(AppLog.run_id == job_id)
            if level:
                levels = [l.strip() for l in level.replace(",", "|").split("|") if l.strip()]
                if len(levels) == 1:
                    stmt = stmt.where(AppLog.level == levels[0])
                else:
                    stmt = stmt.where(AppLog.level.in_(levels))
            if component:
                stmt = stmt.where(AppLog.component == component)
            if since:
                try:
                    stmt = stmt.where(AppLog.created_at >= datetime.fromisoformat(since.replace("Z", "+00:00")))
                except ValueError:
                    pass
            if until:
                try:
                    stmt = stmt.where(AppLog.created_at <= datetime.fromisoformat(until.replace("Z", "+00:00")))
                except ValueError:
                    pass
            limit = min(500, max(1, int(request.args.get("limit", "200"))))
            rows = list(db.scalars(stmt.limit(limit)).all())
            return jsonify(
                {
                    "count": len(rows),
                    "items": [
                        {
                            "created_at": str(r.created_at),
                            "level": r.level,
                            "component": r.component,
                            "message": r.message,
                            "feed_source_id": r.feed_source_id,
                            "run_id": r.run_id,
                            "metadata": r.metadata_,
                        }
                        for r in rows
                    ],
                }
            )
        finally:
            db.close()

    @app.get("/logs")
    @limiter.limit("30 per minute")
    def logs_page():
        return render_template("logs.html")

    # Legacy inline HTML - migrated to logs.html template above
    _ = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/><title>Logs</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 0; padding: 0 1.5rem 1.5rem; background: var(--bg); color: var(--fg); }
  body[data-theme="light"] { --bg: #f8fafc; --fg: #0f172a; --card: #ffffff; --line: #dbe1ea; }
  body[data-theme="dark"] { --bg: #0f172a; --fg: #e2e8f0; --card: #111827; --line: #334155; }
  body:not([data-theme]) { --bg: #f8fafc; --fg: #0f172a; --card: #ffffff; --line: #dbe1ea; }
  .topbar { display:flex; justify-content:space-between; align-items:center; gap:1rem; padding:.8rem 0; margin-bottom:1rem; border-bottom:1px solid var(--line); }
  .topbar nav a { margin-right:.8rem; }
  .card { border:1px solid var(--line); border-radius:12px; padding:1rem; background:var(--card); }
  input, button { border:1px solid var(--line); border-radius:8px; padding:.4rem .5rem; background:var(--bg); color:var(--fg); }
  label { display:inline-block; margin: .2rem .6rem .2rem 0; }
  pre { white-space: pre-wrap; border:1px solid var(--line); padding:10px; min-height:300px; background:var(--card); }
</style></head><body>
<header class="topbar" id="globalTopbar">
  <nav>
    <a href="/">Overview</a>
    <a href="/indicators">Indicators</a>
    <a href="/admin">Admin</a>
    <a href="/logs">Logs</a>
  </nav>
  <button type="button" id="themeToggleGlobal">Toggle dark mode</button>
</header>
<div class="card">
<h1>Logs</h1><p><a href="/admin">Back to admin</a></p>
<form id="filters">
  <label>Feed <input name="feed" /></label>
  <label>Job ID <input name="job_id" /></label>
  <label>Level <input name="level" placeholder="INFO|WARN|ERROR" /></label>
  <label>Component <input name="component" placeholder="scheduler|fetcher|parser|exporter" /></label>
  <label>Since <input name="since" placeholder="2026-02-26T00:00:00Z" /></label>
  <label>Until <input name="until" placeholder="2026-02-26T23:59:59Z" /></label>
  <label><input type="checkbox" id="autorefresh" checked/> auto-refresh</label>
  <button type="submit">Apply</button>
  <button type="button" id="copyBtn">Copy all visible logs</button>
  <button type="button" id="downloadBtn">Download visible .log</button>
</form>
<p id="copyStatus" role="status" aria-live="polite"></p>
<pre id="out"></pre>
</div>
<script>
const themeKey = 'ioc-theme';
const preferredTheme = localStorage.getItem(themeKey);
if (preferredTheme === 'dark' || preferredTheme === 'light') {
  document.body.setAttribute('data-theme', preferredTheme);
} else {
  const systemDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
  document.body.setAttribute('data-theme', systemDark ? 'dark' : 'light');
}
const themeToggle = document.getElementById('themeToggleGlobal');
if (themeToggle) {
  themeToggle.addEventListener('click', () => {
    const curr = document.body.getAttribute('data-theme') || 'light';
    const next = curr === 'dark' ? 'light' : 'dark';
    document.body.setAttribute('data-theme', next);
    localStorage.setItem(themeKey, next);
  });
}
let visibleRows = [];
function setCopyStatus(message, kind){
  const el = document.getElementById('copyStatus');
  if (!el) return;
  el.textContent = message || '';
  el.style.color = kind === 'error' ? '#b91c1c' : '#047857';
}
function buildQuery(){const fd=new FormData(document.getElementById('filters'));const p=new URLSearchParams();for(const [k,v] of fd.entries()){if((v||'').trim())p.set(k,v);}p.set('limit','200');return p.toString();}
function formatLine(x){return `[${x.created_at}] ${x.level} ${x.component} ${x.feed_source_id||'-'} ${x.run_id||'-'} ${x.message} ${JSON.stringify(x.metadata||{})}`;}
function buildVisibleText(){
  const lines = (visibleRows || []).map(formatLine);
  return lines.join('\\n');
}
function fallbackCopyText(payload){
  const ta = document.createElement('textarea');
  ta.value = payload;
  ta.setAttribute('readonly', '');
  ta.style.position = 'fixed';
  ta.style.top = '-9999px';
  ta.style.left = '-9999px';
  document.body.appendChild(ta);
  ta.focus();
  ta.select();
  let ok = false;
  try { ok = document.execCommand('copy'); } catch (_) { ok = false; }
  document.body.removeChild(ta);
  return ok;
}
async function copyVisibleLogs(){
  const payload = buildVisibleText();
  const lineCount = payload ? payload.split('\\n').length : 0;
  if (!payload) {
    setCopyStatus('No visible logs to copy.', 'error');
    return;
  }
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(payload);
      setCopyStatus(`Copied ${lineCount} lines.`, 'ok');
      return;
    }
  } catch (err) {
  }
  const copied = fallbackCopyText(payload);
  if (copied) {
    setCopyStatus(`Copied ${lineCount} lines (fallback).`, 'ok');
  } else {
    setCopyStatus('Copy failed. Use HTTPS/focused tab or copy manually.', 'error');
  }
}
function downloadVisibleLogs(){
  const payload = buildVisibleText();
  if (!payload) {
    setCopyStatus('No visible logs to download.', 'error');
    return;
  }
  const blob = new Blob([payload + '\\n'], {type: 'text/plain;charset=utf-8'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  const ts = new Date().toISOString().replace(/[:]/g, '-');
  a.href = url;
  a.download = `visible-logs-${ts}.log`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  setCopyStatus(`Downloaded ${(visibleRows || []).length} lines.`, 'ok');
}
async function refreshLogs(){
  const q=buildQuery();
  try {
    const r=await fetch('/api/logs?'+q);
    const d=await r.json();
    visibleRows = d.items || [];
    const lines=visibleRows.map(formatLine);
    document.getElementById('out').textContent=lines.length ? lines.join('\\n') : 'No logs found for current filters.';
  } catch (err) {
    visibleRows = [];
    document.getElementById('out').textContent='Failed to load logs.';
    setCopyStatus('Failed to refresh logs.', 'error');
  }
}
document.getElementById('filters').addEventListener('submit',(e)=>{e.preventDefault();refreshLogs();});
document.getElementById('copyBtn').addEventListener('click',copyVisibleLogs);
document.getElementById('downloadBtn').addEventListener('click',downloadVisibleLogs);
setInterval(()=>{if(document.getElementById('autorefresh').checked)refreshLogs();},5000);refreshLogs();
</script></body></html>"""  # noqa: F841

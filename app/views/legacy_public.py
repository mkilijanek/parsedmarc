from __future__ import annotations

from typing import Any
from urllib.parse import urlencode

from flask import render_template

from ..models import Indicator

STARTUP_LOADER_STYLE = """
    .startup-loader { position: fixed; inset: 0; z-index: 9999; background: radial-gradient(circle at 20% 20%, #103040 0%, rgba(16,48,64,.55) 35%, transparent 70%), radial-gradient(circle at 80% 0%, #2a1f3f 0%, rgba(42,31,63,.45) 35%, transparent 70%), #05090f; display: flex; align-items: center; justify-content: center; padding: 20px; transition: opacity .35s ease, visibility .35s ease; }
    .startup-loader.done { opacity: 0; visibility: hidden; }
    .startup-loader-card { position: relative; overflow: hidden; width: min(560px, 94vw); border: 1px solid #224b63; background: linear-gradient(180deg, #071523 0%, #0a1520 100%); border-radius: 16px; padding: 22px 20px; box-shadow: 0 20px 50px rgba(0,0,0,.45); }
    .startup-loader-card h2 { margin: 0 0 8px; color: #9cecff; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; letter-spacing: .08em; text-transform: uppercase; }
    .startup-loader-card p { margin: 0 0 14px; color: #b5d7e8; font-size: 14px; }
    .startup-loader-grid { position: absolute; inset: -200% -50% auto -50%; height: 220%; background: repeating-linear-gradient(90deg, rgba(40,176,255,.08) 0, rgba(40,176,255,.08) 1px, transparent 1px, transparent 22px), repeating-linear-gradient(0deg, rgba(40,176,255,.06) 0, rgba(40,176,255,.06) 1px, transparent 1px, transparent 22px); transform: perspective(380px) rotateX(68deg); opacity: .65; }
    .startup-loader-scan { position: absolute; left: 0; right: 0; top: -40%; height: 38%; background: linear-gradient(180deg, rgba(76,208,255,0), rgba(76,208,255,.22), rgba(76,208,255,0)); animation: loader-scan 2.1s linear infinite; }
    .startup-loader-progress { position: relative; height: 8px; border: 1px solid #2d6486; background: #05131d; border-radius: 999px; overflow: hidden; }
    .startup-loader-progress span { display: block; height: 100%; width: 0; background: linear-gradient(90deg, #37dcff, #7effc8); box-shadow: 0 0 16px rgba(55,220,255,.8); transition: width .16s ease; }
    @keyframes loader-scan { 0% { transform: translateY(0); } 100% { transform: translateY(300%); } }
"""

STARTUP_LOADER_MARKUP = """
<div id="startupLoader" class="startup-loader" aria-live="polite" aria-label="Application startup in progress">
  <div class="startup-loader-card">
    <div class="startup-loader-grid" aria-hidden="true"></div>
    <div class="startup-loader-scan" aria-hidden="true"></div>
    <h2>IOC Service</h2>
    <p>Booting modules, validating feeds, preparing data plane...</p>
    <div class="startup-loader-progress"><span id="startupLoaderBar"></span></div>
  </div>
</div>
"""

STARTUP_LOADER_SCRIPT = """
(function () {
  const loader = document.getElementById('startupLoader');
  const bar = document.getElementById('startupLoaderBar');
  if (!loader || !bar) { return; }
  const startedAt = Date.now();
  let done = false;
  let width = 10;
  const tick = window.setInterval(function () {
    if (done) { return; }
    width = Math.min(92, width + Math.random() * 7);
    bar.style.width = width.toFixed(1) + '%';
  }, 120);
  function finish() {
    if (done) { return; }
    done = true;
    const minVisibleMs = 400;
    const remaining = Math.max(0, minVisibleMs - (Date.now() - startedAt));
    window.setTimeout(function () {
      bar.style.width = '100%';
      loader.classList.add('done');
      window.setTimeout(function () {
        loader.remove();
      }, 450);
      window.clearInterval(tick);
    }, remaining);
  }
  const timeout = window.setTimeout(finish, 3500);
  fetch('/health', { cache: 'no-store' })
    .then(function () { finish(); })
    .catch(function () { finish(); })
    .finally(function () { window.clearTimeout(timeout); });
  window.addEventListener('load', finish, { once: true });
})();
"""


def _esc(s: str) -> str:
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def _badge(label: str, cls: str, aria: str) -> str:
    return f"<span class='badge {cls}' aria-label='{_esc(aria)}'>{_esc(label)}</span>"


def render_index(total: int, active: int, feeds: list[Any]) -> str:
    return render_template(
        "legacy/index.html",
        total=total,
        active=active,
        feeds=list(feeds),
        startup_loader_style=STARTUP_LOADER_STYLE,
        startup_loader_markup=STARTUP_LOADER_MARKUP,
        startup_loader_script=STARTUP_LOADER_SCRIPT,
    )


def render_indicators(
    rows: list[Indicator],
    *,
    q: str | None,
    type_filter: str,
    tlp: str,
    source: str,
    min_conf: int | None,
    max_conf: int | None,
    limit: int,
    offset: int,
    total_count: int,
    source_options: list[str],
) -> str:
    def _query_escape(value: str) -> str:
        return (value or "").replace("\\", "\\\\").replace('"', '\\"')

    def type_badge(t: str) -> str:
        cls = {"ip": "b-ip", "domain": "b-domain", "url": "b-url", "hash": "b-hash", "email": "b-email"}.get(t, "b-other")
        return _badge(t, cls, f"Type {t}")

    def tlp_badge(t: str) -> str:
        cls = {"WHITE": "b-white", "GREEN": "b-green", "AMBER": "b-amber", "RED": "b-red"}.get(t, "b-green")
        return _badge(t, cls, f"TLP {t}")

    view_rows: list[dict[str, Any]] = []
    for ind in rows:
        conf = int(ind.confidence or 0)
        misp_link = ""
        if ind.source == "misp" and ind.source_id:
            misp_link = f"<a href='/misp/event/{_esc(ind.source_id)}' aria-label='Open MISP event {ind.source_id}'>Event {ind.source_id}</a>"

        if ind.source == "misp" and ind.source_id:
            exports = " ".join(
                [
                    f"<a href='/misp/event/{_esc(ind.source_id)}/{_esc(ind.type)}/{fmt}' aria-label='Export MISP event indicator in {fmt} format'>{fmt.upper()}</a>"
                    for fmt in ("csv", "txt", "json", "fortigate")
                ]
            )
        else:
            q_row = f'value:"{_query_escape(ind.value)}" AND source:"{_query_escape(ind.source)}"'
            exports = " ".join(
                [
                    f"<a href='/indicators/{fmt}?{_esc(urlencode({'q': q_row}))}' aria-label='Export indicator in {fmt} format'>{fmt.upper()}</a>"
                    for fmt in ("txt", "csv", "json", "fortigate")
                ]
            )

        view_rows.append(
            {
                "value": str(ind.value or ""),
                "type_badge": type_badge(ind.type),
                "confidence": conf,
                "tlp_badge": tlp_badge(ind.tlp),
                "source": str(ind.source or ""),
                "exports": exports,
                "tags": list((ind.tags or [])[:10]),
                "misp_link": misp_link,
            }
        )

    active_query: dict[str, str] = {}
    if q:
        active_query["q"] = q
    if type_filter and type_filter != "all":
        active_query["type"] = type_filter
    if tlp and tlp != "ALL" and tlp != "all":
        active_query["tlp"] = tlp
    if source and source != "all":
        active_query["source"] = source
    if min_conf is not None:
        active_query["min_conf"] = str(min_conf)
    if max_conf is not None:
        active_query["max_conf"] = str(max_conf)
    active_query["limit"] = str(limit)
    active_query["offset"] = str(offset)
    filter_qs = urlencode(active_query)
    filter_suffix = f"?{filter_qs}" if filter_qs else ""
    has_filters = any(k in active_query for k in ("q", "type", "tlp", "source", "min_conf", "max_conf"))
    page = (offset // max(1, limit)) + 1
    total_pages = max(1, (total_count + max(1, limit) - 1) // max(1, limit))
    prev_offset = max(0, offset - limit)
    next_offset = offset + limit

    def _page_link(target_offset: int) -> str:
        qv = dict(active_query)
        qv["offset"] = str(target_offset)
        return "/indicators?" + urlencode(qv)

    prev_link = _page_link(prev_offset)
    next_link = _page_link(next_offset)
    min_conf_options = [{"value": "", "label": "", "match_value": None}] + [
        {"value": str(n), "label": str(n), "match_value": n} for n in [0, 25, 50, 60, 70, 80, 90]
    ]
    max_conf_options = [{"value": "", "label": "", "match_value": None}] + [
        {"value": str(n), "label": str(n), "match_value": n} for n in [100, 90, 80, 70, 60, 50, 25]
    ]
    return render_template(
        "legacy/indicators.html",
        q=q,
        type_filter=type_filter,
        tlp=tlp,
        source=source,
        min_conf=min_conf,
        max_conf=max_conf,
        limit=limit,
        offset=offset,
        total_count=total_count,
        source_options=source_options,
        type_options=["all", "ip", "domain", "url", "hash", "email"],
        tlp_options=["all", "WHITE", "GREEN", "AMBER", "RED"],
        min_conf_options=min_conf_options,
        max_conf_options=max_conf_options,
        has_filters=has_filters,
        page=page,
        total_pages=total_pages,
        next_offset=next_offset,
        prev_link=prev_link,
        next_link=next_link,
        filter_suffix=filter_suffix,
        view_rows=view_rows,
        startup_loader_style=STARTUP_LOADER_STYLE,
        startup_loader_markup=STARTUP_LOADER_MARKUP,
        startup_loader_script=STARTUP_LOADER_SCRIPT,
    )

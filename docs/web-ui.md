# Web UI Documentation

Status: updated for `1.9.x` (2026-05-19).

## Overview

The Web UI provides a browser-based interface for viewing and searching IOCs, managing feeds, monitoring operations, and browsing documentation.

---

## Pages

### Dashboard — `/`

System overview with statistics and quick links.

- Total / active indicator counts
- Feed statistics table with per-source health
- Quick links to export formats
- Dark / light theme toggle (persisted in `localStorage` as `ioc-theme`)

### Indicators — `/indicators`

Kibana-like search interface with multi-field filtering.

**Search & filters:**
- Free-text query with boolean syntax (`type:ip AND confidence:>70 AND tags:apt`)
- Type / TLP / Source dropdowns
- Confidence range (min / max sliders)
- **Time-window** dropdown: `30m`, `1h`, `6h`, `12h`, `24h`, `7d`, `30d`, `2m`, `3m`, `6m`, `1y`, `all` — filters on `last_seen >= now - period`
- Absolute date range: `date_from` / `date_to` HTML5 date pickers
- Autocomplete suggestions in the search box, including `since:*` completions

**Results table columns:** value, type, confidence (bar + hover tooltip showing %), TLP, source, export links, tags, MISP event link.

**Export:** inline per-row export and bulk export in 17 formats from the sidebar.

### Admin — `/admin`

Operational controls for feeds, configuration, and sync jobs.

- Feed management table: enable / disable, configure, run now, view logs per feed
- Feed metrics panel with window selector (24 h / 7 d / 30 d), status chips, fetched-count trend chart, datasource / status / text filters, CSV export
- Global settings: proxy (HTTP / HTTPS / no-proxy / CA bundle / trusted proxy count / skip-TLS flag), MWDB group selection
- Sync job queue viewer with dead-letter queue
- Dangerous operations (wipe, reset) behind confirmation gate

### Logs — `/logs`

Filterable application log viewer.

- Filters: feed, job ID, run ID, log level, component, time range (since / until)
- Live refresh
- Structured log entries with metadata

### Docs — `/docs`

In-app documentation section. See [Architecture](architecture.md) for diagrams, or [API Reference](/docs/api) for interactive Swagger UI.

---

## Keyboard Shortcuts

| Keys | Action |
|------|--------|
| `/` | Focus search box |
| `g` `i` | Go to Indicators |
| `g` `a` | Go to Admin panel |
| `g` `l` | Go to Logs |
| `g` `d` | Go to Docs |
| `r` | Refresh page |
| `?` | Show shortcut help |
| `Esc` | Close / blur |

---

## Search Syntax

```
# Type filter
type:ip
type:domain

# Confidence threshold
confidence:>70
confidence:<40

# TLP
tlp:AMBER

# Tags
tags:apt
tags:malware

# Boolean operators
type:ip AND confidence:>70 AND (tags:apt OR tags:malware)

# Wildcards
value:192.168.*
```

---

## Time Window Filter

The `since` dropdown restricts results to indicators seen within a recent period. It sets `last_seen >= now - period`.

Supported values: `30m`, `1h`, `6h`, `12h`, `24h`, `7d`, `30d`, `2m`, `3m`, `6m`, `1y`. Default: `all` (no restriction).

Absolute range via URL: `?date_from=2026-01-01&date_to=2026-03-31`

---

## Mobile Support

Responsive design with horizontal scroll for table, touch-friendly controls, and a collapsible sidebar navigation in the Docs section.

---

## See Also

- [API Reference](/docs/api) — REST endpoints
- [Configuration](configuration.md) — environment variables
- [Architecture](architecture.md) — application layers

# Web UI Documentation

Status: updated for `1.2.x` (2026-03-02).

## Overview

The Web UI provides a browser-based interface for searching and viewing IOCs with WCAG 2.1 AA accessibility compliance.

---

## Endpoints

### Dashboard: `/`

System overview with statistics and quick links.

**Features:**
- Total/active indicator counts
- Feed statistics table
- Quick links to exports
- Shared dark/light theme toggle with persisted preference

### Indicator Search: `/indicators`

Kibana-like search interface with filters.

**Features:**
- Search input with syntax help
- Type/TLP/Source filters
- Confidence range sliders
- Per-row export links
- Responsive table layout

**Accessibility:**
- ARIA labels on all controls
- Keyboard shortcuts (/ to focus search)
- Skip links
- Semantic HTML
- Screen reader support

---

## Search Interface

### Query Input

Supports Kibana-like syntax:

```
value:192.168.*
type:ip AND confidence:>70
tlp:AMBER OR tlp:RED
```

### Filters

- **Type:** ip, domain, url, hash, email, all
- **TLP:** WHITE, GREEN, AMBER, RED, all
- **Source:** misp, crowdsec, malwarebazaar, mwdb, all
- **Confidence:** Min/Max sliders (0-100)

### Results Table

Columns:
1. Indicator value (monospace)
2. Type (badge)
3. Confidence (progress bar)
4. TLP (badge)
5. Source
6. Export formats
7. Tags
8. MISP Event link (if applicable)

---

## Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `/` | Focus search box |
| `Esc` | Clear search and blur |
| `Tab` | Navigate between controls |

---

## Mobile Support

Responsive design with:
- Horizontal scroll for table
- Touch-friendly buttons
- Readable font sizes
- Optimized layout

---

## Customization

### Theming

Theme is unified across `/`, `/indicators`, `/admin`, `/logs`, and feed config pages.
Preference is stored in browser `localStorage` under key `ioc-theme`.

### Admin Feed Configuration UX

Feed forms include:
- `Save settings`
- `Test connection`
- `Back`
- Disabled/loading button states on submit

**MWDB feed** additionally shows a "My MWDB group" single-select dropdown populated
after a successful connection test. Selecting a group configures `MWDB_MY_GROUP`:
indicators uploaded by members of that group are tagged `TLP:AMBER` instead of the
default `TLP:GREEN`. The selection is persisted in DB settings.

### Admin Proxy Settings

Global admin configuration includes outbound proxy controls:
- `HTTP proxy`
- `HTTPS proxy`
- `No proxy list`
- `Trusted proxy count`
- `Skip TLS certificate verification for outbound HTTP requests (insecure, curl -k equivalent)`

`Skip TLS certificate verification` is intended for troubleshooting only. For production,
prefer proper CA trust (`REQUESTS_CA_BUNDLE`) instead of disabling verification.

### Layout

Modify HTML templates in rendering functions:
- `_render_index()` - Dashboard
- `_render_indicators()` - Search results

---

## See Also

- [API Documentation](api.md) - REST endpoints
- [Architecture](architecture.md) - Web application layer

# Web UI Documentation

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

Edit inline CSS in `app/main.py`:

```python
def _render_indicators(...):
    # CSS variables in <style> block
    # Modify colors, fonts, spacing
```

### Layout

Modify HTML templates in rendering functions:
- `_render_index()` - Dashboard
- `_render_indicators()` - Search results

---

## See Also

- [API Documentation](api.md) - REST endpoints
- [Architecture](architecture.md) - Web application layer

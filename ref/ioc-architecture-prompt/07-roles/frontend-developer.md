# 07 — Frontend Developer

[← Powrót do README](../README.md) | [← Backend Developer](./backend-developer.md) | [Następna: DevOps Engineer →](./devops-engineer.md)

---

## 🎯 Zakres odpowiedzialności

Jako Frontend Developer w projekcie IOC Service jesteś odpowiedzialny za:
- Redesign Web UI z tech-centric na workflow-centric
- Implementację komponentów Jinja2 templates (server-side rendering)
- Accessibility (WCAG 2.1 AA)
- Responsive design (tablet + desktop)
- JavaScript interakcje (vanilla JS / HTMX / Alpine.js)

---

## 🏗️ Component Architecture

### Obecny stan

Aplikacja używa **server-side rendering** (Jinja2 templates) z minimalnym JavaScript. To jest świadoma decyzja — nie wprowadzamy SPA framework (React/Vue) ze względu na:
- Zespół backend-heavy
- Prosta interaktywność (formularze, tabele, filtry)
- SEO nie jest istotne (internal tool)
- SSR + HTMX daje 80% interaktywności SPA przy 20% złożoności

### Docelowa architektura UI

```
app/templates/
├── base.html              # Master layout (nav, sidebar, footer)
├── components/            # Reusable components
│   ├── _table.html        # Data table (sortable, paginated)
│   ├── _badge.html        # Status badge (active, error, etc.)
│   ├── _alert.html        # Flash messages
│   ├── _pagination.html   # Pagination controls
│   ├── _search_bar.html   # Search with autocomplete
│   ├── _feed_card.html    # Feed status card
│   └── _modal.html        # Modal dialog
├── auth/
│   ├── login.html
│   └── profile.html
├── dashboard/
│   ├── index.html         # Main dashboard (KPIs)
│   └── _feed_status.html  # Feed status widget
├── indicators/
│   ├── search.html        # IOC search page
│   ├── detail.html        # IOC detail view
│   └── export.html        # Export dialog
├── admin/
│   ├── feeds.html         # Feed management
│   ├── feed_edit.html     # Feed configuration form
│   ├── users.html         # User management
│   ├── settings.html      # System settings
│   └── audit.html         # Audit log viewer
└── errors/
    ├── 403.html
    ├── 404.html
    └── 500.html
```

### Technologie UI

| Technologia | Rola | Uzasadnienie |
|-------------|------|--------------|
| **Jinja2** | Server-side templates | Już używane, team experience |
| **HTMX** | Partial page updates, AJAX | Minimum JS, progressive enhancement |
| **Alpine.js** | Client-side interakcje | Dropdowns, modals, toggles |
| **TailwindCSS** / Bootstrap 5 | Styling | Utility-first, responsive |
| **Chart.js** | Wykresy na dashboard | Lightweight, no dependencies |

---

## 📐 UX/UI Requirements

### Top 3 Workflows

#### Workflow A: Search & Export IOC

```
┌─────────────────────────────────────────────┐
│  IOC Search                      [Export ▼] │
├─────────────────────────────────────────────┤
│ 🔍 [Search query...               ] [Search]│
│                                              │
│ Filters:                                     │
│ Source: [All ▼] Type: [All ▼] Active: [✓]  │
│ TLP: [All ▼]   Confidence: [≥50    ]       │
│                                              │
│ ┌───┬──────────┬──────┬────┬─────┬────────┐ │
│ │ # │ Value    │ Type │ Src│ Conf│ Last   │ │
│ ├───┼──────────┼──────┼────┼─────┼────────┤ │
│ │ 1 │ 1.2.3.4  │ IP   │MWDB│ 85  │ 2h ago │ │
│ │ 2 │ evil.com │ DOM  │MISP│ 90  │ 1h ago │ │
│ │ 3 │ a1b2c3.. │ HASH │ AB │ 75  │ 5h ago │ │
│ └───┴──────────┴──────┴────┴─────┴────────┘ │
│                                              │
│ Showing 1-50 of 15,432   [< 1 2 3 ... 309 >]│
└─────────────────────────────────────────────┘
```

#### Workflow B: Feed Health Dashboard

```
┌─────────────────────────────────────────────┐
│  Dashboard                                   │
├─────────────────────────────────────────────┤
│                                              │
│ ┌──────────┐ ┌──────────┐ ┌──────────┐     │
│ │ 154,320  │ │   10     │ │  99.7%   │     │
│ │Active IOC│ │  Feeds   │ │  Uptime  │     │
│ └──────────┘ └──────────┘ └──────────┘     │
│                                              │
│ Feed Status:                                 │
│ ┌─────────────┬────────┬──────┬──────────┐  │
│ │ Feed        │ Status │ IOCs │ Last Sync│  │
│ ├─────────────┼────────┼──────┼──────────┤  │
│ │ CrowdSec    │ ✅ OK  │ 45K  │ 5 min    │  │
│ │ MISP        │ ✅ OK  │ 12K  │ 2h       │  │
│ │ MWDB        │ ⚠️ SLOW│ 8K   │ 15 min   │  │
│ │ abuse.ch    │ ✅ OK  │ 89K  │ 30 min   │  │
│ │ Bazaar      │ 🔴 DOWN│ 0    │ 4h ago   │  │
│ └─────────────┴────────┴──────┴──────────┘  │
│                                [Sync All ▶]  │
└─────────────────────────────────────────────┘
```

---

## ♿ Accessibility Requirements (WCAG 2.1 AA)

| Kryterium | Wymaganie | Jak sprawdzić |
|-----------|-----------|---------------|
| **1.1.1** | Alt text dla obrazów | Lighthouse audit |
| **1.4.3** | Kontrast ≥4.5:1 (tekst), ≥3:1 (duży tekst) | axe DevTools |
| **2.1.1** | Keyboard navigation | Tab through all interactive elements |
| **2.4.1** | Skip navigation link | "Skip to content" na top of page |
| **3.3.1** | Error identification | Error messages powiązane z polami |
| **4.1.2** | ARIA labels | Dynamiczne elementy mają role i label |

---

## 🧪 Testing Strategy

| Typ | Narzędzie | Coverage |
|-----|-----------|----------|
| Visual regression | Percy / Playwright screenshots | Kluczowe strony |
| Component testing | Playwright | Tabele, formularze, modals |
| Accessibility | axe-core + Lighthouse | WCAG 2.1 AA |
| Cross-browser | Playwright (Chrome, Firefox) | Desktop + tablet |
| Performance | Lighthouse | Score >90 |

### Browser Compatibility

| Browser | Min Version | Support Level |
|---------|-------------|---------------|
| Chrome | 100+ | ✅ Full |
| Firefox | 100+ | ✅ Full |
| Edge | 100+ | ✅ Full |
| Safari | 16+ | ⚠️ Functional |
| Mobile | N/A | ❌ Out of scope (internal tool) |

---

## 📋 Performance Optimization

1. **Lazy loading** — ładuj tabele danych przez HTMX (partial update)
2. **Debounce search** — 300ms debounce na search input
3. **Pagination** — server-side, max 100 items per page
4. **Asset optimization** — minify CSS/JS, gzip w Nginx
5. **Caching** — ETag headers dla static assets (1 week)

---

[← Backend Developer](./backend-developer.md) | [Następna: DevOps Engineer →](./devops-engineer.md)

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from flask import abort, make_response, render_template, send_file
from markdown_it import MarkdownIt

_REPO_ROOT = Path(__file__).resolve().parents[2]
_DOCS_ROOT  = _REPO_ROOT / "docs"
_UML_DIR    = _DOCS_ROOT / "uml" / "generated"
_MMD_DIR    = _DOCS_ROOT / "diagrams"

_md = MarkdownIt("commonmark", {"html": False}).enable("table")

# slug must be lowercase letters, digits, hyphens — no path traversal possible
_SAFE_SLUG_RE = re.compile(r'^[a-z0-9][a-z0-9.-]*$')

# filename → slug overrides for files whose stem != sidebar slug
# Subdir paths (e.g. troubleshooting/502-bad-gateway.md) must be listed here.
_FILENAME_TO_SLUG: dict[str, str] = {
    "README.md":                       "",
    "api-v1-migration.md":             "api-migration",
    "troubleshooting/502-bad-gateway.md": "troubleshooting",
}

DOCS_SIDEBAR: list[dict[str, Any]] = [
    {"section": None, "pages": [
        {"slug": "",                  "title": "Introduction"},
    ]},
    {"section": "Reference", "pages": [
        {"slug": "api",               "title": "API Reference"},
        {"slug": "configuration",     "title": "Configuration"},
        {"slug": "data-sources",      "title": "Data Sources"},
        {"slug": "api-migration",     "title": "API Migration"},
    ]},
    {"section": "Architecture", "pages": [
        {"slug": "architecture",      "title": "Architecture Overview"},
        {"slug": "diagrams",          "title": "UML Diagrams"},
        {"slug": "database",          "title": "Database Schema"},
    ]},
    {"section": "Guides", "pages": [
        {"slug": "web-ui",            "title": "Web UI"},
        {"slug": "cli",               "title": "CLI Tool"},
        {"slug": "ssl",               "title": "SSL / TLS"},
        {"slug": "siem-integration",  "title": "SIEM Integration"},
    ]},
    {"section": "Operations", "pages": [
        {"slug": "runbook",           "title": "Runbook"},
        {"slug": "performance",       "title": "Performance"},
        {"slug": "access-control",    "title": "Access Control"},
        {"slug": "troubleshooting",   "title": "Troubleshooting"},
    ]},
]

_PAGE_FILES: dict[str, str | None] = {
    "":                "README.md",
    "api":             None,
    "architecture":    None,
    "diagrams":        None,
    "configuration":   "configuration.md",
    "data-sources":    "data-sources.md",
    "database":        "database.md",
    "api-migration":   "api-v1-migration.md",
    "web-ui":          "web-ui.md",
    "cli":             "cli.md",
    "ssl":             "ssl.md",
    "siem-integration":"siem-integration.md",
    "runbook":         "runbook.md",
    "performance":     "performance.md",
    "access-control":  "access-control.md",
    "troubleshooting": "troubleshooting/502-bad-gateway.md",
}

_PAGE_TITLES: dict[str, str] = {
    "":                "Introduction",
    "api":             "API Reference",
    "architecture":    "Architecture Overview",
    "diagrams":        "UML Diagrams",
    "configuration":   "Configuration",
    "data-sources":    "Data Sources",
    "database":        "Database Schema",
    "api-migration":   "API Migration Guide",
    "web-ui":          "Web UI",
    "cli":             "CLI Tool",
    "ssl":             "SSL / TLS",
    "siem-integration":"SIEM Integration",
    "runbook":         "Operations Runbook",
    "performance":     "Performance & SLOs",
    "access-control":  "Access Control",
    "troubleshooting": "Troubleshooting",
}

_MERMAID_FILES = [
    ("architecture-overview.mmd", "Architecture Overview (C4)"),
    ("class-domain.mmd",          "Domain Model"),
    ("service-layer.mmd",         "Service Layer"),
    ("data-flow.mmd",             "Feed Ingestion Data Flow"),
    ("request-flow.mmd",          "API Request Lifecycle"),
    ("admin-sync-flow.mmd",       "Admin Sync Flow"),
]

_UML_SVGS = [
    ("IOC_Service_Component.svg",           "Component Diagram"),
    ("IOC_Service_Deployment.svg",          "Deployment Diagram"),
    ("IOC_Service_Domain_Model.svg",        "Domain Model"),
    ("IOC_Service_ER_Diagram.svg",          "ER Diagram"),
    ("IOC_Service_Export_Sequence.svg",     "Export Sequence"),
    ("IOC_Service_Ingestion_Activity.svg",  "Ingestion Activity"),
    ("IOC_Service_Layer.svg",               "Service Layer"),
    ("IOC_Service_SyncJob_StateMachine.svg","SyncJob State Machine"),
    ("IOC_Service_Sync_Sequence.svg",       "Sync Sequence"),
    ("IOC_Service_Use_Cases.svg",           "Use Cases"),
]

_SAFE_SVG_NAMES = frozenset(fname for fname, _ in _UML_SVGS)


def _md_link_to_docs(href: str) -> str | None:
    """Convert a relative .md href to /docs/<slug>[#anchor]. Returns None to leave unchanged."""
    anchor = ""
    if "#" in href:
        href, anchor = href.split("#", 1)
        anchor = "#" + anchor
    if not href.endswith(".md"):
        return None
    # Explicit map first — handles subdir paths (troubleshooting/502-bad-gateway.md)
    if href in _FILENAME_TO_SLUG:
        return f"/docs/{_FILENAME_TO_SLUG[href]}{anchor}"
    # parent-relative: ../foo.md
    # Rewrite only lowercase filenames (repo-root docs are UPPERCASE: DEPLOYMENT.md etc.)
    if href.startswith("../"):
        inner = href[3:]
        if "/" in inner or not inner or not inner[0].islower():
            return None
        slug = _FILENAME_TO_SLUG.get(inner, Path(inner).stem)
        return f"/docs/{slug}{anchor}"
    # Reject remaining subdir links (uml/README.md, diagrams/README.md, etc.)
    if "/" in href:
        return None
    slug = _FILENAME_TO_SLUG.get(href, Path(href).stem)
    return f"/docs/{slug}{anchor}"


def _rewrite_md_links(html: str) -> str:
    """Rewrite href="*.md" links in rendered HTML to /docs/<slug> URLs."""
    def repl(m: re.Match) -> str:
        url = _md_link_to_docs(m.group(1))
        return f'href="{url}"' if url is not None else m.group(0)
    return re.sub(r'href="([^"]*\.md(?:#[^"]*)?)"', repl, html)


def _render_md(rel: str) -> str:
    try:
        text = (_DOCS_ROOT / rel).read_text(encoding="utf-8")
    except (FileNotFoundError, OSError):
        return "<p><em>Documentation file not found.</em></p>"
    return _rewrite_md_links(_md.render(text))


def register_docs_routes(app, *, limiter) -> None:

    @app.get("/docs")
    @app.get("/docs/")
    @limiter.limit("60 per minute")
    def docs_index():
        return make_response(render_template(
            "docs/page.html",
            active_page="docs",
            docs_slug="",
            docs_sidebar=DOCS_SIDEBAR,
            docs_title="Introduction",
            content_html=_render_md("README.md"),
        ))

    @app.get("/docs/<slug>")
    @limiter.limit("60 per minute")
    def docs_page(slug: str):
        slug = slug.lower().strip("/")

        if slug == "api":
            return make_response(render_template(
                "docs/api.html",
                active_page="docs",
                docs_slug=slug,
                docs_sidebar=DOCS_SIDEBAR,
                docs_title="API Reference",
            ))

        if slug == "architecture":
            diagrams = []
            for fname, title in _MERMAID_FILES:
                try:
                    source = (_MMD_DIR / fname).read_text(encoding="utf-8")
                    diagrams.append({"title": title, "source": source})
                except (FileNotFoundError, OSError):
                    pass
            return make_response(render_template(
                "docs/architecture.html",
                active_page="docs",
                docs_slug=slug,
                docs_sidebar=DOCS_SIDEBAR,
                docs_title="Architecture Overview",
                diagrams=diagrams,
            ))

        if slug == "diagrams":
            svgs = [
                {"filename": fname, "title": title}
                for fname, title in _UML_SVGS
                if (_UML_DIR / fname).exists()
            ]
            return make_response(render_template(
                "docs/diagrams.html",
                active_page="docs",
                docs_slug=slug,
                docs_sidebar=DOCS_SIDEBAR,
                docs_title="UML Diagrams",
                svgs=svgs,
            ))

        # Explicit mapping takes priority; fall back to any docs/{slug}.md
        if slug in _PAGE_FILES:
            md_rel = _PAGE_FILES[slug]
        else:
            if not _SAFE_SLUG_RE.match(slug):
                abort(404)
            candidate = _DOCS_ROOT / f"{slug}.md"
            if not candidate.exists():
                abort(404)
            md_rel = f"{slug}.md"

        return make_response(render_template(
            "docs/page.html",
            active_page="docs",
            docs_slug=slug,
            docs_sidebar=DOCS_SIDEBAR,
            docs_title=_PAGE_TITLES.get(slug, slug.replace("-", " ").title()),
            content_html=_render_md(md_rel),
        ))

    @app.get("/docs/_uml/<filename>")
    @limiter.limit("120 per minute")
    def docs_uml_svg(filename: str):
        if filename not in _SAFE_SVG_NAMES:
            abort(404)
        path = _UML_DIR / filename
        if not path.exists():
            abort(404)
        return send_file(str(path), mimetype="image/svg+xml")

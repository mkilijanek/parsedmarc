from __future__ import annotations

from pathlib import Path
from typing import Any

from flask import abort, make_response, render_template, send_file
from markdown_it import MarkdownIt

_REPO_ROOT = Path(__file__).resolve().parents[2]
_DOCS_ROOT  = _REPO_ROOT / "docs"
_UML_DIR    = _DOCS_ROOT / "uml" / "generated"
_MMD_DIR    = _DOCS_ROOT / "diagrams"

_md = MarkdownIt("commonmark", {"html": False}).enable("table")

DOCS_SIDEBAR: list[dict[str, Any]] = [
    {"section": None, "pages": [
        {"slug": "",                "title": "Introduction"},
    ]},
    {"section": "Reference", "pages": [
        {"slug": "api",             "title": "API Reference"},
        {"slug": "configuration",   "title": "Configuration"},
        {"slug": "data-sources",    "title": "Data Sources"},
        {"slug": "api-migration",   "title": "API Migration"},
    ]},
    {"section": "Architecture", "pages": [
        {"slug": "architecture",    "title": "Architecture Overview"},
        {"slug": "diagrams",        "title": "UML Diagrams"},
        {"slug": "database",        "title": "Database Schema"},
        {"slug": "deployment",      "title": "Deployment"},
    ]},
    {"section": "Operations", "pages": [
        {"slug": "troubleshooting", "title": "Troubleshooting"},
    ]},
]

_PAGE_FILES: dict[str, str | None] = {
    "":               "README.md",
    "api":            None,
    "architecture":   None,
    "diagrams":       None,
    "configuration":  "configuration.md",
    "data-sources":   "data-sources.md",
    "database":       "database.md",
    "deployment":     "architecture.md",
    "api-migration":  "api-v1-migration.md",
    "troubleshooting":"troubleshooting/502-bad-gateway.md",
}

_PAGE_TITLES: dict[str, str] = {
    "":               "Introduction",
    "api":            "API Reference",
    "architecture":   "Architecture Overview",
    "diagrams":       "UML Diagrams",
    "configuration":  "Configuration",
    "data-sources":   "Data Sources",
    "database":       "Database Schema",
    "deployment":     "Deployment",
    "api-migration":  "API Migration Guide",
    "troubleshooting":"Troubleshooting",
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


def _render_md(rel: str) -> str:
    try:
        text = (_DOCS_ROOT / rel).read_text(encoding="utf-8")
    except (FileNotFoundError, OSError):
        return "<p><em>Documentation file not found.</em></p>"
    return _md.render(text)


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
        if slug not in _PAGE_FILES:
            abort(404)

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

        return make_response(render_template(
            "docs/page.html",
            active_page="docs",
            docs_slug=slug,
            docs_sidebar=DOCS_SIDEBAR,
            docs_title=_PAGE_TITLES.get(slug, slug.replace("-", " ").title()),
            content_html=_render_md(_PAGE_FILES[slug]),
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

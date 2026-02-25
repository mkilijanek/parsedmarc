#!/usr/bin/env python3
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONF_DIR = ROOT / "Confluence"
PAGES_DIR = CONF_DIR / "pages"

PAGES = [
    {"id": "home", "title": "IOC Service Documentation", "parent": None, "source": "docs/README.md", "file": "00-home.wiki", "purpose": "Central entry page for the IOC Service documentation tree."},
    {"id": "getting-started", "title": "Getting Started", "parent": "home", "source": "README.md", "file": "10-getting-started.wiki", "purpose": "Entry point for installation and first-run setup."},
    {"id": "quickstart", "title": "Quickstart", "parent": "getting-started", "source": "QUICKSTART.md", "file": "11-quickstart.wiki", "purpose": "Fast setup and operational shortcuts for local/prod usage."},
    {"id": "deployment", "title": "Deployment", "parent": "getting-started", "source": "DEPLOYMENT.md", "file": "12-deployment.wiki", "purpose": "Deployment process, prerequisites, and rollout guidance."},
    {"id": "security", "title": "Security", "parent": "getting-started", "source": "SECURITY.md", "file": "13-security.wiki", "purpose": "Security posture, controls, and recommended hardening."},
    {"id": "contributing", "title": "Contributing", "parent": "getting-started", "source": "CONTRIBUTING.md", "file": "14-contributing.wiki", "purpose": "Contribution workflow and quality gates."},
    {"id": "operations", "title": "Operations", "parent": "home", "source": "docs/runbook.md", "file": "20-operations.wiki", "purpose": "Operational practices and production support guidance."},
    {"id": "configuration", "title": "Configuration", "parent": "operations", "source": "docs/configuration.md", "file": "21-configuration.wiki", "purpose": "Environment variables and runtime configuration matrix."},
    {"id": "data-sources", "title": "Data Sources", "parent": "operations", "source": "docs/data-sources.md", "file": "22-data-sources.wiki", "purpose": "Supported feeds and ingestion behavior."},
    {"id": "api", "title": "API Reference", "parent": "operations", "source": "docs/api.md", "file": "23-api-reference.wiki", "purpose": "HTTP API endpoints, parameters, and examples."},
    {"id": "database", "title": "Database", "parent": "operations", "source": "docs/database.md", "file": "24-database.wiki", "purpose": "Schema, functions, and DB operational notes."},
    {"id": "web-ui", "title": "Web UI", "parent": "operations", "source": "docs/web-ui.md", "file": "25-web-ui.wiki", "purpose": "UI screens, behavior, and usage."},
    {"id": "ssl", "title": "SSL", "parent": "operations", "source": "docs/ssl.md", "file": "26-ssl.wiki", "purpose": "TLS certificate setup and validation."},
    {"id": "runbook", "title": "Runbook", "parent": "operations", "source": "docs/runbook.md", "file": "27-runbook.wiki", "purpose": "Incident and routine operations playbook."},
    {"id": "engineering", "title": "Engineering", "parent": "home", "source": "docs/architecture.md", "file": "30-engineering.wiki", "purpose": "Engineering-oriented architecture and delivery topics."},
    {"id": "architecture", "title": "Architecture", "parent": "engineering", "source": "docs/architecture.md", "file": "31-architecture.wiki", "purpose": "System components, data flow, and design rationale."},
    {"id": "cli", "title": "CLI", "parent": "engineering", "source": "docs/cli.md", "file": "32-cli.wiki", "purpose": "Command-line ingestion workflows."},
    {"id": "performance", "title": "Performance", "parent": "engineering", "source": "docs/performance.md", "file": "33-performance.wiki", "purpose": "Benchmarking methods and performance tuning."},
    {"id": "maintenance", "title": "Maintenance Plan", "parent": "engineering", "source": "docs/maintenance-plan.md", "file": "34-maintenance-plan.wiki", "purpose": "Maintenance milestones and periodic tasks."},
    {"id": "m16", "title": "M16 Finalization", "parent": "engineering", "source": "docs/m16-finalization.md", "file": "35-m16-finalization.wiki", "purpose": "Finalization checklist and readiness outcomes."},
]


def _inline_convert(text: str) -> str:
    text = re.sub(r"`([^`]+)`", r"{{\1}}", text)
    text = re.sub(r"\*\*([^*]+)\*\*", r"*\1*", text)
    text = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r"[\1|\2]", text)
    return text


def md_to_wiki(md: str) -> str:
    out: list[str] = []
    in_code = False
    code_lang = ""

    for raw in md.splitlines():
        line = raw.rstrip("\n")

        fence = re.match(r"^```([a-zA-Z0-9_+-]*)\s*$", line.strip())
        if fence:
            if in_code:
                out.append("{code}")
                in_code = False
                code_lang = ""
            else:
                in_code = True
                code_lang = fence.group(1) or "none"
                out.append(f"{{code:language={code_lang}}}")
            continue

        if in_code:
            out.append(line)
            continue

        hm = re.match(r"^(#{1,6})\s+(.*)$", line)
        if hm:
            level = min(len(hm.group(1)), 6)
            heading = _inline_convert(hm.group(2).strip())
            out.append(f"h{level}. {heading}")
            continue

        if re.match(r"^\s*[-*]\s+", line):
            item = re.sub(r"^\s*[-*]\s+", "", line)
            out.append(f"* {_inline_convert(item)}")
            continue

        if re.match(r"^\s*\d+\.\s+", line):
            item = re.sub(r"^\s*\d+\.\s+", "", line)
            out.append(f"# {_inline_convert(item)}")
            continue

        out.append(_inline_convert(line))

    return "\n".join(out).rstrip() + "\n"


def extract_body(md: str) -> str:
    lines = md.splitlines()
    if lines and lines[0].startswith("# "):
        return "\n".join(lines[1:]).lstrip("\n")
    return md


def build_page(entry: dict) -> str:
    source_path = ROOT / entry["source"]
    raw_md = source_path.read_text(encoding="utf-8")
    content_md = extract_body(raw_md)
    wiki_body = md_to_wiki(content_md)
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")

    return (
        f"h1. {entry['title']}\n\n"
        f"{{info:title=Documentation Metadata}}\n"
        f"Purpose: {entry['purpose']}\\\\\n"
        f"Source file: {{code}}{entry['source']}{{code}}\\\\\n"
        f"Generated (UTC): {generated}\n"
        f"{{info}}\n\n"
        f"h2. Content\n\n"
        f"{wiki_body}"
    )


def write_manifest() -> None:
    lines = ["# Confluence page tree manifest", "pages:"]
    for idx, p in enumerate(PAGES, start=1):
        lines.append(f"  - id: {p['id']}")
        lines.append(f"    title: \"{p['title']}\"")
        parent = p["parent"] if p["parent"] is not None else ""
        lines.append(f"    parent: \"{parent}\"")
        lines.append(f"    file: pages/{p['file']}")
        lines.append(f"    source: {p['source']}")
        lines.append(f"    order: {idx}")
    (CONF_DIR / "manifest.yaml").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    PAGES_DIR.mkdir(parents=True, exist_ok=True)
    for p in PAGES:
        content = build_page(p)
        (PAGES_DIR / p["file"]).write_text(content, encoding="utf-8")
    write_manifest()


if __name__ == "__main__":
    main()

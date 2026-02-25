#!/usr/bin/env python3
from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import requests
import yaml


@dataclass
class Page:
    id: str
    title: str
    parent: str
    file: str
    source: str
    order: int


def load_manifest(manifest_path: Path) -> list[Page]:
    data = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    pages = [Page(**item) for item in data.get("pages", [])]
    return sorted(pages, key=lambda p: p.order)


def api_get_page(base_url: str, space_key: str, title: str, auth: tuple[str, str], verify: bool) -> dict[str, Any] | None:
    resp = requests.get(
        f"{base_url}/rest/api/content",
        params={"spaceKey": space_key, "title": title, "expand": "version"},
        auth=auth,
        verify=verify,
        timeout=30,
    )
    resp.raise_for_status()
    results = resp.json().get("results", [])
    return results[0] if results else None


def api_create_or_update(
    *,
    base_url: str,
    space_key: str,
    title: str,
    body_wiki: str,
    parent_id: str | None,
    auth: tuple[str, str],
    verify: bool,
    dry_run: bool,
) -> str:
    existing = api_get_page(base_url, space_key, title, auth, verify)

    ancestors = [{"id": str(parent_id)}] if parent_id else []

    if existing is None:
        payload = {
            "type": "page",
            "title": title,
            "space": {"key": space_key},
            "body": {"wiki": {"value": body_wiki, "representation": "wiki"}},
        }
        if ancestors:
            payload["ancestors"] = ancestors

        if dry_run:
            print(f"[DRY-RUN] CREATE: {title}")
            return f"dry-{title}"

        resp = requests.post(
            f"{base_url}/rest/api/content",
            json=payload,
            auth=auth,
            verify=verify,
            timeout=60,
        )
        resp.raise_for_status()
        created = resp.json()
        print(f"[CREATE] {title} -> id={created['id']}")
        return str(created["id"])

    page_id = str(existing["id"])
    version = int(existing["version"]["number"]) + 1
    payload = {
        "id": page_id,
        "type": "page",
        "title": title,
        "version": {"number": version},
        "body": {"wiki": {"value": body_wiki, "representation": "wiki"}},
    }
    if ancestors:
        payload["ancestors"] = ancestors

    if dry_run:
        print(f"[DRY-RUN] UPDATE: {title} -> id={page_id}, version={version}")
        return page_id

    resp = requests.put(
        f"{base_url}/rest/api/content/{page_id}",
        json=payload,
        auth=auth,
        verify=verify,
        timeout=60,
    )
    resp.raise_for_status()
    print(f"[UPDATE] {title} -> id={page_id}, version={version}")
    return page_id


def main() -> None:
    parser = argparse.ArgumentParser(description="Import Confluence pages/subpages from Confluence/manifest.yaml")
    parser.add_argument("--base-url", required=True, help="Confluence base URL, e.g. https://confluence.example.com")
    parser.add_argument("--space-key", required=True, help="Confluence space key")
    parser.add_argument("--user", required=True, help="Confluence username")
    parser.add_argument("--token", required=True, help="Confluence API token/password")
    parser.add_argument("--manifest", default="Confluence/manifest.yaml")
    parser.add_argument("--root-parent-id", default="", help="Optional existing parent page ID for top-level page")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS verification")
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    manifest_path = root / args.manifest
    pages = load_manifest(manifest_path)

    auth = (args.user, args.token)
    verify = not args.insecure

    page_ids: dict[str, str] = {}

    for page in pages:
        parent_id = None
        if page.parent:
            parent_id = page_ids.get(page.parent)
            if parent_id is None:
                raise RuntimeError(f"Parent page '{page.parent}' for '{page.id}' was not created yet")
        elif args.root_parent_id:
            parent_id = args.root_parent_id

        file_path = root / "Confluence" / page.file
        body = file_path.read_text(encoding="utf-8")

        page_id = api_create_or_update(
            base_url=args.base_url.rstrip("/"),
            space_key=args.space_key,
            title=page.title,
            body_wiki=body,
            parent_id=parent_id,
            auth=auth,
            verify=verify,
            dry_run=args.dry_run,
        )
        page_ids[page.id] = page_id


if __name__ == "__main__":
    main()

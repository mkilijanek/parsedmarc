# Confluence Export Package

Status: updated for 1.4.1 (2026-04-06).

Ten katalog zawiera ujednoliconą dokumentację projektu w formacie **Confluence Wiki Markup**,
przygotowaną do importu jako drzewo stron i podstron w **Confluence 9.2.13**.

## Struktura

- `manifest.yaml` - definicja hierarchii stron (id, parent, kolejność, plik)
- `pages/*.wiki` - treść stron w spójnym formacie Confluence Wiki Markup

## Regeneracja stron z Markdown

```bash
. .venv/bin/activate
python scripts/build_confluence_docs.py
```

Generator pobiera treści z repo (`README.md`, `QUICKSTART.md`, `docs/*.md`), normalizuje format
i aktualizuje pliki w `Confluence/pages`.

## Import do Confluence (REST API)

```bash
. .venv/bin/activate
python scripts/confluence_import.py \
  --base-url "https://confluence.example.com" \
  --space-key "IOC" \
  --user "your.user" \
  --token "your_api_token"
```

Opcjonalnie:

- `--root-parent-id 123456` - osadzenie całego drzewa pod istniejącą stroną
- `--dry-run` - walidacja bez zmian po stronie Confluence
- `--insecure` - wyłączenie walidacji TLS (tylko środowiska testowe)

## Uwagi

- Importer tworzy brakujące strony i aktualizuje istniejące po tytule (`spaceKey + title`).
- Hierarchia parent/child jest odtwarzana zgodnie z `manifest.yaml`.
- Wymagane pakiety: `requests`, `PyYAML` (dostępne w `requirements.txt`).

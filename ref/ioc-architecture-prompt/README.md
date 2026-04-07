# 🛡️ IOC Service — Master Prompt Architektoniczny

**Wersja:** 2.0.0  
**Data:** 7 kwietnia 2026  
**Projekt:** IOC Service — Threat Intelligence Feed Aggregator  
**Wersja bazowa kodu:** v1.4.1 (version-3)  

---

## 📋 Spis treści i nawigacja

| # | Sekcja | Plik | Opis |
|---|--------|------|------|
| 1 | [Executive Summary](./01-executive-summary.md) | `01-executive-summary.md` | Wizja, cele, ROI, stakeholders |
| 2 | [Wizja Architektury](./02-architecture-vision.md) | `02-architecture-vision.md` | Obecna i docelowa architektura, ADR |
| 3 | [**Architektura Integracji**](./03-integration-architecture.md) | `03-integration-architecture.md` | 🔑 **KLUCZOWA SEKCJA** — Plugin System, Adaptery |
| 4 | [Zgodność ISO 27001](./04-iso27001-compliance.md) | `04-iso27001-compliance.md` | Gap analysis, kontrole, compliance |
| 5 | [Stack Technologiczny](./05-technology-stack.md) | `05-technology-stack.md` | Obecny stack, propozycje zmian |
| 6 | [Milestones & Roadmap](./06-milestones-roadmap.md) | `06-milestones-roadmap.md` | Szczegółowy breakdown milestones |
| 7 | Role zespołowe | `07-roles/` | Instrukcje per rola |
|   | → [Backend Developer](./07-roles/backend-developer.md) | | API, DB, services |
|   | → [Frontend Developer](./07-roles/frontend-developer.md) | | UI/UX, komponenty |
|   | → [DevOps Engineer](./07-roles/devops-engineer.md) | | CI/CD, infra, monitoring |
|   | → [Security Engineer](./07-roles/security-engineer.md) | | Threat modeling, pentesty |
|   | → [QA Engineer](./07-roles/qa-engineer.md) | | Strategia testów, automatyzacja |
|   | → [Product Owner](./07-roles/product-owner.md) | | Priorytety, user stories |
| 8 | [Best Practices](./08-best-practices.md) | `08-best-practices.md` | Standardy kodu, Git, review |
| 9 | [Metryki Jakości](./09-quality-metrics.md) | `09-quality-metrics.md` | KPI, SLA, dashboards |
| 10 | [Zarządzanie Ryzykiem](./10-risk-management.md) | `10-risk-management.md` | Risk matrix, mitigation |
| 11 | Załączniki | `11-appendices/` | Diagramy, API spec, schema |
|   | → [Słownik](./11-appendices/glossary.md) | | Terminy, akronimy |
|   | → [Diagramy](./11-appendices/diagrams.md) | | C4, sekwencje, deployment |
|   | → [Specyfikacja API](./11-appendices/api-specifications.md) | | OpenAPI, endpointy |
|   | → [Schemat Bazy Danych](./11-appendices/database-schema.md) | | ERD, tabele, migracje |

---

## 🚀 Quick Start Guide

### Dla kogo jest ten dokument?

Ten prompt architektoniczny to **kompletny przewodnik** dla zespołu deweloperskiego, który będzie implementował IOC Service od wersji 1.4.1 do wersji docelowej 2.0. Każda rola w zespole ma dedykowaną sekcję z konkretnymi instrukcjami.

### Jak korzystać?

1. **Product Owner / Tech Lead** → Zacznij od [Executive Summary](./01-executive-summary.md) i [Milestones](./06-milestones-roadmap.md)
2. **Backend Developer** → Przeczytaj [Architekturę Integracji](./03-integration-architecture.md), potem [swoją rolę](./07-roles/backend-developer.md)
3. **Frontend Developer** → [Wizja Architektury](./02-architecture-vision.md), potem [swoją rolę](./07-roles/frontend-developer.md)
4. **DevOps Engineer** → [Stack Technologiczny](./05-technology-stack.md), potem [swoją rolę](./07-roles/devops-engineer.md)
5. **Security Engineer** → [ISO 27001](./04-iso27001-compliance.md), potem [swoją rolę](./07-roles/security-engineer.md)
6. **QA Engineer** → [Metryki Jakości](./09-quality-metrics.md), potem [swoją rolę](./07-roles/qa-engineer.md)

### Priorytety czytania

```
🔴 MUST READ:  03-integration-architecture.md (klucz do sukcesu projektu)
🔴 MUST READ:  04-iso27001-compliance.md (wymóg regulacyjny)
🟠 IMPORTANT:  06-milestones-roadmap.md (plan pracy)
🟠 IMPORTANT:  Twoja rola w 07-roles/
🟡 REFERENCE:  Pozostałe sekcje — czytaj w miarę potrzeb
```

---

## 🏢 Kontekst Biznesowy

### Czym jest IOC Service?

**IOC Service** (Indicators of Compromise Service) to profesjonalna platforma do **agregacji, normalizacji i dystrybucji wskaźników kompromitacji** (IOC) z wielu źródeł Threat Intelligence. Aplikacja centralizuje dane z 10 źródeł (CrowdSec, MISP, MWDB, MalwareBazaar, abuse.ch) i eksportuje je w 17 formatach do systemów SIEM, firewalli i innych narzędzi bezpieczeństwa.

### Dlaczego ten projekt jest ważny?

1. **Bezpieczeństwo organizacji** — centralizacja threat intelligence eliminuje silosy informacyjne
2. **Compliance ISO 27001** — wymóg regulacyjny dla organizacji
3. **Efektywność operacyjna** — automatyzacja zamiast ręcznego zbierania IOC
4. **Skalowalność** — łatwe dodawanie nowych źródeł i formatów eksportu

### Główny problem do rozwiązania

> **Dodanie nowej integracji (źródła Threat Intelligence) zajmuje obecnie ~2 tygodnie.**  
> Docelowo: **≤2 dni** dzięki Plugin Architecture z Adapter Pattern.

### Stan obecny vs. docelowy

| Aspekt | Obecny (v1.4.1) | Docelowy (v2.0) |
|--------|-----------------|------------------|
| Czas dodania integracji | ~2 tygodnie | ≤2 dni |
| ISO 27001 compliance | ~54% | 100% |
| `app/main.py` LOC | 2,555 | <500 |
| Adapter Pattern | ❌ Brak | ✅ FeedAdapter Protocol |
| Admin authentication | ❌ Brak | ✅ Session-based admin auth + RBAC, API auth for machine clients |
| Test coverage | ~75% | >85% |
| API versioning | ❌ Brak | ✅ `/api/v1/` |

---

## 📐 Konwencje dokumentu

- **Język:** Polski z angielskimi terminami technicznymi
- **Kod:** Python 3.11+, PEP 8, type hints
- **Diagramy:** Mermaid (renderowane w GitHub/GitLab)
- **Priorytety:** 🔴 Critical → 🟠 High → 🟡 Medium → 🟢 Low
- **Status:** ❌ Brak → ⚠️ Częściowo → ✅ Zaimplementowane
- **Linki:** Relatywne ścieżki między plikami

---

## 📊 Kluczowe metryki projektu

```
📦 Rozmiar kodu:      ~10,400 LOC (Python) + ~5,871 LOC testów
🔌 Integracje:        10 connectorów (5 primary + 5 abuse.ch)
📤 Formaty eksportu:  17 (txt, csv, json, xml, SIEM, firewalls)
🗄️ Tabele DB:         9 (PostgreSQL 16)
📡 Endpointy API:     ~32
🏗️ Milestones:        6 (M1.4.2 → M1.7.0)
👥 Role:              6 (backend, frontend, devops, security, QA, PO)
```

---

*Dokument wygenerowany na podstawie [Raportu Analizy](/home/ubuntu/ioc-analysis/ANALYSIS_REPORT.md) z dnia 6 kwietnia 2026.*

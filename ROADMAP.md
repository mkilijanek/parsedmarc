# IOC Service — Roadmap

This roadmap uses semantic versioning with the following intent:
- **1.2.x** — patches/hotfixes/observability/docs improvements (no big architecture refactors)
- **1.3.0** — architecture milestone (connector standardization + modularization)

## Prompt Mapping (01-11)

The reference bundle under [ref/ioc-architecture-prompt](/home/kili/Repo/ioc-service/ref/ioc-architecture-prompt) is mapped into the active roadmap as follows:

| Prompt | Focus | Primary roadmap target |
|--------|-------|------------------------|
| `01-executive-summary` | business goals, success criteria, sequencing | `1.4.2` → `1.7.0` umbrella |
| `02-architecture-vision` | target architecture, ADRs, migration strategy | `1.5.0`, `1.5.1`, `1.6.0`, `1.6.1` |
| `03-integration-architecture` | adapter contracts, registry, pipeline, scheduling | `1.6.1` |
| `04-iso27001-compliance` | auth, RBAC, CSRF, audit, secrets, controls | `1.4.2` |
| `05-technology-stack` | dependency, scheduler, packaging, API tooling choices | `1.6.0`, `1.6.1` |
| `06-milestones-roadmap` | delivery breakdown and effort model | `1.4.2` → `1.7.0` planning baseline |
| `07-roles/*` | team execution responsibilities by discipline | cross-cutting, anchored to the matching milestone |
| `08-best-practices` | coding/review/versioning/error-handling standards | `1.5.0`, `1.6.0` |
| `09-quality-metrics` | quality gates, KPI thresholds, success criteria | `1.5.0`, `1.5.1`, `1.6.1` |
| `10-risk-management` | delivery and architecture risks with mitigations | all active milestones, especially `1.4.2` and `1.6.1` |
| `11-appendices/*` | API/schema/diagram reference detail | `1.5.1`, `1.6.0`, `1.6.1` |

Known gaps filled in the local roadmap:
- `M1.6.0` is treated as a first-class milestone with explicit API/config scope; the prompt bundle referenced it across sections but did not fully operationalize it in one place.
- Authentication strategy is normalized as: session-based admin/web auth with RBAC, plus API token/JWT style auth for non-UI clients as part of the versioned API surface.
- The adapter milestone includes registry/discovery, capability metadata, contract testing, and runtime-hardening work that was spread across multiple prompt sections.

## Historical Tracking State

- GitHub milestones closed on 2026-04-07 as already delivered historical work:
  - `1.1.x`
  - `1.2.1`
  - `1.3.0`
  - `1.4.0`
- Historical GitHub releases created on 2026-04-07 to match already existing version tags:
  - `1.4.0`
  - `1.4.1`
- `1.4.2+` remain active implementation milestones.

---

## Milestone 1.2.1 — Stability & Non-Fatal Dependencies

**Goal**
Ensure external dependencies (e.g., MISP) never crash the service process, never break liveness, and never cause reverse-proxy 502 due to the app not listening.

**Scope**
Reliability, health endpoint semantics, F5/Nginx compatibility.

**Issues (existing)**
- #53 Split health endpoints: liveness vs readiness vs dependency status
- #55 Align F5 / load balancer monitoring to liveness (/healthz)
- #59 External dependency checks should never crash the service process
- #54 Make MISP checks non-fatal and bounded (timeouts, circuit breaker, caching)

**Issues (new placeholders)**
- NEW-ISSUE: Dep health refresh job (periodic dependency status updater)
- NEW-ISSUE: MISP update job: `not_configured` → skip (no exception)

**Checklist**
- [x] `/healthz` returns **200**, performs **no external calls**, target **<50ms**
- [x] `/readyz` checks **DB + Redis only**
- [x] `/health` uses **cached summary only** (no live external calls)
- [x] Worker never exits due to MISP dependency failures
- [x] F5 monitor points to `/healthz`
- [x] Deployment docs updated (monitor endpoints + expectations)

**Status**
- Done on 2026-03-10.

**Definition of Done**
- Simulated MISP outage does not stop service; port **8004 stays listening**
- Nginx does not return 502 due to dependency checks
- Health endpoints behave per contract (liveness != readiness != deps)

---

## Milestone 1.2.2 — Observability & "0 Fetched" Determinism

**Goal**
Every `fetched=0` outcome is explainable with persisted `stop_reason` and diagnostic context (not only free-text logs).

**Scope**
Telemetry, scheduler stats consistency, MWDB default semantics and robustness.

**Issues (existing)**
- #61 Feed sync scheduler: manual and scheduled sync produce consistent stats
- #56 MWDB "0 fetched" root-cause telemetry (stop_reason, request params, response shape)
- #58 MWDB time filtering robustness (parse failures, timezone, early-break correctness)
- #57 MWDB default query semantics (avoid "empty query" edge cases)

**Issues (new placeholders)**
- NEW-ISSUE: MWDB regression tests for 30-day default window and stop reasons
- NEW-ISSUE: Persist `stop_reason` + request params + filter counters in `FeedStats.details`

**Checklist**
- [x] `FeedStats.details` (JSON) includes:
  - [x] `stop_reason`
  - [x] sanitized request params (query/count/older_than)
  - [x] filter counters (time/org/type/parse_failures)
- [x] Manual and scheduled sync use identical stats schema
- [x] MWDB default 30-day time window deterministic
- [x] Default query semantics enforced (no empty query ambiguity)
- [x] Unit/regression tests cover early-break + parse failures

**Definition of Done**
- Operator can answer "why 0 fetched?" from DB/logs without guessing
- MWDB edge cases yield a deterministic stop_reason

---

## Milestone 1.2.3 — Deployment & Ops Hardening (RHEL / Nginx / F5)

**Goal**
10-minute triage for `502 Bad Gateway` / `ECONNREFUSED` / unhealthy app conditions.

**Scope**
Documentation and runbooks for RHEL deployments, SELinux, Nginx, and F5 monitors.

**Issues (existing)**
- #62 Documentation: default time window behavior and "0 fetched" troubleshooting guide

**Issues (new placeholders)**
- NEW-ISSUE: Add RHEL + SELinux + Nginx + F5 troubleshooting runbook (502 guide)
- NEW-ISSUE: Refresh `docs/uml/*` diagrams and include them as maintained release artifacts for 1.2.x

**Checklist**
- [x] Add `docs/troubleshooting/502-bad-gateway.md`
- [x] Include SELinux triage and fixes:
  - `ausearch -m AVC`
  - `semanage port`
  - `setsebool -P httpd_can_network_connect 1` (when applicable)
- [x] Include F5 SNI/Host header monitor notes
- [x] Include minimal `ss/curl` triage flow
- [x] Link runbook from `DEPLOYMENT.md`
- [x] Update `docs/uml/*.puml` to match current architecture and APIs
- [x] Regenerate UML rendered outputs (PNG/SVG where applicable) from current `.puml` sources
- [x] Link UML docs from `docs/README.md` and release notes as 1.2.x documentation scope

**Definition of Done**
- Documented fix paths for:
  - backend not listening (connection refused)
  - SELinux blocking proxy connects
  - wrong upstream address (host vs container)
  - wrong health endpoint used by LB monitor
- `docs/uml/` is current and explicitly tracked in 1.2.x release documentation scope

---

## Milestone 1.3.0 — Connector Architecture & Modularization

**Goal**
Standardize connector contract and shared fault-tolerance logic; modularize the app; enable streaming exports for large datasets.

**Scope**
Refactor + connector interface standardization + performance gating.

**Issues (existing)**
- #60 Standardize connector interface + shared retry/throttle/circuit logic
- #39 Refactor monolithic app/main.py into blueprints and services
- #40 Replace baseline migration strategy with explicit Alembic operations
- #41 Add streaming exports for large indicator datasets
- #42 UX feature bundle
- #43 Performance decision gate (profile before rewrite decisions)
- #50 Unify `update_*_indicators` result contract (optional but included)
- #44 Kibana-like filtered export to Azure Sentinel TI via Microsoft Graph

**Architecture targets**
- Connector contract:
  - `fetch() -> { items: [...], stats: {...}, stop_reason: "...", details: {...} }`
- Shared modules:
  - retry, throttle, circuit breaker (no duplication in connectors)
- Modular app layout:
  - main file contains no business logic
- Streaming exports:
  - avoid large in-memory lists; stable memory footprint

**Definition of Done**
- New feed can be added quickly with minimal boilerplate
- Connectors reuse shared resilience modules
- Exports stream for large datasets without OOM
- Codebase is modular and testable

---

## Milestone 1.4.0 — Full Route Modularization (Carry-over)

**Goal**
Dowieźć pełną modularizację routingu jako kontynuację po 1.3.0.

**Scope**
- przenieść pozostałe grupy endpointów z `app/main.py` do modułów `app/routes/*`
- zostawić `app/main.py` jako app factory + wiring
- zachować 100% kompatybilność URL i zachowania

**Issues**
- #119 Complete modularization of `app/main.py` into domain blueprints

**Status**
- Done on 2026-03-10.

**Definition of Done**
- `app/main.py` nie zawiera logiki biznesowej endpointów
- testy regresji endpointów są zielone
- dokumentacja architektury i Confluence odzwierciedla nowy podział

---

## Milestone 1.4.1 — Archive Integration & Dependency Hygiene

**Goal**
Dowiezienie bezpiecznej integracji kodu z archiwum `ioc-service-refactored-v1.4.0.zip` bez regresji względem aktualnego `main`.

**Scope**
- selektywna integracja zmian źródłowych z archiwum
- dalszy podział routingu przez wydzielenie logów
- odświeżenie workflow release/CI pod zaległe aktualizacje dependabota
- zapisanie znanych issue z integracji archiwum

**Issues**
- NEW-ISSUE: Extract `/logs` and `/api/logs` from ops routes into a dedicated module
- NEW-ISSUE: Update release workflow action dependencies flagged by dependabot
- NEW-ISSUE: Record archive integration issues and excluded regressions

**Status**
- Done on 2026-04-06.

**Definition of Done**
- `app/routes/logs.py` przejmuje obsługę `/logs` i `/api/logs`
- workflow CI używa `healthz` zamiast starego `/health` wait loop
- workflow release nie używa przestarzałych akcji zgłaszanych przez dependabota
- issue z integracji archiwum są zapisane w dokumentacji release

---

## Milestone 1.4.2 — Security & Runtime Hardening

**Goal**
Zamknąć krytyczne ryzyka bezpieczeństwa i uruchomieniowe przed dalszym refaktorem architektury.

**Scope**
- dodać autentykację i autoryzację dla `/admin` oraz wrażliwych operacji administracyjnych
- wdrożyć ochronę CSRF dla formularzy i endpointów zmieniających stan
- usunąć auto-generowanie `SECRET_KEY` na starcie kontenera
- doprecyzować bezpieczne zachowanie destrukcyjnych operacji i audit trail
- dodać `.dockerignore` i ograniczyć kontekst buildu
- dodać minimalny model ról/uprawnień oraz politykę access control dla operacji administracyjnych

**Issues (planned)**
- NEW-ISSUE: Protect `/admin` with authentication and authorization
- NEW-ISSUE: Add CSRF protection for admin HTML flows
- NEW-ISSUE: Require explicit `SECRET_KEY` provisioning in containers
- NEW-ISSUE: Add `.dockerignore` and tighten image build context
- NEW-ISSUE: Implement comprehensive admin audit trail and RBAC policy baseline

**Definition of Done**
- panel admina nie jest publicznie używalny bez logowania
- formularze POST są chronione tokenami CSRF
- kontener nie startuje z losowo generowanym `SECRET_KEY`
- build Docker nie pakuje zbędnych plików repo
- operacje admina mają spójny audit trail: kto, co, kiedy, z jakim wynikiem
- istnieje jawny model ról/uprawnień dla panelu administracyjnego

---

## Milestone 1.5.0 — Core Modularization & Template Extraction

**Goal**
Zmniejszyć złożoność kodu przez rozbicie monolitycznych modułów, usunięcie inline HTML i jednoznaczne przeniesienie logiki biznesowej do warstwy services/use-cases.

**Scope**
- rozbić `app/routes/ops.py` na mniejsze moduły domenowe
- zostawić `app/main.py` wyłącznie jako composition root
- przenieść logikę orkiestracji z tras do usług aplikacyjnych
- przenieść HTML z f-stringów do `app/templates/`
- wprowadzić zasady odpowiedzialności: routes vs services vs adapters
- dodać quality gates dla złożoności, coverage i typowania, żeby regresja architektoniczna była wykrywana automatycznie

**Issues (planned)**
- NEW-ISSUE: Split `app/routes/ops.py` into admin, sync-jobs, settings and metrics modules
- NEW-ISSUE: Extract orchestration logic from routes into dedicated services/use-cases
- NEW-ISSUE: Move inline HTML rendering into Jinja templates
- NEW-ISSUE: Add architecture/regression tests for route and service boundaries
- NEW-ISSUE: Add code quality gates (ruff/mypy/coverage/radon) for modularization regressions

**Definition of Done**
- `app/main.py` nie zawiera logiki biznesowej
- `app/routes/ops.py` staje się cienką warstwą lub znika
- HTML nie jest renderowany przez wielkie f-stringi w modułach aplikacyjnych
- nowe use-case’y trafiają wyłącznie do services/use-cases
- CI zgłasza przekroczenie ustalonych progów jakości i złożoności

---

## Milestone 1.5.1 — Database Convergence & PostgreSQL Validation

**Goal**
Usunąć dualizm schematu SQL/ORM i dodać prawdziwą walidację zachowań PostgreSQL.

**Scope**
- wybrać i opisać jedno źródło prawdy dla schematu
- uzgodnić `database/init/*`, Alembic, ORM i namespace tabel/funkcji
- dodać testy integracyjne z PostgreSQL dla triggerów, widoków, FTS, JSONB i funkcji eksportu
- uzupełnić brakujące relacje/FK tam, gdzie są elementem modelu domenowego
- usunąć zahardcodowane limity omijające runtime config
- dodać automatyczne wykrywanie schema drift w CI/CD

**Issues (planned)**
- NEW-ISSUE: Reconcile SQL schema, ORM metadata and Alembic migrations
- NEW-ISSUE: Add PostgreSQL integration test suite in CI
- NEW-ISSUE: Add relational integrity constraints and config-aligned export limits
- NEW-ISSUE: Detect schema drift automatically between SQL, ORM and migrations

**Definition of Done**
- oba sposoby inicjalizacji bazy dają równoważne zachowanie
- PostgreSQL-only mechanizmy są testowane automatycznie
- drift schematu między SQL a ORM jest wykrywalny
- CI blokuje niespójne zmiany schematu

---

## Milestone 1.6.0 — API & Configuration Modernization

**Goal**
Ustabilizować kontrakt API i uprościć zarządzanie konfiguracją oraz zależnościami.

**Scope**
- wprowadzić wersjonowanie API (`/api/v1/`)
- opublikować specyfikację OpenAPI
- rozbić konfigurację na logiczne sekcje zamiast jednej klasy 100+ pól
- usunąć duplikację odczytu env poza warstwą config
- przejść na nowocześniejsze zarządzanie zależnościami i rozdzielić dev/prod
- opisać ścieżkę migracji ze starego API do wersjonowanego kontraktu

**Issues (planned)**
- NEW-ISSUE: Introduce versioned API surface and migration path
- NEW-ISSUE: Publish and maintain OpenAPI specification
- NEW-ISSUE: Refactor `Config` into grouped sections and modernize packaging
- NEW-ISSUE: Separate production and development dependencies in project metadata

**Definition of Done**
- API ma stabilny, wersjonowany kontrakt
- integratorzy mają formalną specyfikację
- konfiguracja ma jedno źródło prawdy i sensowne grupowanie
- istnieje jawna ścieżka kompatybilności/migracji dla istniejących klientów

---

## Milestone 1.6.1 — Integration Adapter Boundary & Runtime Resilience

**Goal**
Ułatwić wymianę integracji zewnętrznych i usunąć kruche zachowania runtime w warstwie infra.

**Scope**
- wprowadzić interfejsy/kontrakty adapterów dla connectorów i targetów eksportu
- ukryć mapowanie payloadów providerów za adapterami
- dodać fake adapters i test harness do integracji
- znormalizować rejestrację i capability metadata integracji
- usunąć mutowanie globalnego `os.environ` w runtime dla proxy/bootstrapu
- scalić zduplikowaną logikę bootstrap/proxy między app i worker
- doprecyzować retry/invalidation strategy dla DB/cache
- wprowadzić registry/discovery mechanizm dla adapterów i testy kontraktowe dla wspólnego protokołu

**Issues (planned)**
- NEW-ISSUE: Define adapter contracts for feeds and export targets
- NEW-ISSUE: Move provider-specific mapping behind adapter implementations
- NEW-ISSUE: Add adapter fixtures and contract tests
- NEW-ISSUE: Remove runtime env mutation and duplicate proxy bootstrap logic
- NEW-ISSUE: Add adapter registry, capability metadata and discovery flow

**Definition of Done**
- nowa integracja powstaje według jednego szablonu adaptera
- use-case/domain code nie zależy od szczegółów payloadów providerów
- testy adapterów bronią kontraktu integracyjnego
- runtime nie polega na globalnych mutacjach środowiska procesu
- adaptery są rejestrowane i introspekcyjne przez wspólne capability metadata

---

## Milestone 1.7.0 — Product UX & Scope Rationalization

**Goal**
Przekształcić projekt z technicznego panelu w czytelniejszy produkt i ograniczyć funkcje o niskiej wartości względem kosztu utrzymania.

**Scope**
- wskazać top 3 scenariusze użytkownika i oprzeć o nie UI
- rozdzielić interfejs biznesowy od admin/debug
- przeprowadzić audyt funkcji pod kątem użycia i kosztu utrzymania
- uporządkować nawigację wokół realnych workflow
- jasno wskazać primary interface dla nowych użytkowników i integratorów

**Issues (planned)**
- NEW-ISSUE: Redesign UI around primary workflows instead of technical modules
- NEW-ISSUE: Separate business-facing UI from admin/debug tooling
- NEW-ISSUE: Audit features for simplification, deprecation or scope reduction
- NEW-ISSUE: Define and document the primary interface for onboarding and adoption

**Definition of Done**
- UI wspiera podstawowe workflow bez wiedzy operatorskiej
- admin/debug pozostaje dostępny, ale jest wyraźnie odseparowany
- roadmap rozróżnia scope core vs power-user
- użytkownik wie, czy podstawową ścieżką jest UI, API czy CLI dla jego scenariusza

---

## Dependencies

### Dependency graph (text)

```
#53 ─┬─> #55
     ├─> #59
     └─> #54

#57 ─┬─> #56 ─┬─> #61
#58 ─┘        └─> #62

#53/#55/#56/#57/#58/#61 ──> #62

(After 1.2.x stabilization)
#39 ─┬─> #60
     └─> #41 ──> #44
#43 ─┬─> #41
     └─> #44
```

### Dependency table

| Issue | Blocks / Enables | Depends on |
|------:|------------------|------------|
| #53 | #55, #54, #59 (clean health semantics) | — |
| #55 | LB monitor stability | #53 |
| #59 | "no crash from deps" policy | #53 (semantics) |
| #54 | MISP bounded/non-fatal checks | #53, (aligned with #55), #59 |
| #57 | Deterministic MWDB query behavior | — |
| #58 | Deterministic MWDB time filtering | — |
| #56 | MWDB "0 fetched" diagnosability | #57, #58 |
| #61 | Stats consistency | (ties to) #56 |
| #62 | Accurate documentation | #53, #55, #56, #57, #58, #61 |
| #39 | Modularization | (recommended after) 1.2.x |
| #60 | Connector standardization | #39 (recommended), 1.2.x stabilized |
| #43 | Perf decision gate | before #41/#44 heavy work |
| #41 | Streaming exports | #39 (often), #43 |
| #44 | Sentinel TI export | #41, #43 |

---

## Roadmap Table

| Version | Milestone | Theme | Primary issues |
|--------:|-----------|-------|----------------|
| 1.2.1 | Stability & Non-Fatal Dependencies | uptime behind F5/Nginx | #53 #55 #59 #54 + NEW dep refresh + NEW misp skip |
| 1.2.2 | Observability & "0 Fetched" Determinism | diagnose 0 fetched | #61 #56 #58 #57 + NEW tests + NEW stats persistence |
| 1.2.3 | Deployment & Ops Hardening | RHEL/Nginx/F5/SELinux runbooks | #62 + NEW 502 guide |
| 1.3.0 | Connector Architecture & Modularization | refactor + standard contract | #60 #39 #40 #41 #42 #43 #50 #44 |
| 1.4.0 | Full Route Modularization (Carry-over) | finalize blueprint split | #119 |
| 1.4.1 | Archive Integration & Dependency Hygiene | safe archive import + dependabot hygiene | NEW logs split + NEW workflow deps + NEW archive review |
| 1.4.2 | Security & Runtime Hardening | lock down admin and startup/runtime safety | NEW admin auth + NEW CSRF + NEW SECRET_KEY + NEW dockerignore |
| 1.5.0 | Core Modularization & Template Extraction | split monoliths + remove inline HTML | NEW ops split + NEW template migration + NEW boundary tests |
| 1.5.1 | Database Convergence & PostgreSQL Validation | unify schema and verify PG behavior | NEW schema convergence + NEW PG integration tests + NEW FK/limits |
| 1.6.0 | API & Configuration Modernization | versioned API + OpenAPI + config cleanup | NEW api v1 + NEW OpenAPI + NEW config/packaging refactor |
| 1.6.1 | Integration Adapter Boundary & Runtime Resilience | decouple providers + harden infra behavior | NEW adapter contracts + NEW env/bootstrap cleanup + NEW cache/retry strategy |
| 1.7.0 | Product UX & Scope Rationalization | business-ready workflows + scope pruning | NEW UI redesign + NEW admin split + NEW feature audit |

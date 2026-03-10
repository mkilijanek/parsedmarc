# IOC Service — Roadmap

This roadmap uses semantic versioning with the following intent:
- **1.2.x** — patches/hotfixes/observability/docs improvements (no big architecture refactors)
- **1.3.0** — architecture milestone (connector standardization + modularization)

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

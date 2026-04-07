# 07 — Product Owner

[← Powrót do README](../README.md) | [← QA Engineer](./qa-engineer.md)

---

## 🎯 Zakres odpowiedzialności

- Feature prioritization i backlog management
- User stories z acceptance criteria
- Stakeholder communication
- Release planning i roadmap
- Metryki biznesowe i KPI
- User feedback i continuous discovery

---

## 📊 Feature Prioritization Framework

### RICE Scoring

| Feature | **R**each | **I**mpact | **C**onfidence | **E**ffort | RICE Score | Priorytet |
|---------|----------|-----------|---------------|-----------|------------|------------|
| Admin Authentication | 100% users | 3 (massive) | 95% | 34 SP | **8.4** | 🔴 #1 |
| Adapter Pattern | 100% ops | 3 (massive) | 85% | 62 SP | **4.1** | 🔴 #2 |
| Code Modularization | 100% devs | 2 (high) | 90% | 40 SP | **4.5** | 🟠 #3 |
| Database Alignment | 80% devs | 2 (high) | 80% | 26 SP | **4.9** | 🟡 #4 |
| API Versioning | 60% users | 2 (high) | 85% | 30 SP | **3.4** | 🟡 #5 |
| UX Redesign | 100% users | 2 (high) | 70% | 37 SP | **3.8** | 🟢 #6 |

> RICE = (Reach × Impact × Confidence) / Effort

### MoSCoW per Release

**v1.5 (Security + Modularization):**
- **Must:** Admin auth, CSRF, RBAC, audit logging
- **Should:** Code modularization (main.py split)
- **Could:** Database convergence (start)
- **Won't:** UX redesign, adapter pattern

**v1.6 (Integration Foundation):**
- **Must:** Adapter Pattern, Registry, Pipeline
- **Should:** API versioning, OpenAPI
- **Could:** Feed config YAML
- **Won't:** UX redesign

**v2.0 (Full Product):**
- **Must:** UX redesign, all adapters migrated
- **Should:** Performance optimization
- **Could:** Kubernetes deployment
- **Won't:** Microservices migration

---

## 📝 User Stories (INVEST Criteria)

### Epic: Feed Management

**US-001: Jako operator SOC, chcę dodać nowe źródło Threat Intelligence w <2 dni, aby szybko reagować na nowe zagrożenia.**

Acceptance Criteria:
- [ ] AC1: Mogę dodać nowy adapter implementując FeedAdapter protocol
- [ ] AC2: Konfiguracja nowego feeda to plik YAML, nie zmiana kodu
- [ ] AC3: Auto-discovery: registry wykrywa nowy adapter bez restartu
- [ ] AC4: test_connection() weryfikuje config przed aktywacją
- [ ] AC5: Contract tests automatycznie walidują nowy adapter

**US-002: Jako analityk, chcę wyszukać IOC po wartości i wyeksportować wyniki do SIEM.**

Acceptance Criteria:
- [ ] AC1: Wyszukiwanie pełnotekstowe (substring match)
- [ ] AC2: Filtrowanie po: source, type, confidence, TLP, active
- [ ] AC3: Export w formacie: CSV, JSON, Splunk, Sentinel (min 4)
- [ ] AC4: Response time <200ms dla 50 wyników
- [ ] AC5: Paginacja dla dużych result setów

**US-003: Jako CISO, chcę mieć pełny audit trail, aby spełnić wymagania ISO 27001.**

Acceptance Criteria:
- [ ] AC1: Każde logowanie (success/failure) w audit logu
- [ ] AC2: Każda zmiana konfiguracji feedu w audit logu
- [ ] AC3: Każdy export danych >1000 rekordów w audit logu
- [ ] AC4: Audit log immutable (append-only)
- [ ] AC5: Filtrowanie i eksport audit logów

---

## 📅 Release Planning

### Sprint Cadence

- **Sprint duration:** 2 tygodnie
- **Sprint planning:** Poniedziałek, 1. dzień sprintu
- **Daily standup:** 15 min, co dzień
- **Sprint review:** Piątek, ostatni dzień sprintu
- **Sprint retrospective:** Po review

### Velocity Estimation

- **Zespół:** 3-4 developerów
- **Estimated velocity:** 25-35 SP / sprint
- **Total backlog:** ~229 SP
- **Estimated delivery:** 7-9 sprintów (14-18 tygodni)

---

## 📊 Business KPIs

| KPI | Baseline (v1.4.1) | Target (v2.0) | Jak mierzyć |
|-----|-------------------|---------------|-------------|
| Czas dodania integracji | ~10 dni | ≤2 dni | Tracking per adapter |
| ISO 27001 compliance | 54% | 100% | Audit checklist |
| Uptime | ~99% (est.) | >99.9% | Prometheus + Grafana |
| Response time p95 | ~300ms (est.) | <200ms | Prometheus histogram |
| Active IOC count | ~150k | >200k | DB query |
| User satisfaction | N/A | >4.0/5.0 | Quarterly survey |
| Deploy frequency | ~1/miesiąc | >1/tydzień | CI/CD metrics |
| Mean time to recovery | ~1h (est.) | <30 min | Incident tracking |

---

## 🔄 Stakeholder Communication Plan

| Stakeholder | Format | Częstotliwość | Zawartość |
|-------------|--------|---------------|----------|
| CISO | Email + spotkanie | Miesięcznie | Security compliance status |
| SOC Team Lead | Demo | Co sprint | Nowe features, feed status |
| Development Team | Standup + retro | Co sprint | Backlog, velocity, blockers |
| IT Management | Report | Kwartalnie | ROI, roadmap, budget |

---

## 🔄 Change Management

### Komunikacja zmian

1. **CHANGELOG.md** — technical changelog per release
2. **Release Notes** — user-friendly opis zmian
3. **Migration Guide** — jeśli breaking changes
4. **Training session** — przy dużych zmianach UI (M1.7.0)

### Rollback Criteria

- Error rate >5% po deploy → automatic rollback
- Critical bug w prod → manual rollback decision <15 min
- Data corruption → immediate rollback + incident

---

[← QA Engineer](./qa-engineer.md) | [Powrót do README →](../README.md)

# 09 — Metryki Jakości

[← Powrót do README](./README.md) | [← Best Practices](./08-best-practices.md) | [Następna: Zarządzanie Ryzykiem →](./10-risk-management.md)

---

## 📊 Dashboard Metryk

### Code Quality Metrics

| Metryka | Obecna | Target | Narzędzie |
|---------|--------|--------|----------|
| **Line coverage** | ~75% (est.) | ≥85% | pytest-cov |
| **Branch coverage** | ~60% (est.) | ≥75% | pytest-cov |
| **Cyclomatic complexity (avg)** | ~12 (est.) | <10 | radon |
| **Max function complexity** | ~30 | <20 | radon |
| **Code duplication** | ~8% (est.) | <3% | jscpd / radon |
| **Technical debt ratio** | ~15% | <10% | SonarQube (optional) |
| **Type hint coverage** | ~40% (est.) | ≥90% | mypy |
| **Linting errors** | >50 (est.) | 0 | ruff |

### Performance Metrics

| Metryka | Obecna | Target | Źródło |
|---------|--------|--------|--------|
| **Response time p50** | ~100ms | <50ms | Prometheus |
| **Response time p95** | ~300ms | <200ms | Prometheus |
| **Response time p99** | ~800ms | <500ms | Prometheus |
| **Throughput** | ~500 req/s | >1000 req/s | Locust |
| **Error rate** | <1% | <0.1% | Prometheus |
| **Feed sync time (avg)** | ~45s | <30s | Prometheus |
| **Export 100k IOC** | ~20s | <10s | Benchmark |

### Security Metrics

| Metryka | Obecna | Target | Narzędzie |
|---------|--------|--------|----------|
| **Critical vulnerabilities** | 0 | 0 | Trivy + Safety |
| **High vulnerabilities** | 0 | 0 | Trivy + Safety |
| **ISO 27001 compliance** | 54% | 100% | Audit checklist |
| **OWASP Top 10 coverage** | 70% | 100% | Manual audit |
| **Secret exposure incidents** | 0 | 0 | GitGuardian |
| **Mean time to patch (critical)** | N/A | <24h | Incident tracking |

### Business Metrics

| Metryka | Obecna | Target | Jak mierzyć |
|---------|--------|--------|-------------|
| **System uptime** | ~99% | >99.9% | Prometheus uptime |
| **Data freshness** | ~30 min | <5 min | last_fetch timestamp |
| **Active IOC count** | ~150k | >200k | DB query |
| **Feed count** | 10 | ≥15 | Registry count |
| **Export format count** | 17 | ≥20 | Formatter registry |
| **Time to add integration** | ~10 dni | ≤2 dni | Per-adapter tracking |

### Developer Experience Metrics

| Metryka | Obecna | Target | Jak mierzyć |
|---------|--------|--------|-------------|
| **CI build time** | ~8 min (est.) | <5 min | CI pipeline |
| **Deploy frequency** | ~1/miesiąc | >1/tydzień | Deploy log |
| **Lead time for changes** | ~2 tygodnie | <3 dni | PR open → deploy |
| **Mean time to recovery** | ~1h | <30 min | Incident tracking |
| **Change failure rate** | ~10% | <5% | Rollback count |
| **PR review time** | ~2 dni | <1 dzień | GitHub/GitLab metrics |

---

## ✅ Success Criteria per Milestone

### M1.4.2 — Security

| Kryterium | Metryka | Threshold |
|-----------|---------|-----------|
| Auth working | Login success rate | >99% |
| CSRF protection | CSRF bypass attempts blocked | 100% |
| Audit completeness | Admin operations logged | 100% |
| Penetration test | Critical/High findings | 0 |

### M1.5.0 — Modularization

| Kryterium | Metryka | Threshold |
|-----------|---------|-----------|
| main.py size | LOC | <500 |
| ops.py eliminated | Files created | ≥3 nowe moduły |
| Regression | Existing tests passing | 100% |
| New coverage | New module coverage | ≥85% |

### M1.5.1 — Database

| Kryterium | Metryka | Threshold |
|-----------|---------|-----------|
| Schema alignment | Drift detection | 0 differences |
| FK constraints | Missing FKs | 0 |
| PG tests | PG-specific test count | ≥20 |

### M1.6.1 — Adapters 🎯

| Kryterium | Metryka | Threshold |
|-----------|---------|-----------|
| Data parity | Old vs new adapter output | 100% match |
| Contract tests | All adapters passing | 100% |
| Integration time | New adapter (measured) | ≤2 dni |
| Performance | Sync time regression | <10% |
| Old code removed | Dead connector code | 0 LOC |

---

## 📊 Monitoring Dashboards Design

### Dashboard 1: Operations Overview

```
┌─────────────────────────────────────────────┐
│ IOC Service — Operations Dashboard           │
├───────────┬───────────┬───────────┬──────────┤
│ Requests/s │ Error Rate │ Latency p95│ Uptime   │
│  1,234     │   0.02%   │   145ms   │ 99.97%   │
├───────────┴───────────┴───────────┴──────────┤
│ [Request Rate Graph ──────────────────────]  │
│ [Error Rate Graph ────────────────────────]  │
│ [Latency Heatmap ─────────────────────────]  │
├─────────────────────────────────────────────┤
│ Feed Health:                                 │
│ CrowdSec  [██████████] 100% ✅               │
│ MISP      [████████░░]  80% ⚠️               │
│ MWDB      [██████████] 100% ✅               │
│ abuse.ch  [█████████░]  90% ✅               │
│ Bazaar    [██░░░░░░░░]  20% 🔴               │
└─────────────────────────────────────────────┘
```

### Alerting Thresholds

| Metryka | Warning | Critical | Akcja |
|---------|---------|----------|-------|
| Error rate | >1% (5min) | >5% (5min) | Page on-call |
| Latency p95 | >300ms (10min) | >1s (5min) | Investigate |
| Feed down | 1h no data | 4h no data | Check feed |
| Circuit open | Any | >15min | Investigate source |
| Disk usage | >80% | >90% | Cleanup/expand |
| Memory | >75% | >90% | Scale/investigate |
| DB connections | >80% pool | >95% pool | Scale pool |

---

[← Best Practices](./08-best-practices.md) | [Następna: Zarządzanie Ryzykiem →](./10-risk-management.md)

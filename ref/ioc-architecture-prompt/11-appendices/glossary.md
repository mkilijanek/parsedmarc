# 11 — Załącznik A: Słownik

[← Powrót do README](../README.md) | [Następna: Diagramy →](./diagrams.md)

---

## Terminy techniczne

| Termin | Definicja |
|--------|----------|
| **IOC** | Indicator of Compromise — wskaźnik kompromitacji (IP, domena, hash, URL) |
| **Threat Intelligence** | Informacje o zagrożeniach cyberbezpieczeństwa (TI) |
| **Feed** | Źródło danych Threat Intelligence (np. CrowdSec, MISP) |
| **Adapter** | Komponent implementujący FeedAdapter Protocol dla danego źródła |
| **Pipeline** | Sekwencja kroków przetwarzania danych (fetch → normalize → dedup → persist) |
| **Registry** | Centralny rejestr adapterów z auto-discovery |
| **Circuit Breaker** | Wzórc fault isolation — zapobiega kaskadowym awariom |
| **Canonical IOC** | Znormalizowany format IOC wewnątrz systemu |
| **Upsert** | INSERT ... ON CONFLICT UPDATE — wstaw lub zaktualizuj |
| **TLP** | Traffic Light Protocol — klasyfikacja poufności (WHITE/GREEN/AMBER/RED) |
| **SIEM** | Security Information and Event Management (np. Splunk, Sentinel) |
| **RBAC** | Role-Based Access Control — kontrola dostępu oparta na rolach |
| **CSRF** | Cross-Site Request Forgery — atak polegający na wymuszeniu akcji |
| **JWT** | JSON Web Token — token autentykacji |
| **ADR** | Architecture Decision Record — zapis decyzji architektonicznej |
| **CC** | Cyclomatic Complexity — miara złożoności kodu |
| **SP** | Story Points — jednostka estymacji wysiłku |
| **FTS** | Full-Text Search — wyszukiwanie pełnotekstowe |
| **JSONB** | PostgreSQL binary JSON — wydajny format przechowywania JSON |
| **pg_trgm** | PostgreSQL trigram extension — wyszukiwanie substring |
| **AOF** | Append Only File — tryb persystencji Redis |
| **LRU** | Least Recently Used — strategia eviction cache |
| **mTLS** | Mutual TLS — dwustronna weryfikacja certyfikatów |
| **WAF** | Web Application Firewall |
| **SSRF** | Server-Side Request Forgery |
| **IDOR** | Insecure Direct Object Reference |
| **RTO** | Recovery Time Objective — max czas przywracania |
| **RPO** | Recovery Point Objective — max utrata danych |
| **SLA** | Service Level Agreement |
| **DORA** | DevOps Research and Assessment — metryki DevOps |

---

## Akronimy

| Akronim | Rozwinięcie |
|---------|----------|
| API | Application Programming Interface |
| CI/CD | Continuous Integration / Continuous Delivery |
| CVE | Common Vulnerabilities and Exposures |
| CVSS | Common Vulnerability Scoring System |
| DI | Dependency Injection |
| DTO | Data Transfer Object |
| ERD | Entity-Relationship Diagram |
| GDPR | General Data Protection Regulation |
| HA | High Availability |
| HSTS | HTTP Strict Transport Security |
| ISO | International Organization for Standardization |
| K8s | Kubernetes |
| LOC | Lines of Code |
| MISP | Malware Information Sharing Platform |
| MWDB | Malware Database (CERT.pl) |
| ORM | Object-Relational Mapping |
| OWASP | Open Web Application Security Project |
| PO | Product Owner |
| QA | Quality Assurance |
| REST | Representational State Transfer |
| SOC | Security Operations Center |
| SSR | Server-Side Rendering |
| TDE | Transparent Data Encryption |
| TLS | Transport Layer Security |
| UoW | Unit of Work |
| WSGI | Web Server Gateway Interface |

---

## Referencje do standardów

| Standard | Opis | Link |
|----------|------|------|
| **ISO/IEC 27001:2022** | Information security management | [iso.org](https://www.iso.org/standard/27001) |
| **OWASP Top 10 (2021)** | Top web application security risks | [owasp.org/Top10](https://owasp.org/www-project-top-ten/) |
| **OWASP ASVS 4.0** | Application Security Verification Standard | [owasp.org/ASVS](https://owasp.org/www-project-application-security-verification-standard/) |
| **CIS Docker Benchmark** | Container security best practices | [cisecurity.org](https://www.cisecurity.org/benchmark/docker) |
| **NIST SP 800-53** | Security and Privacy Controls | [nist.gov](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final) |
| **STRIDE** | Threat modeling methodology (Microsoft) | [microsoft.com](https://docs.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats) |
| **PEP 8** | Python style guide | [peps.python.org](https://peps.python.org/pep-0008/) |
| **Semantic Versioning** | Version numbering convention | [semver.org](https://semver.org/) |
| **Conventional Commits** | Commit message format | [conventionalcommits.org](https://www.conventionalcommits.org/) |
| **C4 Model** | Software architecture diagrams | [c4model.com](https://c4model.com/) |
| **TLP 2.0** | Traffic Light Protocol | [first.org/tlp](https://www.first.org/tlp/) |

---

[← Powrót do README](../README.md) | [Następna: Diagramy →](./diagrams.md)

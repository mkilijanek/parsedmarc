# IOC Service — Architecture Diagrams

Mermaid source files for the v1.9.1 architecture diagrams.
Render with [Mermaid Live Editor](https://mermaid.live/) or any IDE plugin that supports Mermaid.

| File | Diagram Type | Description |
|------|-------------|-------------|
| [`class-domain.mmd`](class-domain.mmd) | Class | Core domain model — Indicator, Feed, FeedRun, SyncJob, ExportJob, AppSetting, AppLog, AuditLog, DeadLetterJob |
| [`service-layer.mmd`](service-layer.mmd) | Class | Service layer — query_svc, feed_ops, audit_svc, app_log_svc, scheduler_svc, export_svc, feed_config_svc |
| [`data-flow.mmd`](data-flow.mmd) | Flowchart | Feed ingestion pipeline — adapter → fetch_batches → persist_batches → DB → cache invalidation |
| [`request-flow.mmd`](request-flow.mmd) | Sequence | API v1 request lifecycle — auth → rate limit → query parser → cache → DB → formatter → response |
| [`admin-sync-flow.mmd`](admin-sync-flow.mmd) | Sequence | Admin manual sync — browser → Flask → enqueue_sync_for_source → SyncJob → worker → FeedRun |
| [`architecture-overview.mmd`](architecture-overview.mmd) | C4 Context | System component overview — Flask, Worker, Nginx, PostgreSQL, Redis, service layer, external feeds |

## PlantUML Diagrams

The `docs/uml/` directory contains the full PlantUML source set with pre-rendered PNGs/SVGs
covering deployment, ER diagram, state machines, use cases, and service class diagrams.

See [`docs/uml/README.md`](../uml/README.md) for details.

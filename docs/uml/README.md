# UML Diagrams for IOC Threat Intelligence Service

Status: refreshed for release `1.2.0` (2026-03-02).

This directory contains UML source and generated diagram artifacts aligned with current scheduler, admin sync-job controls, and deployment/runtime behavior.

## 1.2.0 Updates

- Sync job lifecycle includes `cancel_requested` and `cancelled` states.
- Sync sequence includes admin actions: retry failed/cancelled jobs and cancel queued/running jobs.
- Deployment and component diagrams include sync-job control surface and worker refresh jobs.
- Diagram set is now part of 1.2.x release documentation scope.

## File Structure

### PlantUML Source Files (.puml)
These are the primary source files that can be rendered to PNG/SVG:

| File | Diagram Type | Description |
|------|--------------|-------------|
| `deployment.puml` | Deployment | Production Docker architecture |
| `class-domain.puml` | Class | Domain model (entities) |
| `class-services.puml` | Class | Service layer classes |
| `er-diagram.puml` | ERD | PostgreSQL database schema |
| `component.puml` | Component | System components |
| `use-cases.puml` | Use Case | User interactions |
| `sequence-sync.puml` | Sequence | Feed synchronization flow |
| `sequence-export.puml` | Sequence | Export request flow |
| `activity-ingestion.puml` | Activity | Indicator ingestion process |
| `state-syncjob.puml` | State Machine | SyncJob lifecycle |

### StarUML Files (.mdj)
Legacy StarUML format files (for reference):
- `system-architecture.mdj`
- `component-diagram.mdj`
- `database-er-diagram.mdj`
- `use-case-diagram.mdj`
- `activity-diagrams.mdj`
- `state-machine.mdj`

## Generating Images

### Option 1: Using the Script (Recommended)

```bash
cd docs/uml
chmod +x generate-images.sh
./generate-images.sh png    # For PNG images
./generate-images.sh svg    # For SVG images
```

This will:
1. Download PlantUML if not present
2. Generate images for all `.puml` files
3. Save them to `generated/` directory
4. Optionally create an HTML gallery

For non-interactive CI/local automation:
```bash
cd docs/uml
printf 'n\n' | ./generate-images.sh png
printf 'n\n' | ./generate-images.sh svg
```

Pre-generated artifacts for release `1.2.0` are included in:
- `docs/uml/generated/*.png`
- `docs/uml/generated/*.svg`
- `docs/uml/generated/index.html`

### Option 2: Using PlantUML Online

Visit [PlantUML Online Server](http://www.plantuml.com/plantuml/) and paste the content of any `.puml` file.

### Option 3: Using VS Code Extension

Install the "PlantUML" extension by Jebbs in VS Code:
1. Open any `.puml` file
2. Press `Alt+D` to preview
3. Right-click → "Export Current Diagram" to save as PNG/SVG

### Option 4: Using Docker

```bash
docker run -v $(pwd):/data plantuml/plantuml -tpng /data/*.puml
docker run -v $(pwd):/data plantuml/plantuml -tsvg /data/*.puml
```

### Option 5: Using Java CLI

```bash
# Download PlantUML
wget https://github.com/plantuml/plantuml/releases/download/v1.2024.0/plantuml-1.2024.0.jar

# Generate PNG
java -jar plantuml-1.2024.0.jar -tpng *.puml

# Generate SVG
java -jar plantuml-1.2024.0.jar -tsvg *.puml
```

## Diagram Overview

### 1. Deployment Diagram
Shows production deployment with Docker containers:
- Nginx Edge (TLS, rate limiting)
- Flask App (Gunicorn)
- Background Worker
- PostgreSQL 16 + Redis 7
- External APIs (CrowdSec, MISP, abuse.ch, MWDB)

### 2. Class Diagrams

**Domain Model**: Core entities
- Indicator, SyncJob, Feed, FeedStats
- AuditLog, ExportJob, AppSetting, FeedRun, AppLog

**Service Layer**: Implementation classes
- CrowdSecService, MISPService, MalwareBazaarService
- MWDBService, AbuseChService, CorrelationService
- ExportService, QueryParser

### 3. Database ER Diagram
PostgreSQL schema with:
- 9 tables with relationships
- Column types, constraints, indexes
- JSONB columns for metadata
- PostgreSQL-specific types (INET, UUID, arrays)

### 4. Component Diagram
High-level components:
- Web Application (API, UI, Security)
- Feed Connectors (5 external sources)
- Processing engines (Query, Export, Correlation)
- Background Worker
- PostgreSQL, Redis, Nginx

### 5. Use Case Diagram
Three actors:
- Security Analyst (search, export, view)
- Administrator (configure, manage feeds)
- External System (API integration, metrics)

### 6. Sequence Diagrams

**Feed Sync**: Scheduler → SyncJob → FeedService → External API → Database

**Export Request**: Client → Flask → Security → Parser → Database → Formatter → Response

### 7. Activity Diagram
Indicator ingestion workflow:
1. Scheduler triggers sync
2. Idempotency check
3. API fetch with retry
4. Parse and normalize
5. Database upsert
6. Update statistics

### 8. State Machine
SyncJob lifecycle:
- `queued` → `running` → (`success` | `failed`)
- With entry/exit actions

## Architecture Summary

```
┌─────────────────────────────────────────────────────────────┐
│                        Docker Host                           │
│  ┌──────────┐    ┌──────────────┐    ┌──────────────────┐  │
│  │  Nginx   │───▶│  Flask App   │───▶│   PostgreSQL 16  │  │
│  │  (Edge)  │    │  (Gunicorn)  │    │    (Primary)     │  │
│  └──────────┘    └──────┬───────┘    └──────────────────┘  │
│                         │                                   │
│              ┌──────────┴──────────┐   ┌─────────────────┐ │
│              │    Redis 7 Cache    │   │  Worker (BG)    │ │
│              │    (Rate Limit)     │   │   (Scheduler)   │ │
│              └─────────────────────┘   └─────────────────┘ │
└─────────────────────────────────────────────────────────────┘
         │              │              │              │
         ▼              ▼              ▼              ▼
   ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐
   │ CrowdSec │  │   MISP   │  │ abuse.ch │  │   MWDB   │
   └──────────┘  └──────────┘  └──────────┘  └──────────┘
```

## Data Flow

### Ingestion
```
External API → Connector → Normalizer → PostgreSQL
                   ↓
              SyncJob Queue ← Worker
                   ↓
              FeedStats Update
```

### Export
```
Client → Validation → Query Parser → Cache Check → DB Query
                                             ↓
              Formatted Response ← Formatter ← Results
                                             ↓
                                        Cache Store
```

## Customization

### Themes
PlantUML files use `!theme cerulean-outline`. Available themes:
- `cerulean-outline` (current)
- `plain`
- `bluegray`
- `materia`
- `sketchy`
- `spacelab`

Change by editing the `!theme` line in any `.puml` file.

### Colors
You can customize colors using skinparam:
```plantuml
skinparam classBackgroundColor White
skinparam classArrowColor Black
skinparam componentBackgroundColor LightBlue
```

## Contributing

When adding new diagrams:
1. Create a new `.puml` file following naming convention
2. Add entry to this README
3. Run `./generate-images.sh` to regenerate images
4. Commit both `.puml` source and generated images

## References

- [PlantUML Guide](https://plantuml.com/guide)
- [PlantUML Cheat Sheet](https://blog.anoff.io/puml-cheatsheet.pdf)
- [Project AGENTS.md](../AGENTS.md)
- [Project README](../../README.md)

# Quick Start - UML Diagrams

## View Diagrams Online

The fastest way to view these diagrams is using the PlantUML online server:

1. Go to [www.plantuml.com/plantuml](http://www.plantuml.com/plantuml/uml/SyfFKj2rKt3CoKnELR1Io4ZDoSa70000)
2. Copy-paste content from any `.puml` file
3. Diagram renders automatically

## Generate Local Images

### Prerequisites

**Option A: Using Docker (No Java needed)**
```bash
docker run -v $(pwd):/data plantuml/plantuml -tpng /data/*.puml
```

**Option B: Using Java**
```bash
# Download PlantUML once
wget https://github.com/plantuml/plantuml/releases/download/v1.2024.0/plantuml-1.2024.0.jar

# Generate all PNGs
java -jar plantuml-1.2024.0.jar -tpng *.puml

# Generate all SVGs
java -jar plantuml-1.2024.0.jar -tsvg *.puml
```

**Option C: Using the helper script**
```bash
./generate-images.sh png
# or
./generate-images.sh svg
```

### VS Code Extension

For live preview while editing:

1. Install "PlantUML" extension by Jebbs
2. Open any `.puml` file
3. Press `Alt+D` for preview
4. Right-click → "Export Current Diagram"

## Individual Diagrams

### Deployment
```bash
plantuml -tpng deployment.puml
```
Shows Docker architecture with all services.

### Domain Model
```bash
plantuml -tpng class-domain.puml
```
Core entities: Indicator, SyncJob, Feed, etc.

### Service Layer
```bash
plantuml -tpng class-services.puml
```
Feed connectors and business logic.

### Database Schema
```bash
plantuml -tpng er-diagram.puml
```
PostgreSQL schema with all tables.

### Component Diagram
```bash
plantuml -tpng component.puml
```
System components and dependencies.

### Use Cases
```bash
plantuml -tpng use-cases.puml
```
User interactions and functionality.

### Sequences & Activities
```bash
plantuml -tpng sequence-sync.puml
plantuml -tpng sequence-export.puml
plantuml -tpng activity-ingestion.puml
```

### State Machine
```bash
plantuml -tpng state-syncjob.puml
```

## Generate HTML Gallery

After generating images, run:
```bash
./generate-images.sh png
# Type 'y' when prompted for HTML gallery
```

Then open `generated/index.html` in your browser.

## Tips

- All diagrams use `!theme cerulean-outline` for consistent styling
- PNG files are ~50-200KB each
- SVG files are vector graphics, ideal for documentation
- Edit `.puml` files with any text editor
- VS Code with PlantUML extension provides live preview

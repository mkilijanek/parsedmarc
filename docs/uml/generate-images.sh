#!/bin/bash
# Generate PNG/SVG images from PlantUML files
# Usage: ./generate-images.sh [png|svg]

set -e

FORMAT=${1:-png}
PLANTUML_VERSION="1.2024.0"
PLANTUML_JAR="plantuml-${PLANTUML_VERSION}.jar"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}IOC Service UML Diagram Generator${NC}"
echo "=================================="
echo ""

# Check for PlantUML
if ! command -v plantuml &> /dev/null; then
    echo -e "${YELLOW}PlantUML not found in PATH${NC}"
    
    # Check for local JAR
    if [ ! -f "$PLANTUML_JAR" ]; then
        echo -e "${BLUE}Downloading PlantUML...${NC}"
        wget -q "https://github.com/plantuml/plantuml/releases/download/v${PLANTUML_VERSION}/${PLANTUML_JAR}"
        echo -e "${GREEN}Downloaded ${PLANTUML_JAR}${NC}"
    fi
    
    PLANTUML_CMD="java -jar ${PLANTUML_JAR}"
else
    PLANTUML_CMD="plantuml"
fi

# Create output directory
mkdir -p generated

echo -e "${BLUE}Generating ${FORMAT} images...${NC}"
echo ""

# Generate images for all .puml files
for file in *.puml; do
    if [ -f "$file" ]; then
        name=$(basename "$file" .puml)
        echo -e "Processing: ${YELLOW}${file}${NC}"
        
        if [ "$FORMAT" == "svg" ]; then
            $PLANTUML_CMD -tsvg "$file" -o generated/
            echo -e "  ${GREEN}✓ generated/${name}.svg${NC}"
        else
            $PLANTUML_CMD -tpng "$file" -o generated/
            echo -e "  ${GREEN}✓ generated/${name}.png${NC}"
        fi
    fi
done

echo ""
echo -e "${GREEN}Done!${NC} Images saved to 'generated/' directory"
echo ""

# List generated files
echo "Generated files:"
ls -lh generated/

# Optional: Generate HTML gallery
if command -v python3 &> /dev/null; then
    echo ""
    read -p "Generate HTML gallery? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        cat > generated/index.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>IOC Service UML Diagrams</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 1400px; margin: 0 auto; padding: 20px; background: #f5f5f5; }
        h1 { color: #333; border-bottom: 3px solid #4CAF50; padding-bottom: 10px; }
        .diagram { background: white; margin: 20px 0; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .diagram h2 { margin-top: 0; color: #2196F3; }
        .diagram img { max-width: 100%; height: auto; border: 1px solid #ddd; border-radius: 4px; }
        .info { color: #666; font-size: 0.9em; margin-top: 10px; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(600px, 1fr)); gap: 20px; }
    </style>
</head>
<body>
    <h1>🏗️ IOC Threat Intelligence Service - UML Diagrams</h1>
    <p>This gallery contains all UML diagrams for the IOC Service project.</p>
    
    <div class="grid">
        <div class="diagram">
            <h2>Deployment Diagram</h2>
            <img src="deployment.png" alt="Deployment Diagram" />
            <div class="info">Production deployment architecture with Docker containers</div>
        </div>
        
        <div class="diagram">
            <h2>Domain Model</h2>
            <img src="class-domain.png" alt="Domain Model" />
            <div class="info">Core domain entities and their relationships</div>
        </div>
        
        <div class="diagram">
            <h2>Service Layer</h2>
            <img src="class-services.png" alt="Service Layer" />
            <div class="info">Service classes implementing feed connectors and business logic</div>
        </div>
        
        <div class="diagram">
            <h2>Database Schema</h2>
            <img src="er-diagram.png" alt="ER Diagram" />
            <div class="info">PostgreSQL database schema with all tables and relationships</div>
        </div>
        
        <div class="diagram">
            <h2>Component Diagram</h2>
            <img src="component.png" alt="Component Diagram" />
            <div class="info">High-level system components and dependencies</div>
        </div>
        
        <div class="diagram">
            <h2>Use Cases</h2>
            <img src="use-cases.png" alt="Use Case Diagram" />
            <div class="info">User interactions and system functionality</div>
        </div>
    </div>
    
    <h2>Behavioral Diagrams</h2>
    
    <div class="diagram">
        <h2>Feed Sync Sequence</h2>
        <img src="sequence-sync.png" alt="Sync Sequence" />
        <div class="info">Sequence diagram for feed synchronization workflow</div>
    </div>
    
    <div class="diagram">
        <h2>Export Sequence</h2>
        <img src="sequence-export.png" alt="Export Sequence" />
        <div class="info">Sequence diagram for indicator export workflow</div>
    </div>
    
    <div class="diagram">
        <h2>Ingestion Activity</h2>
        <img src="activity-ingestion.png" alt="Ingestion Activity" />
        <div class="info">Activity diagram for indicator ingestion process</div>
    </div>
    
    <div class="diagram">
        <h2>SyncJob State Machine</h2>
        <img src="state-syncjob.png" alt="State Machine" />
        <div class="info">State transitions for sync job lifecycle</div>
    </div>
    
    <footer style="text-align: center; margin-top: 40px; color: #666;">
        <p>Generated for IOC Threat Intelligence Service v1.1.x</p>
    </footer>
</body>
</html>
EOF
        echo -e "${GREEN}Generated generated/index.html${NC}"
    fi
fi

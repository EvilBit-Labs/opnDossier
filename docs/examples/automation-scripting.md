# Automation and Scripting Examples

This guide covers automation workflows and scripting examples for integrating opnDossier into CI/CD pipelines and automated processes.

## CI/CD Integration

### GitHub Actions Workflow

```yaml
# .github/workflows/documentation.yml
name: Generate Documentation
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  generate-docs:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.26'

      - name: Install opnDossier
        run: go install github.com/EvilBit-Labs/opnDossier@latest

      - name: Validate Configuration
        run: opndossier validate config.xml

      - name: Generate Documentation
        run: |
          opndossier convert config.xml -o docs/network-config.md

      - name: Commit Documentation
        if: github.event_name == 'push'
        run: |
          git config --local user.email "action@github.com"
          git config --local user.name "GitHub Action"
          git add docs/network-config.md
          git commit -m "docs: update network configuration" || exit 0
          git push
```

### GitLab CI Pipeline

```yaml
# .gitlab-ci.yml
stages:
  - validate
  - documentation

variables:
  GOVERSION: '1.26'

validate:
  stage: validate
  image: golang:${GOVERSION}
  before_script:
    - go install github.com/EvilBit-Labs/opnDossier@latest
  script:
    - opndossier validate config.xml

documentation:
  stage: documentation
  image: golang:${GOVERSION}
  before_script:
    - go install github.com/EvilBit-Labs/opnDossier@latest
  script:
    - opndossier convert config.xml -o docs/network-config.md
    - opndossier convert config.xml -f json -o docs/network-config.json
  artifacts:
    paths:
      - docs/network-config.md
      - docs/network-config.json
    expire_in: 30 days
```

### Jenkins Pipeline

```groovy
// Jenkinsfile
pipeline {
    agent any

    stages {
        stage('Setup') {
            steps {
                sh 'go install github.com/EvilBit-Labs/opnDossier@latest'
            }
        }

        stage('Validate') {
            steps {
                sh 'opndossier validate config.xml'
            }
        }

        stage('Generate Documentation') {
            steps {
                sh 'opndossier convert config.xml -o docs/network-config.md'
                sh 'opndossier convert config.xml -f json -o docs/network-config.json'
            }
        }

        stage('Archive') {
            steps {
                archiveArtifacts artifacts: 'docs/*.md,docs/*.json', fingerprint: true
            }
        }
    }

    post {
        always {
            cleanWs()
        }
    }
}
```

## Batch Processing Scripts

### Process Multiple Configurations

```bash
#!/bin/bash
# batch-process.sh

set -e

# Configuration
INPUT_DIR="configs"
OUTPUT_DIR="docs"
LOG_FILE="batch-process.log"

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Initialize log file
echo "Batch processing started at $(date)" > "$LOG_FILE"

# Process all XML files
for config_file in "$INPUT_DIR"/*.xml; do
    if [ -f "$config_file" ]; then
        filename=$(basename "$config_file" .xml)
        echo "Processing $filename..." | tee -a "$LOG_FILE"

        # Validate configuration
        if opndossier validate "$config_file" >> "$LOG_FILE" 2>&1; then
            # Generate documentation
            opndossier convert "$config_file" -o "$OUTPUT_DIR/${filename}.md" >> "$LOG_FILE" 2>&1
            echo "  $filename processed successfully" | tee -a "$LOG_FILE"
        else
            echo "  $filename validation failed" | tee -a "$LOG_FILE"
        fi
    fi
done

echo "Batch processing completed at $(date)" | tee -a "$LOG_FILE"
```

### Parallel Processing

```bash
#!/bin/bash
# parallel-process.sh

# Configuration
INPUT_DIR="configs"
OUTPUT_DIR="docs"
MAX_JOBS=4

# Function to process a single file
process_file() {
    local config_file="$1"
    local filename
    filename=$(basename "$config_file" .xml)

    if opndossier validate "$config_file" > /dev/null 2>&1; then
        opndossier convert "$config_file" -o "$OUTPUT_DIR/${filename}.md" > /dev/null 2>&1
        echo "  $filename completed"
    else
        echo "  $filename failed validation"
        return 1
    fi
}

# Export function for parallel execution
export -f process_file
export OUTPUT_DIR

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Process files in parallel
find "$INPUT_DIR" -name "*.xml" | xargs -P "$MAX_JOBS" -I {} bash -c 'process_file "$@"' _ {}
```

### Scheduled Processing

```bash
#!/bin/bash
# scheduled-process.sh

# Configuration
CONFIG_DIR="/etc/opnsense"
BACKUP_DIR="/backups/configs"
DOCS_DIR="/var/www/docs"
RETENTION_DAYS=30

# Create directories
mkdir -p "$BACKUP_DIR" "$DOCS_DIR"

# Get current timestamp
TIMESTAMP=$(date +%Y-%m-%d_%H-%M-%S)

# Backup current configuration
cp "$CONFIG_DIR/config.xml" "$BACKUP_DIR/config-${TIMESTAMP}.xml"

# Generate documentation
opndossier convert "$CONFIG_DIR/config.xml" -o "$DOCS_DIR/current-config.md"

# Clean up old backups
find "$BACKUP_DIR" -name "config-*.xml" -mtime +$RETENTION_DAYS -delete

echo "Scheduled processing completed at $(date)"
```

## Automated Documentation

### Daily Documentation Update

```bash
#!/bin/bash
# daily-docs.sh

# Configuration
CONFIG_FILE="/etc/opnsense/config.xml"
DOCS_DIR="/var/www/network-docs"

# Create documentation directory
mkdir -p "$DOCS_DIR"

# Get current date
DATE=$(date +%Y-%m-%d)

# Validate configuration
if ! opndossier validate "$CONFIG_FILE"; then
    echo "Configuration validation failed"
    exit 1
fi

# Generate documentation
if opndossier convert "$CONFIG_FILE" -o "$DOCS_DIR/network-config-${DATE}.md"; then
    echo "Documentation generated successfully"
else
    echo "Documentation generation failed"
    exit 1
fi
```

### Configuration Change Detection

```bash
#!/bin/bash
# config-change-detector.sh

# Configuration
CONFIG_FILE="/etc/opnsense/config.xml"
PREVIOUS_HASH_FILE="/tmp/config.hash"

# Calculate current hash
CURRENT_HASH=$(sha256sum "$CONFIG_FILE" | cut -d' ' -f1)

# Check if hash file exists
if [ -f "$PREVIOUS_HASH_FILE" ]; then
    PREVIOUS_HASH=$(cat "$PREVIOUS_HASH_FILE")

    # Compare hashes
    if [ "$CURRENT_HASH" != "$PREVIOUS_HASH" ]; then
        echo "Configuration change detected"

        # Generate updated documentation
        opndossier convert "$CONFIG_FILE" \
            -o "/var/www/network-docs/network-config-$(date +%Y-%m-%d_%H-%M-%S).md"

        # Generate JSON export for diff analysis
        opndossier convert "$CONFIG_FILE" -f json -o "/tmp/current-config.json"
    fi
fi

# Update hash file
echo "$CURRENT_HASH" > "$PREVIOUS_HASH_FILE"
```

## Monitoring and Health Checks

### Health Check Script

```bash
#!/bin/bash
# health-check.sh

CONFIG_FILE="/etc/opnsense/config.xml"
LOG_FILE="/var/log/opndossier-health.log"

# Check if configuration file exists
if [ ! -f "$CONFIG_FILE" ]; then
    echo "$(date): Configuration file not found: $CONFIG_FILE" >> "$LOG_FILE"
    exit 1
fi

# Validate configuration
if ! opndossier validate "$CONFIG_FILE" > /dev/null 2>&1; then
    echo "$(date): Configuration validation failed" >> "$LOG_FILE"
    exit 1
fi

# Test documentation generation
if ! opndossier convert "$CONFIG_FILE" -o /tmp/test.md > /dev/null 2>&1; then
    echo "$(date): Documentation generation failed" >> "$LOG_FILE"
    exit 1
fi

# Clean up test file
rm -f /tmp/test.md

echo "$(date): Health check passed" >> "$LOG_FILE"
```

### Performance Monitoring

```bash
#!/bin/bash
# performance-monitor.sh

CONFIG_FILE="/etc/opnsense/config.xml"
METRICS_FILE="/var/log/opndossier-metrics.csv"

# Measure validation time
VALIDATION_START=$(date +%s%N)
opndossier validate "$CONFIG_FILE" > /dev/null 2>&1
VALIDATION_END=$(date +%s%N)
VALIDATION_MS=$(( (VALIDATION_END - VALIDATION_START) / 1000000 ))

# Measure conversion time
CONVERSION_START=$(date +%s%N)
opndossier convert "$CONFIG_FILE" -o /tmp/test.md > /dev/null 2>&1
CONVERSION_END=$(date +%s%N)
CONVERSION_MS=$(( (CONVERSION_END - CONVERSION_START) / 1000000 ))

# Log metrics
echo "$(date +%Y-%m-%d_%H:%M:%S),${VALIDATION_MS}ms,${CONVERSION_MS}ms" >> "$METRICS_FILE"

# Clean up
rm -f /tmp/test.md
```

## Integration Examples

### Ansible Playbook

```yaml
  - name: Generate opnDossier Documentation
    hosts: firewalls
    become: true
    tasks:
      - name: Install Go
        package:
          name: golang
          state: present

      - name: Install opnDossier
        shell: go install github.com/EvilBit-Labs/opnDossier@latest
        environment:
          PATH: '{{ ansible_env.PATH }}:/root/go/bin'

      - name: Create documentation directory
        file:
          path: /var/www/network-docs
          state: directory
          mode: '0755'

      - name: Generate documentation
        shell: >
          opndossier convert /conf/config.xml
          -o /var/www/network-docs/network-config.md
        environment:
          PATH: '{{ ansible_env.PATH }}:/root/go/bin'
```

### Docker Usage

opnDossier can be used in Docker containers for ephemeral documentation generation:

```dockerfile
FROM golang:1.26-alpine AS builder

RUN go install github.com/EvilBit-Labs/opnDossier@latest

FROM alpine:latest

COPY --from=builder /go/bin/opnDossier /usr/local/bin/opndossier

ENTRYPOINT ["opndossier"]
```

```bash
# Build and use
docker build -t opndossier .
docker run --rm -v "$PWD:/data" opndossier convert /data/config.xml -o /data/report.md
```

## Best Practices

### 1. Error Handling in Scripts

```bash
#!/bin/bash
set -e  # Exit on any error

# Function to handle errors
error_handler() {
    local exit_code=$?
    echo "Error occurred in line $1, exit code: $exit_code"
    exit $exit_code
}

trap 'error_handler $LINENO' ERR

# Your automation logic here
opndossier validate config.xml
opndossier convert config.xml -o docs/network-config.md
```

### 2. Logging and Monitoring

```bash
#!/bin/bash
LOG_FILE="/var/log/opndossier-automation.log"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

log "Starting automation process"

if opndossier validate config.xml; then
    log "Configuration validation successful"
else
    log "Configuration validation failed"
    exit 1
fi

if opndossier convert config.xml -o docs/network-config.md; then
    log "Documentation generation successful"
else
    log "Documentation generation failed"
    exit 1
fi

log "Automation process completed successfully"
```

### 3. Always Validate Before Converting

```bash
# Good practice - validate first
opndossier validate config.xml && opndossier convert config.xml -o output.md

# Even better - capture validation errors
if ! opndossier validate config.xml 2>validation-errors.log; then
    echo "Validation failed. See validation-errors.log"
    exit 1
fi
opndossier convert config.xml -o output.md
```

---

**Next Steps:**

- For troubleshooting, see [Troubleshooting](troubleshooting.md)
- For advanced configuration, see [Advanced Configuration](advanced-configuration.md)
- For basic documentation, see [Basic Documentation](basic-documentation.md)

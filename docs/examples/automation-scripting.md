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
          go-version: '1.24'

      - name: Install opnDossier
        run: go install github.com/EvilBit-Labs/opnDossier@latest

      - name: Generate Documentation
        env:
          OPNDOSSIER_LOG_FORMAT: json
          OPNDOSSIER_LOG_LEVEL: info
        run: |
          opnDossier convert config.xml -o docs/network-config.md

      - name: Generate Security Audit
        run: |
          opnDossier convert config.xml --mode blue --comprehensive -o docs/security-audit.md

      - name: Commit Documentation
        if: github.event_name == 'push'
        run: |
          git config --local user.email "action@github.com"
          git config --local user.name "GitHub Action"
          git add docs/network-config.md docs/security-audit.md
          git commit -m "docs: update network configuration and security audit" || exit 0
          git push
```

### GitLab CI Pipeline

```yaml
# .gitlab-ci.yml
stages:
  - documentation
  - security

variables:
  OPNDOSSIER_LOG_FORMAT: json
  OPNDOSSIER_LOG_LEVEL: info

documentation:
  stage: documentation
  image: golang:1.24
  before_script:
    - go install github.com/EvilBit-Labs/opnDossier@latest
  script:
    - opnDossier validate config.xml
    - opnDossier convert config.xml -o docs/network-config.md
    - opnDossier convert config.xml -f json -o docs/network-config.json
  artifacts:
    paths:
      - docs/network-config.md
      - docs/network-config.json
    expire_in: 30 days

security-audit:
  stage: security
  image: golang:1.24
  before_script:
    - go install github.com/EvilBit-Labs/opnDossier@latest
  script:
    - opnDossier convert config.xml --mode blue --comprehensive -o 
      docs/security-audit.md
    - opnDossier convert config.xml --mode red --blackhat-mode -o 
      docs/attack-surface.md
  artifacts:
    paths:
      - docs/security-audit.md
      - docs/attack-surface.md
    expire_in: 30 days
```

### Jenkins Pipeline

```groovy
// Jenkinsfile
pipeline {
    agent any

    environment {
        OPNDOSSIER_LOG_FORMAT = 'json'
        OPNDOSSIER_LOG_LEVEL = 'info'
    }

    stages {
        stage('Setup') {
            steps {
                sh 'go install github.com/EvilBit-Labs/opnDossier@latest'
            }
        }

        stage('Validate') {
            steps {
                sh 'opnDossier validate config.xml'
            }
        }

        stage('Generate Documentation') {
            steps {
                sh 'opnDossier convert config.xml -o docs/network-config.md'
                sh 'opnDossier convert config.xml -f json -o docs/network-config.json'
            }
        }

        stage('Security Audit') {
            steps {
                sh 'opnDossier convert config.xml --mode blue --comprehensive -o docs/security-audit.md'
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
        if opnDossier validate "$config_file" >> "$LOG_FILE" 2>&1; then
            # Generate documentation
            opnDossier convert "$config_file" -o "$OUTPUT_DIR/${filename}.md" >> "$LOG_FILE" 2>&1
            echo "✓ $filename processed successfully" | tee -a "$LOG_FILE"
        else
            echo "✗ $filename validation failed" | tee -a "$LOG_FILE"
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
    local filename=$(basename "$config_file" .xml)

    echo "Processing $filename..."

    if opnDossier validate "$config_file" > /dev/null 2>&1; then
        opnDossier convert "$config_file" -o "$OUTPUT_DIR/${filename}.md" > /dev/null 2>&1
        echo "✓ $filename completed"
    else
        echo "✗ $filename failed validation"
        return 1
    fi
}

# Export function for parallel execution
export -f process_file

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
opnDossier convert "$CONFIG_DIR/config.xml" -o "$DOCS_DIR/current-config.md"

# Generate security audit
opnDossier convert "$CONFIG_DIR/config.xml" \
    --mode blue --comprehensive \
    -o "$DOCS_DIR/security-audit.md"

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
WEBHOOK_URL="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"

# Set up environment
export OPNDOSSIER_LOG_FORMAT=json
export OPNDOSSIER_LOG_LEVEL=info

# Create documentation directory
mkdir -p "$DOCS_DIR"

# Get current date
DATE=$(date +%Y-%m-%d)

# Validate configuration
if ! opnDossier validate "$CONFIG_FILE"; then
    echo "Configuration validation failed"
    curl -X POST -H 'Content-type: application/json' \
        --data "{\"text\":\"❌ Daily documentation update failed: Configuration validation error\"}" \
        "$WEBHOOK_URL"
    exit 1
fi

# Generate documentation
if opnDossier convert "$CONFIG_FILE" -o "$DOCS_DIR/network-config-${DATE}.md"; then
    echo "Documentation generated successfully"

    # Send success notification
    curl -X POST -H 'Content-type: application/json' \
        --data "{\"text\":\"✅ Daily documentation updated: network-config-${DATE}.md\"}" \
        "$WEBHOOK_URL"
else
    echo "Documentation generation failed"

    # Send failure notification
    curl -X POST -H 'Content-type: application/json' \
        --data "{\"text\":\"❌ Daily documentation update failed: Generation error\"}" \
        "$WEBHOOK_URL"
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
WEBHOOK_URL="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"

# Calculate current hash
CURRENT_HASH=$(sha256sum "$CONFIG_FILE" | cut -d' ' -f1)

# Check if hash file exists
if [ -f "$PREVIOUS_HASH_FILE" ]; then
    PREVIOUS_HASH=$(cat "$PREVIOUS_HASH_FILE")

    # Compare hashes
    if [ "$CURRENT_HASH" != "$PREVIOUS_HASH" ]; then
        echo "Configuration change detected"

        # Generate updated documentation
        opnDossier convert "$CONFIG_FILE" -o "/var/www/network-docs/network-config-$(date +%Y-%m-%d_%H-%M-%S).md"

        # Generate diff report
        opnDossier convert "$CONFIG_FILE" -f json -o "/tmp/current-config.json"

        # Send notification
        curl -X POST -H 'Content-type: application/json' \
            --data "{\"text\":\"🔄 Configuration change detected. New documentation generated.\"}" \
            "$WEBHOOK_URL"
    fi
fi

# Update hash file
echo "$CURRENT_HASH" > "$PREVIOUS_HASH_FILE"
```

## Monitoring and Alerting

### Health Check Script

```bash
#!/bin/bash
# health-check.sh

# Configuration
CONFIG_FILE="/etc/opnsense/config.xml"
ALERT_EMAIL="admin@example.com"
LOG_FILE="/var/log/opndossier-health.log"

# Function to send alert
send_alert() {
    local message="$1"
    echo "$(date): $message" >> "$LOG_FILE"
    echo "$message" | mail -s "opnDossier Health Alert" "$ALERT_EMAIL"
}

# Check if configuration file exists
if [ ! -f "$CONFIG_FILE" ]; then
    send_alert "Configuration file not found: $CONFIG_FILE"
    exit 1
fi

# Validate configuration
if ! opnDossier validate "$CONFIG_FILE" > /dev/null 2>&1; then
    send_alert "Configuration validation failed"
    exit 1
fi

# Test documentation generation
if ! opnDossier convert "$CONFIG_FILE" -o /tmp/test.md > /dev/null 2>&1; then
    send_alert "Documentation generation failed"
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

# Configuration
CONFIG_FILE="/etc/opnsense/config.xml"
METRICS_FILE="/var/log/opndossier-metrics.log"

# Function to measure execution time
measure_time() {
    local start_time=$(date +%s.%N)
    "$@"
    local end_time=$(date +%s.%N)
    echo "$(echo "$end_time - $start_time" | bc)"
}

# Measure validation time
VALIDATION_TIME=$(measure_time opnDossier validate "$CONFIG_FILE")

# Measure conversion time
CONVERSION_TIME=$(measure_time opnDossier convert "$CONFIG_FILE" -o /tmp/test.md)

# Get file size
FILE_SIZE=$(stat -c%s "$CONFIG_FILE")

# Log metrics
echo "$(date),$FILE_SIZE,$VALIDATION_TIME,$CONVERSION_TIME" >> "$METRICS_FILE"

# Clean up
rm -f /tmp/test.md

echo "Metrics logged: File size: ${FILE_SIZE} bytes, Validation: ${VALIDATION_TIME}s, Conversion: ${CONVERSION_TIME}s"
```

## Integration Examples

### Ansible Playbook

```yaml
  - name: Generate opnDossier Documentation
    hosts: firewalls
    become: yes
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
        shell: opnDossier convert /etc/opnsense/config.xml -o 
          /var/www/network-docs/network-config.md
        environment:
          PATH: '{{ ansible_env.PATH }}:/root/go/bin'

      - name: Generate security audit
        shell: opnDossier convert /etc/opnsense/config.xml --mode blue 
          --comprehensive -o /var/www/network-docs/security-audit.md
        environment:
          PATH: '{{ ansible_env.PATH }}:/root/go/bin'

      - name: Set file permissions
        file:
          path: /var/www/network-docs
          state: directory
          mode: '0755'
          recurse: yes
```

### Docker Integration

```dockerfile
# Dockerfile
FROM golang:1.24-alpine

# Install opnDossier
RUN go install github.com/EvilBit-Labs/opnDossier@latest

# Create working directory
WORKDIR /app

# Copy configuration files
COPY configs/ ./configs/

# Create output directory
RUN mkdir -p ./docs

# Generate documentation
RUN opnDossier convert ./configs/config.xml -o ./docs/network-config.md

# Expose documentation
EXPOSE 8080

# Serve documentation
CMD ["python3", "-m", "http.server", "8080"]
```

### Kubernetes Job

```yaml
# opndossier-job.yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: opndossier-docs
spec:
  template:
    spec:
      containers:
        - name: opndossier
          image: golang:1.24
          command:
            - /bin/bash
            - -c
            - |
              go install github.com/EvilBit-Labs/opnDossier@latest
              opnDossier convert /configs/config.xml -o /docs/network-config.md
              opnDossier convert /configs/config.xml --mode blue --comprehensive -o /docs/security-audit.md
          volumeMounts:
            - name: configs
              mountPath: /configs
            - name: docs
              mountPath: /docs
      volumes:
        - name: configs
          configMap:
            name: firewall-config
        - name: docs
          persistentVolumeClaim:
            claimName: docs-pvc
      restartPolicy: Never
  backoffLimit: 3
```

## Best Practices

### 1. Error Handling

```bash
#!/bin/bash
# robust-automation.sh

set -e  # Exit on any error

# Function to handle errors
error_handler() {
    local exit_code=$?
    echo "Error occurred in line $1, exit code: $exit_code"
    # Send alert or log error
    exit $exit_code
}

# Set error handler
trap 'error_handler $LINENO' ERR

# Your automation logic here
opnDossier validate config.xml
opnDossier convert config.xml -o docs/network-config.md
```

### 2. Logging and Monitoring

```bash
#!/bin/bash
# monitored-automation.sh

# Configuration
LOG_FILE="/var/log/opndossier-automation.log"
METRICS_FILE="/var/log/opndossier-metrics.log"

# Function to log with timestamp
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# Function to record metrics
record_metric() {
    local metric_name="$1"
    local value="$2"
    echo "$(date '+%Y-%m-%d %H:%M:%S'),$metric_name,$value" >> "$METRICS_FILE"
}

# Start processing
log "Starting automation process"

# Record start time
START_TIME=$(date +%s)

# Process configuration
if opnDossier validate config.xml; then
    log "Configuration validation successful"
    record_metric "validation_success" 1
else
    log "Configuration validation failed"
    record_metric "validation_success" 0
    exit 1
fi

# Generate documentation
if opnDossier convert config.xml -o docs/network-config.md; then
    log "Documentation generation successful"
    record_metric "conversion_success" 1
else
    log "Documentation generation failed"
    record_metric "conversion_success" 0
    exit 1
fi

# Record processing time
END_TIME=$(date +%s)
PROCESSING_TIME=$((END_TIME - START_TIME))
record_metric "processing_time_seconds" "$PROCESSING_TIME"

log "Automation process completed successfully"
```

### 3. Resource Management

```bash
#!/bin/bash
# resource-managed-automation.sh

# Set resource limits
ulimit -v 1048576  # 1GB virtual memory limit
ulimit -t 300      # 5 minute CPU time limit

# Monitor resource usage
monitor_resources() {
    local pid=$1
    while kill -0 "$pid" 2>/dev/null; do
        local memory=$(ps -o rss= -p "$pid" 2>/dev/null || echo "0")
        local cpu=$(ps -o %cpu= -p "$pid" 2>/dev/null || echo "0")
        echo "$(date),$memory,$cpu" >> resource-usage.log
        sleep 5
    done
}

# Start resource monitoring
opnDossier convert config.xml -o docs/network-config.md &
OPNDOSSIER_PID=$!

# Monitor resources
monitor_resources "$OPNDOSSIER_PID" &
MONITOR_PID=$!

# Wait for opnDossier to complete
wait "$OPNDOSSIER_PID"
OPNDOSSIER_EXIT_CODE=$?

# Stop monitoring
kill "$MONITOR_PID" 2>/dev/null || true

exit "$OPNDOSSIER_EXIT_CODE"
```

---

**Next Steps:**

- For troubleshooting, see [Troubleshooting](troubleshooting.md)
- For advanced configuration, see [Advanced Configuration](advanced-configuration.md)
- For basic documentation, see [Basic Documentation](basic-documentation.md)

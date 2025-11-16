#!/bin/bash
# opnDossier Migration Validation Tool v2.0
# Validates migration from template-based to programmatic markdown generation

set -e  # Exit on any error

# Default values
TEMPLATE_DIR="${1:-.}"
SAMPLE_CONFIG="${2:-sample.xml}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

# Function to print error to stderr
print_error() {
    print_status "$RED" "$1" >&2
}

# Function to display usage
usage() {
    cat << EOF
Usage: $0 [TEMPLATE_DIR] [SAMPLE_CONFIG]

Arguments:
  TEMPLATE_DIR    Directory containing custom templates (default: current directory)
  SAMPLE_CONFIG   Path to sample OPNsense config.xml file (default: sample.xml)

Options:
  --help          Display this help message

Examples:
  $0
  $0 ./custom-templates
  $0 ./custom-templates ./testdata/config.xml

EOF
}

# Check for help flag
if [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
    usage
    exit 0
fi

# Banner display
cat << "EOF"
  ___  _ __  _   _  ____            _       _   _
 / _ \| '_ \| | | |/ ___|  ___   __| | ___ | |_(_) ___  _ __
| | | | |_) | |_| | |  _  / _ \ / _` |/ _ \| __| |/ _ \| '_ \
| |_| | .__/ \__, | |_| || (_) | (_| |  __/| |_| | (_) | | | |
 \___/|_|    |___/ \____| \___/ \__,_|\___| \__|_|\___/|_| |_|

        Migration Validation Tool v2.0
EOF

echo ""
print_status "$BLUE" "Purpose: Validate migration from template-based to programmatic generation"
echo ""

# Prerequisites check
print_status "$YELLOW" "Checking prerequisites..."

if ! command -v opndossier &> /dev/null; then
    print_error "✗ opndossier command not found in PATH"
    echo ""
    print_status "$YELLOW" "Installation instructions:"
    echo "  go install github.com/EvilBit-Labs/opnDossier@latest"
    echo ""
    print_status "$YELLOW" "Or build from source:"
    echo "  git clone https://github.com/EvilBit-Labs/opnDossier.git"
    echo "  cd opnDossier"
    echo "  just install"
    echo "  just build"
    echo ""
    exit 1
fi

print_status "$GREEN" "✓ opndossier command found"
echo ""

# Custom template detection
print_status "$YELLOW" "Detecting custom templates..."

TEMPLATES_DIR="${TEMPLATE_DIR}/templates"
if [ -d "$TEMPLATES_DIR" ]; then
    print_status "$GREEN" "✓ Custom templates directory found: $TEMPLATES_DIR"
    echo ""

    # Extract template functions
    print_status "$YELLOW" "Extracting template functions..."

    # Find all template files
    TEMPLATE_FILES=$(find "$TEMPLATES_DIR" -type f \( -name "*.tmpl" -o -name "*.tpl" -o -name "*.html" \) 2>/dev/null || true)

    if [ -n "$TEMPLATE_FILES" ]; then
        # Extract function patterns: {{ function( or {{ function | or {{ function.
        # Also detect Sprig-style pipeline functions: {{ .Value | upper }}
        # Filter out Go template keywords
        DIRECT_FUNCTIONS=$(echo "$TEMPLATE_FILES" | xargs grep -h -oE '\{\{ *[a-zA-Z_][a-zA-Z0-9_]*' 2>/dev/null | \
            sed 's/{{ *//' || true)
        PIPELINE_FUNCTIONS=$(echo "$TEMPLATE_FILES" | xargs grep -h -oE '\| *[a-zA-Z_][a-zA-Z0-9_]*' 2>/dev/null | \
            sed 's/| *//' || true)
        # Combine both lists and filter out template keywords
        FUNCTIONS=$(printf '%s\n%s\n' "$DIRECT_FUNCTIONS" "$PIPELINE_FUNCTIONS" | \
            grep -vE '^(if|range|end|define|template|with|block|else|eq|ne|lt|le|gt|ge|and|or|not)$' | \
            sort -u || true)

        if [ -n "$FUNCTIONS" ]; then
            echo "Detected template functions:"
            while IFS= read -r func; do
                echo "  - $func"
            done <<< "$FUNCTIONS"
            echo ""

            # Check for unmigrated functions
            print_status "$YELLOW" "Checking for unmigrated functions..."
            UNMIGRATED_COUNT=0

            while IFS= read -r func; do
                # Check if function has Go equivalent (simplified check)
                # In a real implementation, this would cross-reference with markdown-function-migration.md
                # Capitalize first character for Go method name (portable for Bash 3.2+)
                func_cap="$(printf '%s' "$func" | awk '{print toupper(substr($0,1,1)) substr($0,2)}')"
                if ! grep -q "func (b \*MarkdownBuilder) ${func_cap}" internal/converter/*.go 2>/dev/null; then
                    print_status "$YELLOW" "  ⚠ Function '$func' may not have a Go equivalent"
                    UNMIGRATED_COUNT=$((UNMIGRATED_COUNT + 1))
                fi
            done <<< "$FUNCTIONS"

            if [ $UNMIGRATED_COUNT -gt 0 ]; then
                echo ""
                print_status "$YELLOW" "⚠ $UNMIGRATED_COUNT function(s) may need migration"
                print_status "$BLUE" "  Reference: docs/template-function-migration.md for mapping details"
            else
                print_status "$GREEN" "✓ All detected functions appear to have Go equivalents"
            fi
        else
            print_status "$YELLOW" "  No template functions detected in template files"
        fi
    else
        print_status "$YELLOW" "  No template files found in $TEMPLATES_DIR"
    fi
else
    print_status "$YELLOW" "⚠ No custom templates directory found at: $TEMPLATES_DIR"
    print_status "$BLUE" "  This is expected if you're not using custom templates"
fi

echo ""

# Comparison report generation (if sample config provided)
if [ -f "$SAMPLE_CONFIG" ]; then
    print_status "$YELLOW" "Generating comparison reports..."
    echo ""

    # Generate template mode report
    print_status "$YELLOW" "→ Generating template mode report..."
    if opndossier convert "$SAMPLE_CONFIG" -o /tmp/report-template.md --use-template 2>/dev/null; then
        TEMPLATE_LINES=$(wc -l < /tmp/report-template.md)
        print_status "$GREEN" "✓ Template report generated ($TEMPLATE_LINES lines)"
    else
        print_status "$YELLOW" "⚠ Template report generation failed (expected if no templates exist)"
    fi

    # Generate programmatic mode report
    print_status "$YELLOW" "→ Generating programmatic mode report..."
    if opndossier convert "$SAMPLE_CONFIG" -o /tmp/report-programmatic.md 2>/dev/null; then
        PROGRAMMATIC_LINES=$(wc -l < /tmp/report-programmatic.md)
        print_status "$GREEN" "✓ Programmatic report generated ($PROGRAMMATIC_LINES lines)"
    else
        print_error "✗ Programmatic report generation failed"
        exit 1
    fi

    echo ""

    # Compare outputs if both reports generated
    if [ -f "/tmp/report-template.md" ] && [ -f "/tmp/report-programmatic.md" ]; then
        print_status "$YELLOW" "Comparing outputs..."

        # Count lines
        TEMPLATE_LINES=$(wc -l < /tmp/report-template.md)
        PROGRAMMATIC_LINES=$(wc -l < /tmp/report-programmatic.md)
        LINE_DIFF=$((PROGRAMMATIC_LINES - TEMPLATE_LINES))

        echo "  Template report:     $TEMPLATE_LINES lines"
        echo "  Programmatic report: $PROGRAMMATIC_LINES lines"
        echo "  Difference:          $LINE_DIFF lines"
        echo ""

        # Generate detailed diff
        if diff -u /tmp/report-template.md /tmp/report-programmatic.md > /tmp/migration-diff.txt 2>/dev/null; then
            print_status "$GREEN" "✓ Reports are identical"
            rm -f /tmp/migration-diff.txt
        else
            print_status "$YELLOW" "⚠ Reports differ - see /tmp/migration-diff.txt for details"
            DIFF_LINES=$(wc -l < /tmp/migration-diff.txt)
            echo "  Diff file: /tmp/migration-diff.txt ($DIFF_LINES lines)"
        fi
    fi
else
    print_status "$YELLOW" "⚠ Sample config file not found: $SAMPLE_CONFIG"
    print_status "$BLUE" "  Skipping comparison report generation"
    print_status "$BLUE" "  Provide a sample config.xml file to enable comparison"
fi

echo ""

# Summary and next steps
print_status "$GREEN" "Migration validation complete!"
echo ""
print_status "$BLUE" "Next Steps:"
echo "  1. Review function mappings in docs/template-function-migration.md"
if [ -f "/tmp/migration-diff.txt" ]; then
    echo "  2. Check detailed diff at /tmp/migration-diff.txt"
fi
echo "  3. Follow migration guide at docs/migration.md"
echo "  4. Test your custom functions with programmatic mode"
echo "  5. Consider contributing useful custom functions back to the project"
echo ""

exit 0

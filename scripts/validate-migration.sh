#!/bin/bash
# Validate migration from template to programmatic

set -e  # Exit on any error

echo "Migration Validation Tool"
echo "========================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

# Check if opndossier binary exists
if ! command -v opndossier &> /dev/null; then
    if [ -f "./main.go" ]; then
        print_status $YELLOW "Using 'go run main.go' instead of opndossier binary"
        OPNDOSSIER_CMD="go run main.go"
    else
        print_status $RED "✗ opndossier binary not found and main.go not available"
        exit 1
    fi
else
    OPNDOSSIER_CMD="opndossier"
fi

# Check for custom templates
if [ -d "./templates" ]; then
    print_status $GREEN "✓ Custom templates found"
    
    # List template functions used
    echo ""
    echo "Template functions in use:"
    if find ./templates -name "*.tmpl" -o -name "*.tpl" 2>/dev/null | grep -q .; then
        find ./templates -name "*.tmpl" -o -name "*.tpl" -exec grep -h -o '{{ [a-zA-Z][a-zA-Z0-9_]* ' {} \; | sort -u | sed 's/{{/  -/'
    else
        print_status $YELLOW "  No .tmpl or .tpl files found"
    fi
    
    echo ""
    echo "Verifying programmatic equivalents..."
    # Check if equivalent methods exist by looking at the source
    if [ -d "./internal/converter" ]; then
        echo "Available MarkdownBuilder methods:"
        grep -h "func (b \*MarkdownBuilder)" ./internal/converter/*.go | grep -v "_test.go" | sed 's/func (b \*MarkdownBuilder) /  - /' | sed 's/(.*$/()/' | sort
    fi
else
    print_status $YELLOW "⚠ No custom templates directory found (./templates)"
fi

# Check for sample configuration files
SAMPLE_CONFIG=""
if [ -f "testdata/config.xml" ]; then
    SAMPLE_CONFIG="testdata/config.xml"
elif [ -f "sample.xml" ]; then
    SAMPLE_CONFIG="sample.xml"
elif [ -f "config.xml" ]; then
    SAMPLE_CONFIG="config.xml"
elif [ -f "final_test.xml" ]; then
    SAMPLE_CONFIG="final_test.xml"
else
    print_status $YELLOW "⚠ No sample configuration file found. Creating minimal test config..."
    cat > sample.xml << 'EOF'
<?xml version="1.0"?>
<opnsense>
    <system>
        <hostname>test-firewall</hostname>
        <domain>example.com</domain>
        <version>24.1</version>
    </system>
</opnsense>
EOF
    SAMPLE_CONFIG="sample.xml"
fi

print_status $GREEN "✓ Using sample config: $SAMPLE_CONFIG"

# Generate comparison reports
echo ""
echo "Generating comparison reports..."

# Test programmatic mode (default)
print_status $YELLOW "→ Generating programmatic report..."
if $OPNDOSSIER_CMD convert "$SAMPLE_CONFIG" -o report-programmatic.md --format markdown; then
    print_status $GREEN "✓ Programmatic report generated"
else
    print_status $RED "✗ Failed to generate programmatic report"
    exit 1
fi

# Test template mode (if templates exist)
if [ -d "./templates" ]; then
    print_status $YELLOW "→ Generating template report..."
    if $OPNDOSSIER_CMD convert "$SAMPLE_CONFIG" -o report-template.md --use-template --format markdown; then
        print_status $GREEN "✓ Template report generated"
        
        # Compare outputs
        echo ""
        echo "Comparing outputs..."
        if diff -u report-template.md report-programmatic.md > migration-diff.txt 2>/dev/null; then
            print_status $GREEN "✓ Reports are identical"
            rm -f migration-diff.txt
        else
            print_status $YELLOW "⚠ Reports differ - see migration-diff.txt for details"
            echo "Difference summary:"
            head -20 migration-diff.txt
            if [ $(wc -l < migration-diff.txt) -gt 20 ]; then
                echo "... (output truncated, see migration-diff.txt for full diff)"
            fi
        fi
    else
        print_status $YELLOW "⚠ Template report generation failed (may be expected if no built-in templates)"
    fi
else
    print_status $YELLOW "⚠ Skipping template comparison - no custom templates found"
fi

# Test different output formats
echo ""
echo "Testing output formats..."

for format in json yaml; do
    print_status $YELLOW "→ Testing $format format..."
    if $OPNDOSSIER_CMD convert "$SAMPLE_CONFIG" -o "report-test.$format" --format "$format"; then
        print_status $GREEN "✓ $format format generated successfully"
        rm -f "report-test.$format"
    else
        print_status $RED "✗ Failed to generate $format format"
    fi
done

# Validate markdown output
echo ""
echo "Validating markdown output..."
if command -v markdownlint-cli2 &> /dev/null; then
    if markdownlint-cli2 report-programmatic.md; then
        print_status $GREEN "✓ Markdown validation passed"
    else
        print_status $YELLOW "⚠ Markdown validation warnings (see above)"
    fi
else
    print_status $YELLOW "⚠ markdownlint-cli2 not available, skipping markdown validation"
fi

# Performance comparison (if both reports exist)
if [ -f "report-template.md" ] && [ -f "report-programmatic.md" ]; then
    echo ""
    echo "Performance comparison:"
    echo "Template report size:     $(wc -c < report-template.md) bytes"
    echo "Programmatic report size: $(wc -c < report-programmatic.md) bytes"
    
    # Simple timing test
    print_status $YELLOW "→ Running simple performance test..."
    echo "Template mode timing:"
    time $OPNDOSSIER_CMD convert "$SAMPLE_CONFIG" --use-template --format markdown > /dev/null 2>&1 || true
    
    echo "Programmatic mode timing:"
    time $OPNDOSSIER_CMD convert "$SAMPLE_CONFIG" --format markdown > /dev/null 2>&1 || true
fi

# Cleanup temporary files
if [ "$SAMPLE_CONFIG" = "sample.xml" ] && [ -f "sample.xml" ]; then
    rm -f sample.xml
fi

echo ""
print_status $GREEN "Migration validation complete!"
echo ""
echo "Summary:"
echo "- Programmatic report: report-programmatic.md"
[ -f "report-template.md" ] && echo "- Template report: report-template.md"
[ -f "migration-diff.txt" ] && echo "- Differences: migration-diff.txt"
echo ""
echo "Next steps:"
echo "1. Review any differences in migration-diff.txt"
echo "2. Test your custom functions with programmatic generation"
echo "3. Update your CI/CD pipelines to use programmatic mode"
echo "4. Consider contributing useful custom functions back to the project"
# opnDossier Justfile
# Run `just` or `just --list` to see available recipes

set shell := ["bash", "-cu"]
set windows-powershell := true
set dotenv-load := true
set ignore-comments := true

# ─────────────────────────────────────────────────────────────────────────────
# Variables
# ─────────────────────────────────────────────────────────────────────────────

project_dir := justfile_directory()
binary_name := "opndossier"

# Platform-specific commands
_cmd_exists := if os_family() == "windows" { "where" } else { "command -v" }
_null := if os_family() == "windows" { "nul" } else { "/dev/null" }

# Act configuration
act_arch := "linux/amd64"
act_cmd := "act --container-architecture " + act_arch

# ─────────────────────────────────────────────────────────────────────────────
# Default & Help
# ─────────────────────────────────────────────────────────────────────────────

[private]
default:
    @just --list --unsorted

alias h := help
alias l := list

# Show available recipes
[group('help')]
help:
    @just --list

# Show recipes in a specific group
[group('help')]
list group="":
    @just --list --unsorted {{ if group != "" { "--list-heading='' --list-prefix='  ' | grep -A999 '" + group + "'" } else { "" } }}

# ─────────────────────────────────────────────────────────────────────────────
# Setup & Installation
# ─────────────────────────────────────────────────────────────────────────────

alias i := install

# Install all dependencies and setup environment
[group('setup')]
install: _update-python
    @pre-commit install --hook-type commit-msg
    @go mod tidy
    @just _install-tool git-cliff

# Alias for install
[group('setup')]
setup: install

# Update all dependencies
[group('setup')]
update-deps: _update-go _update-python _update-pnpm _update-precommit _update-tools
    @echo "✅ All dependencies updated"

[private]
_setup-venv:
    @cd {{ project_dir }} && {{ if os_family() == "windows" { "python" } else { "python3" } }} -m venv .venv 2>{{ _null }} || true

[private]
_update-go:
    @echo "Updating Go dependencies..."
    @go get -u ./...
    @go mod tidy
    @go mod verify

[private]
_update-python:
    @echo "Updating Python dependencies..."
    @uv pip install --quiet --upgrade mkdocs-material pre-commit

[private]
_update-pnpm:
    #!/usr/bin/env bash
    if command -v pnpm >/dev/null 2>&1; then
        echo "Updating pnpm dependencies..."
        pnpm update
    fi

[private]
_update-precommit:
    @echo "Updating pre-commit hooks..."
    @pre-commit autoupdate

[private]
_update-tools:
    @echo "Updating development tools..."
    @go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest 2>{{ _null }} || true

# Install a specific tool (git-cliff, cyclonedx-gomod, gosec, cosign)
[group('setup')]
[private]
_install-tool tool:
    #!/usr/bin/env bash
    set -euo pipefail
    {{ _cmd_exists }} {{ tool }} >{{ _null }} 2>&1 && echo "{{ tool }} is already installed" && exit 0
    echo "Installing {{ tool }}..."
    case "{{ tool }}" in
        git-cliff)
            cargo install git-cliff 2>{{ _null }} || brew install git-cliff
            ;;
        cyclonedx-gomod)
            go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@latest
            ;;
        gosec)
            go install github.com/securego/gosec/v2/cmd/gosec@latest 2>{{ _null }} || brew install gosec
            ;;
        cosign)
            brew install cosign 2>{{ _null }} || go install github.com/sigstore/cosign/v2/cmd/cosign@latest
            ;;
        *)
            echo "Error: Unknown tool {{ tool }}"
            exit 1
            ;;
    esac

# Install security and SBOM tools (cyclonedx-gomod, gosec, cosign)
[group('setup')]
install-security-tools:
    @just _install-tool cyclonedx-gomod
    @just _install-tool gosec
    @just _install-tool cosign

# ─────────────────────────────────────────────────────────────────────────────
# Development
# ─────────────────────────────────────────────────────────────────────────────

alias r := run

# Run the application with optional arguments
[group('dev')]
run *args:
    @go run main.go {{ args }}

# Run in development mode (alias for run)
[group('dev')]
dev *args:
    @go run main.go {{ args }}

# ─────────────────────────────────────────────────────────────────────────────
# Code Quality
# ─────────────────────────────────────────────────────────────────────────────

alias f := format
alias fmt := format

# Format code and apply fixes
[group('quality')]
format:
    @golangci-lint run --fix ./...
    @just modernize

# Check formatting without making changes
[group('quality')]
format-check:
    @golangci-lint fmt ./...

# Run linter
[group('quality')]
lint:
    @golangci-lint run ./...
    @just modernize-check

# Run pre-commit checks on all files
[group('quality')]
check:
    @pre-commit run --all-files

# Apply Go modernization fixes
[group('quality')]
modernize:
    @go run golang.org/x/tools/gopls/internal/analysis/modernize/cmd/modernize@latest -fix -test ./...

# Check for modernization opportunities (dry-run)
[group('quality')]
modernize-check:
    @go run golang.org/x/tools/gopls/internal/analysis/modernize/cmd/modernize@latest -test ./...

# ─────────────────────────────────────────────────────────────────────────────
# Testing
# ─────────────────────────────────────────────────────────────────────────────

alias t := test

# Run all tests
[group('test')]
test:
    @go test ./...

# Run tests with verbose output
[group('test')]
test-v:
    @go test -v ./...

# Run tests with coverage report
[group('test')]
test-coverage:
    @go test -coverprofile=coverage.txt ./...
    @go tool cover -func=coverage.txt

# Run tests and open coverage in browser
[group('test')]
coverage:
    @go test -coverprofile=coverage.txt ./...
    @go tool cover -html=coverage.txt

# Generate coverage artifact
[group('test')]
cover: test-coverage

# Run benchmarks
[group('test')]
bench:
    @go test -bench=. ./...

# Run memory benchmarks for parser
[group('test')]
bench-mem:
    @go test -bench=BenchmarkParse -benchmem ./internal/parser

# Run comprehensive performance benchmarks
[group('test')]
bench-perf:
    @go test -bench=. -run=^$ -benchtime=1s -count=3 ./internal/converter

# Run model completeness check
[group('test')]
completeness-check:
    @go test -tags=completeness ./internal/model -run TestModelCompleteness

# ─────────────────────────────────────────────────────────────────────────────
# Build
# ─────────────────────────────────────────────────────────────────────────────

alias b := build

# Build the binary
[group('build')]
build:
    @go build -o {{ binary_name }}{{ if os_family() == "windows" { ".exe" } else { "" } }} main.go

# Build with optimizations for release
[group('build')]
build-release:
    @CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o {{ binary_name }}{{ if os_family() == "windows" { ".exe" } else { "" } }} main.go

# Clean build artifacts
[group('build')]
[confirm("This will remove build artifacts. Continue?")]
clean:
    @go clean
    @rm -f coverage.txt {{ binary_name }} {{ binary_name }}.exe 2>{{ _null }} || true

# Clean and rebuild
[group('build')]
rebuild: clean build

# ─────────────────────────────────────────────────────────────────────────────
# Release (GoReleaser)
# ─────────────────────────────────────────────────────────────────────────────

# Check GoReleaser configuration
[group('release')]
release-check:
    @goreleaser check --verbose

# Build snapshot (no tag required)
[group('release')]
release-snapshot:
    @goreleaser build --clean --snapshot

# Build for current platform only
[group('release')]
release-local:
    @goreleaser build --clean --snapshot --single-target

# Full release (requires git tag and GITHUB_TOKEN)
[group('release')]
[confirm("This will create a GitHub release. Continue?")]
release: check test
    @goreleaser release --clean

# ─────────────────────────────────────────────────────────────────────────────
# Documentation
# ─────────────────────────────────────────────────────────────────────────────

alias d := docs

# Serve documentation locally
[group('docs')]
docs:
    @uv run mkdocs serve

# Alias for docs
[group('docs')]
site: docs

# Build documentation
[group('docs')]
docs-build:
    @uv run mkdocs build

# Build documentation with verbose output
[group('docs')]
docs-test:
    @uv run mkdocs build --verbose

# ─────────────────────────────────────────────────────────────────────────────
# Changelog
# ─────────────────────────────────────────────────────────────────────────────

# Generate changelog
[group('docs')]
changelog: _require-git-cliff
    @git-cliff --output CHANGELOG.md

# Generate changelog for a specific version
[group('docs')]
changelog-version version: _require-git-cliff
    @git-cliff --tag {{ version }} --output CHANGELOG.md

# Generate changelog for unreleased changes only
[group('docs')]
changelog-unreleased: _require-git-cliff
    @git-cliff --unreleased --output CHANGELOG.md

[private]
_require-git-cliff:
    #!/usr/bin/env bash
    if ! command -v git-cliff >/dev/null 2>&1; then
        echo "Error: git-cliff not found. Run 'just install' to install it."
        exit 1
    fi

# ─────────────────────────────────────────────────────────────────────────────
# Security
# ─────────────────────────────────────────────────────────────────────────────

# Run gosec security scanner
[group('security')]
scan:
    @echo "Running security scan..."
    @gosec ./...

# Generate SBOM with cyclonedx-gomod
[group('security')]
sbom:
    @echo "Generating SBOM..."
    @just build-release
    @cyclonedx-gomod bin -output sbom-binary.cyclonedx.json ./{{ binary_name }}{{ if os_family() == "windows" { ".exe" } else { "" } }}
    @cyclonedx-gomod app -output sbom-modules.cyclonedx.json -json .
    @echo "✅ SBOM generated: sbom-binary.cyclonedx.json, sbom-modules.cyclonedx.json"

# Run all security checks (SBOM + security scan)
[group('security')]
security-all: sbom scan
    @echo "✅ All security checks complete"

# ─────────────────────────────────────────────────────────────────────────────
# CI
# ─────────────────────────────────────────────────────────────────────────────

# Run full CI checks (pre-commit, format, lint, test)
[group('ci')]
ci-check: check format-check lint test
    @echo "✅ All CI checks passed"

# Run smoke tests (fast, minimal validation)
[group('ci')]
ci-smoke:
    @echo "Running smoke tests..."
    @go build -trimpath -ldflags="-s -w -X main.version=dev" -v ./...
    @go test -count=1 -failfast -short -timeout 5m ./cmd/... ./internal/config/...
    @echo "✅ Smoke tests passed"

# Run full checks including security and release validation
[group('ci')]
ci-full: ci-check security-all release-check
    @echo "✅ All checks passed"

# ─────────────────────────────────────────────────────────────────────────────
# GitHub Actions (act)
# ─────────────────────────────────────────────────────────────────────────────

[private]
_require-act:
    #!/usr/bin/env bash
    if ! command -v act >/dev/null 2>&1; then
        echo "Error: act not found. Install: brew install act"
        exit 1
    fi

# List available GitHub Actions workflows
[group('act')]
act-list: _require-act
    @{{ act_cmd }} --list

# Run a specific workflow
[group('act')]
act-run workflow: _require-act
    @echo "Running workflow: {{ workflow }}"
    @{{ act_cmd }} --workflows .github/workflows/{{ workflow }}.yml --verbose

# Dry-run a workflow (list steps only)
[group('act')]
act-dry workflow: _require-act
    @{{ act_cmd }} --workflows .github/workflows/{{ workflow }}.yml --list

# Test PR workflow locally
[group('act')]
act-pr: _require-act
    @{{ act_cmd }} pull_request --verbose

# Test push workflow locally
[group('act')]
act-push: _require-act
    @{{ act_cmd }} push --verbose

# Test all PR workflows (dry-run)
[group('act')]
act-test-all: _require-act
    @echo "Testing CI workflow..."
    @just act-dry ci
    @echo ""
    @echo "Testing CodeQL workflow..."
    @just act-dry codeql
    @echo ""
    @echo "Testing Scorecard workflow..."
    @just act-dry scorecard

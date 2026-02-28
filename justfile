# opnDossier Justfile
# Run `just` or `just --list` to see available recipes

set shell := ["bash", "-cu"]
set windows-powershell := true
set dotenv-load := true
set ignore-comments := true

# Use mise to manage all dev tools (go, pre-commit, uv, etc.)
# See mise.toml for tool versions
mise_exec := "mise exec --"

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
install:
    @mise install
    @{{ mise_exec }} pre-commit install --hook-type commit-msg
    @{{ mise_exec }} go mod tidy


# Alias for install
[group('setup')]
setup: install

# Update all dependencies
[group('setup')]
update-deps: _update-go _update-python _update-precommit

[private]
_update-go:
    @{{ mise_exec }} go get -u ./...
    @{{ mise_exec }} go mod tidy
    @{{ mise_exec }} go mod verify

[private]
[no-exit-message]
_update-python:
    @{{ mise_exec }} pre-commit install --hook-type commit-msg 2>{{ _null }} || true

[private]
_update-precommit: _update-python
    @{{ mise_exec }} pre-commit autoupdate


# Install security and SBOM tools (cyclonedx-gomod, gosec)
[group('setup')]
install-security-tools:
    @{{ mise_exec }} go install github.com/securego/gosec/v2/cmd/gosec@latest
    @{{ mise_exec }} go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@latest
    # cosign is now handled by mise

# ─────────────────────────────────────────────────────────────────────────────
# Development
# ─────────────────────────────────────────────────────────────────────────────

alias r := run

# Run the application with optional arguments
[group('dev')]
run *args:
    @{{ mise_exec }} go run main.go {{ args }}

# Run in development mode (alias for run)
[group('dev')]
dev *args:
    @{{ mise_exec }} go run main.go {{ args }}

# ─────────────────────────────────────────────────────────────────────────────
# Code Quality
# ─────────────────────────────────────────────────────────────────────────────

alias f := format
alias fmt := format

# Format code and apply fixes
[group('quality')]
format:
    @{{ mise_exec }} golangci-lint run --fix ./...
    @just modernize

# Check formatting without making changes
[group('quality')]
format-check:
    @{{ mise_exec }} golangci-lint fmt ./...

# Run linter
[group('quality')]
lint:
    @{{ mise_exec }} golangci-lint run ./...
    @just modernize-check

# Run pre-commit checks on all files
[group('quality')]
check:
    @{{ mise_exec }} pre-commit run --all-files

# Apply Go modernization fixes
[group('quality')]
modernize:
    @{{ mise_exec }} go run golang.org/x/tools/gopls/internal/analysis/modernize/cmd/modernize@latest -fix -test ./...

# Check for modernization opportunities (dry-run)
[group('quality')]
modernize-check:
    @{{ mise_exec }} go run golang.org/x/tools/gopls/internal/analysis/modernize/cmd/modernize@latest -test ./...

# ─────────────────────────────────────────────────────────────────────────────
# Testing
# ─────────────────────────────────────────────────────────────────────────────

alias t := test

# Run all tests
[group('test')]
test:
    @{{ mise_exec }} go test ./...

# Run tests with verbose output
[group('test')]
test-v:
    @{{ mise_exec }} go test -v ./...

# Run tests with coverage report
[group('test')]
test-coverage:
    @{{ mise_exec }} go test -coverprofile=coverage.txt ./...
    @{{ mise_exec }} go tool cover -func=coverage.txt

# Run integration tests (build tag)
[group('test')]
test-integration:
    @{{ mise_exec }} go test -tags=integration ./...

# Run tests with race detector
[group('test')]
test-race:
    @{{ mise_exec }} go test -race -timeout 10m ./...

# Run stress tests (heavy load testing)
[group('test')]
test-stress:
    @{{ mise_exec }} go test -tags=stress -timeout 5m ./...

# Run tests and open coverage in browser
[group('test')]
coverage:
    @{{ mise_exec }} go test -coverprofile=coverage.txt ./...
    @{{ mise_exec }} go tool cover -html=coverage.txt

# Generate coverage artifact
[group('test')]
cover: test-coverage

# Run benchmarks
[group('test')]
bench:
    @{{ mise_exec }} go test -bench=. ./...

# Run memory benchmarks for parser
[group('test')]
bench-mem:
    @{{ mise_exec }} go test -bench=BenchmarkParse -benchmem ./internal/parser

# Run comprehensive performance benchmarks
[group('test')]
bench-perf:
    @{{ mise_exec }} go test -bench=. -run=^$ -benchtime=1s -count=3 ./internal/converter

# Save benchmark baseline for comparison
[group('test')]
bench-save:
    @{{ mise_exec }} go test -bench=. -run=^$ -benchmem -count=5 ./... 2>/dev/null | tee .benchmark-baseline.txt

# Compare current benchmarks against baseline
[group('test')]
bench-compare:
    @if [ ! -f .benchmark-baseline.txt ]; then \
        echo "No baseline found. Run 'just bench-save' first."; \
        exit 1; \
    fi
    @{{ mise_exec }} go test -bench=. -run=^$ -benchmem -count=5 ./... 2>/dev/null | tee .benchmark-current.txt
    @{{ mise_exec }} go install golang.org/x/perf/cmd/benchstat@latest
    @{{ mise_exec }} benchstat .benchmark-baseline.txt .benchmark-current.txt

# Run startup time benchmarks
[group('test')]
bench-startup:
    @{{ mise_exec }} go test -bench=BenchmarkStartup -run=^$ -benchmem ./cmd/...

# Run pool benchmarks
[group('test')]
bench-pool:
    @{{ mise_exec }} go test -bench=. -run=^$ -benchmem ./internal/pool/...

# Run model completeness check
[group('test')]
completeness-check:
    @{{ mise_exec }} go test -tags=completeness ./internal/model -run TestModelCompleteness

# ─────────────────────────────────────────────────────────────────────────────
# Build
# ─────────────────────────────────────────────────────────────────────────────

alias b := build

# Build the binary
[group('build')]
build:
    @{{ mise_exec }} go build -o {{ binary_name }}{{ if os_family() == "windows" { ".exe" } else { "" } }} main.go

# Build with optimizations for release
[group('build')]
build-release:
    @CGO_ENABLED=0 {{ mise_exec }} go build -trimpath -ldflags="-s -w" -o {{ binary_name }}{{ if os_family() == "windows" { ".exe" } else { "" } }} main.go

# Clean build artifacts
[group('build')]
[confirm("This will remove build artifacts. Continue?")]
clean:
    @{{ mise_exec }} go clean
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
    @{{ mise_exec }} goreleaser build --clean --snapshot

# Build for current platform only
[group('release')]
release-local:
    @{{ mise_exec }} goreleaser build --clean --snapshot --single-target

# Full release (requires git tag and GITHUB_TOKEN)
[group('release')]
[confirm("This will create a GitHub release. Continue?")]
release: check test
    @{{ mise_exec }} goreleaser release --clean

# ─────────────────────────────────────────────────────────────────────────────
# Documentation
# ─────────────────────────────────────────────────────────────────────────────

alias d := docs

# Serve documentation locally
[group('docs')]
docs:
    @{{ mise_exec }} uv run mkdocs serve

# Alias for docs
[group('docs')]
site: docs

# Build documentation
[group('docs')]
docs-build:
    @{{ mise_exec }} uv run mkdocs build

# Build documentation with verbose output
[group('docs')]
docs-test:
    @{{ mise_exec }} uv run mkdocs build --verbose

# Generate model reference documentation
[group('docs')]
generate-docs:
    @{{ mise_exec }} go run tools/docgen/main.go

# ─────────────────────────────────────────────────────────────────────────────
# Changelog
# ─────────────────────────────────────────────────────────────────────────────

# Generate changelog
[group('docs')]
changelog: _require-git-cliff
    @{{ mise_exec }} git-cliff --output CHANGELOG.md

# Generate changelog for a specific version
[group('docs')]
changelog-version version: _require-git-cliff
    @{{ mise_exec }} git-cliff --tag {{ version }} --output CHANGELOG.md

# Generate changelog for unreleased changes only
[group('docs')]
changelog-unreleased: _require-git-cliff
    @{{ mise_exec }} git-cliff --unreleased --output CHANGELOG.md

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
    @{{ mise_exec }} gosec ./...

# Generate SBOM with cyclonedx-gomod
[group('security')]
sbom: build-release
    @{{ mise_exec }} cyclonedx-gomod bin -output sbom-binary.cyclonedx.json ./{{ binary_name }}{{ if os_family() == "windows" { ".exe" } else { "" } }}
    @{{ mise_exec }} cyclonedx-gomod app -output sbom-modules.cyclonedx.json -json .

# Run all security checks (SBOM + security scan)
[group('security')]
security-all: sbom scan

# ─────────────────────────────────────────────────────────────────────────────
# Licensing
# ─────────────────────────────────────────────────────────────────────────────

# Generate THIRD_PARTY_NOTICES from dependency licenses
[group('licensing')]
notices:
    {{ mise_exec }} go-licenses report ./... \
        --ignore github.com/EvilBit-Labs/opnDossier \
        --template packaging/notices.tpl > THIRD_PARTY_NOTICES 2>/dev/null

# ─────────────────────────────────────────────────────────────────────────────
# CI
# ─────────────────────────────────────────────────────────────────────────────

# Run full CI checks (pre-commit, format, lint, test)
[group('ci')]
ci-check: check format-check lint test test-integration

# Run smoke tests (fast, minimal validation)
[group('ci')]
ci-smoke:
    @{{ mise_exec }} go build -trimpath -ldflags="-s -w -X main.version=dev" -v ./...
    @{{ mise_exec }} go test -count=1 -failfast -short -timeout 5m ./cmd/... ./internal/config/...

# Run full checks including security and release validation
[group('ci')]
ci-full: ci-check security-all release-check docs-test

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
    @{{ mise_exec }} just act-dry ci
    @{{ mise_exec }} just act-dry sbom
    @{{ mise_exec }} just act-dry scorecard

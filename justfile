# Justfile for opnDossier

set shell := ["bash", "-cu"]
set windows-powershell := true
set dotenv-load := true
set ignore-comments := true


default:
    just --summary

alias h := help
help:
    just --summary

# -----------------------------
# 🔧 Setup & Installation
# -----------------------------


# Setup the environment for windows
[windows]
setup-env:
    @cd {{justfile_dir()}}
    python -m venv .venv

# Setup the environment for unix
[unix]
setup-env:
    @cd {{justfile_dir()}}
    python3 -m venv .venv

# Virtual environment paths
venv-python := if os_family() == "windows" { ".venv\\Scripts\\python.exe" } else { ".venv/bin/python" }
venv-pip := if os_family() == "windows" { ".venv\\Scripts\\pip.exe" } else { ".venv/bin/pip" }
venv-mkdocs := if os_family() == "windows" { ".venv\\Scripts\\mkdocs.exe" } else { ".venv/bin/mkdocs" }


# Install dependencies
install:
    @just setup-env
    @{{venv-pip}} install mkdocs-material
    @pre-commit install --hook-type commit-msg
    @go mod tidy
    @just install-git-cliff

# Update dependencies
update-deps:
    go get -u ./...
    go mod tidy
    go mod verify

# Install git-cliff for changelog generation
[unix]
install-git-cliff:
    @echo "Installing git-cliff..."
    @if ! command -v git-cliff >/dev/null 2>&1; then \
        if command -v cargo >/dev/null 2>&1; then \
            cargo install git-cliff; \
        elif command -v brew >/dev/null 2>&1; then \
            brew install git-cliff; \
        else \
            echo "Error: git-cliff not found. Please install it manually:"; \
            echo "  - Using Cargo: cargo install git-cliff"; \
            echo "  - Using Homebrew: brew install git-cliff"; \
            echo "  - Or download from: https://github.com/orhun/git-cliff/releases"; \
            exit 1; \
        fi; \
    else \
        echo "git-cliff is already installed"; \
    fi

[windows]
install-git-cliff:
    @echo "Installing git-cliff..."
    @if ! where git-cliff >nul 2>&1; then \
        if where cargo >nul 2>&1; then \
            cargo install git-cliff; \
        else \
            echo "Error: git-cliff not found. Please install it manually:"; \
            echo "  - Using Cargo: cargo install git-cliff"; \
            echo "  - Or download from: https://github.com/orhun/git-cliff/releases"; \
            exit 1; \
        fi; \
    else \
        echo "git-cliff is already installed"; \
    fi


# -----------------------------
# 🧹 Linting, Typing, Dep Check
# -----------------------------

# Run pre-commit checks
check:
    pre-commit run --all-files

# Run code formatting
format:
    golangci-lint run --fix ./...
    @just modernize

# Run code formatting checks
format-check:
    golangci-lint fmt ./...

# Run code linting
lint:
    golangci-lint run ./...
    @just modernize-check

# Run modernize analyzer to check for modernization opportunities
modernize:
    go run golang.org/x/tools/gopls/internal/analysis/modernize/cmd/modernize@latest -fix -test ./...

# Run modernize analyzer in dry-run mode (no fixes applied)
modernize-check:
    go run golang.org/x/tools/gopls/internal/analysis/modernize/cmd/modernize@latest -test ./...


# -----------------------------
# 🧪 Testing & Coverage
# -----------------------------

# Run tests
test:
    go test ./...

# Run benchmarks
bench:
    go test -bench=. ./...

# Run memory benchmark
bench-memory:
    go test -bench=BenchmarkParse -benchmem ./internal/parser

test-with-coverage:
    go test -coverprofile=coverage.txt ./...

coverage:
    @just test-with-coverage
    go tool cover -html=coverage.txt

# Run tests with coverage (alternative to separate test + coverage)
test-coverage:
    @just test-with-coverage
    go tool cover -func=coverage.txt


completeness-check:
    go test -tags=completeness ./internal/model -run TestModelCompleteness



# -----------------------------
# 📦 Build & Clean
# -----------------------------

[unix]
clean:
    go clean
    rm -f coverage.txt
    rm -f opndossier

[windows]
clean:
    go clean
    del /q coverage.txt
    del /q opndossier.exe


# Build the project
build:
    go build -o opndossier main.go

clean-build:
    just clean
    just build

# Build for release using GoReleaser
build-for-release:
    @just check
    @just test
    goreleaser build --clean --snapshot --single-target

# Build snapshot release
build-snapshot:
    goreleaser build --clean --snapshot

# Build full release (requires git tag)
build-release:
    goreleaser build --clean

# Check GoReleaser configuration
check-goreleaser:
    goreleaser check --verbose

# Release to GitHub (requires git tag and GITHUB_TOKEN)
release:
    goreleaser release --clean

# Release snapshot to GitHub
release-snapshot:
    goreleaser release --clean --snapshot

# -----------------------------
# 📖 Documentation
# -----------------------------

# Serve documentation locally
@docs:
    @{{venv-mkdocs}} serve

# Test documentation build
docs-test:
    @{{venv-mkdocs}} build --verbose

# Build documentation
docs-export:
    @{{venv-mkdocs}} build

# Generate changelog using git-cliff
changelog:
    @just check-git-cliff
    git-cliff --output CHANGELOG.md

# Generate changelog for a specific version
changelog-version *version:
    @just check-git-cliff
    git-cliff --tag {{version}} --output CHANGELOG.md

# Generate changelog for unreleased changes
changelog-unreleased:
    @just check-git-cliff
    git-cliff --unreleased --output CHANGELOG.md

# Check if git-cliff is available
[unix]
check-git-cliff:
    @if ! command -v git-cliff >/dev/null 2>&1; then \
        echo "Error: git-cliff not found. Run 'just install' to install it."; \
        exit 1; \
    fi

[windows]
check-git-cliff:
    @if ! where git-cliff >nul 2>&1; then \
        echo "Error: git-cliff not found. Run 'just install' to install it."; \
        exit 1; \
    fi



# -----------------------------
# 🚀 Development Environment
# -----------------------------

# Run the agent (development)
dev *args="":
    go run main.go {{args}}

# -----------------------------
# 🤖 CI Workflow
# -----------------------------

# Run all checks and tests (CI)
ci-check:
    @cd {{justfile_dir()}}
    @just check
    @just format-check
    @just lint
    @just test

# Run all checks, tests, and release validation
full-checks:
    @cd {{justfile_dir()}}
    @just ci-check
    @just check-goreleaser



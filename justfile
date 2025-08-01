# Justfile for opnFocus

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
    goimports -w .
    @just modernize

# Run code formatting checks
format-check:
    golangci-lint fmt ./...
    goimports -d .

# Run code linting
lint:
    golangci-lint run ./...
    go vet ./...
    gosec ./...
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

coverage:
    go test -coverprofile=coverage.out ./...
    go tool cover -html=coverage.out


completeness-check:
    go test -tags=completeness ./internal/model -run TestModelCompleteness



# -----------------------------
# 📦 Build & Clean
# -----------------------------

[unix]
clean:
    go clean
    rm -f coverage.out
    rm -f opnfocus

[windows]
clean:
    go clean
    del /q coverage.out
    del /q opnfocus.exe


# Build the project
build:
    go build -o opnfocus main.go

clean-build:
    just clean
    just build

# Run all checks and tests, and build the agent
build-for-release:
    @just install
    @go mod tidy
    @just check
    @just test
    goreleaser build --clean --auto-snapshot --single-target

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
    @just modernize-check
    @just test
    @goreleaser check --verbose



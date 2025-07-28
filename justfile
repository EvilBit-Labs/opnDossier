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

# Update dependencies
update-deps:
    go get -u ./...
    go mod tidy
    go mod verify


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

# Run code formatting checks
format-check:
    golangci-lint fmt ./...
    goimports -d .

# Run code linting
lint:
    golangci-lint run ./...
    go vet ./...
    gosec ./...


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
    @goreleaser check --verbose



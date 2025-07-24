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
    just use-venv

# Setup the environment for unix
[unix]
setup-env:
    @cd {{justfile_dir()}}
    python -m venv .venv

# Activate the virtual environment
[windows]
use-venv:
    @.venv\Scripts\Activate.ps1

# Activate the virtual environment
[unix]
use-venv:
    @.venv/bin/activate


# Install dependencies
install:
    @just setup-env
    @pip install mkdocs-material
    @pre-commit install --hook-type commit-msg
    @go mod tidy

# Update dependencies
update-deps:
    go get -u ./...
    go mod tidy
    go mod verify
    go mod vendor
    go mod tidy


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

coverage:
    go test -coverprofile=coverage.out ./...
    go tool cover -html=coverage.out


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
    @just use-venv
    @mkdocs serve

# Test documentation build
docs-test:
    @just use-venv
    @mkdocs build --verbose

# Build documentation
docs-export:
    @just use-venv
    @mkdocs build



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



# Justfile for opnFocus

# Set shell to PowerShell for Windows compatibility
set shell := ["pwsh", "-c"]

# Serve documentation locally
@docs:
    .venv\Scripts\Activate.ps1; mkdocs serve

# Run the agent (development)
dev *args="":
    go run main.go {{args}}

# Install all requirements and build the project
install:
    cd {{justfile_dir()}}
    python -m venv .venv
    .venv\Scripts\Activate.ps1; pip install mkdocs-material
    pre-commit install --hook-type commit-msg
    go mod tidy


# Code quality
format:
    golangci-lint run --fix ./...
    goimports -w .

format-check:
    golangci-lint fmt ./...
    goimports -d .

lint:
    golangci-lint run ./...
    go vet ./...
    gosec ./...

check:
    just format-check
    just lint
    goreleaser check --verbose

# Run tests
test:
    go test ./...

# Run all checks and tests (CI)
ci-check:
    just format-check
    just lint
    just test
    goreleaser check --verbose

# Run all checks and tests, and build the agent
build:
    cd {{justfile_dir()}}
    just install
    go mod tidy
    just check
    just test
    goreleaser build --clean --auto-snapshot --single-target

update-deps:
    cd {{justfile_dir()}}
    go get -u ./...
    go mod tidy
    go mod verify
    go mod vendor
    go mod tidy

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


# Install dev dependencies
setup: install

# Install dependencies
install:
    @just setup-env
    @{{venv-pip}} install mkdocs-material
    @pre-commit install --hook-type commit-msg
    @go mod tidy
    @just install-git-cliff

# Update dependencies
update-deps:
    @just update-go-deps
    @just update-python-deps
    @just update-pnpm-deps
    @just update-pre-commit
    @just update-dev-tools
    @echo "Dependency updates complete!"

# Update Go dependencies
update-go-deps:
    @echo "Updating Go dependencies..."
    go get -u ./...
    go mod tidy
    go mod verify

# Update Python virtual environment dependencies
update-python-deps:
    @echo "Updating Python virtual environment dependencies..."
    @{{venv-pip}} install --upgrade mkdocs-material

# Update pre-commit hooks
update-pre-commit:
    @echo "Updating pre-commit hooks..."
    pre-commit autoupdate

# Update development tools
update-dev-tools:
    @echo "Updating development tools..."
    @if command -v go >/dev/null 2>&1; then \
        go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest; \
    fi

# Update pnpm dependencies (Unix)
[unix]
update-pnpm-deps:
    @echo "Updating npm dependencies..."
    @if command -v pnpm >/dev/null 2>&1; then \
        pnpm update; \
    else \
        echo "Warning: pnpm not found, skipping pnpm dependency updates"; \
    fi

# Update pnpm dependencies (Windows)
[windows]
update-pnpm-deps:
    @echo "Updating npm dependencies..."
    @if where pnpm >nul 2>&1; then \
        pnpm update; \
    else \
        echo "Warning: pnpm not found, skipping pnpm dependency updates"; \
    fi

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

# Install Grype for vulnerability scanning
[unix]
install-grype:
    @echo "Installing Grype..."
    @if ! command -v grype >/dev/null 2>&1; then \
        if command -v brew >/dev/null 2>&1; then \
            brew tap anchore/grype && brew install grype; \
        elif command -v go >/dev/null 2>&1; then \
            go install github.com/anchore/grype@latest; \
        else \
            echo "Error: Grype not found. Please install it manually:"; \
            echo "  - Using Homebrew: brew tap anchore/grype && brew install grype"; \
            echo "  - Using Go: go install github.com/anchore/grype@latest"; \
            exit 1; \
        fi; \
    else \
        echo "Grype is already installed"; \
    fi

[windows]
install-grype:
    @echo "Installing Grype..."
    @if ! where grype >nul 2>&1; then \
        if where go >nul 2>&1; then \
            go install github.com/anchore/grype@latest; \
        else \
            echo "Error: Grype not found. Please install it manually:"; \
            echo "  - Using Go: go install github.com/anchore/grype@latest"; \
            exit 1; \
        fi; \
    else \
        echo "Grype is already installed"; \
    fi

# Install Syft for SBOM generation
[unix]
install-syft:
    @echo "Installing Syft..."
    @if ! command -v syft >/dev/null 2>&1; then \
        if command -v brew >/dev/null 2>&1; then \
            brew tap anchore/syft && brew install syft; \
        elif command -v go >/dev/null 2>&1; then \
            go install github.com/anchore/syft@latest; \
        else \
            echo "Error: Syft not found. Please install it manually:"; \
            echo "  - Using Homebrew: brew tap anchore/syft && brew install syft"; \
            echo "  - Using Go: go install github.com/anchore/syft@latest"; \
            exit 1; \
        fi; \
    else \
        echo "Syft is already installed"; \
    fi

[windows]
install-syft:
    @echo "Installing Syft..."
    @if ! where syft >nul 2>&1; then \
        if where go >nul 2>&1; then \
            go install github.com/anchore/syft@latest; \
        else \
            echo "Error: Syft not found. Please install it manually:"; \
            echo "  - Using Go: go install github.com/anchore/syft@latest"; \
            exit 1; \
        fi; \
    else \
        echo "Syft is already installed"; \
    fi

# Install Cosign for artifact signing
[unix]
install-cosign:
    @echo "Installing Cosign..."
    @if ! command -v cosign >/dev/null 2>&1; then \
        if command -v brew >/dev/null 2>&1; then \
            brew install cosign; \
        elif command -v go >/dev/null 2>&1; then \
            go install github.com/sigstore/cosign/v2/cmd/cosign@latest; \
        else \
            echo "Error: Cosign not found. Please install it manually:"; \
            echo "  - Using Homebrew: brew install cosign"; \
            echo "  - Using Go: go install github.com/sigstore/cosign/v2/cmd/cosign@latest"; \
            exit 1; \
        fi; \
    else \
        echo "Cosign is already installed"; \
    fi

[windows]
install-cosign:
    @echo "Installing Cosign..."
    @if ! where cosign >nul 2>&1; then \
        if where go >nul 2>&1; then \
            go install github.com/sigstore/cosign/v2/cmd/cosign@latest; \
        else \
            echo "Error: Cosign not found. Please install it manually:"; \
            echo "  - Using Go: go install github.com/sigstore/cosign/v2/cmd/cosign@latest"; \
            exit 1; \
        fi; \
    else \
        echo "Cosign is already installed"; \
    fi


# -----------------------------
# 🧹 Linting, Typing, Dep Check
# -----------------------------

# Run pre-commit checks
check:
    pre-commit run --all-files

# Run code formatting
fmt: format

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

# Generate coverage artifacts
cover: test-with-coverage


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

# GoReleaser dry run
release-dry: build-snapshot

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
site: docs

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
# 🔒 Security & Vulnerability Scanning
# -----------------------------

# Run Grype vulnerability scanner locally
scan-vulnerabilities:
    @echo "Running Grype vulnerability scan..."
    @if ! command -v grype >/dev/null 2>&1; then \
        echo "Error: grype not found. Install with:"; \
        echo "  - Using Homebrew: brew tap anchore/grype && brew install grype"; \
        echo "  - Using Go: go install github.com/anchore/grype@latest"; \
        exit 1; \
    fi
    grype .

# Generate SBOM with Syft
sbom: generate-sbom

# Generate SBOM with Syft
generate-sbom:
    @echo "Generating SBOM with Syft..."
    @if ! command -v syft >/dev/null 2>&1; then \
        echo "Error: syft not found. Install with:"; \
        echo "  - Using Homebrew: brew tap anchore/syft && brew install syft"; \
        echo "  - Using Go: go install github.com/anchore/syft@latest"; \
        exit 1; \
    fi
    syft . -o spdx-json=sbom.spdx.json
    @echo "SBOM generated: sbom.spdx.json"

# Run Snyk vulnerability scanner locally (requires Snyk CLI)
snyk-scan:
    @echo "Running Snyk vulnerability scan..."
    @if ! command -v snyk >/dev/null 2>&1; then \
        echo "Error: snyk CLI not found. Install with:"; \
        echo "  - Using npm: npm install -g snyk"; \
        echo "  - Using Homebrew: brew install snyk-cli"; \
        echo "  - Or download from: https://github.com/snyk/cli/releases"; \
        exit 1; \
    fi
    @if [ -z "$$SNYK_TOKEN" ]; then \
        echo "Warning: SNYK_TOKEN not set. Some features may be limited."; \
        echo "Set SNYK_TOKEN environment variable for full functionality."; \
    fi
    snyk test --severity-threshold=high
    snyk monitor --severity-threshold=high

# Run FOSSA analysis locally (requires FOSSA CLI)
fossa-scan:
    @echo "Running FOSSA license scan..."
    @if ! command -v fossa >/dev/null 2>&1; then \
        echo "Error: fossa CLI not found. Install from: https://github.com/fossas/fossa-cli"; \
        exit 1; \
    fi
    @if [ -z "$$FOSSA_API_KEY" ]; then \
        echo "Warning: FOSSA_API_KEY not set. Some features may be limited."; \
        echo "Set FOSSA_API_KEY environment variable for full functionality."; \
    fi
    fossa analyze
    fossa test

# Run all security scans locally
security-scan:
    @echo "Running comprehensive security scan..."
    just generate-sbom
    just scan-vulnerabilities
    just snyk-scan
    just fossa-scan
    @echo "Security scan complete. Check results above."

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

# Smoke test for Windows CI (minimal validation)
ci-check-smoke:
    @cd {{justfile_dir()}}
    @echo "Running smoke tests..."
    @go build -v ./...
    @go test -short -timeout 5m ./cmd/... ./internal/config/...
    @echo "✅ Smoke tests passed"

# Run all checks, tests, and release validation
full-checks:
    @cd {{justfile_dir()}}
    @just ci-check
    @just security-scan
    @just check-goreleaser

# Test specific GitHub Actions workflow
[unix]
act-workflow *workflow:
    @echo "Testing GitHub Actions workflow: {{workflow}}"
    @if ! command -v act >/dev/null 2>&1; then \
        echo "Error: act not found. Please install it:"; \
        echo "  - Using Homebrew: brew install act"; \
        echo "  - Using Go: go install github.com/nektos/act@latest"; \
        echo "  - Or download from: https://github.com/nektos/act/releases"; \
        exit 1; \
    fi
    act --workflows .github/workflows/{{workflow}}.yml --list --container-architecture linux/amd64

[windows]
act-workflow *workflow:
    @echo "Testing GitHub Actions workflow: {{workflow}}"
    @if (-not (Get-Command act -ErrorAction SilentlyContinue)) { \
        echo "Error: act not found. Please install it:"; \
        echo "  - Using Go: go install github.com/nektos/act@latest"; \
        echo "  - Or download from: https://github.com/nektos/act/releases"; \
        exit 1; \
    }
    act --workflows .github/workflows/{{workflow}}.yml --list --container-architecture linux/amd64





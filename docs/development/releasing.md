# Releasing opnDossier

This document has been consolidated. See the canonical location:

**[RELEASING.md](../../RELEASING.md)**

The canonical document covers:

- Version numbering (SemVer) and pre-release tags
- Prerequisites and tool installation (`mise`, `goreleaser`, `git-cliff`, `cosign`, `cyclonedx-gomod`, `go-licenses`, Quill)
- Pre-release checklist and CI verification
- Tagging, GitHub release creation, and release workflow monitoring
- Post-release verification (checksums, SLSA provenance, Cosign v3 `.sigstore.json` bundles, GPG signatures)
- Release candidates and hotfix process
- macOS signing and notarization via Quill
- Release artifacts inventory

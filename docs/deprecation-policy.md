# Deprecation Policy

## Overview

This document outlines the deprecation policy for opnDossier features and APIs. We follow a predictable lifecycle to ensure stability while allowing the project to evolve.

## Deprecation Lifecycle

Features and APIs go through a three-stage lifecycle:

1. **Deprecated (Warning Phase)**

   - The feature is still fully functional.
   - Usage triggers a warning message (log output, CLI warning).
   - Documentation is updated to reflect deprecation.
   - A migration path is provided.
   - Lasts for at least one minor version (e.g., v2.1 to v2.5).

2. **Frozen (Final Phase)**

   - The feature is frozen and will receive no further updates or bug fixes.
   - Warnings become more prominent.
   - Lasts for one minor version before removal.

3. **Removed**

   - The feature is removed from the codebase.
   - Usage results in an error.
   - Occurs in a major version bump (e.g., v3.0).

## Current Deprecations

### Template-Based Generation

**Status:** Deprecated (Warning Phase) **Since:** v2.0 **Removal Target:** TBD

Template-based generation (using `text/template`) is being replaced by a programmatic generation approach for improved performance, type safety, and maintainability.

**Impact:**

- The `--use-template` flag and custom template support will be removed in v3.0.
- The `markdown.NewMarkdownGeneratorWithTemplates` function will be removed.

**Migration:**

- See the [Migration Guide](migration.md) for detailed instructions on moving to programmatic generation.

## Suppressing Warnings

Deprecation warnings can be suppressed using the `--quiet` CLI flag or by setting `quiet: true` in your configuration file, though this is not recommended as it hides important migration notices.

## Versioning Policy

We adhere to [Semantic Versioning](https://semver.org/):

- **Major (X.y.z):** Incompatible API changes.
- **Minor (x.Y.z):** Backward-compatible functionality.
- **Patch (x.y.Z):** Backward-compatible bug fixes.

## Communication

Deprecations are communicated via:

- **Release Notes:** Prominently featured in "Breaking Changes" or "Deprecations".
- **CLI Warnings:** Runtime warnings when using deprecated features.
- **Documentation:** Updated guides and API references.
- **GitHub Issues:** Tracking issues for deprecation progress.

## Feedback

If a deprecation significantly impacts your workflow, please open a GitHub issue to discuss your use case. We value user feedback and may adjust timelines based on community needs.

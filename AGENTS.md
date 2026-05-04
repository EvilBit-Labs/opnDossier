# Agent Context

This file provides AI coding assistants with project context. All substantive documentation lives in the files linked below. Read the linked documents for implementation details — this file only contains agent-specific behavioral rules.

> **Agents invoking opnDossier at runtime** (vs. contributing to it): start at [docs/for-agents.md](docs/for-agents.md). That page aggregates every stable machine-readable interface — auto-generated CLI reference, JSON/YAML output schemas, exit codes, public Go API, configuration schema — in one place and is kept in sync with the code via generators. The rest of this document is for AI assistants contributing to the repo itself.

@GOTCHAS.md

## Project Documentation

- **[Contributing Standards](CONTRIBUTING.md)** — Code style, PR process, testing expectations, commit conventions, security
- **[Development Standards](docs/development/standards.md)** — Go patterns, implementation details, data processing, architecture
- **[Architecture](docs/development/architecture.md)** — System design, component interactions, deployment patterns
- **[Known Gotchas](GOTCHAS.md)** — Non-obvious behaviors, common pitfalls, hard-won lessons
- **[Plugin Development](docs/development/plugin-development.md)** — Compliance plugin and device parser development
- **[Requirements](project_spec/requirements.md)** — Project requirements and specifications
- **[Tasks](project_spec/tasks.md)** — Implementation tasks
- **[User Stories](project_spec/user_stories.md)** — User stories
- **[Solutions](docs/solutions/)** — Documented problem solutions for searchable future reference

## Agent-Specific Rules

### Rule Precedence

Rules are applied in the following order:

1. **Project-specific rules** (this document, linked docs above)
2. **General development standards** (docs/development/standards.md)
3. **Language-specific style guides** (Go conventions)

When rules conflict, follow the higher precedence rule.

### Code Quality Policy

**Zero tolerance for tech debt.** Never dismiss warnings, lint failures, or CI errors as "pre-existing" or "not from our changes." If CI fails, investigate and fix it — regardless of when the issue was introduced. Every session should leave the codebase better than it found it.

### Mandatory Practices

1. **CRITICAL: Run `just ci-check` BEFORE committing, not after** — tasks are not complete until it passes
2. **Always run tests** after changes (`just test`) and **linting** before committing (`just lint`)
3. **Consult project documentation** before making changes
4. Prefer structured config data + audit overlays over flat summary tables
5. Validate markdown with `mdformat` — **never run `mdformat` directly**; use `pre-commit run -a` which loads the correct plugins
6. Place `//nolint:` directives on SEPARATE LINE above call (inline gets stripped by gofumpt)
7. **Preallocate slices when the final size is known ahead of time.** Prefer `make([]T, 0, len(src))` over `var s []T` followed by `append` in a loop when the output length is guaranteed by the input (e.g., a transform that does not filter). `prealloc` is not enabled in CI because it also recommends the anti-pattern on validator error-collector loops where the common case is zero appends — so this is a manual-review rule, not a lint-enforced one. Do *not* preallocate when the loop may skip the append (validation, filtering, conditional matching); in those cases the nil-slice-grow-on-demand pattern is correct.

### JSON / YAML Tag Naming

The `tagliatelle` linter is disabled in `.golangci.yml` because the vendor-controlled OPNsense/pfSense `config.xml` schema mixes casing conventions (`hostname`, `descr`, `sourceport`, `created-time`, `Phase1`) and the `pkg/schema/*` Go types must mirror that reality — a single case convention fights the input format we do not control.

For **new Go types that are not mirroring a vendor schema**, follow these conventions anyway so the public JSON/YAML surface we *do* control stays consistent:

- **JSON tags** — `camelCase` (e.g. `"complianceResults"`, `"firewallRules"`, `"deviceType"`). This matches the existing `pkg/model.CommonDevice` JSON surface.
- **YAML tags** — same `camelCase` as the JSON tag; do not diverge.
- **Nested struct types** — every field gets an explicit tag. Do not rely on the default `FieldName` lowercasing.
- **Boolean-flag fields** — name positively (e.g. `"enabled"`, not `"disabled"`), prefer omitting the field when unset via `omitempty`.

When mirroring a vendor schema (anything under `pkg/schema/opnsense/`, `pkg/schema/pfsense/`, or `pkg/schema/shared/`), the vendor's XML element name wins. Do not rename vendor fields to match our camelCase policy — downstream consumers reading `config.xml` will break, and the round-trip invariant in the schema tests will fail.

This convention is enforced manually via code review since tagliatelle cannot express the schema-carve-out accurately. Reviewers should flag any non-schema type with a non-camelCase JSON tag and any schema type with a Go-renamed tag.

### Code Review Checklist

- [ ] Formatting, linting, and tests pass (`just ci-check`)
- [ ] Error handling includes context
- [ ] No hardcoded secrets
- [ ] Input validation at boundaries
- [ ] Documentation updated
- [ ] Follows established patterns and architecture

### Rules of Engagement

- **TERM=dumb Support**: Ensure terminal output respects `TERM="dumb"` for CI/automation
- **No Merging**: Never merge without a passing CI check and code review approval on a PR. This must be performed by a human maintainer, not an AI assistant.
- **Security-First**: All changes must maintain least privilege and undergo security review.
- **Focus on Value**: Enhance the project's unique value as an OPNsense auditing tool
- **Stay Focused**: Avoid scope creep
- **AI Disclosure**: Always disclose AI usage in PR descriptions, following the [AI Usage Policy](AI_POLICY.md). Be transparent, but brief — no need to list every prompt, just the tools used (e.g., "Used Claude Code (`Claude Opus 4.7 (1M Context)`) for initial draft of detection engine refactor. All code reviewed and tested."). For the broader expectation of what belongs (and doesn't) in a PR body or commit message — and how minimal the AI disclosure should stay — see [PR body and commit message content standard](docs/solutions/conventions/pr-and-commit-message-content-standard-2026-05-04.md).

### Issue Resolution

When encountering problems:

1. Identify the specific issue clearly
2. Explain the problem in 5 lines or fewer
3. Propose a concrete path forward
4. Don't proceed without resolving blockers

### Documentation Accuracy for Interfaces

When documenting interfaces in prose, Mermaid diagrams, or code examples:

- Extract method lists from `go doc` output or source code, never from memory or design proposals
- Verify every identifier in Mermaid diagrams resolves to a real symbol (`grep -r` in source)
- Method counts stated in prose must match actual interface definitions
- Update docs in the same commit as interface changes, not in follow-up PRs
- See `docs/solutions/logic-errors/documentation-code-drift-interface-refactoring.md`

## Agent Rules <!-- tessl-managed -->

@.tessl/RULES.md follow the [instructions](.tessl/RULES.md)

# Agent Context

This file provides AI coding assistants with project context. All substantive documentation lives in the files linked below. Read the linked documents for implementation details — this file only contains agent-specific behavioral rules.

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
5. Validate markdown with `mdformat` and `markdownlint-cli2` — **never run `mdformat` directly**; use `pre-commit run -a` which loads the correct plugins
6. Place `//nolint:` directives on SEPARATE LINE above call (inline gets stripped by gofumpt)

### Code Review Checklist

- [ ] Formatting, linting, and tests pass (`just ci-check`)
- [ ] Error handling includes context
- [ ] No hardcoded secrets
- [ ] Input validation at boundaries
- [ ] Documentation updated
- [ ] Follows established patterns and architecture

### Rules of Engagement

- **TERM=dumb Support**: Ensure terminal output respects `TERM="dumb"` for CI/automation
- **No Auto-commits**: Never commit without explicit permission
- **Focus on Value**: Enhance the project's unique value as an OPNsense auditing tool
- **No Destructive Actions**: No major refactors without explicit permission
- **Stay Focused**: Avoid scope creep
- **Task Tracking**: Jira (NATS project) is the primary tracker for planned work — reference tickets by key (e.g., `NATS-33`) in plans, commits, and PR titles. GitHub issues are reserved for community-submitted bug reports/feature requests and for PRs. Do not open new GitHub issues for internal work; file in Jira instead.

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

# Agent Rules <!-- tessl-managed -->

@.tessl/RULES.md follow the [instructions](.tessl/RULES.md)
